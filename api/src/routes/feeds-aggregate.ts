import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { fetchResilient } from '../lib/fetch-resilient';
import { FEED_ALLOWED_HOSTS as ALLOWED_HOSTS } from '../lib/feed-hosts';
import { unwrapBingNewsLink } from '../lib/rss-parser';
import { safeIso } from '../lib/safe-date';
import { buildMtiRansomwareRss, MTI_RANSOMWARE_FEED_PATH } from './mti-ransomware-rss';
import { safeNull } from '../lib/safe-catch';
import { buildRansomwareMergedRss, RANSOMWARE_MERGED_FEED_PATH } from './ransomware-merged-rss';

/**
 * Server-side feed aggregator. Cuts client-side network calls from N (one per
 * feed) to 1. Each call into the underlying proxy benefits from Cloudflare
 * edge caching, so 95% of work is the parse + sort, not the fetch.
 *
 * Response shape mirrors the per-feed proxy enough that the frontend can keep
 * its existing FeedItem type.
 *
 * GET /api/v1/feeds/aggregate?urls=<comma-separated-urls>
 *   - urls: comma-separated, URL-encoded list of feed URLs (max MAX_FEEDS)
 *   - limit: max items to return after merging + sorting (default 30, max 100)
 *   - perSource: max items per source before global cap (default 3, max 10)
 *
 * Items are sorted newest-first by pubDate.
 */

// Hard ceiling on feeds per invocation. Every feed costs at least one
// subrequest (the caches.default.match lookup); a cold feed costs
// match + fetch + up to 4 redirect hops + a write-back put.
//
// Cloudflare's free plan allows 50 subrequests per invocation, so the previous
// ceiling of 40 could reach ~120-320 subrequests on a cold cache and hard-fail
// the entire request ("Too many subrequests"). 15 matches the frontend's own
// AGGREGATOR_CHUNK_SIZE (rssService.ts), which was already sized against the
// 50-subrequest cap — so every first-party batch now fits without being
// silently truncated, while direct/untrusted callers can no longer force a
// 3-6x subrequest overrun. The worst case (15 fully cold, every feed
// redirecting) is ~75 and the warm case is 15.
const MAX_FEEDS = 15;
/** Default page-size when caller doesn't pass ?limit=. Bumped 30 → 100 so
 *  the threat-pulse / threat-feeds pages surface a representative week
 *  rather than just a day's churn. */
const DEFAULT_LIMIT = 100;
/** Hard ceiling for ?limit=. Raised 100 → 500 to support the 7-day window. */
const MAX_LIMIT = 500;
const DEFAULT_PER_SOURCE = 5;
/** Per-source cap. Raised 10 → 25 in step with MAX_LIMIT so no single
 *  high-volume RSS dominates the merged response. */
const MAX_PER_SOURCE = 25;
const FETCH_TIMEOUT_MS = 20_000;
// Per-URL parsed-response cache key prefix — checked BEFORE the upstream
// fetch in fetchOne. NOTE: caches.default.match() DOES count as a subrequest
// (Cache API ops share the same per-invocation budget as fetch()). The win
// is not "zero subrequests" — it's swapping a slow upstream fetch (+ up to 4
// redirect hops + a write-back put) for a single cheap local cache read, and
// avoiding the timeout-prone origin entirely. TTL kept generous because RSS
// items rarely change faster than that for the slow upstreams that timeout most.
// 1h — long enough that most users land on a warm cache for the entire
// session. RSS feeds rarely publish more than once per hour, and the
// cache-first pattern means cold-cache visits are the only ones that
// hit upstream timeouts. Was 10min, which produced too many cold-cache
// visits (every Google News URL would re-fail before the next user hit
// the cache that did succeed). 1h dramatically reduces cold-cache rate.
const PER_URL_CACHE_TTL_SECONDS = 3600;
const CACHE_TTL_SECONDS = 300; // 5 minutes — matches per-feed proxy cache

/**
 * BleepingComputer's Cloudflare bot-challenge returns 403 to datacenter
 * egress (any Cloudflare Worker — documented in writeup-sources.ts, verified
 * live 2026-08-09). Its content is mirrored by Bing News RSS
 * (www.bing.com, allowlisted), which is served to any client. Was a Google
 * News mirror until news.google.com started 503ing Worker egress IPs
 * (rate limited, 2026-10). Fetch the mirror but keep the ORIGINAL URL as the
 * canonical host so cache keys and per-feed status/section grouping stay stable.
 */
const BLEEPING_COMPUTER_MIRROR = 'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US';
const BLEEPING_COMPUTER_HOST_RE = /^(?:www\.)?bleepingcomputer\.com$/i;

/**
 * Bing News wraps every item link in an apiclick.aspx redirect with the real
 * target in `?url=`. `unwrapBingNewsLink` (lib/rss-parser.ts) resolves it so
 * merged items link straight to the publisher instead of routing readers
 * through Bing's click tracker.
 */
interface AggregatedItem {
  source: string; // hostname of the feed URL
  source_url: string; // original feed URL
  title: string;
  link: string;
  description?: string;
  pubDate: string; // ISO 8601 if parseable, else raw
  guid?: string;
}

interface FeedSourceStatus {
  url: string;
  ok: boolean;
  items: number;
  /** Short reason when ok=false (e.g. "timeout", "404", "non_rss_response"). */
  error?: string;
}

interface AggregateResponse {
  generated_at: string;
  total_items: number;
  feeds_attempted: number;
  feeds_returned: number;
  items: AggregatedItem[];
  /** Per-feed status so the page can show which sources failed. Always
   * populated; absent items mean the feed wasn't included in the query. */
  feeds?: FeedSourceStatus[];
}

/** Strip HTML / XML entities from a feed string. Keep it short and conservative. */
function decodeEntities(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/&#(\d+);/g, (_m, n: string) => String.fromCharCode(parseInt(n, 10)))
    .replace(/<[^>]+>/g, '')
    .trim();
}

function pickTag(body: string, tag: string): string {
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'i');
  const m = body.match(re);
  return m && m[1] !== undefined ? decodeEntities(m[1]) : '';
}

function pickAttr(body: string, tag: string, attr: string): string {
  const re = new RegExp(`<${tag}\\b[^>]*\\b${attr}=["']([^"']+)["']`, 'i');
  const m = body.match(re);
  return m && m[1] !== undefined ? m[1] : '';
}

/** Parse RSS or Atom feed body into items. Tolerant; never throws. */
function parseFeedBody(body: string, sourceUrl: string, host: string, perSource: number): AggregatedItem[] {
  // Detect JSON Feed (v1.0/v1.1) — starts with {, has "version" and "items".
  if (body.trimStart().startsWith('{')) {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed === 'object' && 'version' in parsed && Array.isArray(parsed.items)) {
        return parseJsonFeedItems(parsed.items, sourceUrl, host, perSource);
      }
    } catch (_catchErr) {
      logError('parseFeedBody failed', _catchErr);
      // Not valid JSON — fall through to XML parsing
    }
  }

  const items: AggregatedItem[] = [];
  // RSS <item> + Atom <entry>; both are matched with the same regex.
  const itemRe = /<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi;
  let match: RegExpExecArray | null;
  while ((match = itemRe.exec(body)) !== null) {
    const inner = match[2];
    if (!inner) continue;
    const title = pickTag(inner, 'title') || '(untitled)';
    let link = pickTag(inner, 'link');
    if (!link) link = pickAttr(inner, 'link', 'href');
    if (!link) link = pickTag(inner, 'guid');
    link = unwrapBingNewsLink(link);
    const description = pickTag(inner, 'description') || pickTag(inner, 'summary') || pickTag(inner, 'content');
    const pubRaw = pickTag(inner, 'pubDate') || pickTag(inner, 'updated') || pickTag(inner, 'published') || '';
    const pubDate = safeIso(pubRaw) ?? '';
    const guid = pickTag(inner, 'guid') || pickTag(inner, 'id') || link;
    items.push({
      source: host,
      source_url: sourceUrl,
      title: title.slice(0, 300),
      link,
      description: description ? description.slice(0, 500) : undefined,
      pubDate: pubDate || pubRaw,
      guid,
    });
    if (items.length >= perSource) break;
  }
  return items;
}

/** Parse JSON Feed v1.0/v1.1 items array. */
function parseJsonFeedItems(items: unknown[], sourceUrl: string, host: string, perSource: number): AggregatedItem[] {
  const out: AggregatedItem[] = [];
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;
    const title = typeof record.title === 'string' ? record.title.trim() : '(untitled)';
    const link = typeof record.url === 'string' ? record.url : typeof record.id === 'string' ? record.id : '';
    if (!title || !link) continue;
    const description =
      typeof record.content_text === 'string'
        ? record.content_text.slice(0, 500)
        : typeof record.summary === 'string'
          ? record.summary.slice(0, 500)
          : typeof record.content_html === 'string'
            ? record.content_html.replace(/<[^>]*>/g, '').slice(0, 500)
            : undefined;
    const dateRaw =
      typeof record.date_published === 'string'
        ? record.date_published
        : typeof record.date_modified === 'string'
          ? record.date_modified
          : undefined;
    const pubDate = dateRaw ? (safeIso(dateRaw) ?? dateRaw) : '';
    const guid = typeof record.id === 'string' ? record.id : link;
    out.push({ source: host, source_url: sourceUrl, title: title.slice(0, 300), link, description, pubDate, guid });
    if (out.length >= perSource) break;
  }
  return out;
}

interface FetchOneResult {
  items: AggregatedItem[];
  /** Reason for empty items, when the failure mode is known. */
  error?: string;
}

async function fetchOne(url: string, perSource: number, env?: Env): Promise<FetchOneResult> {
  const parsed = new URL(url);
  // Same-origin synthesised feeds: resolve IN-PROCESS. A Worker HTTP-fetching
  // its own hostname is unreliable (the earlier symptom: feed returned 0 via
  // the aggregator while the standalone endpoint served 10 items).
  if (parsed.pathname === MTI_RANSOMWARE_FEED_PATH) {
    try {
      const { xml } = await buildMtiRansomwareRss();
      return { items: parseFeedBody(xml, url, parsed.hostname, perSource) };
    } catch (e) {
      logError('fetchOne failed', e);
      return { items: [], error: `mti_build_failed: ${(e as Error).message}` };
    }
  }
  if (parsed.pathname === RANSOMWARE_MERGED_FEED_PATH) {
    try {
      const { xml } = await buildRansomwareMergedRss(env);
      return { items: parseFeedBody(xml, url, parsed.hostname, perSource) };
    } catch (e) {
      logError('fetchOne failed', e);
      return { items: [], error: `ransomware_merged_build_failed: ${(e as Error).message}` };
    }
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
    return { items: [], error: 'host_not_in_allowlist' };
  }

  // Explicit edge-cache lookup BEFORE the upstream fetch. Both caches.default
  // ops AND fetch() count against Cloudflare's 50-subrequest-per-invocation
  // budget — so the win here is NOT "free", it's that a warm read costs ONE
  // cheap cache match instead of a slow upstream fetch (+ up to 4 redirect
  // hops + a write-back put). That's still ~1 subrequest per warm feed, which
  // is why the caller must bound the feed count (MAX_FEEDS). This is the fix
  // for the "every Google News feed times out under load" pattern: once any
  // visitor warmed the cache, the slow upstream is bypassed until TTL expires.
  // Synthetic internal URL as the cache key — pattern used elsewhere in
  // the codebase (lib/cache.ts ProviderCache). `s-maxage` on the cached
  // Response is what actually makes Cloudflare's edge cache honor TTL.
  const edgeCache = (caches as unknown as { default: Cache }).default;
  const edgeKey = new Request(`https://feeds-perurl-cache.internal/v3?u=${encodeURIComponent(url)}&p=${perSource}`);
  try {
    const hit = await edgeCache.match(edgeKey);
    if (hit) {
      const body = await hit.text();
      const items = parseFeedBody(body, url, parsed.hostname, perSource);
      if (items.length > 0) return { items };
      // Empty parse on cached body falls through to a fresh fetch — but
      // only once, since the next put will overwrite this key.
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* edge-cache miss / parse fail; fall through to live fetch */
  }

  // Resolve upstream: bleepingComputer.com 403s datacenter egress, so
  // fetch its Google News mirror instead (still parsed under the original
  // host so items keep `source: bleepingcomputer.com` and sections work).
  const upstreamUrl = BLEEPING_COMPUTER_HOST_RE.test(parsed.hostname) ? BLEEPING_COMPUTER_MIRROR : url;

  try {
    // Retry transient 429/5xx — several upstreams (hnrss.org, ycombinator,
    // some vendor blogs) rate-limit the shared Worker IP; one miss used to
    // silently drop the whole feed for the visit.
    const fetchInit = {
      // Manual redirect handling — see the per-hop re-validation loop below.
      redirect: 'manual' as const,
      headers: {
        'user-agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-rss/1.0 Safari/537.36',
        accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
        'accept-language': 'en-US,en;q=0.9',
      },
      // Only edge-cache SUCCESSFUL responses. With a blanket `cacheTtl`,
      // `cacheEverything` also caches 4xx/5xx — so a transient 403 (several
      // origins, e.g. ccb.belgium.be, are Cloudflare-fronted and intermittently
      // challenge our datacenter egress IP) got pinned for the whole TTL,
      // surfacing as a stuck `http_403` badge even though a fresh fetch
      // succeeds. `cacheTtlByStatus` with 0 for error buckets re-fetches them.
      cf: {
        cacheTtlByStatus: { '200-299': CACHE_TTL_SECONDS, '300-399': 0, '400-599': 0 },
        cacheEverything: true,
      },
    } as RequestInit;
    // attempts: 1 — Cloudflare Workers have a 50-subrequest limit per
    // invocation; 3 retries × 54 feeds blew the budget. One attempt per feed
    // keeps us well under the cap; the 30s edge cache catches the next visit.
    const resilientOpts = { attempts: 1, timeoutMs: FETCH_TIMEOUT_MS };

    // Follow redirects MANUALLY, re-validating every hop's host against the
    // allow-list. An allow-listed origin with an open redirect could otherwise
    // bounce `redirect:'follow'` to an arbitrary internal/private target,
    // defeating the allow-list (SSRF-2). Hop count is bounded.
    let currentUrl = upstreamUrl;
    let res = await fetchResilient(currentUrl, fetchInit, resilientOpts);
    for (let hop = 0; hop < 4 && res.status >= 300 && res.status < 400; hop++) {
      const location = res.headers.get('location');
      if (!location) break;
      let next: URL;
      try {
        next = new URL(location, currentUrl);
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return { items: [], error: 'redirect_malformed' };
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return { items: [], error: 'redirect_unsupported_protocol' };
      }
      if (!ALLOWED_HOSTS.has(next.hostname.toLowerCase())) {
        return { items: [], error: 'redirect_not_allowlisted' };
      }
      if (res.body) void safeNull(res.body.cancel());
      currentUrl = next.toString();
      res = await fetchResilient(currentUrl, fetchInit, resilientOpts);
    }
    if (res.status >= 300 && res.status < 400) {
      return { items: [], error: 'too_many_redirects' };
    }
    if (res.status === 429) {
      return { items: [], error: 'rate_limited_429' };
    }
    if (!res.ok) return { items: [], error: `http_${res.status}` };
    const body = await res.text();
    const items = parseFeedBody(body, url, parsed.hostname, perSource);
    if (items.length === 0) return { items: [], error: 'parser_zero_items' };
    // Write-through the per-URL edge cache so the next reader skips the slow
    // upstream fetch + redirect chain (the match still costs ~1 subrequest,
    // but it's local and fast vs the timeout-prone origin). This is the remedy
    // for the Krebs / Web3 / rekt.news / Google News timeouts — once any
    // visitor warms the cache, subsequent readers see them as instant hits.
    try {
      // `s-maxage` is the edge-cache directive Cloudflare's caches.default
      // honors; `max-age` alone is browser/client only. Without s-maxage,
      // the put silently succeeds but match() returns null (verified via
      // load test where successive warm requests still re-fetched all
      // upstreams). This is the actual fix.
      const cacheable = new Response(body, {
        status: 200,
        headers: {
          'content-type': res.headers.get('content-type') ?? 'application/xml; charset=utf-8',
          'cache-control': `public, max-age=${PER_URL_CACHE_TTL_SECONDS}, s-maxage=${PER_URL_CACHE_TTL_SECONDS}`,
        },
      });
      await edgeCache.put(edgeKey, cacheable);
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* cache put failures are non-fatal */
    }
    return { items };
  } catch (e) {
    logError('handler failed', e);
    const msg = (e as Error).message || String(e);
    if (msg.toLowerCase().includes('abort') || msg.toLowerCase().includes('timeout')) {
      return { items: [], error: 'timeout' };
    }
    return { items: [], error: `fetch_failed: ${msg.slice(0, 60)}` };
  }
}

/**
 * Run `tasks` concurrently and return the results that resolved within
 * `deadlineMs`. Slots still pending at the deadline come back as `undefined`
 * — the caller treats those as "didn't return this pass". A non-positive or
 * absent deadline waits for every task (legacy all-or-nothing behaviour).
 *
 * This is what lets a fan-out caller (the /api/v1/snapshot tech/AI card)
 * render the feeds that DID respond instead of failing the whole card when
 * one cold-cache upstream is slow: the snapshot's 8s per-source budget no
 * longer has to choose between waiting ~20s for the slowest feed or
 * discarding the five fast ones. The slow feed's own fetch (and its
 * write-through edge-cache warm) keeps running to completion in the
 * background of the same invocation, so the next reader gets it warm.
 */
export async function collectWithinDeadline<T>(
  tasks: Array<Promise<T>>,
  deadlineMs?: number
): Promise<Array<T | undefined>> {
  const results: Array<T | undefined> = new Array(tasks.length).fill(undefined);
  const tracked = tasks.map((p, i) =>
    p
      .then((v) => {
        results[i] = v;
      })
      .catch(() => {
        /* leave slot undefined */
      })
  );
  if (!deadlineMs || deadlineMs <= 0) {
    await Promise.allSettled(tracked);
    return results;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, deadlineMs);
  });
  await Promise.race([Promise.allSettled(tracked), deadline]);
  if (timer) clearTimeout(timer);
  return results;
}

/**
 * Pure-data aggregator exposed for /api/v1/snapshot. Same logic as the HTTP
 * handler but returns the body directly so the snapshot endpoint can
 * compose without a worker-internal HTTP call.
 *
 * `opts.deadlineMs` caps how long to wait for the per-feed fan-out before
 * returning whatever completed — set it BELOW the snapshot's per-source
 * budget so a single slow feed degrades to "missing from this pass" rather
 * than timing out the entire card. Omit it to wait for every feed.
 */
export async function aggregateFeeds(
  urls: string[],
  limit: number = DEFAULT_LIMIT,
  perSource: number = DEFAULT_PER_SOURCE,
  opts?: { deadlineMs?: number }
): Promise<AggregateResponse> {
  const cleanUrls = urls
    .map((u) => u.trim())
    .filter(Boolean)
    .slice(0, MAX_FEEDS);
  const cappedLimit = Math.min(limit || DEFAULT_LIMIT, MAX_LIMIT);
  const cappedPerSource = Math.min(perSource || DEFAULT_PER_SOURCE, MAX_PER_SOURCE);

  const settled = await collectWithinDeadline(
    cleanUrls.map((u) => fetchOne(u, cappedPerSource)),
    opts?.deadlineMs
  );
  const allItems: AggregatedItem[] = [];
  let feedsReturned = 0;
  for (const r of settled) {
    if (r && r.items.length > 0) {
      feedsReturned += 1;
      allItems.push(...r.items);
    }
  }

  allItems.sort((a, b) => {
    const da = new Date(a.pubDate).getTime() || 0;
    const db = new Date(b.pubDate).getTime() || 0;
    return db - da;
  });
  // 7d cutoff. Items with no parseable pubDate are kept (some feeds strip
  // dates — better to surface them than to silently drop them).
  const cutoffMs = Date.now() - 7 * 86_400_000;
  const recentItems = allItems.filter((it) => {
    const t = new Date(it.pubDate).getTime();
    return !Number.isFinite(t) || t === 0 || t >= cutoffMs;
  });

  return {
    generated_at: new Date().toISOString(),
    total_items: recentItems.length,
    feeds_attempted: cleanUrls.length,
    feeds_returned: feedsReturned,
    items: recentItems.slice(0, cappedLimit),
  };
}

export async function feedsAggregateHandler(c: Context<{ Bindings: Env }>) {
  const urlsParam = c.req.query('urls');
  if (!urlsParam) return badRequest(c, 'missing urls param');

  const urls = urlsParam
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean)
    .slice(0, MAX_FEEDS);
  if (urls.length === 0) return badRequest(c, 'no valid urls');

  const limit = Math.min(parseInt(c.req.query('limit') ?? `${DEFAULT_LIMIT}`, 10) || DEFAULT_LIMIT, MAX_LIMIT);
  const perSource = Math.min(
    parseInt(c.req.query('perSource') ?? `${DEFAULT_PER_SOURCE}`, 10) || DEFAULT_PER_SOURCE,
    MAX_PER_SOURCE
  );

  // Cache the aggregated response in the Cache API too (key by query string).
  // 1-min cache so the page feels instant on subsequent loads but stays fresh.
  const cache = caches.default;
  const cacheKey = new Request(
    `https://feeds-agg.internal/?urls=${encodeURIComponent(urlsParam)}&limit=${limit}&perSource=${perSource}`
  );
  const cached = await cache.match(cacheKey);
  if (cached) {
    return new Response(cached.body, {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': 'public, max-age=60',
        'x-cache': 'HIT',
      },
    });
  }

  const settled = await Promise.allSettled(urls.map((u) => fetchOne(u, perSource, c.env)));
  const allItems: AggregatedItem[] = [];
  let feedsReturned = 0;
  const feedStatuses: FeedSourceStatus[] = [];
  for (let i = 0; i < settled.length; i += 1) {
    const s = settled[i]!;
    const url = urls[i] ?? '';
    if (s.status === 'fulfilled') {
      const { items, error } = s.value;
      if (items.length > 0) {
        feedsReturned += 1;
        allItems.push(...items);
        feedStatuses.push({ url, ok: true, items: items.length });
      } else {
        feedStatuses.push({ url, ok: false, items: 0, error: error ?? 'empty_response' });
      }
    } else {
      const reason = s.reason instanceof Error ? s.reason.message : String(s.reason);
      feedStatuses.push({ url, ok: false, items: 0, error: reason.slice(0, 80) });
    }
  }

  // Sort newest first, then cap globally
  allItems.sort((a, b) => {
    const da = new Date(a.pubDate).getTime() || 0;
    const db = new Date(b.pubDate).getTime() || 0;
    return db - da;
  });
  // 7d cutoff. Items with no parseable pubDate are kept (some feeds strip
  // dates — better to surface them than to silently drop them).
  const cutoffMs = Date.now() - 7 * 86_400_000;
  const recentItems = allItems.filter((it) => {
    const t = new Date(it.pubDate).getTime();
    return !Number.isFinite(t) || t === 0 || t >= cutoffMs;
  });

  const body: AggregateResponse = {
    generated_at: new Date().toISOString(),
    total_items: recentItems.length,
    feeds_attempted: urls.length,
    feeds_returned: feedsReturned,
    items: recentItems.slice(0, limit),
    feeds: feedStatuses,
  };
  const json = JSON.stringify(body);
  const response = new Response(json, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'public, max-age=60',
      'x-cache': 'MISS',
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
