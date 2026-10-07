/**
 * cvemon (Intruder) CVE trends feed.
 *
 * https://cvemon.intruder.io/rss/cvetrends/latest — "the latest rankings and
 * info for CVEs currently trending on social media".
 *
 * This is the only source in the stack that measures attention rather than
 * technical severity. NVD tells you how bad a CVE is; KEV tells you whether
 * it is being exploited; EPSS tells you how likely it is to be. None of them
 * tell you what practitioners are actually talking about this week, which is
 * the signal that tells you where to point the writing.
 *
 * Two reasons it is a good fit for the content pipeline:
 *
 *  - Every entry is a real CVE with a real NVD record behind it, so a trend
 *    hit can be promoted straight into a research dossier with a CVE lookup
 *    and a source fetch — no fabrication risk at all.
 *  - The hype score is a genuine lead-time signal. A CVE trending before it
 *    reaches KEV is the interesting case.
 *
 * The feed uses an `intruder:` XML namespace for rank / hypeScore / cveUrl
 * and CDATA for every text node, so a plain regex parser has to handle both.
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import { readLastGood, writeLastGood } from './lastgood';

const FEED_URL = 'https://cvemon.intruder.io/rss/cvetrends/latest';
const USER_AGENT = 'pranithjain.qzz.io cve-trends (+https://pranithjain.qzz.io/about)';
const FETCH_TIMEOUT_MS = 8000;

export interface CveTrend {
  /** CVE id, always uppercase, e.g. CVE-2026-88779. */
  id: string;
  /** Position in the trending list, 1 = most discussed. */
  rank: number;
  /** Intruder's hype score. Higher = more social discussion. */
  hypeScore: number;
  /** Description as published, with the "Currently trending CVE - Hype Score"
   *  prefix stripped. */
  description: string;
  /** Intruder's own detail page for this CVE. */
  cveUrl: string;
  /** Feed publication time (ISO). All items share the build time. */
  publishedAt: string;
}

export interface CveTrendsResult {
  generated_at: string;
  source: { id: string; url: string; ok: boolean; count: number };
  count: number;
  /** True when the fetch failed and `cves` came from cache or is empty. */
  stale: boolean;
  cves: CveTrend[];
}

const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/i;

/** Strip CDATA wrappers and decode the handful of entities these feeds use. */
function unwrap(raw: string | undefined): string {
  if (!raw) return '';
  return raw
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, '&')
    .trim();
}

/**
 * Pull one tag's text from an item block. Handles the namespaced
 * `intruder:hypeScore` form as well as a bare tag.
 */
function tag(block: string, name: string): string {
  const re = new RegExp(`<(?:[a-z0-9]+:)?${name}[^>]*>([\\s\\S]*?)</(?:[a-z0-9]+:)?${name}>`, 'i');
  return unwrap(block.match(re)?.[1]);
}

/** "Currently trending CVE - Hype Score: 8 - real description text" → the tail. */
function cleanDescription(raw: string, hypeScore: number): string {
  let d = raw;
  // Strip the feed's own prefix, however many variants of it appear.
  d = d.replace(/^Currently trending CVE\s*[-–—:]*\s*/i, '');
  d = d.replace(new RegExp(`Hype Score\\s*:?\\s*${hypeScore}\\s*[-–—:]\\s*`, 'i'), '');
  // Some entries drop the prefix but keep a dangling separator.
  d = d.replace(/^[-–—:]\s*/, '');
  // The source truncates mid-word with "..."; keep it but normalise spacing.
  return d
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Parse the feed XML. Exported for unit tests with fixture strings.
 *
 * Returns [] rather than throwing on malformed input — a broken feed should
 * degrade the CVE intel page, never break it.
 */
export function parseCvemonFeed(xml: string): CveTrend[] {
  const channelDate = unwrap(
    xml.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i)?.[1] ??
      xml.match(/<lastBuildDate[^>]*>([\s\S]*?)<\/lastBuildDate>/i)?.[1] ??
      ''
  );
  const channelTs = channelDate ? new Date(channelDate) : null;
  const channelIso = channelTs && !Number.isNaN(channelTs.getTime()) ? channelTs.toISOString() : '';

  const out: CveTrend[] = [];
  const blocks = xml.match(/<item[\s\S]*?<\/item>/gi) ?? [];
  const seen = new Set<string>();

  for (const block of blocks) {
    // <title> is exactly the CVE id on this feed, so try it first.
    const title = unwrap(block.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]).toUpperCase();
    let id = CVE_ID_RE.test(title) ? title : (title.match(/\bCVE-\d{4}-\d{4,7}\b/i)?.[0]?.toUpperCase() ?? '');

    // Fall back to the item's own links, but ONLY when they point at cvemon's
    // own /cves/ path. Without that host check, a link to any third-party page
    // mentioning a CVE would make a non-CVE headline parse as a CVE entry.
    if (!id) {
      const link =
        tag(block, 'cveUrl') || unwrap(block.match(/<link[^>]*>([\s\S]*?)<\/link>/i)?.[1]) || tag(block, 'guid');
      if (/cvemon\.intruder\.io\/cves\//i.test(link)) {
        id = link.match(/\bCVE-\d{4}-\d{4,7}\b/i)?.[0]?.toUpperCase() ?? '';
      }
    }

    if (!id || !CVE_ID_RE.test(id) || seen.has(id)) continue;
    seen.add(id);

    const rank = Number.parseInt(tag(block, 'rank'), 10);
    const hype = Number.parseInt(tag(block, 'hypeScore'), 10);
    const description = cleanDescription(tag(block, 'description'), Number.isFinite(hype) ? hype : -1);
    const itemDate = unwrap(block.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i)?.[1]);

    out.push({
      id,
      rank: Number.isFinite(rank) ? rank : out.length + 1,
      hypeScore: Number.isFinite(hype) ? hype : 0,
      description,
      cveUrl: tag(block, 'cveUrl') || unwrap(block.match(/<link[^>]*>([\s\S]*?)<\/link>/i)?.[1]) || '',
      publishedAt:
        itemDate && !Number.isNaN(new Date(itemDate).getTime()) ? new Date(itemDate).toISOString() : channelIso,
    });
  }

  return out.sort((a, b) => a.rank - b.rank);
}

/** Cache-API key. Bumped when the parse shape changes. */
export const CVE_TRENDS_CACHE_KEY = 'https://cvemon.intruder.io/rss/cvetrends/latest/cached/v1';
/** Cross-colo last-good slot, written through `writeLastGood`. */
const LASTGOOD_KEY = 'cve-trends/cvemon/v1';
const CACHE_TTL_SECONDS = 30 * 60;

interface SelfFetcher {
  fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response>;
}

export interface FetchCveTrendsEnv {
  SELF?: SelfFetcher;
  /** Cross-colo last-good slot. Optional: degrades to Cache-API only. */
  KV_CACHE?: KVNamespace;
  /** skipCache forces a live fetch (used by the discovery cron, which wants
   *  fresh rankings rather than a possibly-stale cached page). */
  skipCache?: boolean;
}

/**
 * Fetch + cache the trending CVEs.
 *
 * Three-layer cache, matching the rest of the CVE surfaces: Cache-API
 * (per-colo, fast), KV (cross-colo last-good), then the network. A failed
 * fetch falls back to KV rather than returning an empty list, so a cvemon
 * outage degrades the page instead of blanking it.
 */
export async function fetchCveTrends(env: FetchCveTrendsEnv = {}): Promise<CveTrendsResult> {
  const nowIso = new Date().toISOString();
  const fallback = (cves: CveTrend[], stale: boolean, ok: boolean): CveTrendsResult => ({
    generated_at: nowIso,
    source: { id: 'cvemon', url: FEED_URL, ok, count: cves.length },
    count: cves.length,
    stale,
    cves,
  });

  // Cache-API layer.
  const cacheApi = (caches as unknown as { default?: Cache }).default;
  const cacheKey = new Request(CVE_TRENDS_CACHE_KEY);
  if (!env.skipCache && cacheApi) {
    const hit = await cacheApi.match(cacheKey).catch(() => undefined);
    if (hit) {
      try {
        const data = (await hit.json()) as CveTrend[];
        return fallback(data, false, true);
      } catch {
        /* fall through */
      }
    }
  }

  // Network.
  let parsed: CveTrend[] = [];
  let ok = true;
  try {
    const res = await fetch(FEED_URL, {
      headers: { 'user-agent': USER_AGENT, accept: 'application/rss+xml, application/xml, text/xml' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`http ${res.status}`);
    parsed = parseCvemonFeed(await res.text());
    if (parsed.length === 0) throw new Error('no items parsed');
  } catch {
    ok = false;
    parsed = [];
  }

  if (ok) {
    if (cacheApi) {
      // `caches.default` in the Workers runtime accepts CacheOptions; the
      // bundled TS lib types only declare the 2-arg overload, so cast.
      const cacheWithOpts = cacheApi as Cache & {
        put: (req: Request, res: Response, opts: { expirationTtl: number }) => Promise<void>;
      };
      await cacheWithOpts
        .put(cacheKey, new Response(JSON.stringify(parsed), { headers: { 'content-type': 'application/json' } }), {
          expirationTtl: CACHE_TTL_SECONDS,
        })
        .catch(() => {});
    }
    // Cross-colo last-good via the shared helper: it debounces writes, keeps a
    // Cache-API shadow in sync, and stays inside the repo's raw-KV rule.
    await writeLastGood({ KV_CACHE: env.KV_CACHE }, LASTGOOD_KEY, parsed as unknown as Record<string, unknown>);
    return fallback(parsed, false, true);
  }

  // Network failed — serve the cross-colo last-good, marked stale. A stale
  // trending list is not neutral: it reads as "nothing is trending", so the
  // response carries `stale: true` and the admin probe reports it as degraded.
  const cached = await readLastGood<unknown>({ KV_CACHE: env.KV_CACHE }, LASTGOOD_KEY).catch(() => null);
  if (Array.isArray(cached) && cached.length > 0) return fallback(cached as CveTrend[], true, false);
  return fallback([], true, false);
}
