import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';

/**
 * Cybersec social-media firehose at /api/v1/x-feed.
 *
 * Endpoint kept named 'x-feed' for compatibility with the existing
 * /threatintel/x route. Implementation pivoted 2026-05-11 — Nitter
 * mirrors all block Cloudflare's egress IPs as scrapers, so the prior
 * attempt to pull X via Nitter returned 0 of 12 handles consistently.
 *
 * Many of the same cybersec researchers + vendor accounts have moved
 * to Bluesky and Mastodon (infosec.exchange) since X killed the free
 * read API in 2023. Both expose proper, keyless RSS — Bluesky at
 * bsky.app/profile/<handle>/rss and Mastodon at
 * <instance>/@<handle>.rss.
 *
 * The handle set is HAND-PROBED — each was verified 200 OK with actual
 * content (not the 404-shell that Bluesky returns for unknown profiles).
 */

const FETCH_TIMEOUT_MS = 9_000;
const CACHE_TTL = 60 * 60;
const CONCURRENCY = 4;
// Per-handle cap. Bumped 6 → 25 alongside the cross-platform "show last
// 500 items OR 7 days" upgrade. Bluesky + Mastodon RSS feeds typically
// return 20-50 posts per fetch — 25 is the realistic ceiling without
// paginated chaining and keeps a single handle from dominating the page.
const MAX_POSTS_PER_HANDLE = 25;
const MAX_TEXT_LEN = 400;

type Platform = 'bluesky' | 'mastodon';

interface HandleSpec {
  platform: Platform;
  /** Full handle as the platform writes it (bsky.app domain, mastodon @user). */
  handle: string;
  /** Display name. */
  name: string;
  blurb: string;
  topic: 'research' | 'news' | 'vendor' | 'gov' | 'malware';
  /**
   * Optional Mastodon instance host override. Defaults to infosec.exchange
   * (where most cybersec accounts live). Some accounts are on other servers
   * — e.g. cyberplace.social hosts a fedi-cybersec community.
   */
  instance?: string;
}

/**
 * Curated cybersec accounts on Bluesky + Mastodon (infosec.exchange).
 * All verified live 2026-05-11.
 */
const HANDLES: HandleSpec[] = [
  // Bluesky — cybersec researchers + vendor labs
  {
    platform: 'bluesky',
    handle: 'malwaretech.com',
    name: 'Marcus Hutchins',
    blurb: 'WannaCry kill-switch — malware research',
    topic: 'research',
  },
  {
    platform: 'bluesky',
    handle: 'thedfirreport.bsky.social',
    name: 'The DFIR Report',
    blurb: 'Real intrusion case-studies',
    topic: 'research',
  },
  {
    platform: 'bluesky',
    handle: 'talosintelligence.com',
    name: 'Cisco Talos',
    blurb: 'Cisco Talos threat research',
    topic: 'vendor',
  },
  {
    platform: 'bluesky',
    handle: 'mandiant.com',
    name: 'Mandiant',
    blurb: 'Mandiant / Google Cloud threat research',
    topic: 'vendor',
  },
  {
    platform: 'bluesky',
    handle: 'huntress.com',
    name: 'Huntress',
    blurb: 'Huntress threat lab + IR write-ups',
    topic: 'vendor',
  },
  {
    platform: 'bluesky',
    handle: 'sentinelone.com',
    name: 'SentinelOne',
    blurb: 'SentinelLabs malware + APT research',
    topic: 'vendor',
  },
  // vxunderground.bsky.social was dropped 2026-05-11 — Bluesky RSS returned
  // 187 bytes with zero items (account dormant). The Mastodon variant
  // (@vxunderground@infosec.exchange) is healthy and remains below.
  {
    platform: 'bluesky',
    handle: 'swiftonsecurity.bsky.social',
    name: 'SwiftOnSecurity',
    blurb: 'Security tradecraft + commentary',
    topic: 'research',
  },
  // Added 2026-10-03 — each verified live via the AT Protocol API (post count
  // + newest post date) rather than guessed from a name.
  {
    platform: 'bluesky',
    handle: 'threatintel.microsoft.com',
    name: 'Microsoft Threat Intelligence',
    blurb: 'MSTI — nation-state campaigns + advisories',
    topic: 'vendor',
  },
  {
    platform: 'bluesky',
    handle: 'kosh38.bsky.social',
    name: 'Shane Huntley',
    blurb: 'Google TAG — nation-state research, counter-intel',
    topic: 'research',
  },
  {
    platform: 'bluesky',
    handle: 'pulsedive.com',
    name: 'Pulsedive',
    blurb: 'IOC enrichment + community threat scoring',
    topic: 'vendor',
  },
  {
    platform: 'bluesky',
    handle: 'hegel.bsky.social',
    name: 'Tom Hegel',
    blurb: 'Threat-intel commentary + tooling notes',
    topic: 'research',
  },
  // Added 2026-10-03 (batch 2) — discovered via Bluesky's own actor search,
  // then each verified live via the AT Protocol API for post count AND
  // newest-post date. The "APT"/"CVE" searches return heavy false positives
  // (apartment, apt-cache, …) so every candidate was checked by hand.
  {
    platform: 'bluesky',
    handle: 'mindthegaap.bsky.social',
    name: 'Matthew Gardner',
    blurb: 'Threat hunting + detection write-ups',
    topic: 'research',
  },
  {
    platform: 'bluesky',
    handle: 'righto.com',
    name: 'Ken Shirriff',
    blurb: 'Reverse engineering — disassembly, firmware, x86',
    topic: 'research',
  },
  {
    platform: 'bluesky',
    handle: 'hexacorn.bsky.social',
    name: 'Hexacorn',
    blurb: 'Co-author of the CISA malware analysis catalog',
    topic: 'research',
  },
  {
    platform: 'bluesky',
    handle: 'richinseattle.bsky.social',
    name: 'Richard Johnson',
    blurb: 'Malwarebytes — commodity malware + tooling',
    topic: 'research',
  },

  // Mastodon — infosec.exchange (the de-facto cybersec instance)
  {
    platform: 'mastodon',
    handle: 'briankrebs',
    name: 'Brian Krebs',
    blurb: 'KrebsOnSecurity author — breach reporting',
    topic: 'news',
  },
  {
    platform: 'mastodon',
    handle: 'GossiTheDog',
    instance: 'cyberplace.social',
    name: 'Kevin Beaumont',
    blurb: 'Live exploitation tracking — DoublePulsar',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'campuscodi',
    instance: 'mastodon.social',
    name: 'Catalin Cimpanu',
    blurb: 'Risky Biz News — daily cyber news',
    topic: 'news',
  },
  {
    platform: 'mastodon',
    handle: 'malwaretech',
    name: 'Marcus Hutchins (Mastodon)',
    blurb: 'Marcus on Mastodon — same content',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'cyb3rops',
    name: 'Florian Roth',
    blurb: 'Signature-base / YARA author — Sigma maintainer',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'mttaggart',
    name: 'Matt Taggart',
    blurb: 'Detection engineering + threat hunting',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'x0rz',
    name: '@x0rz',
    blurb: 'IOC drops + threat-actor commentary',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'vxunderground',
    name: 'vx-underground (Mastodon)',
    blurb: 'Sample drops + research commentary',
    topic: 'research',
  },

  // Added 2026-10-03 (batch 2) — Mastodon's account-search API requires auth
  // on infosec.exchange and cyberplace.social, so these were discovered by
  // walking Kevin Beaumont's federated follow graph (a public endpoint on
  // cyberplace.social, which returns accounts across every instance) and then
  // verifying each one's RSS for item count and newest-post date. Every entry
  // below returned 20 live items on 2026-10-03.
  {
    platform: 'mastodon',
    handle: 'watchTowr',
    name: 'watchTowr Labs',
    blurb: 'Vulnerability research + offensive tooling releases',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'dotdotslash_bot',
    name: 'dotdotslash_bot',
    blurb: 'Bot — new directory-traversal CVEs as they land',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'hardcoded_bot',
    name: 'hardcoded_bot',
    blurb: 'Bot — newly disclosed hardcoded credentials',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'rebane2001',
    name: 'rebane2001',
    blurb: 'Browser sandbox internals — Chrome CVEs, exploitation research',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'gadi',
    name: 'Gadi Evron',
    blurb: 'CISO-in-residence — AI threat landscape, incident response',
    topic: 'news',
  },
  {
    platform: 'mastodon',
    handle: 'cert_eu',
    name: 'CERT-EU',
    blurb: 'EU institutional CERT advisories',
    topic: 'gov',
  },
  {
    platform: 'mastodon',
    handle: 'kev_Stalker',
    name: 'KEV Ransomware Flip Monitor',
    blurb: 'Bot — watches the CISA KEV JSON for silent flips',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'hacksilon',
    name: 'Max Maass',
    blurb: 'Security research — exploitation + tooling',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'realhackhistory',
    instance: 'chaos.social',
    name: 'hack.history',
    blurb: 'History of phreaking and intrusion culture',
    topic: 'research',
  },
  {
    platform: 'mastodon',
    handle: 'mayahustle',
    name: 'Jimmy Wylie',
    blurb: 'Malware analyst — commodity loaders, botnets',
    topic: 'malware',
  },
  // Removed 2026-10-18: these three handles consistently returned 0 items
  // from the Worker's egress even though their RSS feeds are valid from a
  // normal client (infosec.exchange / mastodon.social block or rate-limit
  // the Workers egress IP for these accounts). Re-add if the upstream
  // behaviour changes.
  //   gayint, DailyCyberSecurity (infosec.exchange), David_Hollingworth (mastodon.social)
];

export interface XFeedItem {
  handle: string;
  handle_name: string;
  handle_topic: HandleSpec['topic'];
  handle_blurb: string;
  platform: Platform;
  text: string;
  link: string;
  pub_date: string;
}

export interface XFeedResponse {
  generated_at: string;
  handles: {
    handle: string;
    name: string;
    platform: Platform;
    topic: HandleSpec['topic'];
    ok: boolean;
    count: number;
  }[];
  items: XFeedItem[];
  warnings: string[];
}

function stripCdata(s: string): string {
  return s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
}

function decodeEntities(s: string): string {
  return (
    s
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&nbsp;/g, ' ')
      // Generic decimal numeric entities (Mastodon emits &#34; &#39; &#10; etc.)
      .replace(/&#(\d+);/g, (_, code: string) => {
        const n = parseInt(code, 10);
        return Number.isFinite(n) && n >= 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
      })
      // Generic hex numeric entities (&#xA; for newline etc.)
      .replace(/&#x([0-9a-fA-F]+);/g, (_, code: string) => {
        const n = parseInt(code, 16);
        return Number.isFinite(n) && n >= 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
      })
  );
}

function stripHtml(s: string): string {
  // Mastodon's RSS double-encodes HTML inside <description> (so `<p>foo</p>`
  // comes through as `&lt;p&gt;foo&lt;/p&gt;`). Decoding entities FIRST
  // gives us real tags that the regex passes can then strip; otherwise the
  // user sees literal "<p>foo</p>" in the rendered text.
  const decoded = decodeEntities(s);
  return decoded
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<p[^>]*>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .trim();
}

/** Both Bluesky + Mastodon use RSS 2.0 with <item>. Parsing is shared. */
function parseRssItems(xml: string): Array<{ title: string; description: string; link: string; pub_date: string }> {
  const out: Array<{ title: string; description: string; link: string; pub_date: string }> = [];
  const itemRe = /<item[^>]*>([\s\S]*?)<\/item>/g;
  let m: RegExpExecArray | null;
  while ((m = itemRe.exec(xml)) !== null) {
    const block = m[1];
    if (!block) continue;
    const title = /<title[^>]*>([\s\S]*?)<\/title>/.exec(block)?.[1] ?? '';
    const description = /<description[^>]*>([\s\S]*?)<\/description>/.exec(block)?.[1] ?? '';
    const link = /<link[^>]*>([\s\S]*?)<\/link>/.exec(block)?.[1] ?? '';
    const pub = /<pubDate[^>]*>([^<]+)<\/pubDate>/.exec(block)?.[1] ?? '';
    if (!link) continue;
    out.push({
      title: decodeEntities(stripCdata(title)).trim(),
      description: stripHtml(stripCdata(description)),
      link: link.trim(),
      pub_date: pub.trim(),
    });
  }
  return out;
}

function rssUrl(spec: HandleSpec): string {
  if (spec.platform === 'bluesky') return `https://bsky.app/profile/${encodeURIComponent(spec.handle)}/rss`;
  const instance = spec.instance ?? 'infosec.exchange';
  return `https://${instance}/@${encodeURIComponent(spec.handle)}.rss`;
}

/** Fetch Bluesky posts via the AT Protocol (public, keyless) API.
 *  Fallback when the deprecated RSS endpoint returns stale/empty data. */
async function fetchBlueskyApi(spec: HandleSpec): Promise<{ ok: boolean; items: XFeedItem[] }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const url = `https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=${encodeURIComponent(spec.handle)}&limit=${MAX_POSTS_PER_HANDLE}`;
    const r = await fetch(url, {
      signal: ctrl.signal,
      headers: { accept: 'application/json' },
    });
    clearTimeout(timer);
    if (!r.ok) return { ok: false, items: [] };
    const body = (await r.json()) as {
      feed?: Array<{
        post: {
          uri: string;
          author: { handle: string; displayName?: string };
          record: { text: string; createdAt: string; embed?: unknown };
          likeCount?: number;
          repostCount?: number;
          replyCount?: number;
        };
      }>;
    };
    if (!body.feed) return { ok: false, items: [] };
    const items: XFeedItem[] = body.feed
      .filter((f) => f.post?.record?.text && f.post?.uri)
      .map((f) => ({
        handle: spec.handle,
        handle_name: spec.name,
        handle_topic: spec.topic,
        handle_blurb: spec.blurb,
        platform: 'bluesky' as Platform,
        text: (f.post.record.text || '').slice(0, MAX_TEXT_LEN),
        link: f.post.uri,
        pub_date: f.post.record.createdAt,
      }));
    return { ok: items.length > 0, items };
  } catch (_catchErr) {
    logError('bsky-api failed', _catchErr);
    clearTimeout(timer);
    return { ok: false, items: [] };
  }
}

async function fetchHandle(spec: HandleSpec): Promise<{ ok: boolean; items: XFeedItem[] }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const r = await fetch(rssUrl(spec), {
      signal: ctrl.signal,
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)',
        accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5',
      },
      redirect: 'follow',
      // NOTE: previously `cf: { cacheTtl: 1800, cacheEverything: true }`.
      // cacheEverything pinned stale/empty responses at the edge (several
      // handles reported `ok:false` with 0 items for hours even though their
      // feeds had content), so it's dropped — the manual edge cache in the
      // handler is sufficient.
    });
    clearTimeout(timer);
    if (r.ok) {
      const body = await r.text();
      if (body.includes('<rss') || body.includes('<channel>')) {
        const parsed = parseRssItems(body).slice(0, MAX_POSTS_PER_HANDLE);
        const items: XFeedItem[] = parsed
          .filter((p) => p.link)
          .map((p) => ({
            handle: spec.handle,
            handle_name: spec.name,
            handle_topic: spec.topic,
            handle_blurb: spec.blurb,
            platform: spec.platform,
            text: (p.description || p.title || '').slice(0, MAX_TEXT_LEN),
            link: p.link,
            pub_date: p.pub_date,
          }));
        return { ok: items.length > 0, items };
      }
    }
    // RSS failed or returned empty — try AT Protocol API for Bluesky
    if (spec.platform === 'bluesky') {
      return fetchBlueskyApi(spec);
    }
    return { ok: false, items: [] };
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    clearTimeout(timer);
    // Last-resort fallback for Bluesky
    if (spec.platform === 'bluesky') return fetchBlueskyApi(spec);
    return { ok: false, items: [] };
  }
}

export async function fetchXFeed(): Promise<XFeedResponse> {
  const warnings: string[] = [];
  const handleStatus: XFeedResponse['handles'] = [];
  const allItems: XFeedItem[] = [];

  const queue = [...HANDLES];
  async function worker() {
    while (queue.length > 0) {
      const spec = queue.shift();
      if (!spec) return;
      const r = await fetchHandle(spec);
      if (!r.ok) warnings.push(`no posts for ${spec.platform}:${spec.handle}`);
      handleStatus.push({
        handle: spec.handle,
        name: spec.name,
        platform: spec.platform,
        topic: spec.topic,
        ok: r.ok,
        count: r.items.length,
      });
      allItems.push(...r.items);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  // Newest-first across all handles. Bluesky pubDate is RFC-822-ish ("11 May
  // 2026 00:56 +0000"); Mastodon is RFC-3339. Date.parse handles both.
  allItems.sort((a, b) => Date.parse(b.pub_date) - Date.parse(a.pub_date));

  return {
    generated_at: new Date().toISOString(),
    handles: handleStatus.sort((a, b) => a.name.localeCompare(b.name)),
    items: allItems,
    warnings,
  };
}

export const X_FEED_CACHE_KEY = 'https://x-feed-cache.internal/v9-25pc';

export async function xFeedHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(X_FEED_CACHE_KEY);
  const cached = await cache.match(cacheKey);
  if (cached) {
    // Stale-while-revalidate: serve the cached copy immediately, then
    // refresh in the background if it's older than 80% of the TTL. The
    // x-feed fetches 16 Bluesky/Mastodon handles (CONCURRENCY=4) which
    // takes ~14s cold — SWR keeps the page fast for every visitor after
    // the first.
    const cacheDate = cached.headers.get('date');
    const age = cacheDate ? (Date.now() - new Date(cacheDate).getTime()) / 1000 : 0;
    if (age > CACHE_TTL * 0.8) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            const body = await fetchXFeed();
            const fresh = c.json(body, 200, {
              'Cache-Control': `public, max-age=${CACHE_TTL}, stale-while-revalidate=${CACHE_TTL * 4}`,
            });
            await cache.put(cacheKey, fresh);
          } catch {
            /* non-fatal — the stale copy stays */
          }
        })()
      );
    }
    return new Response(cached.body, cached);
  }

  const body = await fetchXFeed();
  const response = c.json(body, 200, {
    'Cache-Control': `public, max-age=${CACHE_TTL}, stale-while-revalidate=${CACHE_TTL * 4}`,
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
