import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { buildDeepDarkCti } from './deepdarkcti';
import { getTelegramFeedCacheKey, TELEGRAM_FEED_CACHE_KEY } from './telegram-feed';
import { REDDIT_FEED_CACHE_KEY } from './reddit-feed';

/**
 * Combo & stealer-forum INTELLIGENCE — strictly metadata-about, never the
 * data itself.
 *
 * This endpoint composes signals we already hold:
 *   1. deepdarkCTI directory rows for criminal forums, dark markets and
 *      infostealer/threat-actor Telegram channels (names, links, status).
 *   2. Keyword-tagged *counts + permalinks* of combolist/stealer chatter
 *      across our curated Telegram and Reddit feeds.
 *
 * HARD BOUNDARY: it surfaces only directory metadata (name, url, status)
 * and chatter pointers (source, permalink, timestamp, matched keyword). It
 * MUST NOT fetch, parse, store, or relay stolen credentials, combolists or
 * breach contents. No post body text is returned — only the fact that a
 * tracked source mentioned a tracked term, and where to read it.
 *
 * Cached 30 min — inputs are themselves cached upstream.
 */

export const STEALER_FORUM_INTEL_CACHE_KEY = 'https://stealer-forum-intel-cache.internal/v13-no-debug';
const CACHE_TTL_SECONDS = 30 * 60;
/**
 * TTL for a build whose chatter sources were missing from this colo's cache.
 * Short enough that the counters self-heal on the next request instead of
 * showing a hard 0 for half an hour. Same idea as DEGRADED_TTL_SECONDS in
 * deepdarkcti.
 */
const DEGRADED_TTL_SECONDS = 5 * 60;

/** deepdarkCTI category labels that map to combo/stealer/forum tradecraft. */
const FORUM_CATEGORIES = new Set(['Criminal Forums', 'Dark Markets', 'Infostealer Telegram', 'Threat-Actor Telegram']);

/** Combolist / stealer-log tradecraft terms. Word-ish to limit over-match. */
const STEALER_TERMS =
  /\b(combolist|combo list|ulp|url[- ]?log[- ]?pass|cloud logs?|stealer logs?|logs? cloud|fullz|redline|lumma|stealc|vidar|raccoon|rhadamanthys|meta ?stealer|risepro|lockbit logs|infostealer)\b/i;

interface ForumEntry {
  name: string;
  url: string;
  onion: boolean;
  status: string;
}
interface ForumGroup {
  category: string;
  count: number;
  entries: ForumEntry[];
}
interface ChatterSample {
  source: string;
  link: string;
  when?: string;
  keyword: string;
}
interface ChatterBlock {
  matches: number;
  samples: ChatterSample[];
}

export interface StealerForumIntelResponse {
  generated_at: string;
  forums: ForumGroup[];
  chatter: { telegram: ChatterBlock; reddit: ChatterBlock };
  totals: { tracked_sources: number; categories: number };
  /**
   * Build health. A `chatter-source-missing:<platform>` entry means that
   * platform's feed wasn't in this colo's Cache API when the payload was
   * built, so its `matches` count is 0-because-unavailable, not
   * 0-because-nothing-matched. Consumers should surface it instead of
   * rendering a bare zero.
   */
  warnings: string[];
}

async function _readCachedJson<T>(cacheKey: string): Promise<T | null> {
  try {
    const cache = (caches as unknown as { default: Cache }).default;
    const hit = await cache.match(cacheKey);
    if (!hit) return null;
    return (await hit.json()) as T;
  } catch (_catchErr) {
    logError('_readCachedJson failed', _catchErr);
    return null;
  }
}

function firstMatch(text: string): string | null {
  const m = STEALER_TERMS.exec(text);
  return m ? m[0].toLowerCase() : null;
}

export async function buildStealerForumIntel(env: Env, ctx: ExecutionContext): Promise<StealerForumIntelResponse> {
  // 1. deepdarkCTI directory — metadata rows only.
  let forums: ForumGroup[] = [];
  try {
    const ddc = await buildDeepDarkCti(env.KV_CACHE, ctx);
    const byCat = new Map<string, ForumEntry[]>();
    for (const e of ddc.entries) {
      if (!FORUM_CATEGORIES.has(e.category)) continue;
      const arr = byCat.get(e.category) ?? [];
      arr.push({ name: e.name, url: e.url, onion: e.onion, status: e.status });
      byCat.set(e.category, arr);
    }
    forums = [...byCat.entries()]
      .map(([category, entries]) => ({ category, count: entries.length, entries }))
      .sort((a, b) => b.count - a.count);
  } catch (_catchErr) {
    logError('buildStealerForumIntel failed', _catchErr);
    forums = [];
  }

  // 2. Keyword-tagged chatter — counts + pointers, never body text.
  //
  // Read both feeds from the *Cache API* — never via direct fetch() in
  // the SFI. Reasons:
  //   - The SFI build is already near the Cloudflare subrequest limit
  //     (deepdarkCTI + forums fan out to many upstream calls). A direct
  //     tg/rd fetch tips it over and the response is 500.
  //   - The telegram feed uses a *bump-aware* cache key; we resolve it
  //     via getTelegramFeedCacheKey(env) so the SFI reads the same key
  //     the feed producer wrote to (no string-vs-Request drift). We
  //     also try the base key (no bump) as a fallback in case the bump
  //     just changed and the hourly cron hasn't republished yet.
  //   - Reddit uses a static cache key. The producer wraps it in
  //     `new Request(...)` for `cache.put`; we mirror that here with
  //     `new Request(...)` for `cache.match` so the keys normalize
  //     identically (string-vs-Request mismatch has been a real cause
  //     of silent 0s in this codebase).
  const tgCache = (caches as unknown as { default: Cache }).default;
  const tgKeyReq = await getTelegramFeedCacheKey(env);
  type TgFeed = { items?: Array<{ channel_name?: string; permalink?: string; datetime?: string; text?: string }> };
  type RdFeed = {
    items?: Array<{ sub_label?: string; link?: string; pub_date?: string; title?: string; text?: string }>;
  };
  let tg: TgFeed | null = null;
  let rd: RdFeed | null = null;
  try {
    let tgMatch: Response | undefined;
    tgMatch = await tgCache.match(tgKeyReq);
    if (!tgMatch) {
      // Fall back to the base key (no bump suffix). The producer writes
      // BOTH the bump-aware key and the base key in the feed handler so
      // consumers (e.g. the stealer-forum-intel chatter counter) always
      // find data, even across a bump change.
      tgMatch = await tgCache.match(new Request(TELEGRAM_FEED_CACHE_KEY));
    }
    if (tgMatch) {
      tg = (await tgMatch.json()) as TgFeed;
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    tg = null;
  }
  try {
    const rdMatch = await tgCache.match(new Request(REDDIT_FEED_CACHE_KEY));
    if (rdMatch) {
      rd = (await rdMatch.json()) as RdFeed;
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    rd = null;
  }

  const tgSamples: ChatterSample[] = [];
  let tgMatches = 0;
  for (const it of tg?.items ?? []) {
    const kw = firstMatch(`${it.text ?? ''} ${it.permalink ?? ''}`);
    if (!kw) continue;
    tgMatches++;
    if (tgSamples.length < 12)
      tgSamples.push({
        source: it.channel_name ?? 'telegram',
        link: it.permalink ?? '',
        when: it.datetime,
        keyword: kw,
      });
  }

  const rdSamples: ChatterSample[] = [];
  let rdMatches = 0;
  for (const it of rd?.items ?? []) {
    const kw = firstMatch(`${it.title ?? ''} ${it.text ?? ''}`);
    if (!kw) continue;
    rdMatches++;
    if (rdSamples.length < 12)
      rdSamples.push({ source: it.sub_label ?? 'reddit', link: it.link ?? '', when: it.pub_date, keyword: kw });
  }

  const trackedSources = forums.reduce((s, g) => s + g.count, 0);
  const warnings: string[] = [];
  if (!tg) warnings.push('chatter-source-missing:telegram (feed not in this colo cache)');
  if (!rd) warnings.push('chatter-source-missing:reddit (feed not in this colo cache)');

  return {
    generated_at: new Date().toISOString(),
    forums,
    chatter: {
      telegram: { matches: tgMatches, samples: tgSamples },
      reddit: { matches: rdMatches, samples: rdSamples },
    },
    totals: { tracked_sources: trackedSources, categories: forums.length },
    warnings,
  };
}

export async function stealerForumIntelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(STEALER_FORUM_INTEL_CACHE_KEY);
  const cached = await cache.match(cacheReq);
  if (cached) return new Response(cached.body, cached);

  const body = await buildStealerForumIntel(
    c.env,
    c.executionCtx as unknown as Parameters<typeof buildStealerForumIntel>[1]
  );
  const cacheable = body.forums.length > 0 || body.chatter.telegram.matches > 0 || body.chatter.reddit.matches > 0;

  // Degraded build → short TTL, so a missing chatter source self-heals on the
  // next request instead of pinning zeros for the full window.
  //
  // The chatter counts are read from the per-colo Cache-API entries that the
  // telegram-feed and reddit-feed producers write. On a colo where neither has
  // been requested yet both reads miss, `matches` stays 0, and — because the
  // deepdarkCTI forum rows are non-empty — that zero-chatter payload was still
  // cacheable for the full CACHE_TTL_SECONDS. Readers then saw "0 matches",
  // which reads as "no stealer chatter exists" rather than "this colo's cache
  // was cold when it was built". Measured 2026-10-16: the live endpoint
  // reported 0/0 while the underlying feeds held 2 telegram and 4 reddit
  // matching items. Same approach as `ttlFor()` in deepdarkcti.
  const chatterMissing = body.warnings.some((w) => w.startsWith('chatter-source-missing'));
  const maxAge = chatterMissing ? DEGRADED_TTL_SECONDS : CACHE_TTL_SECONDS;

  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': cacheable ? `public, max-age=${maxAge}` : 'no-store',
      ...(chatterMissing ? { 'x-si-stale': 'chatter-source-missing' } : {}),
    },
  });
  if (cacheable) c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  return response;
}
