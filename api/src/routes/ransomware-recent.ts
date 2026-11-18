import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { classifySector, type Sector } from '../lib/sector-classifier';
import { safeIsoOr } from '../lib/safe-date';
import { fetchMythreatintelRansomwareVictims } from '../lib/mythreatintel-parser';
import { safeNullLog } from '../lib/safe-catch';
import { fetchAFRansomwareVictims } from '../lib/andreafortuna-feeds';
import { fetchMtiSource, type MtiRansomwareClaim } from '../lib/mythreatintel-api';
import { readXClaimsCache } from './x-claims';
import { normalizeGroup } from '../lib/group-normalize';
import { normalizeVictimKey } from '../lib/briefing-builder/aggregate';
import { readLastGood, writeLastGood } from '../lib/lastgood';

/**
 * Recent ransomware leak-site posts via Ransomlook.io's free `/api/recent`
 * endpoint (no auth, JSON, ~100 most recent victim claims). Cache 1 h
 * server-side.
 *
 * Ransomlook captures a PNG screenshot of each .onion leak post and serves
 * it from clearnet at https://www.ransomlook.io/<screen_path>. We surface
 * that URL on each victim — it's the closest we can get to "showing .onion
 * content" from the edge (Workers can't egress through Tor, but we can
 * embed a clearnet-hosted screenshot of what's on the .onion site).
 *
 * Internal Ransomlook magnet links are stripped — they're stub paths that
 * 404 when followed and add no value.
 */

/** Exported so /api/v1/snapshot can read the same cached payload directly. */
export const RANSOMWARE_RECENT_CACHE_KEY = 'https://ransomware-recent-cache.internal/v11-tz-abbrev-fix';
const CACHE_KEY = RANSOMWARE_RECENT_CACHE_KEY;
/**
 * Edge-cache TTL on the merged ransomware feed. Was 1 hour, which made
 * the hero sparkline on / feel stale to repeat visitors — the same
 * "231 claims · last 7d" number on multiple loads inside the same hour.
 * Cut to 15 minutes so a manual refresh (or the client's own polling
 * loop in HeroLiveSparkline) reflects new upstream data within a quarter
 * hour while still keeping the upstream merge cheap (one origin
 * recomputation per ~15 min per edge region).
 */
const CACHE_TTL_SECONDS = 900;
const FETCH_TIMEOUT_MS = 15_000;
const UPSTREAM = 'https://www.ransomlook.io/api/recent';
/** Secondary tracker. RSS of victim claims. Independently aggregated. */
const RANSOMFEED_RSS = 'https://www.ransomfeed.it/rss.php';
/**
 * Tertiary tracker — the "ransomwatch" gap-filler slot. The original
 * joshhighet/ransomwatch source (a GitHub posts.json dump) was ARCHIVED
 * upstream and its data froze on 2025-06-16, so the 7-day window filtered
 * it down to zero live rows. We keep the `ransomwatch` origin pill but back
 * it with RansomLook's DEEP recent feed (`/api/recent/<N>`) instead: the
 * primary Ransomlook source (UPSTREAM, `/api/recent`) is capped at ~100
 * entries which covers under a day of leak-site activity, so the deeper
 * pull surfaces the rest of the 7-day window. The merge dedupes by
 * (group + victim), so rows already carried by the primary source, cti.fyi,
 * or ransomfeed collapse to those origins — only the genuinely-additional
 * leak-site claims are attributed to `ransomwatch`. Same JSON shape as
 * UPSTREAM, so it reuses the primary parser's field mapping (incl. .onion
 * screenshot URLs the old joshhighet dump never had).
 */
const RANSOMWATCH_DEEP = 'https://www.ransomlook.io/api/recent/500';
/**
 * ransomware.live public data dump (free, no key). Newest-first, ~28k
 * entries, richer than ransomwatch: carries country + activity (sector) +
 * description. The /v2 REST API 301s to HTML and the PRO API needs a paid
 * X-API-KEY, so the static dump is the usable free surface.
 */
const RANSOMWARELIVE_JSON = 'https://data.ransomware.live/posts.json';
/**
 * Cap on the merged victim list returned to clients. Was 60 (~2 days of
 * leak-site activity at typical pace) which made the Metrics page's
 * 7/30/90-day window selectors mostly cosmetic past day-1. 500 covers
 * roughly 14-16 days at typical volume and matches the MTI proxy's
 * canonical limit, so the per-source fetches reuse the same edge-cache
 * entry as the rest of the platform. ~250KB on the wire, served from
 * cache.
 */
const MAX_ITEMS = 500;

interface RansomlookEntry {
  post_title: string;
  discovered: string;
  description?: string;
  link?: string;
  group_name?: string;
  /** Relative path to a PNG screenshot of the leak post on .onion. */
  screen?: string;
}

/**
 * Which tracker contributed this victim to the merged response. Set by each
 * fetcher; preserved by mergeVictims() so the frontend can render an
 * origin-pill per row.
 */
export type RansomwareOrigin =
  'ransomlook' | 'mti' | 'ransomfeed' | 'ransomwatch' | 'ransomwarelive' | 'andreafortuna' | 'ctifyi' | 'x';

export interface RansomwareVictim {
  victim: string;
  group: string;
  discovered: string;
  description?: string;
  source_url: string;
  /**
   * Absolute clearnet URL to a PNG screenshot of the .onion leak page.
   * Captured by Ransomlook's Tor-equipped backend and rehosted on their
   * static CDN. Render directly with <img src=...>; CSP `img-src https:`
   * already permits this.
   */
  screen_url?: string;
  /** Heuristic sector classification — see lib/sector-classifier.ts. */
  sector?: Sector;
  /** Which of the four trackers surfaced this victim. */
  origin: RansomwareOrigin;
  /** ISO-3166 country name when the upstream provided it (mythreatintel only today). */
  country?: string;
}

interface ResponseBody {
  generated_at: string;
  source: string;
  count: number;
  groups: Array<{ group: string; count: number }>;
  /** Heuristic sector aggregation. `pct` is share of classified (non-Unknown) victims. */
  sectors: Array<{ sector: Sector; count: number; pct: number }>;
  victims: RansomwareVictim[];
}

function toIsoDate(s: string): string {
  // Ransomlook returns "YYYY-MM-DD HH:MM:SS.ffffff" without timezone.
  // Treat as UTC.
  const cleaned = s.replace(' ', 'T').replace(/\.\d+$/, '') + 'Z';
  const d = new Date(cleaned);
  return Number.isFinite(d.getTime()) ? d.toISOString() : s;
}

/**
 * Map of common RFC-2822 timezone abbreviations (used by RSS feeds —
 * notably ransomfeed.it) to a fixed UTC offset. V8's Date.parse does
 * NOT understand abbreviations like "CEST" / "CET" / "PDT"; it returns
 * NaN, which would make every ransomfeed item silently look like "now"
 * in the metrics page. We replace the abbreviation with a numeric
 * offset here so Date.parse accepts the result.
 *
 * Northern-hemisphere DST rules (CEST ↔ CET, PDT ↔ PST, etc.) are
 * hardcoded — ransomfeed.it publishes from an EU server so we only
 * need the European ones in practice, but the full table is small.
 */
const TZ_ABBREV_TO_OFFSET: Record<string, string> = {
  UTC: '+0000',
  GMT: '+0000',
  // Europe
  CET: '+0100',
  CEST: '+0200',
  EET: '+0200',
  EEST: '+0300',
  // North America (the offsets are the same regardless of hemisphere
  // when looking at a single source — ransomfeed is always CET/CEST
  // today, but other RSS sources vary)
  EST: '-0500',
  EDT: '-0400',
  CST: '-0600',
  CDT: '-0500',
  MST: '-0700',
  MDT: '-0600',
  PST: '-0800',
  PDT: '-0700',
  AKST: '-0900',
  AKDT: '-0800',
  HST: '-1000',
};

/**
 * Parse an RFC-2822 pubDate that ends in a *timezone abbreviation*
 * (e.g. "Fri, 05 Jun 2026 00:50:22 CEST") into an ISO string with a
 * numeric offset V8 can read. Returns undefined if we can't recognise
 * the abbreviation; caller should fall back to safeIsoOr.
 */
function parseRssDateWithTzAbbrev(raw: string): string | undefined {
  if (!raw) return undefined;
  // Match "... HH:MM:SS ABBR" at the end. The abbrev is 2-5 letters
  // and we look it up in the offset table.
  const m = /^(.+?\d{2}:\d{2}:\d{2})\s+([A-Z]{2,5})\s*$/.exec(raw.trim());
  if (!m) return undefined;
  const abbr = m[2]!;
  const offset = TZ_ABBREV_TO_OFFSET[abbr];
  if (!offset) return undefined;
  // "Fri, 05 Jun 2026 00:50:22 CEST" → "Fri, 05 Jun 2026 00:50:22 +0200"
  const normalized = `${m[1]!} ${offset}`;
  const t = Date.parse(normalized);
  if (!Number.isFinite(t)) return undefined;
  return new Date(t).toISOString();
}

/**
 * Parse ransomfeed.it's RSS into our normalized victim shape.
 *
 * Feed item format:
 *   <title>VictimName</title>
 *   <description><![CDATA[Ransomware group called <b>{group}</b> claims
 *                attack for <b>{victim}</b>. ...]]></description>
 *   <pubDate>Tue, 12 May 2026 05:50:57 CEST</pubDate>
 *   <link>https://ransomfeed.it/index.php?page=post_details&id_post=...</link>
 *
 * Note: ransomfeed.it lists `<dc:creator>RansomLook</dc:creator>` so a lot
 * of items overlap with the Ransomlook primary source — the merge below
 * dedupes by (group + victim + day) so duplicates collapse to a single row.
 */
async function fetchRansomfeedVictims(): Promise<RansomwareVictim[]> {
  try {
    const res = await fetch(RANSOMFEED_RSS, {
      headers: {
        Accept: 'application/rss+xml, application/xml, text/xml, */*',
        'User-Agent': 'pranithjain.qzz.io DFIR toolkit (free, read-only)',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return [];
    const body = await res.text();
    const items: RansomwareVictim[] = [];
    const itemRe = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
    let m: RegExpExecArray | null;
    // 7-day cutoff: ransomfeed.it's RSS often omits a parseable <pubDate>
    // (unparseable dates fall through to safeIsoOr→now), and without a
    // hard cutoff the merge can surface months-old items stamped "today"
    // — which inflated the metrics page "today = 200+" surface. Cap the
    // window so the per-day count matches what the upstream actually
    // indexed. RSS is newest-first-ish but not guaranteed; we read all
    // items and let the cutoff filter.
    const cutoffMs = Date.now() - 7 * 24 * 3600 * 1000;
    while ((m = itemRe.exec(body)) !== null) {
      const block = m[1];
      if (!block) continue;
      const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(block)?.[1];
      const desc = /<description[^>]*>([\s\S]*?)<\/description>/i.exec(block)?.[1] ?? '';
      const link = /<link[^>]*>([\s\S]*?)<\/link>/i.exec(block)?.[1] ?? '';
      const pub = /<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i.exec(block)?.[1] ?? '';
      if (!title) continue;
      // Unwrap CDATA + strip basic HTML for the victim/description.
      const cdataStrip = (s: string) =>
        s
          .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/, '$1')
          .replace(/<[^>]+>/g, '')
          .trim();
      const victim = cdataStrip(title);
      const cleanedDesc = cdataStrip(desc);
      // Extract group from description: "Ransomware group called <b>X</b> claims attack for <b>Y</b>".
      // We already stripped tags, so match the plain-text form.
      const groupMatch = /Ransomware group called\s+([^\s,]+)/i.exec(cleanedDesc);
      const group = normalizeGroup(groupMatch?.[1] ?? 'unknown');
      // safeIsoOr never throws on a junk date (the old `new Date(pub).toISOString()`
      // did, dropping the whole feed); falls back to now() for missing/unparseable.
      //
      // ransomfeed.it publishes `pubDate` as RFC-2822 with a *timezone
      // abbreviation* (e.g. "CEST", "CET", "UTC"). V8's Date.parse does
      // NOT understand those abbreviations — it returns NaN and
      // safeIsoOr would silently fall back to `new Date().toISOString()`,
      // making every item look like "today" in the metrics page. Parse
      // the abbreviation ourselves with the well-known offset table,
      // then normalize to ISO with a real +HH:MM offset so Date.parse
      // accepts it.
      const discovered = parseRssDateWithTzAbbrev(pub) ?? safeIsoOr(pub);
      // Skip items with unparseable `pubDate` (would default to now and
      // show up as "today" in metrics). Only the structured trackers
      // — Ransomlook, cti.fyi, ransomware.live, ransomwatch, MTI —
      // feed us rows we trust without an upstream date.
      const parsed = Date.parse(discovered);
      if (!Number.isFinite(parsed)) continue;
      if (parsed < cutoffMs) continue;
      items.push({
        victim,
        group,
        discovered,
        // Use the prose part of the description, not the boilerplate.
        description: cleanedDesc.length > 320 ? cleanedDesc.slice(0, 317) + '…' : cleanedDesc,
        source_url: link.trim() || 'https://www.ransomfeed.it/',
        // ransomfeed.it doesn't expose screenshots.
        sector: classifySector(victim, cleanedDesc),
        origin: 'ransomfeed' as const,
      });
      if (items.length >= MAX_ITEMS) break;
    }
    return items;
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/**
 * The "ransomwatch" gap-filler slot, backed by RansomLook's DEEP recent
 * feed (`/api/recent/500`). See RANSOMWATCH_DEEP for why the original
 * joshhighet/ransomwatch source was dropped (archived, year-stale).
 *
 * The primary Ransomlook source (UPSTREAM, `/api/recent`) is capped at ~100
 * entries — under a day of leak-site activity — so it truncates the 7-day
 * window hard. This pulls the deeper 500-entry feed and keeps the last 7
 * days; the merge dedupes by (group + victim), so the ~100 rows already
 * carried by the primary source (plus cti.fyi / ransomfeed) collapse to
 * those higher-priority origins, and only the *additional* leak-site claims
 * keep the `ransomwatch` origin. Same JSON shape as UPSTREAM, so the field
 * mapping (incl. .onion screenshot URLs) mirrors the primary parser.
 */
async function fetchRansomwatchVictims(): Promise<RansomwareVictim[]> {
  try {
    const res = await fetch(RANSOMWATCH_DEEP, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain.qzz.io DFIR toolkit (free, read-only)',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtlByStatus: { '200-299': 3600, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    if (!res.ok) return [];
    const raw = (await res.json()) as RansomlookEntry[];
    if (!Array.isArray(raw)) return [];
    const cutoffMs = Date.now() - 7 * 24 * 3600 * 1000;
    const out: RansomwareVictim[] = [];
    // Newest-first array. Walk forward, keep rows inside the 7-day window;
    // the list is sorted by discovery so we can stop at the first older row.
    for (const e of raw) {
      if (out.length >= MAX_ITEMS) break;
      if (!e || !e.post_title || !e.group_name || !e.discovered) continue;
      const discovered = toIsoDate(e.discovered);
      const ts = Date.parse(discovered);
      if (!Number.isFinite(ts)) continue;
      if (ts < cutoffMs) break; // sorted desc — everything after is older
      const victim = e.post_title.trim();
      const description = e.description?.trim() || undefined;
      out.push({
        victim,
        group: normalizeGroup(e.group_name),
        discovered,
        description,
        source_url: e.link
          ? `https://www.ransomlook.io${e.link.startsWith('/') ? '' : '/'}${e.link}`
          : 'https://www.ransomlook.io/recent',
        screen_url: e.screen ? `https://www.ransomlook.io/${e.screen.replace(/^\//, '')}` : undefined,
        sector: classifySector(victim, description),
        origin: 'ransomwatch' as const,
      });
    }
    return out;
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/**
 * ransomware.live public dump. Newest-first array; walk forward and stop
 * once entries fall outside the 7-day window. Carries country + activity
 * (sector label) + description, so it produces high-quality rows.
 */
async function fetchRansomwareLiveVictims(): Promise<RansomwareVictim[]> {
  try {
    const res = await fetch(RANSOMWARELIVE_JSON, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain.qzz.io DFIR toolkit (free, read-only)',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtlByStatus: { '200-299': 3600, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    if (!res.ok) return [];
    const raw = (await res.json()) as Array<{
      post_title?: string;
      group_name?: string;
      discovered?: string;
      description?: string;
      country?: string;
      activity?: string;
    }>;
    if (!Array.isArray(raw)) return [];
    const cutoffMs = Date.now() - 7 * 24 * 3600 * 1000;
    const out: RansomwareVictim[] = [];
    // Newest-first: walk forward, stop when older than the window.
    for (let i = 0; i < raw.length && out.length < MAX_ITEMS; i++) {
      const e = raw[i];
      if (!e || !e.post_title || !e.group_name || !e.discovered) continue;
      const discovered = toIsoDate(e.discovered);
      const ts = Date.parse(discovered);
      if (!Number.isFinite(ts)) continue;
      if (ts < cutoffMs) break; // ordered — nothing newer beyond here
      const victim = e.post_title.trim();
      const description = e.description?.trim() || undefined;
      out.push({
        victim,
        group: normalizeGroup(e.group_name),
        discovered,
        description,
        source_url: 'https://www.ransomware.live/',
        sector: classifySector(victim, description ?? e.activity),
        origin: 'ransomwarelive' as const,
        country: e.country?.trim() || undefined,
      });
    }
    return out;
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/**
 * cti.fyi leak-site post tracker. Free public JSON API (`/api/v1/posts/recent`)
 * returning `{ post_title, group_name, discovered, post_url, screenshot_path }`.
 * Like Ransomlook it captures a clearnet-rehosted `.webp` screenshot of each
 * .onion post, so it both fills coverage gaps AND carries screenshots for the
 * UI to inline. Independently aggregated; the merge dedupes by (group|victim|day).
 */
const CTIFYI_RECENT = 'https://cti.fyi/api/v1/posts/recent?limit=500';

interface CtiFyiPost {
  post_title?: string;
  group_name?: string;
  discovered?: string;
  post_url?: string;
  screenshot_path?: string;
}

/**
 * Map a cti.fyi recent-post entry to our normalized victim shape, or null when
 * the entry is unusable (missing victim/group/date). `post_url` is the raw
 * .onion claim; we link the clearnet group page instead so the row is
 * followable from a normal browser, and surface the clearnet `.webp`
 * screenshot (CSP `img-src https:` already permits it). Exported for unit
 * coverage of the field/date/screenshot mapping.
 */
export function ctiFyiPostToVictim(e: CtiFyiPost): RansomwareVictim | null {
  const victim = e.post_title?.trim();
  const group = e.group_name?.trim();
  if (!victim || !group || !e.discovered) return null;
  const discovered = toIsoDate(e.discovered);
  if (Number.isNaN(Date.parse(discovered))) return null;
  const slug = normalizeGroup(group);
  const screen = e.screenshot_path?.trim();
  return {
    victim,
    group: slug,
    discovered,
    source_url: `https://cti.fyi/groups/${encodeURIComponent(slug)}.html`,
    screen_url: screen ? `https://cti.fyi/${screen.replace(/^\//, '')}` : undefined,
    sector: classifySector(victim, undefined),
    origin: 'ctifyi' as const,
  };
}

async function fetchCtiFyiVictims(): Promise<RansomwareVictim[]> {
  try {
    const res = await fetch(CTIFYI_RECENT, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain.qzz.io DFIR toolkit (free, read-only)',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtlByStatus: { '200-299': CACHE_TTL_SECONDS, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    if (!res.ok) return [];
    const json = (await res.json()) as { results?: CtiFyiPost[] };
    const results = Array.isArray(json?.results) ? json.results : [];
    const cutoffMs = Date.now() - 7 * 24 * 3600 * 1000;
    const out: RansomwareVictim[] = [];
    for (const e of results) {
      const v = ctiFyiPostToVictim(e);
      if (!v || Date.parse(v.discovered) < cutoffMs) continue;
      out.push(v);
      if (out.length >= MAX_ITEMS) break;
    }
    return out;
  } catch (_catchErr) {
    logError('fetchCtiFyiVictims failed', _catchErr);
    return [];
  }
}

/**
 * MyThreatIntel REST API `ransomware` source — ransomware victim claims
 * (`{ victim, gang, date, country, website, description }`). NOTE: the
 * upstream `events` source is empty; victim/CTI-event data is served by
 * `ransomware`. Higher-fidelity than the t.me/s/mythreatintel scraper
 * (same `origin: 'mti'`); when the token is unset or the upstream is
 * unhealthy this returns [] and the scraper list remains the 'mti'
 * fallback. The merge dedupes by (group|victim|day) so they never
 * double-count.
 */
async function fetchMtiApiVictims(env: Env): Promise<RansomwareVictim[]> {
  const res = await safeNullLog('fetch-mti-ransomware-recent', fetchMtiSource(env, 'ransomware', { limit: MAX_ITEMS }));
  if (!res || !res.ok) return [];
  // 7-day cutoff: the MTI REST API returns the latest N rows (no
  // server-side date filter). Without this, months-old claims get
  // pulled into the merge and inflate the metrics counts. We trust
  // the upstream date field and skip anything older than 7 days.
  const cutoffMs = Date.now() - 7 * 24 * 3600 * 1000;
  const out: RansomwareVictim[] = [];
  for (const raw of res.items) {
    const e = raw as MtiRansomwareClaim;
    const victim = e.victim?.trim();
    const gang = e.gang?.trim();
    if (!victim || !gang || !e.date) continue;
    const discovered = toIsoDate(e.date);
    const parsed = Date.parse(discovered);
    if (!Number.isFinite(parsed) || parsed < cutoffMs) continue;
    const description = e.description?.trim() || undefined;
    const country = e.country?.trim();
    out.push({
      victim,
      group: normalizeGroup(gang),
      discovered,
      description: description && description.length > 320 ? description.slice(0, 317) + '…' : description,
      source_url: 'https://mythreatintel.com/',
      sector: classifySector(victim, description),
      origin: 'mti' as const,
      ...(country && country !== 'N/D' ? { country } : {}),
    });
    if (out.length >= MAX_ITEMS) break;
  }
  return out;
}

/**
 * Ransomware victim claims parsed from threat-intel X channels (FalconFeeds,
 * @DailyDarkWeb, …) by the /api/v1/x-claims route. We read ONLY its cache here
 * — never re-fetching X — so the core ransomware feed carries no X auth /
 * rate-limit risk. Cold cache → []; the x-claims endpoint (page view + hourly
 * cron warm) keeps it populated. Lowest dedupe priority: these are free-text
 * extractions, so a structured tracker always wins a (group|victim|day) tie.
 */
async function fetchXVictims(): Promise<RansomwareVictim[]> {
  const cached = await readXClaimsCache();
  return cached?.ransomware ?? [];
}

/** Merge N victim lists, dedupe by (group + victim + day), keep newest. */
function mergeVictims(...lists: RansomwareVictim[][]): RansomwareVictim[] {
  const byKey = new Map<string, RansomwareVictim>();
  const key = (v: RansomwareVictim) => {
    const day = v.discovered.slice(0, 10); // YYYY-MM-DD
    // normalizeGroup is idempotent — every fetcher above already calls it, but
    // applying it here too means a future caller that forgets the step still
    // gets a stable dedupe. The 1st occurrence (source-priority order) wins.
    // normalizeVictimKey collapses tracker spelling variants ("Encore
    // Enterprises, Inc." vs "Encore-Enterprises-Inc.") so a victim claimed by
    // the same group the same day appears once in the list and in briefings.
    const victim = normalizeVictimKey(v.victim);
    return `${normalizeGroup(v.group)}|${victim || v.victim.toLowerCase().trim()}|${day}`;
  };
  // Insert in source-priority order. Earlier lists win ties — call sites pass
  // Ransomlook first because its entries carry screen_url which the UI inlines.
  for (const list of lists) {
    for (const v of list) {
      if (!byKey.has(key(v))) byKey.set(key(v), v);
    }
  }
  return [...byKey.values()].sort((a, b) => b.discovered.localeCompare(a.discovered));
}

/**
 * Pure-data fetcher — exported for the unified /api/v1/snapshot endpoint
 * which calls upstream handlers directly (worker-internal fetch loops on
 * Cloudflare). Returns `{ body, upstreamOk, rateLimited }` so the calling
 * handler can decide on cache + status semantics.
 */
export async function fetchRansomwareRecent(env?: Env): Promise<{
  body: ResponseBody;
  upstreamOk: boolean;
  rateLimited?: { retryAfter: string };
}> {
  let primary: RansomwareVictim[] = [];
  let upstreamOk = false;
  let rateLimited: { retryAfter: string } | undefined;

  // Four trackers fetched in parallel. Dedupe by (group + victim + day);
  // priority order at tie-break:
  //   1. Ransomlook        — carries .onion screenshot URLs the UI inlines
  //   2. mythreatintel     — Spanish CTI channel, real-time, has descriptions
  //   3. ransomfeed.it     — RSS of victim claims, has descriptions
  //   4. ransomwatch       — id-only, fills coverage gaps from leak-site scrapes
  const [
    primarySettled,
    mtiApiVictims,
    mtiVictims,
    secondaryVictims,
    tertiaryVictims,
    rlVictims,
    afVictims,
    ctiFyiVictims,
    xVictims,
  ] = await Promise.all([
    (async () => {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
        const res = await fetch(UPSTREAM, {
          headers: {
            Accept: 'application/json',
            'User-Agent': 'pranithjain.qzz.io DFIR toolkit (free, read-only)',
          },
          signal: ctrl.signal,
        });
        clearTimeout(timer);
        return res;
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return null;
      }
    })(),
    // MyThreatIntel REST API `events` — higher-fidelity 'mti' victims.
    // Skipped (→ []) when no env/token; the scraper below stays the fallback.
    env ? fetchMtiApiVictims(env).catch(() => []) : Promise.resolve([] as RansomwareVictim[]),
    // mythreatintel parser returns a structurally-compatible shape; the only
    // extra field is `country`, which RansomwareVictim doesn't yet carry —
    // safe to upcast.
    fetchMythreatintelRansomwareVictims().catch(() => []),
    fetchRansomfeedVictims(),
    fetchRansomwatchVictims(),
    fetchRansomwareLiveVictims(),
    fetchAFRansomwareVictims().catch(() => []),
    // cti.fyi — independent leak-site tracker; carries .webp screenshots.
    fetchCtiFyiVictims().catch(() => []),
    // X channels (FalconFeeds, @DailyDarkWeb) — cache-only, best-effort.
    fetchXVictims().catch(() => []),
  ]);

  try {
    const res = primarySettled;
    if (res && res.status === 429) {
      rateLimited = { retryAfter: res.headers.get('retry-after') ?? '60' };
    } else if (res && res.ok) {
      const raw = (await res.json()) as RansomlookEntry[];
      upstreamOk = true;
      primary = raw
        .filter((e) => e && e.post_title && e.group_name)
        .slice(0, MAX_ITEMS)
        .map((e) => {
          const victim = e.post_title.trim();
          const description = e.description?.trim() || undefined;
          return {
            victim,
            group: normalizeGroup(e.group_name),
            discovered: toIsoDate(e.discovered),
            description,
            source_url: e.link
              ? `https://www.ransomlook.io${e.link.startsWith('/') ? '' : '/'}${e.link}`
              : 'https://www.ransomlook.io/recent',
            screen_url: e.screen ? `https://www.ransomlook.io/${e.screen.replace(/^\//, '')}` : undefined,
            sector: classifySector(victim, description),
            origin: 'ransomlook' as const,
          };
        });
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* upstream unreachable — fall through; secondary may still have data */
  }

  // Single-source-down tolerance: cacheable as long as ANY non-primary
  // tracker returned data. The page shouldn't blank when 3/4 trackers are
  // healthy.
  if (
    !upstreamOk &&
    (mtiApiVictims.length > 0 ||
      mtiVictims.length > 0 ||
      secondaryVictims.length > 0 ||
      tertiaryVictims.length > 0 ||
      rlVictims.length > 0 ||
      afVictims.length > 0 ||
      ctiFyiVictims.length > 0 ||
      xVictims.length > 0)
  ) {
    upstreamOk = true;
  }

  // AF passed last → lowest dedupe priority. It re-aggregates Ransomlook, so
  // originals win ties; AF only fills gaps the other trackers missed.
  // Priority at tie-break: Ransomlook (screenshots) → MTI (country+desc) →
  // cti.fyi (screenshots) → ransomfeed → ransomware.live (country+sector) →
  // ransomwatch (deep RansomLook gap-filler) → AF.
  // cti.fyi sits ahead of the screenshot-less trackers so its .webp wins ties.
  // ransomwatch (tertiaryVictims, now a deep RansomLook pull) sits AFTER
  // ransomware.live so the latter's country/sector enrichment wins ties; the
  // ransomwatch slot then only keeps leak-site claims no richer source had.
  const victims = mergeVictims(
    primary,
    mtiApiVictims,
    mtiVictims as RansomwareVictim[],
    ctiFyiVictims,
    secondaryVictims,
    rlVictims,
    tertiaryVictims,
    afVictims,
    // X channels last — free-text parsed, so any structured tracker wins ties.
    xVictims
  ).slice(0, MAX_ITEMS);

  const groupCounts = new Map<string, number>();
  for (const v of victims) groupCounts.set(v.group, (groupCounts.get(v.group) ?? 0) + 1);

  const groups = [...groupCounts.entries()]
    .map(([group, count]) => ({ group, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  // Sector aggregation — pct is share of *classified* victims (excludes Unknown
  // from the denominator so the percentages mean "of the ones we could
  // identify, what share is each sector"). The Unknown row is still surfaced
  // with its own count so analysts see how much we couldn't classify.
  const sectorCounts = new Map<Sector, number>();
  for (const v of victims) {
    const s = v.sector ?? 'Unknown';
    sectorCounts.set(s, (sectorCounts.get(s) ?? 0) + 1);
  }
  const classifiedTotal = victims.filter((v) => v.sector && v.sector !== 'Unknown').length;
  const sectors = [...sectorCounts.entries()]
    .map(([sector, count]) => ({
      sector,
      count,
      pct: sector === 'Unknown' || classifiedTotal === 0 ? 0 : Math.round((count / classifiedTotal) * 100),
    }))
    .sort((a, b) => b.count - a.count);

  const body: ResponseBody = {
    generated_at: new Date().toISOString(),
    source:
      'ransomlook.io + mythreatintel + cti.fyi + ransomfeed.it + ransomwatch + ransomware.live + X/FalconFeeds (merged + deduped)',
    count: victims.length,
    groups,
    sectors,
    victims,
  };

  // Persist last-good payload to KV so stale data is served when all
  // upstreams fail (cold cache, transient outages). The calling snapshot
  // handler reads this backup via the ok flag on the return.
  // Only persist a NON-EMPTY payload. A zero-victim result (all upstreams
  // momentarily thin/down) must never become the cached "good" copy, or it
  // pins an empty feed for the whole TTL and the page blanks for repeat
  // visitors — the exact failure this guards against.
  if (upstreamOk && body.victims.length > 0 && env?.KV_CACHE) {
    void safeNullLog(
      'cache-put-ransomware-recent',
      (caches as unknown as { default: Cache }).default.put(
        new Request(RANSOMWARE_RECENT_CACHE_KEY),
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'cache-control': `public, max-age=${CACHE_TTL_SECONDS}` },
        })
      )
    );
  }

  return { body, upstreamOk, rateLimited };
}

/**
 * Global (cross-colo) last-good store. caches.default is per-colo, so a colo
 * whose upstream fetch transiently fails — or one with a cold cache after a
 * deploy/key-bump — has no neighbour to borrow from and would serve "0
 * claims". KV is global: any healthy colo's fetch refreshes it, and every
 * other colo can fall back to it. 48h TTL covers a long upstream outage.
 *
 * Read/write goes through the shared lib/lastgood.ts helper (free per-colo
 * Cache-API shadow in front of KV). keyPrefix '' keeps the legacy verbatim KV
 * key. The shared reader doesn't filter payloads on read, so the non-empty
 * victims guard lives at the call site below — same guarantee as the old
 * inline reader.
 */
const RANSOMWARE_LASTGOOD_KV_KEY = 'ransomware-recent:lastgood:v1';
const LASTGOOD_TTL_SECONDS = 172800;

/**
 * Apply the `?days=N` window filter to a merged-victim response. The
 * upstream fetchers each keep a 7-day sliding window internally, but
 * some (MTI REST, X cache) do not, and the cached response itself is
 * always 7 days — so without this client-side filter the `?days=1`
 * and `?days=7` views returned identical payloads, which inflated
 * the metrics page (e.g. "today's 200+ claims" when the real daily
 * number is < 100). The filter is bounded — 1..30 days, default 7.
 */
function filterByDaysWindow(body: ResponseBody, days: number): ResponseBody {
  if (days >= 30) return body; // cache is 7d; >30 is a no-op
  const cutoffMs = Date.now() - days * 24 * 3600 * 1000;
  const victims = body.victims.filter((v) => {
    const t = Date.parse(v.discovered);
    return Number.isFinite(t) && t >= cutoffMs;
  });
  // Recompute the pre-aggregated rollups so the JSON matches the
  // windowed victims list. Without this, the `groups` array would
  // still reflect the unfiltered 7-day counts and disagree with the
  // victim list length — confusing for any consumer that reads both.
  const groupCounts = new Map<string, number>();
  const sectorCounts = new Map<Sector, number>();
  for (const v of victims) {
    groupCounts.set(v.group, (groupCounts.get(v.group) ?? 0) + 1);
    const s = v.sector ?? 'Unknown';
    sectorCounts.set(s, (sectorCounts.get(s) ?? 0) + 1);
  }
  // Match the production `sectors` shape: an array of {sector, count, pct}
  // where pct is the share of *classified* (non-Unknown) victims. The
  // Unknown row is included with its own count so analysts can see how
  // much we couldn't classify.
  const classifiedTotal = victims.filter((v) => v.sector && v.sector !== 'Unknown').length;
  const sectors: ResponseBody['sectors'] = [...sectorCounts.entries()]
    .map(([sector, count]) => ({
      sector,
      count,
      // Match the full-body builder: Unknown's pct is 0 because the
      // denominator (classifiedTotal) excludes it. With Unknown=21 and
      // classified=8, naive (21/8)*100=263 — a "percentage" > 100.
      pct: sector === 'Unknown' || classifiedTotal === 0 ? 0 : Math.round((count / classifiedTotal) * 100),
    }))
    .sort((a, b) => b.count - a.count);
  return {
    ...body,
    victims,
    count: victims.length,
    groups: [...groupCounts.entries()]
      .map(([group, count]) => ({ group, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    sectors,
  };
}

function filterByGroup(body: ResponseBody, group: string): ResponseBody {
  const victims = body.victims.filter((v) => v.group?.toLowerCase() === group);
  const groupCounts = new Map<string, number>();
  const sectorCounts = new Map<Sector, number>();
  for (const v of victims) {
    groupCounts.set(v.group, (groupCounts.get(v.group) ?? 0) + 1);
    const s = v.sector ?? 'Unknown';
    sectorCounts.set(s, (sectorCounts.get(s) ?? 0) + 1);
  }
  const classifiedTotal = victims.filter((v) => v.sector && v.sector !== 'Unknown').length;
  const sectors: ResponseBody['sectors'] = [...sectorCounts.entries()]
    .map(([sector, count]) => ({
      sector,
      count,
      pct: sector === 'Unknown' || classifiedTotal === 0 ? 0 : Math.round((count / classifiedTotal) * 100),
    }))
    .sort((a, b) => b.count - a.count);
  return {
    ...body,
    victims,
    count: victims.length,
    groups: [...groupCounts.entries()]
      .map(([g, count]) => ({ group: g, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    sectors,
  };
}

function parseDaysParam(raw: string | undefined): number {
  const n = raw ? parseInt(raw, 10) : 7;
  if (!Number.isFinite(n) || n < 1) return 7;
  if (n > 30) return 30;
  return n;
}

/**
 * Cron-warm for the ransomware-recent merged payload. Must run inside the DO
 * cron (30s CPU budget), never a user/self fetch (10ms free-plan cap). Builds
 * the merged feed once and refreshes the edge Cache-API + KV last-good so the
 * request handler stays on splash: Cache-API hit → KV last-good → 503.
 */
export async function warmRansomwareRecentCache(env?: Env): Promise<{ count: number; ok: boolean }> {
  const { body, upstreamOk } = await fetchRansomwareRecent(env);
  const cache = (caches as unknown as { default: Cache }).default;
  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
      'x-source': 'cron-warm',
    },
  });
  await cache.put(new Request(CACHE_KEY), response);
  if (env?.KV_CACHE && upstreamOk && body.victims.length > 0) {
    // Cron-controlled refresh — force:true skips the request-path debounce so
    // the global copy always advances on each warm. skipIfUnchanged keeps the
    // 24x/day warm from spending a KV write (the scarce free-plan quota) on a
    // byte-identical payload; keyPrefix '' keeps the legacy verbatim KV key.
    await writeLastGood(env, RANSOMWARE_LASTGOOD_KV_KEY, body, {
      keyPrefix: '',
      ttlSeconds: LASTGOOD_TTL_SECONDS,
      force: true,
      skipIfUnchanged: true,
    });
  }
  return { count: body.victims.length, ok: upstreamOk };
}

export async function ransomwareRecentHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const days = parseDaysParam(c.req.query('days'));
  const groupFilter = (c.req.query('group') ?? '').trim().toLowerCase();
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(CACHE_KEY);
  const cached = await cache.match(cacheKey);
  if (cached) {
    if (days === 7 && !groupFilter) return new Response(cached.body, cached);
    let filtered = filterByDaysWindow((await cached.json()) as ResponseBody, days);
    if (groupFilter) filtered = filterByGroup(filtered, groupFilter);
    return c.json(filtered, 200, { 'x-cache': 'FILTERED' });
  }

  // Free-plan guard: NEVER build the merged feed inline. A cold-cache miss has
  // only a 10ms CPU budget (fetch invocation) — insufficient for the 9-upstream
  // merge (4 trackers + MTI API + scraper + ransomware.live + X + cti.fyi).
  // The hourly DO cron runs `warmRansomwareRecentCache` (30s DO budget) instead.
  // Serve the global KV last-good here; err on the side of a fast 503 if we
  // have nothing yet.
  const lastGood = await readLastGood<ResponseBody>(c.env, RANSOMWARE_LASTGOOD_KV_KEY, { keyPrefix: '' });
  // Only a real feed serves as last-good (guards against an empty/corrupt
  // payload in KV — the write paths already filter, this keeps the guarantee).
  if (lastGood && Array.isArray(lastGood.victims) && lastGood.victims.length > 0) {
    let finalBody = filterByDaysWindow(lastGood, days);
    if (groupFilter) finalBody = filterByGroup(finalBody, groupFilter);
    const response = c.json(finalBody, 200, {
      'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
      'x-cache': 'LASTGOOD',
    });
    // Write-through ONLY the canonical unfiltered payload. A ?days=1/?group=x
    // variant written under CACHE_KEY would poison every default consumer
    // (GlobalPulse ransom layer, sparkline, feed-status probe) with truncated
    // data for the full TTL — same rule the cache-hit branch above applies.
    if (days === 7 && !groupFilter) {
      c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()).catch(() => {}));
    }
    return response;
  }

  const empty: ResponseBody = {
    generated_at: new Date().toISOString(),
    source: 'warming',
    count: 0,
    groups: [],
    sectors: [],
    victims: [],
  };
  return c.json(empty, 503, {
    'retry-after': '300',
    'x-source': 'ransomware-recent-warming',
  });
}
