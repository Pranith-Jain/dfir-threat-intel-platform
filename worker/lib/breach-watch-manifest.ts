/**
 * Breach Watch manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/breach-watch/.
 * Data sourced from 6 free open ransomware/breach trackers:
 *   - ransomware.live     (public posts.json dump, free, no auth)
 *   - ransomlook.io       (/api/recent, free, no auth)
 *   - Darkfield           (darkfield.orizon.one, free REST, CC-BY-like)
 *   - RecentBreaches.com  (public API, free, no auth)
 *   - CTI.FYI             (free API, 60 req/min, no auth)
 *   - XposedOrNot         (free API, 100 req/day/IP, open source MIT)
 *
 * Shape:
 *   /data/breach-watch/index.json           (~50 KB, slim — no bodies)
 *   /data/breach-watch/breaches/<slug>.json  (one per breach, full body)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export type BwCategory = 'ransomware' | 'data_breach' | 'combo_list' | 'source_code' | 'credential_leak' | 'other';

export type BwSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface BwBreachIndexEntry {
  slug: string;
  title: string;
  group: string;
  discovered: string;
  category: BwCategory;
  severity: BwSeverity;
  country: string | null;
  sizeBytes: number;
}

export interface BwGroupEntry {
  name: string;
  count: number;
  topCategory: BwCategory;
}

export interface BwIndex {
  source: string;
  license: string;
  replicatedAt: string;
  counts: { breaches: number; groups: number; categories: number };
  lastSyncedAt: string | null;
  categories: Array<{ key: BwCategory; label: string; count: number }>;
  groups: BwGroupEntry[];
  breachIndex: BwBreachIndexEntry[];
}

export interface BwBreachBody extends BwBreachIndexEntry {
  description: string | null;
  source_url: string;
  groupAliases: string[];
  activity: string | null;
  references: string[];
}

const DATA_PREFIX = '/data/breach-watch';
const MAX_BODY_CACHE = 200;

const breachBodyCache: BodyCache<BwBreachBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: BwIndex | null = null;
let cachedIndexAt: number | null = null;

function safeFilename(slug: string): string {
  return slug.replace(/\//g, '__').replace(/[^A-Za-z0-9._-]/g, '_');
}

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://bw.local');
}

export async function loadBwIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<BwIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<BwIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Breach Watch index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-breach-watch.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getBwBreach(assets: Fetcher, slug: string): Promise<BwBreachBody | null> {
  const hit = trackHit(breachBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<BwBreachBody>(assets, `${DATA_PREFIX}/breaches/${safeFilename(slug)}.json`);
  if (!body) return null;
  return recordHit(breachBodyCache, slug, body, MAX_BODY_CACHE);
}

export interface BwListBreachesOptions {
  group?: string;
  category?: BwCategory;
  severity?: BwSeverity;
  country?: string;
  daysBack?: number;
  keyword?: string;
  limit?: number;
  /** Number of matching results to skip before returning (for pagination). */
  offset?: number;
}

export function filterBreaches(idx: BwIndex, opts: BwListBreachesOptions = {}): BwBreachIndexEntry[] {
  const { group, category, severity, country, daysBack, keyword, limit = 100, offset = 0 } = opts;
  const needle = keyword?.toLowerCase();
  const now = Date.now();
  const cutoffMs = daysBack ? daysBack * 86_400_000 : null;
  const countryNeedle = country?.toLowerCase();
  let skipped = 0;

  const out: BwBreachIndexEntry[] = [];
  for (const b of idx.breachIndex) {
    if (group && b.group !== group) continue;
    if (category && b.category !== category) continue;
    if (severity && b.severity !== severity) continue;
    if (countryNeedle && !(b.country ?? '').toLowerCase().includes(countryNeedle)) continue;
    if (cutoffMs) {
      const disc = Date.parse(b.discovered);
      if (!isNaN(disc) && now - disc > cutoffMs) continue;
    }
    if (needle) {
      const hay = `${b.slug} ${b.title} ${b.group}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    if (skipped < offset) {
      skipped++;
      continue;
    }
    out.push(b);
    if (out.length >= limit) break;
  }
  return out;
}

export function listGroups(
  idx: BwIndex,
  opts: { minCount?: number; keyword?: string; limit?: number } = {}
): BwGroupEntry[] {
  const { minCount, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: BwGroupEntry[] = [];
  for (const g of idx.groups) {
    if (minCount !== undefined && g.count < minCount) continue;
    if (needle && !g.name.toLowerCase().includes(needle)) continue;
    out.push(g);
    if (out.length >= limit) break;
  }
  return out;
}

export function bwCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  breaches: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    breaches: { size: breachBodyCache.map.size, hits: breachBodyCache.hits, misses: breachBodyCache.misses },
  };
}

export function _resetBwCacheForTests(): void {
  breachBodyCache.map.clear();
  breachBodyCache.hits = breachBodyCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
