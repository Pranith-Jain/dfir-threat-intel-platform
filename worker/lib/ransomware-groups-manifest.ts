/**
 * Ransomware Groups directory manifest loader (Sinon-style /ransomware reference).
 *
 * Reads the static JSON manifest shipped in /public/data/ransomware-groups/
 * (built by scripts/build-ransomware-groups.mjs from Ransomlook +
 * ransomware.live clearnet aggregation). The Worker fetches them through
 * the env.ASSETS binding — no Tor egress, no per-request upstream calls.
 *
 * Shape (sharded — the Workers free plan caps static assets at 20,000
 * files, so 43 per-slug bodies ship as 3 shard maps instead):
 *   /data/ransomware-groups/index.json          (slim row per group; rows
 *                                                with bodies carry `shard`)
 *   /data/ransomware-groups/groups/shard-0000.json … (maps slug → body)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface RansomwareGroupRow {
  slug: string;
  name: string;
  victims_7d: number;
  victims_total: number;
  last_seen: string | null;
  origins: string[];
  /** Ransomlook reachability at last scrape; null when never enriched. */
  online: boolean | null;
  mirrors: number;
  up_mirrors: number;
  has_profile: boolean;
  blurb: string;
  /** Shard file index when a body ships (see build script); absent otherwise. */
  shard?: number;
}

export interface RansomwareGroupsIndex {
  source: string;
  sourceUrl: string;
  license: string;
  syncedAt: string | null;
  builtAt: string;
  counts: {
    groups: number;
    sites_up: number;
    active_week: number;
    profiled: number;
    with_activity: number;
  };
  groups: RansomwareGroupRow[];
  /** Slugs of the 12 most-recently-changed groups ("moved most recently"). */
  recent: string[];
}

export interface RansomwareGroupMirror {
  fqdn: string;
  title: string | null;
  available: boolean;
  updated: string | null;
  version: number | null;
}

export interface RansomwareVictimSample {
  victim: string;
  discovered: string;
  origin: string;
  source_url: string;
}

export interface RansomwareGroupBody extends RansomwareGroupRow {
  meta: string | null;
  meta_source: string | null;
  mirrors_detail: RansomwareGroupMirror[];
  victims_sample: RansomwareVictimSample[];
  source_urls: { ransomlook: string; ransomware_live: string };
}

const DATA_PREFIX = '/data/ransomware-groups';
const MAX_BODY_CACHE = 200;
const MAX_SHARD_CACHE = 8;

function shardName(idx: number): string {
  return `${DATA_PREFIX}/groups/shard-${String(idx).padStart(4, '0')}.json`;
}

const bodyCache: BodyCache<RansomwareGroupBody> = { map: new Map(), hits: 0, misses: 0 };
const shardCache: BodyCache<Record<string, RansomwareGroupBody>> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: RansomwareGroupsIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://ransomware-groups.local');
}

export async function loadRansomwareGroupsIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<RansomwareGroupsIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<RansomwareGroupsIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Ransomware Groups index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-ransomware-groups.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

/**
 * Bodies ship in shard maps ({slug: body}); rows without a `shard` pointer
 * synthesize a body from the slim row, so every /groups/:slug lookup
 * resolves. Shards are LRU-cached whole (few files, small bodies).
 */
export async function getRansomwareGroup(assets: Fetcher, slug: string): Promise<RansomwareGroupBody | null> {
  const hit = trackHit(bodyCache, slug);
  if (hit) return hit;
  const idx = await loadRansomwareGroupsIndex(assets);
  const row = idx.groups.find((g) => g.slug === slug);
  if (!row) return null;
  if (row.shard !== undefined) {
    const key = shardName(row.shard);
    let shard = trackHit(shardCache, key);
    if (!shard) {
      const raw = await fetchJson<Record<string, RansomwareGroupBody>>(assets, key);
      if (raw) {
        shard = raw;
        recordHit(shardCache, key, shard, MAX_BODY_CACHE);
        while (shardCache.map.size > MAX_SHARD_CACHE) {
          const oldest = shardCache.map.keys().next().value;
          if (oldest === undefined) break;
          shardCache.map.delete(oldest);
        }
      }
    }
    const found = shard?.[slug];
    if (found) return recordHit(bodyCache, slug, withMirrorsDetail(found), MAX_BODY_CACHE);
  }
  return recordHit(bodyCache, slug, synthesizeBody(row), MAX_BODY_CACHE);
}

/** Normalize the legacy per-slug shape (`mirrors` array) to mirrors_detail. */
function withMirrorsDetail(raw: RansomwareGroupBody & { mirrors?: unknown }): RansomwareGroupBody {
  return {
    ...raw,
    mirrors_detail: Array.isArray(raw.mirrors_detail)
      ? raw.mirrors_detail
      : Array.isArray(raw.mirrors)
        ? (raw.mirrors as RansomwareGroupMirror[])
        : [],
  };
}

function synthesizeBody(row: RansomwareGroupRow): RansomwareGroupBody {
  return {
    ...row,
    meta: null,
    meta_source: null,
    mirrors_detail: [],
    victims_sample: [],
    source_urls: {
      ransomlook: `https://www.ransomlook.io/api/group/${encodeURIComponent(row.name)}`,
      ransomware_live: 'https://www.ransomware.live/',
    },
  };
}

export type RansomwareGroupStatus = 'online' | 'offline' | 'unknown';
export type RansomwareGroupSort = 'recent' | 'name' | 'victims';

export interface RansomwareGroupListOptions {
  q?: string;
  status?: RansomwareGroupStatus;
  activeWeek?: boolean;
  hasProfile?: boolean;
  sort?: RansomwareGroupSort;
  limit?: number;
}

export function filterRansomwareGroups(
  idx: RansomwareGroupsIndex,
  opts: RansomwareGroupListOptions = {}
): RansomwareGroupRow[] {
  const { q, status, activeWeek, hasProfile, sort = 'recent', limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const weekAgo = Date.now() - 7 * 24 * 3600 * 1000;
  let out = idx.groups.filter((g) => {
    if (status === 'online' && g.online !== true) return false;
    if (status === 'offline' && g.online !== false) return false;
    if (status === 'unknown' && g.online !== null) return false;
    if (activeWeek) {
      if (!g.last_seen || Date.parse(g.last_seen) < weekAgo) return false;
    }
    if (hasProfile && !g.has_profile) return false;
    if (needle && !`${g.slug} ${g.name} ${g.blurb}`.toLowerCase().includes(needle)) return false;
    return true;
  });
  out = [...out].sort((a, b) => {
    if (sort === 'name') return a.slug.localeCompare(b.slug);
    if (sort === 'victims')
      return b.victims_7d - a.victims_7d || String(b.last_seen ?? '').localeCompare(String(a.last_seen ?? ''));
    return String(b.last_seen ?? '').localeCompare(String(a.last_seen ?? '')) || b.victims_7d - a.victims_7d;
  });
  return out.slice(0, Math.min(Math.max(limit, 1), 620));
}

export function ransomwareGroupsCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodies: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodies: { size: bodyCache.map.size, hits: bodyCache.hits, misses: bodyCache.misses },
  };
}

export function _resetRansomwareGroupsCacheForTests(): void {
  bodyCache.map.clear();
  cachedIndex = null;
  cachedIndexAt = null;
  bodyCache.hits = bodyCache.misses = 0;
}
