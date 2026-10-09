/**
 * OSS Feed Registry manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/oss-feed-registry/
 * (the Bert-JanP/Open-Source-Threat-Intel-Feeds catalog, BSD-3-Clause).
 * The Worker fetches them through the env.ASSETS binding.
 *
 * Shape:
 *   /data/oss-feed-registry/index.json                        (slim index + feed list)
 *   /data/oss-feed-registry/categories/<slug>.json            (per-category full feed lists)
 *
 * Source: https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface OssFeedIndexEntry {
  vendor: string;
  description: string;
  category: string;
  feedStatus: string;
}

export interface OssCategoryEntry {
  category: string;
  count: number;
  slug: string;
}

export interface OssFeedsIndex {
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  lastSyncedAt: string;
  counts: {
    total: number;
    byCategory: Record<string, number>;
    byStatus: Record<string, number>;
  };
  categories: OssCategoryEntry[];
  feedIndex: OssFeedIndexEntry[];
}

export interface OssCategoryBody {
  category: string;
  count: number;
  feeds: Array<{
    vendor: string;
    description: string;
    category: string;
    url: string;
    feedStatus: string;
  }>;
}

const DATA_PREFIX = '/data/oss-feed-registry';
const MAX_CATEGORY_CACHE = 50;

const categoryBodyCache: BodyCache<OssCategoryBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: OssFeedsIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://oss-feeds.local');
}

export async function loadOssFeedsIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<OssFeedsIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<OssFeedsIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `OSS Feeds index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-oss-feeds.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getOssFeedsByCategory(assets: Fetcher, category: string): Promise<OssCategoryBody | null> {
  const slug = category.toLowerCase().replace(/[^a-z0-9]/g, '-');
  const hit = trackHit(categoryBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<OssCategoryBody>(assets, `${DATA_PREFIX}/categories/${slug}.json`);
  if (!body) return null;
  return recordHit(categoryBodyCache, slug, body, MAX_CATEGORY_CACHE);
}

export interface OssFeedListOptions {
  vendor?: string;
  category?: string;
  status?: string;
  keyword?: string;
  limit?: number;
}

export function filterFeeds(idx: OssFeedsIndex, opts: OssFeedListOptions = {}): OssFeedIndexEntry[] {
  const { vendor, category, status, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: OssFeedIndexEntry[] = [];
  for (const f of idx.feedIndex) {
    if (category && f.category !== category) continue;
    if (status && f.feedStatus !== status) continue;
    if (vendor && !f.vendor.toLowerCase().includes(vendor.toLowerCase())) continue;
    if (needle) {
      const hay = `${f.vendor} ${f.description} ${f.category} ${f.feedStatus}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(f);
    if (out.length >= limit) break;
  }
  return out;
}

export function ossFeedsCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  categories: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    categories: { size: categoryBodyCache.map.size, hits: categoryBodyCache.hits, misses: categoryBodyCache.misses },
  };
}

export function _resetOssFeedsCacheForTests(): void {
  categoryBodyCache.map.clear();
  cachedIndex = null;
  cachedIndexAt = null;
  categoryBodyCache.hits = categoryBodyCache.misses = 0;
}
