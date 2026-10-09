/**
 * DFIR Reference manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/dfir-ref/
 * (Windows Event IDs, memory forensics, browser artifacts, evidence
 * collection) through the env.ASSETS binding.
 *
 * Shape:
 *   /data/dfir-ref/index.json
 *   /data/dfir-ref/sections/<category>/<slug>.json
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface DfirRefCategory {
  key: string;
  name: string;
  count: number;
}

export interface DfirRefIndexEntry {
  slug: string;
  id: string;
  name: string;
  category: string;
  categoryLabel: string;
  tags: string[];
  mitre: string | null;
  sizeBytes: number;
}

export interface DfirRefIndex {
  metadata: { description: string; totalItems: number; totalCategories: number };
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: { eventIds: number; memoryCommands: number; browserArtifacts: number; evidencePhases: number };
  categories: DfirRefCategory[];
  itemIndex: DfirRefIndexEntry[];
}

export interface DfirRefItemBody {
  slug: string;
  category: string;
  categoryLabel: string;
  [key: string]: string | number | string[] | null;
}

const DATA_PREFIX = '/data/dfir-ref';
const MAX_BODY_CACHE = 200;

const bodyCache: BodyCache<DfirRefItemBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: DfirRefIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://dfirref.local');
}

export async function loadDfirRefIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<DfirRefIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<DfirRefIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `DFIR Ref index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-dfir-ref.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getDfirRefItem(assets: Fetcher, slug: string): Promise<DfirRefItemBody | null> {
  const hit = trackHit(bodyCache, slug);
  if (hit) return hit;
  const idx = await loadDfirRefIndex(assets);
  const entry = idx.itemIndex.find((e) => e.slug === slug);
  if (!entry) return null;
  const body = await fetchJson<DfirRefItemBody>(assets, `${DATA_PREFIX}/sections/${entry.category}/${slug}.json`);
  if (!body) return null;
  return recordHit(bodyCache, slug, body, MAX_BODY_CACHE);
}

export interface DfirRefListOptions {
  category?: string;
  keyword?: string;
  mitre?: string;
  limit?: number;
}

export function filterDfirRefItems(idx: DfirRefIndex, opts: DfirRefListOptions = {}): DfirRefIndexEntry[] {
  const { category, keyword, mitre, limit = 200 } = opts;
  const needle = keyword?.toLowerCase();
  const out: DfirRefIndexEntry[] = [];
  for (const e of idx.itemIndex) {
    if (category && e.category !== category) continue;
    if (mitre && e.mitre !== mitre) continue;
    if (needle) {
      const hay = `${e.name} ${e.id} ${e.categoryLabel} ${e.tags.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

export function dfirRefCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  items: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    items: { size: bodyCache.map.size, hits: bodyCache.hits, misses: bodyCache.misses },
  };
}

export function _resetDfirRefCacheForTests(): void {
  bodyCache.map.clear();
  bodyCache.hits = bodyCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
