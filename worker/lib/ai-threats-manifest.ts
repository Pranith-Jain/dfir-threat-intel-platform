/**
 * AI Threat Actors manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/ai-threats/ (the
 * Cybershujin Threat Actors' Use of Artificial Intelligence tracker,
 * MIT). The Worker fetches them through the env.ASSETS binding.
 *
 * Shape:
 *   /data/ai-threats/index.json                (slim index)
 *   /data/ai-threats/entries/<slug>.json       (1 per threat entry)
 *
 * Source: https://cybershujin.github.io/Threat-Actors-use-of-Artifical-Intelligence/
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface AiThreatIndexEntry {
  slug: string;
  name: string;
  akas: string;
  brief: string;
  ttps: string[];
  categories: string[];
  reported: string;
  activity: string;
  table: string;
  sizeBytes: number;
}

export interface AiThreatsIndex {
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  lastSyncedAt: string;
  counts: {
    total: number;
    main: number;
    deepfake: number;
  };
  stixAvailable: boolean;
  threatIndex: AiThreatIndexEntry[];
}

export interface AiThreatBody extends AiThreatIndexEntry {
  brief: string;
  ttpMd: string;
}

const DATA_PREFIX = '/data/ai-threats';
const MAX_BODY_CACHE = 200;

const entryBodyCache: BodyCache<AiThreatBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: AiThreatsIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://ai-threats.local');
}

export async function loadAiThreatsIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<AiThreatsIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<AiThreatsIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `AI Threats index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-ai-threats.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getAiThreat(assets: Fetcher, slug: string): Promise<AiThreatBody | null> {
  const hit = trackHit(entryBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<AiThreatBody>(assets, `${DATA_PREFIX}/entries/${slug}.json`);
  if (!body) return null;
  return recordHit(entryBodyCache, slug, body, MAX_BODY_CACHE);
}

export interface AiThreatListOptions {
  table?: string;
  category?: string;
  ttp?: string;
  keyword?: string;
  limit?: number;
}

export function filterThreats(idx: AiThreatsIndex, opts: AiThreatListOptions = {}): AiThreatIndexEntry[] {
  const { table, category, ttp, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: AiThreatIndexEntry[] = [];
  for (const e of idx.threatIndex) {
    if (table && e.table !== table) continue;
    if (category && !e.categories.some((c) => c.toLowerCase().includes(category.toLowerCase()))) continue;
    if (ttp && !e.ttps.includes(ttp)) continue;
    if (needle) {
      const hay =
        `${e.slug} ${e.name} ${e.akas} ${e.brief} ${e.ttps.join(' ')} ${e.categories.join(' ')} ${e.reported} ${e.activity}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

export function aiThreatsCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  entries: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    entries: { size: entryBodyCache.map.size, hits: entryBodyCache.hits, misses: entryBodyCache.misses },
  };
}

export function _resetAiThreatsCacheForTests(): void {
  entryBodyCache.map.clear();
  cachedIndex = null;
  cachedIndexAt = null;
  entryBodyCache.hits = entryBodyCache.misses = 0;
}
