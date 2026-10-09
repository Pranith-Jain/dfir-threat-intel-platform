/**
 * SIEM Use-Case Library manifest loader.
 *
 * Reads the static detection use-case manifest shipped in
 * /public/data/siem-library/ (60 detection use-cases with KQL + SPL,
 * MITRE ATT&CK mapping, FP guidance and APT attribution) through the
 * env.ASSETS binding — no D1, no KV, no public fetch.
 *
 * Shape:
 *   /data/siem-library/index.json          (slim index)
 *   /data/siem-library/use-cases/<id>.json (full use-case)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface SiemUseCaseIndexEntry {
  id: string;
  name: string;
  category: string;
  mitre: string;
  severity: string;
}

export interface SiemLibraryIndex {
  metadata: { description: string; totalUseCases: number; totalCategories: number };
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: { useCases: number; categories: number; techniques: number };
  categories: { name: string; count: number }[];
  severities: Record<string, number>;
  techniques: Record<string, number>;
  useCaseIndex: SiemUseCaseIndexEntry[];
}

export interface SiemUseCaseBody {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: string;
  mitre: string;
  mitreName?: string;
  query: { kql: string; spl?: string; sigma?: string };
  tuning: string;
  falsePositives: string[] | string;
  apt?: string;
  references?: string[];
  tags: string[];
}

const DATA_PREFIX = '/data/siem-library';
const MAX_BODY_CACHE = 120;

const useCaseCache: BodyCache<SiemUseCaseBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: SiemLibraryIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://siem.local');
}

export async function loadSiemLibraryIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<SiemLibraryIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<SiemLibraryIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `SIEM Library index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-siem-library.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getSiemUseCase(assets: Fetcher, id: string): Promise<SiemUseCaseBody | null> {
  const hit = trackHit(useCaseCache, id);
  if (hit) return hit;
  const body = await fetchJson<SiemUseCaseBody>(assets, `${DATA_PREFIX}/use-cases/${id}.json`);
  if (!body) return null;
  return recordHit(useCaseCache, id, body, MAX_BODY_CACHE);
}

export interface SiemListOptions {
  category?: string;
  mitre?: string;
  severity?: string;
  keyword?: string;
  limit?: number;
}

export function filterSiemUseCases(idx: SiemLibraryIndex, opts: SiemListOptions = {}): SiemUseCaseIndexEntry[] {
  const { category, mitre, severity, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: SiemUseCaseIndexEntry[] = [];
  for (const u of idx.useCaseIndex) {
    if (category && u.category !== category) continue;
    if (mitre && u.mitre !== mitre) continue;
    if (severity && u.severity !== severity) continue;
    if (needle) {
      const hay = `${u.id} ${u.name} ${u.category} ${u.mitre}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(u);
    if (out.length >= limit) break;
  }
  return out;
}

export function siemLibraryCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  useCases: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    useCases: { size: useCaseCache.map.size, hits: useCaseCache.hits, misses: useCaseCache.misses },
  };
}

export function _resetSiemLibraryCacheForTests(): void {
  useCaseCache.map.clear();
  useCaseCache.hits = useCaseCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
