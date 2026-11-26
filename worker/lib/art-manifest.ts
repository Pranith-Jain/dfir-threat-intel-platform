/**
 * Atomic Red Team catalog manifest — ATT&CK technique index with test
 * metadata and upstream deep links.
 *
 * Edge loader for the replication of redcanaryco/atomic-red-team (MIT) as
 * presented by https://www.atomicredteam.io, built by
 * scripts/build-art-manifest.mjs into public/data/art/. Read through
 * env.ASSETS — no D1, no KV, no public fetch.
 *
 * Only metadata is stored: executor *type*, platforms, argument names and
 * dependency counts. Raw test commands are deliberately not vendored; each
 * body deep-links its upstream YAML, which is the canonical test source.
 */

export interface ArtTest {
  name: string;
  guid: string;
  description: string;
  platforms: string[];
  executor: {
    name: string;
    elevationRequired: boolean;
    hasCleanup: boolean;
  };
  inputArguments: string[];
  dependencyCount: number;
}

export interface ArtTechniqueSlim {
  id: string;
  displayName: string;
  testCount: number;
  platforms: string[];
  executors: string[];
  subtechnique: boolean;
  upstreamUrl: string;
}

export interface ArtTechniqueBody extends ArtTechniqueSlim {
  tests: ArtTest[];
}

export interface ArtIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  siteUrl: string;
  license: string;
  description: string;
  stats: {
    techniques: number;
    tests: number;
    platforms: number;
    executors: number;
    failed: number;
  };
  platformCounts: Record<string, number>;
  executorCounts: Record<string, number>;
  techniques: ArtTechniqueSlim[];
}

const DATA_PREFIX = '/data/art';

let cachedIndex: ArtIndex | null = null;
let cachedIndexAt: number | null = null;
const bodyCache = new Map<string, ArtTechniqueBody>();
let cacheHits = 0;
let cacheMisses = 0;
const BODY_CACHE_MAX = 100;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://art.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

export async function loadArtIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<ArtIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<ArtIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Atomic Red Team index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-art-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export interface ArtTechniqueFilter {
  keyword?: string;
  platform?: string;
  executor?: string;
  subtechnique?: boolean;
  minTests?: number;
  limit?: number;
}

export function filterArtTechniques(rows: ArtTechniqueSlim[], opts: ArtTechniqueFilter = {}): ArtTechniqueSlim[] {
  const { keyword, platform, executor, subtechnique, minTests, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: ArtTechniqueSlim[] = [];
  for (const r of rows) {
    if (needle && !`${r.id} ${r.displayName}`.toLowerCase().includes(needle)) continue;
    if (platform && !r.platforms.some((p) => p.toLowerCase() === platform.toLowerCase())) continue;
    if (executor && !r.executors.some((e) => e.toLowerCase() === executor.toLowerCase())) continue;
    if (subtechnique !== undefined && r.subtechnique !== subtechnique) continue;
    if (minTests !== undefined && r.testCount < minTests) continue;
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getArtTechnique(assets: Fetcher, id: string): Promise<ArtTechniqueBody | null> {
  const techniqueId = id.toUpperCase();
  if (!/^T\d{4}(\.\d{3})?$/.test(techniqueId)) return null;
  const hit = bodyCache.get(techniqueId);
  if (hit) {
    cacheHits++;
    bodyCache.delete(techniqueId);
    bodyCache.set(techniqueId, hit);
    return hit;
  }
  cacheMisses++;
  const body = await fetchJson<ArtTechniqueBody>(assets, `${DATA_PREFIX}/techniques/${techniqueId}.json`);
  if (!body) return null;
  if (bodyCache.has(techniqueId)) bodyCache.delete(techniqueId);
  bodyCache.set(techniqueId, body);
  while (bodyCache.size > BODY_CACHE_MAX) {
    const oldest = bodyCache.keys().next();
    if (oldest.done) break;
    bodyCache.delete(oldest.value);
  }
  return body;
}

export function artCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodies: number;
  hits: number;
  misses: number;
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodies: bodyCache.size,
    hits: cacheHits,
    misses: cacheMisses,
  };
}

export function _resetArtCacheForTests(): void {
  cachedIndex = null;
  cachedIndexAt = null;
  bodyCache.clear();
  cacheHits = 0;
  cacheMisses = 0;
}
