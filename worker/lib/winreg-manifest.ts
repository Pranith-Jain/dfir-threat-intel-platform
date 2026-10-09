/**
 * WinReg DFIR manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/winreg/ (the
 * Windows Registry Forensic Artifacts schema replicated from
 * github.com/dfir-scripts/dfir-scripts.github.io, MIT). The Worker fetches
 * them through the env.ASSETS binding — the data lives in dist/data/winreg/
 * after `npm run build`, and the Worker can pull it back through ASSETS
 * without going over the public internet.
 *
 * Shape:
 *   /data/winreg/index.json                  (~95 KB, slim artifact index)
 *   /data/winreg/artifacts/<slug>.json       (1 per artifact, full body)
 *
 * Source: https://dfir-scripts.github.io/registry/
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface WinRegCategory {
  key: string;
  name: string;
  description: string;
  count: number;
}

export interface WinRegArtifactIndexEntry {
  slug: string;
  name: string;
  category: string;
  categoryLabel: string;
  hive: string[];
  techniques: string[];
  mitre: string | null;
  tool: string[];
  sizeBytes: number;
}

export interface WinRegIndex {
  metadata: {
    version: string;
    description: string;
    totalArtifacts: number;
    totalCategories: number;
  };
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: {
    artifacts: number;
    categories: number;
    hives: number;
    tactics: number;
    techniques: number;
  };
  hives: string[];
  tactics: string[];
  techniques: string[];
  categories: WinRegCategory[];
  artifactIndex: WinRegArtifactIndexEntry[];
}

export interface WinRegArtifactBody {
  slug: string;
  name: string;
  category: string;
  categoryLabel: string;
  categoryDescription: string;
  hive: string[];
  keys: string[];
  description: string;
  forensic_value: string;
  mitre: string | null;
  techniques: string[];
  parsers: string[];
  source: string;
  sourceUrl: string;
  license: string;
}

const DATA_PREFIX = '/data/winreg';
const MAX_BODY_CACHE = 200;

const artifactBodyCache: BodyCache<WinRegArtifactBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: WinRegIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://winreg.local');
}

export async function loadWinRegIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<WinRegIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<WinRegIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `WinReg index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-winreg-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getWinRegArtifact(assets: Fetcher, slug: string): Promise<WinRegArtifactBody | null> {
  const hit = trackHit(artifactBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<WinRegArtifactBody>(assets, `${DATA_PREFIX}/artifacts/${slug}.json`);
  if (!body) return null;
  return recordHit(artifactBodyCache, slug, body, MAX_BODY_CACHE);
}

export interface WinRegListOptions {
  category?: string;
  hive?: string;
  technique?: string;
  keyword?: string;
  limit?: number;
}

export function filterArtifacts(idx: WinRegIndex, opts: WinRegListOptions = {}): WinRegArtifactIndexEntry[] {
  const { category, hive, technique, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: WinRegArtifactIndexEntry[] = [];
  for (const a of idx.artifactIndex) {
    if (category && a.category !== category) continue;
    if (hive && !a.hive.some((h) => h.toLowerCase().includes(hive.toLowerCase()))) continue;
    if (technique && !a.techniques.includes(technique)) continue;
    if (needle) {
      const hay =
        `${a.slug} ${a.name} ${a.categoryLabel} ${a.hive.join(' ')} ${a.techniques.join(' ')} ${a.tool.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(a);
    if (out.length >= limit) break;
  }
  return out;
}

export function winRegCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  artifacts: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    artifacts: { size: artifactBodyCache.map.size, hits: artifactBodyCache.hits, misses: artifactBodyCache.misses },
  };
}

export function _resetWinRegCacheForTests(): void {
  artifactBodyCache.map.clear();
  cachedIndex = null;
  cachedIndexAt = null;
  artifactBodyCache.hits = artifactBodyCache.misses = 0;
}
