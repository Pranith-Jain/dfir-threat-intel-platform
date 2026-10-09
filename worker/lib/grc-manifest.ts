/**
 * GRC manifest loader.
 *
 * Reads the static compliance checklist manifest shipped in
 * /public/data/grc/ (ISO 27001:2022, CERT-In 2022, SEBI CSCRF, RBI IT
 * framework, SOC 2, PCI DSS v4, DPDP 2023 + cross-framework mapper + AI
 * risk register) through the env.ASSETS binding — no D1, no KV, no public
 * fetch.
 *
 * Shape:
 *   /data/grc/index.json              (slim framework index + mapper)
 *   /data/grc/frameworks/<key>.json   (full control lists)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface GrcFrameworkCategory {
  key: string;
  name: string;
  controls: GrcControl[];
}

export interface GrcControl {
  id: string;
  title: string;
  description?: string;
  priority?: 'P0' | 'P1' | 'P2' | 'P3';
  references?: string[];
}

export interface GrcFrameworkBrief {
  key: string;
  name: string;
  year: string;
  description: string;
  themes: string[];
  categories: { key: string; name: string; count: number }[];
  controlCount: number;
}

export interface GrcMapperTheme {
  id: string;
  name: string;
  description: string;
  mappings: { key: string; label: string; controls: string[] }[];
}

export interface GrcIndex {
  metadata: {
    description: string;
    totalFrameworks: number;
    totalControls: number;
    mapperThemes: number;
  };
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: { frameworks: number; controls: number; mapperThemes: number };
  frameworks: GrcFrameworkBrief[];
  mapper: { title: string; description: string; themes: GrcMapperTheme[] };
}

export interface GrcFramework {
  key: string;
  name: string;
  year: string;
  description: string;
  themes: string[];
  categories: GrcFrameworkCategory[];
}

const DATA_PREFIX = '/data/grc';
const MAX_BODY_CACHE = 20;

const frameworkCache: BodyCache<GrcFramework> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: GrcIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://grc.local');
}

export async function loadGrcIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<GrcIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<GrcIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `GRC index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-grc-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getGrcFramework(assets: Fetcher, key: string): Promise<GrcFramework | null> {
  const hit = trackHit(frameworkCache, key);
  if (hit) return hit;
  const body = await fetchJson<GrcFramework>(assets, `${DATA_PREFIX}/frameworks/${key}.json`);
  if (!body) return null;
  return recordHit(frameworkCache, key, body, MAX_BODY_CACHE);
}

export interface GrcControlLookupOptions {
  framework?: string;
  theme?: string;
  tier?: string;
  keyword?: string;
  limit?: number;
}

export function filterGrcFrameworks(idx: GrcIndex, opts: GrcControlLookupOptions = {}): GrcFrameworkBrief[] {
  const { theme, keyword, limit = 50 } = opts;
  const needle = keyword?.toLowerCase();
  const out: GrcFrameworkBrief[] = [];
  for (const f of idx.frameworks) {
    if (theme && !f.themes.some((t) => t.toLowerCase().includes(theme.toLowerCase()))) continue;
    if (needle) {
      const hay = `${f.name} ${f.description} ${f.themes.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(f);
    if (out.length >= limit) break;
  }
  return out;
}

export function grcCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  frameworks: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    frameworks: { size: frameworkCache.map.size, hits: frameworkCache.hits, misses: frameworkCache.misses },
  };
}

export function _resetGrcCacheForTests(): void {
  frameworkCache.map.clear();
  frameworkCache.hits = frameworkCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
