/**
 * Post-Quantum Cryptography manifest loader.
 *
 * Reads the static PQC reference manifest shipped in /public/data/pqc/
 * (NIST FIPS 203/204/205/206 algorithms, HNDL threat model, crypto class
 * risk table, readiness assessment) through the env.ASSETS binding — no
 * D1, no KV, no public fetch.
 *
 * Shape:
 *   /data/pqc/index.json                (slim index + classes + readiness)
 *   /data/pqc/algorithms/<slug>.json    (full algorithm reference)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface PqcAlgorithmIndexEntry {
  slug: string;
  name: string;
  fips: string;
  type: 'KEM' | 'Signature';
  status: string;
}

export interface PqcIndex {
  metadata: { description: string; totalAlgorithms: number; totalReadiness: number; totalCryptoClasses: number };
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: { algorithms: number; readiness: number; cryptoClasses: number };
  algorithmIndex: PqcAlgorithmIndexEntry[];
  models: string[];
  hndl: { title: string; description: string; summary: string };
  cryptoClasses: { id: string; name: string; risk: string; migration: string }[];
  readiness: { id: string; question: string; why: string }[];
}

export interface PqcAlgorithmBody {
  slug: string;
  name: string;
  fips: string;
  type: 'KEM' | 'Signature';
  status: string;
  class: string;
  keySizes: string;
  description: string;
  uses: string[];
  migration: string;
  rfc?: string;
}

const DATA_PREFIX = '/data/pqc';
const MAX_BODY_CACHE = 20;

const algorithmCache: BodyCache<PqcAlgorithmBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: PqcIndex | null = null;
let cachedIndexAt: number | null = null;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://pqc.local');
}

export async function loadPqcIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<PqcIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<PqcIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(`PQC index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-pqc.mjs' first.`);
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getPqcAlgorithm(assets: Fetcher, slug: string): Promise<PqcAlgorithmBody | null> {
  const hit = trackHit(algorithmCache, slug);
  if (hit) return hit;
  const body = await fetchJson<PqcAlgorithmBody>(assets, `${DATA_PREFIX}/algorithms/${slug}.json`);
  if (!body) return null;
  return recordHit(algorithmCache, slug, body, MAX_BODY_CACHE);
}

export function pqcCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  algorithms: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    algorithms: { size: algorithmCache.map.size, hits: algorithmCache.hits, misses: algorithmCache.misses },
  };
}

export function _resetPqcCacheForTests(): void {
  algorithmCache.map.clear();
  algorithmCache.hits = algorithmCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
