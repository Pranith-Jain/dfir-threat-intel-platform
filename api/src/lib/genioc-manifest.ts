/**
 * Gen Threat Labs IoC manifest loader (gendigitalinc/ioc).
 *
 * Reads the static JSON manifest shipped in /public/data/genioc/
 * (built by scripts/build-genioc-manifest.mjs from the upstream repo
 * tarball). The Worker fetches through env.ASSETS — no D1, no KV, and
 * critically no GitHub contents API at runtime (that listing call was
 * a rate-limit fragility for anonymous workers).
 *
 * Shape:
 *   /data/genioc/index.json           (slim family cards + counts)
 *   /data/genioc/sections/<slug>.json (full classified IoC set per family)
 *
 * Source: https://github.com/gendigitalinc/ioc (Gen Threat Labs), DRL 1.1.
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface GeniocFamilyCard {
  slug: string;
  name: string;
  hashes: number;
  network: number;
  mutexes: number;
  filenames: number;
  extras: number;
  yara: number;
  summary?: string;
}

export interface GeniocIndex {
  source: string;
  license: string;
  builtAt: string;
  counts: {
    families: number;
    hashes: number;
    network: number;
    mutexes: number;
    filenames: number;
    yara: number;
  };
  families: GeniocFamilyCard[];
}

export interface GeniocExtra {
  name: string;
  count: number;
  bytes: number;
  kind: 'list' | 'doc' | 'script' | 'other';
}

export interface GeniocSection {
  name: string;
  slug: string;
  readme: { summary: string; links: string[] } | null;
  extras: GeniocExtra[];
  yara: { name: string; rules: number; names: string[] }[];
  totals: Record<string, number>;
  iocs: {
    domains: string[];
    ips: string[];
    urls: string[];
    cidrs: string[];
    md5: string[];
    sha1: string[];
    sha256: string[];
    mutexes: string[];
    filenames: string[];
    other: string[];
  };
}

const DATA_PREFIX = '/data/genioc';
const MAX_SECTION_CACHE = 100;

const sectionCache: BodyCache<GeniocSection> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: GeniocIndex | null = null;

function safeFilename(slug: string): string {
  return slug.replace(/[^A-Za-z0-9._-]/g, '_');
}

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://genioc.local');
}

export async function loadGeniocIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<GeniocIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<GeniocIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Genioc manifest not found at ${DATA_PREFIX}/index.json — did the build run? Run \`node scripts/build-genioc-manifest.mjs\`.`
    );
  }
  cachedIndex = idx;
  return idx;
}

export async function getGeniocFamily(assets: Fetcher, slug: string): Promise<GeniocSection | null> {
  const key = slug.toLowerCase();
  const hit = trackHit(sectionCache, key);
  if (hit) return hit;
  const body = await fetchJson<GeniocSection>(assets, `${DATA_PREFIX}/sections/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(sectionCache, key, body, MAX_SECTION_CACHE);
}

export interface GeniocListOptions {
  q?: string;
  minHashes?: number;
  withYara?: boolean;
  limit?: number;
}

export function filterGeniocFamilies(idx: GeniocIndex, opts: GeniocListOptions = {}): GeniocFamilyCard[] {
  const needle = opts.q?.toLowerCase();
  const out: GeniocFamilyCard[] = [];
  for (const f of idx.families) {
    if (opts.minHashes !== undefined && f.hashes < opts.minHashes) continue;
    if (opts.withYara && f.yara === 0) continue;
    if (needle) {
      const hay = `${f.name} ${f.summary ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(f);
    if (out.length >= (opts.limit ?? 200)) break;
  }
  return out;
}

export function geniocCacheStats() {
  return {
    index: cachedIndex ? { builtAt: cachedIndex.builtAt, counts: cachedIndex.counts } : null,
    section: { hits: sectionCache.hits, misses: sectionCache.misses, size: sectionCache.map.size },
  };
}
