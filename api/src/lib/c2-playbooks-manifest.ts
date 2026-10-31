/**
 * C2 & infrastructure hunting playbook manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/c2-playbooks/
 * (built by scripts/build-c2-playbooks.mjs from MANTIS's curated
 * C2 hunting catalog). The Worker fetches through env.ASSETS — no D1,
 * no KV, no upstream KB calls at runtime.
 *
 * Shape:
 *   /data/c2-playbooks/index.json           (counts, engines, categories, fingerprints)
 *   /data/c2-playbooks/sections/<engine>.json (full entry list per engine)
 *
 * Source: https://github.com/fareedfauzi/MANTIS (MIT), backend/c2_hunting_catalog.py.
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface C2PlaybookEntry {
  id: string;
  family: string;
  category: string;
  technique: string;
  engine: string;
  query: string;
  externalUrl: string;
  notes?: string;
  hash?: string;
}

export interface C2PlaybooksIndex {
  source: string;
  license: string;
  portedFrom: string;
  builtAt: string;
  counts: { entries: number; engines: number; categories: number; families: number };
  engines: Record<string, number>;
  categories: Record<string, number>;
  topFamilies: { family: string; count: number }[];
  faviconHashes: { family: string; hash: string }[];
  jarmHashes: { family: string; hash: string }[];
}

const DATA_PREFIX = '/data/c2-playbooks';
const MAX_SECTION_CACHE = 12; // one per engine — small even if all opened

const sectionCache: BodyCache<EngineSection> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: C2PlaybooksIndex | null = null;

export interface EngineSection {
  engine: string;
  count: number;
  entries: C2PlaybookEntry[];
}

function safeFilename(engine: string): string {
  return engine.replace(/[^A-Za-z0-9._-]/g, '_');
}

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://c2playbooks.local');
}

export async function loadC2PlaybooksIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<C2PlaybooksIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<C2PlaybooksIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `C2 playbooks manifest not found at ${DATA_PREFIX}/index.json — did the build run? Run \`node scripts/build-c2-playbooks.mjs\`.`
    );
  }
  cachedIndex = idx;
  return idx;
}

export async function getC2EngineSection(assets: Fetcher, engine: string): Promise<EngineSection | null> {
  const key = engine.toLowerCase();
  if (key === 'all') return null;
  const hit = trackHit(sectionCache, key);
  if (hit) return hit;
  const body = await fetchJson<EngineSection>(assets, `${DATA_PREFIX}/sections/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(sectionCache, key, body, MAX_SECTION_CACHE);
}

/** Load every engine section up-front when the API is queried cross-engine. */
export async function loadAllEngineSections(assets: Fetcher): Promise<EngineSection[]> {
  const idx = await loadC2PlaybooksIndex(assets);
  const sections: EngineSection[] = [];
  for (const engine of Object.keys(idx.engines)) {
    const sec = await getC2EngineSection(assets, engine);
    if (sec) sections.push(sec);
  }
  return sections;
}

export interface C2PlaybookQuery {
  q?: string;
  engine?: string;
  family?: string;
  category?: string;
  limit?: number;
  offset?: number;
}

/**
 * query_playbooks — ported from c2_hunting_catalog.query_playbooks
 * (same filter lanes: engine, category, family, free-text haystack).
 */
export function filterPlaybooks(sections: EngineSection[], opts: C2PlaybookQuery = {}) {
  const q = opts.q?.toLowerCase().trim();
  const engine = opts.engine?.toLowerCase().trim();
  const family = opts.family?.toLowerCase().trim();
  const category = opts.category?.toLowerCase().trim();
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), 500);
  const offset = Math.max(opts.offset ?? 0, 0);

  const filtered: C2PlaybookEntry[] = [];
  for (const sec of sections) {
    if (engine && engine !== 'all' && sec.engine !== engine) continue;
    for (const item of sec.entries) {
      if (category && category !== 'all' && item.category.toLowerCase() !== category) continue;
      if (family && family !== 'all' && !item.family.toLowerCase().includes(family)) continue;
      if (q) {
        const hay = `${item.family} ${item.technique} ${item.category} ${item.query} ${item.notes ?? ''}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }
      filtered.push(item);
    }
  }
  const total = filtered.length;
  return { total, offset, limit, items: filtered.slice(offset, offset + limit) };
}

/** Fingerprint lookup: favicon MMH3 (± int), JARM (62 hex) or payload SHA-256 kind hint. */
export function lookupFingerprint(idx: C2PlaybooksIndex, value: string) {
  const v = value.trim().toLowerCase();
  if (!v) return null;
  if (idx.jarmHashes.some((j) => j.hash === v)) {
    const families = [...new Set(idx.jarmHashes.filter((j) => j.hash === v).map((j) => j.family))];
    return { kind: 'jarm' as const, value: v, families };
  }
  const favicon = idx.faviconHashes.find((f) => f.hash === value.trim());
  if (favicon) return { kind: 'favicon-mmh3' as const, value: favicon.hash, families: [favicon.family] };
  if (/^[a-f\d]{64}$/.test(v)) {
    return { kind: 'sha256' as const, value: v, families: [] }; // payload hashes live in urlscan entries, not the index
  }
  return null;
}

/** Payload SHA-256 lookup: find urlscan entries whose associated payload hash matches. */
export function lookupSha256(sections: EngineSection[], value: string): C2PlaybookEntry[] {
  const v = value.trim().toLowerCase();
  if (!/^[a-f\d]{64}$/.test(v)) return [];
  return sections.flatMap((s) => s.entries).filter((e) => e.hash?.toLowerCase() === v);
}

export function c2PlaybooksCacheStats() {
  return {
    index: cachedIndex ? { builtAt: cachedIndex.builtAt, counts: cachedIndex.counts } : null,
    section: { hits: sectionCache.hits, misses: sectionCache.misses, size: sectionCache.map.size },
  };
}
