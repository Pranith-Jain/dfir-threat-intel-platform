/**
 * Signature-Base manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/sigbase/ (the
 * YARA rule set + IOC lists replicated from github.com/Neo23x0/signature-base,
 * Detection Rule License 1.1). The Worker fetches them through the
 * env.ASSETS binding — the data lives in dist/data/sigbase/ after
 * `npm run build`, and the Worker can pull it back through ASSETS
 * without going over the public internet.
 *
 * Shape:
 *   /data/sigbase/index.json              (~170 KB, slim — no bodies)
 *   /data/sigbase/yara/<slug>.json        (1 per .yar file, full source + parsed rules)
 *   /data/sigbase/iocs/<slug>.json        (1 per IOC list: hashes / c2 / filenames / keywords)
 *
 * Source: github.com/Neo23x0/signature-base (DRL 1.1)
 *
 * In-memory cache: the index is kept forever after first fetch. Bodies
 * are cached on demand with an LRU bound of 200 entries to keep the
 * Worker under its 128 MB memory cap.
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export type SigBaseIocType = 'hash' | 'c2' | 'filename' | 'keyword';

export interface SigBaseYaraIndexEntry {
  slug: string;
  filename: string;
  identifier: string | null;
  ruleCount: number;
  tags: string[];
  author: string | null;
  date: string | null;
  score: number | null;
  /** True when the rule file needs LOKI/THOR external variables
   *  (undefined identifier errors under plain YARA). */
  externalVars: boolean;
  sizeBytes: number;
}

export interface SigBaseIocIndexEntry {
  slug: string;
  title: string;
  type: SigBaseIocType;
  entryCount: number;
  sizeBytes: number;
}

export interface SigBaseIndex {
  source: string;
  license: string;
  replicatedAt: string;
  counts: {
    yaraFiles: number;
    yaraRules: number;
    iocFiles: number;
    iocEntries: number;
    externalVarFiles: number;
  };
  yaraIndex: SigBaseYaraIndexEntry[];
  iocIndex: SigBaseIocIndexEntry[];
}

export interface SigBaseRuleMeta {
  description?: string;
  license?: string;
  author?: string;
  reference?: string;
  date?: string;
  hash?: string;
  hash1?: string;
  hash2?: string;
  score?: string;
  id?: string;
  tags?: string;
  [key: string]: string | undefined;
}

export interface SigBaseYaraRule {
  name: string;
  meta: SigBaseRuleMeta;
}

export interface SigBaseYaraBody extends SigBaseYaraIndexEntry {
  source: string;
  license: string;
  headerComment: string;
  rules: SigBaseYaraRule[];
  body: string;
}

export interface SigBaseIocEntry {
  value: string;
  comment?: string;
  type?: string | null;
  score?: number | null;
  exclude?: string | null;
  category?: string | null;
}

export interface SigBaseIocBody extends SigBaseIocIndexEntry {
  source: string;
  license: string;
  entries: SigBaseIocEntry[];
}

const DATA_PREFIX = '/data/sigbase';
const MAX_BODY_CACHE = 200;

const yaraBodyCache: BodyCache<SigBaseYaraBody> = { map: new Map(), hits: 0, misses: 0 };
const iocBodyCache: BodyCache<SigBaseIocBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: SigBaseIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://sigbase.local');
}

export async function loadSigBaseIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<SigBaseIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<SigBaseIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Signature-Base index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-sigbase-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getSigBaseYara(assets: Fetcher, slug: string): Promise<SigBaseYaraBody | null> {
  const hit = trackHit(yaraBodyCache, slug);
  if (hit) return hit;
  // Per-slug bodies ship without the index metadata (tags, author, date,
  // score, externalVars) — re-merge it from the index so every consumer
  // (REST, MCP, SPA modal) gets the complete entry shape.
  let entry: SigBaseYaraIndexEntry | undefined;
  try {
    const idx = await loadSigBaseIndex(assets);
    entry = idx.yaraIndex.find((y) => y.slug === slug);
  } catch {
    entry = undefined;
  }
  const body = await fetchJson<SigBaseYaraBody>(assets, `${DATA_PREFIX}/yara/${slug}.json`);
  if (!body) return null;
  if (entry) {
    body.slug = entry.slug;
    body.filename = entry.filename;
    body.identifier = entry.identifier;
    body.ruleCount = entry.ruleCount;
    body.tags = entry.tags;
    body.author = entry.author;
    body.date = entry.date;
    body.score = entry.score;
    body.externalVars = entry.externalVars;
    body.sizeBytes = entry.sizeBytes;
  } else {
    body.tags = body.tags ?? [];
    body.author = body.author ?? null;
    body.date = body.date ?? null;
    body.score = body.score ?? null;
    body.externalVars = body.externalVars ?? false;
    body.ruleCount = body.rules?.length ?? 0;
  }
  return recordHit(yaraBodyCache, slug, body, MAX_BODY_CACHE);
}

export async function getSigBaseIoc(assets: Fetcher, slug: string): Promise<SigBaseIocBody | null> {
  const hit = trackHit(iocBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<SigBaseIocBody>(assets, `${DATA_PREFIX}/iocs/${slug}.json`);
  if (!body) return null;
  return recordHit(iocBodyCache, slug, body, MAX_BODY_CACHE);
}

// ─── Filter helpers ────────────────────────────────────────────────────

export interface SigBaseListYaraOptions {
  /** Category tag: apt, malware, expl, gen, thr, etc. (filename prefix). */
  tag?: string;
  author?: string;
  /** Free-text match against slug, filename, identifier, author, tags. */
  keyword?: string;
  /** Only return rule files that need LOKI/THOR external variables. */
  externalVars?: boolean;
  limit?: number;
}

export interface SigBaseListIocOptions {
  type?: SigBaseIocType;
  keyword?: string;
  limit?: number;
}

export function filterYara(idx: SigBaseIndex, opts: SigBaseListYaraOptions = {}): SigBaseYaraIndexEntry[] {
  const { tag, author, keyword, externalVars, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const authorNeedle = author?.toLowerCase();
  const out: SigBaseYaraIndexEntry[] = [];
  for (const y of idx.yaraIndex) {
    if (tag && !y.tags.includes(tag)) continue;
    if (externalVars !== undefined && y.externalVars !== externalVars) continue;
    if (authorNeedle && !(y.author ?? '').toLowerCase().includes(authorNeedle)) continue;
    if (needle) {
      const hay = `${y.slug} ${y.filename} ${y.identifier ?? ''} ${y.author ?? ''} ${y.tags.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(y);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterIocs(idx: SigBaseIndex, opts: SigBaseListIocOptions = {}): SigBaseIocIndexEntry[] {
  const { type, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: SigBaseIocIndexEntry[] = [];
  for (const i of idx.iocIndex) {
    if (type && i.type !== type) continue;
    if (needle) {
      const hay = `${i.slug} ${i.title} ${i.type}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(i);
    if (out.length >= limit) break;
  }
  return out;
}

export function searchIocEntries(body: SigBaseIocBody, keyword?: string, limit = 500): SigBaseIocEntry[] {
  const needle = keyword?.toLowerCase();
  const out: SigBaseIocEntry[] = [];
  for (const e of body.entries) {
    if (needle) {
      const hay = `${e.value} ${e.comment ?? ''} ${e.category ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── Cache stats ───────────────────────────────────────────────────────

export function sigBaseCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  yara: { size: number; hits: number; misses: number };
  iocs: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    yara: { size: yaraBodyCache.map.size, hits: yaraBodyCache.hits, misses: yaraBodyCache.misses },
    iocs: { size: iocBodyCache.map.size, hits: iocBodyCache.hits, misses: iocBodyCache.misses },
  };
}

export function _resetSigBaseCacheForTests(): void {
  yaraBodyCache.map.clear();
  iocBodyCache.map.clear();
  yaraBodyCache.hits = yaraBodyCache.misses = 0;
  iocBodyCache.hits = iocBodyCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
