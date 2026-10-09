import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export type ToolCategory =
  | 'recon'
  | 'exploitation'
  | 'post-exploitation'
  | 'defense'
  | 'detection'
  | 'forensics'
  | 'osint'
  | 'c2'
  | 'phishing'
  | 'crypto'
  | 'mobile'
  | 'cloud'
  | 'network'
  | 'reverse-engineering'
  | 'web'
  | 'misc';

export interface ToolEntry {
  slug: string;
  name: string;
  category: ToolCategory;
  description: string;
  url: string;
  githubUrl?: string;
  language?: string;
  platforms?: string[];
  license?: string;
  isOpenSource: boolean;
  isOffensive: boolean;
  tags: string[];
  sizeBytes: number;
}

export interface ToolBody extends ToolEntry {
  fullDescription: string;
  features: string[];
  useCases: string[];
  alternatives?: string[];
  notes?: string;
}

const DATA_PREFIX = '/data/tools';
const MAX_BODY_CACHE = 100;

const bodyCache: BodyCache<ToolBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: ToolEntry[] | null = null;
let cachedIndexAt: number | null = null;
let cachedBodies: ToolBody[] | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://tools.local');
}

export async function loadToolsIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<ToolEntry[]> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const bodies = await fetchJson<ToolBody[]>(assets, `${DATA_PREFIX}/index.json`);
  if (!bodies) {
    throw new Error(
      `Tools manifest not found at ${DATA_PREFIX}/index.json — ` +
        'did the build run? Run `node scripts/build-tools-manifest.mjs`.'
    );
  }
  cachedBodies = bodies;
  cachedIndex = bodies.map((b) => {
    const { fullDescription, features, useCases, alternatives, notes, ...entry } = b;
    void fullDescription;
    void features;
    void useCases;
    void alternatives;
    void notes;
    return entry;
  });
  cachedIndexAt = Date.now();
  return cachedIndex;
}

export async function loadToolsBodies(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<ToolBody[]> {
  if (cachedBodies && !opts.forceRefresh) return cachedBodies;
  await loadToolsIndex(assets, opts);
  return cachedBodies ?? [];
}

export async function getTool(assets: Fetcher, slug: string): Promise<ToolBody | null> {
  const hit = trackHit(bodyCache, slug);
  if (hit) return hit;
  const bodies = await loadToolsBodies(assets);
  const body = bodies.find((b) => b.slug === slug) ?? null;
  if (!body) return null;
  return recordHit(bodyCache, slug, body, MAX_BODY_CACHE);
}

export interface ListToolsOptions {
  category?: ToolCategory;
  keyword?: string;
  offensive?: boolean;
  limit?: number;
}

export function listTools(idx: ToolEntry[], opts: ListToolsOptions = {}): ToolEntry[] {
  const { category, keyword, offensive, limit = 50 } = opts;
  const needle = keyword?.toLowerCase();
  const out: ToolEntry[] = [];
  for (const t of idx) {
    if (category && t.category !== category) continue;
    if (offensive !== undefined && t.isOffensive !== offensive) continue;
    if (needle) {
      const hay = `${t.slug} ${t.name} ${t.description} ${t.tags.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(t);
    if (out.length >= limit) break;
  }
  return out;
}

export function toolsCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodyCache: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodyCache: { size: bodyCache.map.size, hits: bodyCache.hits, misses: bodyCache.misses },
  };
}

export function _resetToolsCacheForTests(): void {
  bodyCache.map.clear();
  bodyCache.hits = bodyCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
  cachedBodies = null;
}
