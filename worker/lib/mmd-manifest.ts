/**
 * MMD toolkit manifest — MalwareMustDie shared codes & tools collection.
 *
 * Edge loader for the replicated catalog of
 * github.com/unixfreaxjp/malwaremustdie: the open-share repository of the
 * MalwareMustDie (MMD) non-profit malware awareness team (est. 2012) —
 * malware-analysis tooling, log-triage utilities, radare2 material, slides
 * and case notes across 12 language-organized directories (228 files).
 *
 * Data source: public/data/mmd/ (built by scripts/build-mmd-manifest.mjs),
 * read through env.ASSETS — no D1, no KV, no public fetch. The weekly sync
 * workflow re-fetches the GitHub tree + commits so new upstream commits
 * surface as refreshed manifest data.
 */

export interface MmdFile {
  path: string;
  name: string;
  category: string;
  ext: string;
  kind: string;
  size: number;
}

export interface MmdCategorySummary {
  category: string;
  description: string;
  count: number;
  totalSize: number;
  kinds: Record<string, number>;
}

export interface MmdCommit {
  sha: string;
  date: string | null;
  author: string | null;
  message: string;
}

export interface MmdIndex {
  source: string;
  sourceUrl: string;
  siteUrl: string;
  license: string;
  builtAt: string;
  branch: string;
  about: string;
  counts: {
    files: number;
    categories: number;
    scripts: number;
    docs: number;
    binaries: number;
    totalSize: number;
    commitsTracked: number;
    recentCommits: number;
  };
  categories: MmdCategorySummary[];
  files: MmdFile[];
  recentCommits: MmdCommit[];
  lastCommit: string | null;
}

export interface MmdCategoryBody {
  category: string;
  description: string;
  count: number;
  totalSize: number;
  source: string;
  sourceUrl: string;
  license: string;
  files: MmdFile[];
}

const DATA_PREFIX = '/data/mmd';

let cachedIndex: MmdIndex | null = null;
let cachedIndexAt: number | null = null;
const bodyCache = new Map<string, MmdCategoryBody | MmdCommitsBody | string>();
let bodyHits = 0;
let bodyMisses = 0;
const BODY_CACHE_MAX = 40;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://mmd.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

function bodyGet<T>(key: string): T | null {
  const v = bodyCache.get(key);
  if (v === undefined) {
    bodyMisses++;
    return null;
  }
  bodyHits++;
  bodyCache.delete(key);
  bodyCache.set(key, v);
  return v as unknown as T;
}

function bodySet(key: string, value: MmdCategoryBody | MmdCommitsBody | string): void {
  if (bodyCache.has(key)) bodyCache.delete(key);
  bodyCache.set(key, value);
  while (bodyCache.size > BODY_CACHE_MAX) {
    const oldest = bodyCache.keys().next();
    if (oldest.done) break;
    bodyCache.delete(oldest.value);
  }
}

export async function loadMmdIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<MmdIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<MmdIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `MMD index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-mmd-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export interface MmdToolListOptions {
  category?: string;
  kind?: string;
  ext?: string;
  keyword?: string;
  limit?: number;
}

export function listMmdTools(idx: MmdIndex, opts: MmdToolListOptions = {}): MmdFile[] {
  const { category, kind, ext, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: MmdFile[] = [];
  for (const f of idx.files) {
    if (category && f.category.toLowerCase() !== category.toLowerCase()) continue;
    if (kind && f.kind.toLowerCase() !== kind.toLowerCase()) continue;
    if (ext && f.ext.toLowerCase() !== ext.toLowerCase()) continue;
    if (needle && !f.path.toLowerCase().includes(needle)) continue;
    out.push(f);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getMmdCategory(assets: Fetcher, category: string): Promise<MmdCategoryBody | null> {
  const key = `category:${category.toLowerCase()}`;
  const cached = bodyGet<MmdCategoryBody>(key);
  if (cached) return cached;
  const body = await fetchJson<MmdCategoryBody>(
    assets,
    `${DATA_PREFIX}/categories/${encodeURIComponent(category)}.json`
  );
  if (!body) return null;
  bodySet(key, body);
  return body;
}

export interface MmdCommitsBody {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  count: number;
  commits: MmdCommit[];
}

export async function loadMmdCommits(assets: Fetcher): Promise<MmdCommitsBody | null> {
  const cached = bodyGet<MmdCommitsBody>('commits');
  if (cached) return cached;
  const body = await fetchJson<MmdCommitsBody>(assets, `${DATA_PREFIX}/commits.json`);
  if (!body) return null;
  bodySet('commits', body);
  return body;
}

export async function loadMmdReadme(assets: Fetcher): Promise<string | null> {
  const cached = bodyGet<string>('readme');
  if (cached) return cached;
  const body = await fetchJson<{ body: string }>(assets, `${DATA_PREFIX}/readme.json`);
  if (!body?.body) return null;
  bodySet('readme', body.body);
  return body.body;
}

export function mmdCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodies: number;
  bodyHits: number;
  bodyMisses: number;
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodies: bodyCache.size,
    bodyHits,
    bodyMisses,
  };
}

export function _resetMmdCacheForTests(): void {
  cachedIndex = null;
  cachedIndexAt = null;
  bodyCache.clear();
  bodyHits = 0;
  bodyMisses = 0;
}
