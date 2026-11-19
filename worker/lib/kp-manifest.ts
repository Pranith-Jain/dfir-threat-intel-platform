/**
 * Kitploit directory manifest — tools, CVE exploit evidence and feeds
 * (kitploit.com/en).
 *
 * Edge loader for the replicated crawl of Kitploit's public HTML + RSS
 * surfaces. Its robots.txt disallows /api/, so no JSON API is used: the
 * manifest holds newest tool cards, newest CVE evidence cards and the three
 * public feeds (updates / exploits / blog). Every item deep-links upstream;
 * no images or prose are vendored.
 *
 * Data source: public/data/kp/ (built by scripts/build-kp-manifest.mjs), read
 * through env.ASSETS — no D1, no KV, no public fetch.
 */

export interface KpTool {
  id: string;
  title: string;
  url: string;
  provider: string | null;
  repo: string | null;
  description: string | null;
  image: string | null;
  categories: string[];
  stars: string | null;
}

export interface KpExploit {
  id: string;
  cve: string | null;
  title: string;
  url: string;
  cvssScore: number | null;
  cvssSeverity: string | null;
  epss: string | null;
  exploitCount: number | null;
  evidence: string | null;
}

export interface KpFeedItemRef {
  title: string | null;
  url: string | null;
  published: string | null;
}

export interface KpFeedItem {
  title: string | null;
  url: string | null;
  description: string | null;
  published: string | null;
  guid: string | null;
  image: string | null;
}

export interface KpStats {
  listedTools: number;
  listedExploits: number;
  feedItems: Record<string, number>;
  byProvider: Record<string, number>;
  byCategory: Record<string, number>;
  byCvssSeverity: Record<string, number>;
  sourceLinks: number;
}

export interface KpIndex {
  source: string;
  sourceUrl: string;
  license: string;
  robots: string;
  builtAt: string;
  counts: {
    tools: number;
    exploits: number;
    updates: number;
    exploitUpdates: number;
    blogPosts: number;
  };
  stats: KpStats;
  tools: KpTool[];
  exploits: KpExploit[];
  feeds: Record<string, KpFeedItemRef[]>;
  webPages: Record<string, string>;
}

const DATA_PREFIX = '/data/kp';
let cachedIndex: KpIndex | null = null;
let indexHits = 0;
let indexMisses = 0;
const feedCache = new Map<string, KpFeedItem[]>();
let feedHits = 0;
let feedMisses = 0;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://kp.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

export async function loadKpIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<KpIndex> {
  if (cachedIndex && !opts.forceRefresh) {
    indexHits++;
    return cachedIndex;
  }
  indexMisses++;
  const idx = await fetchJson<KpIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Kitploit index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-kp-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  return idx;
}

export function filterKpTools(
  rows: KpTool[],
  opts: { category?: string; provider?: string; keyword?: string; limit?: number } = {}
): KpTool[] {
  const { category, provider, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: KpTool[] = [];
  for (const t of rows) {
    if (category && !t.categories.some((c) => c.toLowerCase() === category.toLowerCase())) continue;
    if (provider && String(t.provider).toLowerCase() !== provider.toLowerCase()) continue;
    if (
      needle &&
      !`${t.title} ${t.description ?? ''} ${t.repo ?? ''} ${t.categories.join(' ')}`.toLowerCase().includes(needle)
    )
      continue;
    out.push(t);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterKpExploits(
  rows: KpExploit[],
  opts: { severity?: string; keyword?: string; limit?: number } = {}
): KpExploit[] {
  const { severity, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: KpExploit[] = [];
  for (const e of rows) {
    if (severity && String(e.cvssSeverity).toLowerCase() !== severity.toLowerCase()) continue;
    if (needle && !`${e.cve ?? ''} ${e.title}`.toLowerCase().includes(needle)) continue;
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getKpFeed(assets: Fetcher, name: string): Promise<KpFeedItem[] | null> {
  if (!/^[a-z]+$/.test(name)) return null;
  const cached = feedCache.get(name);
  if (cached) {
    feedHits++;
    return cached;
  }
  feedMisses++;
  const data = await fetchJson<{ items: KpFeedItem[] }>(assets, `${DATA_PREFIX}/feeds/${name}.json`);
  if (!data?.items) return null;
  feedCache.set(name, data.items);
  return data.items;
}

/** Test-only: drop all cached state so consecutive cases stay independent. */
export function _resetKpCacheForTests(): void {
  cachedIndex = null;
  feedCache.clear();
  indexHits = indexMisses = feedHits = feedMisses = 0;
}

export function kpCacheStats(): {
  index: { hits: number; misses: number };
  feeds: { hits: number; misses: number; entries: number };
} {
  return {
    index: { hits: indexHits, misses: indexMisses },
    feeds: { hits: feedHits, misses: feedMisses, entries: feedCache.size },
  };
}
