/** ThreatFeed (MIT) feed-catalog manifest, read through env.ASSETS. */
import { fetchJsonAsset } from './manifest-cache';

export interface ThreatFeedEntry {
  id: string;
  name: string;
  url: string | null;
  category: string;
  tags: string[];
  enabled: boolean;
  upstreamUrl: string;
}

export interface ThreatFeedIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  feedUrl: string;
  license: string;
  note: string;
  counts: { feeds: number; categories: number; enabled: number; retired: number };
  categories: Array<{ name: string; count: number; feeds: string[] }>;
  feeds: ThreatFeedEntry[];
}

let cached: ThreatFeedIndex | null = null;

export async function loadThreatFeedIndex(assets: Fetcher): Promise<ThreatFeedIndex> {
  if (cached) return cached;
  const idx = await fetchJsonAsset<ThreatFeedIndex>(assets, '/data/threatfeed/index.json', 'https://threatfeed.local');
  if (!idx) throw new Error('ThreatFeed manifest missing — run scripts/build-threatfeed.mjs');
  cached = idx;
  return idx;
}

export function filterThreatFeeds(
  index: ThreatFeedIndex,
  opts: { category?: string; q?: string; enabled?: boolean; limit?: number } = {}
): ThreatFeedEntry[] {
  const { category, q, enabled, limit = 200 } = opts;
  const needle = q?.trim().toLowerCase();
  const cat = category?.trim().toLowerCase();
  const out: ThreatFeedEntry[] = [];
  for (const f of index.feeds) {
    if (cat && f.category.toLowerCase() !== cat) continue;
    if (enabled !== undefined && f.enabled !== enabled) continue;
    if (needle && !`${f.name} ${f.id} ${f.category} ${f.tags.join(' ')}`.toLowerCase().includes(needle)) continue;
    out.push(f);
    if (out.length >= limit) break;
  }
  return out;
}

export function threatFeedCacheStats(): { loaded: boolean; feeds: number; categories: number } {
  return { loaded: cached !== null, feeds: cached?.feeds.length ?? 0, categories: cached?.categories.length ?? 0 };
}

export function _resetThreatFeedCacheForTests(): void {
  cached = null;
}
