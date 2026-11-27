import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadThreatFeedIndex,
  filterThreatFeeds,
  threatFeedCacheStats,
  _resetThreatFeedCacheForTests,
  type ThreatFeedIndex,
} from './threatfeed-manifest';

const feed = (id: string, category: string, enabled = true) => ({
  id,
  name: id,
  url: `https://feeds.local/${id}`,
  category,
  tags: ['news'],
  enabled,
  upstreamUrl: `https://github.com/jozeta/ThreatFeed#${id}`,
});

const INDEX: ThreatFeedIndex = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'ThreatFeed',
  sourceUrl: 'https://github.com/jozeta/ThreatFeed',
  feedUrl: 'https://jozeta.github.io/ThreatFeed/data/feeds.json',
  license: 'MIT',
  note: 'metadata only',
  counts: { feeds: 3, categories: 2, enabled: 2, retired: 1 },
  categories: [
    { name: 'Security News', count: 2, feeds: ['a', 'b'] },
    { name: 'Other', count: 1, feeds: ['c'] },
  ],
  feeds: [feed('a', 'Security News'), feed('b', 'Security News'), feed('c', 'Other', false)],
};

beforeEach(() => _resetThreatFeedCacheForTests());

describe('ThreatFeed manifest', () => {
  it('loads and caches the catalog', async () => {
    const assets = {
      fetch: async () => new Response(JSON.stringify(INDEX), { headers: { 'content-type': 'application/json' } }),
    } as unknown as Fetcher;
    const idx = await loadThreatFeedIndex(assets);
    expect(idx.counts.feeds).toBe(3);
    expect(threatFeedCacheStats().categories).toBe(2);
  });

  it('filters by category, keyword and enabled state', () => {
    expect(filterThreatFeeds(INDEX, { category: 'security news' }).map((f) => f.id)).toEqual(['a', 'b']);
    expect(filterThreatFeeds(INDEX, { q: 'a' }).map((f) => f.id)).toEqual(['a']);
    expect(filterThreatFeeds(INDEX, { enabled: false }).map((f) => f.id)).toEqual(['c']);
    expect(filterThreatFeeds(INDEX, { limit: 1 })).toHaveLength(1);
  });
});
