/** Route tests for the ThreatFeed catalog, including the Subscribe feeds. */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { threatFeedRouter } from '../../src/routes/threatfeed-edge-tools';
import { _resetThreatFeedCacheForTests } from '../../src/lib/threatfeed-manifest';

const feed = (id: string) => ({
  id,
  name: id,
  url: `https://feeds.local/${id}`,
  category: 'Security News',
  tags: ['news'],
  enabled: true,
  upstreamUrl: `https://github.com/jozeta/ThreatFeed#${id}`,
});

const INDEX = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'ThreatFeed',
  sourceUrl: 'https://github.com/jozeta/ThreatFeed',
  feedUrl: 'https://jozeta.github.io/ThreatFeed/data/feeds.json',
  license: 'MIT',
  note: 'metadata only',
  counts: { feeds: 2, categories: 1, enabled: 2, retired: 0 },
  categories: [{ name: 'Security News', count: 2, feeds: ['a', 'b'] }],
  feeds: [feed('a'), feed('b')],
  curatedFeeds: [
    {
      id: 'news',
      name: 'News',
      description: 'Important stories',
      url: 'https://jozeta.github.io/ThreatFeed/data/feeds/news.xml',
    },
  ],
};

function env(): Env {
  return {
    ASSETS: {
      fetch: async () => new Response(JSON.stringify(INDEX), { headers: { 'content-type': 'application/json' } }),
    },
  } as unknown as Env;
}

function app(): Hono<{ Bindings: Env }> {
  const a = new Hono<{ Bindings: Env }>();
  a.route('/api/v1', threatFeedRouter);
  return a;
}

describe('ThreatFeed routes', () => {
  it('index includes curated RSS subscriptions', async () => {
    _resetThreatFeedCacheForTests();
    const res = await app().request('/api/v1/threatfeed/', {}, env());
    expect(res.status).toBe(200);
    const body = (await res.json()) as { curatedFeeds: Array<{ id: string; url: string }>; feeds: unknown[] };
    expect(body.curatedFeeds).toHaveLength(1);
    expect(body.curatedFeeds[0]!.url).toContain('news.xml');
    expect(body.feeds).toHaveLength(2);
  });

  it('filters feeds and reports stats', async () => {
    _resetThreatFeedCacheForTests();
    const a = app();
    const list = await a.request('/api/v1/threatfeed/feeds?category=security%20news', {}, env());
    expect(((await list.json()) as { count: number }).count).toBe(2);
    const stats = await a.request('/api/v1/threatfeed/stats', {}, env());
    expect(((await stats.json()) as { counts: { feeds: number } }).counts.feeds).toBe(2);
  });
});
