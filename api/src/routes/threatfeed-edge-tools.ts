/** ThreatFeed REST surface: /threatfeed/  /threatfeed/feeds  /threatfeed/stats */
import { Hono } from 'hono';
import type { Env } from '../env';
import { filterThreatFeeds, loadThreatFeedIndex, threatFeedCacheStats } from '../lib/threatfeed-manifest';

export const threatFeedRouter = new Hono<{ Bindings: Env }>();

threatFeedRouter.get('/threatfeed/', async (c) => {
  const idx = await loadThreatFeedIndex(c.env.ASSETS);
  return c.json(
    {
      generatedAt: idx.generatedAt,
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      note: idx.note,
      counts: idx.counts,
      categories: idx.categories,
      feeds: idx.feeds.slice(0, 120),
    },
    200,
    { 'cache-control': 'public, max-age=600', 'x-source': 'threatfeed-mirror' }
  );
});

threatFeedRouter.get('/threatfeed/feeds', async (c) => {
  const idx = await loadThreatFeedIndex(c.env.ASSETS);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 200, 500));
  const feeds = filterThreatFeeds(idx, {
    category: c.req.query('category'),
    q: c.req.query('q'),
    enabled: c.req.query('enabled') === 'true' ? true : c.req.query('enabled') === 'false' ? false : undefined,
    limit,
  });
  return c.json({ count: feeds.length, feeds }, 200, { 'cache-control': 'public, max-age=600' });
});

threatFeedRouter.get('/threatfeed/stats', async (c) => {
  const idx = await loadThreatFeedIndex(c.env.ASSETS);
  return c.json({ counts: idx.counts, categories: idx.categories, cache: threatFeedCacheStats() }, 200, {
    'cache-control': 'public, max-age=600',
  });
});
