/**
 * BlueTeam-Tools REST surface — metadata-only catalog, no upstream hop.
 * GET /api/v1/blue-team-tools/       slim index + counts + cache stats
 * GET /api/v1/blue-team-tools/tools  filtered list (category/q/linked/limit)
 * GET /api/v1/blue-team-tools/stats  counts + cache stats
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { bttCacheStats, filterBttTools, getBttTool, loadBttIndex } from '../lib/blue-team-tools-manifest';

export const blueTeamToolsRouter = new Hono<{ Bindings: Env }>();

blueTeamToolsRouter.get('/blue-team-tools/', async (c) => {
  const idx = await loadBttIndex(c.env.ASSETS);
  return c.json(
    {
      generatedAt: idx.generatedAt,
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      counts: idx.counts,
      categories: idx.categories,
      tools: idx.tools.slice(0, 100),
    },
    200,
    { 'cache-control': 'public, max-age=600', 'x-source': 'blue-team-tools-mirror' }
  );
});

blueTeamToolsRouter.get('/blue-team-tools/tools', async (c) => {
  const idx = await loadBttIndex(c.env.ASSETS);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 200, 500));
  const tools = filterBttTools(idx, {
    category: c.req.query('category'),
    q: c.req.query('q'),
    linked: c.req.query('linked') === 'true',
    limit,
  });
  return c.json({ count: tools.length, tools }, 200, { 'cache-control': 'public, max-age=600' });
});

blueTeamToolsRouter.get('/blue-team-tools/tools/:slug', async (c) => {
  const idx = await loadBttIndex(c.env.ASSETS);
  const tool = getBttTool(idx, c.req.param('slug') ?? '');
  if (!tool) return c.json({ error: 'not_found' }, 404);
  return c.json(tool, 200, { 'cache-control': 'public, max-age=3600' });
});

blueTeamToolsRouter.get('/blue-team-tools/stats', async (c) => {
  const idx = await loadBttIndex(c.env.ASSETS);
  return c.json(
    {
      counts: idx.counts,
      categories: idx.categories.map((cat) => ({ name: cat.name, toolCount: cat.toolCount })),
      cache: bttCacheStats(),
    },
    200,
    { 'cache-control': 'public, max-age=600' }
  );
});
