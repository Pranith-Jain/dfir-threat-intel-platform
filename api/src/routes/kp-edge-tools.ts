/**
 * Kitploit directory — REST surface for the replicated public HTML + RSS
 * crawl (newest tools, CVE evidence cards and three feeds).
 *
 * Kitploit's robots.txt disallows /api/, so this vertical deliberately never
 * calls the upstream JSON API — only crawlable pages and feeds are mirrored.
 *
 * Endpoints (all under /api/v1/kp/):
 *   GET  /kp/             — slim index (counts, stats, items)
 *   GET  /kp/tools        — filtered tool cards (category/provider/q)
 *   GET  /kp/exploits     — filtered CVE evidence cards (severity/q)
 *   GET  /kp/feeds/:name  — full RSS feed (updates|exploits|blog)
 *   GET  /kp/stats        — computed stats
 *
 * All routes are automatically key-gated by the global /api/v1/* auth
 * middleware in api/src/index.ts. Data is read-only from env.ASSETS.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import { loadKpIndex, filterKpTools, filterKpExploits, getKpFeed } from '../lib/kp-manifest';

export const kpRouter = new Hono<{ Bindings: Env }>();

kpRouter.get('/kp/', async (c) => {
  try {
    return c.json(await loadKpIndex(c.env.ASSETS));
  } catch (e) {
    logError('kp index failed', e);
    return internalError(c, `kp_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

kpRouter.get('/kp/tools', async (c) => {
  try {
    const idx = await loadKpIndex(c.env.ASSETS);
    const rows = filterKpTools(idx.tools, {
      category: c.req.query('category') || undefined,
      provider: c.req.query('provider') || undefined,
      keyword: c.req.query('keyword') || c.req.query('q') || undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : undefined,
    });
    return c.json({ total: idx.counts.tools, returned: rows.length, source: idx.source, tools: rows });
  } catch (e) {
    logError('kp tools failed', e);
    return internalError(c, `kp_tools_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

kpRouter.get('/kp/exploits', async (c) => {
  try {
    const idx = await loadKpIndex(c.env.ASSETS);
    const rows = filterKpExploits(idx.exploits, {
      severity: c.req.query('severity') || undefined,
      keyword: c.req.query('keyword') || c.req.query('q') || undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : undefined,
    });
    return c.json({ total: idx.counts.exploits, returned: rows.length, source: idx.source, exploits: rows });
  } catch (e) {
    logError('kp exploits failed', e);
    return internalError(c, `kp_exploits_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

kpRouter.get('/kp/feeds/:name', async (c) => {
  try {
    const items = await getKpFeed(c.env.ASSETS, c.req.param('name'));
    if (!items) return notFound(c, `Feed '${c.req.param('name')}' not found`);
    return c.json({ source: 'kitploit.com', feed: c.req.param('name'), count: items.length, items });
  } catch (e) {
    logError('kp feed failed', e);
    return internalError(c, `kp_feed_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

kpRouter.get('/kp/stats', async (c) => {
  try {
    const idx = await loadKpIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      robots: idx.robots,
      stats: idx.stats,
    });
  } catch (e) {
    logError('kp stats failed', e);
    return internalError(c, `kp_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
