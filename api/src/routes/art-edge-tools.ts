import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import { loadArtIndex, filterArtTechniques, getArtTechnique, artCacheStats } from '../lib/art-manifest';

export const artRouter = new Hono<{ Bindings: Env }>();

artRouter.get('/art/', async (c) => {
  try {
    return c.json(await loadArtIndex(c.env.ASSETS));
  } catch (e) {
    logError('art index failed', e);
    return internalError(c, `art_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

artRouter.get('/art/techniques', async (c) => {
  try {
    const idx = await loadArtIndex(c.env.ASSETS);
    const limit = c.req.query('limit') ? Number(c.req.query('limit')) : 100;
    const subParam = c.req.query('subtechnique');
    const rows = filterArtTechniques(idx.techniques, {
      keyword: c.req.query('q') || c.req.query('keyword') || undefined,
      platform: c.req.query('platform') || undefined,
      executor: c.req.query('executor') || undefined,
      subtechnique: subParam === 'true' ? true : subParam === 'false' ? false : undefined,
      minTests: c.req.query('min_tests') ? Number(c.req.query('min_tests')) : undefined,
      limit: Math.min(Math.max(1, limit), 400),
    });
    return c.json({ total: idx.techniques.length, returned: rows.length, techniques: rows });
  } catch (e) {
    logError('art techniques failed', e);
    return internalError(c, `art_techniques_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

artRouter.get('/art/techniques/:id', async (c) => {
  try {
    const body = await getArtTechnique(c.env.ASSETS, c.req.param('id').toUpperCase());
    if (!body) return notFound(c, `Atomic technique '${c.req.param('id')}' not found`);
    return c.json(body);
  } catch (e) {
    logError('art technique failed', e);
    return internalError(c, `art_technique_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

artRouter.get('/art/stats', async (c) => {
  try {
    const idx = await loadArtIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      siteUrl: idx.siteUrl,
      license: idx.license,
      generatedAt: idx.generatedAt,
      stats: idx.stats,
      platformCounts: idx.platformCounts,
      executorCounts: idx.executorCounts,
      cache: artCacheStats(),
    });
  } catch (e) {
    logError('art stats failed', e);
    return internalError(c, `art_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
