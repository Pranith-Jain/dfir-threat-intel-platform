import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import {
  loadAadIndex,
  filterAadFrameworks,
  getAadFramework,
  filterAadIndicators,
  loadAadAttack,
} from '../lib/aad-manifest';

export const aadRouter = new Hono<{ Bindings: Env }>();

aadRouter.get('/aad/', async (c) => {
  try {
    return c.json(await loadAadIndex(c.env.ASSETS));
  } catch (e) {
    logError('aad index failed', e);
    return internalError(c, `aad_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aadRouter.get('/aad/frameworks', async (c) => {
  try {
    const idx = await loadAadIndex(c.env.ASSETS);
    const num = (name: string) => (c.req.query(name) ? Number(c.req.query(name)) : undefined);
    const rows = filterAadFrameworks(idx.frameworks, {
      keyword: c.req.query('q') || c.req.query('keyword') || undefined,
      minIndicators: num('min_indicators'),
      minRules: num('min_rules'),
      limit: num('limit'),
    });
    return c.json({ total: idx.frameworks.length, returned: rows.length, frameworks: rows });
  } catch (e) {
    logError('aad frameworks failed', e);
    return internalError(c, `aad_frameworks_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aadRouter.get('/aad/frameworks/:slug', async (c) => {
  try {
    const body = await getAadFramework(c.env.ASSETS, c.req.param('slug'));
    if (!body) return notFound(c, `Agentic attack framework '${c.req.param('slug')}' not found`);
    return c.json(body);
  } catch (e) {
    logError('aad framework failed', e);
    return internalError(c, `aad_framework_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aadRouter.get('/aad/indicators', async (c) => {
  try {
    const limit = c.req.query('limit') ? Number(c.req.query('limit')) : 100;
    const items = await filterAadIndicators(c.env.ASSETS, {
      type: c.req.query('type') || undefined,
      framework: c.req.query('framework') || undefined,
      keyword: c.req.query('q') || c.req.query('keyword') || undefined,
      limit: Math.min(Math.max(1, limit), 500),
    });
    return c.json({ returned: items.length, indicators: items });
  } catch (e) {
    logError('aad indicators failed', e);
    return internalError(c, `aad_indicators_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aadRouter.get('/aad/attack', async (c) => {
  try {
    const layer = await loadAadAttack(c.env.ASSETS);
    if (!layer) return notFound(c, 'ATT&CK layer not found');
    return c.json(layer);
  } catch (e) {
    logError('aad attack failed', e);
    return internalError(c, `aad_attack_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aadRouter.get('/aad/stats', async (c) => {
  try {
    const idx = await loadAadIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      generatedAt: idx.generatedAt,
      stats: idx.stats,
      indicatorTypes: idx.indicatorTypes,
      shared: idx.shared,
    });
  } catch (e) {
    logError('aad stats failed', e);
    return internalError(c, `aad_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
