/**
 * PRTF REST surface — GET-only metadata mirror, no upstream hop.
 * /prtf/  /prtf/tactics  /prtf/techniques  /prtf/techniques/:id  /prtf/stats
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import {
  filterPrtfTechniques,
  getPrtfTechnique,
  loadPrtfIndex,
  normalizePrtfId,
  prtfCacheStats,
} from '../lib/prtf-manifest';

export const prtfRouter = new Hono<{ Bindings: Env }>();

prtfRouter.get('/prtf/', async (c) => {
  const idx = await loadPrtfIndex(c.env.ASSETS);
  return c.json(
    {
      generatedAt: idx.generatedAt,
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      version: idx.version,
      counts: idx.counts,
      tactics: idx.tactics,
      techniques: idx.techniques.slice(0, 120),
    },
    200,
    { 'cache-control': 'public, max-age=600', 'x-source': 'prtf-mirror' }
  );
});

prtfRouter.get('/prtf/tactics', async (c) => {
  const idx = await loadPrtfIndex(c.env.ASSETS);
  return c.json({ count: idx.tactics.length, tactics: idx.tactics }, 200, { 'cache-control': 'public, max-age=600' });
});

prtfRouter.get('/prtf/techniques', async (c) => {
  const idx = await loadPrtfIndex(c.env.ASSETS);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 200, 500));
  const techniques = filterPrtfTechniques(idx, {
    tactic: c.req.query('tactic'),
    q: c.req.query('q'),
    limit,
  });
  return c.json({ count: techniques.length, techniques }, 200, { 'cache-control': 'public, max-age=600' });
});

prtfRouter.get('/prtf/techniques/:id', async (c) => {
  const raw = c.req.param('id') ?? '';
  if (!normalizePrtfId(raw)) return c.json({ error: 'bad_technique_id' }, 400);
  const body = await getPrtfTechnique(c.env.ASSETS, raw);
  if (!body) return c.json({ error: 'not_found' }, 404);
  return c.json(body, 200, { 'cache-control': 'public, max-age=3600' });
});

prtfRouter.get('/prtf/stats', async (c) => {
  const idx = await loadPrtfIndex(c.env.ASSETS);
  return c.json({ counts: idx.counts, license: idx.license, cache: prtfCacheStats() }, 200, {
    'cache-control': 'public, max-age=600',
  });
});
