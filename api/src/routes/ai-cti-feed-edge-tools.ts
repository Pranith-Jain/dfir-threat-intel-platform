/**
 * OWASP GenAI Threat Intelligence Initiative REST surface.
 * GET /ai-cti-feed/  /actors  /techniques  /indicators  /stats
 *     /actors/:slug  /techniques/:slug  /malware/:slug
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import {
  aiCtiCacheStats,
  filterAiCtiRows,
  getAiCtiBody,
  loadAiCtiIndex,
  type AiCtiKind,
} from '../lib/ai-cti-feed-manifest';

export const aiCtiRouter = new Hono<{ Bindings: Env }>();

aiCtiRouter.get('/ai-cti-feed/', async (c) => {
  const idx = await loadAiCtiIndex(c.env.ASSETS);
  return c.json(
    {
      generatedAt: idx.generatedAt,
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      repoUrl: idx.repoUrl,
      license: idx.license,
      counts: idx.counts,
      actors: idx.actors,
      techniques: idx.techniques,
      malware: idx.malware,
      reports: idx.reports,
      indicators: idx.indicators,
    },
    200,
    { 'cache-control': 'public, max-age=600', 'x-source': 'ai-cti-mirror' }
  );
});

const listRoute = (path: string, kind: 'actors' | 'techniques' | 'malware') => {
  aiCtiRouter.get(`/ai-cti-feed/${path}`, async (c) => {
    const idx = await loadAiCtiIndex(c.env.ASSETS);
    const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 100, 300));
    const rows = filterAiCtiRows(idx[kind], {
      category: c.req.query('category'),
      q: c.req.query('q'),
      limit,
    });
    return c.json({ count: rows.length, [path]: rows }, 200, { 'cache-control': 'public, max-age=600' });
  });
};
listRoute('actors', 'actors');
listRoute('techniques', 'techniques');
listRoute('malware', 'malware');

aiCtiRouter.get('/ai-cti-feed/indicators', async (c) => {
  const idx = await loadAiCtiIndex(c.env.ASSETS);
  const q = c.req.query('q')?.toLowerCase();
  const rows = idx.indicators.filter((i) => !q || i.name.toLowerCase().includes(q)).slice(0, 200);
  return c.json({ count: rows.length, indicators: rows }, 200, { 'cache-control': 'public, max-age=600' });
});

const bodyRoute = (path: string, kind: AiCtiKind) => {
  aiCtiRouter.get(`/ai-cti-feed/${path}/:slug`, async (c) => {
    const body = await getAiCtiBody(c.env.ASSETS, kind, c.req.param('slug') ?? '');
    if (!body) return c.json({ error: 'not_found' }, 404);
    return c.json(body, 200, { 'cache-control': 'public, max-age=3600' });
  });
};
bodyRoute('actors', 'actors');
bodyRoute('techniques', 'ttps');
bodyRoute('malware', 'malware');

aiCtiRouter.get('/ai-cti-feed/stats', async (c) => {
  const idx = await loadAiCtiIndex(c.env.ASSETS);
  return c.json({ counts: idx.counts, generatedAt: idx.generatedAt, cache: aiCtiCacheStats() }, 200, {
    'cache-control': 'public, max-age=600',
  });
});
