/**
 * Gen Threat Labs IoC REST surface (gendigitalinc/ioc),
 * served from the static ASSETS manifest — read-only, no upstream hits:
 *   GET /genioc/                — headline counts + index meta
 *   GET /genioc/families        — slim family cards (q, minHashes, withYara, limit)
 *   GET /genioc/families/:slug  — full classified IoC set (hashes/network/mutexes/extras/yara)
 *   GET /genioc/stats           — cache + manifest stats
 *
 * Complements the live /malware-iocs route (GitHub contents API) which stays
 * the freshness surface; this manifest is the deep, type-classified surface.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound, badRequest } from '../lib/api-error';

function loadMod() {
  return import('../lib/genioc-manifest');
}

export const geniocRouter = new Hono<{ Bindings: Env }>();

geniocRouter.get('/genioc/', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadGeniocIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      license: idx.license,
      builtAt: idx.builtAt,
      counts: idx.counts,
      firstFamilies: idx.families
        .slice(0, 20)
        .map((f) => ({ slug: f.slug, name: f.name, hashes: f.hashes, network: f.network })),
    });
  } catch (e) {
    logError('genioc index failed', e);
    return internalError(c, `genioc_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

geniocRouter.get('/genioc/families', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadGeniocIndex(c.env.ASSETS);
    const entries = mod.filterGeniocFamilies(idx, {
      q: c.req.query('q') || undefined,
      minHashes: c.req.query('minHashes') ? Number(c.req.query('minHashes')) : undefined,
      withYara: c.req.query('withYara') === '1' || c.req.query('withYara') === 'true',
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 200,
    });
    return c.json({ total: idx.counts.families, returned: entries.length, families: entries });
  } catch (e) {
    logError('genioc families failed', e);
    return internalError(c, `genioc_families_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

geniocRouter.get('/genioc/families/:slug', async (c) => {
  const slug = c.req.param('slug').toLowerCase();
  if (!slug || /[^a-z0-9-]/.test(slug)) return badRequest(c, 'invalid family slug');
  try {
    const mod = await loadMod();
    const body = await mod.getGeniocFamily(c.env.ASSETS, slug);
    if (!body) return notFound(c, `genioc_family_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('genioc family failed', e);
    return internalError(c, `genioc_family_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

geniocRouter.get('/genioc/stats', async (c) => {
  try {
    const mod = await loadMod();
    const _idx = await mod.loadGeniocIndex(c.env.ASSETS).catch(() => null);
    return c.json(_idx === null ? { ok: false } : { ok: true, cache: mod.geniocCacheStats() });
  } catch (e) {
    return c.json({ ok: false, error: String(e) });
  }
});
