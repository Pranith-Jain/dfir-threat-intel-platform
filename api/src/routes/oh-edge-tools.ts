/**
 * Offsec Harness Index — REST surface for the replicated offsecharnesses.ai
 * export (154 tracked offensive-AI harnesses, 14 seen in real attacks).
 *
 * Endpoints (all under /api/v1/oh/):
 *   GET  /oh/                — slim index (counts, stats, tiers, rows)
 *   GET  /oh/harnesses       — filtered list (table/tier/useTag/actor/q)
 *   GET  /oh/harnesses/:slug — full harness (uses, quotes, sources, incidents)
 *   GET  /oh/sources         — 32 primary reports
 *   GET  /oh/references      — 72 discovery references
 *   GET  /oh/stats           — computed stats
 *
 * All routes are automatically key-gated by the global /api/v1/* auth
 * middleware in api/src/index.ts. Data is read-only from env.ASSETS.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import {
  loadOhIndex,
  filterOhHarnesses,
  getOhHarness,
  loadOhSideFile,
  type OhSource,
  type OhReference,
} from '../lib/oh-manifest';

export const ohRouter = new Hono<{ Bindings: Env }>();

ohRouter.get('/oh/', async (c) => {
  try {
    return c.json(await loadOhIndex(c.env.ASSETS));
  } catch (e) {
    logError('oh index failed', e);
    return internalError(c, `oh_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

ohRouter.get('/oh/harnesses', async (c) => {
  try {
    const idx = await loadOhIndex(c.env.ASSETS);
    const rows = filterOhHarnesses(idx.harnesses, {
      table: c.req.query('table') || undefined,
      tier: c.req.query('tier') || undefined,
      useTag: c.req.query('useTag') || c.req.query('use') || undefined,
      actor: c.req.query('actor') || undefined,
      kind: c.req.query('kind') || undefined,
      keyword: c.req.query('keyword') || c.req.query('q') || undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : undefined,
    });
    return c.json({
      total: idx.counts.tracked,
      returned: rows.length,
      source: idx.source,
      harnesses: rows,
    });
  } catch (e) {
    logError('oh harnesses failed', e);
    return internalError(c, `oh_harnesses_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

ohRouter.get('/oh/harnesses/:slug', async (c) => {
  try {
    const body = await getOhHarness(c.env.ASSETS, c.req.param('slug'));
    if (!body) return notFound(c, `Harness '${c.req.param('slug')}' not found`);
    return c.json(body);
  } catch (e) {
    logError('oh harness failed', e);
    return internalError(c, `oh_harness_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

ohRouter.get('/oh/sources', async (c) => {
  try {
    const idx = await loadOhIndex(c.env.ASSETS);
    const body = await loadOhSideFile<{ sources: OhSource[] }>(c.env.ASSETS, 'sources');
    return c.json({ source: idx.source, count: body?.sources.length ?? 0, sources: body?.sources ?? [] });
  } catch (e) {
    logError('oh sources failed', e);
    return internalError(c, `oh_sources_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

ohRouter.get('/oh/references', async (c) => {
  try {
    const idx = await loadOhIndex(c.env.ASSETS);
    const body = await loadOhSideFile<{ references: OhReference[] }>(c.env.ASSETS, 'references');
    return c.json({ source: idx.source, count: body?.references.length ?? 0, references: body?.references ?? [] });
  } catch (e) {
    logError('oh references failed', e);
    return internalError(c, `oh_references_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

ohRouter.get('/oh/stats', async (c) => {
  try {
    const idx = await loadOhIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      evidenceReviewed: idx.evidenceReviewed,
      githubFacts: idx.githubFacts,
      stats: idx.stats,
    });
  } catch (e) {
    logError('oh stats failed', e);
    return internalError(c, `oh_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
