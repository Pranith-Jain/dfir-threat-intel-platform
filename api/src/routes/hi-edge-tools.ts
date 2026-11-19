/**
 * Hacking Incidents ledger — REST surface for the replicated
 * hackingincidents.ai export (286 graded AI-assisted cyberattacks).
 *
 * Endpoints (all under /api/v1/hi/):
 *   GET  /hi/               — slim index (counts, stats, months, rows)
 *   GET  /hi/incidents      — filtered slim list (confidence/autonomy/role/…)
 *   GET  /hi/incidents/:id  — full record (summary, sources, upstream link)
 *   GET  /hi/stats          — computed stats
 *
 * All routes are automatically key-gated by the global /api/v1/* auth
 * middleware in api/src/index.ts. Data is read-only from env.ASSETS.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import { loadHiIndex, filterHiIncidents, getHiIncident, loadHiStats } from '../lib/hi-manifest';

export const hiRouter = new Hono<{ Bindings: Env }>();

hiRouter.get('/hi/', async (c) => {
  try {
    return c.json(await loadHiIndex(c.env.ASSETS));
  } catch (e) {
    logError('hi index failed', e);
    return internalError(c, `hi_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

hiRouter.get('/hi/incidents', async (c) => {
  try {
    const idx = await loadHiIndex(c.env.ASSETS);
    const harnessParam = c.req.query('harness');
    const rows = filterHiIncidents(idx.incidents, {
      confidence: c.req.query('confidence') || undefined,
      autonomy: c.req.query('autonomy') || undefined,
      role: c.req.query('role') || undefined,
      year: c.req.query('year') || undefined,
      month: c.req.query('month') || undefined,
      actorType: c.req.query('actorType') || undefined,
      country: c.req.query('country') || undefined,
      sector: c.req.query('sector') || undefined,
      model: c.req.query('model') || undefined,
      harness: harnessParam === 'true' ? true : harnessParam === 'false' ? false : undefined,
      keyword: c.req.query('keyword') || c.req.query('q') || undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : undefined,
    });
    return c.json({
      total: idx.counts.records,
      returned: rows.length,
      source: idx.source,
      upstreamUpdated: idx.upstreamUpdated,
      incidents: rows,
    });
  } catch (e) {
    logError('hi incidents failed', e);
    return internalError(c, `hi_incidents_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

hiRouter.get('/hi/incidents/:id', async (c) => {
  try {
    const body = await getHiIncident(c.env.ASSETS, c.req.param('id'));
    if (!body) return notFound(c, `Incident '${c.req.param('id')}' not found`);
    return c.json(body);
  } catch (e) {
    logError('hi incident failed', e);
    return internalError(c, `hi_incident_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

hiRouter.get('/hi/stats', async (c) => {
  try {
    const idx = await loadHiIndex(c.env.ASSETS);
    const stats = await loadHiStats(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      upstreamUpdated: idx.upstreamUpdated,
      stats: stats ?? idx.stats,
    });
  } catch (e) {
    logError('hi stats failed', e);
    return internalError(c, `hi_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
