/**
 * ORCA AI Incident Archive — REST surface for the open database of
 * real-world AI agent incidents (Continuum-AI-Corp, CC BY 4.0).
 *
 * Endpoints (all under /api/v1/orca/):
 *   GET  /orca/               — slim index (counts, stats, months, slim rows)
 *   GET  /orca/incidents      — filtered slim list (kind/severity/type/harm/region/month/q)
 *   GET  /orca/incidents/:id  — full record (summary, sources, upstream link)
 *   GET  /orca/stats          — upstream stats pass-through
 *
 * Data source: github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive (CC BY 4.0).
 * Read-only, served from env.ASSETS; upstream `kind: policy`/`report` rows are
 * informational moves, not incidents — filter with `kind=incident` when only
 * damage events are wanted.
 *
 * All routes are automatically key-gated by the global /api/v1/* auth
 * middleware (authenticate('external-only')) in api/src/index.ts.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import { loadOrcaIndex, filterOrcaIncidents, getOrcaIncident, loadOrcaStats } from '../lib/orca-manifest';

export const orcaRouter = new Hono<{ Bindings: Env }>();

// ─── Slim index ────────────────────────────────────────────────────────
orcaRouter.get('/orca/', async (c) => {
  try {
    return c.json(await loadOrcaIndex(c.env.ASSETS));
  } catch (e) {
    logError('orca index failed', e);
    return internalError(c, `orca_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Filtered incident list ────────────────────────────────────────────
orcaRouter.get('/orca/incidents', async (c) => {
  try {
    const idx = await loadOrcaIndex(c.env.ASSETS);
    const harmParam = c.req.query('harm');
    const realHarm =
      harmParam === undefined || harmParam === ''
        ? undefined
        : harmParam === 'null'
          ? null
          : harmParam === 'true'
            ? true
            : harmParam === 'false'
              ? false
              : undefined;
    const landmarkParam = c.req.query('landmark');
    const disputedParam = c.req.query('disputed');
    const rows = filterOrcaIncidents(idx.incidents, {
      kind: c.req.query('kind') || undefined,
      severity: c.req.query('severity') || undefined,
      type: c.req.query('type') || undefined,
      realHarm,
      aiInvolvement: c.req.query('involvement') || undefined,
      region: c.req.query('region') || undefined,
      month: c.req.query('month') || undefined,
      landmark: landmarkParam === 'true' ? true : landmarkParam === 'false' ? false : undefined,
      disputed: disputedParam === 'true' ? true : disputedParam === 'false' ? false : undefined,
      keyword: c.req.query('keyword') || c.req.query('q') || undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : undefined,
    });
    return c.json({
      total: idx.counts.records,
      returned: rows.length,
      source: idx.source,
      upstreamVersion: idx.upstreamVersion,
      incidents: rows,
    });
  } catch (e) {
    logError('orca incidents failed', e);
    return internalError(c, `orca_incidents_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single record ─────────────────────────────────────────────────────
orcaRouter.get('/orca/incidents/:id', async (c) => {
  try {
    const body = await getOrcaIncident(c.env.ASSETS, c.req.param('id'));
    if (!body) return notFound(c, `ORCA incident '${c.req.param('id')}' not found`);
    return c.json(body);
  } catch (e) {
    logError('orca incident failed', e);
    return internalError(c, `orca_incident_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Stats ─────────────────────────────────────────────────────────────
orcaRouter.get('/orca/stats', async (c) => {
  try {
    const idx = await loadOrcaIndex(c.env.ASSETS);
    const stats = await loadOrcaStats(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      license: idx.license,
      upstreamVersion: idx.upstreamVersion,
      stats: stats ?? idx.stats,
    });
  } catch (e) {
    logError('orca stats failed', e);
    return internalError(c, `orca_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
