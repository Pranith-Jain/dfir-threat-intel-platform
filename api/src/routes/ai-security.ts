/**
 * AI Security hub — REST surface for matrix tools + incident reports +
 * escape parity + vulns + advisories + research.
 *
 * All read-only, served from the static ASSETS manifest (no per-request
 * upstream, no secrets):
 *   GET  /ai-security/                  — hub meta + counts
 *   GET  /ai-security/matrix            — tool rows (?category, q, min_stars, limit)
 *   GET  /ai-security/matrix/:slug      — full tool body
 *   GET  /ai-security/incidents         — report rows (?q, cite, limit)
 *   GET  /ai-security/incidents/:id     — full report body
 *   GET  /ai-security/escape-parity     — two-way parity report vs ai-escape.watch
 *   GET  /ai-security/vulns             — vuln rows (?q, kev_only, min_epss, source, stack, limit)
 *   GET  /ai-security/vulns/:id         — full vuln body
 *   GET  /ai-security/advisories        — advisory rows (?q, source, kind, limit)
 *   GET  /ai-security/research          — research rows (?q, source, limit)
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';

async function loadMod() {
  return await import('../lib/ai-security-manifest');
}

export const aiSecurityRouter = new Hono<{ Bindings: Env }>();

aiSecurityRouter.get('/ai-security/', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadAiSecurityHub(c.env.ASSETS);
    return c.json(idx);
  } catch (e) {
    logError('ai-security hub failed', e);
    return internalError(c, `ai_security_hub_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/matrix', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadMatrixIndex(c.env.ASSETS);
    const tools = mod.filterMatrixTools(idx, {
      category: c.req.query('category') || undefined,
      q: c.req.query('q') || undefined,
      minStars: c.req.query('min_stars') ? Number(c.req.query('min_stars')) : undefined,
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 100,
    });
    return c.json({ total: idx.total, byCategory: idx.byCategory, returned: tools.length, tools });
  } catch (e) {
    logError('ai-security matrix failed', e);
    return internalError(c, `ai_security_matrix_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/matrix/:slug', async (c) => {
  try {
    const mod = await loadMod();
    const body = await mod.getMatrixTool(c.env.ASSETS, c.req.param('slug'));
    if (!body) return notFound(c, `ai_security_tool_not_found: ${c.req.param('slug')}`);
    return c.json(body);
  } catch (e) {
    logError('ai-security tool failed', e);
    return internalError(c, `ai_security_tool_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/incidents', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadIncidentsIndex(c.env.ASSETS);
    const reports = mod.filterIncidentReports(idx, {
      q: c.req.query('q') || undefined,
      citeId: c.req.query('cite') || undefined,
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 100,
    });
    return c.json({ total: idx.total, returned: reports.length, reports });
  } catch (e) {
    logError('ai-security incidents failed', e);
    return internalError(c, `ai_security_incidents_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/incidents/:id', async (c) => {
  try {
    const mod = await loadMod();
    const body = await mod.getIncidentReport(c.env.ASSETS, c.req.param('id'));
    if (!body) return notFound(c, `ai_security_incident_not_found: ${c.req.param('id')}`);
    return c.json(body);
  } catch (e) {
    logError('ai-security incident failed', e);
    return internalError(c, `ai_security_incident_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/escape-parity', async (c) => {
  try {
    const mod = await loadMod();
    const parity = await mod.loadEscapeParity(c.env.ASSETS);
    if (!parity) return notFound(c, 'ai_security_parity_not_found');
    return c.json(parity);
  } catch (e) {
    logError('ai-security parity failed', e);
    return internalError(c, `ai_security_parity_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/vulns', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadVulnsIndex(c.env.ASSETS);
    const kevOnly = c.req.query('kev_only');
    const stack = c.req.query('stack') || undefined;
    const vulns = mod.filterVulns(idx, {
      q: c.req.query('q') || undefined,
      kevOnly: kevOnly === 'true' ? true : kevOnly === 'false' ? false : undefined,
      minEpss: c.req.query('min_epss') ? Number(c.req.query('min_epss')) : undefined,
      source: c.req.query('source') || undefined,
      stack,
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 100,
    });
    return c.json({
      total: idx.total,
      kev: idx.kev,
      returned: vulns.length,
      stackFacets: idx.stackFacets ?? [],
      byStack: idx.byStack ?? {},
      filters: { stack },
      vulns,
    });
  } catch (e) {
    logError('ai-security vulns failed', e);
    return internalError(c, `ai_security_vulns_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/vulns/:id', async (c) => {
  try {
    const mod = await loadMod();
    const body = await mod.getVuln(c.env.ASSETS, c.req.param('id'));
    if (!body) return notFound(c, `ai_security_vuln_not_found: ${c.req.param('id')}`);
    return c.json(body);
  } catch (e) {
    logError('ai-security vuln failed', e);
    return internalError(c, `ai_security_vuln_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/advisories', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadAdvisoriesIndex(c.env.ASSETS);
    const items = mod.filterAdvisories(idx, {
      q: c.req.query('q') || undefined,
      source: c.req.query('source') || undefined,
      kind: c.req.query('kind') || undefined,
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 100,
    });
    return c.json({ total: idx.total, bySource: idx.bySource, returned: items.length, items });
  } catch (e) {
    logError('ai-security advisories failed', e);
    return internalError(c, `ai_security_advisories_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

aiSecurityRouter.get('/ai-security/research', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadResearchIndex(c.env.ASSETS);
    const items = mod.filterResearch(idx, {
      q: c.req.query('q') || undefined,
      source: c.req.query('source') || undefined,
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 100,
    });
    return c.json({ total: idx.total, bySource: idx.bySource, returned: items.length, items });
  } catch (e) {
    logError('ai-security research failed', e);
    return internalError(c, `ai_security_research_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
