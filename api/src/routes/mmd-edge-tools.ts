/**
 * MMD toolkit — REST surface for the MalwareMustDie shared codes & tools
 * collection (github.com/unixfreaxjp/malwaremustdie).
 *
 * Endpoints (all under /api/v1/mmd/):
 *   GET  /mmd/               — slim index (counts, categories, file list, recent commits)
 *   GET  /mmd/categories     — category summary
 *   GET  /mmd/categories/:cat — per-category file listing
 *   GET  /mmd/tools          — filtered file list (category/kind/ext/q)
 *   GET  /mmd/commits        — recent upstream commits (activity feed)
 *   GET  /mmd/readme         — upstream README body
 *
 * Data source: github.com/unixfreaxjp/malwaremustdie (public share; upstream
 * disclaimer applies). Read-only, served from env.ASSETS. The weekly sync
 * workflow re-fetches the GitHub tree + commits, so upstream updates surface
 * automatically.
 *
 * All routes are automatically key-gated by the global /api/v1/* auth
 * middleware (authenticate('external-only')) in api/src/index.ts.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound } from '../lib/api-error';
import { loadMmdIndex, listMmdTools, getMmdCategory, loadMmdCommits, loadMmdReadme } from '../lib/mmd-manifest';

export const mmdRouter = new Hono<{ Bindings: Env }>();

// ─── Slim index ────────────────────────────────────────────────────────
mmdRouter.get('/mmd/', async (c) => {
  try {
    return c.json(await loadMmdIndex(c.env.ASSETS));
  } catch (e) {
    logError('mmd index failed', e);
    return internalError(c, `mmd_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Category summary ──────────────────────────────────────────────────
mmdRouter.get('/mmd/categories', async (c) => {
  try {
    const idx = await loadMmdIndex(c.env.ASSETS);
    return c.json({
      total: idx.categories.length,
      categories: idx.categories,
    });
  } catch (e) {
    logError('mmd categories failed', e);
    return internalError(c, `mmd_categories_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single category body ──────────────────────────────────────────────
mmdRouter.get('/mmd/categories/:cat', async (c) => {
  try {
    const body = await getMmdCategory(c.env.ASSETS, c.req.param('cat'));
    if (!body) return notFound(c, `MMD category '${c.req.param('cat')}' not found`);
    return c.json(body);
  } catch (e) {
    logError('mmd category failed', e);
    return internalError(c, `mmd_category_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Filtered tool list ────────────────────────────────────────────────
mmdRouter.get('/mmd/tools', async (c) => {
  try {
    const idx = await loadMmdIndex(c.env.ASSETS);
    const tools = listMmdTools(idx, {
      category: c.req.query('category') || undefined,
      kind: c.req.query('kind') || undefined,
      ext: c.req.query('ext') || undefined,
      keyword: c.req.query('keyword') || c.req.query('q') || undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : undefined,
    });
    return c.json({
      total: idx.counts.files,
      returned: tools.length,
      source: idx.source,
      lastCommit: idx.lastCommit,
      tools,
    });
  } catch (e) {
    logError('mmd tools failed', e);
    return internalError(c, `mmd_tools_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Recent commits ────────────────────────────────────────────────────
mmdRouter.get('/mmd/commits', async (c) => {
  try {
    const body = await loadMmdCommits(c.env.ASSETS);
    if (!body) return notFound(c, 'MMD commits manifest not found');
    return c.json(body);
  } catch (e) {
    logError('mmd commits failed', e);
    return internalError(c, `mmd_commits_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── README body ───────────────────────────────────────────────────────
mmdRouter.get('/mmd/readme', async (c) => {
  try {
    const body = await loadMmdReadme(c.env.ASSETS);
    if (!body) return notFound(c, 'MMD README not found');
    return c.json({ source: 'github.com/unixfreaxjp/malwaremustdie', body });
  } catch (e) {
    logError('mmd readme failed', e);
    return internalError(c, `mmd_readme_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
