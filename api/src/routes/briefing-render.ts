/**
 * GET /api/v1/briefings/:slug/render — render a briefing as
 * TI Mindmap HUB-style rich markdown.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, internalError, serviceUnavailable } from '../lib/api-error';
import { readBriefing } from '../lib/briefing-builder/build';
import { getThreatDb } from '../lib/do-database';
import { renderBriefingMarkdown } from '../lib/briefing-markdown-renderer';

export async function briefingRenderHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const slug = c.req.param('slug');
  if (!slug) return badRequest(c, 'missing slug');
  try {
    const db = getThreatDb(c.env);
    if (!db) return serviceUnavailable(c, 'BRIEFINGS_DB not bound');
    const briefing = await readBriefing(db, slug);
    if (!briefing) return notFound(c, `briefing ${slug} not found`);
    const md = renderBriefingMarkdown(briefing);
    // Return JSON so MCP's apiFetch (which always calls res.json()) can
    // consume it.
    return c.json({ markdown: md }, 200);
  } catch (e) {
    logError('briefingRenderHandler failed', e);
    const msg = e instanceof Error ? e.message : String(e);
    return internalError(c, msg);
  }
}
