import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, badGateway, serviceUnavailable } from '../lib/api-error';
import { kvBackedGet, kvBackedPut } from '../lib/route-cache';
import { opencveGetCve } from '../lib/opencve';

const CACHE_TTL = 21600; // 6h — CVE records change, but slowly

export const opencveRouter = new Hono<{ Bindings: Env }>();

opencveRouter.get('/opencve/cve/:id', async (c) => {
  const id = c.req.param('id').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return badRequest(c, 'id must look like CVE-2024-3094');

  const cacheKey = `opencve:cve:${id}`;
  const { value: cached } = await kvBackedGet<Record<string, unknown>>(c.env.KV_CACHE, cacheKey, CACHE_TTL);
  if (cached) return c.json({ ...cached, cached: true });

  try {
    const token = (c.env as { OPENCVE_API_TOKEN?: string }).OPENCVE_API_TOKEN;
    if (!token)
      return serviceUnavailable(c, 'OPENCVE_API_TOKEN not configured (wrangler secret put OPENCVE_API_TOKEN)');

    const r = await opencveGetCve(id, { OPENCVE_API_TOKEN: token });
    if (!r.success) {
      if (r.error?.includes('not found')) return notFound(c, r.error);
      return badGateway(c, r.error ?? 'OpenCVE unreachable');
    }

    const body = { cve: r.data, generated_at: new Date().toISOString(), cached: false };
    if (c.env.KV_CACHE || c.env.UPSTASH_REDIS_REST_URL)
      c.executionCtx.waitUntil(kvBackedPut(c.env, cacheKey, body, CACHE_TTL));
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'OpenCVE unreachable');
  }
});
