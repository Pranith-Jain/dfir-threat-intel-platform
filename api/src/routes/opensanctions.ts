import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, badGateway, serviceUnavailable } from '../lib/api-error';
import { kvBackedGet, kvBackedPut } from '../lib/route-cache';

const CACHE_TTL = 1800;

export const opensanctionsRouter = new Hono<{ Bindings: Env }>();

opensanctionsRouter.get('/opensanctions/search', async (c) => {
  const q = c.req.query('q');
  const limit = Math.min(Number(c.req.query('limit')) || 20, 100);

  if (!q || q.length > 500) return badRequest(c, 'q parameter required (max 500 chars)');

  const cacheKey = `opensanctions:search:${q}:${limit}`;
  const { value: cached } = await kvBackedGet<Record<string, unknown>>(c.env.KV_CACHE, cacheKey, CACHE_TTL);
  if (cached) return c.json({ ...cached, cached: true });

  try {
    // The hosted API requires Authorization: ApiKey … since 2025.
    const apiKey = c.env.OPENSANCTIONS_API_KEY;
    if (!apiKey)
      return serviceUnavailable(c, 'OPENSANCTIONS_API_KEY not configured (wrangler secret put OPENSANCTIONS_API_KEY)');
    const url = `https://api.opensanctions.org/search/default?q=${encodeURIComponent(q)}&limit=${limit}`;
    const res = await fetch(url, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain-threatintel/1.0',
        Authorization: `ApiKey ${apiKey}`,
      },
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) return badGateway(c, `OpenSanctions upstream ${res.status}`);

    const data = await res.json();
    const body = { query: q, results: data, generated_at: new Date().toISOString(), cached: false };

    if (c.env.KV_CACHE || c.env.UPSTASH_REDIS_REST_URL)
      c.executionCtx.waitUntil(kvBackedPut(c.env, cacheKey, body, CACHE_TTL));
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'OpenSanctions unreachable');
  }
});

opensanctionsRouter.get('/opensanctions/entity', async (c) => {
  const id = c.req.query('id');
  if (!id) return badRequest(c, 'id parameter required');

  try {
    const apiKey = c.env.OPENSANCTIONS_API_KEY;
    if (!apiKey) return serviceUnavailable(c, 'OPENSANCTIONS_API_KEY not configured');
    const res = await fetch(`https://api.opensanctions.org/entities/${encodeURIComponent(id)}`, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain-threatintel/1.0',
        Authorization: `ApiKey ${apiKey}`,
      },
      signal: AbortSignal.timeout(10000),
    });

    if (res.status === 404) return notFound(c, 'entity not found');
    if (!res.ok) return badGateway(c, `OpenSanctions upstream ${res.status}`);

    const data = await res.json();
    return c.json({ entity: data, generated_at: new Date().toISOString() });
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'OpenSanctions unreachable');
  }
});

opensanctionsRouter.get('/opensanctions/stats', async (c) => {
  const cacheKey = 'opensanctions:stats';
  const { value: cached } = await kvBackedGet<Record<string, unknown>>(c.env.KV_CACHE, cacheKey, 3600);
  if (cached) return c.json({ ...cached, cached: true });

  try {
    const apiKey = c.env.OPENSANCTIONS_API_KEY;
    if (!apiKey) return serviceUnavailable(c, 'OPENSANCTIONS_API_KEY not configured');
    const res = await fetch('https://api.opensanctions.org/statistics', {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain-threatintel/1.0',
        Authorization: `ApiKey ${apiKey}`,
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) return badGateway(c, `OpenSanctions upstream ${res.status}`);

    const data = await res.json();
    const body = { statistics: data, generated_at: new Date().toISOString(), cached: false };

    if (c.env.KV_CACHE) {
      c.executionCtx.waitUntil(kvBackedPut(c.env, cacheKey, body, 3600));
    }
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'OpenSanctions unreachable');
  }
});
