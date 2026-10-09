// ssrf-audit: accept-reason `?url=` is passed as the `host` QUERY PARAMETER of a
// fixed upstream (http-observatory.security.mozilla.org), encodeURIComponent'd.
// The fetch target is always that constant host, so a caller cannot redirect it
// at an internal address. Not SSRF-reachable.
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, badGateway } from '../lib/api-error';
import { routeCacheGet, routeCachePut } from '../lib/route-cache';

const CACHE_TTL = 3600;

// L1-only (Cache API): the HTTP Observatory is free and keyless, so a cold
// colo refetching a scan costs nothing scarce. (Contrast opencve /
// opensanctions in this same directory, which stay KV-backed because their
// metered API keys make cross-colo reuse worth the write quota.)

export const mozillaTlsRouter = new Hono<{ Bindings: Env }>();

mozillaTlsRouter.get('/mozilla-tls/scan', async (c) => {
  const url = c.req.query('url');
  if (!url) return badRequest(c, 'url parameter required');

  const cacheKey = `mozilla:tls:${url}`;
  const cached = await routeCacheGet<Record<string, unknown>>(cacheKey);
  if (cached) return c.json({ ...cached, cached: true });

  try {
    // The hosted TLS Observatory (tls-observatory.services.mozilla.com) was
    // retired (NXDOMAIN). The live successor is the HTTP Observatory.
    const res = await fetch(
      `https://http-observatory.security.mozilla.org/api/v1/analyze?host=${encodeURIComponent(url)}`,
      {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(20000),
      }
    );

    if (!res.ok) return badGateway(c, `Mozilla Observatory upstream ${res.status}`);

    const data = await res.json();
    const body = { url, results: data, generated_at: new Date().toISOString(), cached: false };

    c.executionCtx.waitUntil(routeCachePut(cacheKey, body, CACHE_TTL));
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Mozilla TLS unreachable');
  }
});

mozillaTlsRouter.get('/mozilla-tls/result', async (c) => {
  const scanId = c.req.query('scanId');
  if (!scanId) return badRequest(c, 'scanId parameter required');

  try {
    const res = await fetch(
      `https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=${encodeURIComponent(scanId)}`,
      {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(10000),
      }
    );

    if (!res.ok) return badGateway(c, `Mozilla Observatory upstream ${res.status}`);
    const data = await res.json();
    return c.json({ scanId, results: data, generated_at: new Date().toISOString() });
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Mozilla Observatory unreachable');
  }
});
