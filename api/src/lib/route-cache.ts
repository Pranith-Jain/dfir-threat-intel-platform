import type { KVNamespace } from '@cloudflare/workers-types';
import type { Context } from 'hono';
import type { Env } from '../env';

const CACHE_BASE = 'https://route-cache.internal/v1';

function req(key: string): Request {
  return new Request(`${CACHE_BASE}/${encodeURIComponent(key)}`);
}

export async function routeCacheGet<T>(key: string): Promise<T | null> {
  try {
    const hit = await (caches as unknown as { default: Cache }).default.match(req(key));
    if (hit) return (await hit.json()) as T;
  } catch {
    /* best-effort */
  }
  return null;
}

/**
 * Drop a cached value from BOTH tiers.
 *
 * Deleting only KV is a common and easy-to-miss half-fix: the L1
 * `caches.default` shadow is per-colo and free, which makes it the tier most
 * readers actually hit, so leaving it populated means the colo that ran the
 * write keeps serving stale data until the shadow TTL lapses while every
 * other colo has already refreshed. Always drop both.
 *
 * Never throws — a failed delete just means the entry ages out on its own
 * TTL, which is better than failing the caller's write.
 */
export async function routeCacheDelete(kv: KVNamespace | undefined | null, key: string): Promise<void> {
  try {
    await (caches as unknown as { default: Cache }).default.delete(req(key));
  } catch {
    /* best-effort */
  }
  try {
    await kv?.delete(key);
  } catch {
    /* best-effort */
  }
}

export function routeCachePut(key: string, data: unknown, ttlSeconds: number): Promise<void> {
  return (caches as unknown as { default: Cache }).default
    .put(
      req(key),
      new Response(JSON.stringify(data), {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttlSeconds}` },
      })
    )
    .catch(() => {});
}

/**
 * L1-first, KV-L2 read with write-through to L1.
 *
 * Collapses repeated reads of the same key in a colo to a single KV read
 * per TTL window: the first miss populates the per-colo Cache-API shadow
 * so subsequent reads (same colo) skip KV entirely. KV is still the
 * cross-colo source of truth — this only adds a free L1 in front of it.
 *
 * Use for route handlers that cache an upstream response under a stable
 * key (e.g. `opensanctions:search:<q>`, `mozilla:tls:<url>`). The TTL
 * should match the KV entry's TTL so the shadow doesn't outlive the
 * canonical value.
 *
 * Returns `{ value, source }` so callers can set a `cached` flag or
 * `X-Cache` header if they want. Never throws — a KV error degrades to
 * `null` (caller falls through to its upstream fetch).
 */
export async function kvBackedGet<T>(
  kv: KVNamespace | undefined | null,
  key: string,
  ttlSeconds: number
): Promise<{ value: T | null; source: 'l1' | 'kv' | 'miss' }> {
  const cache = (caches as unknown as { default: Cache }).default;
  // L1: per-colo Cache API (free, does not count against KV quota).
  try {
    const hit = await cache.match(req(key));
    if (hit) return { value: (await hit.json()) as T, source: 'l1' };
  } catch {
    /* fall through to KV */
  }
  if (!kv) return { value: null, source: 'miss' };
  try {
    const value = (await kv.get(key, 'json')) as T | null;
    if (value !== null) {
      // Write-through to L1 so the next read in this colo skips KV.
      try {
        await cache.put(
          req(key),
          new Response(JSON.stringify(value), {
            headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttlSeconds}` },
          })
        );
      } catch {
        /* best-effort — a shadow miss just means the next read hits KV again */
      }
      return { value, source: 'kv' };
    }
  } catch {
    /* KV read error — degrade to miss */
  }
  return { value: null, source: 'miss' };
}

/**
 * Write-through to both L1 (Cache API) and L2 (KV).
 *
 * KV is the cross-colo durable store; L1 is the per-colo free shadow so
 * the next read in this colo is a cache hit. The KV write is fire-and-
 * forget (waitUntil) since the response doesn't depend on it; the L1
 * write is awaited so an immediate same-colo re-read is a hit.
 */
export function kvBackedPut(
  kv: KVNamespace | undefined | null,
  key: string,
  data: unknown,
  ttlSeconds: number,
  waitUntil?: (p: Promise<unknown>) => void
): Promise<void> {
  // L1 write — started first so a same-colo re-read is a hit.
  const l1 = routeCachePut(key, data, ttlSeconds);
  // L2 write — fire-and-forget if a waitUntil ctx is available, else awaited.
  if (kv) {
    const l2 = kv.put(key, JSON.stringify(data), { expirationTtl: ttlSeconds }).catch(() => {});
    if (waitUntil) {
      // Hono's `c.executionCtx` THROWS when a context has no ExecutionContext
      // (cron, subrequest, and unit tests that mount a bare Hono app), and
      // callers routinely pass `(p) => c.executionCtx.waitUntil(p)` straight
      // through. Without this guard a throw here escapes mid-function: the L2
      // write is left floating and `l1` is never returned or awaited, so a
      // cache write silently degrades into a race — an in-flight L1 put can
      // land after a later invalidate() and resurrect stale data.
      try {
        waitUntil(l2);
        return l1;
      } catch {
        // No usable waitUntil — fall through and await both writes properly.
        return Promise.all([l1, l2]).then(() => undefined);
      }
    }
    return Promise.all([l1, l2]).then(() => undefined);
  }
  return l1;
}

/**
 * Cache-first + stale-while-revalidate response helper for Hono routes.
 *
 * The pattern every route handler wants:
 *   1. Check the per-colo Cache API (free, no KV quota).
 *   2. If cached AND fresh (< ttl * 0.8): serve immediately.
 *   3. If cached BUT stale (> ttl * 0.8): serve immediately + refresh in
 *      the background via `executionCtx.waitUntil`.
 *   4. If not cached: fetch from upstream, cache, serve.
 *
 * This uses ZERO KV reads/writes — the Cache API is per-colo and free.
 * The trade-off: a cold colo (first visitor in a region) still hits the
 * upstream, but every subsequent visitor in that colo gets an instant
 * cache hit. For routes that need cross-colo durability, use `kvBackedGet`
 * / `kvBackedPut` instead.
 *
 * @example
 *   return cachedJson(c, 'cve-recent:v1', 300, async () => {
 *     const res = await fetch('https://upstream/api');
 *     return res.json();
 *   });
 */
export async function cachedJson<T>(
  c: Context<{ Bindings: Env }>,
  key: string,
  ttlSeconds: number,
  fetcher: () => Promise<T>
): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(`${CACHE_BASE}/${encodeURIComponent(key)}`);

  // 1. Check the per-colo Cache API.
  const cached = await cache.match(cacheReq);
  if (cached) {
    const cacheDate = cached.headers.get('date');
    const age = cacheDate ? (Date.now() - new Date(cacheDate).getTime()) / 1000 : 0;

    // 3. Stale-while-revalidate: serve immediately, refresh in background.
    if (age > ttlSeconds * 0.8) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            const fresh = await fetcher();
            const resp = new Response(JSON.stringify(fresh), {
              headers: {
                'content-type': 'application/json',
                'cache-control': `public, max-age=${ttlSeconds}, stale-while-revalidate=${ttlSeconds * 4}`,
              },
            });
            await cache.put(cacheReq, resp);
          } catch {
            /* non-fatal — the stale copy stays */
          }
        })()
      );
    }
    return new Response(cached.body, cached);
  }

  // 4. Cold cache — fetch from upstream, cache, serve.
  try {
    const data = await fetcher();
    const response = c.json(data, 200, {
      'cache-control': `public, max-age=${ttlSeconds}, stale-while-revalidate=${ttlSeconds * 4}`,
    });
    c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
    return response;
  } catch (e) {
    return c.json({ error: 'upstream_fetch_failed', message: e instanceof Error ? e.message : String(e) }, 502, {
      'cache-control': 'no-store',
    });
  }
}
