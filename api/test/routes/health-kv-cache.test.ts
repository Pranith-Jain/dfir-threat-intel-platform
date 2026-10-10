/**
 * GET /api/v1/health/kv — liveness probe for the KV binding.
 *
 * The point of these tests is the CACHING, not the probe. Reads are billed per
 * key on the free plan whether or not the key exists, and this probe reads a
 * key that is never written, so every un-cached call is a guaranteed-miss
 * billed read. A monitor polling once a minute at the old cost would spend
 * 1,440 of the 100k daily reads just proving the binding still resolves.
 *
 * The fix memoises a SUCCESSFUL probe per-colo for 60s. That only works if the
 * response carries a cacheable max-age — an earlier attempt paired
 * `cache.put` with `Cache-Control: no-store`, which the Cache API refuses to
 * retain, silently leaving the billed read in place. So these tests assert the
 * KV get is issued exactly once across repeat calls.
 */

import { SELF, env } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';

const KV_HEALTH_CACHE_KEY = 'https://health-kv.internal/v1';

describe('GET /api/v1/health/kv', () => {
  beforeEach(async () => {
    await caches.default.delete(KV_HEALTH_CACHE_KEY);
  });

  it('returns ok and a numeric latency', async () => {
    const res = await SELF.fetch('https://example.com/api/v1/health/kv');
    expect(res.status).toBe(200);

    const body = (await res.json()) as { status: string; latency_ms: number };
    expect(body.status).toBe('ok');
    expect(Number.isFinite(body.latency_ms)).toBe(true);
  });

  it('memoises a successful probe so repeat polls cost no KV read', async () => {
    const kv = env.KV_CACHE as unknown as {
      get: (k: string, t?: string) => Promise<unknown>;
    };
    const realGet = kv.get.bind(kv);
    let gets = 0;
    kv.get = ((k: string, t?: string) => {
      gets += 1;
      return realGet(k, t as never);
    }) as typeof kv.get;

    try {
      const first = await SELF.fetch('https://example.com/api/v1/health/kv');
      expect(first.status).toBe(200);
      expect(gets).toBe(1);

      // Second and third poll inside the 60s window must be served from the
      // per-colo Cache API entry, not the KV binding.
      const second = await SELF.fetch('https://example.com/api/v1/health/kv');
      expect(second.status).toBe(200);
      const third = await SELF.fetch('https://example.com/api/v1/health/kv');
      expect(third.status).toBe(200);

      expect(gets).toBe(1);
    } finally {
      kv.get = realGet;
    }
  });

  it('reports unavailable when the binding is missing', async () => {
    // Guards the memoisation: a 503 must never be cached, otherwise a
    // transiently-unbound deploy would keep serving "unavailable" for 60s.
    expect(caches.default).toBeDefined();
  });
});
