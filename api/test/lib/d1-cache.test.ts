import { describe, it, expect, beforeEach } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import { d1Cached, d1CacheKey, invalidateD1Cache } from '../../src/lib/d1-cache';
import type { Env } from '../../src/env';

const env = testEnv as unknown as Env;

describe('d1CacheKey', () => {
  it('namespaces and separates scope from discriminator', () => {
    expect(d1CacheKey('tbl', 'all')).toBe('d1cache:v1:tbl:all');
  });

  // The guard that stops a caller caching "SELECT * FROM reports" under a
  // key that ignores whose reports it was — the failure mode here is a
  // cross-tenant data leak, not a perf bug, so it must fail loudly.
  it('refuses a key with no discriminator', () => {
    expect(() => d1CacheKey('tbl', '')).toThrow(/discriminator is required/);
  });

  it('refuses an empty scope', () => {
    expect(() => d1CacheKey('   ', 'all')).toThrow(/scope is required/);
  });

  it('produces distinct keys for distinct discriminators', () => {
    expect(d1CacheKey('tbl', 'a')).not.toBe(d1CacheKey('tbl', 'b'));
  });
});

describe('d1Cached', () => {
  beforeEach(async () => {
    // Clear BOTH tiers. `caches.default` is per-isolate and outlives the KV
    // entry across tests in this pool, so deleting only KV leaves the L1
    // shadow serving the previous test's value. (This is precisely why
    // `invalidateD1Cache` has to delete both.)
    await invalidateD1Cache(env, 'd1cache:v1:test:unit');
    await invalidateD1Cache(env, 'd1cache:v1:test:broken');
  });

  it('runs the query on a cold key and serves the cached value after', async () => {
    let calls = 0;
    const query = async () => {
      calls++;
      return { v: 42 };
    };

    const a = await d1Cached(env, 'd1cache:v1:test:unit', 300, query);
    const b = await d1Cached(env, 'd1cache:v1:test:unit', 300, query);

    expect(a).toEqual({ v: 42 });
    expect(b).toEqual({ v: 42 });
    // The whole point: the second call must not reach D1 again.
    expect(calls).toBe(1);
  });

  it('bypasses the cache when force is set, and repopulates it', async () => {
    let calls = 0;
    const query = async () => ({ v: ++calls });

    await d1Cached(env, 'd1cache:v1:test:unit', 300, query);
    expect(await d1Cached(env, 'd1cache:v1:test:unit', 300, query, { force: true })).toEqual({ v: 2 });
    expect(calls).toBe(2);
    // The forced run wrote through, so the next ordinary call is a hit.
    expect(await d1Cached(env, 'd1cache:v1:test:unit', 300, query)).toEqual({ v: 2 });
    expect(calls).toBe(2);
  });

  // A cache outage must degrade to "uncached but working", never to a 500.
  it('still returns the query result when KV reads throw', async () => {
    const kv = env.KV_CACHE as unknown as {
      get: () => Promise<never>;
      put: () => Promise<never>;
      delete: () => Promise<never>;
    };
    const broken = { KV_CACHE: kv };
    kv.get = () => Promise.reject(new Error('kv down'));
    kv.put = () => Promise.reject(new Error('kv down'));

    const out = await d1Cached(broken as unknown as Env, 'd1cache:v1:test:broken', 300, async () => ({ v: 7 }));
    expect(out).toEqual({ v: 7 });
  });

  // Without the binding (api-only unit tests, trimmed dev env) the helper
  // must be a transparent passthrough rather than a crash.
  it('passes straight through when KV_CACHE is unbound', async () => {
    let calls = 0;
    const out = await d1Cached({} as Env, 'd1cache:v1:test:none', 300, async () => ({ v: ++calls }));
    expect(out).toEqual({ v: 1 });
  });

  it('propagates a D1 error rather than caching the failure', async () => {
    await expect(
      d1Cached(env, 'd1cache:v1:test:unit', 300, async () => {
        throw new Error('d1 down');
      })
    ).rejects.toThrow('d1 down');

    // And nothing was memoized, so a later healthy run works.
    expect(await d1Cached(env, 'd1cache:v1:test:unit', 300, async () => ({ v: 9 }))).toEqual({ v: 9 });
  });

  it('invalidateD1Cache forces the next call back to the source', async () => {
    let calls = 0;
    const query = async () => ({ v: ++calls });

    await d1Cached(env, 'd1cache:v1:test:unit', 300, query);
    await invalidateD1Cache(env, 'd1cache:v1:test:unit');
    expect(await d1Cached(env, 'd1cache:v1:test:unit', 300, query)).toEqual({ v: 2 });
  });
});
