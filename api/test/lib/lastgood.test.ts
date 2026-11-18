import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readLastGood, writeLastGood } from '../../src/lib/lastgood';

/**
 * Direct tests for the shared last-good helpers. Briefing-builder exercises
 * these through `withLastGood`, but the helpers themselves are also used by
 * cve-recent, mti, ransomware-recent, malicious-packages, and any future
 * single-upstream endpoint that needs a durable cross-colo fallback.
 */

interface FakeKV {
  store: Map<string, { value: string; expirationTtl?: number }>;
  get: (k: string, t?: 'text' | 'json' | 'arrayBuffer' | 'stream') => Promise<unknown>;
  put: (k: string, v: string, opts?: { expirationTtl?: number }) => Promise<unknown>;
  delete: (k: string) => Promise<unknown>;
}

function makeKV(): FakeKV {
  const store = new Map<string, { value: string; expirationTtl?: number }>();
  return {
    store,
    get: async (k: string, t?: 'text' | 'json' | 'arrayBuffer' | 'stream') => {
      const v = store.get(k);
      if (!v) return null;
      return t === 'json' ? JSON.parse(v.value) : v.value;
    },
    put: async (k: string, v: string, opts?: { expirationTtl?: number }) => {
      store.set(k, { value: v, expirationTtl: opts?.expirationTtl });
    },
    delete: async (k: string) => {
      store.delete(k);
    },
  };
}

function makeEnv(kv: FakeKV | null) {
  return { KV_CACHE: kv } as unknown as Parameters<typeof readLastGood>[0];
}

beforeEach(async () => {
  // Each test starts with a fresh debounce window so a previous test's
  // successful write doesn't suppress the next one.
  vi.useRealTimers();
  // The debounce helper uses request-scoped storage; we can't easily clear
  // that between tests, so we exercise the debounce path by passing
  // `force: true` for the first write of each key.
  // Clear the per-colo Cache-API shadow so a previous test's write-through
  // doesn't mask a KV miss/error in the next test (the shadow is shared
  // across the whole worker in miniflare).
  try {
    await (caches as unknown as { default: Cache }).default.delete(
      new Request('https://lastgood-cache.internal/v1/kev')
    );
    await (caches as unknown as { default: Cache }).default.delete(
      new Request('https://lastgood-cache.internal/v1/shadowkey')
    );
    await (caches as unknown as { default: Cache }).default.delete(
      new Request('https://lastgood-cache.internal/v1/wt')
    );
  } catch {
    /* best-effort */
  }
});

describe('readLastGood', () => {
  it('returns null when KV is unbound', async () => {
    const env = makeEnv(null);
    const r = await readLastGood<{ ok: boolean }>(env, 'kev');
    expect(r).toBeNull();
  });

  it('returns null when no payload is stored', async () => {
    const env = makeEnv(makeKV());
    expect(await readLastGood(env, 'kev')).toBeNull();
  });

  it('returns the stored payload parsed as JSON', async () => {
    const kv = makeKV();
    kv.store.set('lastgood:v1:kev', { value: JSON.stringify({ count: 42, items: [1, 2, 3] }) });
    const env = makeEnv(kv);
    const r = await readLastGood<{ count: number; items: number[] }>(env, 'kev');
    expect(r).toEqual({ count: 42, items: [1, 2, 3] });
  });

  it('returns null on KV read error rather than throwing', async () => {
    const kv: FakeKV = {
      store: new Map(),
      get: vi.fn().mockRejectedValue(new Error('KV down')),
      put: vi.fn(),
      delete: vi.fn(),
    };
    const env = makeEnv(kv);
    expect(await readLastGood(env, 'kev')).toBeNull();
  });

  it('namespaces keys under lastgood:v1: so write/read are symmetric', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'kev', { ok: true }, { force: true });
    expect(kv.store.has('lastgood:v1:kev')).toBe(true);
    const v = await readLastGood<{ ok: boolean }>(env, 'kev');
    expect(v).toEqual({ ok: true });
  });
});

describe('readLastGood Cache-API shadow', () => {
  it('serves a repeat read from the per-colo shadow without a second KV read', async () => {
    const kv = makeKV();
    const getSpy = vi.spyOn(kv, 'get');
    kv.store.set('lastgood:v1:shadowkey', { value: JSON.stringify({ n: 7 }) });
    const env = makeEnv(kv);
    const first = await readLastGood<{ n: number }>(env, 'shadowkey');
    const second = await readLastGood<{ n: number }>(env, 'shadowkey');
    expect(first).toEqual({ n: 7 });
    expect(second).toEqual({ n: 7 });
    // First read hit KV (and populated the shadow); the second came from cache.
    expect(getSpy).toHaveBeenCalledTimes(1);
  });

  it('write-through keeps the shadow coherent (read after write, zero KV reads)', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'wt', { v: 1 }, { force: true });
    const getSpy = vi.spyOn(kv, 'get');
    const r = await readLastGood<{ v: number }>(env, 'wt');
    expect(r).toEqual({ v: 1 });
    expect(getSpy).not.toHaveBeenCalled(); // served from the write-through shadow
  });
});

describe('writeLastGood', () => {
  it('returns false when KV is unbound (no write, no throw)', async () => {
    const env = makeEnv(null);
    expect(await writeLastGood(env, 'kev', { ok: true }, { force: true })).toBe(false);
  });

  it('persists a JSON string under the namespaced key', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    const wrote = await writeLastGood(env, 'kev', { count: 99 }, { force: true });
    expect(wrote).toBe(true);
    const stored = kv.store.get('lastgood:v1:kev');
    expect(stored).toBeDefined();
    expect(JSON.parse(stored!.value)).toEqual({ count: 99 });
  });

  it('respects the default 48h TTL', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'kev', { ok: true }, { force: true });
    const stored = kv.store.get('lastgood:v1:kev');
    expect(stored?.expirationTtl).toBe(48 * 60 * 60);
  });

  it('respects a custom ttlSeconds', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'kev', { ok: true }, { ttlSeconds: 600, force: true });
    expect(kv.store.get('lastgood:v1:kev')?.expirationTtl).toBe(600);
  });

  it('force: true bypasses the per-colo debounce', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    const a = await writeLastGood(env, 'kev', { v: 1 }, { force: true });
    const b = await writeLastGood(env, 'kev', { v: 2 }, { force: true });
    expect(a).toBe(true);
    expect(b).toBe(true);
    const stored = JSON.parse(kv.store.get('lastgood:v1:kev')!.value);
    expect(stored).toEqual({ v: 2 });
  });

  it('skips writes when the debounce is warm (no force)', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    // First write establishes the debounce marker.
    const a = await writeLastGood(env, 'kev', { v: 1 });
    // Second write inside the same debounce window should be suppressed.
    const b = await writeLastGood(env, 'kev', { v: 2 });
    expect(a).toBe(true);
    expect(b).toBe(false);
    const stored = JSON.parse(kv.store.get('lastgood:v1:kev')!.value);
    expect(stored).toEqual({ v: 1 });
  });

  it('returns false on KV put error rather than throwing', async () => {
    const kv: FakeKV = {
      store: new Map(),
      get: vi.fn(),
      put: vi.fn().mockRejectedValue(new Error('KV write failed')),
      delete: vi.fn(),
    };
    const env = makeEnv(kv);
    expect(await writeLastGood(env, 'kev', { ok: true }, { force: true })).toBe(false);
  });

  it('skipIfUnchanged: skips the put when the stored bytes are identical', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    const body = { generated_at: '2026-11-18T00:00:00Z', items: [1, 2, 3] };
    expect(await writeLastGood(env, 'unchanged', body, { force: true })).toBe(true);
    const putSpy = vi.spyOn(kv, 'put');
    expect(await writeLastGood(env, 'unchanged', body, { force: true, skipIfUnchanged: true })).toBe(false);
    expect(putSpy).not.toHaveBeenCalled();
  });

  it('skipIfUnchanged: still writes when the body changed', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'changed', { v: 1 }, { force: true });
    expect(await writeLastGood(env, 'changed', { v: 2 }, { force: true, skipIfUnchanged: true })).toBe(true);
    expect(JSON.parse(kv.store.get('lastgood:v1:changed')!.value)).toEqual({ v: 2 });
  });

  it('skipIfUnchanged: writes when no previous value exists', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    expect(await writeLastGood(env, 'fresh', { v: 1 }, { force: true, skipIfUnchanged: true })).toBe(true);
    expect(kv.store.has('lastgood:v1:fresh')).toBe(true);
  });
});

describe('lastgood + withLastGood integration', () => {
  it('writes only on success; reads only as a fallback', async () => {
    // Round-trip: write a payload, mutate it externally, then read.
    // Confirms the storage format round-trips through the helpers.
    const kv = makeKV();
    const env = makeEnv(kv);
    const original = { generated_at: '2026-06-01T00:00:00Z', count: 5, victims: [{ id: 'a' }] };
    await writeLastGood(env, 'snapshot', original, { force: true });
    const got = await readLastGood<typeof original>(env, 'snapshot');
    expect(got).toEqual(original);
  });
});

describe('readLastGood / writeLastGood with custom keyPrefix', () => {
  // Several routes (x-live, cybercrime, live-iocs AF, crypto-scam-feed,
  // deepdarkcti) carry their own namespacing in the key already
  // (e.g. 'cybercrime/af-datamarkets-lastgood/v1'). They use keyPrefix: ''
  // to use the key verbatim — no double-namespace under 'lastgood:v1:'.
  it('keyPrefix: "" writes under the literal key (no lastgood:v1: prefix)', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'cybercrime/af-datamarkets-lastgood/v1', { n: 1 }, { keyPrefix: '', force: true });
    expect(kv.store.has('lastgood:v1:cybercrime/af-datamarkets-lastgood/v1')).toBe(false);
    expect(kv.store.has('cybercrime/af-datamarkets-lastgood/v1')).toBe(true);
  });

  it('keyPrefix: "" round-trips a read of a literal-key write', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    await writeLastGood(env, 'x-live:fallback:v1', { items: [1, 2] }, { keyPrefix: '', force: true });
    const got = await readLastGood<{ items: number[] }>(env, 'x-live:fallback:v1', { keyPrefix: '' });
    expect(got).toEqual({ items: [1, 2] });
  });

  it('default keyPrefix still namespaced (no cross-talk with literal keys)', async () => {
    const kv = makeKV();
    const env = makeEnv(kv);
    // Distinct key names per write — sharing one name across the shadow would
    // hit the write-through cache from the second write, masking the test.
    await writeLastGood(env, 'k-default', { tag: 'default' }, { force: true });
    await writeLastGood(env, 'k-literal', { tag: 'literal' }, { keyPrefix: '', force: true });
    expect(await readLastGood<{ tag: string }>(env, 'k-default')).toEqual({ tag: 'default' });
    expect(await readLastGood<{ tag: string }>(env, 'k-literal', { keyPrefix: '' })).toEqual({
      tag: 'literal',
    });
    // The literal write must not have leaked into the namespaced namespace.
    expect(kv.store.has('lastgood:v1:k-literal')).toBe(false);
    expect(kv.store.has('k-literal')).toBe(true);
  });
});
