import { describe, it, expect, vi, afterEach } from 'vitest';
import { readLastGood, writeLastGood } from '../../src/lib/lastgood';
import { kvBulkGetText, kvPutSafe } from '../../src/lib/safe-catch';
import { kvPutIfChanged } from '../../src/lib/kv-write';

const upstashEnv = {
  UPSTASH_REDIS_REST_URL: 'https://example.upstash.io',
  UPSTASH_REDIS_REST_TOKEN: 'token',
};

function makeKV() {
  const store = new Map<string, string>();
  return {
    store,
    get: vi.fn(async (k: string | string[]) => {
      if (Array.isArray(k)) return new Map(k.map((key) => [key, store.get(key) ?? null]));
      return store.get(k) ?? null;
    }),
    put: vi.fn(async (k: string, v: string) => {
      store.set(k, v);
    }),
  };
}

function envWith(kv: ReturnType<typeof makeKV>) {
  return { KV_CACHE: kv, ...upstashEnv } as unknown as Parameters<typeof writeLastGood>[0];
}

/** Mock Upstash REST: inspect the command and return a canned result. */
function mockRedis(resultFor: (cmd: unknown[]) => unknown) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    const cmd = JSON.parse((init as RequestInit).body as string) as unknown[];
    return { ok: true, json: async () => ({ result: resultFor(cmd) }) } as Response;
  });
}

afterEach(() => vi.restoreAllMocks());

describe('Redis-first cache wrappers', () => {
  it('writeLastGood writes to Redis and skips KV when configured', async () => {
    const kv = makeKV();
    const spy = mockRedis((cmd) => (cmd[0] === 'SET' ? 'OK' : null));
    const written = await writeLastGood(envWith(kv), 'redis-lg-1', { ok: true }, { force: true, ttlSeconds: 60 });
    expect(written).toBe(true);
    expect(kv.put).not.toHaveBeenCalled();
    expect(spy).toHaveBeenCalled();
    const cmd = JSON.parse(spy.mock.calls[0]![1]!.body as string) as unknown[];
    expect(cmd[0]).toBe('SET');
    expect(cmd[1]).toBe('lastgood:v1:redis-lg-1');
    expect(cmd.slice(-2)).toEqual(['EX', 60]);
  });

  it('readLastGood reads Redis before KV', async () => {
    const kv = makeKV();
    kv.store.set('lastgood:v1:redis-lg-2', '{"ok":false}');
    mockRedis((cmd) => (cmd[0] === 'GET' ? '{"ok":true}' : null));
    const value = await readLastGood<{ ok: boolean }>(envWith(kv), 'redis-lg-2');
    expect(value).toEqual({ ok: true });
    expect(kv.get).not.toHaveBeenCalled();
  });

  it('kvBulkGetText uses MGET and only reads KV for misses', async () => {
    const kv = makeKV();
    kv.store.set('missing-2', 'from-kv');
    const spy = mockRedis((cmd) => (cmd[0] === 'MGET' ? ['a', null, 'c'] : null));
    const out = await kvBulkGetText(envWith(kv), ['k1', 'missing-2', 'k3']);
    expect(out.get('k1')).toBe('a');
    expect(out.get('k3')).toBe('c');
    expect(out.get('missing-2')).toBe('from-kv');
    expect(spy.mock.calls.some((c) => (JSON.parse(c[1]!.body as string) as unknown[])[0] === 'MGET')).toBe(true);
    expect(kv.get).toHaveBeenCalledTimes(1);
  });

  it('kvPutIfChanged skips KV when Redis accepts the write', async () => {
    const kv = makeKV();
    mockRedis((cmd) => (cmd[0] === 'GET' ? null : 'OK'));
    const written = await kvPutIfChanged(envWith(kv), 'redis-ifchanged', '{"v":1}', { expirationTtl: 60 });
    expect(written).toBe(true);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it('kvPutSafe writes text through Redis', async () => {
    const kv = makeKV();
    const spy = mockRedis(() => 'OK');
    const written = await kvPutSafe(envWith(kv), 'redis-safe', 'value', { expirationTtl: 30 });
    expect(written).toBe(true);
    expect(kv.put).not.toHaveBeenCalled();
    expect(JSON.parse(spy.mock.calls[0]![1]!.body as string)[0]).toBe('SET');
  });

  it('falls back to KV when Redis is not configured', async () => {
    const kv = makeKV();
    const spy = vi.spyOn(globalThis, 'fetch');
    const written = await writeLastGood(
      { KV_CACHE: kv } as unknown as Parameters<typeof writeLastGood>[0],
      'kv-only-lg',
      { ok: true },
      { force: true, ttlSeconds: 60 }
    );
    expect(written).toBe(true);
    expect(kv.put).toHaveBeenCalled();
    expect(spy).not.toHaveBeenCalled();
  });
});
