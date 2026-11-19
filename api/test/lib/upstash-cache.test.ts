import { describe, it, expect, vi, afterEach } from 'vitest';
import { upstashConfigured, upstashGet, upstashSet, upstashMGet } from '../../src/lib/upstash-cache';

const env = { UPSTASH_REDIS_REST_URL: 'https://example.upstash.io', UPSTASH_REDIS_REST_TOKEN: 'token' };

afterEach(() => vi.restoreAllMocks());

function mockFetch(result: unknown, ok = true) {
  const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok,
    json: async () => ({ result }),
  } as Response);
  return spy;
}

describe('upstash-cache', () => {
  it('reports unconfigured without making requests', async () => {
    expect(upstashConfigured(undefined)).toBe(false);
    expect(upstashConfigured({ UPSTASH_REDIS_REST_URL: 'x' })).toBe(false);
    const spy = vi.spyOn(globalThis, 'fetch');
    expect(await upstashGet(undefined, 'k')).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it('GETs a key with a bearer token', async () => {
    const spy = mockFetch('payload');
    expect(await upstashGet(env, 'gp:key')).toBe('payload');
    const [url, init] = spy.mock.calls[0]!;
    expect(url).toBe(env.UPSTASH_REDIS_REST_URL);
    expect((init as RequestInit).headers).toMatchObject({ authorization: 'Bearer token' });
    expect(JSON.parse((init as RequestInit).body as string)).toEqual(['GET', 'gp:key']);
  });

  it('SETs with TTL and only reports success for OK', async () => {
    const spy = mockFetch('OK');
    expect(await upstashSet(env, 'k', 'v', 90)).toBe(true);
    expect(JSON.parse(spy.mock.calls[0]![1]!.body as string)).toEqual(['SET', 'k', 'v', 'EX', 90]);
    mockFetch('QUEUED');
    expect(await upstashSet(env, 'k', 'v', 90)).toBe(false);
  });

  it('MGETs many keys in one command and skips misses', async () => {
    const spy = mockFetch(['a', null, 'c']);
    const out = await upstashMGet(env, ['k1', 'k2', 'k3']);
    expect([...out.entries()]).toEqual([
      ['k1', 'a'],
      ['k3', 'c'],
    ]);
    expect(JSON.parse(spy.mock.calls[0]![1]!.body as string)).toEqual(['MGET', 'k1', 'k2', 'k3']);
  });

  it('degrades to null when the REST call fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('offline'));
    expect(await upstashGet(env, 'k')).toBeNull();
  });
});
