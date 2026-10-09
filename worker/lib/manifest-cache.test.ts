/**
 * Tests for the shared manifest cache primitives.
 *
 * `worker/lib/manifest-cache.ts` was extracted because twenty manifest loaders
 * each carried their own copy of `BodyCache` / `trackHit` / `recordHit` /
 * `fetchJson`. Folding twenty copies into one helper is exactly the refactor
 * that silently changes behaviour: the copies were "byte-identical" by
 * inspection, but inspection is what the refactor was betting on, and these
 * tests are what makes the bet checkable.
 *
 * LRU eviction is the behaviour most likely to break silently — a wrong
 * comparison or an off-by-one only shows up as unbounded memory growth under
 * load, never as a failed assertion elsewhere.
 */
import { describe, it, expect } from 'vitest';
import { trackHit, recordHit, fetchJsonAsset, type BodyCache } from './manifest-cache';

const cache = <T>(): BodyCache<T> => ({ map: new Map(), hits: 0, misses: 0 });

describe('trackHit', () => {
  it('returns the value and counts a hit', () => {
    const c = cache<string>();
    recordHit(c, 'a', 'A', 10);
    expect(trackHit(c, 'a')).toBe('A');
    expect(c.hits).toBe(1);
    expect(c.misses).toBe(0);
  });

  it('returns undefined and counts a miss', () => {
    const c = cache<string>();
    expect(trackHit(c, 'nope')).toBeUndefined();
    expect(c.misses).toBe(1);
    expect(c.hits).toBe(0);
  });

  it('does not count a stored undefined as a hit', () => {
    // `v === undefined` (not `!v`) is what makes a stored undefined a miss;
    // using a truthiness check here would miscount and, worse, let a stored
    // falsy value like 0 or '' be treated as absent.
    const c = cache<string | undefined>();
    recordHit(c, 'u', undefined, 10);
    expect(trackHit(c, 'u')).toBeUndefined();
    expect(c.misses).toBe(1);
    expect(c.hits).toBe(0);
  });

  it('treats a stored falsy value as present', () => {
    const c = cache<number>();
    recordHit(c, 'zero', 0, 10);
    expect(trackHit(c, 'zero')).toBe(0);
    expect(c.hits).toBe(1);

    const s = cache<string>();
    recordHit(s, 'empty', '', 10);
    expect(trackHit(s, 'empty')).toBe('');
    expect(s.hits).toBe(1);
  });

  it('refreshes recency on a hit so LRU order is real', () => {
    const c = cache<string>();
    recordHit(c, 'a', 'A', 10);
    recordHit(c, 'b', 'B', 10);
    recordHit(c, 'c', 'C', 10);
    // 'a' is now the most recently used, so 'b' becomes the eviction candidate.
    trackHit(c, 'a');
    expect([...c.map.keys()]).toEqual(['b', 'c', 'a']);
  });
});

describe('recordHit', () => {
  it('returns the value it stored', () => {
    const c = cache<string>();
    expect(recordHit(c, 'a', 'A', 10)).toBe('A');
  });

  it('evicts the oldest entry when over capacity', () => {
    const c = cache<string>();
    recordHit(c, 'a', 'A', 2);
    recordHit(c, 'b', 'B', 2);
    recordHit(c, 'c', 'C', 2);
    expect(c.map.size).toBe(2);
    expect(c.map.has('a')).toBe(false);
    expect([...c.map.keys()]).toEqual(['b', 'c']);
  });

  it('evicts down to exactly the limit, not limit-1', () => {
    const c = cache<string>();
    for (const k of ['a', 'b', 'c', 'd']) recordHit(c, k, k, 3);
    expect(c.map.size).toBe(3);
    expect(c.map.has('a')).toBe(false);
    expect(c.map.has('d')).toBe(true);
  });

  it('overwriting a key does not consume capacity', () => {
    // The delete-then-set in recordHit exists for this: without it, Map.set on
    // an existing key keeps the ORIGINAL insertion position, so an overwrite
    // would leave the entry looking stale and get evicted early.
    const c = cache<string>();
    recordHit(c, 'a', 'A', 3);
    recordHit(c, 'b', 'B', 3);
    recordHit(c, 'a', 'A2', 3);
    expect(c.map.size).toBe(2);
    expect([...c.map.keys()]).toEqual(['b', 'a']);
    recordHit(c, 'c', 'C', 3);
    recordHit(c, 'd', 'D', 3);
    // 'b' is now oldest; the refreshed 'a' survives.
    expect(c.map.has('b')).toBe(false);
    expect(c.map.has('a')).toBe(true);
  });

  it('handles a capacity of 1', () => {
    const c = cache<string>();
    recordHit(c, 'a', 'A', 1);
    recordHit(c, 'b', 'B', 1);
    expect(c.map.size).toBe(1);
    expect(c.map.has('b')).toBe(true);
  });

  it('does not throw when eviction empties the map', () => {
    // Defensive: a max below 1 would otherwise spin on `keys().next()` forever.
    const c = cache<string>();
    recordHit(c, 'a', 'A', 0);
    expect(c.map.size).toBe(0);
  });
});

describe('fetchJsonAsset', () => {
  const assets = (body: string, ok = true): Fetcher =>
    ({
      fetch: async () => new Response(body, { status: ok ? 200 : 404 }),
    }) as unknown as Fetcher;

  it('parses a JSON body', async () => {
    const out = await fetchJsonAsset<{ a: number }>(assets('{"a":1}'), '/data/x.json', 'https://x.local');
    expect(out).toEqual({ a: 1 });
  });

  it('returns null on a non-ok response', async () => {
    // The contract the twenty loaders rely on: a missing asset degrades to
    // "not available", never a thrown error that would 500 the whole route.
    const out = await fetchJsonAsset(assets('', false), '/data/x.json', 'https://x.local');
    expect(out).toBeNull();
  });

  it('propagates a malformed-JSON rejection rather than swallowing it', async () => {
    // Distinct from a non-ok response: `res.ok` is true here, so the caller
    // learns the asset is corrupt instead of being told it is absent.
    await expect(fetchJsonAsset(assets('{not json'), '/data/x.json', 'https://x.local')).rejects.toThrow();
  });

  it('requests the asset under the caller-supplied origin', async () => {
    // `host` is only the origin for cache-key readability — ASSETS serves from
    // the bundled dir regardless — so the path must survive intact.
    const seen: string[] = [];
    const spy = {
      fetch: async (req: Request) => {
        seen.push(req.url);
        return new Response('{}', { status: 200 });
      },
    } as unknown as Fetcher;
    await fetchJsonAsset(spy, '/data/threat-monitor/sources.json', 'https://tam.local');
    expect(seen).toEqual(['https://tam.local/data/threat-monitor/sources.json']);
  });
});
