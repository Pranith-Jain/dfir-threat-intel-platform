import { describe, it, expect } from 'vitest';
import { dailyBriefsRouter, mergeIndexes } from '../../src/routes/daily-briefs-edge-tools';
// Same module the route loads (api/src/lib/daily-briefs-manifest.ts is a symlink
// to worker/lib), so the memo reset targets the identical instance.
import { _resetDbCacheForTests } from '../../src/lib/daily-briefs-manifest';
import type { Env } from '../../src/env';

/**
 * Regression cover for the daily-briefs index staleness.
 *
 * `/api/v1/daily-briefs/` listed September briefs while the repository already
 * carried October ones. `loadIndex` preferred whichever source was merely
 * NON-EMPTY, so a stale-but-populated KV index shadowed a newer static manifest
 * and the ASSETS fallback became unreachable. Neither source raised an error —
 * each looked healthy on its own — so this presented purely as "the data is
 * stale" with no signal about why.
 *
 * The merge is asserted directly rather than through the route: `loadIndex`
 * memoises the static manifest module-level AND writes its result to the
 * per-colo Cache API under a fixed key with a 10-minute TTL. Both outlive a
 * single test, so an HTTP-level assertion ends up measuring the previous test's
 * cached response rather than the code.
 */

type Counts = { cyber: number; deepfake: number; disaster: number; maritime: number };
type Row = { type: string; date: string; sizeBytes: number };
interface Idx {
  source: string;
  license: string;
  generatedAt: string;
  counts: Counts;
  briefs: Row[];
}

const idx = (generatedAt: string, rows: Array<[string, string]>): Idx => ({
  source: 'agentic-ai-daily-reports.netlify.app',
  license: 'MIT',
  generatedAt,
  counts: { cyber: 0, deepfake: 0, disaster: 0, maritime: 0 },
  briefs: rows.map(([type, date]) => ({ type, date, sizeBytes: 100 })),
});

function kvWithIndex(value: Idx): KVNamespace {
  const raw = JSON.stringify(value);
  return {
    // Honour KV's `type` argument — loadIndex reads with 'json', and a stub
    // returning the raw string makes `'briefs' in value` false, which looks
    // exactly like an empty index.
    get: async (key: string, type?: string) => {
      if (key !== 'db:index') return null;
      return type === 'json' ? (JSON.parse(raw) as unknown) : raw;
    },
  } as unknown as KVNamespace;
}

type RouterLike = { request: (p: string, i?: RequestInit, e?: unknown, ctx?: unknown) => Promise<Response> };

/**
 * `dailyBriefsRouter` is mounted at `/api/v1` in index.ts, so its own route paths
 * are relative to that prefix. Hono's `app.request(path, init, env)` takes the
 * bindings as the THIRD argument — passing a ctx-shaped object there makes the
 * handler read `c.env.KV_CACHE` off that object and get undefined.
 */
async function call(path: string, env: Partial<Env>): Promise<Response> {
  const router = dailyBriefsRouter as unknown as RouterLike;
  return router.request(path, {}, env, { executionCtx: { waitUntil: () => {} } });
}

describe('mergeIndexes', () => {
  /**
   * Mirrors the production shape exactly: the KV index carries the long tail
   * and is the MORE RECENT source by wall clock, but its per-type coverage
   * lags — cyber stopped at 2026-09-30 while the committed static manifest had
   * already moved to 2026-10-07. So "pick whichever has more rows" and "pick
   * whichever is newer" both give the wrong answer, and only the union is
   * right.
   */
  const staleKv = idx('2026-10-09', [
    ['cyber', '2026-09-28'],
    ['cyber', '2026-09-29'],
    ['cyber', '2026-09-30'],
  ]);
  const freshStatic = idx('2026-10-07', [
    ['cyber', '2026-10-06'],
    ['cyber', '2026-10-07'],
    ['deepfake', '2026-10-07'],
  ]);

  it('keeps dates from BOTH sources rather than preferring the non-empty one', () => {
    const out = mergeIndexes(staleKv, freshStatic);
    const cyber = out!.briefs.filter((b) => b.type === 'cyber').map((b) => b.date);
    // KV-only dates are retained…
    expect(cyber).toContain('2026-09-28');
    // …and the newer static dates KV was missing are present too.
    expect(cyber).toContain('2026-10-07');
  });

  it('does not lose a brief TYPE that only one source carries', () => {
    // The old code returned KV alone, so every deepfake brief vanished from the
    // page even though the static manifest had them.
    const out = mergeIndexes(staleKv, freshStatic);
    expect(out!.briefs.some((b) => b.type === 'deepfake')).toBe(true);
  });

  it('reports the newest generatedAt, not the one with more rows', () => {
    // KV wins on row count; "current as of" must still come from the newer
    // source rather than regressing to whichever contributed more.
    const many: Array<[string, string]> = Array.from({ length: 40 }, (_, i) => [
      'cyber',
      `2026-08-${String(i + 1).padStart(2, '0')}`,
    ]);
    const out = mergeIndexes(idx('2026-10-09', many), idx('2026-10-07', [['cyber', '2026-10-07']]));
    expect(out!.generatedAt).toBe('2026-10-09');
  });

  it('de-duplicates a date present in both sources', () => {
    const out = mergeIndexes(
      idx('2026-10-09', [['cyber', '2026-10-07']]),
      idx('2026-10-08', [['cyber', '2026-10-07']])
    );
    expect(out!.briefs.filter((b) => b.date === '2026-10-07')).toHaveLength(1);
  });

  it('takes the shared row from the NEWER source, whichever side it arrived on', () => {
    // Both sources carry `cyber:2026-10-07` with different sizes. The fresh row
    // must win regardless of argument order — otherwise the envelope advertises
    // the newer generatedAt while the row itself is the stale one.
    const older = {
      ...idx('2026-10-08', [['cyber', '2026-10-07']]),
      briefs: [{ type: 'cyber', date: '2026-10-07', sizeBytes: 1 }],
    };
    const newer = {
      ...idx('2026-10-09', [['cyber', '2026-10-07']]),
      briefs: [{ type: 'cyber', date: '2026-10-07', sizeBytes: 2 }],
    };
    expect(mergeIndexes(older, newer)?.briefs[0]?.sizeBytes).toBe(2);
    expect(mergeIndexes(newer, older)?.briefs[0]?.sizeBytes).toBe(2);
  });

  it('recounts counts from the union, not by copying either side', () => {
    const out = mergeIndexes(
      idx('2026-10-09', [
        ['cyber', '2026-09-28'],
        ['cyber', '2026-09-29'],
      ]),
      idx('2026-10-08', [
        ['cyber', '2026-10-07'],
        ['maritime', '2026-10-07'],
      ])
    );
    expect(out!.counts.cyber).toBe(3);
    expect(out!.counts.maritime).toBe(1);
  });

  it('sorts the union newest-first', () => {
    const out = mergeIndexes(
      idx('2026-10-09', [['cyber', '2026-09-01']]),
      idx('2026-10-08', [['cyber', '2026-10-07']])
    );
    const dates = out!.briefs.map((b) => b.date);
    expect([...dates].sort((a, b) => b.localeCompare(a))).toEqual(dates);
  });

  it('passes a single source through unchanged', () => {
    expect(mergeIndexes(idx('2026-10-09', [['cyber', '2026-10-07']]), null)?.generatedAt).toBe('2026-10-09');
    expect(mergeIndexes(null, idx('2026-10-08', [['cyber', '2026-10-06']]))?.generatedAt).toBe('2026-10-08');
  });

  it('returns null when neither source has data', () => {
    expect(mergeIndexes(null, null)).toBeNull();
  });
});

/** ASSETS stub serving a fixed manifest at the path `loadDbIndex` requests. */
function assetsWith(manifest: Idx): Fetcher {
  return {
    fetch: async (input: RequestInfo | URL) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.includes('/data/daily-briefs/index.json')) {
        return new Response(JSON.stringify(manifest), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('nf', { status: 404 });
    },
  } as unknown as Fetcher;
}

/** Drop the per-colo Cache-API shadow so `loadIndex` reads its sources. */
async function coldShadow(): Promise<void> {
  _resetDbCacheForTests();
  const cache = (globalThis as unknown as { caches?: { default?: Cache } }).caches?.default;
  await cache?.delete(new Request('https://db-cache.internal/v1/db:index'));
}

describe('/api/v1/daily-briefs/ — end to end through loadIndex', () => {
  it('serves the union of KV and the static manifest', async () => {
    // Exercises the real loadIndex (not just the exported helper), which is
    // where the "prefer whichever is non-empty" bug lived.
    //
    // KV carries the long tail and looks NEWER by wall clock, but its per-type
    // coverage stops at 2026-09-30; the static manifest has already moved to
    // 2026-10-07. "More rows" and "newer generatedAt" both pick KV here and
    // lose the October briefs, so only the union is correct.
    await coldShadow();
    const res = await call('/daily-briefs/', {
      KV_CACHE: kvWithIndex(
        idx('2026-10-09', [
          ['cyber', '2026-01-01'],
          ['cyber', '2026-09-30'],
        ])
      ),
      ASSETS: assetsWith(
        idx('2026-10-07', [
          ['cyber', '2026-10-06'],
          ['cyber', '2026-10-07'],
          ['deepfake', '2026-10-07'],
        ])
      ),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { briefs: Row[]; generatedAt: string };
    const cyberDates = body.briefs.filter((b) => b.type === 'cyber').map((b) => b.date);
    // KV-only dates are retained…
    expect(cyberDates).toContain('2026-01-01');
    expect(cyberDates).toContain('2026-09-30');
    // …and the newer static dates KV was missing are present too.
    expect(cyberDates).toContain('2026-10-07');
    // A brief TYPE only the static manifest carries survives.
    expect(body.briefs.some((b) => b.type === 'deepfake')).toBe(true);
    // "Current as of" is the newer of the two sources.
    expect(body.generatedAt).toBe('2026-10-09');
  });

  it('still serves the static manifest when KV has nothing', async () => {
    await coldShadow();
    const emptyKv = { get: async () => null } as unknown as KVNamespace;
    const res = await call('/daily-briefs/', {
      KV_CACHE: emptyKv,
      ASSETS: assetsWith(idx('2026-10-07', [['cyber', '2026-10-07']])),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { briefs: Row[] };
    expect(body.briefs.map((b) => b.date)).toEqual(['2026-10-07']);
  });
});

describe('/daily-briefs/stats route', () => {
  it('is not swallowed by the /daily-briefs/:type parametrised route', async () => {
    // Hono matches in registration order, so the literal `/stats` route
    // declared AFTER `/daily-briefs/:type` was unreachable and answered
    // 400 "invalid_type: stats".
    const res = await call('/daily-briefs/stats', {
      KV_CACHE: kvWithIndex(idx('2026-10-09', [['cyber', '2026-10-07']])),
    });
    // 200 when the index loads, 400 only if `stats` is being read as a type.
    expect(res.status).toBe(200);
    const body = (await res.json()) as { counts?: Counts };
    expect(body.counts).toBeDefined();
  });

  it('still rejects a genuinely unknown brief type with 400', async () => {
    const res = await call('/daily-briefs/not-a-type', {
      KV_CACHE: kvWithIndex(idx('2026-10-09', [['cyber', '2026-10-07']])),
    });
    expect(res.status).toBe(400);
  });
});
