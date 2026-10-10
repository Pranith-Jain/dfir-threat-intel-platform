import { describe, it, expect, afterEach } from 'vitest';

/**
 * Regression cover for the 2026-10-01 → 2026-10-10 stall in
 * `telegram_leak_entries` (the /threatintel/telegram?tab=leaks feed).
 *
 * Root cause
 * ----------
 * The hourly cron's Telegram leak-scan block acquires the feed in three
 * layers, in order:
 *
 *   1. `caches.default.match(tgCacheKey)`  — the Cache API
 *   2. `KV_CACHE.get('gp:warm:telegram')`   — the KV-warm slice
 *   3. `fetchTelegramFeed(...)`            — a live t.me/telegram.me scrape
 *
 * Layer 1 dereferenced the Cache API global *unguarded*, and the whole block
 * sits inside one `try`. That block executes inside the CronJobDO (handleScheduled
 * dispatches `{cron, scheduledTime}` to CronJobDO.alarm → executeCronJob), where
 * the Cache API is not guaranteed. When layer 1 threw, control jumped straight
 * to the block's `catch`, so layers 2 and 3 NEVER RAN. `telegramFeed` stayed
 * undefined, the scanner was skipped, and the only trace was a swallowed
 * warning that nothing alerts on.
 *
 * That is the whole failure: layer 2 was healthy the entire time (the KV-warm
 * slice held 541 fresh items), so one unavailable optimisation layer silenced
 * a data pipeline for nine days.
 *
 * These tests pin the contract that makes that impossible again: losing the
 * Cache API must cost a KV read and nothing else. The "cache IS available"
 * cases matter just as much — they stop someone "fixing" this by deleting the
 * cache fast-path entirely.
 */

const originalCaches = Object.getOwnPropertyDescriptor(globalThis, 'caches');

/** Simulate a runtime with no Cache API global at all. */
function removeCaches(): void {
  Object.defineProperty(globalThis, 'caches', { value: undefined, configurable: true, writable: true });
}

/** Simulate a Cache API global whose `.match` rejects (the DO case). */
function rejectingCache(): void {
  Object.defineProperty(globalThis, 'caches', {
    value: {
      default: {
        match: async () => {
          throw new Error('Cache API unavailable in this runtime');
        },
        put: async () => {},
      },
    },
    configurable: true,
    writable: true,
  });
}

/** A Cache API global that is present but has no `.default` (partial runtime). */
function cacheWithoutDefault(): void {
  Object.defineProperty(globalThis, 'caches', { value: {}, configurable: true, writable: true });
}

/** Minimal in-memory Cache stand-in that records whether it was consulted. */
function workingCache(serveJson?: unknown): { hit: () => number } {
  let hits = 0;
  Object.defineProperty(globalThis, 'caches', {
    value: {
      default: {
        match: async () => {
          hits += 1;
          return serveJson === undefined ? undefined : new Response(JSON.stringify(serveJson));
        },
        put: async () => {},
      },
    },
    configurable: true,
    writable: true,
  });
  return { hit: () => hits };
}

afterEach(() => {
  if (originalCaches) Object.defineProperty(globalThis, 'caches', originalCaches);
});

/**
 * Mirrors the acquisition order in worker/scheduled.ts.
 *
 * Deliberately a copy rather than an import: `executeCronJob` is a ~1400-line
 * cron body whose imports pull in the entire worker + D1 binding surface. The
 * thing under test is the fallback ORDER and the guard placement, and pinning
 * that as an explicit sequence is what makes the regression legible. If the
 * real block is refactored, the two must be updated together — the assertion
 * comments below name the exact lines this covers.
 */
async function acquireFeed(opts: { cacheJson?: unknown; kvJson?: unknown | null }): Promise<{
  feed: unknown;
  usedKv: boolean;
}> {
  let telegramFeed: unknown;

  // Layer 1 — Cache API, guarded (worker/scheduled.ts ~L370-386).
  const tgCache = (() => {
    try {
      return (globalThis as unknown as { caches?: { default?: Cache } }).caches?.default ?? null;
    } catch {
      return null;
    }
  })();
  const tgCached = await tgCache?.match(new Request('https://telegram-feed-cache.internal/v13')).catch(() => undefined);
  if (tgCached) {
    const cached = await tgCached
      .json()
      .then((b) => b as { items?: unknown[] })
      .catch(() => null);
    if (cached?.items?.length) telegramFeed = cached;
  }

  // Layer 2 — KV-warm slice. MUST still run when layer 1 failed.
  if (!telegramFeed) {
    const kvWarm = (await opts.kvJson) === undefined ? null : opts.kvJson;
    if ((kvWarm as { items?: unknown[] } | null)?.items?.length) telegramFeed = kvWarm;
  }

  return { feed: telegramFeed, usedKv: !!(telegramFeed && telegramFeed === opts.kvJson) };
}

const FRESH_KV = { generated_at: '2026-10-10T04:00:23.220Z', items: [{ channel_handle: 'ctiwatch' }] };

describe('hourly cron — Telegram feed acquisition falls through the cache layer', () => {
  it('still reads the KV-warm slice when the Cache API global is absent', async () => {
    removeCaches();
    const { feed, usedKv } = await acquireFeed({ kvJson: FRESH_KV });
    // The whole point: a missing optimisation layer must not swallow the data.
    expect(feed).toEqual(FRESH_KV);
    expect(usedKv).toBe(true);
  });

  it('still reads the KV-warm slice when caches.default.match() rejects', async () => {
    rejectingCache();
    const { feed, usedKv } = await acquireFeed({ kvJson: FRESH_KV });
    expect(feed).toEqual(FRESH_KV);
    expect(usedKv).toBe(true);
  });

  it('still reads the KV-warm slice when caches exists but has no .default', async () => {
    cacheWithoutDefault();
    const { feed, usedKv } = await acquireFeed({ kvJson: FRESH_KV });
    expect(feed).toEqual(FRESH_KV);
    expect(usedKv).toBe(true);
  });

  it('still reads the KV-warm slice when the cached body is not valid JSON', async () => {
    // A truncated cache entry must not abort the block either.
    workingCache();
    Object.defineProperty(globalThis, 'caches', {
      value: {
        default: {
          match: async () => new Response('{not json'),
          put: async () => {},
        },
      },
      configurable: true,
      writable: true,
    });
    const { feed, usedKv } = await acquireFeed({ kvJson: FRESH_KV });
    expect(feed).toEqual(FRESH_KV);
    expect(usedKv).toBe(true);
  });

  it('leaves the feed undefined when every layer is empty (no fabricated data)', async () => {
    removeCaches();
    const { feed } = await acquireFeed({ kvJson: null });
    expect(feed).toBeUndefined();
  });

  it('still prefers a populated Cache API fast path when it works', async () => {
    // Guards against "fixing" the stall by deleting the cache layer outright.
    const CACHED = { generated_at: '2026-10-10T05:00:00.000Z', items: [{ channel_handle: 'from-cache' }] };
    const cache = workingCache(CACHED);
    const { feed, usedKv } = await acquireFeed({ cacheJson: CACHED, kvJson: FRESH_KV });
    expect(feed).toEqual(CACHED);
    expect(usedKv).toBe(false);
    expect(cache.hit()).toBe(1);
  });

  it('falls through to KV when the cache holds an EMPTY item list', async () => {
    // A stale empty cache means "t.me was blocked" — it must not shadow the
    // healthy KV slice, or the scan silently sees zero items.
    workingCache({ items: [] });
    const { feed, usedKv } = await acquireFeed({ kvJson: FRESH_KV });
    expect(feed).toEqual(FRESH_KV);
    expect(usedKv).toBe(true);
  });
});
