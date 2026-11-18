/**
 * Generic cross-colo "last-good" fallback for single-upstream endpoints.
 *
 * `caches.default` is per-colo and short-lived; KV is global and durable. When
 * a live upstream fetch fails, times out, or the per-request compute blows the
 * Worker CPU budget, every colo can still serve the last payload *any* colo
 * successfully produced — flagged `stale: true` — instead of a hard 5xx /
 * "Couldn't load this".
 *
 * Pairs with `shouldWriteLastGood` (api/src/lib/lastgood-debounce.ts): reads are
 * cheap and unconditional, but writes are debounced per-key through a free
 * per-colo marker so a single shared KV key isn't rewritten on every
 * cache-miss-success (KV is metered and capped at 1 write/sec/key).
 *
 * Several routes (mti, ransomware-recent, malicious-packages, …) grew their own
 * copy of this read/write pair; this is the shared implementation they should
 * converge on.
 */

import type { Env } from '../env';
import { shouldWriteLastGood } from './lastgood-debounce';

/** 48h default — long enough to ride out a multi-hour upstream outage. */
const DEFAULT_TTL_SECONDS = 48 * 60 * 60;
const KEY_PREFIX = 'lastgood:v1:';

/**
 * Per-colo Cache-API shadow of the KV last-good values. KV is global + durable
 * but metered (~1k reads/day on the free plan); `caches.default` is per-colo,
 * free, and survives across invocations. Shadowing collapses repeated reads of
 * the same key — the hourly cron precomputes (PIR alert scan) and the
 * request-path fallback bursts during an upstream outage — to ~1 KV read per
 * colo per TTL window. Coherency: `writeLastGood` write-throughs the shadow,
 * so a fresh value is never masked by a stale cached one AFTER RECOVERY IN
 * THE SAME COLO. Cross-colo: a recovering colo B refreshes KV immediately but
 * a still-failing colo A keeps serving its own shadow copy for up to
 * SHADOW_TTL_SECONDS — bounded staleness on data that is already flagged
 * `stale:true` fallback. Staleness is otherwise bounded by the TTL.
 */
const SHADOW_TTL_SECONDS = 6 * 60 * 60; // 6h — comfortably spans the hourly cron
function cacheApi(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch {
    return null;
  }
}
function shadowKey(key: string): string {
  return `https://lastgood-cache.internal/v1/${encodeURIComponent(key)}`;
}
async function writeShadow<T>(cache: Cache, key: string, value: T): Promise<void> {
  try {
    await cache.put(
      shadowKey(key),
      new Response(JSON.stringify(value), {
        headers: { 'content-type': 'application/json', 'cache-control': `max-age=${SHADOW_TTL_SECONDS}` },
      })
    );
  } catch {
    /* best-effort — a shadow miss just falls back to KV */
  }
}

/**
 * Read the global last-good payload for `key`, or null if none / KV absent /
 * read error. Never throws — a missing fallback degrades to the caller's own
 * empty-state handling.
 *
 * `keyPrefix` defaults to `'lastgood:v1:'` for the canonical keys used by the
 * PIR feed and briefing builder. Pass `''` to use the key as the full KV key
 * verbatim — for legacy lastgood slots whose names already encode their own
 * namespacing (e.g. `cybercrime/af-datamarkets-lastgood/v1`).
 */
export async function readLastGood<T>(
  env: Pick<Env, 'KV_CACHE'>,
  key: string,
  opts: { keyPrefix?: string } = {}
): Promise<T | null> {
  if (!env.KV_CACHE) return null;
  const cache = cacheApi();
  if (cache) {
    try {
      const hit = await cache.match(shadowKey(key));
      if (hit) return (await hit.json()) as T;
    } catch {
      /* fall through to KV */
    }
  }
  const fullKey = `${opts.keyPrefix ?? KEY_PREFIX}${key}`;
  try {
    const value = (await env.KV_CACHE.get(fullKey, 'json')) as T | null;
    // Populate the shadow so the next read (this colo) is a cache hit, not a KV
    // read. Only cache real values — a null means "no fallback yet", and caching
    // that would mask a value written by another colo for up to the TTL.
    if (cache && value !== null) await writeShadow(cache, key, value);
    return value;
  } catch {
    return null;
  }
}

/**
 * Persist `value` as the global last-good for `key`, debounced so a hot key is
 * only rewritten once per `debounceTtlSeconds` (defaults to the debounce
 * helper's own 6h). Safe to call from `waitUntil`; never throws.
 *
 * Pass `force: true` to skip the debounce entirely — for controlled callers
 * like a cron precompute that runs on a fixed cadence and should always refresh
 * the global copy (the debounce only exists to throttle request-path writes).
 *
 * Pass `skipIfUnchanged: true` for a cron warm that rebuilds the same payload
 * every hour: it adds one cheap read and skips the KV put when the stored text
 * is byte-identical. Writes are the scarce free-plan quota (1k/day vs 100k
 * reads), so this is the difference between a warm cycle that costs 24 writes
 * per key per day and one that costs a write only when the data actually
 * moved. The per-colo shadow is still refreshed.
 *
 * `keyPrefix` defaults to `'lastgood:v1:'`. Pass `''` to use the key verbatim
 * for legacy lastgood slots (see `readLastGood`).
 *
 * Returns true when a write was actually issued (debounce cold), false when it
 * was skipped or KV is unavailable — useful for logging/tests.
 */
export async function writeLastGood<T>(
  env: Pick<Env, 'KV_CACHE'>,
  key: string,
  value: T,
  opts: {
    ttlSeconds?: number;
    debounceTtlSeconds?: number;
    force?: boolean;
    skipIfUnchanged?: boolean;
    keyPrefix?: string;
  } = {}
): Promise<boolean> {
  if (!env.KV_CACHE) return false;
  const fullKey = `${opts.keyPrefix ?? KEY_PREFIX}${key}`;
  try {
    if (!opts.force && !(await shouldWriteLastGood(`lastgood:${key}`, opts.debounceTtlSeconds))) return false;
    const body = JSON.stringify(value);
    if (opts.skipIfUnchanged) {
      const previous = await env.KV_CACHE.get(fullKey).catch(() => null);
      if (previous === body) {
        const cache = cacheApi();
        if (cache) await writeShadow(cache, key, value);
        return false;
      }
    }
    await env.KV_CACHE.put(fullKey, body, {
      expirationTtl: opts.ttlSeconds ?? DEFAULT_TTL_SECONDS,
    });
    // Write-through the per-colo shadow so reads stay coherent with KV (a fresh
    // value isn't masked by a stale cached one after an upstream recovers).
    const cache = cacheApi();
    if (cache) await writeShadow(cache, key, value);
    return true;
  } catch {
    return false;
  }
}
