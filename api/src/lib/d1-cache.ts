import type { Env } from '../env';
import { kvBackedGet, kvBackedPut, routeCacheDelete } from './route-cache';
import { logError } from './logger';

/**
 * KV read-through cache for expensive D1 reads.
 *
 * ── Why ────────────────────────────────────────────────────────────────────
 * D1 bills by ROWS READ, not rows returned. A `COUNT(*)` over a 450k-row
 * table is billed as 450k row reads even though it yields a single number,
 * and on the Free plan the daily read ceiling is enforced as a HARD BLOCK:
 * once the account crosses it, D1 refuses every query account-wide until the
 * 00:00 UTC reset (error 7500), taking unrelated routes down with it. That
 * happened on 2026-10-05..07 and again on 2026-10-10 (see
 * `migrations/0052_breach_forum_deltas.sql` for the post-mortem).
 *
 * The fix is not "make the query cheaper" for genuinely O(n) aggregates —
 * some of them (severity rollups, GROUP BY distributions) must touch every
 * row no matter how they are written. The fix is to stop paying for them on
 * every request.
 *
 * ── Shape ──────────────────────────────────────────────────────────────────
 *   Read  : L1 caches.default → L2 KV → D1, then write-through to both.
 *   Write : D1, then `invalidateD1Cache` (or a shorter-TTL write).
 *
 * The L1 tier (`caches.default`) is per-colo and free; the L2 tier (KV) is
 * what makes the saving cross-colo. Both come from `route-cache.ts`, so this
 * is the SAME helper the ~30 upstream-HTTP caching routes already use —
 * it just also puts D1 behind it.
 *
 * ── When NOT to use it ─────────────────────────────────────────────────────
 *   * Queries that are already index-served and read a handful of rows. The
 *     cache would cost a KV read to save nothing.
 *   * Anything the caller must see writes through. Use a short TTL, or
 *     `invalidateD1Cache` from the write path.
 *   * Per-user / per-tenant data unless the key encodes the identity —
 *     see the assertion in `d1CacheKey` below.
 */

/** Namespaced so a D1 cache key can never collide with an upstream-HTTP
 *  cache key that happens to use a similar-looking name. */
const D1_CACHE_PREFIX = 'd1cache:v1:';

/**
 * Build a cache key, refusing anything that looks un-namespaced.
 *
 * A D1 result cached under a key that does not include every input that
 * shaped it is a cross-tenant data leak. Rather than trusting each call site
 * to remember that, the builder requires an explicit non-empty discriminator
 * (a table name, a filter signature, a tenant id) and makes the caller pass
 * it by name.
 */
export function d1CacheKey(scope: string, discriminator: string): string {
  if (!scope.trim()) throw new Error('d1CacheKey: scope is required');
  if (!discriminator.trim()) {
    throw new Error(
      `d1CacheKey: discriminator is required for scope "${scope}" — refusing to cache a key that could collide across inputs`
    );
  }
  return `${D1_CACHE_PREFIX}${scope}:${discriminator}`;
}

/**
 * Run `query`, serving a KV/L1-cached result when one is fresh.
 *
 * Fails OPEN in the sense that matters: any cache-layer error is swallowed
 * and the D1 query runs anyway, so a KV outage degrades to uncached reads
 * rather than to 500s. The D1 error itself propagates to the caller.
 *
 * @param ttlSeconds KV `expirationTtl` AND the L1 shadow TTL. Must be at
 *   least 60 (KV's minimum); values below are clamped up. Use the smallest
 *   TTL the caller can tolerate — this is the entire staleness budget.
 */
export async function d1Cached<T>(
  env: Pick<Env, 'KV_CACHE'>,
  key: string,
  ttlSeconds: number,
  query: () => Promise<T>,
  opts?: { waitUntil?: (p: Promise<unknown>) => void; force?: boolean }
): Promise<T> {
  const kv = env.KV_CACHE ?? null;
  const ttl = Math.max(60, Math.round(ttlSeconds));

  // No KV binding (api-only unit tests, minimal dev) — just run the query.
  if (!kv) return query();

  if (!opts?.force) {
    try {
      const { value } = await kvBackedGet<T>(kv, key, ttl);
      if (value !== null && value !== undefined) return value;
    } catch (e) {
      logError('d1Cached read failed', e);
    }
  }

  const fresh = await query();

  // Write-through. `kvBackedPut` fires the KV put through `waitUntil` when
  // one is supplied, so this costs the response nothing.
  try {
    await kvBackedPut(kv, key, fresh, ttl, opts?.waitUntil);
  } catch (e) {
    logError('d1Cached write failed', e);
  }

  return fresh;
}

/**
 * Drop a cached D1 result. Call from the write path of whatever produced it.
 *
 * Best-effort by design: a failed delete leaves a stale entry that expires on
 * its own TTL, which is strictly better than failing the user's write.
 *
 * Drops BOTH tiers via `routeCacheDelete` — the L1 shadow in this colo and
 * the cross-colo KV entry. Deleting only KV would leave the current colo
 * serving stale data until its shadow TTL lapses, which is the tier most
 * readers actually hit.
 */
export async function invalidateD1Cache(env: Pick<Env, 'KV_CACHE'>, key: string): Promise<void> {
  await routeCacheDelete(env.KV_CACHE ?? null, key);
}
