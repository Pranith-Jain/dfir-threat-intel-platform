/**
 * Global Pulse warm-slice store — D1 first, KV as the legacy fallback.
 *
 * The hourly queue consumer warms ~28 upstream feeds into `gp:warm:<key>` so
 * any colo can serve the Global Pulse map without re-running the whole fan-out
 * (which blows the free-plan 50-subrequest cap).
 *
 * Those slices used to be KV-only. KV's free tier is 1,000 WRITES/day — the
 * scarce quota, not reads — and the hourly warm cycle plus each route's own L2
 * write kept the account at ~99% of it (27,630 writes / 28 days, peaks
 * 1,450/day). Over-quota writes 429, so slices silently stop refreshing and
 * whole layers go dark. Warm slices are cached *data*, not the cross-colo
 * correctness state (bot offsets, idempotency markers, one-time secrets) that
 * CLAUDE.md says must stay on KV.
 *
 * D1 is the replacement: 100k rows written/day and 5M rows read/day on the
 * free plan. It also collapses the build's 28 sequential KV reads into ONE
 * indexed query, which matters as much as the write quota — those 28 reads
 * were most of the 44-subrequest budget `buildGlobalPulseSync` has to fit in.
 *
 * Storage layout: one row per feed, raw body verbatim (so the queue
 * consumer's write-on-change guard remains a byte comparison). Expiry is a
 * column, not a TTL — a stale row is simply a read miss.
 *
 * Failure policy: every D1 call is best-effort. A missing table (migration not
 * applied yet), a D1 outage, or a body over the row limit falls back to KV.
 * Reads try D1 first and only touch KV for keys D1 did not return, so a
 * cutover deploy cannot serve an empty map while the legacy keys age out.
 */
import type { D1Database, KVNamespace } from '@cloudflare/workers-types';
import { upstashConfigured, upstashGet, upstashMGet, upstashSet } from './upstash-cache';

export interface WarmSliceEnv {
  KV_CACHE?: KVNamespace;
  BRIEFINGS_DB?: D1Database;
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
}

/** Legacy KV key prefix. Kept for fallback reads + old tests. */
export const WARM_SLICE_KV_PREFIX = 'gp:warm:';

/** D1 rejects rows over ~1 MB; leave headroom for encoding. */
const MAX_D1_BODY_CHARS = 900_000;

/** `IN (?, ?, …)` bind limit is 100; chunk well below it. */
const READ_CHUNK = 50;

export function warmSliceKvKey(key: string): string {
  return `${WARM_SLICE_KV_PREFIX}${key}`;
}

/**
 * Raw body for one feed key, D1 first then the legacy KV key.
 * Never throws — a miss is `null`.
 */
export async function readWarmSliceRaw(env: WarmSliceEnv, key: string): Promise<string | null> {
  // External store is first when configured: it is the authoritative warm
  // cache, and D1/KV remain readable for a cutover window.
  if (upstashConfigured(env)) {
    const external = await upstashGet(env, key);
    if (external) return external;
  }
  if (env.BRIEFINGS_DB) {
    try {
      const row = await env.BRIEFINGS_DB.prepare('SELECT body FROM warm_slices WHERE key = ?1 AND expires_at > ?2')
        .bind(key, Date.now())
        .first<{ body: string }>();
      if (row && typeof row.body === 'string') return row.body;
    } catch {
      /* table missing / D1 unavailable — fall through to KV */
    }
  }
  try {
    return (await env.KV_CACHE?.get(warmSliceKvKey(key))) ?? null;
  } catch {
    return null;
  }
}

/** Parsed warm slice for one feed, or null when absent/expired/unparseable. */
export async function readWarmSlice<T>(env: WarmSliceEnv, key: string): Promise<T | null> {
  const raw = await readWarmSliceRaw(env, key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/**
 * Batched read for several feed keys.
 *
 * One D1 query per 50 keys instead of one subrequest per key. Missing keys are
 * backfilled from KV with a batched `get(keys[])` so the KV fallback also
 * stays within one subrequest per 100 keys.
 *
 * Returns a Map keyed by the *feed* key (`reddit`, not `gp:warm:reddit`).
 */
export async function readWarmSlices<T>(env: WarmSliceEnv, keys: readonly string[]): Promise<Map<string, T>> {
  const out = new Map<string, T>();
  if (keys.length === 0) return out;

  if (upstashConfigured(env)) {
    const external = await upstashMGet(env, keys);
    for (const [key, body] of external) {
      try {
        out.set(key, JSON.parse(body) as T);
      } catch {
        /* skip an unparseable row; lower-priority stores may still be good */
      }
    }
  }

  if (env.BRIEFINGS_DB) {
    const now = Date.now();
    for (let i = 0; i < keys.length; i += READ_CHUNK) {
      const chunk = keys.slice(i, i + READ_CHUNK);
      try {
        const placeholders = chunk.map((_, n) => `?${n + 1}`).join(', ');
        const { results } = await env.BRIEFINGS_DB.prepare(
          `SELECT key, body FROM warm_slices WHERE key IN (${placeholders}) AND expires_at > ?${chunk.length + 1}`
        )
          .bind(...chunk, now)
          .all<{ key: string; body: string }>();
        for (const row of results ?? []) {
          try {
            out.set(row.key, JSON.parse(row.body) as T);
          } catch {
            /* skip an unparseable row; its KV fallback may still be good */
          }
        }
      } catch {
        /* table missing / D1 unavailable — KV fallback below covers it */
      }
    }
  }

  const missing = keys.filter((k) => !out.has(k));
  if (missing.length > 0 && env.KV_CACHE) {
    for (let i = 0; i < missing.length; i += 100) {
      const chunk = missing.slice(i, i + 100);
      try {
        const kvMap = (await env.KV_CACHE.get(chunk.map(warmSliceKvKey), 'json')) as Map<string, unknown>;
        for (const [kvKey, value] of kvMap) {
          if (value == null) continue;
          out.set(kvKey.slice(WARM_SLICE_KV_PREFIX.length), value as T);
        }
      } catch {
        /* best-effort fallback */
      }
    }
  }

  return out;
}

/**
 * Persist one feed warm slice.
 *
 * D1 is the canonical store; KV is only touched when D1 is unavailable or the
 * body is too large for a D1 row. The caller is responsible for the
 * write-on-change guard (the body is compared byte-for-byte before this).
 */
export async function writeWarmSlice(env: WarmSliceEnv, key: string, body: string, ttlSeconds: number): Promise<void> {
  // When the external store is configured it owns the warm slice entirely.
  // Skipping D1/KV here is the point of the migration: it removes the CF KV
  // writes that were exceeding the free tier, without losing a read fallback.
  if (upstashConfigured(env) && (await upstashSet(env, key, body, ttlSeconds))) return;
  if (env.BRIEFINGS_DB && body.length <= MAX_D1_BODY_CHARS) {
    const now = Date.now();
    try {
      await env.BRIEFINGS_DB.prepare(
        `INSERT INTO warm_slices (key, body, updated_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET
           body = excluded.body,
           updated_at = excluded.updated_at,
           expires_at = excluded.expires_at`
      )
        .bind(key, body, now, now + ttlSeconds * 1000)
        .run();
      return;
    } catch {
      /* table missing / D1 write failed — fall through to KV */
    }
  }
  await env.KV_CACHE?.put(warmSliceKvKey(key), body, { expirationTtl: ttlSeconds });
}
