/**
 * Per-API-Key Rate Limiting Middleware
 *
 * Tracks API key usage in the per-colo Cache API and enforces per-key rate
 * limits. Complements the existing per-IP rate limiting by preventing
 * abuse from authenticated clients regardless of IP.
 *
 * Rate limit tiers:
 *   - Free (no key): 100 requests/day (existing per-IP limit)
 *   - Readonly key: 1,000 requests/day
 *   - Admin key: 10,000 requests/day
 *
 * Storage: per-colo Cache API (free, does NOT count against KV quota).
 *
 * ── Why Cache API, not D1 ──────────────────────────────────────────────────
 * This middleware used to read + write a D1 row (`api_key_usage`) on EVERY
 * authenticated request — 1 row-read + 1 row-write per API call. On the free
 * plan that is pure overhead against the 5M-row-read / 100k-row-write daily
 * ceilings, and the counters are ephemeral (they reset every minute / every
 * day anyway). The per-colo Cache API is free, sub-millisecond, and expires
 * entries automatically via `max-age` — no bucket-reset logic needed.
 *
 * Trade-off: rate limits are per-colo, not global. An attacker routing
 * requests through multiple CF colos gets a fresh bucket per colo. This is
 * the same trade-off the IP rate limiter (lib/ratelimit.ts) already made on
 * 2026-05-24 when it migrated off KV — the limit is abuse-protection, not a
 * payment gate, and the per-key daily quota is a soft operational guardrail.
 * Cross-colo consistency would require a Durable Object hop per request,
 * which is not worth it for this tier of protection.
 *
 * Usage:
 *   import { apiKeyRateLimit } from '../lib/api-key-ratelimit';
 *   app.use('/api/v1/*', apiKeyRateLimit);
 */

import type { Context, Next } from 'hono';
import type { Env } from '../env';
import type { AuthUser } from './auth';

// Rate limit tiers per API key role
const RATE_LIMITS: Record<string, { daily: number; perMinute: number }> = {
  readonly: { daily: 1000, perMinute: 30 },
  admin: { daily: 10000, perMinute: 100 },
};

const DEFAULT_LIMIT = { daily: 100, perMinute: 10 };

const CACHE_BASE = 'https://api-key-rl.internal/v1';

function dailyKey(keyHash: string, date: string): Request {
  return new Request(`${CACHE_BASE}/d/${keyHash}/${date}`);
}

function minuteKey(keyHash: string, minute: number): Request {
  return new Request(`${CACHE_BASE}/m/${keyHash}/${minute}`);
}

function cacheApi(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch {
    return null;
  }
}

/**
 * Extract API key hash from request (for tracking without storing raw keys).
 */
async function extractKeyHash(c: Context<{ Bindings: Env }>): Promise<string | null> {
  const authz = c.req.header('authorization') ?? '';
  const bearer = /^Bearer\s+(.+)$/i.exec(authz)?.[1];
  const key = bearer ?? c.req.header('x-api-key') ?? null;
  if (!key) return null;

  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Read a counter from the Cache API. Returns 0 on miss/error. */
async function readCounter(cache: Cache, req: Request): Promise<number> {
  try {
    const hit = await cache.match(req);
    if (!hit) return 0;
    const text = await hit.text();
    const n = parseInt(text, 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

/**
 * Per-API-key rate limiting middleware.
 * Extracts API key, checks usage against tier limits, increments counter.
 */
export async function apiKeyRateLimit(c: Context<{ Bindings: Env }>, next: Next): Promise<Response | void> {
  // Only apply to API routes
  const url = new URL(c.req.url);
  if (!url.pathname.startsWith('/api/v1/')) return next();

  // Skip health checks and public endpoints
  if (url.pathname === '/api/v1/health' || url.pathname.startsWith('/api/v1/health/')) return next();

  const keyHash = await extractKeyHash(c);
  if (!keyHash) return next(); // No API key — fall through to IP-based limiting

  const cache = cacheApi();
  if (!cache) return next(); // Cache API unavailable — fall through

  // Read role from the auth middleware's context instead of a redundant query.
  const user = (c as unknown as { user?: AuthUser }).user;
  const role = user?.role ?? 'readonly';

  const limits = RATE_LIMITS[role] ?? DEFAULT_LIMIT;
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const currentMinute = Math.floor(now.getTime() / 60000);

  // Read both counters in parallel.
  const [dailyCount, minuteCount] = await Promise.all([
    readCounter(cache, dailyKey(keyHash, today)),
    readCounter(cache, minuteKey(keyHash, currentMinute)),
  ]);

  // Check daily limit
  if (dailyCount >= limits.daily) {
    return c.json(
      {
        error: 'rate_limited',
        message: `Daily API key limit exceeded (${limits.daily}/day)`,
        limit: limits.daily,
        window: 'daily',
        retry_hint: 'Limit resets at midnight UTC',
      },
      429,
      {
        'retry-after': String(Math.ceil((new Date().setUTCHours(24, 0, 0, 0) - Date.now()) / 1000)),
        'x-ratelimit-limit': String(limits.daily),
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String(Math.floor(new Date().setUTCHours(24, 0, 0, 0) / 1000)),
        'cache-control': 'no-store',
      }
    );
  }

  // Check per-minute limit
  if (minuteCount >= limits.perMinute) {
    return c.json(
      {
        error: 'rate_limited',
        message: `Per-minute API key limit exceeded (${limits.perMinute}/min)`,
        limit: limits.perMinute,
        window: 'minute',
      },
      429,
      {
        'retry-after': '60',
        'x-ratelimit-limit': String(limits.perMinute),
        'x-ratelimit-remaining': '0',
        'cache-control': 'no-store',
      }
    );
  }

  // Add rate limit headers to response
  await next();

  // Increment counters (fire-and-forget). The TTLs handle the resets:
  // daily entries expire at end-of-day, minute entries after ~2 minutes.
  const dailyRemainingSec = Math.max(1, Math.ceil((new Date().setUTCHours(24, 0, 0, 0) - Date.now()) / 1000));
  c.executionCtx.waitUntil(
    Promise.all([
      cache
        .put(
          dailyKey(keyHash, today),
          new Response(String(dailyCount + 1), {
            headers: { 'cache-control': `max-age=${dailyRemainingSec}` },
          })
        )
        .catch(() => undefined),
      cache
        .put(
          minuteKey(keyHash, currentMinute),
          new Response(String(minuteCount + 1), {
            headers: { 'cache-control': 'max-age=120' },
          })
        )
        .catch(() => undefined),
    ])
  );

  // Set rate limit headers
  c.res.headers.set('x-ratelimit-limit', String(limits.daily));
  c.res.headers.set('x-ratelimit-remaining', String(Math.max(0, limits.daily - dailyCount - 1)));
  c.res.headers.set('x-ratelimit-role', role);
}
