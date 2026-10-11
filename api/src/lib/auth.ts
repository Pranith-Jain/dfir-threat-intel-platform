/**
 * API key authentication middleware.
 *
 * Supports three tiers:
 *   - `optional` — attaches user identity if key present, continues otherwise
 *   - `required` — rejects with 401 if key missing or invalid
 *   - `'external-only'` — allows same-origin (frontend) requests through without
 *     a key; external callers must provide a valid API key via Authorization or X-API-Key
 *
 * Keys are stored in D1 (hashed with SHA-256).
 * The raw key is returned once on creation and never stored.
 *
 * Usage:
 *   import { authenticate } from '../lib/auth';
 *   app.get('/api/v1/admin/*', authenticate('required'), adminHandler);
 *   app.get('/api/v1/*', authenticate('external-only'), handler);
 */

import type { Context, MiddlewareHandler, Next } from 'hono';
import type { Env } from '../env';
import { unauthorized } from './api-error';
import { validateInternalToken, ALLOWED_INTERNAL_CALLERS } from './internal-token';
import { feedTokenUnlocks } from './feed-token';
import { getAllowedOrigins } from './site-config';
import { logError } from './logger';
import type { D1Database } from '@cloudflare/workers-types';

/**
 * Failed auth attempt tracker. Per-IP, in-memory, auto-expiring.
 * Provides progressive backoff for repeated invalid API key attempts.
 * Scope: per-Worker-isolate (resets on cold start), but combined with
 * the per-IP rate limiter this closes the "rotate keys to brute-force"
 * gap within a warm isolate's lifetime.
 */
const failedAuthAttempts = new Map<string, { count: number; firstAt: number }>();
const FAILED_AUTH_WINDOW_MS = 15 * 60_000; // 15-minute tracking window
const FAILED_AUTH_THRESHOLD = 10; // lockout after 10 failures

function trackFailedAuth(ip: string): boolean {
  const now = Date.now();
  const entry = failedAuthAttempts.get(ip);
  if (!entry || now - entry.firstAt > FAILED_AUTH_WINDOW_MS) {
    failedAuthAttempts.set(ip, { count: 1, firstAt: now });
    return false;
  }
  entry.count++;
  return entry.count >= FAILED_AUTH_THRESHOLD;
}

function clearFailedAuth(ip: string): void {
  failedAuthAttempts.delete(ip);
}

/**
 * OPEN_PUBLIC_READS emergency valve. When set, GET/HEAD reads bypass the
 * API-key requirement until a deterministic "open until" instant. The secret
 * value is parsed by `valveOpenUntilMs`:
 *   - an ISO-8601 timestamp or epoch-millis → keyless reads allowed only while
 *     `now < that instant`, enforced identically by every isolate (stateless);
 *   - anything else (including the legacy bare 'true'/'yes'/'on') → closed.
 *     The non-expiring mode was removed: a forgotten valve must never leave
 *     all reads open indefinitely.
 *
 * Returns the epoch-ms the valve is open until,
 * or null when the valve is unset/blank/malformed/expired (i.e. closed).
 */
export function valveOpenUntilMs(raw: string | undefined | null): number | null {
  const v = (raw ?? '').trim();
  if (v === '') return null;
  // Legacy bare words ('true'/'yes'/'on') are rejected — fail closed. Use an
  // explicit ISO-8601/epoch-ms expiry instead (even far-future), so every
  // open valve carries a deterministic close instant.
  if (/^(true|yes|on)$/i.test(v)) return null;
  if (/^\d{10,}$/.test(v)) {
    const ms = Number(v);
    return Number.isFinite(ms) && ms > Date.now() ? ms : null;
  }
  const t = Date.parse(v); // ISO-8601
  return Number.isNaN(t) || t <= Date.now() ? null : t;
}

/** Request paths that bypass API key auth — used for webhooks called by external services (Telegram, etc.). Handler-level auth (requireAdmin) still applies. */
const EXEMPT_PATHS = new Set([
  '/api/v1/telegram-leaks/bot-webhook',
  '/api/v1/telegram-leaks/register-webhook',
  '/api/v1/csp-report', // CSP violation reports — POST from browsers, no auth needed
  // RSS feeds — must be public so RSS readers (Feedly, Inoreader, etc.) can
  // subscribe. RSS clients cannot send same-origin headers or API keys.
  '/api/v1/briefings/rss',
  '/api/v1/feeds/abuse-rss',
  '/api/v1/threatsignal/rss',
  '/api/v1/threatsignal/rss.xml',
  '/api/v1/opensourcemalware/rss',
  '/api/v1/opensourcemalware/rss.xml',
  '/api/v1/rss/aggregate',
  '/api/v1/rss/sources',
  '/api/v1/feeds/mti-ransomware',
  '/api/v1/feeds/ransomware-merged',
  // Darknet Intel tools — read-only, same-origin frontend tools (no sensitive data)
  '/api/v1/darknet-intel/sources',
  '/api/v1/darknet-intel/greynoise/ip',
  '/api/v1/darknet-intel/greynoise/check',
  '/api/v1/darknet-intel/pulsedive/indicator',
  '/api/v1/darknet-intel/pulsedive/search',
  '/api/v1/darknet-intel/pulsedive/explore',
  '/api/v1/darknet-intel/vulners/id',
  '/api/v1/darknet-intel/otx/ip',
  '/api/v1/darknet-intel/otx/domain',
  '/api/v1/darknet-intel/otx/hash',
  '/api/v1/darknet-intel/otx/cve',
  '/api/v1/darknet-intel/ransomware/group',
  '/api/v1/darknet-intel/ransomware/victims',
  '/api/v1/darknet-intel/ransomware/search',
  '/api/v1/darknet-intel/ransomware/country',
  '/api/v1/darknet-intel/ransomware/sector',
  '/api/v1/darknet-intel/ransomware/ransomlook-groups',
  '/api/v1/darknet-intel/ransomware/ransomlook-recent',
  '/api/v1/darknet-intel/hibp/breach',
  '/api/v1/darknet-intel/hibp/latest',
  '/api/v1/darknet-intel/hibp/data-classes',
  '/api/v1/darknet-intel/hibp/password',
  '/api/v1/darknet-intel/abusech/threatfox-iocs',
  '/api/v1/darknet-intel/abusech/threatfox-search',
  '/api/v1/darknet-intel/abusech/threatfox-tag',
  '/api/v1/darknet-intel/abusech/threatfox-malware',
  '/api/v1/darknet-intel/abusech/urlhaus',
  '/api/v1/darknet-intel/abusech/urlhaus-tag',
  '/api/v1/darknet-intel/abusech/bazaar-hash',
  '/api/v1/darknet-intel/abusech/bazaar-recent',
  '/api/v1/darknet-intel/abusech/bazaar-tag',
  '/api/v1/darknet-intel/vulners/search',
  '/api/v1/darknet-intel/vulners/exploit',
  // Profile README stat cards — self-hosted replacement for the flaky
  // github-readme-stats / streak-stats services. GitHub's image proxy
  // fetches these without keys, so the endpoint must be public.
  '/api/v1/profile/gh-stats',
]);

export interface AuthUser {
  keyId: string;
  prefix: string;
  role: 'admin' | 'readonly';
}

async function hashKey(key: string): Promise<string> {
  const enc = new TextEncoder().encode(key);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  const hex = Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return hex;
}

/**
 * Extract a candidate key from `Authorization: Bearer <key>`, `X-API-Key`,
 * or HTTP Basic (`Authorization: Basic base64(user:pass)`).
 *
 * Basic exists for TAXII/enterprise clients (ThreatQ, Anomali, XSOAR custom
 * headers) that only speak username/password: put the API key in the
 * password field (preferred) or, when the client sends no password, in the
 * username field. The value is looked up exactly like a Bearer key downstream
 * (SHA-256 hash compare + failure tracking), so a wrong password costs an
 * attacker nothing more than a wrong Bearer token.
 */
function extractKey(c: Context<{ Bindings: Env }>): string | null {
  const authz = c.req.header('authorization') ?? '';
  const bearer = /^Bearer\s+(.+)$/i.exec(authz)?.[1];
  if (bearer) return bearer;
  const basic = /^Basic\s+(.+)$/i.exec(authz)?.[1];
  if (basic) {
    try {
      const decoded = atob(basic.trim());
      const idx = decoded.indexOf(':');
      const user = idx === -1 ? decoded : decoded.slice(0, idx);
      const pass = idx === -1 ? '' : decoded.slice(idx + 1);
      return pass || user || null;
    } catch {
      return null;
    }
  }
  return c.req.header('x-api-key') ?? null;
}

/**
 * Check if a request originates from our own front-end (same-origin).
 *
 * Signals, most-robust first:
 *  1. `Sec-Fetch-Site: same-origin`/`same-site` — a Fetch-Metadata header the
 *     browser sets on EVERY request and that page JS cannot forge (forbidden
 *     header name). Critically it is present on same-origin GET `fetch()`s, which
 *     omit `Origin` entirely (per the Fetch standard, `Origin` is only sent
 *     cross-origin or for non-safe methods) and whose `Referer` can be stripped
 *     by privacy settings — exactly the case the SOC dashboards' reads hit. Relying
 *     on Origin/Referer alone meant a stripped Referer → 403 → blank dashboards.
 *  2. `Origin` — present cross-origin / for non-safe methods; kept for completeness.
 *  3. `Referer` — best-effort fallback; parse the ORIGIN, never prefix-match (a
 *     prefix match let `https://pranithjain.qzz.io.evil.com/` satisfy the gate).
 *
 * This exemption is convenience, not a hard boundary — any non-browser client can
 * forge all three headers. Real protection for sensitive routes is the API-key /
 * admin gate, so honoring Sec-Fetch-Site does not weaken the posture.
 */
function isSameOrigin(c: Context<{ Bindings: Env }>): boolean {
  const allowed = new Set(getAllowedOrigins(c.env as { SITE_URL?: string; ALLOW_DEV_ORIGINS?: string }));

  const origin = c.req.header('origin') ?? '';
  // A present-but-foreign Origin means this is NOT our same-origin SPA — never
  // let a (curl-forgeable) Sec-Fetch-Site override an explicit cross-origin Origin.
  const originConflicts = origin !== '' && !allowed.has(origin);

  // `same-origin` only (not `same-site`) — the SPA is a single origin, so its
  // own reads always report exactly `same-origin`; browsers can't forge it.
  if (!originConflicts && c.req.header('sec-fetch-site') === 'same-origin') return true;

  if (origin && allowed.has(origin)) return true;

  const referer = c.req.header('referer') ?? '';
  if (referer) {
    try {
      if (allowed.has(new URL(referer).origin)) return true;
    } catch {
      /* malformed referer — fall through to deny */
    }
  }
  return false;
}

/**
 * Look up a hashed key in D1. Returns the key metadata or null.
 * The last_used_at update is fire-and-forget (see authenticate middleware).
 *
 * D1-read-cached via the per-colo Cache API (free, does NOT count against
 * the KV quota). On the free plan every D1 row-read counts against a 5M/day
 * hard block, and this lookup ran on EVERY authenticated request — the single
 * most-repeated query on the account. Caching the positive result for 300s
 * collapses same-colo repeat auth to one Cache-API match.
 *
 * Trade-off: key revocation is delayed by up to 300s in the colo that last
 * served the key. Acceptable for API-key auth — revocation is an operational
 * action, not an instant-response requirement, and the 5-minute window is
 * bounded by the TTL. The negative (not-found) result is deliberately NOT
 * cached: a fresh key must work immediately, and brute-force attempts should
 * still pay the D1 read so the failed-auth tracker counts them.
 */
const AUTH_CACHE_TTL_S = 300;

function authCacheApi(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch {
    return null;
  }
}

function authCacheKey(hashed: string): Request {
  return new Request(`https://auth-cache.internal/v1/${hashed}`);
}

async function lookupKey(db: D1Database, hashed: string): Promise<AuthUser | null> {
  // L1: per-colo Cache API — free, sub-millisecond, no D1 cost.
  const cache = authCacheApi();
  if (cache) {
    try {
      const hit = await cache.match(authCacheKey(hashed));
      if (hit) {
        const cached = (await hit.json()) as AuthUser | null;
        // A cached null means "this key was not found last time" — treat as
        // a miss so the D1 query still runs (fresh keys must work immediately).
        if (cached && typeof cached === 'object' && 'keyId' in cached) return cached;
      }
    } catch {
      /* fall through to D1 */
    }
  }

  const row = await db
    .prepare('SELECT id, prefix, role FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL')
    .bind(hashed)
    .first<{ id: string; prefix: string; role: string }>();
  if (!row) return null;
  const user: AuthUser = { keyId: row.id, prefix: row.prefix, role: row.role as 'admin' | 'readonly' };

  // Write-through to L1 so the next request in this colo is a cache hit.
  if (cache) {
    try {
      await cache.put(
        authCacheKey(hashed),
        new Response(JSON.stringify(user), {
          headers: { 'content-type': 'application/json', 'cache-control': `max-age=${AUTH_CACHE_TTL_S}` },
        })
      );
    } catch {
      /* best-effort — a cache-write failure just means the next read hits D1 */
    }
  }
  return user;
}

/**
 * Invalidate the cached auth entry for a hashed key. Called from the revoke
 * and admin-key mutation paths so a revoked key stops working within the same
 * colo immediately rather than waiting out the 300s TTL.
 *
 * Best-effort: a failed delete leaves the entry to expire on its own TTL,
 * which is bounded and acceptable — the cross-colo story is the same TTL.
 */
export async function invalidateAuthCache(hashed: string): Promise<void> {
  const cache = authCacheApi();
  if (!cache) return;
  try {
    await cache.delete(authCacheKey(hashed));
  } catch {
    /* best-effort */
  }
}

/**
 * Touch last_used_at for a key — fire-and-forget. Call via waitUntil
 * so it doesn't add latency to the request.
 * Sampled at 5%: per-request UPDATEs cost 1 D1 write per authenticated
 * API call for pure metadata. 5% keeps last_used_at fresh to ~20-request
 * granularity with 95% fewer writes.
 */
function touchLastUsed(db: D1Database, keyId: string): Promise<void> {
  if (Math.random() >= 0.05) return Promise.resolve();
  return db
    .prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?')
    .bind(new Date().toISOString(), keyId)
    .run()
    .then(() => {})
    .catch((err) => logError('touch-last-used', err));
}

/**
 * Validate a raw API key against D1 (canonical hash + revocation check).
 * Returns the key metadata if valid, else null. Exported for non-Hono callers
 * (e.g. the MCP session gateway in worker/index.ts) that must authenticate a key
 * before delegating, rather than only checking that a key string is present.
 */
export async function validateRawKey(db: D1Database, rawKey: string): Promise<AuthUser | null> {
  if (!rawKey) return null;
  return lookupKey(db, await hashKey(rawKey));
}

/**
 * Authentication middleware.
 *
 * @param mode 'optional' | 'required' | 'external-only'
 *   - `optional` — attaches user if key present, allows anonymous
 *   - `required` — rejects unauthenticated with 401
 *   - `'external-only'` — same-origin passthrough; external callers need a key
 */
export function authenticate(mode: boolean | 'external-only'): MiddlewareHandler<{ Bindings: Env }> {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    // Exempt specific paths from auth (webhooks called by external services).
    if (EXEMPT_PATHS.has(c.req.path)) {
      return next();
    }

    // Signed feed token. The older RSS feeds above solve this by being fully
    // public (EXEMPT_PATHS) because RSS clients can send no credential at
    // all; that makes them enumerable by anyone. A `?key=<hmac>` on a
    // registered feed path is the same "works in any reader" property with an
    // unguessable URL instead, and the HMAC is bound to this one path so the
    // token cannot be replayed against the JSON/CSV siblings. One SHA-256
    // verify, no I/O, and skipped entirely for non-feed paths.
    if (await feedTokenUnlocks(c)) {
      return next();
    }

    // Capability-token public reads (/api/v1/public/**): the unguessable
    // token in the path IS the credential (e.g. shared report links). Only
    // exact-shape tokens reach handlers; handlers 404 on unknown tokens.
    if (c.req.path.startsWith('/api/v1/public/')) {
      return next();
    }

    // Internal requests from our own Durable Objects via the SELF service
    // binding. DOs carry a signed internal token (HMAC-SHA256, short TTL)
    // that replaces the old spoofable X-Internal-Agent header.
    const internalToken = c.req.header('x-internal-token') ?? '';
    if (internalToken) {
      const result = await validateInternalToken(internalToken, c.env?.INTERNAL_TOKEN_SECRET);
      if (result.ok && ALLOWED_INTERNAL_CALLERS.has(result.caller)) {
        return next();
      }
      // Invalid or expired token — fall through to normal auth (reject).
    }

    // 'external-only': allow same-origin (frontend) without a key
    if (mode === 'external-only' && isSameOrigin(c)) {
      return next();
    }

    // CORS preflight carries no credentials and must always pass — the real
    // (keyed) request is gated separately.
    if (c.req.method === 'OPTIONS') {
      return next();
    }

    // External reads (GET/HEAD) are gated behind an API key. Mint one at /admin
    // and send it via `Authorization: Bearer <key>` or `X-API-Key`. The website
    // itself is exempt via the same-origin check above. Break-glass: set the
    // OPEN_PUBLIC_READS secret to an ISO/epoch-ms expiry to allow keyless
    // reads without a redeploy — see valveOpenUntilMs.
    if (mode === 'external-only' && (c.req.method === 'GET' || c.req.method === 'HEAD')) {
      const openUntil = valveOpenUntilMs(c.env.OPEN_PUBLIC_READS);
      if (openUntil !== null && Date.now() < openUntil) {
        return next();
      }
      // valve unset/expired → fall through to normal key auth below
    }

    const required = mode === true || mode === 'external-only';
    const raw = extractKey(c);
    if (!raw) {
      if (required) return unauthorized(c, 'api key required — provide via Authorization: Bearer or X-API-Key');
      return next();
    }

    const db = c.env.BRIEFINGS_DB;
    if (!db) {
      if (required) return unauthorized(c, 'auth backend unavailable');
      return next();
    }

    const hashed = await hashKey(raw);
    let user: AuthUser | null;
    try {
      user = await lookupKey(db, hashed);
    } catch {
      if (required) return unauthorized(c, 'auth backend unavailable');
      return next();
    }
    if (!user) {
      const ip = c.req.header('cf-connecting-ip') ?? 'anon';
      const locked = trackFailedAuth(ip);
      if (locked) {
        return c.json({ error: 'too_many_failed_attempts', message: 'try again later' }, 429, {
          'retry-after': String(Math.ceil(FAILED_AUTH_WINDOW_MS / 1000)),
        });
      }
      if (required) return unauthorized(c, 'invalid api key');
      return next();
    }

    // Successful auth — clear any failed attempt tracking for this IP.
    const ip = c.req.header('cf-connecting-ip') ?? 'anon';
    clearFailedAuth(ip);

    // Touch last_used_at — fire-and-forget so it doesn't add request latency.
    c.executionCtx.waitUntil(touchLastUsed(db, user.keyId));

    // Attach user context.
    (c as Context & { user: AuthUser }).user = user;
    await next();
  };
}

/**
 * Write-authorization guard for mutating routes.
 *
 * `authenticate('external-only')` accepts any *valid* API key — admin or
 * readonly — and lets same-origin (frontend) + internal-token callers through
 * with no attached user. That is correct for reads, but readonly keys must not
 * perform writes. This middleware closes that gap:
 *   - API-key callers carry `c.user`; a non-admin (readonly) key is rejected.
 *   - same-origin frontend and internal-token callers have no `c.user` (they
 *     were trusted by the upstream gate) and are allowed through.
 *
 * Mount it AFTER authenticate() on POST/PATCH/DELETE routes so the MCP write
 * tools (shiftlog, promptvault, …) and direct API calls alike honor roles.
 */
export function requireAdminRole(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    const user = (c as Context & { user?: AuthUser }).user;
    if (user && user.role !== 'admin') {
      return c.json({ error: 'forbidden', message: 'this operation requires an admin API key' }, 403);
    }
    return next();
  };
}

/**
 * Generates a new API key (random 40-char hex).
 * Returns the raw key (only time it's visible) and the metadata.
 */
export async function generateApiKey(
  db: D1Database,
  label: string,
  role: 'admin' | 'readonly'
): Promise<{
  rawKey: string;
  keyId: string;
  prefix: string;
}> {
  // Use cryptographically secure random — Math.random() is predictable.
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const raw = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const prefix = raw.slice(0, 8);
  const hashed = await hashKey(raw);
  const keyId = crypto.randomUUID();

  await db
    .prepare('INSERT INTO api_keys (id, key_hash, prefix, label, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(keyId, hashed, prefix, label, role, new Date().toISOString())
    .run();

  return { rawKey: raw, keyId, prefix };
}

/**
 * Revoke an API key by ID.
 */
export async function revokeApiKey(db: D1Database, keyId: string): Promise<boolean> {
  // Read the key_hash before the UPDATE so we can invalidate the auth cache.
  const row = await db
    .prepare('SELECT key_hash FROM api_keys WHERE id = ? AND revoked_at IS NULL')
    .bind(keyId)
    .first<{ key_hash: string }>();

  const result = await db
    .prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
    .bind(new Date().toISOString(), keyId)
    .run();

  // Invalidate the per-colo auth cache so the revoked key stops working
  // immediately in the colo that served it, instead of waiting out the TTL.
  if (row?.key_hash && (result.meta.changes ?? 0) > 0) {
    await invalidateAuthCache(row.key_hash);
  }

  return (result.meta.changes ?? 0) > 0;
}

/**
 * List all non-revoked API keys (prefix + label only, never the full key).
 */
export async function listApiKeys(
  db: D1Database
): Promise<
  Array<{ id: string; prefix: string; label: string; role: string; created_at: string; last_used_at: string | null }>
> {
  const { results } = await db
    .prepare(
      'SELECT id, prefix, label, role, created_at, last_used_at FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC'
    )
    .all<{
      id: string;
      prefix: string;
      label: string;
      role: string;
      created_at: string;
      last_used_at: string | null;
    }>();
  return results ?? [];
}
