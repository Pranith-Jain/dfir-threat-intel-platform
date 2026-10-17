import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { requireAdmin } from '../lib/admin-auth';
import { badRequest, badGateway, tooManyRequests } from '../lib/api-error';
import {
  fetchAuthedTimeline,
  resolveAuthCookies,
  checkXHealth,
  XAuthMissingError,
  XAuthInvalidError,
  XAuthRateLimitedError,
  type AuthedTimelineResponse,
} from '../lib/twitter-auth-graphql';
import { fetchUserTimeline } from '../lib/twitter-graphql';

const PROBE_BATCH_MAX = 80;
const PROBE_STAGGER_MS = 350;

/**
 * X (Twitter) firehose handler.
 *
 *   GET /api/v1/x-firehose?handle=briankrebs[&count=20][&since_days=7][&include_replies=0][&include_pinned=0]
 *   GET /api/v1/x-firehose?status
 *
 * Stale-fallback uses the Cloudflare Cache API (caches.default) instead
 * of KV — same effective behaviour for the analyst (an old payload is
 * returned on transient upstream failure) but zero against the KV
 * write quota. Cache API entries persist at the colo level long enough
 * to absorb day-scale outages without consuming durable storage.
 */

const HANDLE_RE = /^[A-Za-z0-9_]{1,15}$/;
const STALE_CACHE_TTL_SECONDS = 7 * 24 * 3600;

function staleCacheKey(handle: string): Request {
  return new Request(`https://x-firehose-stale.internal/v1?h=${handle.toLowerCase()}`);
}

export async function xFirehoseHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  // Status probe — let the FE check service availability without
  // attempting a fetch first.
  if (c.req.query('status') !== undefined) {
    // Deep probe: live canary fetch that classifies auth + query-ID health.
    // Opt-in (?status=deep) so the cheap config-only probe stays the default
    // for the XWatch mount check and adds no upstream rate-limit pressure.
    // It spends the operator's X credentials on a canary fetch (and its result
    // discloses credential health), so it is admin-only — the only consumer is
    // the admin XCookiesTab, which carries the admin session cookie.
    if (c.req.query('status') === 'deep') {
      const gate = requireAdmin(c);
      if ('error' in gate) return gate.error;
      const health = await checkXHealth(c.env);
      const ok = health.auth === 'ok' && health.qids !== 'stale';
      return c.json({ ok, configured: health.auth !== 'missing', ...health }, 200, { 'cache-control': 'no-store' });
    }
    try {
      await resolveAuthCookies(c.env);
      return c.json({ ok: true, configured: true });
    } catch (_catchErr) {
      logError('xFirehoseHandler failed', _catchErr);
      return c.json({ ok: false, configured: false, reason: 'service unavailable' }, 200);
    }
  }

  const handleRaw = (c.req.query('handle') ?? '').trim().replace(/^@/, '');
  if (!HANDLE_RE.test(handleRaw)) {
    return badRequest(c, 'invalid handle (1-15 chars, A-Za-z0-9_)');
  }

  const countRaw = Number(c.req.query('count') ?? '25');
  const count = Number.isFinite(countRaw) ? Math.max(5, Math.min(40, Math.floor(countRaw))) : 25;
  const sinceDaysRaw = Number(c.req.query('since_days') ?? '7');
  const sinceDays = Number.isFinite(sinceDaysRaw) ? Math.max(1, Math.min(90, Math.floor(sinceDaysRaw))) : 7;
  const includePinned = c.req.query('include_pinned') === '1';
  const includeReplies = c.req.query('include_replies') === '1';

  const edgeCache = (caches as unknown as { default: Cache }).default;
  const staleKey = staleCacheKey(handleRaw);

  try {
    const body = await fetchAuthedTimeline(c.env, handleRaw, {
      count,
      sinceDays,
      includePinned,
      includeReplies,
    });
    // Stale-fallback warm — write to the Cache API (free, no KV quota).
    // Gated to user-initiated VIEW calls (count >= 15); probe calls
    // (count=5) skip the warm to keep the write storm down.
    if (!body.cached && body.items.length > 0 && count >= 15) {
      const cacheable = new Response(JSON.stringify(body), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${STALE_CACHE_TTL_SECONDS}, s-maxage=${STALE_CACHE_TTL_SECONDS}`,
        },
      });
      c.executionCtx.waitUntil(edgeCache.put(staleKey, cacheable).catch(() => undefined));
    }
    return c.json(body, 200, { 'cache-control': 'public, max-age=600, s-maxage=1800' });
  } catch (err) {
    logError('handler failed', err);
    if (err instanceof XAuthRateLimitedError) {
      // Serve the stale Cache API entry, if any. Better an old payload
      // than a hard error during a transient rate-limit. (Anonymous would
      // hit the same per-IP limit, so no fallback here.)
      try {
        const stale = await edgeCache.match(staleKey);
        if (stale) {
          const parsed = (await stale.json()) as AuthedTimelineResponse;
          return c.json({ ...parsed, stale: true, upstream_error: 'rate-limited' }, 200, {
            'cache-control': 'public, max-age=300',
          });
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* fall through */
      }
      return tooManyRequests(c, 'rate-limited', { windowSeconds: 60 });
    }
    // Every other authed failure - missing cookies, expired cookies, stale
    // GraphQL query IDs (X rotates them; surfaces as HTTP 200 + errors field),
    // or a transient network/parse error - falls back to the anonymous
    // guest-token timeline (separate query IDs, curated "best of" set) so the
    // analyst still sees tweets instead of a hard "could not load" error.
    const msg = err instanceof Error ? err.message : String(err);
    const code =
      err instanceof XAuthMissingError
        ? 'auth_missing'
        : err instanceof XAuthInvalidError
          ? 'auth_expired'
          : /GraphQL error/i.test(msg)
            ? 'stale_qid'
            : 'upstream';
    try {
      const anon = await fetchUserTimeline(c.env, handleRaw, { count, sinceDays, includePinned });
      return c.json({ ...anon, degraded: true, fallback: 'anonymous', authed_error: code }, 200, {
        'cache-control': 'public, max-age=300, s-maxage=600',
      });
    } catch (anonErr) {
      logError('anonymous fallback failed', anonErr);
      return badGateway(c, 'upstream error');
    }
  }
}

interface ProbeResult {
  count: number;
  status: 'ok' | 'rate_limited' | 'error' | 'not_found';
}

/**
 * Batch probe — checks activity for many handles in one request,
 * staggering upstream calls to avoid tripping X's per-IP rate limit.
 *
 *   POST /api/v1/x-firehose/probe-batch
 *   Body: { handles: string[], since_days?: number }
 *   Response: { results: Record<string, ProbeResult>, elapsed_ms: number }
 */
export async function xFirehoseProbeBatchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  let body: { handles?: string[]; since_days?: number };
  try {
    body = (await c.req.json()) as typeof body;
  } catch {
    return badRequest(c, 'invalid JSON body');
  }

  const handles = (body.handles ?? []).filter((h) => HANDLE_RE.test(h)).slice(0, PROBE_BATCH_MAX);
  if (handles.length === 0) return badRequest(c, 'no valid handles');

  const sinceDays = Number.isFinite(body.since_days) ? Math.max(1, Math.min(90, Math.floor(body.since_days!))) : 7;
  const edgeCache = (caches as unknown as { default: Cache }).default;
  const results: Record<string, ProbeResult> = {};
  const start = Date.now();

  for (let i = 0; i < handles.length; i++) {
    const h = handles[i]!;
    if (i > 0) await new Promise((r) => setTimeout(r, PROBE_STAGGER_MS));

    const staleKey = staleCacheKey(h);
    try {
      const res = await fetchAuthedTimeline(c.env, h, {
        count: 5,
        sinceDays,
        includePinned: false,
        includeReplies: false,
      });
      results[h] = { count: res.items.length, status: 'ok' };
      if (res.items.length > 0) {
        const cacheable = new Response(JSON.stringify(res), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'cache-control': `public, max-age=${STALE_CACHE_TTL_SECONDS}`,
          },
        });
        c.executionCtx.waitUntil(edgeCache.put(staleKey, cacheable).catch(() => undefined));
      }
    } catch (err) {
      if (err instanceof XAuthRateLimitedError) {
        try {
          const stale = await edgeCache.match(staleKey);
          if (stale) {
            const parsed = (await stale.json()) as AuthedTimelineResponse;
            results[h] = { count: parsed.items?.length ?? 0, status: 'ok' };
            continue;
          }
        } catch {
          /* fall through */
        }
        results[h] = { count: 0, status: 'rate_limited' };
        for (let j = i + 1; j < handles.length; j++) {
          results[handles[j]!] = { count: 0, status: 'rate_limited' };
        }
        break;
      }
      if (err instanceof XAuthMissingError || err instanceof XAuthInvalidError) {
        for (let j = i; j < handles.length; j++) {
          results[handles[j]!] = { count: 0, status: 'error' };
        }
        break;
      }
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('no result') || msg.includes('could not resolve')) {
        results[h] = { count: 0, status: 'not_found' };
      } else {
        results[h] = { count: 0, status: 'error' };
      }
    }
  }

  return c.json({ results, elapsed_ms: Date.now() - start }, 200, {
    'cache-control': 'public, max-age=300, s-maxage=600',
  });
}
