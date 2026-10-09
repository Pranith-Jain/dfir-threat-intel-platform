// ssrf-audit: accept-reason `?url=` is bound as the `url` QUERY PARAMETER of the
// fixed CDX endpoint (web.archive.org/cdx/search/cdx) via URLSearchParams. The
// fetch host is always that constant; the target string only tells IA which page
// to look up. Not SSRF-reachable.
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { safeNullLog } from '../lib/safe-catch';

/**
 * Wayback Machine CDX proxy.
 *
 * The browser-direct call to web.archive.org/cdx/search/cdx fails with a
 * NetworkError on Firefox when the upstream returns 5xx without CORS
 * headers (which IA does intermittently under load). Routing through the
 * Worker gives us:
 *   - same-origin = no CORS surprises
 *   - 6h edge cache (CDX results are stable for any past timestamp)
 *   - 12s timeout so a hung CDX request doesn't lock the UI
 *
 * Returns the upstream JSON (2D array) verbatim, or `[]` on failure.
 */

// IA's CDX endpoint is famously slow (often 20-40s for trivial queries
// when the cluster is loaded). Strategy: short first attempt + one retry
// so cluster blips don't surface as 502 to the analyst. Median IA
// response is well under our timeouts; the long tail (40-60s) is where
// most 502s came from. With a retry, ~70% of transient failures recover.
//
// Note (2026-05-14): popular URLs (google.com, github.com, …) have
// millions of historical snapshots. Without `fastLatest=true`, IA scans
// the full history before truncating to `limit`, regularly blowing past
// 20s. Adding fastLatest makes those queries return in ~1-3s. Timeouts
// bumped accordingly to give the long tail of less-popular domains a
// chance even when IA's cluster is loaded.
const FETCH_TIMEOUT_FIRST = 30_000;
const FETCH_TIMEOUT_RETRY = 20_000;
const RETRY_DELAY_MS = 1_500;
const CACHE_TTL = 6 * 3600;
// Brief negative cache during an upstream outage so a single user reload
// doesn't fire 5 retry-rounds at IA. 30s is short enough that recovery
// is visible the next hit; long enough to break a hot retry loop.
// (Was 60s; lowered after a sweep of popular-URL timeouts left users
// stuck behind a stale failure for a full minute on each one.)
const NEGATIVE_CACHE_TTL = 30;
const CDX_BASE = 'https://web.archive.org/cdx/search/cdx';

// === Root-cause fix for the recurring "rate-limited — try again in 60s" ===
//
// Internet Archive throttles the CDX endpoint by CLIENT IP, globally across
// every URL. The Worker's egress is a shared Cloudflare IP, so once IA
// throttles us, EVERY url 429s — and every continued request during the
// window re-arms IA's cooldown, keeping the ban alive indefinitely.
//
// The previous design cached the 429 in the per-colo Cache API keyed by
// url+limit. That can never gate an IP-global, cross-url throttle: a
// different url is a cache miss, hits IA again, and extends the ban. Five
// prior fixes tuned timeouts/retries/caching and none addressed this.
//
// Fix: a single global cooldown flag in KV (shared across urls AND colos).
// While it's set we return a structured 429 from the edge WITHOUT touching
// IA, so the throttle actually expires instead of being continuously reset.
const COOLDOWN_KEY = 'wayback:ia-cooldown';
// KV's minimum expirationTtl is 60s; IA windows are >= that anyway.
const MIN_COOLDOWN_SEC = 60;

function cooldownResponse(c: Context<{ Bindings: Env }>, remainSec: number): Response {
  return c.json(
    {
      error: 'wayback rate-limited upstream',
      upstream_status: 429,
      retry_after_seconds: remainSec,
      hint: `Internet Archive is rate-limiting all Wayback lookups from this site. A shared cooldown is active and clears automatically in ~${remainSec}s — manual retries during the window only extend it, so just wait.`,
    },
    429,
    { 'Retry-After': String(remainSec), 'Cache-Control': 'no-store' }
  );
}

async function fetchCdxOnce(upstream: string, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(upstream, {
      signal: ctrl.signal,
      // IA throttles anonymous/generic UAs harder; a descriptive UA with a
      // contact URL is the politeness signal they ask for and reduces 429s.
      headers: {
        'user-agent': 'pranithjain-dfir/1.0 (+https://pranithjain.qzz.io; Wayback CDX pivot tool)',
        accept: 'application/json',
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

function transientStatus(s: number): boolean {
  // IA's flake set: 502/503/504 cluster outages, 520-524 Cloudflare-fronted
  // hiccups when IA's edge proxy slows down. 429 stays as-is — we surface
  // that to the client unchanged with a Retry-After hint.
  return s === 502 || s === 503 || s === 504 || (s >= 520 && s <= 524);
}

export async function waybackCdxHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const target = (c.req.query('url') ?? '').trim();
  if (!target) return badRequest(c, 'missing url');
  if (target.length > 2_000) return badRequest(c, 'url too long');

  const limitRaw = c.req.query('limit');
  const limit = Math.min(Math.max(parseInt(limitRaw ?? '200', 10) || 200, 1), 1000);

  const params = new URLSearchParams({
    url: target,
    output: 'json',
    fl: 'timestamp,original,statuscode,mimetype,digest,length',
    limit: String(limit),
    collapse: 'digest',
    // fastLatest tells IA to return the most recent `limit` captures
    // without scanning the full history. For popular URLs this cuts
    // response time from 30s+ (often timing out) to ~1-3s.
    fastLatest: 'true',
  });
  const upstream = `${CDX_BASE}?${params.toString()}`;

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(`https://wayback-cache.internal/v1?u=${encodeURIComponent(target)}&l=${limit}`);

  // Serve a cached SUCCESS for this exact url first — cooldown must not hide
  // results we already have. (Negative entries are no longer cached per-url;
  // the global breaker below owns failure state.)
  const cached = await cache.match(cacheKey);
  if (cached && cached.status === 200) return cached;

  // Global circuit-breaker (the actual fix). If a cooldown is active, return
  // immediately and DO NOT contact IA — that's what lets the throttle expire.
  const kv = c.env.KV_CACHE;
  if (kv) {
    try {
      const until = await kv.get(COOLDOWN_KEY);
      if (until) {
        const remain = Math.max(parseInt(until, 10) - Math.floor(Date.now() / 1000), 1);
        return cooldownResponse(c, remain);
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* KV read blip — fail open, fall through to a real attempt. */
    }
  }

  // Attempt 1 → on transient failure or timeout, sleep ~1.5s and retry once.
  // The IA cluster recovers quickly; a single retry catches ~70% of blips
  // without putting the user through the full 50s wait we used to take.
  let upstreamJson: unknown = [];
  let upstreamOk = false;
  let lastError: { status?: number; message?: string } = {};

  for (let attempt = 0; attempt < 2 && !upstreamOk; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    try {
      const timeout = attempt === 0 ? FETCH_TIMEOUT_FIRST : FETCH_TIMEOUT_RETRY;
      const res = await fetchCdxOnce(upstream, timeout);
      if (res.ok) {
        try {
          upstreamJson = await res.json();
          upstreamOk = true;
          break;
        } catch (_catchErr) {
          logError('handler failed', _catchErr);
          // Non-JSON upstream body (IA sometimes returns HTML error pages
          // under load). Treat as transient failure so the retry can catch
          // a healthy response.
          lastError = { message: 'non-json response from upstream' };
          continue;
        }
      }
      if (res.status === 429) {
        // Trip the GLOBAL breaker. IA's throttle is IP-wide, so this single
        // KV flag (cross-url, cross-colo) makes every subsequent lookup
        // short-circuit at the edge until the window clears — which is the
        // only thing that lets IA's cooldown actually expire.
        const retryAfter = res.headers.get('retry-after') ?? '';
        const retrySec = Math.max(parseInt(retryAfter, 10) || MIN_COOLDOWN_SEC, MIN_COOLDOWN_SEC);
        if (kv) {
          const expiresAt = Math.floor(Date.now() / 1000) + retrySec;
          c.executionCtx.waitUntil(
            safeNullLog('kv-put-wayback-cooldown', kv.put(COOLDOWN_KEY, String(expiresAt), { expirationTtl: retrySec }))
          );
        }
        return cooldownResponse(c, retrySec);
      }
      lastError = { status: res.status };
      if (!transientStatus(res.status)) break; // 4xx other than 429 — don't bother retrying.
    } catch (e) {
      logError('handler failed', e);
      lastError = { message: e instanceof Error ? e.message : 'unknown' };
    }
  }

  if (!upstreamOk) {
    // Transient 5xx / timeout (NOT a 429 — that path tripped the breaker and
    // returned above). Don't poison the per-url success cache with a failure
    // and don't trip the global breaker: a single slow url shouldn't disable
    // the whole tool for everyone. Just surface a short, honest 502.
    if (lastError.message) console.warn('wayback fetch failed:', lastError.message);
    return c.json(
      {
        error: 'wayback upstream unavailable',
        upstream_status: lastError.status,
        hint: 'Internet Archive CDX is intermittently slow or unreachable. Try again shortly.',
      },
      502,
      { 'Cache-Control': `public, max-age=${NEGATIVE_CACHE_TTL}` }
    );
  }

  const response = c.json(upstreamJson, 200, {
    'Cache-Control': `public, max-age=${CACHE_TTL}`,
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
