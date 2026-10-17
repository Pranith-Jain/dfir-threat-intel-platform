import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { safeErrorMessage } from '../lib/error';
import { badGateway, tooManyRequests, badRequest, forbidden } from '../lib/api-error';
import { FEED_ALLOWED_HOSTS as ALLOWED_HOSTS } from '../lib/feed-hosts';

const TIMEOUT_MS = 10_000;

export async function feedProxyHandler(c: Context<{ Bindings: Env }>) {
  const url = c.req.query('url');
  if (!url) return badRequest(c, 'missing url');

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (_catchErr) {
    logError('feedProxyHandler failed', _catchErr);
    return badRequest(c, 'invalid url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return badRequest(c, 'unsupported protocol');
  }
  // Allow-list to prevent SSRF / abuse
  if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
    return forbidden(c, `host not in allow-list: ${parsed.hostname}`);
  }

  // BleepingComputer 403s datacenter egress (Cloudflare bot challenge).
  // Fetch its Bing News mirror instead; www.bing.com is allowlisted. Was a
  // Google News mirror until news.google.com began 503ing Worker egress
  // (2026-10); Bing serves the same site-scoped results keylessly.
  // Mirrors the same alias in feeds-aggregate.ts fetchOne.
  const BLEEPING_COMPUTER_HOST_RE = /^(?:www\.)?bleepingcomputer\.com$/i;
  if (BLEEPING_COMPUTER_HOST_RE.test(parsed.hostname)) {
    parsed = new URL('https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US');
    if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
      return forbidden(c, `mirror host not in allow-list: ${parsed.hostname}`);
    }
  }

  // Cache-API first (free, no KV quota). Keyed on the full URL so repeated
  // requests for the same feed skip the upstream fetch entirely.
  const CACHE_TTL = 300; // 5min
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(`https://feed-proxy-cache.internal/v1?u=${encodeURIComponent(url)}`);
  const cached = await cache.match(cacheReq);
  if (cached) {
    // SWR: serve immediately, refresh in background if older than 80%.
    const cacheDate = cached.headers.get('date');
    const age = cacheDate ? (Date.now() - new Date(cacheDate).getTime()) / 1000 : 0;
    if (age > CACHE_TTL * 0.8) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            // Re-fetch in background — same redirect/validation logic.
            // We don't re-run the full handler; just re-fetch the upstream
            // and update the cache. If it fails, the stale copy stays.
            const res = await fetch(parsed.toString(), {
              redirect: 'manual',
              headers: {
                'user-agent':
                  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-rss/1.0 Safari/537.36',
                accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
              },
              signal: AbortSignal.timeout(TIMEOUT_MS),
            });
            if (res.ok) {
              const body = await res.text();
              if (body.length <= 512 * 1024) {
                const upstreamCt = (res.headers.get('content-type') ?? '').toLowerCase();
                const safeCt = /(?:xml|rss|atom|json)/.test(upstreamCt)
                  ? (upstreamCt.split(';')[0]?.trim() ?? 'text/plain; charset=utf-8')
                  : 'text/plain; charset=utf-8';
                await cache.put(
                  cacheReq,
                  new Response(body, {
                    headers: {
                      'content-type': safeCt,
                      'x-content-type-options': 'nosniff',
                      'cache-control': `public, max-age=${CACHE_TTL}`,
                    },
                  })
                );
              }
            }
          } catch {
            /* non-fatal */
          }
        })()
      );
    }
    return new Response(cached.body, cached);
  }

  try {
    // Manual redirect handling: an allow-listed host with an open redirect
    // (Google News, Reddit, raw.githubusercontent, …) could otherwise bounce
    // `redirect: 'follow'` to an arbitrary internal/external target,
    // defeating the allow-list. Re-validate every hop's host.
    const reqHeaders = {
      // Many feed origins (Akamai/Cloudflare-fronted, Reddit, etc.) block
      // generic bot UAs. Use a browser-like UA to maximise compatibility.
      'user-agent':
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-rss/1.0 Safari/537.36',
      accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
      'accept-language': 'en-US,en;q=0.9',
    };
    let current = parsed;
    let upstream: Response | null = null;
    for (let hop = 0; hop < 5; hop += 1) {
      upstream = await fetch(current.toString(), {
        redirect: 'manual',
        headers: reqHeaders,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (upstream.status < 300 || upstream.status >= 400) break;
      const location = upstream.headers.get('location');
      if (!location) break;
      let next: URL;
      try {
        next = new URL(location, current);
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return badGateway(c, 'upstream redirect to malformed url');
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return forbidden(c, `upstream redirect to unsupported protocol: ${next.protocol}`);
      }
      if (!ALLOWED_HOSTS.has(next.hostname.toLowerCase())) {
        return forbidden(c, `upstream redirect to non-allow-listed host: ${next.hostname}`);
      }
      current = next;
      if (hop === 4) return badGateway(c, 'too many redirects');
    }
    if (!upstream) return badGateway(c, 'upstream fetch failed');
    if (upstream.status === 429) {
      const retryAfter = upstream.headers.get('retry-after') ?? '60';
      return tooManyRequests(c, 'upstream_rate_limited', { windowSeconds: parseInt(retryAfter, 10) || 60 });
    }
    if (!upstream.ok) {
      return badGateway(c, `upstream ${upstream.status}`);
    }
    const MAX_FEED_BYTES = 512 * 1024;
    const contentLength = Number(upstream.headers.get('content-length') ?? '0');
    if (contentLength > MAX_FEED_BYTES) {
      return badGateway(c, 'upstream response too large');
    }
    const body = await upstream.text();
    if (body.length > MAX_FEED_BYTES) {
      return badGateway(c, 'upstream response too large');
    }
    // Never echo the upstream content-type verbatim: this endpoint is
    // same-origin, and an allow-listed raw-content host (e.g.
    // raw.githubusercontent.com) returning text/html would render as an
    // attacker page on our origin. Only pass through XML/JSON feed types;
    // anything else is served as inert text/plain.
    const upstreamCt = (upstream.headers.get('content-type') ?? '').toLowerCase();
    const safeCt = /(?:xml|rss|atom|json)/.test(upstreamCt)
      ? (upstreamCt.split(';')[0]?.trim() ?? 'text/plain; charset=utf-8')
      : 'text/plain; charset=utf-8';
    const response = new Response(body, {
      status: 200,
      headers: {
        'content-type': safeCt,
        'x-content-type-options': 'nosniff',
        'cache-control': `public, max-age=${CACHE_TTL}`,
      },
    });
    // Write-through to the Cache-API so the next request for the same URL
    // is a cache hit (free, no KV).
    c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
    return response;
  } catch (err) {
    logError('handler failed', err);
    return badGateway(c, safeErrorMessage(c.env as unknown as Record<string, unknown>, err));
  }
}
