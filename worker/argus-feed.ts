/**
 * ARGUS live-feed RSS proxy.
 *
 * The ARGUS Feed view aggregates a set of threat-intel RSS/Atom sources.
 * Fetching them directly from the browser fails on CORS for most publishers,
 * and public CORS proxies are unreliable — so the Worker fetches each
 * allowlisted feed server-side and returns the raw body with permissive CORS.
 * Parsing stays client-side (DOMParser). Results are edge-cached briefly so a
 * page of visitors doesn't hammer the upstream feeds.
 */

import { withSecurityHeaders } from './csp';
import type { Env } from './env';

const ALLOWED_RSS = new Set([
  'https://research.checkpoint.com/feed/',
  'https://blog.checkpoint.com/feed/',
  'https://www.crowdstrike.com/blog/feed/',
  'https://unit42.paloaltonetworks.com/feed/',
  'https://www.welivesecurity.com/feed/',
  'https://www.sentinelone.com/blog/feed/',
  'https://www.microsoft.com/en-us/security/blog/feed/',
  'https://securelist.com/feed/',
  // BleepingComputer 403s datacenter egress (Cloudflare bot challenge) —
  // serve its Bing News mirror instead (news.google.com 503s Worker egress).
  'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
  'https://www.darkreading.com/feeds/rss.xml',
  'https://krebsonsecurity.com/feed/',
  'https://feeds.feedburner.com/TheHackersNews',
  'https://therecord.media/feed',
  'https://www.securityweek.com/feed/',
  'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml',
]);

const CACHE_TTL = 300;

export async function handleArgusRss(request: Request, env: Env, url: URL): Promise<Response | null> {
  if (!url.pathname.startsWith('/api/v1/argus/rss')) return null;

  const argusError = (error: string, status: number): Response =>
    withSecurityHeaders(
      new Response(JSON.stringify({ error }), {
        status,
        headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
      }),
      undefined,
      url.origin
    );

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, OPTIONS',
        'access-control-allow-headers': 'Content-Type',
        'access-control-max-age': '86400',
      },
    });
  }

  const target = url.searchParams.get('url') ?? '';
  if (!ALLOWED_RSS.has(target)) {
    return argusError('feed url not allowlisted', 400);
  }

  const cacheKey = new Request(`https://argus-rss.internal/${encodeURIComponent(target)}`);
  const cached = await caches.default.match(cacheKey);
  if (cached) {
    const h = new Headers(cached.headers);
    h.set('access-control-allow-origin', '*');
    h.set('x-argus-feed', 'cache');
    // Security headers on success responses too (csp.ts invariant: always
    // override — third-party XML must not be served same-origin unguarded).
    return withSecurityHeaders(new Response(cached.body, { status: cached.status, headers: h }), undefined, url.origin);
  }

  try {
    // Manual redirect handling with per-hop revalidation. `redirect: 'follow'`
    // would let any allowlisted publisher that ever adds an open redirect turn
    // this into an SSRF pivot into arbitrary internal/hostile hosts. Mirrors
    // the loop in api/src/routes/feeds.ts.
    const maxHops = 5;
    let current = target;
    let upstream: Response | null = null;
    for (let hop = 0; hop < maxHops; hop += 1) {
      upstream = await fetch(current, {
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; ArgusFeedBot/1.0)' },
        redirect: 'manual',
      });
      if (upstream.status < 300 || upstream.status >= 400) break;
      const location = upstream.headers.get('location');
      if (!location) break;
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        return argusError('upstream redirect to malformed url', 502);
      }
      if (next.protocol !== 'https:') {
        return argusError('upstream redirect to unsupported protocol', 502);
      }
      if (!ALLOWED_RSS.has(next.toString())) {
        return argusError('upstream redirect to non-allow-listed feed', 502);
      }
      current = next.toString();
      if (hop === maxHops - 1) return argusError('too many redirects', 502);
    }
    if (!upstream) return argusError('upstream fetch failed', 502);
    if (!upstream.ok) {
      return argusError(`upstream ${upstream.status}`, 502);
    }
    const body = await upstream.text();
    const res = new Response(body, {
      status: 200,
      headers: {
        'content-type': 'text/xml; charset=utf-8',
        'access-control-allow-origin': '*',
        'cache-control': `public, max-age=${CACHE_TTL}`,
        'x-argus-feed': 'live',
      },
    });
    await caches.default.put(cacheKey, res.clone()).catch(() => {});
    return withSecurityHeaders(res, undefined, url.origin);
  } catch {
    return withSecurityHeaders(
      new Response(JSON.stringify({ error: 'upstream fetch failed' }), {
        status: 502,
        headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
      }),
      undefined,
      url.origin
    );
  }
}
