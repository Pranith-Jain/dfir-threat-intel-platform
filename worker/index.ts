import apiApp from '../api/src/index';
import { LiveFeedDO } from './durable-objects/live-feed';
import { CronLockDO } from './durable-objects/cron-lock';
import { CronJobDO } from './durable-objects/cron-job';
import { ReportBuilderDO } from './durable-objects/report-builder';
import { InvestigatorAgentDO } from './durable-objects/investigator-agent';
import { RadarCrawlerDO } from './durable-objects/radar-crawler';
import { GlobalPulseDO } from './durable-objects/global-pulse';
import { ThreatDataDO } from './durable-objects/threat-data';
import { generateNonce, injectScriptNonce, withSecurityHeaders } from './csp';
import { fetchPrerenderedOrShell } from './router';
import { surfaceForHostname } from './surface';
import { handleOgImage } from './og-route';
import { handleBlogImage } from './blog-image-route';
import { handleScheduled } from './scheduled';
import { handleQueue } from './queue-consumer';
import { logStartupValidation } from './bindings';
import { handleWebSocketUpgrade } from './ws-router';
import { isSocialCrawler } from './og-route';
import { handleMcp } from './mcp-handler';
import { DfirMcpServer } from './mcp-server';
import { handleRadarCrawl } from './radar-handler';
import { handleArgusRss } from './argus-feed';
import type { Env } from './env';

export {
  LiveFeedDO,
  DfirMcpServer,
  CronLockDO,
  ReportBuilderDO,
  InvestigatorAgentDO,
  RadarCrawlerDO,
  GlobalPulseDO,
  CronJobDO,
  ThreatDataDO,
};
export type { Env };

/**
 * Generate a request ID for distributed tracing.
 * 128-bit random → hex (32 chars). Included in response headers and
 * structured logs so operators can correlate frontend errors with
 * backend traces via `x-request-id`.
 */
function generateRequestId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Social-card crawlers (X/Twitter, LinkedIn, Facebook, Slack, Discord,
    // Telegram) fetch share URLs over plain http when the link was shared
    // without a scheme (X stores bare domains as http://). X's card crawler
    // does NOT follow redirects, so an http→https 301 at the edge makes it
    // give up and cache "no card" — while LinkedIn (which follows redirects)
    // still renders the card. Serve known crawlers a 200 over http and
    // redirect everyone else to https.
    if (url.protocol === 'http:' && !isSocialCrawler(request)) {
      return Response.redirect(`https://${url.host}${url.pathname}${url.search}`, 301);
    }

    // Cold-start binding validation.
    logStartupValidation(env as unknown as Record<string, unknown>);

    // Honour an inbound x-request-id (operator curl) so a hand-driven
    // reproduction stays greppable through the entire request chain.
    const inboundRid = request.headers.get('x-request-id');
    const requestId = inboundRid && /^[a-zA-Z0-9_-]{8,128}$/.test(inboundRid) ? inboundRid : generateRequestId();

    // Pre-routing handlers with individual error boundaries so a crash
    // in one path (e.g. MCP, WebSocket, OG image) doesn't take down the
    // entire request. Each returns 500 with x-request-id on failure.
    try {
      // WebSocket upgrades — route to Durable Objects or API handler
      const wsRes = await handleWebSocketUpgrade(request, env, ctx, url, requestId);
      if (wsRes) return wsRes;
    } catch (err) {
      console.error('handleWebSocketUpgrade failed', err);
      return new Response('internal error', { status: 500, headers: { 'x-request-id': requestId } });
    }

    try {
      // MCP server — DFIR & Threat Intel tools for AI agents
      const mcpRes = await handleMcp(request, env, ctx, url);
      if (mcpRes) return mcpRes;
    } catch (err) {
      console.error('handleMcp failed', err);
      return new Response('internal error', { status: 500, headers: { 'x-request-id': requestId } });
    }

    // Dynamic OG card PNGs (public, before /api/v1/* key-gate).
    // Accepted shapes:
    //   /api/v1/og-image/…  — legacy (already-cached meta, MCP bridge)
    //   /og-image/v<ver>/…  — versioned form emitted by pageCardUrl() since
    //                         the per-deploy cache-bust; internally mapped to
    //                         the same handler by rewriting the prefix.
    //   /og/pages/<dot>.png — static-form URLs emitted by an intermediate
    //                         deploy; passed through unrewritten (see below).
    if (
      url.pathname.startsWith('/api/v1/og-image/') ||
      url.pathname.startsWith('/og-image/') ||
      (url.pathname.startsWith('/og/pages/') && url.pathname.endsWith('.png'))
    ) {
      try {
        let ogUrl = url;
        if (url.pathname.startsWith('/og-image/')) {
          ogUrl = new URL(url.pathname.replace(/^\/og-image\//, '/api/v1/og-image/') + url.search, url.origin);
        }
        // /og/pages/<dot>.png needs NO pathname rewrite: matchOgPagePath()'s
        // first branch parses this exact shape. Legacy URL shape emitted by an
        // intermediate deploy; X caches failed image fetches per URL for days,
        // so this route must resolve instead of 404ing into ASSETS.
        const ogRes = await handleOgImage(request, env, ogUrl, ctx);
        const h = new Headers(ogRes.headers);
        h.set('x-request-id', requestId);
        return withSecurityHeaders(
          new Response(ogRes.body, { status: ogRes.status, statusText: ogRes.statusText, headers: h }),
          undefined,
          url.origin
        );
      } catch (err) {
        console.error('handleOgImage failed', err);
        return new Response('internal error', { status: 500, headers: { 'x-request-id': requestId } });
      }
    }

    // AI-generated blog illustrations (public, before /api/v1/* key-gate)
    if (url.pathname.startsWith('/api/v1/blog-image/')) {
      try {
        const imgRes = await handleBlogImage(request, url, env);
        return withSecurityHeaders(imgRes, undefined, url.origin);
      } catch (err) {
        console.error('handleBlogImage failed', err);
        return new Response('internal error', { status: 500, headers: { 'x-request-id': requestId } });
      }
    }

    // Radar deep-crawl DO routes (admin-key required)
    try {
      const radarRes = await handleRadarCrawl(request, env, url, requestId);
      if (radarRes) return radarRes;
    } catch (err) {
      console.error('handleRadarCrawl failed', err);
      return new Response('internal error', { status: 500, headers: { 'x-request-id': requestId } });
    }

    // .well-known/security.txt — serve with explicit Content-Type for scanners
    if (url.pathname === '/.well-known/security.txt') {
      try {
        const assetRes = await env.ASSETS.fetch(request);
        if (assetRes.ok) {
          const body = await assetRes.text();
          return new Response(body, {
            status: 200,
            headers: {
              'content-type': 'text/plain; charset=utf-8',
              'cache-control': 'public, max-age=86400',
              'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
            },
          });
        }
      } catch {
        // fall through
      }
    }

    // ARGUS live-feed RSS proxy (allowlisted, server-side fetch)
    try {
      const argusRssRes = await handleArgusRss(request, env, url);
      if (argusRssRes) return argusRssRes;
    } catch (err) {
      console.error('handleArgusRss failed', err);
      return new Response('internal error', { status: 500, headers: { 'x-request-id': requestId } });
    }

    // Forward /api/* and legacy /blog/rss.xml to the API app
    if (url.pathname.startsWith('/api/') || url.pathname === '/blog/rss.xml') {
      try {
        const apiRes = await apiApp.fetch(request, env as Env, ctx);
        const h = new Headers(apiRes.headers);
        h.set('x-request-id', requestId);
        return withSecurityHeaders(
          new Response(apiRes.body, {
            status: apiRes.status,
            statusText: apiRes.statusText,
            headers: h,
          }),
          undefined,
          url.origin
        );
      } catch (err) {
        console.error('apiApp.fetch failed', err);
        return new Response('internal error', { status: 500 });
      }
    }

    // NetDraw standalone page — serve static HTML with CSP nonce
    if (url.pathname === '/dfir/netdraw' || url.pathname === '/dfir/netdraw/') {
      const assetRes = await env.ASSETS.fetch(request);
      const ct = assetRes.headers.get('content-type') ?? '';
      if (ct.toLowerCase().includes('text/html') && assetRes.ok) {
        const nonce = generateNonce();
        const body = injectScriptNonce(await assetRes.text(), nonce);
        return withSecurityHeaders(
          new Response(body, { headers: { 'content-type': 'text/html;charset=UTF-8' } }),
          nonce,
          url.origin
        );
      }
      return withSecurityHeaders(assetRes, undefined, url.origin);
    }

    // Daily Briefs — serve from KV Cache if available (fresh data from Worker cron),
    // fall back to ASSETS (committed static files from the build pipeline).
    // NOTE: the ASSETS fallback must run even when KV_CACHE is unbound
    // (dev/miniflare) — gating the whole branch on the binding turned these
    // JSON files into the SPA shell (HTML) with no JSON anywhere.
    if (url.pathname.startsWith('/data/daily-briefs/')) {
      if (env.KV_CACHE) {
        try {
          let kvKey: string | undefined;
          if (url.pathname === '/data/daily-briefs/index.json') {
            kvKey = 'db:index';
          } else {
            const m = url.pathname.match(
              /^\/data\/daily-briefs\/(cyber|deepfake|disaster|maritime)\/(\d{4}-\d{2}-\d{2})\.json$/
            );
            if (m) kvKey = `db:body:${m[1]}:${m[2]}`;
          }
          if (kvKey) {
            // L1: per-colo Cache-API shadow. /data/daily-briefs/* is a public read
            // path hit on every page load of the daily-briefs UI; shadowing
            // collapses repeated reads to ~1 KV read per colo per window. The
            // index flips only on the daily cron; bodies are immutable per
            // (type,date), so a 10-min shadow is safe.
            const cache = (caches as unknown as { default: Cache }).default;
            const shadowReq = new Request(`https://db-data-cache.internal/v1/${encodeURIComponent(kvKey)}`);
            let kvData: { briefs?: unknown[] } | null = null;
            try {
              const hit = await cache.match(shadowReq);
              if (hit) kvData = (await hit.json()) as { briefs?: unknown[] } | null;
            } catch {
              /* fall through to KV */
            }
            if (kvData === null) {
              kvData = (await env.KV_CACHE.get(kvKey, 'json')) as { briefs?: unknown[] } | null;
              if (kvData) {
                try {
                  await cache.put(
                    shadowReq,
                    new Response(JSON.stringify(kvData), {
                      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=600' },
                    })
                  );
                } catch {
                  /* best-effort shadow */
                }
              }
            }
            // For the index, skip KV if it's empty (stale/cleared) so the
            // committed static manifest in ASSETS is used as fallback.
            const useKv =
              kvData && (kvKey !== 'db:index' || (Array.isArray(kvData.briefs) && kvData.briefs.length > 0));
            if (useKv) {
              const h = new Headers({
                'content-type': 'application/json',
                'x-source': 'kv-cache',
                'x-request-id': requestId,
              });
              return withSecurityHeaders(new Response(JSON.stringify(kvData), { headers: h }), undefined, url.origin);
            }
          }
        } catch {
          // KV miss or error — fall through to ASSETS
        }
      }
      // KV/shadow miss: serve the committed static file from ASSETS (the build
      // pipeline writes public/data/daily-briefs/ → dist/data/daily-briefs/).
      // Without this, /data/daily-briefs/*.json would fall through to the SPA
      // shell and return HTML instead of JSON.
      const dbAsset = await env.ASSETS.fetch(request);
      if (dbAsset.ok) {
        const h = new Headers(dbAsset.headers);
        h.set('x-source', 'assets');
        h.set('x-request-id', requestId);
        return withSecurityHeaders(
          new Response(dbAsset.body, { status: dbAsset.status, statusText: dbAsset.statusText, headers: h }),
          undefined,
          url.origin
        );
      }
    }

    // SPA shell fallback — serve prerendered HTML or the shell for client routing
    const nonce = generateNonce();
    // Which front door this Host is for; picks the prerendered tree below and
    // must agree with what the browser resolves from location.hostname.
    const surface = surfaceForHostname(url.hostname, env);
    let html: Response;
    try {
      html = await fetchPrerenderedOrShell(request, env, ctx, url, nonce, surface);
    } catch (err) {
      console.error('fetchPrerenderedOrShell failed', err);
      return new Response('internal error', { status: 500 });
    }
    const h = new Headers(html.headers);
    h.set('x-request-id', requestId);
    return withSecurityHeaders(
      new Response(html.body, {
        status: html.status,
        statusText: html.statusText,
        headers: h,
      }),
      nonce,
      url.origin
    );
  },

  scheduled: handleScheduled,

  queue: handleQueue,
};
