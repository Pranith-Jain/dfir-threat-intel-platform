/**
 * Threat Monitor — Global Threat Actor Monitor replication (hero-itsme).
 *
 * Endpoints (all under /api/v1/threat-monitor/):
 *   GET  /threat-monitor/                — slim index + upstream/expanded stats
 *   GET  /threat-monitor/groups          — list APT groups (q, origin, upstream_only, limit)
 *   GET  /threat-monitor/groups/:slug    — single group body
 *   GET  /threat-monitor/techniques      — list techniques (q, tactic, kill_chain, limit)
 *   GET  /threat-monitor/sources         — list OSINT sources (q, category, upstream_only, limit)
 *   GET  /threat-monitor/proxy?url=      — RSS proxy (avoids CORS)
 *   GET  /threat-monitor/config          — legacy config (proxyUrl + counts)
 *   GET  /threat-monitor/stats           — cache + manifest stats
 *
 * Source: https://github.com/hero-itsme/Global-Threat-Actor-Monitor (MIT)
 * Data ships in public/data/threat-monitor/ via ASSETS.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound, badRequest, forbidden, badGateway } from '../lib/api-error';
import { pinnedFetchFollow, SsrfError } from '../lib/ssrf-guard';

async function loadMod() {
  return await import('../lib/threat-monitor-manifest');
}

export const threatMonitorRouter = new Hono<{ Bindings: Env }>();

/**
 * Hosts the proxy will fetch, derived from the shipped sources manifest rather
 * than a hand-maintained list: the proxy exists solely to fetch the OSINT feeds
 * in that file, so the manifest IS the allow-list. A hand-kept copy would drift
 * every time a feed was added or retired, and a drifted allow-list is either
 * needlessly blocking or — worse — silently widened.
 *
 * Keyed by hostname, lowercased. Rebuilt at most once per 30 min by the
 * manifest loader's own cache.
 */
async function allowedProxyHosts(env: Env): Promise<Set<string>> {
  const mod = await loadMod();
  const file = await mod.loadTamSources(env.ASSETS);
  const hosts = new Set<string>();
  for (const src of file.sources) {
    try {
      hosts.add(new URL(src.url).hostname.toLowerCase());
    } catch {
      // A malformed entry in the manifest can't be a valid target anyway.
    }
  }
  return hosts;
}

/**
 * Proxy RSS feed fetch (avoids CORS in browser).
 *
 * SECURITY (#298): this handler previously fetched an arbitrary `?url=` with no
 * validation and echoed the body back with `Access-Control-Allow-Origin: *`.
 * That is an unauthenticated SSRF primitive — the platform egress is not
 * loopback, so `?url=http://169.254.169.254/` reaches the cloud metadata
 * service, and the wildcard ACAO let any web page read the response cross-origin.
 *
 * Three independent layers, because any one of them alone has a known bypass:
 *   1. allow-list — the host must be one of the manifest's OSINT feeds,
 *   2. assertPublicHost per redirect hop, inside pinnedFetchFollow — defeats
 *      DNS rebinding and stops an allow-listed host 302-ing to an internal IP,
 *   3. no wildcard ACAO, so a hostile page cannot read a successful fetch.
 */
threatMonitorRouter.get('/threat-monitor/proxy', async (c) => {
  const url = c.req.query('url');
  if (!url) return badRequest(c, 'url required');

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return badRequest(c, 'invalid url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return badRequest(c, 'unsupported protocol');
  }
  if (parsed.username || parsed.password) return badRequest(c, 'credentials-in-url');

  let hosts: Set<string>;
  try {
    hosts = await allowedProxyHosts(c.env);
  } catch (e) {
    logError('threat-monitor proxy allow-list failed', e);
    // Fail closed: without the allow-list we cannot tell a feed from an
    // internal target, so refuse rather than serve an open proxy.
    return badGateway(c, 'feed allow-list unavailable');
  }
  if (hosts.size === 0) return badGateway(c, 'feed allow-list empty');
  if (!hosts.has(parsed.hostname.toLowerCase())) {
    return forbidden(c, `host not in allow-list: ${parsed.hostname}`);
  }

  try {
    const res = await pinnedFetchFollow(
      parsed.toString(),
      {
        headers: { 'User-Agent': 'GlobalThreatActorMonitor/1.0' },
        signal: AbortSignal.timeout(15000),
      },
      { maxRedirects: 3 }
    );
    // An allow-listed host can still answer 3xx to something else;
    // pinnedFetchFollow already re-validated each hop, so a 3xx that survives
    // that is a dead end rather than a bypass — report it as an upstream error
    // instead of echoing the redirect body.
    if (res.status >= 300 && res.status < 400) {
      return badGateway(c, `upstream redirect not followed (${res.status})`);
    }
    const body = await res.text();
    return new Response(body, {
      // An upstream 4xx/5xx becomes a 502: our allow-list accepted the host, so
      // the failure is upstream's, not the caller's request. Echoing the
      // upstream status would let a caller probe third-party feed health.
      status: res.ok ? 200 : 502,
      headers: {
        'Content-Type': res.headers.get('Content-Type') ?? 'application/xml',
        // Explicitly same-origin. The page fetches this endpoint from its own
        // origin, so no CORS header is needed — and a wildcard one would let any
        // site read proxied responses through a victim's browser.
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'public, max-age=300',
      },
    });
  } catch (e) {
    if (e instanceof SsrfError) {
      // 403 for a blocked hop (private/reserved target), 400 for malformed.
      return c.json({ error: 'blocked', message: e.detail }, e.status === 400 ? 400 : 403);
    }
    logError('threat-monitor proxy fetch failed', e);
    return badGateway(c, 'upstream fetch failed');
  }
});

// ─── Slim index ───────────────────────────────────────────────────────
threatMonitorRouter.get('/threat-monitor/', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadTamIndex(c.env.ASSETS);
    return c.json(idx);
  } catch (e) {
    logError('tam index failed', e);
    return internalError(c, `tam_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Groups ─────────────────────────────────────────────────────────
threatMonitorRouter.get('/threat-monitor/groups', async (c) => {
  try {
    const mod = await loadMod();
    const file = await mod.loadTamGroups(c.env.ASSETS);
    const q = c.req.query('q') ?? undefined;
    const origin = c.req.query('origin') ?? undefined;
    const upstreamOnly = c.req.query('upstream_only') === 'true';
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : 50;
    const filtered = mod.filterTamGroups(file.groups, { q, origin, upstreamOnly, limit });
    return c.json({
      total: file.totalGroups,
      upstream: file.upstreamGroups,
      expanded: file.expandedGroups,
      returned: filtered.length,
      groups: filtered,
    });
  } catch (e) {
    logError('tam groups failed', e);
    return internalError(c, `tam_groups_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatMonitorRouter.get('/threat-monitor/groups/:slug', async (c) => {
  try {
    const mod = await loadMod();
    const slug = c.req.param('slug');
    const body = await mod.getTamGroup(c.env.ASSETS, slug);
    if (!body) return notFound(c, `Group '${slug}' not found`);
    return c.json(body);
  } catch (e) {
    logError('tam group failed', e);
    return internalError(c, `tam_group_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Techniques ─────────────────────────────────────────────────────
threatMonitorRouter.get('/threat-monitor/techniques', async (c) => {
  try {
    const mod = await loadMod();
    const file = await mod.loadTamTechniques(c.env.ASSETS);
    const q = c.req.query('q') ?? undefined;
    const tactic = c.req.query('tactic') ?? undefined;
    const kill_chain = c.req.query('kill_chain') ?? undefined;
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : 50;
    const filtered = mod.filterTamTechniques(file.techniques, { q, tactic, kill_chain, limit });
    return c.json({
      total: file.totalTechniques,
      upstream: file.upstreamTechniques,
      expanded: file.expandedTechniques,
      returned: filtered.length,
      techniques: filtered,
      killChainStages: file.killChainStages,
    });
  } catch (e) {
    logError('tam techniques failed', e);
    return internalError(c, `tam_techniques_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Sources ────────────────────────────────────────────────────────
threatMonitorRouter.get('/threat-monitor/sources', async (c) => {
  try {
    const mod = await loadMod();
    const file = await mod.loadTamSources(c.env.ASSETS);
    const q = c.req.query('q') ?? undefined;
    const category = c.req.query('category') ?? undefined;
    const upstreamOnly = c.req.query('upstream_only') === 'true';
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) : 50;
    const filtered = mod.filterTamSources(file.sources, { q, category, upstreamOnly, limit });
    return c.json({
      total: file.totalSources,
      upstream: file.upstreamSources,
      expanded: file.expandedSources,
      categories: file.categories,
      returned: filtered.length,
      sources: filtered,
    });
  } catch (e) {
    logError('tam sources failed', e);
    return internalError(c, `tam_sources_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Stats ──────────────────────────────────────────────────────────
threatMonitorRouter.get('/threat-monitor/stats', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadTamIndex(c.env.ASSETS);
    return c.json({
      stats: idx.stats,
      upstream: idx.upstream,
      expanded: idx.expanded,
      source: idx.source,
      cache: mod.tamCacheStats(),
    });
  } catch (e) {
    logError('tam stats failed', e);
    return internalError(c, `tam_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// Config endpoint (legacy)
threatMonitorRouter.get('/threat-monitor/config', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadTamIndex(c.env.ASSETS).catch(() => null);
    return c.json({
      proxyUrl: '/api/v1/threat-monitor/proxy',
      aptGroups: idx?.expanded.groups ?? 40,
      upstreamGroups: idx?.upstream.groups ?? 40,
      techniques: idx?.expanded.techniques ?? 29,
      upstreamTechniques: idx?.upstream.techniques ?? 29,
      killChainStages: idx?.stats.killChainStages ?? 7,
      osintFeeds: idx?.expanded.sources ?? 30,
      upstreamFeeds: idx?.upstream.sources ?? 30,
    });
  } catch {
    return c.json({
      proxyUrl: '/api/v1/threat-monitor/proxy',
      aptGroups: 40,
      techniques: 29,
      killChainStages: 7,
      osintFeeds: 30,
    });
  }
});
