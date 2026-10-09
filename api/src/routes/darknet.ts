// ssrf-audit: accept-reason `?url=` must be a v2/v3 .onion address —
// extractOnionHostname()/isValidOnionAddress() enforce
// /^[a-z2-7]{16,56}\.onion$/i — and is then fetched only through a fixed
// TOR2WEB_GATEWAYS host. A caller cannot choose the fetch host, and anything
// that is not a bare .onion hostname is rejected before the fetch.
// Not SSRF-reachable.
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import {
  torStatus,
  torFetchOnion,
  torScrapeOnion,
  torSearchOnion,
  torExitNodes,
  torExitCheck,
  torExitDetails,
  onionLookup,
  btcAbuseCheck,
} from '../lib/darknet';

export async function torStatusHandler(c: Context<{ Bindings: Env }>) {
  const r = await torStatus();
  return c.json(r);
}

export async function torFetchOnionHandler(c: Context<{ Bindings: Env }>) {
  const url = c.req.query('url');
  if (!url) return badRequest(c, '?url= parameter is required');
  const gateway = parseInt(c.req.query('gateway') ?? '0', 10);
  const r = await torFetchOnion(url, isNaN(gateway) ? 0 : Math.min(Math.max(gateway, 0), 3));
  return c.json(r);
}

export async function torScrapeOnionHandler(c: Context<{ Bindings: Env }>) {
  const url = c.req.query('url');
  if (!url) return badRequest(c, '?url= parameter is required');
  const gateway = parseInt(c.req.query('gateway') ?? '0', 10);
  const r = await torScrapeOnion(url, isNaN(gateway) ? 0 : Math.min(Math.max(gateway, 0), 3));
  return c.json(r);
}

export async function torSearchOnionHandler(c: Context<{ Bindings: Env }>) {
  const q = c.req.query('q');
  if (!q) return badRequest(c, '?q= parameter is required');
  const limit = parseInt(c.req.query('limit') ?? '20', 10);
  const r = await torSearchOnion(q, isNaN(limit) ? 20 : Math.min(Math.max(limit, 1), 100));
  return c.json({ query: q, count: r.length, results: r });
}

export async function torExitNodesHandler(c: Context<{ Bindings: Env }>) {
  const limitStr = c.req.query('limit');
  const limit = limitStr ? parseInt(limitStr, 10) : undefined;
  try {
    const ips = await torExitNodes(isNaN(limit ?? 0) ? undefined : limit, c.env.KV_CACHE);
    return c.json({ count: ips.length, ips });
  } catch (err) {
    return c.json(
      {
        error: 'upstream_unavailable',
        message: `Tor exit list unavailable: ${err instanceof Error ? err.message : 'unknown'}`,
      },
      502
    );
  }
}

export async function torExitCheckHandler(c: Context<{ Bindings: Env }>) {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, '?ip= parameter is required');
  try {
    const r = await torExitCheck(ip, c.env.KV_CACHE);
    return c.json(r);
  } catch (err) {
    return c.json({
      isTorExit: false,
      ip,
      error: 'upstream_unavailable',
      message: `Tor exit list temporarily unavailable: ${err instanceof Error ? err.message : 'unknown'}`,
    });
  }
}

export async function torExitDetailsHandler(c: Context<{ Bindings: Env }>) {
  const limitStr = c.req.query('limit');
  const limit = limitStr ? parseInt(limitStr, 10) : undefined;
  const r = await torExitDetails(isNaN(limit ?? 0) ? undefined : limit);
  return c.json({ count: r.length, exits: r });
}

export async function onionLookupHandler(c: Context<{ Bindings: Env }>) {
  const address = c.req.query('address');
  if (!address) return badRequest(c, '?address= parameter is required');
  try {
    const r = await onionLookup(address);
    return c.json(r);
  } catch (err) {
    logError('onionLookupHandler failed', err);
    // CIRCL (the upstream onion-intel provider) is intermittently down / rate-
    // limited and returns non-2xx for some addresses. Degrade gracefully with a
    // 200 "unavailable" result so the Dark Web Recon page renders an empty card
    // instead of a hard "upstream error". The shape mirrors onionLookup's
    // not_found case so the frontend renders it unchanged.
    const hostname = address.trim().toLowerCase();
    return c.json({
      address: hostname,
      first_seen: null,
      last_seen: null,
      last_check: null,
      status: 'unavailable',
      tags: [],
      pgp: [],
      certificates: [],
      ports: [],
      title: null,
      bitcoin_addresses: [],
      note: `onion lookup temporarily unavailable: ${err instanceof Error ? err.message : 'upstream error'}`,
    });
  }
}

export async function btcAbuseCheckHandler(c: Context<{ Bindings: Env }>) {
  const address = c.req.query('address');
  if (!address) return badRequest(c, '?address= parameter is required');
  const r = await btcAbuseCheck(address, c.env.CHAINABUSE_API_KEY);
  return c.json(r);
}
