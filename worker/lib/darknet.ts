/**
 * Dark web intelligence tools — Tor .onion access, CIRCL AIL metadata,
 * ChainAbuse BTC abuse reports.
 *
 * Ported from badchars/darknet-mcp-server (MIT) and adapted for
 * Cloudflare Workers. Instead of a local Tor SOCKS5 daemon, .onion
 * fetching uses tor2web gateways (clearnet proxies to the Tor network).
 * For full Tor-native access, pair this with a sidecar Tor daemon.
 *
 * API sources (all clearnet):
 *   - Ahmia.fi       — .onion search (https://ahmia.fi)
 *   - Tor Project    — exit node lists (https://check.torproject.org)
 *   - CIRCL AIL      — .onion metadata (https://onion.ail-project.org)
 *   - ChainAbuse     — BTC abuse reports (https://api.chainabuse.com)
 */

// ─── Constants ────────────────────────────────────────────────────────────

const TOR2WEB_GATEWAYS = ['tor2web.io', 'onion.ws', 'onion.sh', 'tor2web.org'] as const;

const TOR_BULK_EXIT_URL = 'https://check.torproject.org/torbulkexitlist';
const TOR_EXIT_ADDRESSES_URL = 'https://check.torproject.org/exit-addresses';
const AHMIA_SEARCH_URL = 'https://ahmia.fi/search/';
const CIRCL_BASE = 'https://onion.ail-project.org';
const CHAINABUSE_API = 'https://api.chainabuse.com/v0/reports';

const UA = 'pranithjain-threatintel-mcp/1.0';

/**
 * Upper bound on any single `.text()` buffer from a tor2web gateway or Ahmia
 * search response. Onion pages via gateways are untrusted and unbounded — a
 * malicious/huge page could OOM the isolate (128 MB limit) before parsing.
 * 5 MB is well above any legitimate HTML search/scrape result.
 */
const MAX_FETCH_BYTES = 5_000_000;

/**
 * Read a response body as text with a hard byte ceiling. Guards against
 * unbounded `await res.text()` on tor2web/Ahmia responses. If Content-Length
 * exceeds the cap the response is rejected without buffering; otherwise the
 * stream is read with a running byte count and truncated at the cap.
 */
async function fetchTextBounded(res: Response, max = MAX_FETCH_BYTES): Promise<string> {
  const cl = Number(res.headers.get('content-length') ?? 0);
  if (cl && cl > max) {
    throw new Error(`response too large: Content-Length ${cl} > ${max}`);
  }
  const reader = res.body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder();
  let received = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > max) {
      const keep = value.subarray(0, max - (received - value.byteLength));
      out += decoder.decode(keep, { stream: false });
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      break;
    }
    out += decoder.decode(value, { stream: true });
  }
  out += decoder.decode();
  return out;
}

// ─── Tor: Types ───────────────────────────────────────────────────────────

export interface TorStatusResult {
  ok: boolean;
  method: 'tor2web';
  gateways: string[];
  note: string;
}

export interface ScrapedPage {
  url: string;
  title: string;
  links: Array<{ text: string; href: string }>;
  body_text: string;
  status_code: number;
  fetched_via: string;
}

export interface AhmiaResult {
  title: string;
  url: string;
  description: string;
}

export interface TorExitNode {
  fingerprint: string;
  published: string;
  lastStatus: string;
  exitAddress: string;
  exitAddressTimestamp: string;
}

export interface TorExitCheckResult {
  isTorExit: boolean;
  ip: string;
}

// ─── CIRCL: Types ─────────────────────────────────────────────────────────

export interface OnionLookupResult {
  address: string;
  first_seen: string | null;
  last_seen: string | null;
  last_check: string | null;
  status: string | null;
  tags: string[];
  pgp: string[];
  certificates: string[];
  ports: number[];
  title: string | null;
  bitcoin_addresses: string[];
}

// ─── ChainAbuse: Types ────────────────────────────────────────────────────

export interface ChainAbuseReport {
  id: string;
  address: string;
  chain: string;
  description: string;
  category: string;
  createdAt: string;
  scamType: string;
}

/**
 * Three-state abuse verdict.
 *
 * Modelled explicitly because `count: 0` is ambiguous: it means both "ChainAbuse
 * has no reports" (clean) and "we could not ask ChainAbuse" (unknown). Consumers
 * that only branch on `count` — most notably the `btc_abuse_check` MCP tool, where
 * the payload is read by a language model rather than a human — read the latter
 * as a clean wallet. `verdict` is required on every result so a caller cannot
 * accidentally infer "clean" from an empty report list.
 */
export type ChainAbuseVerdict = 'clean' | 'flagged' | 'unknown';

export interface ChainAbuseResult {
  address: string;
  reports: ChainAbuseReport[];
  count: number;
  /**
   * Authoritative result state. `unknown` whenever the lookup did not complete;
   * never treat `unknown` as an absence of abuse reports.
   */
  verdict: ChainAbuseVerdict;
  /** Set when the lookup could not run (no credentials / upstream down); UI shows this instead of erroring. */
  unavailable?: boolean;
  note?: string;
}

// ─── Tor ──────────────────────────────────────────────────────────────────

/**
 * Build the tor2web gateway URL for an onion address.
 *
 * SECURITY (#300): this was pure string concatenation — `https://${clean}.${gateway}/`
 * with no validation of `onionUrl`. Both current callers happened to validate
 * first via `extractOnionHostname()`, so there was no live exploit path, but the
 * safety lived in the CALLER rather than in the builder. Any future caller
 * (a new handler, a refactored flow) would have inherited an open URL-
 * concatenation sink by default, which is the wrong place for a guard to live.
 *
 * The `.onion` check now happens HERE, so a caller that forgets it still cannot
 * produce a URL pointing at an attacker-chosen host. The caller-side checks stay
 * as defence in depth and as the thing that produces a clean error message.
 *
 * Also normalises the input to a bare hostname first: a scheme, trailing slash,
 * path, port, or embedded credential is stripped or rejected rather than being
 * concatenated into the authority component, where it could change which host
 * the request actually reaches.
 *
 * Throws on a non-.onion input. Callers that want a null-returning check use
 * `extractOnionHostname`.
 */
export function tor2webUrl(onionUrl: string, gateway: string): string {
  const host = extractOnionHostname(onionUrl);
  if (!host) throw new Error(`Invalid .onion address: ${onionUrl}`);
  // The gateway is an internal constant in every call site, but it lands in the
  // authority component too, so it gets the same treatment.
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(gateway)) {
    throw new Error(`Invalid tor2web gateway: ${gateway}`);
  }
  return `https://${host}.${gateway.toLowerCase()}/`;
}

export function parseHtmlBasic(html: string): {
  title: string;
  links: Array<{ text: string; href: string }>;
  bodyText: string;
} {
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const title = titleMatch?.[1]?.trim() ?? '';

  const links: Array<{ text: string; href: string }> = [];
  const linkRe = /<a\s+[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) !== null) {
    const href = (m[1] ?? '').trim();
    const text = (m[2] ?? '').replace(/<[^>]+>/g, '').trim();
    if (href && !href.startsWith('javascript:')) {
      links.push({ text: text || href, href });
    }
  }

  const bodyText = html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z]+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 50_000);

  return { title, links, bodyText };
}

/**
 * Valid onion address: base32 (a-z2-7) of EXACTLY 16 (v2) or 56 (v3) characters.
 *
 * #300 deduped the two validators that disagreed: this one accepted only 16 or
 * 56, while `darkweb-osint.ts`'s inline `onionHost()` used `{16,56}` and so
 * accepted lengths like 20 or 40 that are not valid onion addresses. They now
 * share this implementation, so the two entry points cannot drift again.
 *
 * The length is exact rather than a range deliberately: a wrong-length address
 * would produce a tor2web URL that resolves to somebody else's gateway-hosted
 * subdomain, not to an error.
 */
export function isValidOnionAddress(address: string): boolean {
  const a = address.trim().toLowerCase();
  if (a.endsWith('.onion')) {
    const label = a.slice(0, -'.onion'.length);
    return (label.length === 16 || label.length === 56) && /^[a-z2-7]+$/.test(label);
  }
  return false;
}

export function extractOnionHostname(input: string): string | null {
  let clean = input.trim().toLowerCase();
  if (clean.startsWith('http://') || clean.startsWith('https://')) {
    try {
      clean = new URL(clean).hostname;
    } catch {
      return null;
    }
  }
  clean = clean.replace(/\/+$/, '');
  if (isValidOnionAddress(clean)) return clean;
  return null;
}

export async function torStatus(): Promise<TorStatusResult> {
  return {
    ok: true,
    method: 'tor2web',
    gateways: [...TOR2WEB_GATEWAYS],
    note: 'Using public tor2web gateways to access .onion sites. For true Tor anonymity, run a local Tor daemon (port 9050) and use socks5h://127.0.0.1:9050.',
  };
}

export async function torFetchOnion(
  onionUrl: string,
  gatewayIndex = 0
): Promise<{ html: string; statusCode: number; fetchedVia: string }> {
  const hostname = extractOnionHostname(onionUrl);
  if (!hostname) throw new Error(`Invalid .onion address: ${onionUrl}`);
  const gw = TOR2WEB_GATEWAYS[gatewayIndex] ?? TOR2WEB_GATEWAYS[0];
  const url = tor2webUrl(hostname, gw);
  const res = await fetchOnionPage(url);
  const html = await fetchTextBounded(res);
  return { html, statusCode: res.status, fetchedVia: `${hostname}.${gw}` };
}

/**
 * Fetch a tor2web page with BOUNDED redirects.
 *
 * SECURITY (#300): this used `redirect: 'follow'`, letting the platform follow
 * an unbounded number of hops with no re-validation. A tor2web gateway is a
 * third party we do not control — if one is compromised, buggy, or configured
 * with an open redirect, it can send us anywhere, and an unbounded chain is also
 * a subrequest/latency budget problem on a 12s timeout.
 *
 * `manual` + a hop cap: an allow-listed onion host cannot silently become an
 * arbitrary target. The cap is generous (tor2web legitimately redirects between
 * its own gateways) but finite.
 */
const ONION_MAX_REDIRECTS = 3;

async function fetchOnionPage(url: string): Promise<Response> {
  let current = url;
  for (let hop = 0; hop <= ONION_MAX_REDIRECTS; hop++) {
    const res = await fetch(current, {
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      redirect: 'manual',
      signal: AbortSignal.timeout(12_000),
    });
    if (res.status < 300 || res.status >= 400) return res;
    const location = res.headers.get('location');
    if (!location) return res;
    try {
      await res.body?.cancel();
    } catch {
      /* best-effort */
    }
    current = new URL(location, current).toString();
  }
  throw new Error('too many redirects from tor2web gateway');
}

export async function torScrapeOnion(onionUrl: string, gatewayIndex = 0): Promise<ScrapedPage> {
  const hostname = extractOnionHostname(onionUrl);
  if (!hostname) throw new Error(`Invalid .onion address: ${onionUrl}`);
  const gw = TOR2WEB_GATEWAYS[gatewayIndex] ?? TOR2WEB_GATEWAYS[0];
  const url = tor2webUrl(hostname, gw);
  const res = await fetchOnionPage(url);
  const html = await fetchTextBounded(res);
  const { title, links, bodyText } = parseHtmlBasic(html);
  return {
    url: hostname,
    title,
    links,
    body_text: bodyText,
    status_code: res.status,
    fetched_via: `${hostname}.${gw}`,
  };
}

async function fetchAhmiaCsrfToken(): Promise<{ name: string; value: string } | null> {
  try {
    const res = await fetch(AHMIA_SEARCH_URL, {
      headers: {
        'User-Agent': UA,
        Accept: 'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'en-US,en;q=0.5',
      },
    });
    if (!res.ok) return null;
    const html = await fetchTextBounded(res);
    const m =
      /<input[^>]*type\s*=\s*["']hidden["'][^>]*name\s*=\s*["']([^"']+)["'][^>]*value\s*=\s*["']([^"']+)["'][^>]*\/?>/i.exec(
        html
      );
    if (m) return { name: m[1]!, value: m[2]! };
    const m2 =
      /<input[^>]*type\s*=\s*["']hidden["'][^>]*value\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']([^"']+)["'][^>]*\/?>/i.exec(
        html
      );
    if (m2) return { name: m2[2]!, value: m2[1]! };
    return null;
  } catch {
    return null;
  }
}

export async function torSearchOnion(query: string, limit = 20): Promise<AhmiaResult[]> {
  const csrf = await fetchAhmiaCsrfToken();

  let searchUrl = `${AHMIA_SEARCH_URL}?q=${encodeURIComponent(query)}`;
  if (csrf) {
    searchUrl += `&${encodeURIComponent(csrf.name)}=${encodeURIComponent(csrf.value)}`;
  }

  const res = await fetch(searchUrl, {
    headers: {
      'User-Agent': UA,
      Accept: 'text/html,application/xhtml+xml,*/*',
      'Accept-Language': 'en-US,en;q=0.5',
    },
  });
  if (!res.ok) throw new Error(`Ahmia search failed: HTTP ${res.status}`);
  const html = await fetchTextBounded(res);

  const results: AhmiaResult[] = [];

  const liRe = /<li[^>]*class\s*=\s*["']result["'][^>]*>([\s\S]*?)<\/li>/gi;
  let liMatch: RegExpExecArray | null;
  while ((liMatch = liRe.exec(html)) !== null) {
    const li = liMatch[1] ?? '';
    const titleMatch = /<a[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/i.exec(li);
    const descMatch = /<p[^>]*>([\s\S]*?)<\/p>/i.exec(li);

    if (titleMatch) {
      let href = (titleMatch[1] ?? '').trim();
      const title = (titleMatch[2] ?? '').replace(/<[^>]+>/g, '').trim();
      const description = descMatch ? (descMatch[1] ?? '').replace(/<[^>]+>/g, '').trim() : '';

      if (href.includes('redirect_url=')) {
        try {
          const parsed = new URL(href, 'https://ahmia.fi');
          href = parsed.searchParams.get('redirect_url') ?? href;
        } catch {
          /* keep as-is */
        }
      }

      if (title && href) {
        results.push({ title, url: href, description });
      }
    }
  }

  return results.slice(0, limit);
}

const TOR_EXIT_CACHE_KEY = 'tor:exit:nodes';
const TOR_EXIT_CACHE_TTL_S = 3600;

// Per-colo Cache-API shadow (free) in front of the KV list. torExitNodes is
// the hot path for /darkweb-osint tor-exit checks AND MCP tool calls; the
// shadow collapses repeats to ~1 KV read per colo per window. The list only
// churns on refresh (1h KV TTL), so a 30min shadow is safely fresh.
const TOR_EXIT_SHADOW_TTL_S = 1800;
function torExitShadowReq(): Request {
  return new Request('https://tor-exit-cache.internal/v1/nodes');
}

export async function torExitNodes(
  limit?: number,
  kv?: KVNamespace,
  waitUntil?: (p: Promise<unknown>) => void
): Promise<string[]> {
  // L1: per-colo Cache API first — no KV quota cost.
  try {
    const hit = await (caches as unknown as { default: Cache }).default.match(torExitShadowReq());
    if (hit) {
      const shadowed = (await hit.json()) as string[];
      if (Array.isArray(shadowed) && shadowed.length > 0) {
        return limit ? shadowed.slice(0, limit) : shadowed;
      }
    }
  } catch {
    /* fall through to KV */
  }
  if (kv) {
    try {
      const cached = await kv.get(TOR_EXIT_CACHE_KEY, 'json');
      if (Array.isArray(cached) && cached.length > 0) {
        // Populate the shadow so the next read in this colo skips KV.
        try {
          await (caches as unknown as { default: Cache }).default.put(
            torExitShadowReq(),
            new Response(JSON.stringify(cached), {
              headers: { 'content-type': 'application/json', 'cache-control': `max-age=${TOR_EXIT_SHADOW_TTL_S}` },
            })
          );
        } catch {
          /* best-effort shadow */
        }
        return limit ? cached.slice(0, limit) : cached;
      }
    } catch {
      /* fall through to fetch */
    }
  }
  let text: string;
  try {
    const res = await fetch(TOR_BULK_EXIT_URL, {
      headers: { 'User-Agent': UA },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    text = await fetchTextBounded(res);
  } catch {
    const fallback = await fetch(
      'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/tor-exit.txt',
      { headers: { 'User-Agent': UA } }
    );
    if (!fallback.ok) throw new Error(`Tor exit list failed: both upstreams unreachable`);
    text = await fetchTextBounded(fallback);
  }
  const ips = [
    ...new Set(
      text
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith('#'))
    ),
  ];
  if (kv) {
    // Persist via waitUntil when the caller has an execution context;
    // otherwise best-effort (a lost write just refetches next call).
    const done = kv
      .put(TOR_EXIT_CACHE_KEY, JSON.stringify(ips), { expirationTtl: TOR_EXIT_CACHE_TTL_S })
      .then(() => {})
      .catch(() => {});
    if (waitUntil) waitUntil(done);
  }
  // Write-through the shadow so this colo's next check is free.
  try {
    await (caches as unknown as { default: Cache }).default.put(
      torExitShadowReq(),
      new Response(JSON.stringify(ips), {
        headers: { 'content-type': 'application/json', 'cache-control': `max-age=${TOR_EXIT_SHADOW_TTL_S}` },
      })
    );
  } catch {
    /* best-effort shadow */
  }
  return limit ? ips.slice(0, limit) : ips;
}

export async function torExitCheck(ip: string, kv?: KVNamespace): Promise<TorExitCheckResult> {
  const ipv4Ok = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  const ipv6Ok = /^[0-9a-fA-F:]+$/.test(ip);
  if (!ipv4Ok && !ipv6Ok) throw new Error(`Invalid IP address format: ${ip}`);
  const exitIps = await torExitNodes(undefined, kv);
  return { isTorExit: exitIps.includes(ip), ip };
}

export async function torExitDetails(limit?: number): Promise<TorExitNode[]> {
  const res = await fetch(TOR_EXIT_ADDRESSES_URL, {
    headers: { 'User-Agent': UA },
  });
  if (!res.ok) throw new Error(`Tor exit addresses failed: HTTP ${res.status}`);
  const text = await fetchTextBounded(res);
  const nodes: TorExitNode[] = [];

  let fingerprint = '';
  let published = '';
  let lastStatus = '';

  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('ExitNode ')) {
      fingerprint = trimmed.slice(9).trim();
      published = '';
      lastStatus = '';
    } else if (trimmed.startsWith('Published ')) {
      published = trimmed.slice(10).trim();
    } else if (trimmed.startsWith('LastStatus ')) {
      lastStatus = trimmed.slice(11).trim();
    } else if (trimmed.startsWith('ExitAddress ')) {
      const parts = trimmed.slice(12).trim().split(/\s+/);
      const exitIp = parts[0] ?? '';
      const exitTs = parts.slice(1).join(' ');
      if (fingerprint && exitIp) {
        nodes.push({ fingerprint, published, lastStatus, exitAddress: exitIp, exitAddressTimestamp: exitTs });
      }
    }
  }

  return limit ? nodes.slice(0, limit) : nodes;
}

// ─── CIRCL AIL Onion Lookup ───────────────────────────────────────────────

export async function onionLookup(address: string): Promise<OnionLookupResult> {
  const hostname = extractOnionHostname(address);
  if (!hostname) throw new Error(`Invalid .onion address: ${address}`);
  const res = await fetch(`${CIRCL_BASE}/api/v1/onion/${encodeURIComponent(hostname)}`, {
    headers: { Accept: 'application/json', 'User-Agent': UA },
  });
  if (res.status === 404) {
    return {
      address: hostname,
      first_seen: null,
      last_seen: null,
      last_check: null,
      status: 'not_found',
      tags: [],
      pgp: [],
      certificates: [],
      ports: [],
      title: null,
      bitcoin_addresses: [],
    };
  }
  if (!res.ok) throw new Error(`CIRCL Onion Lookup error: HTTP ${res.status}`);
  const raw = (await res.json()) as Record<string, unknown>;
  return {
    address: hostname,
    first_seen: (raw.first_seen as string) ?? null,
    last_seen: (raw.last_seen as string) ?? null,
    last_check: (raw.last_check as string) ?? null,
    status: (raw.status as string) ?? null,
    tags: Array.isArray(raw.tags) ? (raw.tags as string[]) : [],
    pgp: Array.isArray(raw.pgp) ? (raw.pgp as string[]) : [],
    certificates: Array.isArray(raw.certificates) ? (raw.certificates as string[]) : [],
    ports: Array.isArray(raw.ports) ? (raw.ports as number[]) : [],
    title: (raw.title as string) ?? null,
    bitcoin_addresses: Array.isArray(raw.bitcoin_addresses) ? (raw.bitcoin_addresses as string[]) : [],
  };
}

// ─── ChainAbuse BTC Abuse Check ───────────────────────────────────────────

// ChainAbuse's public API now requires credentials (HTTP 401 unauthenticated).
// Auth is HTTP Basic with the API key as both username and password. When no key
// is configured — or the upstream fails — we degrade gracefully (empty + note)
// rather than throwing, so the Dark Web Recon page never shows "upstream error".
export async function btcAbuseCheck(address: string, apiKey?: string): Promise<ChainAbuseResult> {
  if (!apiKey) {
    return {
      address,
      reports: [],
      count: 0,
      verdict: 'unknown',
      unavailable: true,
      note: 'BTC abuse lookup unavailable: ChainAbuse now requires an API key (set CHAINABUSE_API_KEY).',
    };
  }
  try {
    const params = new URLSearchParams({ address });
    const res = await fetch(`${CHAINABUSE_API}?${params}`, {
      headers: {
        Accept: 'application/json',
        'User-Agent': UA,
        Authorization: `Basic ${btoa(`${apiKey}:${apiKey}`)}`,
      },
    });
    if (res.status === 404) {
      // 404 from ChainAbuse means the address is not in their database —
      // a completed lookup with a genuinely empty result.
      return { address, reports: [], count: 0, verdict: 'clean' };
    }
    if (!res.ok) {
      return {
        address,
        reports: [],
        count: 0,
        verdict: 'unknown',
        unavailable: true,
        note: `BTC abuse lookup unavailable: ChainAbuse returned HTTP ${res.status}.`,
      };
    }
    const data = (await res.json()) as { reports?: ChainAbuseReport[]; count?: number };
    const reports = data.reports ?? [];
    const count = data.count ?? reports.length;
    return {
      address,
      reports,
      count,
      verdict: count > 0 ? 'flagged' : 'clean',
    };
  } catch (err) {
    return {
      address,
      reports: [],
      count: 0,
      verdict: 'unknown',
      unavailable: true,
      note: `BTC abuse lookup unavailable: ${err instanceof Error ? err.message : 'upstream error'}.`,
    };
  }
}
