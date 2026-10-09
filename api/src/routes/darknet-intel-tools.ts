// ssrf-audit: accept-reason `?url=` / `?host=` are sent as JSON BODY FIELDS to
// fixed upstream APIs (urlhaus-api.abuse.ch, pulsedive.com, vulners.com, …),
// encodeURIComponent'd or JSON-encoded. The fetch host is always that constant;
// the user's string is a value the vendor matches against, never a target.
// Not SSRF-reachable.
import { Hono } from 'hono';
import type { Context } from 'hono';
import type { Env } from '../env';
import { badRequest, badGateway, serviceUnavailable, notFound } from '../lib/api-error';

const UA = 'pranithjain-threatintel/1.0';

// ── Per-IP rate limiter (in-memory, per-isolate) ──────────────────────
// Prevents a single client from overwhelming upstream APIs. 30 req/min/IP
// is generous for normal use but blocks scripted bursts.
const RATE_LIMIT_MAX = 30;
const RATE_LIMIT_WINDOW_MS = 60_000;
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
let lastCleanup = Date.now();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  // Lazy cleanup every 5 minutes (runs inside request context, not global)
  if (now - lastCleanup > 300_000) {
    lastCleanup = now;
    for (const [key, entry] of rateLimitMap) {
      if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS * 2) rateLimitMap.delete(key);
    }
  }
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
}

function cacheApiTtl(path: string): number {
  if (
    path.includes('greynoise') ||
    path.includes('ransomlook-recent') ||
    path.includes('threatfox-iocs') ||
    path.includes('bazaar-recent') ||
    path.includes('hybrid/feed')
  )
    return 300;
  if (
    path.includes('abuseipdb/blacklist') ||
    path.includes('vulners/id') ||
    path.includes('hibp/breach') ||
    path.includes('hibp/latest') ||
    path.includes('hibp/data-classes') ||
    path.includes('bazaar/hash') ||
    path.includes('hybrid/search') ||
    path.includes('otx/cve') ||
    path.includes('ransomlook-groups')
  )
    return 1800;
  return 600;
}

async function l1CacheGet(c: Context<{ Bindings: Env }>): Promise<Record<string, unknown> | null> {
  const cached = await caches.default.match(new Request(c.req.url));
  if (cached) return cached.json() as Promise<Record<string, unknown>>;
  return null;
}

function l1CacheSet(c: Context<{ Bindings: Env }>, data: Record<string, unknown>, ttl: number): void {
  const response = new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, s-maxage=${ttl}` },
  });
  c.executionCtx.waitUntil(caches.default.put(new Request(c.req.url), response));
}

export const darknetIntelRouter = new Hono<{ Bindings: Env }>();

darknetIntelRouter.use('/darknet-intel/*', async (c, next) => {
  // Per-IP rate limit (skip for cached responses)
  const ip = c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'anon';
  if (!checkRateLimit(ip)) {
    return c.json(
      { error: 'rate_limited', message: `Max ${RATE_LIMIT_MAX} requests per minute. Try again shortly.` },
      429,
      {
        'Retry-After': '60',
      }
    );
  }
  if (c.req.method !== 'GET') return next();
  const cached = await l1CacheGet(c);
  if (cached) return c.json({ ...cached, cached: true });
  await next();
  if (c.res.status !== 200) return;
  const ct = c.res.headers.get('content-type');
  if (!ct?.includes('application/json')) return;
  const clone = c.res.clone();
  const body = (await clone.json()) as Record<string, unknown>;
  if (body.error) return;
  l1CacheSet(c, body, cacheApiTtl(c.req.path));
});

// ─── GreyNoise Community (free, no key) ───────────────────────────────

darknetIntelRouter.get('/darknet-intel/greynoise/ip', async (c) => {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, 'ip parameter required');
  const key = c.env.GREYNOISE_API_KEY;
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (key) headers['key'] = key;
    const res = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `GreyNoise upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ip, ...data, provider: 'greynoise', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'GreyNoise unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/greynoise/check', async (c) => {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, 'ip parameter required');
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const key = c.env.GREYNOISE_API_KEY;
    if (key) headers['key'] = key;
    const res = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `GreyNoise upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown> as Record<string, unknown>;
    return c.json({
      ip,
      classification: data.noise ? 'malicious' : data.riot ? 'benign' : 'unknown',
      noise: data.noise,
      riot: data.riot,
      provider: 'greynoise',
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'GreyNoise unreachable');
  }
});

// ─── Pulsedive (free, optional key) ───────────────────────────────────

darknetIntelRouter.get('/darknet-intel/pulsedive/indicator', async (c) => {
  const type = c.req.query('type');
  const value = c.req.query('value');
  if (!type || !value) return badRequest(c, 'type and value parameters required');
  try {
    let url = `https://pulsedive.com/api/v3.php?query=indicator&type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`;
    const key = c.env.PULSEDIVE_API_KEY;
    if (key) url += `&key=${encodeURIComponent(key)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return badGateway(c, `Pulsedive upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { type, value, ...data, provider: 'pulsedive', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Pulsedive unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/pulsedive/search', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'q parameter required');
  try {
    let url = `https://pulsedive.com/api/v3.php?query=search&value=${encodeURIComponent(q)}`;
    const key = c.env.PULSEDIVE_API_KEY;
    if (key) url += `&key=${encodeURIComponent(key)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return badGateway(c, `Pulsedive upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ query: q, ...data, provider: 'pulsedive', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Pulsedive unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/pulsedive/explore', async (c) => {
  const indicator = c.req.query('indicator');
  if (!indicator) return badRequest(c, 'indicator parameter required');
  try {
    let url = `https://pulsedive.com/api/v3.php?query=explore&value=${encodeURIComponent(indicator)}&filter_risk=all`;
    const key = c.env.PULSEDIVE_API_KEY;
    if (key) url += `&key=${encodeURIComponent(key)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return badGateway(c, `Pulsedive upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ indicator, ...data, provider: 'pulsedive', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Pulsedive unreachable');
  }
});

// ─── Vulners (free, optional key for search) ──────────────────────────

darknetIntelRouter.get('/darknet-intel/vulners/id', async (c) => {
  const id = c.req.query('id');
  if (!id) return badRequest(c, 'id parameter required (CVE, EDB, GHSA)');
  try {
    let url = `https://vulners.com/api/v3/search/id/?id=${encodeURIComponent(id)}`;
    const key = c.env.VULNERS_API_KEY;
    if (key) url += `&apiKey=${encodeURIComponent(key)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return badGateway(c, `Vulners upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { id, ...data, provider: 'vulners', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Vulners unreachable');
  }
});

darknetIntelRouter.post('/darknet-intel/vulners/search', async (c) => {
  const body = (await c.req.json<{ query?: string; limit?: number }>().catch(() => ({}))) as {
    query?: string;
    limit?: number;
  };
  const query = body.query;
  if (!query) return badRequest(c, 'query field required in JSON body');
  const limit = Math.min(body.limit ?? 20, 100);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const key = c.env.VULNERS_API_KEY;
    if (key) headers['API-KEY'] = key;
    const res = await fetch('https://vulners.com/api/v3/search/lucene/', {
      method: 'POST',
      headers,
      body: JSON.stringify({ query, fields: ['id', 'title', 'type', 'cvss', 'vhref', 'description'], limit }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `Vulners upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ query, limit, ...data, provider: 'vulners', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Vulners unreachable');
  }
});

darknetIntelRouter.post('/darknet-intel/vulners/exploit', async (c) => {
  const body = (await c.req.json<{ query?: string; limit?: number }>().catch(() => ({}))) as {
    query?: string;
    limit?: number;
  };
  const query = body.query;
  if (!query) return badRequest(c, 'query field required in JSON body');
  const limit = Math.min(body.limit ?? 20, 100);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const key = c.env.VULNERS_API_KEY;
    if (key) headers['API-KEY'] = key;
    const exploitQuery = `(${query}) AND type:exploit`;
    const res = await fetch('https://vulners.com/api/v3/search/lucene/', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        query: exploitQuery,
        fields: ['id', 'title', 'type', 'cvss', 'vhref', 'sourceData'],
        limit,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `Vulners upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ query, limit, ...data, provider: 'vulners', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Vulners unreachable');
  }
});

// ─── IntelligenceX (paid key required) ────────────────────────────────

darknetIntelRouter.get('/darknet-intel/intelx/search', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'q parameter required');
  const key = c.env.INTELX_API_KEY;
  if (!key) return serviceUnavailable(c, 'INTELX_API_KEY not configured (wrangler secret put INTELX_API_KEY)');
  try {
    const res = await fetch(
      `https://2.intelx.io/intelligent/search?term=${encodeURIComponent(q)}&key=${key}&maxresults=20&media=0`,
      {
        signal: AbortSignal.timeout(15000),
      }
    );
    if (!res.ok) return badGateway(c, `IntelligenceX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({
      query: q,
      search_id: data.id,
      ...data,
      provider: 'intelx',
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'IntelligenceX unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/intelx/results', async (c) => {
  const id = c.req.query('id');
  if (!id) return badRequest(c, 'id parameter required (search_id from intelx/search)');
  const key = c.env.INTELX_API_KEY;
  if (!key) return serviceUnavailable(c, 'INTELX_API_KEY not configured');
  try {
    const res = await fetch(`https://2.intelx.io/intelligent/search/result?id=${id}&key=${key}&limit=50`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `IntelligenceX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ search_id: id, ...data, provider: 'intelx', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'IntelligenceX unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/intelx/phonebook', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'q parameter required');
  const key = c.env.INTELX_API_KEY;
  if (!key) return serviceUnavailable(c, 'INTELX_API_KEY not configured');
  try {
    const res = await fetch(
      `https://2.intelx.io/phonebook/search?term=${encodeURIComponent(q)}&key=${key}&maxresults=20`,
      {
        signal: AbortSignal.timeout(15000),
      }
    );
    if (!res.ok) return badGateway(c, `IntelligenceX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({
      query: q,
      search_id: data.id,
      ...data,
      provider: 'intelx',
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'IntelligenceX unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/intelx/phonebook-results', async (c) => {
  const id = c.req.query('id');
  if (!id) return badRequest(c, 'id parameter required (search_id from intelx/phonebook)');
  const key = c.env.INTELX_API_KEY;
  if (!key) return serviceUnavailable(c, 'INTELX_API_KEY not configured');
  try {
    const res = await fetch(`https://2.intelx.io/phonebook/search/result?id=${id}&key=${key}&limit=50`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `IntelligenceX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ search_id: id, ...data, provider: 'intelx', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'IntelligenceX unreachable');
  }
});

// ─── AbuseIPDB (key required) ─────────────────────────────────────────

darknetIntelRouter.get('/darknet-intel/abuseipdb/check', async (c) => {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, 'ip parameter required');
  const key = c.env.ABUSEIPDB_API_KEY;
  if (!key) return serviceUnavailable(c, 'ABUSEIPDB_API_KEY not configured (wrangler secret put ABUSEIPDB_API_KEY)');
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: { Key: key, Accept: 'application/json' },
        signal: AbortSignal.timeout(10000),
      }
    );
    if (!res.ok) return badGateway(c, `AbuseIPDB upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ip, ...data, provider: 'abuseipdb', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'AbuseIPDB unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abuseipdb/reports', async (c) => {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, 'ip parameter required');
  const key = c.env.ABUSEIPDB_API_KEY;
  if (!key) return serviceUnavailable(c, 'ABUSEIPDB_API_KEY not configured');
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/reports?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&limit=100`,
      {
        headers: { Key: key, Accept: 'application/json' },
        signal: AbortSignal.timeout(10000),
      }
    );
    if (!res.ok) return badGateway(c, `AbuseIPDB upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ ip, ...data, provider: 'abuseipdb', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'AbuseIPDB unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abuseipdb/blacklist', async (c) => {
  const key = c.env.ABUSEIPDB_API_KEY;
  if (!key) return serviceUnavailable(c, 'ABUSEIPDB_API_KEY not configured');
  try {
    const confidence = c.req.query('confidence') ?? '90';
    const limit = c.req.query('limit') ?? '10000';
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=${confidence}&limit=${limit}`,
      {
        headers: { Key: key, Accept: 'application/json' },
        signal: AbortSignal.timeout(15000),
      }
    );
    if (!res.ok) return badGateway(c, `AbuseIPDB upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ...data, provider: 'abuseipdb', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'AbuseIPDB unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abuseipdb/check-block', async (c) => {
  const network = c.req.query('network');
  if (!network) return badRequest(c, 'network parameter required (CIDR, e.g. 118.208.0.0/16)');
  const key = c.env.ABUSEIPDB_API_KEY;
  if (!key) return serviceUnavailable(c, 'ABUSEIPDB_API_KEY not configured');
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check-block?network=${encodeURIComponent(network)}`, {
      headers: { Key: key, Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `AbuseIPDB upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ network, ...data, provider: 'abuseipdb', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'AbuseIPDB unreachable');
  }
});

// ─── Deep Ransomware Intelligence (free, no key) ─────────────────────

darknetIntelRouter.get('/darknet-intel/ransomware/group', async (c) => {
  const name = c.req.query('name');
  if (!name) return badRequest(c, 'name parameter required');
  try {
    const res = await fetch(`https://api.ransomware.live/v2/group/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ransomware.live upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = {
      group: name,
      ...data,
      provider: 'ransomware.live',
      generated_at: new Date().toISOString(),
      cached: false,
    };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomware.live unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/ransomware/victims', async (c) => {
  const name = c.req.query('name');
  if (!name) return badRequest(c, 'name parameter required (group name)');
  try {
    const res = await fetch(`https://api.ransomware.live/v2/group/${encodeURIComponent(name)}/victims`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ransomware.live upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ group: name, ...data, provider: 'ransomware.live', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomware.live unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/ransomware/search', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'q parameter required');
  try {
    const res = await fetch(`https://api.ransomware.live/v2/search/${encodeURIComponent(q)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ransomware.live upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ query: q, ...data, provider: 'ransomware.live', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomware.live unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/ransomware/country', async (c) => {
  const code = c.req.query('code');
  if (!code) return badRequest(c, 'code parameter required (ISO 3166-1 alpha-2)');
  try {
    const res = await fetch(`https://api.ransomware.live/v2/country/${encodeURIComponent(code)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ransomware.live upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = {
      country: code,
      ...data,
      provider: 'ransomware.live',
      generated_at: new Date().toISOString(),
      cached: false,
    };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomware.live unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/ransomware/sector', async (c) => {
  const sector = c.req.query('sector');
  if (!sector) return badRequest(c, 'sector parameter required (e.g. healthcare, finance)');
  try {
    const res = await fetch(`https://api.ransomware.live/v2/sector/${encodeURIComponent(sector)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ransomware.live upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = {
      sector,
      ...data,
      provider: 'ransomware.live',
      generated_at: new Date().toISOString(),
      cached: false,
    };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomware.live unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/ransomware/ransomlook-groups', async (c) => {
  try {
    const res = await fetch('https://www.ransomlook.io/api/groups', { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return badGateway(c, `ransomlook upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ...data, provider: 'ransomlook', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomlook unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/ransomware/ransomlook-recent', async (c) => {
  try {
    const res = await fetch('https://www.ransomlook.io/api/recent', { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return badGateway(c, `ransomlook upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ...data, provider: 'ransomlook', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ransomlook unreachable');
  }
});

// ─── Deep HIBP Breach Intelligence ────────────────────────────────────

darknetIntelRouter.get('/darknet-intel/hibp/breach', async (c) => {
  const name = c.req.query('name');
  if (!name) return badRequest(c, 'name parameter required (breach name)');
  try {
    const headers: Record<string, string> = { 'User-Agent': UA };
    const key = c.env.HIBP_API_KEY;
    if (key) headers['hibp-api-key'] = key;
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breach/${encodeURIComponent(name)}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (res.status === 404) return notFound(c, 'breach not found');
    if (!res.ok) return badGateway(c, `HIBP upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ...data, provider: 'hibp', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'HIBP unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/hibp/latest', async (c) => {
  try {
    const headers: Record<string, string> = { 'User-Agent': UA };
    const key = c.env.HIBP_API_KEY;
    if (key) headers['hibp-api-key'] = key;
    const res = await fetch('https://haveibeenpwned.com/api/v3/breaches', {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `HIBP upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = {
      breaches: data,
      count: Array.isArray(data) ? data.length : 0,
      provider: 'hibp',
      generated_at: new Date().toISOString(),
      cached: false,
    };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'HIBP unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/hibp/data-classes', async (c) => {
  try {
    const headers: Record<string, string> = { 'User-Agent': UA };
    const key = c.env.HIBP_API_KEY;
    if (key) headers['hibp-api-key'] = key;
    const res = await fetch('https://haveibeenpwned.com/api/v3/dataclasses', {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `HIBP upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = {
      data_classes: data,
      count: Array.isArray(data) ? data.length : 0,
      provider: 'hibp',
      generated_at: new Date().toISOString(),
      cached: false,
    };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'HIBP unreachable');
  }
});

// Shared HIBP pwned-password logic. The password arrives in a JSON BODY —
// never a URL query, which leaks plaintext into CF logs/analytics and any
// intermediary logging.
async function hibpPwnedPassword(c: Context<{ Bindings: Env }>, password: string | undefined) {
  if (!password) return badRequest(c, 'password required');
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);
    const res = await fetch(`https://haveibeenpwned.com/api/v3/pwnedpassword/${prefix}`, {
      headers: { 'User-Agent': UA },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok && res.status !== 404) return badGateway(c, `HIBP upstream ${res.status}`);
    const text = await res.text();
    const lines = text.split('\r\n');
    let count = 0;
    for (const line of lines) {
      const [hashSuffix, n] = line.split(':');
      if (hashSuffix === suffix && n) {
        count = parseInt(n, 10);
        break;
      }
    }
    return c.json({
      password: '***',
      sha1_prefix: prefix,
      pwned: count > 0,
      count,
      provider: 'hibp',
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'HIBP unreachable');
  }
}

/** POST {password} — preferred: keeps the plaintext out of URLs/logs. */
darknetIntelRouter.post('/darknet-intel/hibp/password', async (c) => {
  const body = await c.req.json<{ password?: string }>().catch(() => null);
  return hibpPwnedPassword(c, body?.password);
});

/** Legacy GET — kept for older clients; plaintext rides in the URL. */
darknetIntelRouter.get('/darknet-intel/hibp/password', async (c) => {
  return hibpPwnedPassword(c, c.req.query('password'));
});

// ─── Deep abuse.ch (ThreatFox, URLhaus, MalwareBazaar — free) ────────

darknetIntelRouter.get('/darknet-intel/abusech/threatfox-iocs', async (c) => {
  const days = parseInt(c.req.query('days') ?? '3', 10);
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: Math.min(Math.max(days, 1), 30) }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `ThreatFox upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { days, ...data, provider: 'threatfox', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ThreatFox unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/threatfox-search', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'q parameter required (IP, domain, hash, or URL)');
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: q }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ThreatFox upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ query: q, ...data, provider: 'threatfox', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ThreatFox unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/threatfox-tag', async (c) => {
  const tag = c.req.query('tag');
  if (!tag) return badRequest(c, 'tag parameter required (e.g. Cobalt Strike, Emotet)');
  const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 500);
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'taginfo', tag, limit }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ThreatFox upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ tag, limit, ...data, provider: 'threatfox', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ThreatFox unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/threatfox-malware', async (c) => {
  const malware = c.req.query('malware');
  if (!malware) return badRequest(c, 'malware parameter required (Malpedia name)');
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'malwareinfo', malware }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `ThreatFox upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ malware, ...data, provider: 'threatfox', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'ThreatFox unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/urlhaus', async (c) => {
  const url = c.req.query('url');
  const host = c.req.query('host');
  if (!url && !host) return badRequest(c, 'url or host parameter required');
  try {
    const body: Record<string, string> = {};
    if (url) body.url = url;
    if (host) body.host = host;
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `URLhaus upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ ...data, provider: 'urlhaus', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'URLhaus unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/urlhaus-tag', async (c) => {
  const tag = c.req.query('tag');
  if (!tag) return badRequest(c, 'tag parameter required');
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/tag/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tag }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `URLhaus upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ tag, ...data, provider: 'urlhaus', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'URLhaus unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/bazaar-hash', async (c) => {
  const hash = c.req.query('hash');
  if (!hash) return badRequest(c, 'hash parameter required (MD5, SHA1, or SHA256)');
  try {
    const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `query=get_info&${hash.length === 64 ? 'sha256_hash' : hash.length === 40 ? 'sha1_hash' : 'md5_hash'}=${encodeURIComponent(hash)}`,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `MalwareBazaar upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { hash, ...data, provider: 'malwarebazaar', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'MalwareBazaar unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/bazaar-recent', async (c) => {
  try {
    const res = await fetch('https://mb-api.abuse.ch/api/v1/?query=get_recent&selector=100', {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `MalwareBazaar upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ...data, provider: 'malwarebazaar', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'MalwareBazaar unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/abusech/bazaar-tag', async (c) => {
  const tag = c.req.query('tag');
  if (!tag) return badRequest(c, 'tag parameter required');
  const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 1000);
  try {
    const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `query=get_taginfo&tag=${encodeURIComponent(tag)}&limit=${limit}`,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `MalwareBazaar upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return c.json({ tag, limit, ...data, provider: 'malwarebazaar', generated_at: new Date().toISOString() });
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'MalwareBazaar unreachable');
  }
});

// ─── Deep AlienVault OTX (free, optional key) ────────────────────────

darknetIntelRouter.get('/darknet-intel/otx/ip', async (c) => {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, 'ip parameter required');
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const key = c.env.OTX_API_KEY;
    if (key) headers['X-OTX-API-KEY'] = key;
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `OTX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ip, ...data, provider: 'otx', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'OTX unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/otx/domain', async (c) => {
  const domain = c.req.query('domain');
  if (!domain) return badRequest(c, 'domain parameter required');
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const key = c.env.OTX_API_KEY;
    if (key) headers['X-OTX-API-KEY'] = key;
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`,
      {
        headers,
        signal: AbortSignal.timeout(10000),
      }
    );
    if (!res.ok) return badGateway(c, `OTX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { domain, ...data, provider: 'otx', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'OTX unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/otx/hash', async (c) => {
  const hash = c.req.query('hash');
  if (!hash) return badRequest(c, 'hash parameter required');
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const key = c.env.OTX_API_KEY;
    if (key) headers['X-OTX-API-KEY'] = key;
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/file/${encodeURIComponent(hash)}/general`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `OTX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { hash, ...data, provider: 'otx', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'OTX unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/otx/cve', async (c) => {
  const cve = c.req.query('cve');
  if (!cve) return badRequest(c, 'cve parameter required (e.g. CVE-2024-3094)');
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const key = c.env.OTX_API_KEY;
    if (key) headers['X-OTX-API-KEY'] = key;
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/cve/${encodeURIComponent(cve)}/general`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return badGateway(c, `OTX upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { cve, ...data, provider: 'otx', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'OTX unreachable');
  }
});

// ─── Hybrid Analysis (key required) ───────────────────────────────────

darknetIntelRouter.get('/darknet-intel/hybrid/search', async (c) => {
  const hash = c.req.query('hash');
  if (!hash) return badRequest(c, 'hash parameter required');
  const key = c.env.HYBRID_ANALYSIS_API_KEY;
  if (!key)
    return c.json(
      { error: 'HYBRID_ANALYSIS_API_KEY not configured', docs: 'wrangler secret put HYBRID_ANALYSIS_API_KEY' },
      503
    );
  try {
    const res = await fetch(`https://www.hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(hash)}`, {
      headers: { 'api-key': key, Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `Hybrid Analysis upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { hash, ...data, provider: 'hybrid-analysis', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Hybrid Analysis unreachable');
  }
});

darknetIntelRouter.get('/darknet-intel/hybrid/feed', async (c) => {
  const key = c.env.HYBRID_ANALYSIS_API_KEY;
  if (!key) return serviceUnavailable(c, 'HYBRID_ANALYSIS_API_KEY not configured');
  try {
    const res = await fetch('https://www.hybrid-analysis.com/api/v2/feed/latest', {
      headers: { 'api-key': key, Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return badGateway(c, `Hybrid Analysis upstream ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const body = { ...data, provider: 'hybrid-analysis', generated_at: new Date().toISOString(), cached: false };
    return c.json(body);
  } catch (e) {
    return badGateway(c, e instanceof Error ? e.message : 'Hybrid Analysis unreachable');
  }
});

// ─── Source Status (meta) ─────────────────────────────────────────────

darknetIntelRouter.get('/darknet-intel/sources', async (c) => {
  return c.json({
    providers: [
      { name: 'GreyNoise Community', tools: 2, auth: 'optional', key_env: 'GREYNOISE_API_KEY', free: true },
      { name: 'Pulsedive', tools: 3, auth: 'optional', key_env: 'PULSEDIVE_API_KEY', free: true },
      { name: 'Vulners', tools: 3, auth: 'optional', key_env: 'VULNERS_API_KEY', free: true },
      { name: 'IntelligenceX', tools: 4, auth: 'required', key_env: 'INTELX_API_KEY', free: false },
      { name: 'AbuseIPDB', tools: 4, auth: 'required', key_env: 'ABUSEIPDB_API_KEY', free: true },
      { name: 'Ransomware.live', tools: 5, auth: 'none', key_env: null, free: true },
      { name: 'RansomLook', tools: 2, auth: 'none', key_env: null, free: true },
      { name: 'HIBP', tools: 4, auth: 'partial', key_env: 'HIBP_API_KEY', free: true },
      { name: 'ThreatFox', tools: 4, auth: 'none', key_env: null, free: true },
      { name: 'URLhaus', tools: 2, auth: 'none', key_env: null, free: true },
      { name: 'MalwareBazaar', tools: 3, auth: 'none', key_env: null, free: true },
      { name: 'AlienVault OTX', tools: 4, auth: 'optional', key_env: 'OTX_API_KEY', free: true },
      { name: 'Hybrid Analysis', tools: 2, auth: 'required', key_env: 'HYBRID_ANALYSIS_API_KEY', free: false },
    ],
    total_tools: 42,
    generated_at: new Date().toISOString(),
  });
});
