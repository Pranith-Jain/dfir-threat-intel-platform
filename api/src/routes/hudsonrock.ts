import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { fetchResilient } from '../lib/fetch-resilient';
import { badRequest, badGateway, serviceUnavailable } from '../lib/api-error';
import {
  searchByEmails,
  searchByDomain,
  domainOverview,
  assetsDiscovery,
  thirdPartyRiskAssessment,
  infectionAnalysis,
  searchByUsername,
  searchByIp,
  getAccount,
  type HRStealerEntry,
} from '../../../worker/lib/hudsonrock';

const V2_BASE = 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools';
const CACHE_TTL_SECONDS = 3600;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function hasV3Key(env: Env): boolean {
  return Boolean(env.HUDSONROCK_API_KEY);
}

function cacheGet(key: string): Promise<Response | undefined> {
  return caches.default.match(new Request(key));
}

function cachePut(key: string, res: Response): Promise<void> {
  return caches.default.put(new Request(key), res.clone()).then(() => {});
}

function formatV3Entry(entry: HRStealerEntry) {
  return {
    stealer_id: entry.stealer,
    stealer_family: entry.stealer_family,
    date_compromised: entry.date_compromised,
    date_uploaded: entry.date_uploaded,
    ip: entry.ip,
    computer_name: entry.computer_name,
    operating_system: entry.operating_system,
    employee_at: entry.employeeAt,
    client_at: entry.clientAt,
    credentials: entry.credentials.map((c) => ({
      url: c.url,
      domain: c.domain,
      username: c.username,
      type: c.type,
    })),
  };
}

function successResponse(body: object, cacheKey: string, ctx: Context<{ Bindings: Env }>): Response {
  const raw = JSON.stringify(body);
  const res = new Response(raw, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
    },
  });
  ctx.executionCtx.waitUntil(cachePut(cacheKey, res));
  return res;
}

// ─── Email search ──────────────────────────────────────────────────────────

export async function hudsonRockSearchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const email = c.req.query('email');
  if (!email) return badRequest(c, 'email parameter required');
  if (!EMAIL_RE.test(email)) return badRequest(c, 'invalid email format');

  const cacheKey = `https://hr-cache.internal/v3-email-${encodeURIComponent(email)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  const env = c.env;

  try {
    if (hasV3Key(env)) {
      const data = await searchByEmails(env, [email]);
      const entries = data.data ?? [];
      const totalCredentials = entries.reduce((s, e) => s + e.credentials.length, 0);
      return successResponse(
        {
          api_version: 'v3',
          email,
          found: entries.length > 0,
          total_infections: entries.length,
          total_credentials: totalCredentials,
          has_more: Boolean(data.nextCursor),
          results: entries.map(formatV3Entry),
          generated_at: new Date().toISOString(),
        },
        cacheKey,
        c
      );
    }

    // Fallback to v2 free endpoint
    const res = await fetchResilient(
      `${V2_BASE}/search-by-email?email=${encodeURIComponent(email)}`,
      { headers: { accept: 'application/json', 'user-agent': 'pranithjain.qzz.io DFIR toolkit' } },
      { attempts: 2, timeoutMs: 25000 }
    );
    if (!res.ok) return badGateway(c, `Hudson Rock upstream ${res.status}`);

    const data = (await res.json()) as { data: HRStealerEntry[] };
    const entries = Array.isArray(data?.data) ? data.data : [];
    const totalCredentials = entries.reduce((s, e) => s + e.credentials.length, 0);
    return successResponse(
      {
        api_version: 'v2',
        email,
        found: entries.length > 0,
        total_infections: entries.length,
        total_credentials: totalCredentials,
        results: entries.map(formatV3Entry),
        generated_at: new Date().toISOString(),
      },
      cacheKey,
      c
    );
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Domain search ─────────────────────────────────────────────────────────

export async function hudsonRockDomainHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const domain = c.req.query('domain');
  if (!domain) return badRequest(c, 'domain parameter required');
  if (!DOMAIN_RE.test(domain)) return badRequest(c, 'invalid domain format');

  const cacheKey = `https://hr-cache.internal/v3-domain-${encodeURIComponent(domain)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  const env = c.env;

  try {
    if (hasV3Key(env)) {
      const data = await searchByDomain(env, [domain]);
      const entries = data.data ?? [];
      const totalCredentials = entries.reduce((s, e) => s + e.credentials.length, 0);
      return successResponse(
        {
          api_version: 'v3',
          domain,
          found: entries.length > 0,
          total_infections: entries.length,
          total_credentials: totalCredentials,
          has_more: Boolean(data.nextCursor),
          results: entries.map(formatV3Entry),
          generated_at: new Date().toISOString(),
        },
        cacheKey,
        c
      );
    }

    const res = await fetchResilient(
      `${V2_BASE}/search-by-domain?domain=${encodeURIComponent(domain)}`,
      { headers: { accept: 'application/json', 'user-agent': 'pranithjain.qzz.io DFIR toolkit' } },
      { attempts: 2, timeoutMs: 25000 }
    );
    if (!res.ok) return badGateway(c, `Hudson Rock upstream ${res.status}`);
    const data = await res.json();
    return successResponse(
      { api_version: 'v2', domain, found: true, data, generated_at: new Date().toISOString() },
      cacheKey,
      c
    );
  } catch (e) {
    logError('handler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Domain overview (v3 only) ─────────────────────────────────────────────

export async function hudsonRockDomainOverviewHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const domain = c.req.query('domain');
  if (!domain) return badRequest(c, 'domain parameter required');
  if (!DOMAIN_RE.test(domain)) return badRequest(c, 'invalid domain format');
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');

  const cacheKey = `https://hr-cache.internal/v3-overview-${encodeURIComponent(domain)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  try {
    const data = await domainOverview(c.env, [domain]);
    return successResponse(
      { domain, overview: data.data?.[0] ?? null, generated_at: new Date().toISOString() },
      cacheKey,
      c
    );
  } catch (e) {
    logError('hudsonRockDomainOverviewHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Assets discovery (v3 only) ────────────────────────────────────────────

export async function hudsonRockDiscoveryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const domain = c.req.query('domain');
  if (!domain) return badRequest(c, 'domain parameter required');
  if (!DOMAIN_RE.test(domain)) return badRequest(c, 'invalid domain format');
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');

  const cacheKey = `https://hr-cache.internal/v3-discovery-${encodeURIComponent(domain)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  try {
    const data = await assetsDiscovery(c.env, [domain]);
    return successResponse(
      {
        domain,
        total_urls: data.data?.length ?? 0,
        has_more: Boolean(data.nextCursor),
        results: data.data ?? [],
        generated_at: new Date().toISOString(),
      },
      cacheKey,
      c
    );
  } catch (e) {
    logError('hudsonRockDiscoveryHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Third-party risk (v3 only) ────────────────────────────────────────────

export async function hudsonRockAssessmentHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const domain = c.req.query('domain');
  if (!domain) return badRequest(c, 'domain parameter required');
  if (!DOMAIN_RE.test(domain)) return badRequest(c, 'invalid domain format');
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');

  const cacheKey = `https://hr-cache.internal/v3-assess-${encodeURIComponent(domain)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  try {
    const data = await thirdPartyRiskAssessment(c.env, domain);
    return successResponse({ domain, assessment: data, generated_at: new Date().toISOString() }, cacheKey, c);
  } catch (e) {
    logError('hudsonRockAssessmentHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Infection analysis (v3 only) ──────────────────────────────────────────

export async function hudsonRockInfectionAnalysisHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const stealer = c.req.query('stealer');
  if (!stealer) return badRequest(c, 'stealer parameter required');
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');

  const cacheKey = `https://hr-cache.internal/v3-infection-${encodeURIComponent(stealer)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  try {
    const data = await infectionAnalysis(c.env, stealer);
    return successResponse({ stealer, analysis: data.data, generated_at: new Date().toISOString() }, cacheKey, c);
  } catch (e) {
    logError('hudsonRockInfectionAnalysisHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Username search (v3 only) ─────────────────────────────────────────────

export async function hudsonRockUsernameHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const username = c.req.query('username');
  if (!username) return badRequest(c, 'username parameter required');
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');

  const cacheKey = `https://hr-cache.internal/v3-username-${encodeURIComponent(username)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  try {
    const data = await searchByUsername(c.env, [username]);
    const entries = data.data ?? [];
    return successResponse(
      {
        username,
        found: entries.length > 0,
        total_infections: entries.length,
        has_more: Boolean(data.nextCursor),
        results: entries.map(formatV3Entry),
        generated_at: new Date().toISOString(),
      },
      cacheKey,
      c
    );
  } catch (e) {
    logError('hudsonRockUsernameHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── IP search (v3 only) ───────────────────────────────────────────────────

export async function hudsonRockIpHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const ip = c.req.query('ip');
  if (!ip) return badRequest(c, 'ip parameter required');
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');

  const cacheKey = `https://hr-cache.internal/v3-ip-${encodeURIComponent(ip)}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return cached;

  try {
    const data = await searchByIp(c.env, [ip]);
    const entries = data.data ?? [];
    return successResponse(
      {
        ip,
        found: entries.length > 0,
        total_infections: entries.length,
        has_more: Boolean(data.nextCursor),
        results: entries.map(formatV3Entry),
        generated_at: new Date().toISOString(),
      },
      cacheKey,
      c
    );
  } catch (e) {
    logError('hudsonRockIpHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}

// ─── Account info (v3 only) ────────────────────────────────────────────────

export async function hudsonRockAccountHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!hasV3Key(c.env)) return serviceUnavailable(c, 'requires HUDSONROCK_API_KEY (v3 only)');
  try {
    const data = await getAccount(c.env);
    return c.json({ account: data, generated_at: new Date().toISOString() });
  } catch (e) {
    logError('hudsonRockAccountHandler failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Hudson Rock unreachable');
  }
}
