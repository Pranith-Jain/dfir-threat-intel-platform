/**
 * Edge-side IP enrichment, ported from security-investigator/enrich_ips.py.
 *
 * Hits your existing platform providers through the SELF service binding
 * (in-process, no public internet hop) and merges the results into a
 * single record per IP. Mirrors the upstream shape:
 *
 *   {
 *     ip, city, region, country, org, asn, timezone,
 *     is_vpn, vpn_network,
 *     abuse_confidence_score, total_reports, isp, usage_type,
 *     threat_detected, threat_description, threat_confidence,
 *     shodan_ports, shodan_tags, shodan_vulns, shodan_hostnames,
 *   }
 *
 * The function is `Promise.allSettled`-based so one provider failing
 * (e.g. missing API key) does not poison the rest.
 *
 * IMPORTANT: This module is invoked from the Worker MCP server, not
 * the SSR frontend. The frontend should keep using the existing
 * /api/v1/ioc/check endpoint (which has more providers and uses the
 * proper ProviderAdapter pipeline). This module exists so any
 * LLM-driven client (Codex, Copilot, ChatGPT) can call
 * si_enrich_ip() through MCP and get the same shape upstream's
 * enrich_ips.py produces.
 */

export interface EnrichResult {
  ip: string;
  city?: string;
  region?: string;
  country?: string;
  org?: string;
  asn?: string;
  timezone?: string;
  is_vpn?: boolean;
  vpn_network?: string;
  abuse_confidence_score?: number;
  total_reports?: number;
  isp?: string;
  usage_type?: string;
  threat_detected?: boolean;
  threat_description?: string;
  threat_confidence?: number;
  shodan_ports?: number[];
  shodan_tags?: string[];
  shodan_vulns?: string[];
  shodan_hostnames?: string[];
  /** PhantomCandle threat category (1-17 enum). 1=APT trojan, etc. */
  phantomcandle_category?: number;
  /** PhantomCandle risk level (1-3). 3=high (APT/ransomware). */
  phantomcandle_risk_level?: number;
  /** PhantomCandle malware family name (e.g. "CobaltStrike"). */
  phantomcandle_malicious_family?: string;
  /** PhantomCandle campaign / group attribution (e.g. "SilverFox"). */
  phantomcandle_campaign?: string;
  ipqs_fraud_score?: number;
  ipqs_proxy?: boolean;
  ipqs_vpn?: boolean;
  ipqs_tor?: boolean;
  ipqs_recent_abuse?: boolean;
  ipqs_bot_status?: boolean;
  ipqs_connection_type?: string;
  ipqs_abuse_velocity?: string;
  ipqs_isp?: string;
  /** Per-provider latency + outcome, useful for debugging. */
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'skipped' | 'failed' | 'rate_limited';
    ms: number;
    error?: string;
  }>;
}

interface EnvWithSelf {
  SELF?: Fetcher;
  IPINFO_TOKEN?: string;
  ABUSEIPDB_API_KEY?: string;
  SHODAN_API_KEY?: string;
  VPNAPI_TOKEN?: string;
  KV_CACHE?: KVNamespace;
  PHANTOMCANDLE_USER?: string;
  PHANTOMCANDLE_TOKEN?: string;
  IPQS_API_KEY?: string;
}

async function timed<T>(label: string, fn: () => Promise<T>): Promise<{ value?: T; ms: number; error?: string }> {
  const t0 = Date.now();
  try {
    const v = await fn();
    return { value: v, ms: Date.now() - t0 };
  } catch (e) {
    console.error('timed failed:', errMessage(e));
    return { ms: Date.now() - t0, error: errMessage(e) };
  }
}

async function selfFetch<T>(self: Fetcher, path: string): Promise<T | null> {
  const res = await self.fetch(new Request(`https://si-self${path}`, { headers: { accept: 'application/json' } }));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

import { createSiRateLimiter, type RateLimitedProvider } from './si-rate-limit';
import { errMessage } from './err';

interface PhcResponse {
  code: number;
  msg: string;
  data?: Array<{
    ioc_type: string;
    ioc_host: string;
    ioc_port: string;
    category: number;
    risk_level: number;
    confidence: number;
    malicious_family: string;
    campaign: string;
    disservice: string;
    first_seen: string;
    tags: string[];
    file_hash: string;
    platform: string;
    malicious_stamp: string;
    status: string;
    tpd: number;
    base: number;
    protocol: string;
  }>;
}

async function phantomcandleFetch(
  env: EnvWithSelf,
  ip: string,
  limiter: ReturnType<typeof createSiRateLimiter>
): Promise<{
  value?: Record<string, unknown>;
  ms: number;
  error?: string;
  _rateLimited?: boolean;
  decision?: { retryAfterSeconds: number; limit: number };
}> {
  const label = 'phantomcandle';
  const decision = await limiter.consume('phantomcandle');
  if (!decision.allowed) {
    const t0 = Date.now();
    return {
      _rateLimited: true,
      decision: { retryAfterSeconds: decision.retryAfterSeconds, limit: decision.limit },
      ms: Date.now() - t0,
    };
  }
  return await timed(label, async () => {
    if (!env.PHANTOMCANDLE_USER || !env.PHANTOMCANDLE_TOKEN) {
      throw new Error('PHANTOMCANDLE_USER or PHANTOMCANDLE_TOKEN not set');
    }
    const res = await fetch('https://api.phantomcandle.net/api/search/ti', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        user: env.PHANTOMCANDLE_USER,
        token: env.PHANTOMCANDLE_TOKEN,
        ioc_type: 'ip',
        ioc: ip,
      }),
    });
    if (!res.ok) {
      throw new Error(`phantomcandle returned ${res.status}`);
    }
    const body = (await res.json()) as PhcResponse;
    if (body.code === 0 && body.data && body.data.length > 0) {
      return body.data[0] as unknown as Record<string, unknown>;
    }
    if (body.code === 13) {
      return {}; // miss — no data, but not an error
    }
    throw new Error(`phantomcandle error: code=${body.code} msg=${body.msg}`);
  });
}

interface IPQSResponse {
  success?: boolean;
  fraud_score?: number;
  proxy?: boolean;
  vpn?: boolean;
  tor?: boolean;
  active_vpn?: boolean;
  active_tor?: boolean;
  recent_abuse?: boolean;
  bot_status?: boolean;
  connection_type?: string;
  abuse_velocity?: string;
  ISP?: string;
  ASN?: string;
  organization?: string;
  country_code?: string;
  region?: string;
  city?: string;
  is_crawler?: boolean;
  mobile?: boolean;
  hosting?: boolean;
  message?: string;
}

async function ipqsFetch(
  env: EnvWithSelf,
  ip: string,
  limiter: ReturnType<typeof createSiRateLimiter>
): Promise<{
  value?: Record<string, unknown>;
  ms: number;
  error?: string;
  _rateLimited?: boolean;
  decision?: { retryAfterSeconds: number; limit: number };
}> {
  const label = 'ipqs';
  const decision = await limiter.consume('ipqs');
  if (!decision.allowed) {
    const t0 = Date.now();
    return {
      _rateLimited: true,
      decision: { retryAfterSeconds: decision.retryAfterSeconds, limit: decision.limit },
      ms: Date.now() - t0,
    };
  }
  return await timed(label, async () => {
    const key = env.IPQS_API_KEY;
    if (!key) {
      throw new Error('IPQS_API_KEY not set');
    }
    const res = await fetch(`https://ipqualityscore.com/api/json/ip/${key}/${ip}`, {
      headers: { accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`ipqs returned ${res.status}`);
    }
    const body = (await res.json()) as IPQSResponse;
    if (!body.success) {
      throw new Error(`ipqs error: ${body.message || 'unknown'}`);
    }
    return body as unknown as Record<string, unknown>;
  });
}

export function isValidIp(s: string): boolean {
  if (!s) return false;
  if (IPV4.test(s)) {
    return s.split('.').every((p) => Number(p) >= 0 && Number(p) <= 255);
  }
  if (s.includes(':') && IPV6.test(s)) return true;
  return false;
}

export async function enrichIp(env: EnvWithSelf, ip: string): Promise<EnrichResult> {
  const result: EnrichResult = { ip, diagnostics: [] };
  if (!isValidIp(ip)) {
    result.diagnostics.push({ provider: 'validator', status: 'failed', ms: 0, error: 'not a valid IPv4/IPv6 address' });
    return result;
  }
  if (!env.SELF) {
    result.diagnostics.push({ provider: 'self-binding', status: 'skipped', ms: 0, error: 'env.SELF is not bound' });
    return result;
  }

  // Per-provider rate limiting — see worker/lib/si-rate-limit.ts. The
  // limiter is created per-call (cheap — just an object literal that
  // reads/writes KV). When a bucket is empty, the corresponding
  // selfFetch is skipped and a 'rate_limited' diagnostic is recorded.
  const limiter = createSiRateLimiter(env.KV_CACHE);
  const gated = async <T>(label: string, provider: RateLimitedProvider, path: string) => {
    const decision = await limiter.consume(provider);
    if (!decision.allowed) {
      const t0 = Date.now();
      return { _rateLimited: true, decision, value: undefined as T | undefined, ms: Date.now() - t0 };
    }
    const res = await timed(label, () => selfFetch<Record<string, unknown>>(env.SELF!, path));
    return { _rateLimited: false, value: res.value as T | undefined, ms: res.ms, error: res.error };
  };

  // Run all providers in parallel. Each call records its own timing + status.
  // PhantomCandle uses direct fetch (not SELF proxy) because there's no
  // existing API route for it.
  const [ipinfo, abuse, shodan, internetdb, vpn, phantomcandle, ipqs] = await Promise.all([
    gated<Record<string, unknown>>('ipinfo', 'ipinfo', `/api/v1/ipinfo/${ip}`),
    gated<Record<string, unknown>>('abuseipdb', 'abuseipdb', `/api/v1/abuseipdb/${ip}`),
    gated<Record<string, unknown>>('shodan', 'shodan', `/api/v1/shodan/host/${ip}`),
    gated<Record<string, unknown>>('shodan-internetdb', 'shodan-internetdb', `/api/v1/shodan-internetdb/${ip}`),
    gated<Record<string, unknown>>('vpnapi', 'vpnapi', `/api/v1/vpnapi/${ip}`),
    phantomcandleFetch(env, ip, limiter),
    ipqsFetch(env, ip, limiter),
  ]);

  if ((ipinfo as { _rateLimited?: boolean })._rateLimited) {
    const d = (ipinfo as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'ipinfo',
      status: 'rate_limited' as const,
      ms: (ipinfo as { ms: number }).ms,
      error: `ipinfo quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else if ((ipinfo as { value?: unknown }).value) {
    const v = (ipinfo as { value: Record<string, unknown> }).value;
    result.city = (v.city as string) ?? undefined;
    result.region = (v.region as string) ?? undefined;
    result.country = (v.country as string) ?? undefined;
    result.org = (v.org as string) ?? undefined;
    const loc = (v.loc as string | undefined)?.split(',');
    if (loc) result.timezone = undefined; // not in ipinfo; left undefined
    // ipinfo's "org" is "AS13335 Cloudflare, Inc." — extract ASN
    const orgMatch = (v.org as string | undefined)?.match(/^(AS\d+)\s+(.+)$/);
    if (orgMatch) {
      result.asn = orgMatch[1];
      if (!result.org) result.org = orgMatch[2];
    }
    result.diagnostics.push({ provider: 'ipinfo', status: 'ok', ms: ipinfo.ms });
  } else {
    result.diagnostics.push({
      provider: 'ipinfo',
      status: ipinfo.error ? 'failed' : 'skipped',
      ms: ipinfo.ms,
      error: ipinfo.error,
    });
  }

  if ((abuse as { _rateLimited?: boolean })._rateLimited) {
    const d = (abuse as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'abuseipdb',
      status: 'rate_limited' as const,
      ms: (abuse as { ms: number }).ms,
      error: `abuseipdb quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else if ((abuse as { value?: unknown }).value) {
    const v = (abuse as { value: Record<string, unknown> }).value;
    const data = (v.data as Record<string, unknown> | undefined) ?? v;
    result.abuse_confidence_score =
      (data.abuseConfidenceScore as number | undefined) ?? (data.confidence as number | undefined);
    result.total_reports = (data.totalReports as number | undefined) ?? (data.reports as number | undefined);
    result.isp = data.isp as string | undefined;
    result.usage_type = data.usageType as string | undefined;
    result.diagnostics.push({ provider: 'abuseipdb', status: 'ok', ms: abuse.ms });
  } else {
    result.diagnostics.push({
      provider: 'abuseipdb',
      status: abuse.error ? 'failed' : 'skipped',
      ms: abuse.ms,
      error: abuse.error,
    });
  }

  if ((shodan as { _rateLimited?: boolean })._rateLimited) {
    const d = (shodan as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'shodan',
      status: 'rate_limited' as const,
      ms: (shodan as { ms: number }).ms,
      error: `shodan quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else if ((shodan as { value?: unknown }).value) {
    const v = (shodan as { value: Record<string, unknown> }).value;
    result.shodan_ports = (v.ports as number[] | undefined) ?? undefined;
    result.shodan_tags = (v.tags as string[] | undefined) ?? undefined;
    result.shodan_vulns = (v.vulns as string[] | undefined) ?? undefined;
    result.shodan_hostnames = (v.hostnames as string[] | undefined) ?? undefined;
    result.diagnostics.push({ provider: 'shodan', status: 'ok', ms: shodan.ms });
  } else {
    result.diagnostics.push({
      provider: 'shodan',
      status: shodan.error ? 'failed' : 'skipped',
      ms: shodan.ms,
      error: shodan.error,
    });
  }

  if (
    !(internetdb as { _rateLimited?: boolean })._rateLimited &&
    (internetdb as { value?: unknown }).value &&
    !(shodan as { value?: unknown }).value
  ) {
    // Fall back to shodan-internetdb (free) if paid shodan didn't return.
    const v = (internetdb as { value: Record<string, unknown> }).value;
    result.shodan_ports = (v.ports as number[] | undefined) ?? result.shodan_ports;
    result.shodan_tags = (v.tags as string[] | undefined) ?? result.shodan_tags;
    result.shodan_vulns = (v.vulns as string[] | undefined) ?? result.shodan_vulns;
    result.shodan_hostnames = (v.hostnames as string[] | undefined) ?? result.shodan_hostnames;
    result.diagnostics.push({ provider: 'shodan-internetdb', status: 'ok', ms: internetdb.ms });
  } else if ((internetdb as { _rateLimited?: boolean })._rateLimited) {
    const d = (internetdb as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'shodan-internetdb',
      status: 'rate_limited' as const,
      ms: (internetdb as { ms: number }).ms,
      error: `shodan-internetdb quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else {
    result.diagnostics.push({
      provider: 'shodan-internetdb',
      status: (internetdb as { error?: string }).error ? 'failed' : 'skipped',
      ms: (internetdb as { ms: number }).ms,
      error: (internetdb as { error?: string }).error,
    });
  }

  if ((vpn as { _rateLimited?: boolean })._rateLimited) {
    const d = (vpn as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'vpnapi',
      status: 'rate_limited' as const,
      ms: (vpn as { ms: number }).ms,
      error: `vpnapi quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else if ((vpn as { value?: unknown }).value) {
    const v = (vpn as { value: Record<string, unknown> }).value;
    const security = (v.security as Record<string, unknown> | undefined) ?? v;
    result.is_vpn =
      Boolean(security.vpn) || Boolean(security.proxy) || Boolean(security.tor) || Boolean(security.relay);
    result.vpn_network = (security.network as string | undefined) ?? (security.operator as string | undefined);
    result.diagnostics.push({ provider: 'vpnapi', status: 'ok', ms: vpn.ms });
  } else {
    result.diagnostics.push({
      provider: 'vpnapi',
      status: vpn.error ? 'failed' : 'skipped',
      ms: vpn.ms,
      error: vpn.error,
    });
  }

  if ((phantomcandle as { _rateLimited?: boolean })._rateLimited) {
    const d = (phantomcandle as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'phantomcandle',
      status: 'rate_limited' as const,
      ms: (phantomcandle as { ms: number }).ms,
      error: `phantomcandle quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else if (
    (phantomcandle as { value?: unknown }).value &&
    Object.keys((phantomcandle as { value: Record<string, unknown> }).value).length > 0
  ) {
    const v = (phantomcandle as { value: Record<string, unknown> }).value;
    result.phantomcandle_category = v.category as number | undefined;
    result.phantomcandle_risk_level = v.risk_level as number | undefined;
    result.phantomcandle_malicious_family = v.malicious_family as string | undefined;
    result.phantomcandle_campaign = v.campaign as string | undefined;
    result.diagnostics.push({ provider: 'phantomcandle', status: 'ok', ms: phantomcandle.ms });
  } else {
    result.diagnostics.push({
      provider: 'phantomcandle',
      status: (phantomcandle as { error?: string }).error ? 'failed' : 'skipped',
      ms: (phantomcandle as { ms: number }).ms,
      error: (phantomcandle as { error?: string }).error,
    });
  }

  if ((ipqs as { _rateLimited?: boolean })._rateLimited) {
    const d = (ipqs as { decision: { retryAfterSeconds: number; limit: number } }).decision;
    result.diagnostics.push({
      provider: 'ipqs',
      status: 'rate_limited' as const,
      ms: (ipqs as { ms: number }).ms,
      error: `ipqs quota exhausted (limit ${d.limit}/window); retry in ${d.retryAfterSeconds}s`,
    });
  } else if (
    (ipqs as { value?: unknown }).value &&
    Object.keys((ipqs as { value: Record<string, unknown> }).value).length > 0
  ) {
    const v = (ipqs as { value: Record<string, unknown> }).value;
    result.ipqs_fraud_score = v.fraud_score as number | undefined;
    result.ipqs_proxy = v.proxy as boolean | undefined;
    result.ipqs_vpn = v.vpn as boolean | undefined;
    result.ipqs_tor = v.tor as boolean | undefined;
    result.ipqs_recent_abuse = v.recent_abuse as boolean | undefined;
    result.ipqs_bot_status = v.bot_status as boolean | undefined;
    result.ipqs_connection_type = v.connection_type as string | undefined;
    result.ipqs_abuse_velocity = v.abuse_velocity as string | undefined;
    result.ipqs_isp = v.ISP as string | undefined;
    result.diagnostics.push({ provider: 'ipqs', status: 'ok', ms: ipqs.ms });
  } else {
    result.diagnostics.push({
      provider: 'ipqs',
      status: (ipqs as { error?: string }).error ? 'failed' : 'skipped',
      ms: (ipqs as { ms: number }).ms,
      error: (ipqs as { error?: string }).error,
    });
  }

  return result;
}

/**
 * Batch enrich up to N IPs in parallel. Caps at 25 to keep the
 * Worker's 50 subrequest/Invocation budget headroom (5 providers × 25
 * IPs = 125 worst case, but Promise.allSettled collapses to one round).
 */
export async function enrichIpsBatch(
  env: EnvWithSelf,
  ips: string[],
  opts: { limit?: number } = {}
): Promise<EnrichResult[]> {
  const cap = Math.min(ips.length, opts.limit ?? 25);
  const targets = ips.slice(0, cap);
  return Promise.all(targets.map((ip) => enrichIp(env, ip)));
}
