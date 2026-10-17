/**
 * URL risk analyzer — POST /api/v1/url-risk/analyze.
 *
 * Runs the IntelX-style URL risk correlation pipeline ported to
 * `worker/lib/url-risk.ts`:
 *   1. Static heuristic signals (length, @, keywords, punycode,
 *      shorteners, IP hosts, subdomains, ports, scheme) — no network.
 *   2. Targeted provider fan-out: VirusTotal, Google Safe Browsing,
 *      URLScan (search), plus AbuseIPDB (after a single DoH A lookup for
 *      the hostname) and WHOIS/RDAP domain age.
 *   3. Weighted evidence correlation → 0–100 risk score, verdict bands,
 *      confidence, and an evidence chain (weights carry over the upstream
 *      risk_engine.py: 35/30/30/20/20, capped at 100).
 *
 * Subrequest budget: static (0) + provider prime/flush (2 Cache API) +
 * VT (1) + GSB (1) + urlscan (1) + DoH A (1) + AbuseIPDB (1) +
 * RDAP (1–2) ≈ 9 — well under the 50-subrequest free-plan cap.
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { badRequest, internalError } from '../lib/api-error';
import { analyzeUrlSignals, calculateUrlRisk, type UrlRiskInput } from '../lib/url-risk';
import { ADAPTERS, buildProviderEnv, PROVIDER_TIMEOUT_MS, providerTimeoutMs } from '../providers';
import type { Indicator, ProviderId, ProviderResult } from '../providers/types';
import { ProviderCache } from '../lib/cache';
import { isCircuitOpen, recordProviderFailure, recordProviderSuccess } from '../lib/circuit-breaker';
import { rdapLookup } from '../lib/rdap';
import { logError } from '../lib/logger';

const MAX_URL_BYTES = 2048;

interface UrlRiskRequest {
  url: string;
}

function isIpv4(value: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

/**
 * Resolve the URL host to a single IPv4 for the AbuseIPDB leg. IP-literal
 * hosts skip DNS; bracket/hexet IPv6 hosts are not checkable on
 * AbuseIPDB's v4 API. Returns null when unresolvable — AbuseIPDB simply
 * drops out of the correlation.
 */
async function resolveHostIp(host: string, signal: AbortSignal): Promise<string | null> {
  if (host.includes(':')) return null;
  if (isIpv4(host)) return host;
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal,
    });
    if (!res.ok) return null;
    const json = (await res.json()) as { Answer?: Array<{ data?: string }> };
    const first = json.Answer?.[0]?.data;
    return first && isIpv4(first) ? first : null;
  } catch {
    return null;
  }
}

function trimResult(r: ProviderResult): Record<string, unknown> {
  return {
    source: r.source,
    status: r.status,
    score: r.score,
    verdict: r.verdict,
    tags: r.tags.slice(0, 10),
    raw_summary: r.raw_summary,
    ...(r.error ? { error: r.error } : {}),
  };
}

function unsupportedResult(source: ProviderId, tags: string[] = []): ProviderResult {
  return {
    source,
    status: 'unsupported',
    score: 0,
    verdict: 'unknown',
    raw_summary: {},
    tags,
    fetched_at: new Date().toISOString(),
    cached: false,
  };
}

const isIpHost = (hostname: string): boolean => hostname.includes(':') || isIpv4(hostname);

export async function urlRiskAnalyzeHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    let body: UrlRiskRequest;
    try {
      body = await c.req.json<UrlRiskRequest>();
    } catch {
      return badRequest(c, 'invalid json body');
    }
    const url = (body.url ?? '').trim();
    if (!url) return badRequest(c, 'missing url');
    if (new Blob([url]).size > MAX_URL_BYTES) return badRequest(c, 'url too long (max 2048 bytes)');

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return badRequest(c, 'invalid url');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return badRequest(c, 'only http/https urls are supported');
    }

    const hostname = parsed.hostname.toLowerCase();
    // Route-level budget for the local RDAP/DNS work below; each provider
    // gets its own budget inside runAdapter (see providerTimeoutMs).
    const signal = AbortSignal.timeout(PROVIDER_TIMEOUT_MS);
    const providerEnv = buildProviderEnv(c.env);
    const cache = new ProviderCache(c.env.KV_CACHE as KVNamespace | undefined);
    const indicator: Indicator = { type: 'url', value: url };

    // Static heuristics (no network).
    const signals = analyzeUrlSignals(url);

    // ── Provider fan-out (targeted 5-source correlation) ───────────────
    async function runAdapter(p: ProviderId, ind: Indicator): Promise<ProviderResult> {
      if (isCircuitOpen(p)) return unsupportedResult(p, ['circuit-open']);
      const cached = cache.getBatched(p);
      if (cached) {
        await recordProviderSuccess(p);
        return cached;
      }
      try {
        const r = await ADAPTERS[p](ind, providerEnv, AbortSignal.timeout(providerTimeoutMs(p)));
        if (r.status === 'ok') {
          cache.stageBatched(p, ind, r);
          await recordProviderSuccess(p);
        } else {
          recordProviderFailure(p);
        }
        return r;
      } catch (err) {
        recordProviderFailure(p);
        logError('url-risk provider failed', err);
        return {
          source: p,
          status: 'error',
          score: 0,
          verdict: 'unknown',
          raw_summary: {},
          tags: [],
          error: err instanceof Error ? err.message : String(err),
          fetched_at: new Date().toISOString(),
          cached: false,
        };
      }
    }

    await cache.primeBatch(indicator);

    // WHOIS/RDAP only applies to real domain names — an IP-literal URL has
    // no registration record to score.
    const rdapPromise = isIpHost(hostname) ? Promise.resolve(null) : rdapLookup(hostname).catch(() => null);

    const [vtPromise, gsbPromise, usPromise, ipPromise, rdapResolved] = await Promise.allSettled([
      runAdapter('virustotal', indicator),
      runAdapter('safebrowsing', indicator),
      runAdapter('urlscan', indicator),
      resolveHostIp(hostname, signal),
      rdapPromise,
    ]);

    await cache.flushBatch(indicator);

    const vt = vtPromise.status === 'fulfilled' ? vtPromise.value : unsupportedResult('virustotal');
    const us = usPromise.status === 'fulfilled' ? usPromise.value : unsupportedResult('urlscan');
    const gsb = gsbPromise.status === 'fulfilled' ? gsbPromise.value : unsupportedResult('safebrowsing');
    const ip = ipPromise.status === 'fulfilled' ? ipPromise.value : null;
    const rdap = rdapResolved.status === 'fulfilled' ? rdapResolved.value : null;

    let abuse: ProviderResult = unsupportedResult('abuseipdb');
    if (ip) {
      const abusePromise = await runAdapter('abuseipdb', { type: 'ipv4', value: ip });
      abuse = abusePromise;
    }

    // ── Build the correlation payload ──────────────────────────────────
    const vtOk = vt.status === 'ok' && vt.raw_summary.malicious !== undefined;
    const gsbOk = gsb.status === 'ok' && gsb.raw_summary.safe !== undefined;
    const usFlagged = us.status === 'ok' && (us.raw_summary.flagged_tags as string[] | undefined)?.length;
    const abuseOk = abuse.status === 'ok' && abuse.raw_summary.confidence !== undefined;
    const whoisOk = !!rdap && (!!rdap.created || !!rdap.registrar || rdap.error === undefined);

    const engineInput: UrlRiskInput = {
      virustotal: vtOk
        ? {
            malicious: vt.raw_summary.malicious,
            suspicious: vt.raw_summary.suspicious,
            total_vendors: vt.raw_summary.total,
          }
        : undefined,
      google_safe_browsing: gsbOk
        ? {
            detected: gsb.raw_summary.safe === false,
            matches: ((gsb.raw_summary.threats ?? []) as string[]).map((t) => ({ threatType: t })),
          }
        : undefined,
      urlscan: usFlagged
        ? {
            verdict: us.verdict === 'malicious' ? 'malicious' : '',
            page_domain: hostname,
          }
        : us.status === 'ok' && us.raw_summary.result_count !== undefined
          ? { page_domain: hostname }
          : undefined,
      abuseipdb: abuseOk
        ? {
            abuse_confidence: abuse.raw_summary.confidence,
            total_reports: abuse.raw_summary.totalReports,
            usage_type: (abuse.tags[0] ?? '').toLowerCase(),
          }
        : undefined,
      whois: whoisOk
        ? {
            creation_date: rdap?.created,
            registrar: rdap?.registrar,
            dnssec: rdap?.dnssec,
          }
        : undefined,
    };

    const engine = calculateUrlRisk(engineInput);

    // ── Compose response ───────────────────────────────────────────────
    return c.json(
      {
        url,
        hostname,
        ip_address: ip ?? null,
        static: signals,
        risk: engine,
        providers: {
          virustotal: trimResult(vt),
          google_safe_browsing: trimResult(gsb),
          urlscan: trimResult(us),
          abuseipdb: trimResult(abuse),
          whois: {
            source: 'rdap',
            status: whoisOk ? 'ok' : rdap?.error ? 'error' : 'unsupported',
            ...(rdap?.registrar ? { registrar: rdap.registrar } : {}),
            ...(rdap?.created ? { created: rdap.created } : {}),
            ...(rdap?.dnssec ? { dnssec: rdap.dnssec } : {}),
            ...(rdap?.error ? { error: rdap.error } : {}),
          },
        },
      },
      200,
      { 'Cache-Control': 'no-store' }
    );
  } catch (err) {
    logError('url-risk handler failed', err);
    return internalError(c, err instanceof Error ? err.message : 'internal error');
  }
}
