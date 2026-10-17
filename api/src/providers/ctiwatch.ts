import type { ProviderAdapter, ProviderResult, Verdict } from './types';
import { classifyResponseError, classifyThrownError, toProviderError } from '../lib/provider-errors';
import { getCtiwatchSession } from '../lib/ctiwatch';

/**
 * CTIWatch (ctiwatch.com) — IOC database lookup.
 *
 * The platform already reads CTIWatch's CVE catalogue for the 24h digest
 * (api/src/lib/ctiwatch.ts). This adapter adds the other half of the source:
 * its indicator database (~2.1M IOCs aggregated from ~96 collection sources —
 * T-Pot honeypots, ThreatFox relays, phishing kits, stealer logs) via the
 * single-value lookup endpoint:
 *
 *   GET /api/v1/iocs/lookup?value={value}    (docs: the parameter is `value`)
 *
 * Verified live 2026-10-17:
 *   - Hit:  HTTP 200 {"found":true, confidence_score, is_active, tags,
 *            context, source:{name,type}, threat_actor, first/last_seen, …}
 *   - Miss: HTTP 404 {"found":false,"value":"8.8.8.8"} — a clean negative,
 *            mapped to `clean` (same convention as maltiverse).
 *   - The documented `/check/{value}` route currently answers 404 even for
 *            values present in the list (verified live against two of their
 *            own rows), so `lookup` is the surface that actually works.
 *   - Auth: anonymous session cookie minted by getCtiwatchSession() (cached
 *            12h; the cookie's Max-Age is 24h) or `CTIWATCH_API_KEY` when
 *            configured. Without either, the lookup 401s and the fan-out
 *            records a typed `unauthorized` error rather than a false clean.
 *
 * Score: CTIWatch's own `confidence_score` (0–100) passes through. It is their
 * computed aggregate, not a raw observation count, so it is used as-is:
 * anything found in an IOC database is at least suspicious; ≥ 70 (their
 * stronger honeypot/relay consensus) maps to malicious.
 *
 * Subrequest cost: 1 lookup per indicator, plus the session mint only when
 * the 12h cache is cold. Result caching is the fan-out's shared batched KV —
 * this adapter never touches Cache API or KV itself (the session helper's
 * single Cache API read is auth state, not a result cache).
 */

const SUPPORTED_TYPES = new Set(['ipv4', 'ipv6', 'domain', 'url', 'hash', 'email']);
const LOOKUP_ENDPOINT = 'https://ctiwatch.com/api/v1/iocs/lookup';

interface CtiwatchLookupHit {
  found?: boolean;
  value?: string;
  type?: string;
  confidence_score?: number | string | null;
  is_active?: boolean;
  first_seen?: string | null;
  last_seen?: string | null;
  tags?: unknown;
  context?: string | null;
  source?: { name?: string; type?: string } | null;
  threat_actor?: { name?: string } | null;
}

/** `confidence_score` may arrive as a string; clamp to the 0–100 band. */
function toScore(raw: unknown): number {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number.parseFloat(raw) : NaN;
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

export const ctiwatch: ProviderAdapter = async (indicator, env, signal) => {
  const now = new Date().toISOString();
  const base = (status: ProviderResult['status'], extra: Partial<ProviderResult> = {}): ProviderResult => ({
    source: 'ctiwatch',
    status,
    score: 0,
    verdict: 'unknown',
    raw_summary: {},
    tags: [],
    fetched_at: now,
    cached: false,
    ...extra,
  });

  if (!SUPPORTED_TYPES.has(indicator.type)) return base('unsupported');

  try {
    const headers: Record<string, string> = {
      accept: 'application/json',
      'user-agent': 'pranithjain.qzz.io DFIR toolkit',
    };
    if (env.CTIWATCH_API_KEY) {
      headers['X-Api-Key'] = env.CTIWATCH_API_KEY;
    } else {
      const cookie = await getCtiwatchSession();
      if (cookie) headers.cookie = `cti_anon=${cookie}`;
    }

    const res = await fetch(`${LOOKUP_ENDPOINT}?value=${encodeURIComponent(indicator.value)}`, {
      headers,
      signal,
    });

    // A miss is the documented 404 envelope `{found:false}`. Any other 404
    // (no envelope) is treated the same: no record, no adversarial claim.
    if (res.status === 404) {
      return base('ok', { score: 0, verdict: 'clean', raw_summary: { found: false, value: indicator.value } });
    }
    if (!res.ok) {
      return base('error', toProviderError(classifyResponseError(res)));
    }

    const body = (await res.json().catch(() => null)) as CtiwatchLookupHit | null;
    if (!body || typeof body !== 'object') {
      return base('error', {
        error: 'parse: invalid JSON envelope',
        error_code: 'parse',
        error_tags: ['parse'],
      });
    }
    if (body.found !== true) {
      return base('ok', { score: 0, verdict: 'clean', raw_summary: { found: false, value: indicator.value } });
    }

    const score = toScore(body.confidence_score);
    const verdict: Verdict = score >= 70 ? 'malicious' : 'suspicious';
    const upstreamTags = Array.isArray(body.tags)
      ? [...new Set(body.tags.filter((t): t is string => typeof t === 'string'))].slice(0, 8)
      : [];

    return base('ok', {
      score,
      verdict,
      raw_summary: {
        found: true,
        type: typeof body.type === 'string' ? body.type : indicator.type,
        confidence_score: score,
        is_active: body.is_active === true,
        first_seen: typeof body.first_seen === 'string' ? body.first_seen : null,
        last_seen: typeof body.last_seen === 'string' ? body.last_seen : null,
        source_name: body.source?.name ?? null,
        source_type: body.source?.type ?? null,
        context: typeof body.context === 'string' ? body.context.slice(0, 300) : null,
        threat_actor: body.threat_actor?.name ?? null,
      },
      tags: [...upstreamTags, 'ioc-db'],
    });
  } catch (err) {
    return base('error', toProviderError(classifyThrownError(err)));
  }
};
