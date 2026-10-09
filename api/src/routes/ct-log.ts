// ssrf-audit: accept-reason `?target=` must match a bare-domain regex before use,
// then becomes the `q=%.<target>` QUERY PARAMETER of the fixed crt.sh host.
// The fetch target is always crt.sh. Not SSRF-reachable.
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';

interface CrtShCert {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  entry_timestamp: string;
}

interface CertResult {
  id: number;
  common_name: string;
  names: string[];
  issuer: string;
  issuer_organization?: string;
  not_before: string;
  not_after: string;
  serial: string;
  days_until_expiry: number;
  days_since_issue: number;
  ct_policy_compliant: boolean;
  suspicious_patterns: string[];
  source: 'crt.sh' | 'certspotter' | 'certstream';
}

interface CTLogResponse {
  total: number;
  results: CertResult[];
  target: string;
  filters_applied?: {
    issuer?: string;
    min_validity_days?: number;
    max_validity_days?: number;
    suspicious_only?: boolean;
  };
  analysis?: {
    unique_subdomains: string[];
    issuer_diversity: Record<string, number>;
    wildcard_certs: number;
    short_validity_certs: number;
    total_sans: number;
  };
  timestamp: string;
}

const CRT_SH_TIMEOUT = 15_000;
// crt.sh is fronted by a flaky Postgres+web tier and 502s/503s under load
// far more often than IA. One short retry catches the bulk of those blips
// before they surface as a silent total:0 to the analyst.
const CRT_SH_RETRY_DELAY_MS = 1_000;
// Typosquats sit within a couple of single-character edits of the base
// domain (swapped/dropped/added/transposed letters). >2 edits is almost
// always an unrelated string, so a tight threshold avoids the flood of
// false positives the old length-only heuristic produced.
const TYPOSQUAT_MAX_DISTANCE = 2;

// Classic iterative two-row Levenshtein edit distance. Short-circuits once
// the running minimum for a row exceeds `max`, so we never pay for long
// unrelated strings (the common case for SANs/subdomains).
function levenshtein(a: string, b: string, max: number): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1, // deletion
        curr[j - 1] + 1, // insertion
        prev[j - 1] + cost // substitution
      );
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > max) return max + 1;
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[b.length];
}

function parseIssuer(org?: string): { name: string; organization?: string } {
  if (!org) return { name: '' };
  const parts = org.split(',');
  const name = parts[0]?.trim() || '';
  const orgMatch = org.match(/O=([^,]+)/);
  return { name, organization: orgMatch?.[1]?.trim() };
}

function categorizeSuspicious(cert: CrtShCert, baseDomain: string): string[] {
  const patterns: string[] = [];
  const names = cert.name_value
    ? cert.name_value
        .split('\n')
        .map((n) => n.trim())
        .filter(Boolean)
    : [cert.common_name];

  for (const name of names) {
    if (name.startsWith('*.')) {
      patterns.push('wildcard_cert');
      const wildcardName = name.slice(2);
      if (
        wildcardName.includes(baseDomain) === false &&
        baseDomain.includes(wildcardName?.split('.')[0] ?? '') === false
      ) {
        patterns.push('wildcard_scope_mismatch');
      }
    }

    // Typosquat detection: only flag names that are a near-miss of the base
    // domain by edit distance — NOT legitimate subdomains of it. The old
    // length-only check tagged virtually every SAN/subdomain (any name within
    // 3 chars of the base length), drowning real squats in false positives.
    // Compare the bare hostname (wildcard prefix stripped); skip the base
    // domain itself and anything that is genuinely a subdomain of the base.
    const bare = name.startsWith('*.') ? name.slice(2) : name;
    if (
      bare !== baseDomain &&
      !bare.endsWith('.' + baseDomain) &&
      levenshtein(bare, baseDomain, TYPOSQUAT_MAX_DISTANCE) <= TYPOSQUAT_MAX_DISTANCE
    ) {
      patterns.push('typosquat_candidate');
    }

    const suspiciousWords = ['secure', 'login', 'verify', 'account', 'update', 'payment', 'support', 'admin'];
    if (suspiciousWords.some((w) => name.toLowerCase().includes(w)) && !name.includes(baseDomain)) {
      patterns.push('suspicious_subdomain');
    }
  }

  const notBefore = new Date(cert.not_before);
  const notAfter = new Date(cert.not_after);
  const validityDays = Math.ceil((notAfter.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24));

  if (validityDays < 30) patterns.push('short_validity_lt30d');
  if (validityDays < 7) patterns.push('short_validity_lt7d');

  const now = new Date();
  if (notAfter < now) patterns.push('expired');

  return Array.from(new Set(patterns));
}

function transientStatus(s: number): boolean {
  // crt.sh's flake set: 502/503/504 when the backing Postgres/web tier is
  // saturated, plus 520-524 from its Cloudflare front when the origin slows.
  return s === 502 || s === 503 || s === 504 || (s >= 520 && s <= 524);
}

async function fetchCrtSh(target: string): Promise<CrtShCert[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(target)}&output=json`;

  // crt.sh 502s/times out under load far too often to fetch once — a single
  // miss surfaces as a silent total:0. Attempt 1 → on a transient 5xx or
  // timeout, wait briefly and retry once. A non-transient response (4xx, or
  // a successful body) returns immediately.
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, CRT_SH_RETRY_DELAY_MS));
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(CRT_SH_TIMEOUT),
        headers: { 'User-Agent': 'pranithjain-dfir/1.0' },
      });
      if (res.ok) {
        try {
          const data = await res.json();
          return Array.isArray(data) ? data : [];
        } catch (_catchErr) {
          logError('fetchCrtSh failed', _catchErr);
          // crt.sh occasionally returns an HTML error page with a 200 under
          // load; treat as transient so the retry can catch a clean body.
          continue;
        }
      }
      // Non-transient upstream status (e.g. 4xx) — retrying won't help.
      if (!transientStatus(res.status)) return [];
    } catch (_catchErr) {
      logError('fetchCrtSh failed', _catchErr);
      // AbortError (timeout) or network error — fall through to the retry.
    }
  }
  return [];
}

export async function ctLogHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const target = (c.req.query('target') ?? '').trim();
  if (!target) return badRequest(c, 'missing target parameter');

  const isDomain = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  if (!isDomain.test(target)) {
    return badRequest(c, 'invalid target format (must be domain)');
  }

  const issuerFilter = c.req.query('issuer')?.trim().toLowerCase();
  const minValidityDays = c.req.query('min_validity_days');
  const maxValidityDays = c.req.query('max_validity_days');
  const suspiciousOnly = c.req.query('suspicious') === 'true';

  // Cache-API first (free, per-colo, no KV). Keyed on target + filters so
  // repeated lookups for the same domain are instant. crt.sh is slow (2-10s)
  // and rate-limits aggressively — caching is essential.
  const cacheKey = `ct-log:${target}:${issuerFilter ?? ''}:${minValidityDays ?? ''}:${maxValidityDays ?? ''}:${suspiciousOnly ? 1 : 0}`;
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(`https://ct-log-cache.internal/v1/${encodeURIComponent(cacheKey)}`);
  const cached = await cache.match(cacheReq);
  if (cached) return new Response(cached.body, cached);

  try {
    const rawCerts = await fetchCrtSh(target);

    let results = rawCerts.slice(0, 100).map((cert) => {
      const names = cert.name_value
        ? cert.name_value
            .split('\n')
            .map((n) => n.trim())
            .filter(Boolean)
        : [cert.common_name];
      const { name: issuerName, organization } = parseIssuer(cert.issuer_name);

      const notBefore = new Date(cert.not_before);
      const notAfter = new Date(cert.not_after);
      const now = new Date();
      const daysUntilExpiry = Math.ceil((notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      const daysSinceIssue = Math.floor((now.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24));

      return {
        id: cert.id,
        common_name: cert.common_name,
        names,
        issuer: issuerName,
        issuer_organization: organization,
        not_before: cert.not_before,
        not_after: cert.not_after,
        serial: cert.serial_number,
        days_until_expiry: daysUntilExpiry,
        days_since_issue: daysSinceIssue,
        ct_policy_compliant: cert.issuer_ca_id > 0,
        suspicious_patterns: categorizeSuspicious(cert, target),
        source: 'crt.sh' as const,
      };
    });

    if (issuerFilter) {
      results = results.filter(
        (r) =>
          r.issuer.toLowerCase().includes(issuerFilter) ||
          (r.issuer_organization && r.issuer_organization.toLowerCase().includes(issuerFilter))
      );
    }

    if (minValidityDays) {
      const min = parseInt(minValidityDays);
      if (!Number.isNaN(min)) {
        results = results.filter((r) => r.days_until_expiry >= min);
      }
    }

    if (maxValidityDays) {
      const max = parseInt(maxValidityDays);
      if (!Number.isNaN(max)) {
        results = results.filter((r) => r.days_until_expiry <= max);
      }
    }

    if (suspiciousOnly) {
      results = results.filter((r) => r.suspicious_patterns.length > 0);
    }

    const allNames = results.flatMap((r) => r.names);
    const subdomains = allNames
      .filter((n) => n.endsWith('.' + target) || n !== target)
      .filter((n) => !n.startsWith('*.') || n.slice(2).endsWith('.' + target));

    const issuerCounts: Record<string, number> = {};
    for (const r of results) {
      const key = r.issuer_organization || r.issuer;
      issuerCounts[key] = (issuerCounts[key] || 0) + 1;
    }

    const wildcardCount = results.filter((r) => r.suspicious_patterns.includes('wildcard_cert')).length;
    const shortValidityCount = results.filter((r) => r.suspicious_patterns.includes('short_validity_lt30d')).length;

    const response: CTLogResponse = {
      total: results.length,
      results,
      target,
      filters_applied: {
        ...(issuerFilter && { issuer: issuerFilter }),
        ...(minValidityDays && { min_validity_days: parseInt(minValidityDays) }),
        ...(maxValidityDays && { max_validity_days: parseInt(maxValidityDays) }),
        ...(suspiciousOnly && { suspicious_only: true }),
      },
      analysis: {
        unique_subdomains: Array.from(new Set(subdomains)),
        issuer_diversity: issuerCounts,
        wildcard_certs: wildcardCount,
        short_validity_certs: shortValidityCount,
        total_sans: allNames.length,
      },
      timestamp: new Date().toISOString(),
    };

    return c.json(response, 200, {
      'Cache-Control': 'public, max-age=3600',
    });
  } catch (err) {
    logError('handler failed', err);
    return c.json(
      {
        error: 'CT log lookup failed',
        message: err instanceof Error ? err.message : 'Unknown error',
      },
      502,
      { 'Cache-Control': 'no-store' }
    );
  }
}
