/**
 * FortiBleed Checker — detect vulnerable FortiGate SSL VPN instances.
 *
 * Checks for CVE-2024-21762 (FortiGate FortiOS out-of-bound write RCE, CVSS 9.8)
 * and related FortiGate CVEs. Uses Shodan/FOFA-style passive detection.
 *
 * Detection method: HTTP response fingerprinting for FortiGate login pages
 * and SSL certificate analysis.
 *
 * Abuse-channel hardening (#301): this endpoint is an open port-scanner by
 * design, so every layer that can bound its cost does:
 *   - targets are SSRF-validated before any connection, and each fetch is
 *     pinned + redirect-bounded via lib/ssrf-guard (a redirect could otherwise
 *     walk the probe onto an internal host after the initial check);
 *   - results are cached per target in the Cache API, so repeat scans of the
 *     same host are served, not re-probed;
 *   - the GET sits on the strict limiter bucket (lib/ratelimit.ts) and the
 *     batch POST is behind the Turnstile capacity gate when it is enabled
 *     (lib/turnstile.ts) — callers can always use an API key instead.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { assertPublicHost, pinnedFetch, pinnedFetchFollow } from '../lib/ssrf-guard';
import { cachedJson, routeCacheGet, routeCachePut } from '../lib/route-cache';

interface FortiGateResult {
  target: string;
  isFortiGate: boolean;
  version: string | null;
  vulnerability: string | null;
  cvss: number | null;
  severity: string | null;
  details: string[];
  recommendations: string[];
}

const FORTECVE = {
  id: 'CVE-2024-21762',
  description:
    'FortiOS out-of-bound write vulnerability in SSL VPN may allow remote code execution via specially crafted HTTP requests.',
  cvss: 9.8,
  severity: 'CRITICAL',
  affectedVersions: [
    'FortiOS 7.4.0 through 7.4.2',
    'FortiOS 7.2.0 through 7.2.6',
    'FortiOS 7.0.0 through 7.0.12',
    'FortiOS 6.4.0 through 6.4.14',
    'FortiOS 6.2.0 through 6.2.15',
    'FortiProxy 7.4.0 through 7.4.3',
    'FortiProxy 7.2.0 through 7.2.7',
    'FortiProxy 7.0.0 through 7.0.10',
    'FortiProxy 6.4.0 through 6.4.13',
    'FortiProxy 6.2.0 through 6.2.13',
  ],
  fixedVersions: [
    'FortiOS 7.4.3+',
    'FortiOS 7.2.7+',
    'FortiOS 7.0.13+',
    'FortiOS 6.4.15+',
    'FortiOS 6.2.16+',
    'FortiProxy 7.4.4+',
    'FortiProxy 7.2.8+',
    'FortiProxy 7.0.11+',
    'FortiProxy 6.4.14+',
    'FortiProxy 6.2.14+',
  ],
};

async function detectFortiGate(target: string): Promise<FortiGateResult> {
  const result: FortiGateResult = {
    target,
    isFortiGate: false,
    version: null,
    vulnerability: null,
    cvss: null,
    severity: null,
    details: [],
    recommendations: [],
  };

  // SSRF guard: this probes the target across 4 ports with raw fetch, so
  // private/internal hosts must be rejected before any connection attempt.
  let hostname: string | null = null;
  try {
    hostname = new URL(target.includes('://') ? target : `https://${target}`).hostname || null;
  } catch {
    hostname = null;
  }
  if (!hostname) {
    result.details.push('Invalid target');
    return result;
  }
  const hostCheck = await assertPublicHost(hostname);
  if (!hostCheck.ok) {
    result.details.push('Target host not allowed (private/internal address)');
    return result;
  }

  const baseUrl = target.startsWith('http') ? target : `https://${target}`;
  const ports = [443, 8443, 10443, 80];

  for (const port of ports) {
    try {
      const url =
        port === 443 || port === 80
          ? baseUrl
          : `${target.startsWith('http') ? target.split('://')[0] : 'https'}://${target}:${port}`;

      // Pinned + redirect-bounded (#301): `assertPublicHost` above validated
      // the hostname once, but `redirect: 'follow'` would let the probed host
      // (or anything it redirects through) walk this probe onto an internal
      // address after that check. pinnedFetchFollow re-validates and re-pins
      // every hop and caps the chain; the signal bounds the whole chain.
      const res = await pinnedFetchFollow(url, {
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; FortiBleed-Checker/1.0)' },
      });

      const headers = Object.fromEntries(res.headers.entries());
      const body = await res.text().catch(() => '');

      // Check for FortiGate indicators
      const indicators = [
        /fortigate/i.test(body),
        /fortinet/i.test(body),
        /fortios/i.test(body),
        /\/remote\/login/i.test(body),
        /\/login\.css/i.test(body) && /forti/i.test(body),
        /fgt_lang/i.test(body) || /lang_token/i.test(body),
        /SSL-VPN/i.test(body),
        /server:\s*FortiGate/i.test(headers['server'] || ''),
        /<title>.*FortiGate/i.test(body),
      ];

      if (indicators.some(Boolean)) {
        result.isFortiGate = true;
        result.details.push(`FortiGate detected on port ${port}`);

        // Version detection
        const versionMatch =
          body.match(/Forti(?:Gate|OS)\s+(?:v)?(\d+\.\d+\.?\d*)/i) || body.match(/version["\s:=]+(\d+\.\d+\.?\d*)/i);
        if (versionMatch) {
          result.version = versionMatch[1] ?? null;
          result.details.push(`Version: ${result.version}`);
        }

        // SSL certificate check
        if (res.url.startsWith('https')) {
          try {
            const certInfo = await fetchCertInfo(target, port);
            if (certInfo) result.details.push(`Certificate: ${certInfo}`);
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
            /* skip */
          }
        }

        break;
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* port not reachable */
    }
  }

  // Vulnerability assessment
  if (result.isFortiGate) {
    result.vulnerability = FORTECVE.id;
    result.cvss = FORTECVE.cvss;
    result.severity = FORTECVE.severity;
    result.details.push(`Potential exposure to ${FORTECVE.id} (CVSS ${FORTECVE.cvss})`);

    if (result.version) {
      const parts = result.version.split('.').map(Number);
      const ver = (parts[0] || 0) * 100 + (parts[1] || 0) * 10 + (parts[2] || 0);
      const patched = ver >= 743 || ver >= 727 || ver >= 7013 || ver >= 6415 || ver >= 6216;

      if (patched) {
        result.severity = 'INFO';
        result.details.push('Version appears patched against CVE-2024-21762');
      } else {
        result.details.push('Version is likely vulnerable to CVE-2024-21762');
      }
    }

    result.recommendations = [
      'Upgrade FortiOS to the latest patched version immediately',
      'If immediate upgrade is not possible, disable SSL VPN as a temporary mitigation',
      'Review SSL VPN access logs for suspicious activity',
      'Apply IPS signature for CVE-2024-21762 if available',
      'Restrict SSL VPN access to trusted IP ranges',
      "Monitor for indicators of compromise listed in Fortinet's advisory",
    ];
  }

  return result;
}

async function fetchCertInfo(target: string, port: number): Promise<string | null> {
  // Live TLS probe — pinned for the same reason as the port loop, and
  // `manual` redirects: a certificate probe has no business following a
  // redirect at all.
  try {
    const res = await pinnedFetch(`https://${target}:${port}`, {
      signal: AbortSignal.timeout(5000),
      method: 'HEAD',
    });
    return res.headers.get('server') || null;
  } catch (_catchErr) {
    logError('fetchCertInfo failed', _catchErr);
    return null;
  }
}

/**
 * How long a completed scan is cached per target. FortiGate version banners
 * and exposure do not change minute-to-minute; 15 minutes keeps the tool
 * useful for follow-up clicks while bounding how often one target can make
 * this platform egress probe it.
 */
const FORTIBLEED_CACHE_TTL_S = 900;

/** Per-target cache key, shared between the single and batch handlers. */
function fortibleedCacheKey(target: string): string {
  return `fortibleed:check:${target.trim().toLowerCase()}`;
}

export async function fortibleedCheckHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const target = (c.req.query('target') || '').trim();
  if (!target) return badRequest(c, 'target parameter required');

  // Cache-first (#301): repeat scans of the same host are the expected pattern
  // (a visitor re-checking a finding), and a cache hit spends none of the
  // egress/subrequest budget that makes this endpoint an abuse channel.
  return cachedJson(c, fortibleedCacheKey(target), FORTIBLEED_CACHE_TTL_S, () => detectFortiGate(target));
}

export async function fortibleedBatchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const body = (await c.req.json()) as { targets: string[] };
  if (!body.targets?.length) return badRequest(c, 'targets array required');

  const results = await Promise.all(
    body.targets.slice(0, 10).map(async (t) => {
      const key = fortibleedCacheKey(t);
      const hit = await routeCacheGet<FortiGateResult>(key);
      if (hit) return hit;
      const result = await detectFortiGate(t);
      c.executionCtx.waitUntil(routeCachePut(key, result, FORTIBLEED_CACHE_TTL_S));
      return result;
    })
  );
  return c.json({ results, total: results.length });
}
