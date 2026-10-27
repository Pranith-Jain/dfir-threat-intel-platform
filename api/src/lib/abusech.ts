/**
 * abuse.ch feed access — one place for URLs, auth headers, and the
 * ThreatFox JSON query.
 *
 * WHY THIS EXISTS
 *
 * On 2026-10-21 abuse.ch retired the anonymous file exports. Every legacy
 * download URL now answers HTTP 410 Gone:
 *
 *   https://urlhaus.abuse.ch/downloads/csv_recent/
 *   https://bazaar.abuse.ch/export/csv/recent/
 *   https://threatfox.abuse.ch/export/csv/recent/
 *   https://threatfox.abuse.ch/export/csv/urls/recent/
 *   https://threatfox.abuse.ch/downloads/hostfile/
 *
 * The replacements live under `*-api.abuse.ch/v2/files/exports/<Auth-Key>/…`
 * (Auth-Key in the PATH, not a header — that is abuse.ch's documented form
 * for file exports), or the JSON community APIs with an `Auth-Key` header.
 *
 * Before this module the URLs and headers were copy-pasted into ~12 files.
 * One upstream change therefore broke the briefing builder, the live IOC
 * firehose, the threat map, IOC correlation, the malware pages and the CTI
 * collector independently, and each copy had to be found and fixed by hand.
 * Callers now build every abuse.ch request here so the next change is a
 * one-file edit.
 *
 * The legacy URLs are still returned when no key is configured. That keeps
 * local dev and unit tests (which do not carry provider secrets) working
 * against their mocked fetch, and makes the failure mode explicit: without
 * a key the upstream answers 410 rather than silently returning nothing.
 */

import type { Env } from '../env';

/** The three abuse.ch platforms we consume in bulk. */
export type AbuseChFeedSource = 'urlhaus' | 'malwarebazaar' | 'threatfox';

/** The two platforms whose bulk export is a CSV file (Auth-Key in the path). */
type AbuseChCsvSource = Exclude<AbuseChFeedSource, 'threatfox'>;

/**
 * Legacy anonymous export URLs — retired upstream on 2026-10-21 (HTTP 410).
 * Kept only as the no-key fallback so a misconfigured deployment fails
 * loudly at the upstream instead of throwing locally with no diagnostic.
 */
export const LEGACY_ABUSECH_URLS: Record<AbuseChFeedSource, string> = {
  urlhaus: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
  malwarebazaar: 'https://bazaar.abuse.ch/export/csv/recent/',
  threatfox: 'https://threatfox.abuse.ch/export/csv/recent/',
};

/** Authenticated bulk-export roots (Auth-Key is the next path segment). */
const CSV_EXPORT_ROOTS: Record<AbuseChCsvSource, string> = {
  urlhaus: 'https://urlhaus-api.abuse.ch/v2/files/exports',
  malwarebazaar: 'https://mb-api.abuse.ch/v2/files/exports',
};

/** ThreatFox JSON community API — documented bulk query for up to 7 days. */
export const THREATFOX_API_URL = 'https://threatfox-api.abuse.ch/api/v1/';

/** Largest window `get_iocs` accepts (upstream max, not our choice). */
export const THREATFOX_MAX_DAYS = 7;

/**
 * Build the auth headers for an abuse.ch request.
 *
 * abuse.ch uses `Auth-Key` for header-authenticated endpoints. Existing
 * callers already send `Content-Type` / `user-agent`; merge rather than
 * replace so a caller's headers are never dropped.
 */
export function abuseChHeaders(authKey?: string, extra?: NonNullable<RequestInit['headers']>): Record<string, string> {
  const out: Record<string, string> = {};
  if (authKey) out['Auth-Key'] = authKey;
  if (extra) {
    const entries = extra instanceof Headers ? extra.entries() : Array.isArray(extra) ? extra : Object.entries(extra);
    for (const [k, v] of entries as Iterable<[string, string]>) out[k] = v;
  }
  return out;
}

/**
 * URL for a bulk CSV export. Returns the legacy URL when `authKey` is
 * absent (see the module header for why).
 */
export function abuseChExportUrl(source: AbuseChCsvSource, authKey?: string, file = 'recent.csv'): string {
  if (!authKey) return LEGACY_ABUSECH_URLS[source];
  return `${CSV_EXPORT_ROOTS[source]}/${encodeURIComponent(authKey)}/${file}`;
}

/**
 * API endpoint for one platform (POST JSON/form queries — `get_info`,
 * `get_iocs`, …). Same legacy-fallback rule as `abuseChExportUrl`: callers
 * without a key get the pre-2026-10-21 anonymous endpoint.
 */
export function abuseChApiUrl(source: AbuseChFeedSource, authKey?: string): string {
  if (source === 'threatfox') return authKey ? THREATFOX_API_URL : LEGACY_ABUSECH_URLS.threatfox;
  if (source === 'urlhaus') return authKey ? 'https://urlhaus-api.abuse.ch/v2/' : LEGACY_ABUSECH_URLS.urlhaus;
  return authKey ? 'https://mb-api.abuse.ch/api/v1/' : LEGACY_ABUSECH_URLS.malwarebazaar;
}

/**
 * Resolve a complete abuse.ch bulk-feed request (URL + init).
 *
 * - `urlhaus` / `malwarebazaar`: authenticated CSV export, `Auth-Key` in the
 *   path, so a plain GET works.
 * - `threatfox`: JSON `get_iocs` POST, `Auth-Key` header. There is no
 *   recent CSV export anymore; the only file export is a 6-month ZIP.
 *
 * `days` only applies to ThreatFox (its API is capped at 7).
 */
export function abuseChFeedRequest(
  source: AbuseChFeedSource,
  authKey?: string,
  opts: { file?: string; days?: number; init?: RequestInit } = {}
): { url: string; init: RequestInit } {
  const init = opts.init ?? {};
  // No key → the legacy anonymous endpoint (loud 410 upstream, mocked fetch
  // in tests). See the module header — this is deliberate, not a regression.
  if (!authKey) {
    return {
      url: LEGACY_ABUSECH_URLS[source],
      init: { ...init, headers: abuseChHeaders(undefined, init.headers) },
    };
  }
  if (source === 'threatfox') {
    const days = Math.min(Math.max(Math.trunc(opts.days ?? THREATFOX_MAX_DAYS), 1), THREATFOX_MAX_DAYS);
    return {
      url: THREATFOX_API_URL,
      init: {
        ...init,
        method: 'POST',
        headers: abuseChHeaders(authKey, {
          'Content-Type': 'application/json',
          ...(init.headers as Record<string, string> | undefined),
        }),
        body: JSON.stringify({ query: 'get_iocs', days }),
      },
    };
  }
  return {
    url: abuseChExportUrl(source, authKey, opts.file),
    init: { ...init, headers: abuseChHeaders(authKey, init.headers) },
  };
}

/** Convenience for the briefing builder, which has `Env` not a raw key. */
export function abuseChFeedRequestForEnv(
  env: Env | undefined,
  source: AbuseChFeedSource,
  opts?: { file?: string; days?: number; init?: RequestInit }
): { url: string; init: RequestInit } {
  return abuseChFeedRequest(source, env?.ABUSECH_AUTH_KEY, opts);
}

/**
 * Fetch ThreatFox `get_iocs` and return the raw JSON body.
 *
 * Returning text (not parsed objects) keeps the fetch and parse concerns
 * separate: `buildSummary('threatfox', body)` auto-detects JSON and maps it
 * through the same normalisation path the CSV used to use.
 *
 * Throws on non-2xx so callers can fall back to last-good data.
 */
export async function fetchThreatfoxExport(
  authKey: string | undefined,
  opts: {
    days?: number;
    timeoutMs?: number;
    fetchImpl?: typeof globalThis.fetch;
    signal?: AbortSignal;
  } = {}
): Promise<string> {
  const fetchFn = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const req = abuseChFeedRequest('threatfox', authKey, { days: opts.days ?? THREATFOX_MAX_DAYS });
  const signal = opts.signal ?? AbortSignal.timeout(opts.timeoutMs ?? 15_000);
  const res = await fetchFn(req.url, { ...req.init, signal });
  if (!res.ok) throw new Error(`threatfox feed ${res.status}`);
  const body = await res.text();
  if (!body.trim()) throw new Error('threatfox feed empty body');
  return body;
}

/**
 * True when `body` looks like the JSON community API rather than the legacy
 * CSV export. Used by the pure parser so the same `buildSummary` call works
 * for both shapes (and for fixtures that exercise the old format).
 */
export function looksLikeJson(body: string): boolean {
  const first = body.trimStart()[0];
  return first === '{' || first === '[';
}
