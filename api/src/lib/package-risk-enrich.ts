/**
 * Risk enrichment for a package verdict: CVSS, EPSS and KEV for the CVEs behind
 * its advisories.
 *
 * OSV advisories carry CVE ids but not scores, and a package risk score without
 * exploitability data is the "no advisories means safe" failure mode again one
 * level down. So: collect the CVE ids, score them once, and hand the result to
 * `assessPackageRisk`.
 *
 * Every failure path is a degraded result rather than an error. A package with
 * no network access to EPSS should still get a `malicious` verdict and a 40-point
 * score, not a 500 — the binary answer is more valuable than the precise one.
 */
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { extractCveIds } from './cve-id';
import { enrichEpssBulk } from './cve-enrich';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_CVE = (id: string) => `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`;

const TIMEOUT_MS = 8_000;
const CACHE_TTL = 3600;
const MAX_CVES = 10;

export interface RiskEnrichment {
  /** Highest CVSS base score across the package's CVEs. */
  cvss: number | null;
  /** Highest EPSS across the package's CVEs, 0-1. */
  epss: number | null;
  kev: boolean;
  cves: string[];
  newestAgeDays: number | null;
  /** True when any input was unavailable, so the caller can say the score is partial. */
  degraded: boolean;
}

interface MinimalAdvisory {
  id: string;
  published?: string;
  withdrawn?: boolean;
}

/** Cached KEV id set, refreshed at most hourly. */
let kevPromise: Promise<Set<string> | null> | null = null;
let kevFetchedAt = 0;
const KEV_REFRESH_MS = 3_600_000;

async function loadKevSet(): Promise<Set<string> | null> {
  if (Date.now() - kevFetchedAt > KEV_REFRESH_MS) {
    kevFetchedAt = Date.now();
    kevPromise = (async () => {
      try {
        const res = await fetch(KEV_URL, {
          headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
          cf: { cacheTtl: 3600, cacheEverything: true },
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (!res.ok) return null;
        const body = (await res.json()) as { vulnerabilities?: Array<{ cveID?: string }> };
        return new Set((body.vulnerabilities ?? []).map((v) => (v.cveID ?? '').toUpperCase()).filter(Boolean));
      } catch (err) {
        logError('kev set load failed', err);
        return null;
      }
    })();
  }
  return kevPromise;
}

async function fetchCvss(cve: string): Promise<number | null> {
  const key = `https://pkg-risk-cvss.internal/${cve}`;
  try {
    const hit = await caches.default.match(new Request(key));
    if (hit) return ((await hit.json()) as { score: number | null }).score;
  } catch {
    /* fall through to fetch */
  }

  try {
    const res = await fetch(NVD_CVE(cve), {
      headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
      cf: { cacheTtl: CACHE_TTL, cacheEverything: true },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as {
      vulnerabilities?: Array<{
        cve?: {
          metrics?: {
            cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
            cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
          };
        };
      }>;
    };
    const m = body.vulnerabilities?.[0]?.cve?.metrics;
    // Same selection order as everywhere else in the platform: v3.1, then v3.0.
    const score = m?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? m?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? null;

    await caches.default
      .put(
        new Request(key),
        new Response(JSON.stringify({ score }), {
          headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_TTL}` },
        })
      )
      .catch(() => undefined);
    return typeof score === 'number' ? score : null;
  } catch (err) {
    logError('nvd cvss fetch failed', err);
    return null;
  }
}

export async function enrichForRisk(env: Env, advisories: MinimalAdvisory[]): Promise<RiskEnrichment> {
  // CVE ids across every advisory body. `MAL-*` records are OpenSSF's own
  // namespace and carry no CVE, so they contribute nothing here — which is
  // correct, since a malicious package is scored by the malicious flag alone.
  const ids = new Set<string>();
  for (const a of advisories) {
    for (const id of extractCveIds(`${a.id}\n`)) ids.add(id);
  }
  const cves = [...ids].slice(0, MAX_CVES);

  const newestPublish = advisories
    .map((a) => (a.published ? Date.parse(a.published) : NaN))
    .filter(Number.isFinite)
    .sort((a, b) => b - a)[0];
  const newestAgeDays = newestPublish != null ? Math.max(0, (Date.now() - newestPublish) / 86_400_000) : null;

  if (cves.length === 0) {
    return {
      cvss: null,
      epss: null,
      kev: false,
      cves: [],
      newestAgeDays: newestAgeDays == null ? null : Number(newestAgeDays.toFixed(1)),
      // No CVEs is a real state, not a failure: a MAL- advisory has none.
      degraded: false,
    };
  }

  const kevSet = await loadKevSet();
  const scores = await Promise.all(cves.map((c) => fetchCvss(c)));
  const observed = scores.filter((s): s is number => typeof s === 'number');
  const cvss = observed.length > 0 ? Math.max(...observed) : null;
  const kev = kevSet ? cves.some((c) => kevSet.has(c)) : false;

  let epss: number | null = null;
  try {
    const { scores: epssScores } = await enrichEpssBulk(cves);
    const values = [...epssScores.values()].map((v) => v.score);
    epss = values.length > 0 ? Math.max(...values) : null;
  } catch (err) {
    logError('epss bulk failed for package risk', err);
  }

  return {
    cvss,
    epss,
    kev,
    cves,
    newestAgeDays: newestAgeDays == null ? null : Number(newestAgeDays.toFixed(1)),
    // Degraded when EPSS is missing or KEV could not be loaded: the score is
    // then built from a subset of its inputs and the caller should say so.
    degraded: epss == null || kevSet == null || observed.length < cves.length,
  };
}
