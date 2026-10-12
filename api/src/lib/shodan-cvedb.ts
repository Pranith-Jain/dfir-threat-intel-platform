/**
 * Shodan InternetDB / CVEDB enrichment.
 *
 * `cvedb.shodan.io` was already called from the report gatherer and two copilot
 * paths, so the data existed and was unreachable from any surface a human
 * browses. Mjolnir's CVE table uses vulnerable-host count as a primary sort
 * key, which is the right call: "how many hosts on the internet are running
 * this" is the fastest available proxy for how much this matters to you, and
 * it is the one signal no other source in the platform carries.
 *
 * Both endpoints are keyless. CVEDB returns 404 for an unknown CVE, which is a
 * normal answer rather than an error, so it must not be reported as a failure.
 */
import type { Env } from '../env';
import { logError } from '../lib/logger';

const CVEDB = 'https://cvedb.shodan.io/cve';
const INTERNETDB = 'https://internetdb.shodan.io';

const CACHE_TTL = 6 * 3600;
const TIMEOUT_MS = 6_000;

/**
 * `cvedb.shodan.io` CVE record.
 *
 * Only the fields the platform can actually use are typed. The upstream returns
 * more (and has changed shape before), so anything else is left unclaimed
 * rather than asserted and then wrong.
 */
export interface ShodanCveDb {
  cve: string;
  summary: string | null;
  cvss: number | null;
  epss: number | null;
  rankingEpss: number | null;
  kev: boolean | null;
  /** A STRING upstream, not a boolean. Easy to get wrong, so it is typed as one. */
  ransomwareCampaign: string | null;
  proposeAction: string | null;
  references: string[];
}

export interface ShodanHostCounts {
  /** Internet-exposed hosts running the affected product, when Shodan knows. */
  hosts: number | null;
  /** Distinct services seen across those hosts. */
  services: number | null;
  /** Representative ports, for display. Not a complete list. */
  ports: number[];
}

function cacheKey(cve: string): string {
  return `https://shodan-cvedb.internal/${cve}`;
}

function readCache(env: Env, cve: string): Promise<ShodanCveDb | null> {
  return caches.default
    .match(new Request(cacheKey(cve)))
    .then(async (hit) => {
      if (!hit) return null;
      const parsed = (await hit.json()) as ShodanCveDb | null;
      return parsed && typeof parsed.cve === 'string' ? parsed : null;
    })
    .catch(() => null);
}

function writeCache(env: Env, cve: string, value: ShodanCveDb): Promise<void> {
  return caches.default
    .put(
      new Request(cacheKey(cve)),
      new Response(JSON.stringify(value), {
        headers: {
          'content-type': 'application/json',
          // The cache key encodes the id, so a response body is safe to cache
          // by this URL alone.
          'cache-control': `public, max-age=${CACHE_TTL}`,
        },
      })
    )
    .catch(() => undefined);
}

/**
 * Fetch one CVE's Shodan CVEDB record.
 *
 * Returns null on 404 (unknown CVE) and on transport failure; those are
 * deliberately indistinguishable to the caller, because a missing record and a
 * network blip both mean "we have no Shodan data for this" and neither should
 * surface as an error to an analyst mid-triage.
 */
export async function shodanCveDb(env: Env, cve: string): Promise<ShodanCveDb | null> {
  const id = cve.toUpperCase();
  const cached = await readCache(env, id);
  if (cached) return cached;

  try {
    const res = await fetch(`${CVEDB}/${id}`, {
      headers: { accept: 'application/json', 'user-agent': 'pranithjain-dfir/1.0' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;

    const d = (await res.json()) as Record<string, unknown>;
    // v3 is preferred over the legacy `cvss` field where both are present,
    // matching the selection order used everywhere else in the platform.
    const cvss = typeof d.cvss_v3 === 'number' ? d.cvss_v3 : typeof d.cvss === 'number' ? d.cvss : null;
    const epss = typeof d.epss === 'number' ? d.epss : null;
    const ransomware = typeof d.ransomware_campaign === 'string' ? d.ransomware_campaign : null;

    const record: ShodanCveDb = {
      cve: id,
      summary: typeof d.summary === 'string' ? d.summary : null,
      cvss,
      epss,
      rankingEpss: typeof d.ranking_epss === 'number' ? d.ranking_epss : null,
      kev: typeof d.kev === 'boolean' ? d.kev : null,
      ransomwareCampaign: ransomware,
      proposeAction: typeof d.propose_action === 'string' ? d.propose_action : null,
      references: Array.isArray(d.references) ? d.references.filter((r): r is string => typeof r === 'string') : [],
    };

    await writeCache(env, id, record);
    return record;
  } catch (err) {
    logError('shodan cvedb fetch failed', err);
    return null;
  }
}

/**
 * Internet-exposed host count for an IP.
 *
 * This is the per-IP path, not per-CVE. Shodan's CVEDB record carries no host
 * total, so the count that matters for "how many of me are exposed" is the
 * one InternetDB reports for a specific address. Kept here so the two Shodan
 * sources share a module, a cache convention and a timeout policy rather than
 * growing into two unrelated helpers.
 */
export async function shodanInternetDb(
  env: Env,
  ip: string
): Promise<(ShodanHostCounts & { ip: string; hostnames: string[]; tags: string[] }) | null> {
  const key = `https://shodan-internetdb.internal/${ip}`;

  const hit = await caches.default.match(new Request(key)).catch(() => null);
  if (hit) {
    const cached = (await hit.json()) as ShodanHostCounts & { ip: string; hostnames: string[]; tags: string[] };
    if (cached && cached.ip === ip) return cached;
  }

  try {
    const res = await fetch(`${INTERNETDB}/${ip}`, {
      headers: { accept: 'application/json', 'user-agent': 'pranithjain-dfir/1.0' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;

    const d = (await res.json()) as {
      hostnames?: string[];
      ports?: number[];
      cves?: string[];
      tags?: string[];
    };

    const ports = Array.isArray(d.ports) ? d.ports.filter((p): p is number => typeof p === 'number') : [];
    const record = {
      ip,
      hosts: 1,
      services: ports.length,
      ports: ports.slice(0, 12),
      hostnames: Array.isArray(d.hostnames) ? d.hostnames : [],
      tags: Array.isArray(d.tags) ? d.tags : [],
    };

    await caches.default
      .put(
        new Request(key),
        new Response(JSON.stringify(record), {
          headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_TTL}` },
        })
      )
      .catch(() => undefined);

    return record;
  } catch (err) {
    logError('shodan internetdb fetch failed', err);
    return null;
  }
}
