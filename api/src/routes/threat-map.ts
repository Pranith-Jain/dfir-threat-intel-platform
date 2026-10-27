import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { parseUrlhaus, parseIpsum, parsePlainTextIps, parseMalwarebazaar } from '../lib/ioc-feed-parsers';
import { trackEvent, visitorCountry } from '../lib/analytics';
import { abuseChFeedRequestForEnv, type AbuseChFeedSource } from '../lib/abusech';
import { buildSummary } from '../lib/ioc-feed-parsers';

/**
 * Cyber Threat Map
 *
 * Aggregates current malicious infrastructure indicators across IOC types:
 *   - IPs from URLhaus, ThreatFox, Ipsum, CINS Army, Bitwire — each
 *     batch-geolocated via ip-api.com and aggregated by country for the map.
 *   - URLs from URLhaus + ThreatFox.
 *   - Domains from ThreatFox.
 *   - File hashes from MalwareBazaar + ThreatFox.
 *
 * Cached 1h in Cache API so each visitor doesn't re-trigger the geolocation.
 */

/**
 * Exported so /api/v1/snapshot can read the same cached payload directly.
 *
 * v7: v6 fixed the memory blowup but then spent the whole subrequest budget
 * on per-IP Cache API reads, so the map rendered IPs with zero countries.
 * Geolocation is now one whole-set cache entry instead, and IPs are collected
 * under a per-source quota so CINS Army and Bitwire are not starved to zero by
 * URLhaus and ThreatFox filling the cap first.
 */
export const THREAT_MAP_CACHE_KEY = 'https://threat-map-cache.internal/v7-quota-geo';
const CACHE_KEY = THREAT_MAP_CACHE_KEY;
const CACHE_TTL_SECONDS = 3600;
// ip-api.com batch is 100 per request.
//
// MAX_IPS was 1000, which meant 10 SEQUENTIAL round-trips to a free-tier
// endpoint inside a single invocation. Combined with the duplicate parses that
// is what tipped this route into error 1102. 400 covers the map's needs — it
// renders aggregated countries, not an exhaustive list — in 4 batches, which
// matters because this plan allows 50 subrequests per invocation in total.
const MAX_IPS = 400;
const MAX_PER_TYPE = 60; // per non-IP IOC type (urls / domains / hashes)
const FETCH_TIMEOUT_MS = 12_000;
// A single batch that takes the full timeout, times the whole geolocation
// budget. Without this a partially-hung endpoint can hold the invocation open
// for batches x FETCH_TIMEOUT_MS.
const GEO_BUDGET_MS = 20_000;
const GEO_CACHE_TTL = 86_400;

interface CountryAgg {
  countryCode: string;
  country: string;
  count: number;
  sources: Record<string, number>;
  sample_ips: string[];
}

interface IocSample {
  value: string;
  source: string;
  context?: string;
  timestamp?: string;
}

interface IocTypeBucket {
  type: 'url' | 'domain' | 'hash';
  count: number;
  source_counts: Record<string, number>;
  recent: IocSample[];
}

interface ThreatMapResponse {
  generated_at: string;
  total_ips: number;
  countries: CountryAgg[];
  samples: Array<{ ip: string; country: string; countryCode: string; sources: string[] }>;
  source_counts: Record<string, number>;
  // New in v3: non-IP IOC types from the same feeds
  iocs_by_type: IocTypeBucket[];
  /**
   * Per-stage telemetry. An all-zero map and a working map look identical from
   * the response body alone, so this says which upstream lost the data.
   */
  diagnostics: {
    feeds: Record<string, { fetched: boolean; bytes: number }>;
    geo: GeoDiagnostics;
  };
}

interface IpApiBatchResult {
  query?: string;
  status?: string;
  country?: string;
  countryCode?: string;
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtl: 1800, cacheEverything: true },
    });
    if (res.status === 429) {
      // Aggregator — partial degradation is acceptable; just surface to ops.
      return null;
    }
    if (!res.ok) return null;
    return await res.text();
  } catch (_catchErr) {
    logError('fetchText failed', _catchErr);
    return null;
  }
}

/**
 * abuse.ch bulk fetch — authenticated v2 export / ThreatFox JSON API via the
 * shared helper. Same null-on-failure contract as `fetchText`.
 */
async function fetchAbuseCh(env: Env | undefined, source: AbuseChFeedSource): Promise<string | null> {
  try {
    const req = abuseChFeedRequestForEnv(env, source, { days: 7 });
    const res = await fetch(req.url, {
      ...req.init,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtl: 1800, cacheEverything: true },
    } as RequestInit);
    if (res.status === 429) return null;
    if (!res.ok) return null;
    const text = await res.text();
    return text.trim() ? text : null;
  } catch (_catchErr) {
    logError(`fetchAbuseCh(${source}) failed`, _catchErr);
    return null;
  }
}

/**
 * Geolocate IPs in batches of 100 against ip-api.com.
 *
 * Results are cached per IP for a day. Country assignment for an IP does not
 * change hour to hour, so a warm cache turns the whole stage into Cache-API
 * reads and a cold one only pays for the IPs it has never seen. The previous
 * shape re-geolocated the entire working set on every cache miss, which is the
 * difference between one invocation doing 4 requests and doing several hundred
 * across an hour of misses.
 */
/**
 * Per-stage geolocation telemetry.
 *
 * An empty map is indistinguishable from a working map with no data unless the
 * response says which stage lost the data, so it says so.
 */
interface GeoDiagnostics {
  requested: number;
  cachedHits: number;
  queried: number;
  resolved: number;
  batches: number;
  /** Why the loop stopped early, if it did. */
  stopReason: string | null;
  /** First upstream failure seen, including per-row `status: fail` answers. */
  sampleFailure: string | null;
}

interface GeoResult {
  out: Map<string, { country: string; countryCode: string }>;
  diag: GeoDiagnostics;
}

/**
 * Geolocate IPs via ip-api.com's 100-per-request batch endpoint.
 *
 * Subrequest budget is the binding constraint here, and this plan allows 50 per
 * invocation. Six feed fetches already cost six, and ip-api answers 100 IPs per
 * request, so MAX_IPS/100 batches is all the room there is.
 *
 * An earlier revision cached geolocation PER IP and read it back with
 * `caches.default.match()` for each one. Cache API reads count against the
 * subrequest limit, so a 400-IP working set spent its entire budget on cache
 * lookups and the batch call never happened — the map rendered with IPs and
 * zero countries. The whole working set is now cached as ONE entry instead:
 * one read, one write, and the cache entry expires with the route cache rather
 * than living for a day.
 */
const GEO_MAP_CACHE_KEY = 'https://threat-map-geo-map.internal/v1';

async function geolocateBatch(ips: string[]): Promise<GeoResult> {
  const out = new Map<string, { country: string; countryCode: string }>();
  const diag: GeoDiagnostics = {
    requested: ips.length,
    cachedHits: 0,
    queried: 0,
    resolved: 0,
    batches: 0,
    stopReason: null,
    sampleFailure: null,
  };
  if (ips.length === 0) return { out, diag };

  // Whole-set cache read: ONE subrequest, not one per IP.
  try {
    const hit = await caches.default.match(new Request(GEO_MAP_CACHE_KEY));
    if (hit) {
      const cached = (await hit.json()) as Record<string, { country: string; countryCode: string }>;
      if (cached && typeof cached === 'object') {
        for (const [ip, v] of Object.entries(cached)) {
          if (v?.countryCode) {
            out.set(ip, v);
            diag.cachedHits += 1;
          }
        }
      }
    }
  } catch {
    /* cache miss is the normal path */
  }

  // Only IPs this run has never geolocated cost an upstream request.
  const pending = ips.filter((ip) => !out.has(ip));
  if (pending.length === 0) return { out, diag };

  diag.queried = pending.length;
  const startedAt = Date.now();
  const writes: Promise<void>[] = [];

  for (let i = 0; i < pending.length; i += 100) {
    if (Date.now() - startedAt > GEO_BUDGET_MS) {
      diag.stopReason = `time budget (${GEO_BUDGET_MS}ms) exhausted after ${diag.batches} batches`;
      break;
    }
    const batch = pending.slice(i, i + 100);
    diag.batches += 1;
    try {
      const res = await fetch('http://ip-api.com/batch?fields=query,status,country,countryCode', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch.map((q) => ({ query: q }))),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.status === 429) {
        // ip-api.com free tier is 45 req/min from a single IP, shared per POP.
        diag.stopReason = `upstream rate limited (429) after ${diag.batches} batches`;
        break;
      }
      if (!res.ok) {
        diag.sampleFailure ??= `HTTP ${res.status} ${res.statusText}`;
        continue;
      }
      const data = (await res.json()) as IpApiBatchResult[];
      for (const row of data) {
        if (row.status === 'success' && row.query && row.countryCode && row.country) {
          const value = { country: row.country, countryCode: row.countryCode };
          out.set(row.query, value);
          diag.resolved += 1;
        } else if (!diag.sampleFailure) {
          // ip-api answers HTTP 200 with a per-row `status: fail` when it
          // dislikes an address, which is invisible unless captured.
          diag.sampleFailure = `row ${row.query ?? '?'}: ${row.status ?? 'no status'}`;
        }
      }
    } catch (err) {
      diag.sampleFailure ??= err instanceof Error ? err.message : String(err);
      logError('geolocateBatch failed', err);
      // Skip this batch; the next one may still succeed.
    }
  }

  // Persist the merged map so the next run pays at most one cache read.
  // Keyed without a date so the entry is reused across runs and expires on its
  // own TTL rather than accumulating one entry per hour.
  if (out.size > 0) {
    writes.push(
      caches.default.put(
        new Request(GEO_MAP_CACHE_KEY),
        new Response(JSON.stringify(Object.fromEntries(out)), {
          headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${GEO_CACHE_TTL}` },
        })
      )
    );
  }
  await Promise.allSettled(writes);
  return { out, diag };
}

/**
 * Pure-data fetcher exposed for /api/v1/snapshot. Same body the HTTP handler
 * returns, just without the Response/cache wrapping so the snapshot endpoint
 * can compose it without a worker-internal HTTP call.
 */
export async function fetchThreatMap(env?: Env): Promise<ThreatMapResponse> {
  // Fan out to all IOC feeds we have access to, in parallel.
  const [urlhausText, threatfoxText, ipsumText, cinsText, bitwireText, malwarebazaarText] = await Promise.all([
    fetchAbuseCh(env, 'urlhaus'),
    fetchAbuseCh(env, 'threatfox'),
    fetchText('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt'),
    fetchText('https://cinsscore.com/list/ci-badguys.txt'),
    fetchText('https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt'),
    fetchAbuseCh(env, 'malwarebazaar'),
  ]);

  // Parse each feed ONCE, then bucket from that single result.
  //
  // This previously called parseUrlhaus twice and parseThreatfox twice — once
  // for the IP pass and again for the url/domain/hash pass — re-walking a 7.9 MB
  // CSV each time. With csvLines now lazy the second walk stopped at its cap,
  // but the duplicate work and the duplicate entry arrays were still being
  // held simultaneously, which is what pushed this route past the Worker's
  // memory ceiling (error 1102).
  const PARSE_CAP = MAX_IPS + MAX_PER_TYPE * 4;

  const urlhausEntries = urlhausText ? parseUrlhaus(urlhausText, PARSE_CAP) : [];
  // ThreatFox: the authenticated path returns the JSON `get_iocs` shape, the
  // no-key fallback the retired CSV — buildSummary sniffs and normalises both.
  const threatfoxEntries = threatfoxText ? buildSummary('threatfox', threatfoxText, PARSE_CAP).entries : [];
  const malwarebazaarEntries = malwarebazaarText ? parseMalwarebazaar(malwarebazaarText, PARSE_CAP) : [];

  // Build a map of IP → set of sources, capped at MAX_IPS unique IPs.
  //
  // Per-source quota rather than first-come-first-served. URLhaus and
  // ThreatFox alone fill 400 slots on their own, so a global cap meant CINS
  // Army and Bitwire contributed exactly zero IPs while the page still listed
  // them as sources. The map is a consensus view, and a source that is
  // structurally incapable of appearing is worse than one that is absent —
  // it misrepresents how the picture was built.
  const IP_SOURCES = ['urlhaus', 'threatfox', 'ipsum', 'cinsarmy', 'bitwire'] as const;
  const PER_SOURCE_QUOTA = Math.floor(MAX_IPS / IP_SOURCES.length);
  const perSourceTaken = new Map<string, number>();

  const ipSources = new Map<string, Set<string>>();
  const addIp = (ip: string, source: string) => {
    const already = ipSources.has(ip);
    if (!already) {
      // Global cap backstop, in case many sources agree on the same addresses.
      if (ipSources.size >= MAX_IPS) return;
      const taken = perSourceTaken.get(source) ?? 0;
      if (taken >= PER_SOURCE_QUOTA) return;
      perSourceTaken.set(source, taken + 1);
      ipSources.set(ip, new Set());
    }
    ipSources.get(ip)!.add(source);
  };

  for (const e of urlhausEntries) {
    if (e.type !== 'url') continue;
    try {
      const host = new URL(e.value).hostname;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) addIp(host, 'urlhaus');
    } catch {
      // Skip a malformed URL rather than failing the whole map. A URLhaus row
      // with an unparseable value is upstream's problem, not ours, and one bad
      // row should not cost the other 33,000.
    }
  }
  for (const e of threatfoxEntries) {
    if (e.type === 'ipv4') addIp(e.value, 'threatfox');
  }
  // Ipsum is consensus-scored, so the IPs here have hits from 3+ source lists.
  if (ipsumText) {
    for (const e of parseIpsum(ipsumText, 250)) addIp(e.value, 'ipsum');
  }
  if (cinsText) {
    for (const e of parsePlainTextIps(cinsText, 250)) addIp(e.value, 'cinsarmy');
  }
  if (bitwireText) {
    for (const e of parsePlainTextIps(bitwireText, 250)) addIp(e.value, 'bitwire');
  }

  const ips = Array.from(ipSources.keys());
  const { out: geo, diag: geoDiag } = await geolocateBatch(ips);

  // Aggregate per country
  const byCountry = new Map<string, CountryAgg>();
  const samples: ThreatMapResponse['samples'] = [];
  const sourceCounts: Record<string, number> = {
    urlhaus: 0,
    threatfox: 0,
    ipsum: 0,
    cinsarmy: 0,
    bitwire: 0,
  };

  for (const ip of ips) {
    const sourcesArr = Array.from(ipSources.get(ip) ?? []);
    for (const s of sourcesArr) sourceCounts[s] = (sourceCounts[s] ?? 0) + 1;
    const g = geo.get(ip);
    if (!g) continue;
    if (!byCountry.has(g.countryCode)) {
      byCountry.set(g.countryCode, {
        countryCode: g.countryCode,
        country: g.country,
        count: 0,
        sources: {},
        sample_ips: [],
      });
    }
    const agg = byCountry.get(g.countryCode)!;
    agg.count += 1;
    for (const s of sourcesArr) agg.sources[s] = (agg.sources[s] ?? 0) + 1;
    if (agg.sample_ips.length < 5) agg.sample_ips.push(ip);
    if (samples.length < 60) samples.push({ ip, country: g.country, countryCode: g.countryCode, sources: sourcesArr });
  }

  const countries = Array.from(byCountry.values()).sort((a, b) => b.count - a.count);

  // ─── Non-IP IOC types ──────────────────────────────────────────────────────
  // Same upstream feeds, but extract URLs / domains / hashes so the map page
  // shows a complete current-threat picture, not just IPs.
  const urlBucket: IocTypeBucket = { type: 'url', count: 0, source_counts: {}, recent: [] };
  const domainBucket: IocTypeBucket = { type: 'domain', count: 0, source_counts: {}, recent: [] };
  const hashBucket: IocTypeBucket = { type: 'hash', count: 0, source_counts: {}, recent: [] };

  const seen = { url: new Set<string>(), domain: new Set<string>(), hash: new Set<string>() };
  const pushSample = (bucket: IocTypeBucket, sample: IocSample) => {
    const set = seen[bucket.type];
    if (set.has(sample.value)) return;
    set.add(sample.value);
    bucket.count += 1;
    bucket.source_counts[sample.source] = (bucket.source_counts[sample.source] ?? 0) + 1;
    if (bucket.recent.length < MAX_PER_TYPE) bucket.recent.push(sample);
  };

  if (urlhausText) {
    for (const e of urlhausEntries) {
      if (e.type !== 'url') continue;
      pushSample(urlBucket, { value: e.value, source: 'urlhaus', context: e.context, timestamp: e.timestamp });
    }
  }
  for (const e of threatfoxEntries) {
    if (e.type === 'url') {
      pushSample(urlBucket, { value: e.value, source: 'threatfox', context: e.context, timestamp: e.timestamp });
    } else if (e.type === 'domain') {
      pushSample(domainBucket, { value: e.value, source: 'threatfox', context: e.context, timestamp: e.timestamp });
    } else if (e.type === 'hash') {
      pushSample(hashBucket, { value: e.value, source: 'threatfox', context: e.context, timestamp: e.timestamp });
    }
  }
  if (malwarebazaarText) {
    for (const e of malwarebazaarEntries) {
      if (e.type === 'hash') {
        pushSample(hashBucket, { value: e.value, source: 'malwarebazaar', context: e.context, timestamp: e.timestamp });
      }
    }
  }

  return {
    generated_at: new Date().toISOString(),
    total_ips: ips.length,
    countries,
    samples,
    source_counts: sourceCounts,
    diagnostics: {
      feeds: {
        urlhaus: { fetched: Boolean(urlhausText), bytes: urlhausText?.length ?? 0 },
        threatfox: { fetched: Boolean(threatfoxText), bytes: threatfoxText?.length ?? 0 },
        ipsum: { fetched: Boolean(ipsumText), bytes: ipsumText?.length ?? 0 },
        cinsarmy: { fetched: Boolean(cinsText), bytes: cinsText?.length ?? 0 },
        bitwire: { fetched: Boolean(bitwireText), bytes: bitwireText?.length ?? 0 },
        malwarebazaar: { fetched: Boolean(malwarebazaarText), bytes: malwarebazaarText?.length ?? 0 },
      },
      geo: geoDiag,
    },
    iocs_by_type: [urlBucket, domainBucket, hashBucket].filter((b) => b.count > 0),
  };
}

export async function threatMapHandler(c: Context<{ Bindings: Env }>) {
  const cache = caches.default;
  const cacheReq = new Request(CACHE_KEY);
  const cached = await cache.match(cacheReq);
  if (cached) {
    trackEvent(c.env, 'threat_map_fetch', {
      blobs: ['hit'],
      indexes: [visitorCountry(c.req.raw)],
    });
    return new Response(cached.body, {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
        'x-cache': 'HIT',
      },
    });
  }

  const body = await fetchThreatMap(c.env);

  /**
   * Do not cache a degenerate payload.
   *
   * If every upstream fetch failed we still return 200 with empty arrays, and
   * caching that would pin an empty map in front of every visitor for the full
   * TTL — turning a transient upstream blip into an hour of "the map is
   * broken". Returning it uncached means the next request retries.
   */
  const degenerate = body.total_ips === 0 && body.countries.length === 0;
  // A map with IPs but no countries is the shape a geolocation outage
  // produces. Caching that would pin a blank world in front of every visitor
  // for the full TTL, so it is treated as degraded too.
  const geoFailed = body.total_ips > 0 && body.countries.length === 0;

  const json = JSON.stringify(body);
  const response = new Response(json, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control':
        degenerate || geoFailed
          ? 'no-store'
          : `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
      'x-cache': 'MISS',
      ...(degenerate ? { 'x-degraded': 'all upstream feeds empty' } : {}),
      ...(geoFailed
        ? {
            'x-degraded': `geolocation unavailable: ${body.diagnostics.geo.sampleFailure ?? body.diagnostics.geo.stopReason ?? 'unknown'}`,
          }
        : {}),
    },
  });
  if (!degenerate && !geoFailed) {
    c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  }
  trackEvent(c.env, 'threat_map_fetch', {
    blobs: degenerate || geoFailed ? ['miss', 'degraded'] : ['miss'],
    doubles: [body.total_ips, body.countries.length],
    indexes: [visitorCountry(c.req.raw)],
  });
  return response;
}
