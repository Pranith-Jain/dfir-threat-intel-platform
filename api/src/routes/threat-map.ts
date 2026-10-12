import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import {
  parseUrlhaus,
  parseThreatfox,
  parseIpsum,
  parsePlainTextIps,
  parseMalwarebazaar,
} from '../lib/ioc-feed-parsers';
import { trackEvent, visitorCountry } from '../lib/analytics';

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
 * v6: the 7.9 MB URLhaus feed is now parsed once instead of twice, MAX_IPS
 * dropped 1000 -> 400, and geolocation is cached per IP. All three change the
 * payload's shape and volume, so the cache key is bumped — serving a v5 body
 * for the `stale-while-revalidate` window (4h) would show the old working set
 * and hide whether the fix actually took effect.
 */
export const THREAT_MAP_CACHE_KEY = 'https://threat-map-cache.internal/v6-single-parse';
const CACHE_KEY = THREAT_MAP_CACHE_KEY;
const CACHE_TTL_SECONDS = 3600;
// ip-api.com batch is 100 per request.
//
// MAX_IPS was 1000, which meant 10 SEQUENTIAL round-trips to a free-tier
// endpoint (45 req/min from one egress IP) inside a single invocation. Combined
// with the duplicate parses that is what tipped this route into error 1102.
// 400 covers the map's needs — it renders aggregated countries, not an
// exhaustive list — in 4 batches.
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
}

interface IpApiBatchResult {
  query?: string;
  status?: string;
  country?: string;
  countryCode?: string;
}

/**
 * Per-IP geolocation cache key.
 *
 * Keyed on the IP alone, so a warm cache is shared across every caller that
 * needs the same country. An IPv6 address contains colons, which are legal in a
 * URL path, so no encoding is needed here.
 */
function GEO_CACHE_KEY(ip: string): string {
  return `https://threat-map-geo.internal/${ip}`;
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
 * Geolocate IPs in batches of 100 against ip-api.com.
 *
 * Results are cached per IP for a day. Country assignment for an IP does not
 * change hour to hour, so a warm cache turns the whole stage into Cache-API
 * reads and a cold one only pays for the IPs it has never seen. The previous
 * shape re-geolocated the entire working set on every cache miss, which is the
 * difference between one invocation doing 4 requests and doing several hundred
 * across an hour of misses.
 */
async function geolocateBatch(ips: string[]): Promise<Map<string, { country: string; countryCode: string }>> {
  const out = new Map<string, { country: string; countryCode: string }>();
  if (ips.length === 0) return out;

  const pending: string[] = [];

  // Warm pass: Cache API, no network.
  await Promise.all(
    ips.map(async (ip) => {
      const hit = await caches.default.match(new Request(GEO_CACHE_KEY(ip))).catch(() => null);
      if (!hit) {
        pending.push(ip);
        return;
      }
      const v = (await hit.json()) as { country: string; countryCode: string } | null;
      if (v?.countryCode) out.set(ip, v);
    })
  );

  if (pending.length === 0) return out;

  const startedAt = Date.now();
  const writes: Promise<void>[] = [];

  for (let i = 0; i < pending.length; i += 100) {
    // Budget guard: better to return partial country coverage quickly than to
    // risk the invocation being killed for the payload it is trying to build.
    if (Date.now() - startedAt > GEO_BUDGET_MS) break;
    const batch = pending.slice(i, i + 100);
    try {
      const res = await fetch('http://ip-api.com/batch?fields=query,status,country,countryCode', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch.map((q) => ({ query: q }))),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.status === 429) {
        // ip-api.com free tier is 45 req/min from a single IP; the Worker
        // shares one egress IP per POP so we hit this on bursts. Stop and
        // keep whatever resolved.
        break;
      }
      if (!res.ok) continue;
      const data = (await res.json()) as IpApiBatchResult[];
      for (const row of data) {
        if (row.status === 'success' && row.query && row.countryCode && row.country) {
          const value = { country: row.country, countryCode: row.countryCode };
          out.set(row.query, value);
          writes.push(
            caches.default.put(
              new Request(GEO_CACHE_KEY(row.query)),
              new Response(JSON.stringify(value), {
                headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${GEO_CACHE_TTL}` },
              })
            )
          );
        }
      }
    } catch (_catchErr) {
      logError('geolocateBatch failed', _catchErr);
      // Skip this batch; the next one may still succeed.
    }
  }

  await Promise.allSettled(writes);
  return out;
}

/**
 * Pure-data fetcher exposed for /api/v1/snapshot. Same body the HTTP handler
 * returns, just without the Response/cache wrapping so the snapshot endpoint
 * can compose it without a worker-internal HTTP call.
 */
export async function fetchThreatMap(): Promise<ThreatMapResponse> {
  // Fan out to all IOC feeds we have access to, in parallel.
  const [urlhausText, threatfoxText, ipsumText, cinsText, bitwireText, malwarebazaarText] = await Promise.all([
    fetchText('https://urlhaus.abuse.ch/downloads/csv_recent/'),
    fetchText('https://threatfox.abuse.ch/export/csv/recent/'),
    fetchText('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt'),
    fetchText('https://cinsscore.com/list/ci-badguys.txt'),
    fetchText('https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt'),
    fetchText('https://bazaar.abuse.ch/export/csv/recent/'),
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
  const threatfoxEntries = threatfoxText ? parseThreatfox(threatfoxText, PARSE_CAP) : [];
  const malwarebazaarEntries = malwarebazaarText ? parseMalwarebazaar(malwarebazaarText, PARSE_CAP) : [];

  // Build a map of IP → set of sources, capped at MAX_IPS unique IPs.
  const ipSources = new Map<string, Set<string>>();
  const addIp = (ip: string, source: string) => {
    if (ipSources.size >= MAX_IPS && !ipSources.has(ip)) return;
    if (!ipSources.has(ip)) ipSources.set(ip, new Set());
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
  const geo = await geolocateBatch(ips);

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

  const body = await fetchThreatMap();

  /**
   * Do not cache a degenerate payload.
   *
   * If every upstream fetch failed we still return 200 with empty arrays, and
   * caching that would pin an empty map in front of every visitor for the full
   * TTL — turning a transient upstream blip into an hour of "the map is
   * broken". Returning it uncached means the next request retries.
   */
  const degenerate = body.total_ips === 0 && body.countries.length === 0;

  const json = JSON.stringify(body);
  const response = new Response(json, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': degenerate
        ? 'no-store'
        : `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
      'x-cache': 'MISS',
      ...(degenerate ? { 'x-degraded': 'all upstream feeds empty' } : {}),
    },
  });
  if (!degenerate) {
    c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  }
  trackEvent(c.env, 'threat_map_fetch', {
    blobs: degenerate ? ['miss', 'degraded'] : ['miss'],
    doubles: [body.total_ips, body.countries.length],
    indexes: [visitorCountry(c.req.raw)],
  });
  return response;
}
