import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import {
  parseUrlhaus,
  parseIpsum,
  parsePlainTextIps,
  parseSslblC2,
  parseMalwarebazaar,
  parseOpenPhish,
  parsePhishingArmy,
  parseTweetFeed,
  parseSansIsc,
  parseC2IntelFeeds,
  parseAlienVaultReputation,
  parseHostsFormat,
} from '../lib/ioc-feed-parsers';
import { trackEvent, visitorCountry } from '../lib/analytics';
import { safeNullLog } from '../lib/safe-catch';
import { fetchMtiSource, type MtiIoc } from '../lib/mythreatintel-api';
import { ingestTelegramLeaksFromD1 } from '../lib/telegram-ioc-extract';
import { abuseChFeedRequestForEnv, type AbuseChFeedSource } from '../lib/abusech';
import { buildSummary } from '../lib/ioc-feed-parsers';

/**
 * IOC Cross-Source Correlation
 *
 * Fetches the live IOC feeds we already aggregate elsewhere and groups
 * indicators by their *value*. Anything appearing in 2+ independent feeds
 * is high-signal: a single feed can have false positives, but consensus
 * across independent sources is what CTI analysts actually trust.
 *
 * Output is bucketed by IOC type (ip / url / domain / hash) and ranked by
 * source_count desc.
 */

export const IOC_CORRELATION_CACHE_KEY = 'https://ioc-correlation-cache.internal/v6-mti-hashes';
const CACHE_KEY = IOC_CORRELATION_CACHE_KEY;
const CACHE_TTL_SECONDS = 3600;
const FETCH_TIMEOUT_MS = 12_000;
const PER_FEED_CAP = 500; // parse up to N entries per feed to find overlap
const TOP_PER_BUCKET = 200; // surface up to N correlated indicators per IOC type

type IocKind = 'ip' | 'url' | 'domain' | 'hash';

interface CorrelatedIoc {
  value: string;
  kind: IocKind;
  source_count: number;
  sources: string[];
  /** First context string we encountered for this indicator (malware family etc.) */
  context?: string;
  /** Most recent timestamp string from any source (when available). */
  last_seen?: string;
}

// Re-export the CorrelatedIoc shape so consumers (e.g. the TIFCE engine) can
// type their cross-feed index without re-declaring the same interface.
export type { CorrelatedIoc };

interface SourceMeta {
  id: string;
  ok: boolean;
  count: number;
}

export interface IocCorrelationResponse {
  generated_at: string;
  sources: SourceMeta[];
  totals: {
    indicators_scanned: number;
    correlated_indicators: number;
    by_kind: Record<IocKind, number>;
  };
  ips: CorrelatedIoc[];
  urls: CorrelatedIoc[];
  domains: CorrelatedIoc[];
  hashes: CorrelatedIoc[];
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: '*/*' },
      cf: { cacheTtl: 1800, cacheEverything: true },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch (_catchErr) {
    logError('fetchText failed', _catchErr);
    return null;
  }
}

/**
 * Fetch one abuse.ch bulk feed with the authenticated request shape
 * (`lib/abusech.ts`). Same failure contract as `fetchText` — null, never a
 * throw — so a single dead platform degrades that source only.
 */
async function fetchAbuseCh(env: Env | undefined, source: AbuseChFeedSource): Promise<string | null> {
  try {
    const req = abuseChFeedRequestForEnv(env, source, { days: 7 });
    const res = await fetch(req.url, {
      ...req.init,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: {
        'user-agent': 'pranithjain-dfir/1.0',
        accept: '*/*',
        ...((req.init.headers as Record<string, string>) ?? {}),
      },
      cf: { cacheTtl: 1800, cacheEverything: true },
    } as RequestInit);
    if (!res.ok) return null;
    const text = await res.text();
    return text.trim() ? text : null;
  } catch (_catchErr) {
    logError(`fetchAbuseCh(${source}) failed`, _catchErr);
    return null;
  }
}

interface MutableBucket {
  // value → { sources: Set<string>, context?: string, last_seen?: string }
  map: Map<string, { sources: Set<string>; context?: string; last_seen?: string }>;
}

function add(bucket: MutableBucket, value: string, source: string, context?: string, timestamp?: string): void {
  const existing = bucket.map.get(value);
  if (existing) {
    existing.sources.add(source);
    if (context && !existing.context) existing.context = context;
    if (timestamp && (!existing.last_seen || timestamp > existing.last_seen)) {
      existing.last_seen = timestamp;
    }
    return;
  }
  bucket.map.set(value, {
    sources: new Set([source]),
    context: context || undefined,
    last_seen: timestamp || undefined,
  });
}

function ranked(bucket: MutableBucket, kind: IocKind, cap: number): CorrelatedIoc[] {
  const out: CorrelatedIoc[] = [];
  for (const [value, meta] of bucket.map) {
    if (meta.sources.size < 2) continue;
    out.push({
      value,
      kind,
      source_count: meta.sources.size,
      sources: Array.from(meta.sources).sort(),
      context: meta.context,
      last_seen: meta.last_seen,
    });
  }
  out.sort((a, b) => {
    if (b.source_count !== a.source_count) return b.source_count - a.source_count;
    return (b.last_seen ?? '').localeCompare(a.last_seen ?? '');
  });
  return out.slice(0, cap);
}

/** Lowercase a hostname / domain / hash for stable correlation. */
function norm(s: string): string {
  return s.toLowerCase().trim();
}

/** Extract hostname from a URL — returns null if it doesn't parse. */
function hostOf(u: string): string | null {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch (_catchErr) {
    logError('hostOf failed', _catchErr);
    return null;
  }
}

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export async function fetchIocCorrelation(env?: Env): Promise<IocCorrelationResponse> {
  // Fetch every IOC feed in parallel. Each entry tracks whether it succeeded.
  const [
    urlhausText,
    threatfoxText,
    ipsumText,
    cinsText,
    bitwireText,
    blocklistDeText,
    binaryDefenseText,
    malwarebazaarText,
    openphishText,
    phishingArmyText,
    tweetfeedText,
    sansIscText,
    c2IntelText,
  ] = await Promise.all([
    // abuse.ch: authenticated v2 exports / ThreatFox JSON API. The anonymous
    // export URLs upstream retired on 2026-10-21 all answer 410 now.
    fetchAbuseCh(env, 'urlhaus'),
    fetchAbuseCh(env, 'threatfox'),
    fetchText('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt'),
    fetchText('https://cinsscore.com/list/ci-badguys.txt'),
    fetchText('https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt'),
    fetchText('https://lists.blocklist.de/lists/all.txt'),
    fetchText('https://www.binarydefense.com/banlist.txt'),
    fetchAbuseCh(env, 'malwarebazaar'),
    fetchText('https://openphish.com/feed.txt'),
    fetchText('https://phishing.army/download/phishing_army_blocklist.txt'),
    // ─── NEW SOURCES ───
    fetchText('https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv'),
    fetchText('https://isc.sans.edu/api/sources/attacks/200/?json'),
    fetchText('https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv'),
  ]);

  // Second batch — sources added 2026-05-11 after the DigitalSide path
  // investigation confirmed those URLs are dormant. These four are
  // actively maintained; fetched in a separate Promise.all so the
  // initial batch isn't penalised if any of these stall.
  const [etCompromisedText, otxReputationText, blpRansomwareText, blpScamText] = await Promise.all([
    fetchText('https://rules.emergingthreats.net/blockrules/compromised-ips.txt'),
    fetchText('https://reputation.alienvault.com/reputation.generic'),
    fetchText('https://blocklistproject.github.io/Lists/ransomware.txt'),
    fetchText('https://blocklistproject.github.io/Lists/scam.txt'),
  ]);

  // Third batch — active-C2 + curated-OSINT sources added 2026-05-18.
  // SSLBL = abuse.ch botnet-C2 IPs (malicious-SSL pinned); drb-ra
  // domainC2s = C2 domains (complements the existing IPC2s).
  // (Botvrij domain feed removed — the data was fetched but never parsed
  // into a bucket, wasting a subrequest. Re-add with a parser if needed.)
  const [sslblText, c2DomainText, mtiIocResult] = await Promise.all([
    fetchText('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'),
    fetchText('https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.csv'),
    // MyThreatIntel file-hash IOCs — a hash present here AND in another
    // hash feed (MalwareBazaar / ThreatFox) becomes a correlated indicator.
    env
      ? safeNullLog('fetch-mti-iocs-correlation', fetchMtiSource(env, 'iocs', { limit: PER_FEED_CAP }))
      : Promise.resolve(null),
  ]);

  const ipBucket: MutableBucket = { map: new Map() };
  const urlBucket: MutableBucket = { map: new Map() };
  const domainBucket: MutableBucket = { map: new Map() };
  const hashBucket: MutableBucket = { map: new Map() };

  let totalScanned = 0;
  const sources: SourceMeta[] = [];
  const trackSource = (id: string, ok: boolean, count: number) => {
    sources.push({ id, ok, count });
    if (ok) totalScanned += count;
  };

  // ─── IP feeds ────────────────────────────────────────────────────────────
  if (ipsumText) {
    const e = parseIpsum(ipsumText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'ipsum', x.context, x.timestamp);
    trackSource('ipsum', true, e.length);
  } else trackSource('ipsum', false, 0);

  if (cinsText) {
    const e = parsePlainTextIps(cinsText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'cinsarmy');
    trackSource('cinsarmy', true, e.length);
  } else trackSource('cinsarmy', false, 0);

  if (bitwireText) {
    const e = parsePlainTextIps(bitwireText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'bitwire');
    trackSource('bitwire', true, e.length);
  } else trackSource('bitwire', false, 0);

  if (blocklistDeText) {
    const e = parsePlainTextIps(blocklistDeText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'blocklist-de');
    trackSource('blocklist-de', true, e.length);
  } else trackSource('blocklist-de', false, 0);

  if (binaryDefenseText) {
    const e = parsePlainTextIps(binaryDefenseText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'binary-defense');
    trackSource('binary-defense', true, e.length);
  } else trackSource('binary-defense', false, 0);

  // ─── URLhaus: URLs, plus extract host into ip/domain bucket ──────────────
  if (urlhausText) {
    const e = parseUrlhaus(urlhausText, PER_FEED_CAP);
    let count = 0;
    for (const x of e) {
      if (x.type !== 'url') continue;
      add(urlBucket, x.value, 'urlhaus', x.context, x.timestamp);
      const host = hostOf(x.value);
      if (host) {
        if (IPV4_RE.test(host)) add(ipBucket, host, 'urlhaus', x.context, x.timestamp);
        else add(domainBucket, norm(host), 'urlhaus', x.context, x.timestamp);
      }
      count++;
    }
    trackSource('urlhaus', true, count);
  } else trackSource('urlhaus', false, 0);

  // ─── ThreatFox: mixed (url / domain / ip / hash) ────────────────────────
  if (threatfoxText) {
    // buildSummary sniffs JSON (authenticated `get_iocs`) vs CSV (legacy
    // fallback) and normalises both through the same entry shape.
    const e = buildSummary('threatfox', threatfoxText, PER_FEED_CAP).entries;
    for (const x of e) {
      if (x.type === 'ipv4') add(ipBucket, x.value, 'threatfox', x.context, x.timestamp);
      else if (x.type === 'url') {
        add(urlBucket, x.value, 'threatfox', x.context, x.timestamp);
        const host = hostOf(x.value);
        if (host) {
          if (IPV4_RE.test(host)) add(ipBucket, host, 'threatfox', x.context, x.timestamp);
          else add(domainBucket, norm(host), 'threatfox', x.context, x.timestamp);
        }
      } else if (x.type === 'domain') add(domainBucket, norm(x.value), 'threatfox', x.context, x.timestamp);
      else if (x.type === 'hash') add(hashBucket, norm(x.value), 'threatfox', x.context, x.timestamp);
    }
    trackSource('threatfox', true, e.length);
  } else trackSource('threatfox', false, 0);

  // ─── MalwareBazaar: hashes ───────────────────────────────────────────────
  if (malwarebazaarText) {
    const e = parseMalwarebazaar(malwarebazaarText, PER_FEED_CAP);
    let count = 0;
    for (const x of e) {
      if (x.type !== 'hash') continue;
      add(hashBucket, norm(x.value), 'malwarebazaar', x.context, x.timestamp);
      count++;
    }
    trackSource('malwarebazaar', true, count);
  } else trackSource('malwarebazaar', false, 0);

  // ─── MyThreatIntel: file-hash IOCs (sha256) ─────────────────────────────
  if (mtiIocResult && mtiIocResult.ok && mtiIocResult.items.length > 0) {
    let count = 0;
    for (const raw of mtiIocResult.items) {
      const e = raw as MtiIoc;
      if (!e.sha256) continue;
      const context =
        [e.signature, e.type, e.tags]
          .map((x) => x?.trim())
          .filter((x): x is string => Boolean(x) && x !== 'N/D')
          .join(' | ') || undefined;
      add(hashBucket, norm(e.sha256), 'mythreatintel', context, e.date);
      count++;
      if (count >= PER_FEED_CAP) break;
    }
    trackSource('mythreatintel', true, count);
  } else trackSource('mythreatintel', false, 0);

  // ─── OpenPhish: URLs (also extract host into domain/ip) ─────────────────
  if (openphishText) {
    const e = parseOpenPhish(openphishText, PER_FEED_CAP);
    for (const x of e) {
      add(urlBucket, x.value, 'openphish');
      const host = hostOf(x.value);
      if (host) {
        if (IPV4_RE.test(host)) add(ipBucket, host, 'openphish');
        else add(domainBucket, norm(host), 'openphish');
      }
    }
    trackSource('openphish', true, e.length);
  } else trackSource('openphish', false, 0);

  // ─── Phishing Army: domains ──────────────────────────────────────────────
  if (phishingArmyText) {
    const e = parsePhishingArmy(phishingArmyText, PER_FEED_CAP);
    for (const x of e) add(domainBucket, norm(x.value), 'phishing-army');
    trackSource('phishing-army', true, e.length);
  } else trackSource('phishing-army', false, 0);

  // ─── TweetFeed: mixed types from researcher Twitter posts ────────────────
  if (tweetfeedText) {
    const e = parseTweetFeed(tweetfeedText, PER_FEED_CAP);
    for (const x of e) {
      if (x.type === 'ipv4') add(ipBucket, x.value, 'tweetfeed', x.context, x.timestamp);
      else if (x.type === 'url') {
        add(urlBucket, x.value, 'tweetfeed', x.context, x.timestamp);
        const host = hostOf(x.value);
        if (host) {
          if (IPV4_RE.test(host)) add(ipBucket, host, 'tweetfeed', x.context, x.timestamp);
          else add(domainBucket, norm(host), 'tweetfeed', x.context, x.timestamp);
        }
      } else if (x.type === 'domain') add(domainBucket, norm(x.value), 'tweetfeed', x.context, x.timestamp);
      else if (x.type === 'hash') add(hashBucket, norm(x.value), 'tweetfeed', x.context, x.timestamp);
    }
    trackSource('tweetfeed', true, e.length);
  } else trackSource('tweetfeed', false, 0);

  // ─── SANS ISC: top attack-source IPs ─────────────────────────────────────
  if (sansIscText) {
    const e = parseSansIsc(sansIscText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'sans-isc', x.context, x.timestamp);
    trackSource('sans-isc', true, e.length);
  } else trackSource('sans-isc', false, 0);

  // ─── C2IntelFeeds: Cobalt Strike + other C2 IPs ──────────────────────────
  if (c2IntelText) {
    const e = parseC2IntelFeeds(c2IntelText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'c2-intel', x.context);
    trackSource('c2-intel', true, e.length);
  } else trackSource('c2-intel', false, 0);

  // ─── Emerging Threats compromised-ips: daily-curated IP list ─────────────
  if (etCompromisedText) {
    const e = parsePlainTextIps(etCompromisedText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'emerging-threats');
    trackSource('emerging-threats', true, e.length);
  } else trackSource('emerging-threats', false, 0);

  // ─── AlienVault OTX reputation: IPs with classification context ──────────
  if (otxReputationText) {
    const e = parseAlienVaultReputation(otxReputationText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'otx-reputation', x.context);
    trackSource('otx-reputation', true, e.length);
  } else trackSource('otx-reputation', false, 0);

  // ─── BlocklistProject ransomware: known ransomware C2 + delivery domains ─
  if (blpRansomwareText) {
    const e = parseHostsFormat(blpRansomwareText, PER_FEED_CAP);
    for (const x of e) add(domainBucket, norm(x.value), 'blp-ransomware');
    trackSource('blp-ransomware', true, e.length);
  } else trackSource('blp-ransomware', false, 0);

  // ─── BlocklistProject scam: scam-fraud domains ───────────────────────────
  if (blpScamText) {
    const e = parseHostsFormat(blpScamText, PER_FEED_CAP);
    for (const x of e) add(domainBucket, norm(x.value), 'blp-scam');
    trackSource('blp-scam', true, e.length);
  } else trackSource('blp-scam', false, 0);

  // ─── abuse.ch SSL Blacklist: botnet-C2 IPs (malicious-SSL pinned) ─────────
  if (sslblText) {
    const e = parseSslblC2(sslblText, PER_FEED_CAP);
    for (const x of e) add(ipBucket, x.value, 'sslbl');
    trackSource('sslbl', true, e.length);
  } else trackSource('sslbl', false, 0);

  // ─── drb-ra C2IntelFeeds: C2 DOMAINS (CSV, first column = domain) ─────────
  if (c2DomainText) {
    let n = 0;
    for (const line of c2DomainText.split('\n')) {
      if (n >= PER_FEED_CAP) break;
      const t = line.trim();
      if (!t || t.startsWith('#') || /^domain[,\s]/i.test(t)) continue;
      const d = norm((t.split(',')[0] ?? '').trim());
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) {
        add(domainBucket, d, 'c2-intel-domains');
        n++;
      }
    }
    trackSource('c2-intel-domains', true, n);
  } else trackSource('c2-intel-domains', false, 0);

  // ─── Telegram leak monitor (Sprint 2 §16) ────────────────────────────
  // Pulls IOCs (hashes, IPs, domains, URLs) from `telegram_leak_entries`
  // over the last 7 days and adds them to the same buckets the upstream
  // feeds use. Telegram becomes the 25th source in the cross-source
  // consensus; a hash appearing in both MalwareBazaar AND a Telegram
  // leak jumps to source_count=2 and ranks higher.
  const tgResult = await ingestTelegramLeaksFromD1(env?.BRIEFINGS_DB, 7, 50);
  for (const e of tgResult.entries) {
    if (e.type === 'ipv4') add(ipBucket, e.value, 'telegram-leak', e.context, e.timestamp);
    else if (e.type === 'url') {
      add(urlBucket, e.value, 'telegram-leak', e.context, e.timestamp);
      const host = hostOf(e.value);
      if (host) {
        if (IPV4_RE.test(host)) add(ipBucket, host, 'telegram-leak', e.context, e.timestamp);
        else add(domainBucket, norm(host), 'telegram-leak', e.context, e.timestamp);
      }
    } else if (e.type === 'domain') add(domainBucket, norm(e.value), 'telegram-leak', e.context, e.timestamp);
    else if (e.type === 'hash') add(hashBucket, norm(e.value), 'telegram-leak', e.context, e.timestamp);
  }
  trackSource('telegram-leak', tgResult.meta.ok, tgResult.meta.rowsScanned);

  const ips = ranked(ipBucket, 'ip', TOP_PER_BUCKET);
  const urls = ranked(urlBucket, 'url', TOP_PER_BUCKET);
  const domains = ranked(domainBucket, 'domain', TOP_PER_BUCKET);
  const hashes = ranked(hashBucket, 'hash', TOP_PER_BUCKET);

  return {
    generated_at: new Date().toISOString(),
    sources,
    totals: {
      indicators_scanned: totalScanned,
      correlated_indicators: ips.length + urls.length + domains.length + hashes.length,
      by_kind: {
        ip: ips.length,
        url: urls.length,
        domain: domains.length,
        hash: hashes.length,
      },
    },
    ips,
    urls,
    domains,
    hashes,
  };
}

export async function iocCorrelationHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = caches.default;
  const cacheReq = new Request(CACHE_KEY);
  const cached = await cache.match(cacheReq);
  if (cached) {
    trackEvent(c.env, 'ioc_correlation_fetch', {
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

  const body = await fetchIocCorrelation(c.env);
  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
      'x-cache': 'MISS',
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  trackEvent(c.env, 'ioc_correlation_fetch', {
    blobs: ['miss'],
    doubles: [body.totals.correlated_indicators, body.totals.indicators_scanned],
    indexes: [visitorCountry(c.req.raw)],
  });
  return response;
}
