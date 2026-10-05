import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { isBenign, refang, scoreConfidence } from '../lib/ioc-normalize';
import type { D1Database, Queue } from '@cloudflare/workers-types';
import { safeNullLog } from '../lib/safe-catch';
import { requireAdmin } from '../lib/admin-auth';
import { concurrentMap } from '../lib/concurrent-map';
import { readBatchSlice, type FeedQueueMessage } from '../lib/live-iocs-slices';
import {
  parseTweetFeed,
  parseSansIsc,
  parseC2IntelFeeds,
  parseUrlhaus,
  parseThreatfox,
  parsePlainTextIps,
  parseAlienVaultReputation,
  parsePhishingArmy,
  parseViriback,
  parseThreatviewDomains,
  parseSwiftioc,
  parseAiHoneypots,
  parseLlmThreatintelIocs,
  parseCobaltStrikeCsv,
  parseCarbonBlackC2,
  parseThreatviewC2,
  parseThreatfoxHostfile,
  parseThreatfoxUrls,
  parseC2IntelDomains,
  parseBotvrijDomains,
  parsePlainDomainList,
  parseSslblJa3,
} from '../lib/ioc-feed-parsers';
import { CURATED_FEEDS, type CuratedFeed } from '../lib/feed-curation';
import { fetchMalwareSamplesCached } from './malware-samples';
import { fetchPhishingUrlsCached } from './phishing-urls';
import { fetchCryptoScamCached } from './crypto-scam-feed';
import { trackEvent, visitorCountry } from '../lib/analytics';

/**
 * Live IOC stream — unified, time-ordered, per-entry-attributed.
 *
 * /api/v1/ioc-correlation answers "what's in 2+ feeds." This endpoint answers
 * "what's freshly observed and by whom." Each entry carries a reporter
 * handle / source tag and a timestamp; rendered chronologically the page
 * reads like a CTI firehose for individual indicators.
 *
 * Sources (live; all free; no auth):
 *   - TweetFeed (researcher Twitter posts, per-IOC permalink)
 *   - SANS ISC top attack sources (sensor-network telemetry)
 *   - C2IntelFeeds (Cobalt Strike + similar C2 IPs)
 *   - URLhaus recent (per-URL malware-family context)
 *   - ThreatFox recent (per-IOC malware-family + actor context)
 *   - Emerging Threats compromised-ips (Proofpoint ETOpen daily blocklist)
 *   - AlienVault OTX reputation (classified malicious IPs)
 *   - MalwareBazaar recent (file hashes + family signature)
 *   - OpenPhish (phishing URLs)
 *   - PhishTank (verified phishing URLs + brand attribution)
 *   - SwiftIOC high-confidence (multi-type, score-ranked, defanged)
 *
 * Cached 30 min — these feeds churn faster than the correlation endpoint.
 */

// v14 (2026-10-05): bumped on the registry change — webamon-campaigns retired,
// ai-honeypots + llm-threatintel + the curated open-source feeds added, and the
// compose path moved from per-source slices to batch slices. The shape the
// old key holds is no longer what the handler serves, so serving it would mix a
// 29-source snapshot with the new roster.
export const LIVE_IOCS_CACHE_KEY = 'https://live-iocs-cache.internal/v14-batched-slices';
const CACHE_KEY = LIVE_IOCS_CACHE_KEY;
const CACHE_TTL_SECONDS = 30 * 60;
// When a build is degraded (an upstream fetch failed), cache for a shorter
// window so it recovers sooner — but NOT 60s: a persistently-down feed at 60s
// would re-run the full source fan-out every minute.
const DEGRADED_TTL_SECONDS = 5 * 60;
const FETCH_TIMEOUT_MS = 30_000;
const PER_FEED_CAP = 300;
// Ceiling = PER_FEED_CAP × source-count. Previously 400 — small enough that
// the sort (timestamped-first, no-timestamp tail) silently dropped every
// untimestamped source (c2-intel, emerging-threats, otx-reputation, openphish)
// because the 4 timestamped sources alone produced >400 items.
const MAX_ITEMS = 20000;
// Freshness window for items WITH per-entry timestamps. Items observed
// before this cutoff are dropped — the page is called "live IOCs"; an
// indicator first seen weeks ago is rarely actionable. Bulk-snapshot
// sources (c2-intel, emerging-threats, otx-reputation) have no per-entry
// timestamps and are not affected by this filter — they reflect the
// upstream feed's current state by definition.
const STALENESS_HOURS = 24 * 7;

type IocKind = 'ip' | 'url' | 'domain' | 'hash';

export interface LiveIoc {
  value: string;
  kind: IocKind;
  source: string;
  /** Reporter handle (TweetFeed) or "—" for telemetry sources. */
  reporter?: string;
  /** Context: malware family, tags, or sensor stats. */
  context?: string;
  /** Permalink back to the source post when available (TweetFeed). */
  reference_url?: string;
  /** ISO 8601 — derived from feed entry; undefined for sources without per-entry time. */
  observed_at?: string;
  /**
   * Per-IOC extraction confidence, computed by `scoreConfidence` in
   * ioc-normalize.ts. Bounded [0, 1]. Items in the `rejected` band
   * (allowlist false-positives, RFC 5737, vendor docs, etc.) are
   * filtered out of the public payload before this field is set.
   */
  confidence?: number;
  /** Quick visual band: high / medium / low. */
  confidence_band?: 'high' | 'medium' | 'low';
}

export interface LiveSource {
  id: string;
  ok: boolean;
  count: number;
  /**
   * True when this source returned AT LEAST as many indicators as the
   * per-feed cap, i.e. `count` is a truncation, not the feed's true size.
   *
   * Without this, a 170,954-line feed and a 300-line feed render identically
   * as "300" — which reads as "this feed is nearly empty / not active" when it
   * is in fact the highest-volume source in the roster. Several feeds sit at
   * exactly the cap on every snapshot purely because they are large.
   *
   * `count === capped` is therefore the only evidence available without
   * parsing the whole body: a parser that breaks at `cap` cannot also tell us
   * there were more. It may over-report by one when a feed's true size is
   * exactly `cap`, which is the safe direction (looks saturated, not empty).
   */
  capped?: boolean;
  /**
   * Newest per-entry observation timestamp from this source's contributions,
   * derived from items[].observed_at. Undefined for sources that don't
   * publish per-entry timestamps (C2IntelFeeds, ET compromised-ips,
   * OTX reputation). UI can color-code freshness off this.
   */
  newest_observation?: string;
  /** True when the current data comes from the KV last-good fallback. */
  stale?: boolean;
}

export interface LiveIocsResponse {
  generated_at: string;
  /**
   * Sources that produced items in this snapshot. The "active" subset —
   * derived from `registered_sources` by filtering out count===0 entries.
   * Drives the freshness/count badges in the UI; does NOT represent the
   * full registered feed roster. See `registered_sources` for that.
   */
  sources: LiveSource[];
  /**
   * The full roster of every source the API knows about, including
   * ones that produced 0 fresh items this snapshot (count===0, ok===true)
   * and ones whose last fetch failed (ok===false). This is the pre-filter
   * list — UI uses it for the "Sources: …" prose and the filter-pill
   * row so users can see and filter by the complete set of ~30+ feeds,
   * not just the ones that happened to have items. The "active" subset
   * is in `sources` above.
   */
  registered_sources: LiveSource[];
  total: number;
  /** All items, sorted newest-first (entries without timestamp last). */
  items: LiveIoc[];
  /**
   * True when at least one upstream source's FETCH failed this build — as
   * opposed to a source that fetched fine but had no fresh items. Drives a
   * shorter cache TTL so a transient flake recovers sooner than the full
   * window, without re-fanning on a source that is simply (legitimately) empty.
   */
  degraded?: boolean;
}

/**
 * Consume n subrequests from the shared fan-out budget. Returns false when
 * doing so would exceed the hard cap — callers must degrade the source
 * (return ok:false / null) instead of launching the request.
 */
function consumeBudget(budget: { used: number; max: number } | undefined, n = 1): boolean {
  if (!budget) return true;
  if (budget.used + n > budget.max) return false;
  budget.used += n;
  return true;
}

async function fetchText(url: string, budget?: { used: number; max: number }): Promise<string | null> {
  // The shared fan-out budget counts REAL subrequests (this fetch + the KV
  // reads cached helpers make). Reserve before launching so a source can't
  // overshoot the free-plan 50-subrequest cap mid-run; an exhausted budget
  // degrades THIS source (returns null → ok:false) instead of aborting the
  // whole invocation with "Too many subrequests" (the 2026-08 incident that
  // surfaced as HTTP 503 on the global-pulse live snapshot).
  if (!consumeBudget(budget)) return null;
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: '*/*' },
      // No `cacheEverything: true` — that would cache upstream 5xx/429
      // responses for 25 min and poison every consumer / fan-out in
      // that window, surfacing as "sources show 0" with no way to tell
      // the difference from a real outage (2026-06 incident: 24 of 36
      // sources stuck on `ok:false` for hours after a transient blip).
      // Default `cf:` behaviour (2xx GETs only) is what we want.
      cf: { cacheTtl: 1500 },
    });
    if (!res.ok) return null;
    const text = await res.text();
    if (!text) return null;
    // Detect HTML challenge/captcha pages (Cloudflare, Incapsula, etc.)
    // by checking the actual body content — NOT the content-type header,
    // which many feeds mislabel as text/html or application/octet-stream
    // even when the body is valid plaintext.  The body check alone is
    // sufficient: real challenge pages always start with <!DOCTYPE or <html;
    // valid feeds never do.
    const firstNonWs = text.trimStart().slice(0, 16);
    if (firstNonWs.startsWith('<!DOCTYPE') || firstNonWs.startsWith('<html')) return null;
    return text;
  } catch (_catchErr) {
    logError('fetchText failed', _catchErr);
    return null;
  }
}

/**
 * Diagnostic variant of fetchText that returns WHY a fetch failed instead
 * of swallowing everything to null. Used by the `?debug=1` path on
 * /api/v1/live-iocs so the operator can see the actual HTTP status /
 * network error for each unreachable source. Not on the hot path.
 */
async function fetchTextDiag(
  url: string
): Promise<{ ok: boolean; status?: number; bytes?: number; error?: string; duration_ms?: number }> {
  const t0 = Date.now();
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: '*/*' },
      // Mirrors fetchText — see comment there re: cacheEverything.
      cf: { cacheTtl: 1500 },
    });
    if (!res.ok) {
      return { ok: false, status: res.status, error: `HTTP ${res.status}`, duration_ms: Date.now() - t0 };
    }
    const text = await res.text();
    if (!text) {
      return { ok: false, status: res.status, error: 'empty body', duration_ms: Date.now() - t0 };
    }
    const firstNonWs = text.trimStart().slice(0, 16);
    if (firstNonWs.startsWith('<!DOCTYPE') || firstNonWs.startsWith('<html')) {
      return {
        ok: false,
        status: res.status,
        error: `HTML challenge page (${text.length} bytes)`,
        duration_ms: Date.now() - t0,
      };
    }
    return { ok: true, status: res.status, bytes: text.length, duration_ms: Date.now() - t0 };
  } catch (e) {
    logError('fetchTextDiag failed', e);
    return { ok: false, error: e instanceof Error ? e.message.slice(0, 120) : 'unknown', duration_ms: Date.now() - t0 };
  }
}

/** Parse a TweetFeed row to extract the permalink URL — last column. */
function tweetfeedPermalink(rawRow: string | undefined): string | undefined {
  if (!rawRow) return undefined;
  // Schema: date,source,type,ioc,tags,info_url
  const cols = rawRow.split(',');
  const url = cols[5]?.trim();
  if (url && url.startsWith('http')) return url;
  return undefined;
}

function isoFromLoose(s: string | undefined): string | undefined {
  if (!s) return undefined;
  // TweetFeed gives "YYYY-MM-DD HH:MM:SS" (UTC implied) — coerce to ISO.
  const candidate = s.includes('T') ? s : s.replace(' ', 'T') + 'Z';
  const t = Date.parse(candidate);
  return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
}

function iocKind(t: string): IocKind | null {
  if (t === 'ipv4') return 'ip';
  if (t === 'url') return 'url';
  if (t === 'domain') return 'domain';
  if (t === 'hash') return 'hash';
  return null;
}

// ─────────────────────────────────────────────────────────────────────────
// Feed source registry
//
// Each source is an independent { id, run(deps) } unit: run() fetches and
// parses ONE upstream and returns its contributed items plus a source-health
// entry. fetchLiveIocs fans out over FEED_SOURCES with a bounded concurrency
// and flattens the results in registry order — so adding/removing a feed is a
// one-line edit, the latency-inducing sequential fetch batches collapse into a
// single barrier-free fan-out (audit P7), and a later change can dispatch each
// source to a queue independently.
//
// NB: a source's `count` here is advisory — fetchLiveIocs recomputes every
// source's count from the freshness-filtered item set below, so only `ok`
// (and, for andreafortuna, `stale`/`newest_observation`) is load-bearing on
// the entry returned here.
// ─────────────────────────────────────────────────────────────────────────

export type FeedDeps = {
  executionCtx?: { waitUntil: (p: Promise<unknown>) => void };
  kv?: KVNamespace;
  env?: Env;
  /**
   * Optional per-invocation subrequest budget. Each source's `run()` is
   * expected to check + increment this when it does an upstream fetch or
   * KV read; when the counter is at or over `max`, the caller short-circuits
   * the source to a `ok:false` stub before launching the request. The default
   * (no `budget` passed) is unbounded, so the queue-consumer path and tests
   * stay unaffected.
   */
  budget?: { used: number; max: number };
};
export type FeedResult = { items: LiveIoc[]; sources: LiveSource[] };
interface FeedSource {
  id: string;
  run: (deps: FeedDeps) => Promise<FeedResult>;
}

// Bounded in-flight count for the synchronous source fan-out. The Workers
// free-plan hard cap is 50 SUBREQUESTS per invocation (not connections) -
// a synchronous 36-source fan-out easily blows that when paired with the
// KV/queue/analytics reads fetchLiveIocs does. We cap in-flight requests
// at 5 so the fan-out stays well under the 50-subrequest ceiling even
// with the other reads in flight. The compose-on-read path is the primary
// read model; this only runs on a cold start / slice miss. 2026-06 audit.
const FEED_FANOUT_CONCURRENCY = 5;

/**
 * Mirror of the upstream URL(s) for every registered feed source. Used by
 * the `?debug=1` path to run a per-source diagnostic fetch and surface
 * real HTTP status / network errors in the response. Kept as a separate
 * map (vs reading the source's `run()` closure) so the diagnostic path
 * can hit the network even when the production `run()` is short-circuited
 * (e.g. the budget guard bailed it out).
 *
 * If you add or change a feed's URL, update BOTH the FEED_SOURCES registry
 * AND this map. A drift would surface as "source unreachable in debug"
 * when the real failure is "the debug mirror is stale".
 *
 * Exported so the drift guard in `live-iocs-runner.test.ts` can assert the
 * mirror neither references a retired upstream nor misses a registry source —
 * both failure modes are otherwise invisible until someone opens `?debug=1`.
 */
export const FEED_SOURCE_DEBUG_URLS: Record<string, { url: string; fallbackUrls?: string[] }> = {
  tweetfeed: { url: 'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv' },
  'sans-isc': { url: 'https://isc.sans.edu/api/sources/attacks/200/?json' },
  'c2-intel': { url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv' },
  urlhaus: { url: 'https://urlhaus.abuse.ch/downloads/csv_recent/' },
  'emerging-threats': { url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' },
  'otx-reputation': { url: 'https://reputation.alienvault.com/reputation.generic' },
  threatfox: { url: 'https://threatfox.abuse.ch/export/csv/recent/' },
  malwarebazaar: { url: 'https://mb-api.abuse.ch/api/v1/' },
  phishing: { url: 'https://data.phishtank.com/data/online-valid.json' },
  'crypto-scam': {
    url: 'https://raw.githubusercontent.com/spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed/main/detected_urls.json',
  },
  binarydefense: {
    url: 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/binarydefense.txt',
    fallbackUrls: ['https://www.binarydefense.com/banlist.txt'],
  },
  'tor-exit': {
    url: 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/tor-exit.txt',
    fallbackUrls: ['https://check.torproject.org/torbulkexitlist'],
  },
  'avanzato-c2': {
    url: 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/avanzato_c2.txt',
  },
  'cps-collected': {
    url: 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cps-collected-iocs.txt',
  },
  'blocklist-de': {
    url: 'https://lists.blocklist.de/lists/all.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  cinsscore: {
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  'bbcan177-ips': {
    url: 'https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  'domains-blacklist': {
    url: 'https://www.joewein.net/dl/bl/dom-bl.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/tsirolnik/spam-domains-list/master/spamdomains.txt',
      'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    ],
  },
  // Retired as a primary (9 URLs at the 2026-10-05 audit); kept as the last-resort
  // fallback for `botvrij-domain`.
  'botvrij-urls': {
    url: 'https://www.botvrij.eu/data/ioclist.url.raw',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt',
    ],
  },
  'bruteforce-blocker': {
    url: 'https://danger.rulez.sk/projects/bruteforceblocker/blist.php',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  'threatview-ip': {
    url: 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  'threatview-domains': {
    url: 'https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    ],
  },
  'viriback-c2': {
    url: 'https://tracker.viriback.com/dump.php',
    fallbackUrls: [
      'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cps-collected-iocs.txt',
    ],
  },
  'certpl-warnings': {
    url: 'https://hole.cert.pl/domains/v2/domains.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    ],
  },
  'bitwire-outbound': {
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  'bitwire-inbound': {
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
  },
  phishunt: {
    url: 'https://phishunt.io/feed.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt',
    ],
  },
  // SwiftIOC high-confidence multi-type feed (~3MB, score-desc). Correct
  // path is under public/ (site root); the bare iocs/ path 404s.
  swiftioc: {
    url: 'https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/main/public/iocs/high_confidence.csv',
  },
  // openphish is emitted as a RESPONSE id by the `phishing` source, not a
  // registry runner, so it is listed here only so `?debug=1` can reach it.
  // malwarebazaar + phishing carry key-gated or key-dependent upstreams and
  // cannot be probed as a plain GET — see scripts/audit-feed-health.mjs
  // NOT_PLAIN_GET, and the drift test's documented non-feed exceptions.
  openphish: { url: 'https://openphish.com/feed.txt' },
  // ── Dedicated AI / LLM threat intelligence ─────────────────────────────
  'ai-honeypots': {
    url: 'https://ai-honeypots.com/feeds/iocs.json',
    fallbackUrls: ['https://ai-honeypots.com/feeds/iocs.txt'],
  },
  'llm-threatintel': { url: 'https://llm-threatintel.com/data/iocs.json' },
  // ── Curated open-source feeds ──────────────────────────────────────────
  // Generated from CURATED_FEEDS so this mirror cannot drift from the registry.
  ...Object.fromEntries(
    CURATED_FEEDS.map((f) => [
      f.id,
      { url: f.url, ...(f.fallbackUrls?.length ? { fallbackUrls: f.fallbackUrls } : {}) },
    ])
  ),
};

const CPS_BASE = 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master';

// Common shape across the feed parsers — every parser yields at least a
// `value`; per-entry `type`/`context`/`timestamp` are present on the richer
// feeds and absent on the bare blocklists.
type ParsedEntry = { value: string; type?: string; context?: string; timestamp?: string };

interface TextFeedConfig {
  id: string;
  url: string;
  parse: (text: string, cap: number) => ParsedEntry[];
  /** Fixed kind, or 'per-entry' to derive it from each entry's `type`
   *  (entries whose type isn't a known IOC kind are dropped). */
  kind: IocKind | 'per-entry';
  reporter: string;
  /** Fixed context string, or a fn deriving it from the parsed entry. */
  context: string | ((e: ParsedEntry) => string | undefined);
  /** Attach observed_at from the entry timestamp (per-entry-dated feeds). */
  withTimestamp?: boolean;
  /** Keep only entries whose `type` equals this (e.g. URLhaus → 'url'). */
  filterType?: string;
  /** Mark the source unhealthy when it yielded zero items (vs the default:
   *  healthy whenever the fetch succeeded, even with zero parsed items). */
  okRequiresItems?: boolean;
  /** Optional fallback URLs tried in order when the primary URL fails.
   *  Use for feeds whose primary host is flaky / has a known outage - the
   *  2026-06 CPS_BASE outage (raw.githubusercontent.com 4xx on the
   *  CriticalPathSecurity/Public-Intelligence-Feeds paths) is the first
   *  use case. The first URL to return 2xx with a non-empty body wins;
   *  only when ALL URLs fail do we report `ok:false`. */
  fallbackUrls?: string[];
}

/** Use the parser's per-entry context verbatim. */
const entryContext = (e: ParsedEntry): string | undefined => e.context;

/**
 * Build a standard text-feed source: fetch → parse → map to LiveIoc with a
 * fixed source/reporter/context. Covers the plain blocklist + CSV feeds; the
 * richer sources (tweetfeed, malwarebazaar, phishing, andreafortuna, mti) have
 * bespoke runs below.
 */
function textFeedSource(cfg: TextFeedConfig): FeedSource {
  return {
    id: cfg.id,
    run: async (deps) => {
      const urls = [cfg.url, ...(cfg.fallbackUrls ?? [])];
      let text: string | null = null;
      for (const u of urls) {
        text = await fetchText(u, deps?.budget);
        if (text) break;
      }
      if (!text) return { items: [], sources: [{ id: cfg.id, ok: false, count: 0 }] };
      const parsed = cfg.parse(text, PER_FEED_CAP);
      const items: LiveIoc[] = [];
      for (const e of parsed) {
        if (cfg.filterType && e.type !== cfg.filterType) continue;
        let kind: IocKind;
        if (cfg.kind === 'per-entry') {
          const k = iocKind(e.type ?? '');
          if (!k) continue;
          kind = k;
        } else {
          kind = cfg.kind;
        }
        const item: LiveIoc = {
          value: e.value,
          kind,
          source: cfg.id,
          reporter: cfg.reporter,
          context: typeof cfg.context === 'function' ? cfg.context(e) : cfg.context,
        };
        if (cfg.withTimestamp) item.observed_at = isoFromLoose(e.timestamp);
        items.push(item);
      }
      const ok = cfg.okRequiresItems ? items.length > 0 : true;
      // See LiveSource.capped — items.length === PER_FEED_CAP means the parser
      // truncated, so the real feed is at least this big.
      return {
        items,
        sources: [{ id: cfg.id, ok, count: items.length, capped: items.length >= PER_FEED_CAP }],
      };
    },
  };
}

/** Botvrij.eu URL list: bare `http…` lines, no per-entry type/timestamp. */
const parseBotvrijUrls = (text: string, cap: number): ParsedEntry[] =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('http'))
    .slice(0, cap)
    .map((value) => ({ value }));

// ─── Bespoke sources ───────────────────────────────────────────────────────

/** TweetFeed: richest source — per-entry reporter + permalink + mixed kinds. */
const tweetfeedSource: FeedSource = {
  id: 'tweetfeed',
  run: async (deps) => {
    let tweetfeedText = await fetchText(
      'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv',
      deps?.budget
    );
    // Fall back to week.csv when today.csv is empty so the feed never shows
    // "0 sources" on quiet days (observed: today.csv is 0 bytes when no IOCs
    // are posted in the current UTC day, but week.csv has 7 days of data).
    if (!tweetfeedText) {
      tweetfeedText = await fetchText(
        'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv',
        deps?.budget
      );
    }
    const items: LiveIoc[] = [];
    if (!tweetfeedText) return { items, sources: [{ id: 'tweetfeed', ok: false, count: 0 }] };
    const parsed = parseTweetFeed(tweetfeedText, PER_FEED_CAP);
    // To pull the reporter + permalink we re-walk the raw CSV alongside the
    // parsed entries, indexing rows by IOC value (newest-first).
    const rawRows = tweetfeedText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    const rowByValue = new Map<string, string>();
    for (let i = rawRows.length - 1; i >= 0; i--) {
      const row = rawRows[i]!;
      const cols = row.split(',');
      const value = cols[3];
      if (value && !rowByValue.has(value)) rowByValue.set(value, row);
    }
    let count = 0;
    for (const p of parsed) {
      const kind = iocKind(p.type);
      if (!kind) continue;
      const row = rowByValue.get(p.value);
      const reporter = row?.split(',')[1] || undefined;
      const reference_url = tweetfeedPermalink(row);
      // Context tags come from parseTweetFeed (reporter | tags); slice off the reporter half.
      const tagsPart = p.context?.includes(' | ') ? p.context.split(' | ').slice(1).join(' | ') : p.context;
      items.push({
        value: p.value,
        kind,
        source: 'tweetfeed',
        reporter,
        context: tagsPart,
        reference_url,
        observed_at: isoFromLoose(p.timestamp),
      });
      count++;
    }
    return { items, sources: [{ id: 'tweetfeed', ok: true, count, capped: count >= PER_FEED_CAP }] };
  },
};

/** MalwareBazaar: hash samples with family + file-type context. */
const malwarebazaarSource: FeedSource = {
  id: 'malwarebazaar',
  run: async ({ executionCtx, budget }) => {
    // The cached helper does a fetch + a KV read — consume both so the shared
    // budget stays honest (the old per-source slot reservation didn't).
    if (!consumeBudget(budget, 2)) return { items: [], sources: [{ id: 'malwarebazaar', ok: false, count: 0 }] };
    const malwareBazaarResult = await safeNullLog('fetch-malwarebazaar', fetchMalwareSamplesCached(executionCtx));
    const items: LiveIoc[] = [];
    if (!malwareBazaarResult) return { items, sources: [{ id: 'malwarebazaar', ok: false, count: 0 }] };
    let count = 0;
    for (const s of malwareBazaarResult.samples.slice(0, PER_FEED_CAP)) {
      const context =
        [s.signature, s.file_type].filter((x) => x && x !== 'unknown' && x !== 'n/a').join(' | ') || undefined;
      items.push({
        value: s.sha256,
        kind: 'hash',
        source: 'malwarebazaar',
        reporter: s.reporter || 'abuse.ch MalwareBazaar',
        context,
        reference_url: s.bazaar_url,
        observed_at: isoFromLoose(s.first_seen),
      });
      count++;
    }
    return { items, sources: [{ id: 'malwarebazaar', ok: true, count, capped: count >= PER_FEED_CAP }] };
  },
};

/** PhishTank + OpenPhish: one fetch, two source entries (per-entry reporter).
 *  PhishTank requires an API key — when not configured, only OpenPhish is
 *  emitted so the feed doesn't advertise a permanently-dead source row. */
const phishingSource: FeedSource = {
  id: 'phishing',
  run: async ({ executionCtx, kv, env, budget }) => {
    // Cached helper = fetch + KV read (see malwarebazaarSource).
    if (!consumeBudget(budget, 2)) {
      const hasPtKey = Boolean(env?.PHISHTANK_API_KEY);
      return {
        items: [],
        sources: hasPtKey
          ? [
              { id: 'phishtank', ok: false, count: 0 },
              { id: 'openphish', ok: false, count: 0 },
            ]
          : [{ id: 'openphish', ok: false, count: 0 }],
      };
    }
    const hasPtKey = Boolean(env?.PHISHTANK_API_KEY);
    const phishingResult = await safeNullLog(
      'fetch-phishing',
      fetchPhishingUrlsCached(executionCtx, kv, env?.PHISHTANK_API_KEY)
    );
    const items: LiveIoc[] = [];
    if (!phishingResult) {
      return {
        items,
        sources: hasPtKey
          ? [
              { id: 'phishtank', ok: false, count: 0 },
              { id: 'openphish', ok: false, count: 0 },
            ]
          : [{ id: 'openphish', ok: false, count: 0 }],
      };
    }
    let openphishCount = 0;
    let phishtankCount = 0;
    for (const u of phishingResult.urls) {
      const reporter = u.source === 'phishtank' ? 'PhishTank' : 'OpenPhish';
      const context = u.target ? `brand: ${u.target}` : undefined;
      items.push({
        value: u.url,
        kind: 'url',
        source: u.source,
        reporter,
        context,
        observed_at: isoFromLoose(u.first_seen),
      });
      if (u.source === 'phishtank') phishtankCount++;
      else openphishCount++;
    }
    return {
      items,
      sources: hasPtKey
        ? [
            { id: 'phishtank', ok: phishtankCount > 0, count: phishtankCount },
            { id: 'openphish', ok: openphishCount > 0, count: openphishCount },
          ]
        : [{ id: 'openphish', ok: openphishCount > 0, count: openphishCount }],
    };
  },
};

/** spmedia crypto-scam domains: shared cached fetch, mapped to domain IOCs. */
const cryptoScamSource: FeedSource = {
  id: 'crypto-scam',
  run: async ({ executionCtx, kv, budget }) => {
    // Cached helper = fetch + KV read (see malwarebazaarSource).
    if (!consumeBudget(budget, 2)) return { items: [], sources: [{ id: 'crypto-scam', ok: false, count: 0 }] };
    const result = await safeNullLog('fetch-crypto-scam', fetchCryptoScamCached(executionCtx, kv));
    const items: LiveIoc[] = [];
    if (!result) return { items, sources: [{ id: 'crypto-scam', ok: false, count: 0 }] };
    for (const it of result.items.slice(0, PER_FEED_CAP)) {
      items.push({
        value: it.domain,
        kind: 'domain',
        source: 'crypto-scam',
        reporter: 'spmedia crypto-scam feed',
        context: 'crypto phishing / scam / drainer',
      });
    }
    return {
      items,
      sources: [{ id: 'crypto-scam', ok: items.length > 0, count: items.length, capped: items.length >= PER_FEED_CAP }],
    };
  },
};

// ── Dedicated AI / LLM threat-intelligence sources ────────────────────────
//
// Unlike every other source here, these two are not "malicious IPs someone
// blocklisted". They carry per-indicator ATTRIBUTION — actor category, ATT&CK
// technique, honeypot persona/model interaction — which is what makes a row in
// the live stream say something an analyst can act on rather than just
// "block this address".

/**
 * AI Honeypot Observatory (ai-honeypots.com).
 *
 * The JSON feed is primary and the `.txt` blocklist is the fallback: they carry
 * the same 1,000 IPs, but only the JSON has `last_seen` (→ `observed_at`, so
 * these rows participate in the freshness window and sort to the top of the
 * stream) plus `actor_category` / `ttps` / hit counts. Upstream already orders
 * the JSON most-confident-first, so the per-feed cap keeps the 7 `very-high` and
 * 78 `high` rows rather than an arbitrary slice.
 *
 * TLP:WHITE / CC0 per the feed header — safe to republish.
 */
const aiHoneypotsSource: FeedSource = {
  id: 'ai-honeypots',
  run: async (deps) => {
    const json = await fetchJson('https://ai-honeypots.com/feeds/iocs.json', deps?.budget);
    const txt = json ? null : await fetchText('https://ai-honeypots.com/feeds/iocs.txt', deps?.budget);
    if (!json && !txt) return { items: [], sources: [{ id: 'ai-honeypots', ok: false, count: 0 }] };
    // The .txt fallback has no timestamps/attribution, so it parses to bare
    // entries — still useful, just undated, and the source row stays honest
    // about which upstream actually answered.
    const parsed = json ? parseAiHoneypots(json, PER_FEED_CAP) : parseAiHoneypotsFallback(txt as string, PER_FEED_CAP);
    const items: LiveIoc[] = parsed.map((e) => ({
      value: e.value,
      kind: 'ip',
      source: 'ai-honeypots',
      reporter: 'AI Honeypot Observatory',
      context: e.context,
      reference_url: 'https://ai-honeypots.com/feeds/',
      ...(e.timestamp ? { observed_at: e.timestamp } : {}),
    }));
    return {
      items,
      sources: [
        { id: 'ai-honeypots', ok: items.length > 0, count: items.length, capped: items.length >= PER_FEED_CAP },
      ],
    };
  },
};

/**
 * `feeds/iocs.txt` fallback parser: `<ip>  # ACTOR | conf:X | hits:N`.
 * Only reached when the JSON feed is unreachable.
 */
const parseAiHoneypotsFallback = (text: string, cap: number): ParsedEntry[] => {
  const out: ParsedEntry[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const hash = trimmed.indexOf('#');
    const ip = (hash === -1 ? trimmed : trimmed.slice(0, hash)).trim();
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) continue;
    const meta = hash === -1 ? '' : trimmed.slice(hash + 1).trim();
    out.push({ value: ip, type: 'ip', ...(meta ? { context: `AI honeypot — ${meta}` } : {}) });
    if (out.length >= cap) break;
  }
  return out;
};

/**
 * LLM ThreatIntel (llm-threatintel.com) — the `data/iocs.json` indicator set.
 *
 * Indicators are keyed to a named campaign (`campaign` field) and carry the
 * reporting analyst's own context, so each row is a claim with provenance
 * rather than an anonymous address. The companion actors/posts/blog data lives
 * in `ai-llm-intel.ts`, which is what feeds brief / trends / blog.
 */
const llmThreatintelSource: FeedSource = {
  id: 'llm-threatintel',
  run: async (deps) => {
    const json = await fetchJson('https://llm-threatintel.com/data/iocs.json', deps?.budget);
    if (!json) return { items: [], sources: [{ id: 'llm-threatintel', ok: false, count: 0 }] };
    const parsed = parseLlmThreatintelIocs(json, PER_FEED_CAP);
    const items: LiveIoc[] = [];
    for (const e of parsed) {
      // The feed's `type` is already validated by the parser's LLM_TYPE_MAP, so
      // this only drops entries whose type has no live-IOC kind.
      const kind = iocKind(e.type ?? '');
      if (!kind) continue;
      items.push({
        value: e.value,
        kind,
        source: 'llm-threatintel',
        reporter: 'LLM ThreatIntel',
        context: e.context,
        // The feed's own IOC page as the permalink, so a row is click-throughable.
        reference_url: 'https://llm-threatintel.com/#ioc-feed',
        ...(e.timestamp ? { observed_at: e.timestamp } : {}),
      });
    }
    return {
      items,
      sources: [
        { id: 'llm-threatintel', ok: items.length > 0, count: items.length, capped: items.length >= PER_FEED_CAP },
      ],
    };
  },
};

/** Fetch + parse JSON, sharing `fetchText`'s budget accounting and HTML guard. */
async function fetchJson(url: string, budget?: { used: number; max: number }): Promise<string | null> {
  return fetchText(url, budget);
}

// ── Curated open-source feeds ────────────────────────────────────────────
//
// Generated from `CURATED_FEEDS` (see api/src/lib/feed-curation.ts for the
// per-feed audit, the retired list, and why each feed was chosen) so the
// curation record and the runtime registry cannot drift: there is exactly one
// place to edit when a feed rots.

/** Parser per curated feed id. Anything not listed falls back to a kind-based
 *  plain-list reader, which is correct for the bare blocklists. */
const CURATED_PARSERS: Record<string, (body: string, cap: number) => ParsedEntry[]> = {
  'foxit-cobaltstrike': parseCobaltStrikeCsv,
  'carbonblack-c2': parseCarbonBlackC2,
  'threatview-c2': parseThreatviewC2,
  'threatfox-hostfile': parseThreatfoxHostfile,
  'threatfox-urls': parseThreatfoxUrls,
  'c2intel-domains': parseC2IntelDomains,
  'botvrij-domain': parseBotvrijDomains,
  'sslbl-ja3': parseSslblJa3,
  'tsirolnik-spam': parsePlainDomainList,
  'threatcluster-ip': (body, cap) => parsePlainTextIps(body, cap),
  'threatcluster-domains': parsePlainDomainList,
  greensnow: (body, cap) => parsePlainTextIps(body, cap),
  siberkapan: (body, cap) => parsePlainTextIps(body, cap),
  'bruteforce-login': (body, cap) => parsePlainTextIps(body, cap),
  'bl-de-ssh': (body, cap) => parsePlainTextIps(body, cap),
};

/** Map a curated feed's declared kind onto the live-IOC kind union. */
function curatedKind(f: CuratedFeed): IocKind {
  if (f.kind === 'ipv4') return 'ip';
  if (f.kind === 'domain') return 'domain';
  if (f.kind === 'url') return 'url';
  return 'hash';
}

/**
 * Build the registry entry for one curated feed.
 *
 * `withTimestamp` is on only when the upstream actually publishes per-entry
 * dates. This matters: `finalizeLiveIocs` drops timestamped items older than
 * STALENESS_HOURS, so tagging a dateless blocklist as timestamped would silently
 * delete the entire feed, while leaving a dated C2 list undated would hide its
 * freshness. Dated: foxit-cobaltstrike, carbonblack-c2, threatview-c2,
 * threatfox-urls, sslbl-ja3.
 */
const curatedSource = (f: CuratedFeed): FeedSource => {
  const parse = CURATED_PARSERS[f.id] ?? ((body: string, cap: number) => parsePlainTextIps(body, cap));
  return textFeedSource({
    id: f.id,
    url: f.url,
    fallbackUrls: f.fallbackUrls,
    parse: (body, cap) => parse(body, cap),
    kind: curatedKind(f),
    reporter: f.name,
    context: f.context,
    withTimestamp: CURATED_DATED.has(f.id),
    // An empty body from a 200 means the feed collapsed upstream — report it
    // unhealthy rather than letting it read as a healthy-but-quiet source.
    okRequiresItems: true,
  });
};

const CURATED_DATED = new Set<string>([
  'foxit-cobaltstrike',
  'carbonblack-c2',
  'threatview-c2',
  'threatfox-urls',
  'sslbl-ja3',
]);

// Tier 1 (named C2 infrastructure with attribution) first so the synchronous
// cold-start fan-out's 42-subrequest budget is spent on the evidence-bearing
// feeds before the high-volume context-free blocklists. The queue path — the
// primary refresh model — has no such ceiling and covers everything.
const curatedTier1 = CURATED_FEEDS.filter((f) => f.priority === 1).map(curatedSource);
const curatedTier2 = CURATED_FEEDS.filter((f) => f.priority === 2).map(curatedSource);

// Registry, ordered exactly as the original sequential blocks pushed sources —
// concurrentMap preserves input order, so the flattened sources/items keep this
// order (the post-sort and per-source recount depend only on it being stable).
const FEED_SOURCES: FeedSource[] = [
  tweetfeedSource,
  textFeedSource({
    id: 'sans-isc',
    url: 'https://isc.sans.edu/api/sources/attacks/200/?json',
    parse: parseSansIsc,
    kind: 'ip',
    reporter: 'ISC sensor network',
    context: entryContext,
    withTimestamp: true,
  }),
  textFeedSource({
    id: 'c2-intel',
    url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv',
    parse: parseC2IntelFeeds,
    kind: 'ip',
    reporter: 'drb-ra/C2IntelFeeds',
    context: entryContext,
  }),
  textFeedSource({
    id: 'urlhaus',
    url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    parse: parseUrlhaus,
    kind: 'url',
    reporter: 'abuse.ch URLhaus',
    context: entryContext,
    withTimestamp: true,
    filterType: 'url',
  }),
  textFeedSource({
    id: 'emerging-threats',
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'Proofpoint ETOpen',
    context: 'recent compromise / blocklist',
  }),
  textFeedSource({
    id: 'otx-reputation',
    url: 'https://reputation.alienvault.com/reputation.generic',
    parse: parseAlienVaultReputation,
    kind: 'ip',
    reporter: 'AlienVault OTX',
    context: entryContext,
  }),
  textFeedSource({
    id: 'threatfox',
    url: 'https://threatfox.abuse.ch/export/csv/recent/',
    parse: parseThreatfox,
    kind: 'per-entry',
    reporter: 'abuse.ch ThreatFox',
    context: entryContext,
    withTimestamp: true,
  }),
  malwarebazaarSource,
  phishingSource,
  cryptoScamSource,
  aiHoneypotsSource,
  llmThreatintelSource,
  ...curatedTier1,
  ...curatedTier2,
  textFeedSource({
    id: 'binarydefense',
    url: `${CPS_BASE}/binarydefense.txt`,
    fallbackUrls: ['https://www.binarydefense.com/banlist.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'BinaryDefense',
    context: 'curated malicious IP blocklist',
  }),
  textFeedSource({
    id: 'tor-exit',
    url: `${CPS_BASE}/tor-exit.txt`,
    fallbackUrls: ['https://check.torproject.org/torbulkexitlist'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'Tor Project',
    context: 'Tor exit node',
  }),
  textFeedSource({
    id: 'avanzato-c2',
    url: `${CPS_BASE}/avanzato_c2.txt`,
    fallbackUrls: ['https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'CriticalPathSecurity',
    context: 'Avanzato malware C2 infrastructure',
  }),
  textFeedSource({
    id: 'cps-collected',
    url: `${CPS_BASE}/cps-collected-iocs.txt`,
    fallbackUrls: ['https://lists.blocklist.de/lists/all.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'CriticalPathSecurity',
    context: 'CPS internally collected malicious IPs',
  }),
  textFeedSource({
    id: 'blocklist-de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'Blocklist.de',
    context: 'reported attack source (48h)',
  }),
  textFeedSource({
    id: 'cinsscore',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'CINSscore',
    context: 'suspicious/malicious IP',
  }),
  textFeedSource({
    id: 'bbcan177-ips',
    url: 'https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'BBcan177',
    context: 'malicious IP blocklist',
  }),
  textFeedSource({
    // joewein's dom-bl.txt is tiny (181 domains at the 2026-10-05 audit) and is
    // the only primary we had for curated malicious domains, so it now falls back
    // to the far larger tsirolnik spam/malware domain list before the generic
    // StevenBlack hosts file (which is mostly benign-with-ad-servers and a poor
    // last resort for this source's "known malicious domain" framing).
    id: 'domains-blacklist',
    url: 'https://www.joewein.net/dl/bl/dom-bl.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/tsirolnik/spam-domains-list/master/spamdomains.txt',
      'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    ],
    parse: parsePhishingArmy,
    kind: 'domain',
    reporter: 'Joewein.net',
    context: 'known malicious domain',
  }),
  textFeedSource({
    // RETIRED as the URL primary (audited 2026-10-05: shrunk to 9 URLs, one of
    // them a malformed `ttp://` row). It survives only as the LAST-RESORT
    // fallback for `botvrij-domain`, which carries 3,894 domains.
    id: 'botvrij-urls',
    url: 'https://www.botvrij.eu/data/ioclist.url.raw',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt',
    ],
    parse: parseBotvrijUrls,
    kind: 'url',
    reporter: 'Botvrij.eu',
    context: 'curated malicious URL',
    okRequiresItems: true,
  }),
  textFeedSource({
    id: 'bruteforce-blocker',
    url: 'https://danger.rulez.sk/projects/bruteforceblocker/blist.php',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'BruteForce Blocker',
    context: 'brute-force attack source',
  }),
  textFeedSource({
    id: 'threatview-ip',
    url: 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'Threatview.io',
    context: 'high confidence malicious IP',
  }),
  textFeedSource({
    id: 'threatview-domains',
    url: 'https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    ],
    parse: parseThreatviewDomains,
    kind: 'domain',
    reporter: 'Threatview.io',
    context: 'high confidence malicious domain',
  }),
  textFeedSource({
    id: 'viriback-c2',
    url: 'https://tracker.viriback.com/dump.php',
    fallbackUrls: [
      'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cps-collected-iocs.txt',
    ],
    parse: parseViriback,
    kind: 'per-entry',
    reporter: 'ViriBack C2 Tracker',
    context: entryContext,
    withTimestamp: true,
  }),
  textFeedSource({
    id: 'certpl-warnings',
    url: 'https://hole.cert.pl/domains/v2/domains.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    ],
    parse: parseThreatviewDomains,
    kind: 'domain',
    reporter: 'CERT.PL',
    context: 'phishing/warning domain',
  }),
  textFeedSource({
    id: 'bitwire-outbound',
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'Bitwire',
    context: 'malicious destination IP (C2, malware, phishing)',
  }),
  textFeedSource({
    id: 'bitwire-inbound',
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'],
    parse: parsePlainTextIps,
    kind: 'ip',
    reporter: 'Bitwire',
    context: 'reported attack source (spam, scanning, brute-force)',
  }),
  textFeedSource({
    id: 'phishunt',
    url: 'https://phishunt.io/feed.txt',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt',
    ],
    parse: parseBotvrijUrls,
    kind: 'url',
    reporter: 'phishunt',
    context: 'phishing URL',
    okRequiresItems: true,
  }),
  textFeedSource({
    id: 'swiftioc',
    url: 'https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/main/public/iocs/high_confidence.csv',
    parse: parseSwiftioc,
    kind: 'per-entry',
    reporter: 'SwiftIOC collector',
    context: entryContext,
    withTimestamp: true,
    okRequiresItems: true,
  }),
];

/**
 * Registry source ids — the per-source runner units the queue fan-out
 * enqueues. NB: this is the FeedSource.id set, NOT the response source-id
 * set. It excludes 'feed-scheduler' (a compose-time D1 read that bypasses
 * the staleness filter — see fetchLiveIocs).
 */
export const FEED_SOURCE_IDS: readonly string[] = FEED_SOURCES.map((s) => s.id);

/**
 * Sources per queue message.
 *
 * Sized so one consumer invocation stays well inside the free-plan 50-subrequest
 * cap even on the worst-case batch: most sources cost 1 fetch, but the ones with
 * KV-cached helpers (malwarebazaar, phishing, crypto-scam) and the multi-URL
 * fallback chains cost 2-3. At 6 sources/batch the ceiling is ~18 subrequests,
 * leaving ample room for the slice write.
 *
 * Upper bound on the other side: too small and the compose path needs a slice
 * read per batch, so the batch count is itself the compose subrequest cost.
 * 6 × ~46 sources ≈ 8 slices ≈ 8 reads, comfortably inside the cap, and each
 * still amortises well over the sources it covers.
 */
export const FEED_BATCH_SIZE = 6;

/**
 * Chunk the registry ids into fixed-size batches, preserving order.
 *
 * Order is load-bearing: `finalizeLiveIocs` relies on contributions arriving in
 * FEED_SOURCES order for its stable newest-first sort and per-source recount.
 */
export function feedSourceBatches(size: number = FEED_BATCH_SIZE): string[][] {
  const batches: string[][] = [];
  for (let i = 0; i < FEED_SOURCE_IDS.length; i += size) {
    batches.push(FEED_SOURCE_IDS.slice(i, i + size));
  }
  return batches;
}

/**
 * Stable id for a batch: an FNV-1a hash of its member source ids.
 *
 * Content-addressed rather than index-addressed so the producer and the consumer
 * derive the same key without exchanging an index — the consumer only ever sees
 * `sourceIds`, and an index would silently orphan every slice if the registry
 * were reordered or a source inserted. It also means a registry edit only
 * invalidates the slices of the batches it actually touched.
 */
export function feedBatchId(sourceIds: readonly string[]): string {
  const s = sourceIds.join(',');
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `b${h.toString(16)}`;
}

/**
 * Run a single registered feed source by id and return its contributed
 * items + source-health entries. Returns null for an unknown id (the queue
 * consumer acks-without-retry on null). The result is intentionally the raw
 * pre-freshness-filter contribution — slice consumers (compose-on-read) apply
 * the freshness filter + recount at read time, exactly as fetchLiveIocs does.
 */
export async function runFeedSourceById(id: string, deps: FeedDeps): Promise<FeedResult | null> {
  const source = FEED_SOURCES.find((s) => s.id === id);
  if (!source) return null;
  return source.run(deps);
}

/**
 * Post-processing shared by the synchronous fan-out (fetchLiveIocs) and the
 * slice-composed read (composeLiveIocs): freshness filter → newest-first sort
 * → compose-time feed-scheduler D1 read → per-source recount → drop empty
 * sources → degraded flag → per-source newest_observation. Keeping this in one
 * place guarantees both paths emit a byte-identical response shape.
 *
 * `extraDegraded` lets the compose path flag degraded when a per-source slice
 * is missing (the source is simply absent from `sources`, so the ok===false
 * check below can't see it).
 */
async function finalizeLiveIocs(
  items: LiveIoc[],
  sources: LiveSource[],
  env?: Env,
  extraDegraded = false
): Promise<LiveIocsResponse> {
  // Refang + allowlist + confidence scoring. Runs before the staleness
  // filter so we don't pay the cost of scoring items we're about to drop.
  // Items that fail the allowlist (RFC 5737 docs, vendor domains, etc.) or
  // score in the 'rejected' band are removed here.
  const iocKindToConfidenceKind: Record<IocKind, 'ipv4' | 'domain' | 'url' | 'hash'> = {
    ip: 'ipv4',
    url: 'url',
    domain: 'domain',
    hash: 'hash',
  };
  const normalizedItems: LiveIoc[] = [];
  for (const it of items) {
    const refanged = refang(it.value);
    if (refanged !== it.value) it.value = refanged;
    const kind = iocKindToConfidenceKind[it.kind] ?? 'unknown';
    if (isBenign(it.value, kind).allow === false) continue;
    const c = scoreConfidence(it.value, kind, it.context);
    if (c.band === 'rejected') continue;
    it.confidence = c.score;
    it.confidence_band = c.band;
    normalizedItems.push(it);
  }
  items = normalizedItems;

  // Drop stale items — observed before the freshness cutoff. Items without
  // observed_at survive (they're bulk-snapshot feeds whose freshness is
  // governed by the upstream publish cadence, not per-entry).
  const staleCutoffMs = Date.now() - STALENESS_HOURS * 3600 * 1000;
  const staleCutoffIso = new Date(staleCutoffMs).toISOString();
  const freshItems = items.filter((it) => !it.observed_at || it.observed_at >= staleCutoffIso);

  // Sort newest-first; entries without observed_at land at the tail.
  freshItems.sort((a, b) => {
    if (a.observed_at && b.observed_at) return b.observed_at.localeCompare(a.observed_at);
    if (a.observed_at && !b.observed_at) return -1;
    if (!a.observed_at && b.observed_at) return 1;
    return 0;
  });

  // ─── Feed scheduler IOCs (from graph_nodes D1) ──────────────────────────
  // IOCs fetched by the feed scheduler's auto-run cron and stored in
  // graph_nodes. This stays a compose-time D1 read (it bypasses the staleness
  // filter), so both the synchronous and the slice-composed paths surface the
  // same feed-scheduler IOCs.
  const db = (env as { BRIEFINGS_DB?: D1Database } | undefined)?.BRIEFINGS_DB;
  if (db) {
    try {
      const feedIocs = await db
        .prepare(
          `SELECT value, type, sources, last_seen, properties
           FROM graph_nodes
           WHERE json_extract(sources, '$[0]') LIKE 'feed:%'
           ORDER BY last_seen DESC
           LIMIT ?`
        )
        .bind(PER_FEED_CAP)
        .all<{ value: string; type: string; sources: string; last_seen: string; properties: string }>();
      if (feedIocs.results && feedIocs.results.length > 0) {
        let count = 0;
        let newest = '';
        for (const row of feedIocs.results) {
          const kind =
            row.type === 'ip' ? ('ip' as const) : row.type === 'hash' ? ('hash' as const) : (row.type as IocKind);
          const props = JSON.parse(row.properties || '{}') as Record<string, unknown>;
          const feedName = (props.feed as string) ?? '';
          freshItems.push({
            value: row.value,
            kind,
            source: 'feed-scheduler',
            context: feedName ? `Feed: ${feedName}` : 'Feed scheduler',
            observed_at: row.last_seen,
          });
          count++;
          if (!newest) newest = row.last_seen;
        }
        sources.push({ id: 'feed-scheduler', ok: true, count, newest_observation: newest });
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* non-fatal */
    }
  }

  // Recompute per-source counts after the freshness filter — the response
  // should not advertise contribution counts that include dropped stale items.
  const freshCountBySource = new Map<string, number>();
  for (const it of freshItems) {
    freshCountBySource.set(it.source, (freshCountBySource.get(it.source) ?? 0) + 1);
  }
  for (const s of sources) {
    s.count = freshCountBySource.get(s.id) ?? 0;
    // NB: do NOT downgrade `s.ok` on count===0 — `ok` means "the fetch
    // succeeded"; a source can legitimately fetch fine and have no fresh
    // items. The failure branches above already set ok:false on a real fetch
    // failure, which is what `degraded` (below) keys on.
  }

  // Drop silent-failure sources from the response — sources that returned
  // zero usable items are noise in the UI and look like permanent breakage
  // when they're often a one-off upstream hiccup.
  const activeSources = sources.filter((s) => s.count > 0);
  // `degraded` is true when an upstream FETCH failed (some source ok===false)
  // OR `extraDegraded` is set — the compose-on-read path passes that when a
  // per-source slice is missing (not yet warmed / expired), so an incomplete
  // slice set drives the shorter cache TTL and self-heals.
  const degraded = extraDegraded || sources.some((s) => s.ok === false);

  // Per-source freshness: newest per-entry observation timestamp.
  // Sources without per-entry timestamps (C2IntelFeeds, ET compromised-ips,
  // OTX reputation) get newest_observation=undefined — UI renders that as
  // "no per-entry timestamp" so analysts know the data is bulk-snapshot.
  const newestBySource = new Map<string, string>();
  for (const it of freshItems) {
    if (!it.observed_at) continue;
    const cur = newestBySource.get(it.source);
    if (!cur || it.observed_at > cur) newestBySource.set(it.source, it.observed_at);
  }
  for (const s of activeSources) {
    const newest = newestBySource.get(s.id);
    if (newest) s.newest_observation = newest;
  }

  return {
    generated_at: new Date().toISOString(),
    // Active sources (count > 0) drive the freshness/count badges. We also
    // ship the pre-filter roster as `registered_sources` so the UI can
    // render the full ~30+ feed list (and the filter pills for it),
    // distinguishing "empty this snapshot" from "actively producing".
    sources: activeSources,
    registered_sources: sources,
    total: freshItems.length,
    items: freshItems.slice(0, MAX_ITEMS),
    degraded,
  };
}

export async function fetchLiveIocs(
  executionCtx?: { waitUntil: (p: Promise<unknown>) => void },
  kv?: KVNamespace,
  env?: Env
): Promise<LiveIocsResponse> {
  // Fan out across every registered feed source with a bounded concurrency.
  // Replaces the three sequential fetch batches (P7: a slow feed in batch 1
  // delayed the start of batch 3). concurrentMap preserves input order, so the
  // flattened sources/items keep FEED_SOURCES order — which the freshness sort
  // and the per-source recount in finalizeLiveIocs rely on being stable.
  //
  // Subrequest-budget guard (2026-06 audit): the synchronous fan-out is the
  // FALLBACK for cold-colo / missing-slice, and the cache-warm cron runs it
  // ~22x per cron tick. Each feed `run()` does >= 1 subrequest (most do 1-3
  // + KV reads), so a 35-source fan-out can hit the 50-subrequest cap.
  // We install a shared budget and short-circuit a source to `ok:false`
  // (with `error: 'budget_exhausted'`) when the cap is reached, so we
  // degrade gracefully instead of throwing and dropping ALL sources on the
  // floor (the previous behavior under subrequest exhaustion). The budget
  // must cover every registered source — previously hardcoded to 30, which
  // silently cut the last 5 sources after more feeds were added. It's now
  // derived from FEED_SOURCES.length so it stays correct as feeds change.
  // The cap leaves headroom for the analytics + KV/queue reads that follow
  // the fan-out in composeOrFallback. Each source's run() does exactly 1
  // fetch subrequest (+ optional KV reads for cached helpers like
  // malwarebazaar/phishing). With 30 sources the total stays well under the
  // 50-subrequest free-plan cap. Capped at 45 for safety margin.
  // Hard cap on the fan-out's REAL subrequests (each source consumes 1-3 via
  // fetchText + cached-helper KV reads). Leaves headroom under the free-plan
  // 50-subrequest invocation cap for the cache/KV/analytics reads the handler
  // does after the fan-out (cache.match, trackEvent, cache.put). Previously
  // this reserved 1 slot per source up-front while sources spent 1-3 each, so
  // a full fan-out silently overshot the cap and got killed mid-build
  // ("Too many subrequests") — surfacing as HTTP 503 + empty layers on
  // global-pulse. Sources now consume their actual usage (consumeBudget) and
  // degrade to ok:false when the cap is hit.
  const SUBREQUEST_BUDGET = 42;
  const budget = { used: 0, max: SUBREQUEST_BUDGET };
  const deps: FeedDeps = { executionCtx, kv, env, budget };
  const feedResults = await concurrentMap(
    FEED_SOURCES,
    async (s) => {
      // Only launch a source when the shared budget still has room; otherwise
      // return a stub so concurrentMap still produces a result for this index.
      // (concurrentMap preserves order; finalize needs every slot to have a
      // matching source row.) Actual consumption happens inside each source's
      // run() via consumeBudget — this check is just the cheap launch gate.
      if (budget.used >= budget.max) {
        return {
          items: [] as LiveIoc[],
          sources: [{ id: s.id, ok: false, count: 0 }] as LiveSource[],
        };
      }
      return s.run(deps);
    },
    FEED_FANOUT_CONCURRENCY
  );

  const items: LiveIoc[] = [];
  const sources: LiveSource[] = [];
  for (const r of feedResults) {
    for (const it of r.items) items.push(it);
    for (const s of r.sources) sources.push(s);
  }

  return finalizeLiveIocs(items, sources, env);
}

// Cache API reads are free and parallel, so compose can fan over the slices
// wider than the upstream fetch fan-out.
const SLICE_READ_CONCURRENCY = 12;

/**
 * Compose the live-IOC response from the per-source Cache API slices instead of
 * the synchronous fan-out. Reads every registry slice in parallel, flattens
 * them in FEED_SOURCE_IDS order (so finalize's stable sort + recount behave
 * exactly as the sync path), and flags `extraDegraded` when any slice is
 * missing. Returns the response plus the number of slices present, so the
 * caller can fall back to the synchronous fan-out on a cold start (no slices
 * yet, or an empty compose).
 *
 * Slices live in the per-colo Cache API (free, not counted against the KV
 * write quota) — see `api/src/lib/live-iocs-slices.ts` for the budget
 * reasoning. Cold-colo misses return null; the response flags `extraDegraded`
 * and the caller falls through to the synchronous fan-out.
 */
export async function composeLiveIocs(env?: Env): Promise<{ response: LiveIocsResponse; presentSlices: number }> {
  const batches = feedSourceBatches();
  // One Cache API read per BATCH, not per source — see `FeedQueueMessage.sourceIds`
  // for why per-source slices stopped scaling.
  const batchSlices = await concurrentMap(batches, (ids) => readBatchSlice(feedBatchId(ids)), SLICE_READ_CONCURRENCY);
  const items: LiveIoc[] = [];
  const sources: LiveSource[] = [];
  let presentSlices = 0;
  for (const slice of batchSlices) {
    if (!slice) continue;
    presentSlices++;
    // Defensive per-source cap mirroring the sync path (each source's run() caps
    // at PER_FEED_CAP). A slice is written from those already-capped results, so
    // this only guards against a corrupted/oversized slice ballooning compose.
    for (const it of slice.items.slice(0, PER_FEED_CAP * FEED_BATCH_SIZE)) items.push(it);
    for (const s of slice.sources) sources.push(s);
  }
  const extraDegraded = presentSlices < batches.length;
  const response = await finalizeLiveIocs(items, sources, env, extraDegraded);
  return { response, presentSlices };
}

/**
 * Enqueue a refresh for every registry source, batched, plus the AI/LLM intel
 * slice warm.
 *
 * One message per batch (not per source) so each consumer invocation covers
 * `FEED_BATCH_SIZE` sources against its own subrequest budget and writes a
 * single slice. Sends are staggered so the messages don't land as one burst the
 * consumer (max_concurrency 10) can't drain, which would show up as an
 * average-lag spike. The AI/LLM warm rides the same batch (it is one message,
 * one invocation, independent of the feed batches).
 */
export async function enqueueAllFeeds(queue: Queue<FeedQueueMessage>): Promise<void> {
  const batches = feedSourceBatches();
  const messages: Array<{ body: FeedQueueMessage; delaySeconds?: number }> = batches.map((sourceIds, i) => ({
    body: { sourceIds },
    delaySeconds: i * 2,
  }));
  // AI/LLM intel last, and staggered behind the batches so the dedicated
  // narrative payload never competes with the indicator batches for the head of
  // the drain.
  messages.push({ body: { aiLlmWarm: true }, delaySeconds: batches.length * 2 + 5 });
  await queue.sendBatch(messages as Parameters<Queue<FeedQueueMessage>['sendBatch']>[0]);
}

const ENQUEUE_COOLDOWN_KEY = 'live-iocs:enqueue-cooldown';
const ENQUEUE_COOLDOWN_SECONDS = 15 * 60;
// Per-colo shadow of the KV cooldown marker. `caches.default` is free and
// fast, so we only do the KV read on a miss (1 per cooldown per colo instead
// of 1 per page request). The shadow TTL equals the cooldown TTL, so a stale
// "cooling down" answer can only ever delay — never cause a runaway enqueue.
const ENQUEUE_COOLDOWN_SHADOW = new Request('https://live-iocs-enqueue-cooldown-shadow.internal/v1');

/**
 * Enqueue a slice refresh, debounced via a short KV cooldown so a burst of
 * hits doesn't fire a fan-out fetch per source. Re-checks the KV marker
 * for cross-colo coordination, but caches the result in `caches.default` for
 * `ENQUEUE_COOLDOWN_SECONDS` so a hot path is a cache hit, not a KV read.
 */
async function isEnqueueCoolingDown(kv: KVNamespace | undefined): Promise<boolean> {
  if (!kv) return false;
  const cache = (caches as unknown as { default: Cache }).default;
  if (cache) {
    try {
      if (await cache.match(ENQUEUE_COOLDOWN_SHADOW)) return true;
    } catch (_catchErr) {
      logError('isEnqueueCoolingDown failed', _catchErr);
      /* fall through to KV */
    }
  }
  const fresh = await safeNullLog('kv-get-enqueue-cooldown', kv.get(ENQUEUE_COOLDOWN_KEY));
  if (cache && fresh) {
    try {
      await cache.put(
        ENQUEUE_COOLDOWN_SHADOW,
        new Response('1', { headers: { 'cache-control': `max-age=${ENQUEUE_COOLDOWN_SECONDS}` } })
      );
    } catch (_catchErr) {
      logError('isEnqueueCoolingDown failed', _catchErr);
      /* best-effort — a miss just falls back to KV next time */
    }
  }
  return !!fresh;
}

// ── Hourly enqueue-cycle gate ────────────────────────────────────────────
// The hourly cron enqueues 48 messages (25 gp:warm + 23 live-iocs) every
// hour unconditionally — ~2,400 queue ops/day. The cycle marker lets the
// cron skip the fan-out when a previous cycle (or a hit-path refresh) is
// still fresh: TTL 105 min (cadence 60) means at most one cycle is skipped,
// and the coverage is safe — gp:warm slices carry a 150-min TTL and the
// live-iocs Cache-API slices a 6h TTL, both far beyond a 2-cycle gap.
const ENQUEUE_CYCLE_KEY = 'live-iocs:enqueue-cycle';
export const ENQUEUE_CYCLE_TTL_SECONDS = 105 * 60;

/** True when the last enqueue cycle is still fresh → the hourly fan-out can be skipped. */
export async function shouldSkipEnqueueCycle(kv: KVNamespace | undefined): Promise<boolean> {
  if (!kv) return false;
  return (await safeNullLog('kv-get-enqueue-cycle', kv.get(ENQUEUE_CYCLE_KEY))) !== null;
}

/** Record that a fan-out completed so the next hourly cron skips its redundant re-enqueue. */
export async function markEnqueueCycle(kv: KVNamespace | undefined): Promise<void> {
  if (!kv) return;
  await kv.put(ENQUEUE_CYCLE_KEY, new Date().toISOString(), { expirationTtl: ENQUEUE_CYCLE_TTL_SECONDS });
}

async function maybeEnqueueAllFeeds(
  queue: Queue<FeedQueueMessage> | undefined,
  kv: KVNamespace | undefined
): Promise<void> {
  if (!queue) return;
  if (await isEnqueueCoolingDown(kv)) return;
  await enqueueAllFeeds(queue);
  if (kv) {
    // A hit-path refresh is as fresh as a cron cycle — extend the cycle
    // marker so the next hourly cron skips its redundant fan-out too.
    await markEnqueueCycle(kv).catch(() => {});
    await kv.put(ENQUEUE_COOLDOWN_KEY, new Date().toISOString(), { expirationTtl: ENQUEUE_COOLDOWN_SECONDS });
    const cache = (caches as unknown as { default: Cache }).default;
    if (cache) {
      try {
        await cache.put(
          ENQUEUE_COOLDOWN_SHADOW,
          new Response('1', { headers: { 'cache-control': `max-age=${ENQUEUE_COOLDOWN_SECONDS}` } })
        );
      } catch (_catchErr) {
        logError('maybeEnqueueAllFeeds failed', _catchErr);
        /* best-effort */
      }
    }
  }
}

/**
 * Build the response body for a cache miss / revalidation: compose from the
 * per-colo Cache API slices and warm them (debounced) for next time. Falls
 * back to the synchronous fan-out only on a true cold start (no slices present
 * yet, or an empty compose), so the page is never empty before the producer
 * has run.
 */
async function composeOrFallback(c: Context<{ Bindings: Env }>): Promise<LiveIocsResponse> {
  const kv = c.env.KV_CACHE;
  c.executionCtx.waitUntil(
    maybeEnqueueAllFeeds(c.env.FEEDS_QUEUE, kv).catch((e) => logError('live-iocs-enqueue failed', e))
  );
  const { response, presentSlices } = await composeLiveIocs(c.env);
  // Serve the composed response when slices exist AND it isn't empty. An empty
  // compose (e.g. the only present slices are timestamped and all their items
  // aged out) falls through to the sync fan-out so the page is never blank.
  if (presentSlices > 0 && response.total > 0) return response;
  // Cold start (zero slices, or an empty compose) — synchronous fan-out.
  return fetchLiveIocs(c.executionCtx, kv, c.env);
}

// In-isolate single-flight for the cold-cache build (DOS-1). On a cold colo
// cache, N concurrent requests would each launch the full source upstream
// fan-out (cache stampede). Collapsing concurrent builds onto one shared
// in-flight promise per isolate means only one fan-out runs while the rest
// await its result; the promise clears on settle so the next cold miss
// rebuilds. The result is request-agnostic (global live-IOC data), so sharing
// the first caller's build across the others is correct.
let inflightLiveIocsBuild: Promise<LiveIocsResponse> | null = null;

function buildLiveIocsSingleFlight(c: Context<{ Bindings: Env }>): Promise<LiveIocsResponse> {
  if (inflightLiveIocsBuild) return inflightLiveIocsBuild;
  inflightLiveIocsBuild = composeOrFallback(c).finally(() => {
    inflightLiveIocsBuild = null;
  });
  return inflightLiveIocsBuild;
}

export async function liveIocsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  // Debug escape hatch: `?debug=1` (or any non-empty value) bypasses the
  // cache and runs a fresh synchronous fan-out with per-source error
  // diagnostics. Designed for auditing why specific sources are showing
  // `ok:false` on the page - the normal response body is augmented with
  // a `debug` array describing every registered source's actual HTTP
  // outcome. The cost is a 50-subrequest synchronous fan-out (~5-15s
  // wall time), so this is NOT a hot path.
  const debugMode = c.req.query('debug') === '1' || c.req.query('debug') === 'true';
  if (debugMode) {
    const gate = requireAdmin(c);
    if ('error' in gate) return gate.error;
    const t0 = Date.now();
    const sourceUrls: { id: string; url: string; fallbackUrls?: string[] }[] = [];
    for (const s of FEED_SOURCES) {
      // Walk the registry. We don't have a public way to recover the cfg
      // from a built FeedSource, but every textFeedSource registers a
      // single upstream URL (or list of fallbacks) on its `id`. The named
      // sources (mti, openphish, etc.) have their own URL helpers below.
      const cfg = (FEED_SOURCE_DEBUG_URLS as Record<string, { url: string; fallbackUrls?: string[] }>)[s.id];
      if (cfg) sourceUrls.push({ id: s.id, ...cfg });
    }
    const diagEntries = await concurrentMap(
      sourceUrls,
      async ({ id, url, fallbackUrls }) => {
        const tried: { url: string; ok: boolean; status?: number; error?: string; bytes?: number }[] = [];
        for (const u of [url, ...(fallbackUrls ?? [])]) {
          const r = await fetchTextDiag(u);
          tried.push({ url: u, ...r });
          if (r.ok) break;
        }
        const anyOk = tried.some((r) => r.ok);
        return { id, ok: anyOk, attempts: tried };
      },
      FEED_FANOUT_CONCURRENCY
    );
    const summary = {
      duration_ms: Date.now() - t0,
      total: diagEntries.length,
      ok: diagEntries.filter((d) => d.ok).length,
      failing: diagEntries.filter((d) => !d.ok).map((d) => d.id),
      entries: diagEntries,
    };
    return c.json({
      debug: summary,
      hint: '?debug=1 bypasses cache and runs a fresh fan-out with per-source diagnostics',
    });
  }

  const cache = (caches as unknown as { default: Cache }).default;

  // Force-refresh: bypass both the response cache and the stale slices, run a
  // synchronous fan-out, and write fresh slices + response cache. Use when the
  // cached slices are stale (e.g. after deploying fallback URL changes).
  const forceRefresh = c.req.query('refresh') === '1';
  if (forceRefresh) {
    const gate = requireAdmin(c);
    if ('error' in gate) return gate.error;
    const body = await fetchLiveIocs(c.executionCtx, c.env.KV_CACHE, c.env);
    const ttl = body.degraded ? DEGRADED_TTL_SECONDS : CACHE_TTL_SECONDS;
    const resp = new Response(JSON.stringify(body), {
      headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttl}` },
    });
    c.executionCtx.waitUntil(cache.put(new Request(CACHE_KEY), resp.clone()));
    return c.json(body);
  }

  const cacheReq = new Request(CACHE_KEY);
  const cached = await cache.match(cacheReq);
  if (cached) {
    trackEvent(c.env, 'live_iocs_fetch', {
      blobs: ['hit'],
      indexes: [visitorCountry(c.req.raw)],
    });
    // Stale-while-revalidate: if the cached response is older than 80% of
    // its TTL, serve it immediately but kick off a background refresh so
    // the next request gets fresh data. This eliminates the "cold cliff"
    // where every user at TTL expiry waits for the full upstream fan-out.
    const cacheDate = cached.headers.get('date');
    const age = cacheDate ? (Date.now() - new Date(cacheDate).getTime()) / 1000 : 0;
    const maxAge = CACHE_TTL_SECONDS;
    if (age > maxAge * 0.8) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            const body = await buildLiveIocsSingleFlight(c);
            const ttl = body.degraded ? DEGRADED_TTL_SECONDS : CACHE_TTL_SECONDS;
            const fresh = new Response(JSON.stringify(body), {
              status: 200,
              headers: {
                'content-type': 'application/json',
                'cache-control': `public, max-age=${ttl}, stale-while-revalidate=${ttl * 4}`,
                'x-cache': 'REVALIDATED',
              },
            });
            await cache.put(cacheReq, fresh);
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
            /* revalidation failure is non-fatal */
          }
        })()
      );
    }
    return new Response(cached.body, {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
        'x-cache': 'HIT',
      },
    });
  }

  const body = await buildLiveIocsSingleFlight(c);
  // Adaptive TTL: when a build is degraded (an upstream FETCH failed — not a
  // source that was simply, legitimately empty), cache briefly so the next
  // request retries instead of locking a partial snapshot in for the full
  // window. The old check read `body.sources` (already filtered to count>0), so
  // it was dead — `degraded` is computed from the full source list upstream.
  const ttl = body.degraded ? DEGRADED_TTL_SECONDS : CACHE_TTL_SECONDS;
  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${ttl}, stale-while-revalidate=${ttl * 4}`,
      'x-cache': 'MISS',
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  trackEvent(c.env, 'live_iocs_fetch', {
    blobs: ['miss'],
    doubles: [body.total, body.sources.filter((s) => s.ok).length],
    indexes: [visitorCountry(c.req.raw)],
  });
  return response;
}
