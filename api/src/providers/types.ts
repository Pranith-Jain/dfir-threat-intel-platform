import type { IndicatorType } from '../lib/indicator';

export type ProviderId =
  | 'virustotal'
  | 'abuseipdb'
  | 'shodan'
  | 'censys'
  | 'netlas'
  | 'opensourcemalware'
  | 'otx'
  | 'urlscan'
  | 'hybridanalysis'
  | 'spamhaus'
  | 'tor'
  | 'doh'
  | 'openphish'
  | 'threatfox'
  | 'urlhaus'
  | 'malwarebazaar'
  | 'malshare'
  | 'hashlookup'
  | 'cinsarmy'
  | 'bitwire'
  | 'blocklistde'
  | 'binarydefense'
  | 'ipsum'
  | 'phishingArmy'
  | 'tweetfeed'
  | 'greynoise'
  | 'c2tracker'
  | 'sslbl'
  | 'yaraify'
  | 'phishtank'
  | 'malwareworld'
  | 'emailrep'
  | 'malpedia'
  | 'pulsedive'
  | 'shodan-internetdb'
  | 'spur'
  | 'crowdsec'
  | 'ipinfo'
  | 'ipqs'
  | 'phishstats'
  | 'digitalside'
  | 'criminalip'
  | 'certpl'
  | 'x4bnet'
  | 'kaspersky'
  | 'vulncheck'
  | 'maltiverse'
  | 'secrets'
  | 'webamon'
  | 'stopforumspam'
  | 'dshield'
  | 'safebrowsing'
  | 'zoomeye'
  | 'tre-ge'
  | 'intodns'
  | 'polyswarm'
  | 'fullhunt'
  | 'opensanctions'
  | 'dehash'
  | 'fbi-wanted'
  | 'interpol'
  | 'mozilla-tls'
  | 'virushee'
  | 'dphish'
  | 'destroylist'
  | 'stalkphish'
  | 'apivoid'
  | 'metadefender'
  | 'ctiwatch';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

/**
 * Categorised provider error codes. Surfaced to the UI so an operator can
 * see "this provider is rate-limited" vs "this provider's upstream is
 * throwing 5xx" vs "this provider needs a key" without parsing the raw
 * `error` string. The `error` field is still kept for backward compat
 * and human readability.
 */
export type ProviderErrorCode =
  | 'rate_limited'
  | 'upstream_5xx'
  | 'upstream_4xx'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'timeout'
  | 'network'
  | 'parse'
  | 'unsupported_indicator'
  | 'no_api_key'
  | 'unknown';

export interface ProviderResult {
  source: ProviderId;
  status: 'ok' | 'error' | 'unsupported';
  score: number; // 0-100, higher = more malicious
  verdict: Verdict;
  raw_summary: Record<string, unknown>;
  tags: string[];
  error?: string;
  /** Categorised error — see ProviderErrorCode. Absent when status === 'ok'. */
  error_code?: ProviderErrorCode;
  /** HTTP status code that triggered the error, when applicable. */
  error_status?: number;
  /** Stable, UI-friendly tags for the error. Mirrors `error_code` plus the
   *  numeric status (e.g. ['rate-limited', '429']) so the front-end can
   *  group/filter without re-parsing the `error` string. */
  error_tags?: string[];
  fetched_at: string; // ISO
  cached: boolean;
}

export interface Indicator {
  type: IndicatorType;
  value: string;
}

export interface ProviderEnv {
  VT_API_KEY: string;
  ABUSEIPDB_API_KEY: string;
  SHODAN_API_KEY: string;
  CENSYS_PAT: string;
  CENSYS_ORG_ID: string;
  NETLAS_API_KEY: string;
  /** OpenSourceMalware API token (free, generated at opensourcemalware.com → Settings → API Tokens).
   *  Optional — the provider degrades to 'unsupported' when unset. */
  OSM_API_KEY?: string;
  OTX_API_KEY: string;
  URLSCAN_API_KEY: string;
  HYBRID_ANALYSIS_API_KEY: string;
  ABUSECH_AUTH_KEY?: string;
  MALSHARE_API_KEY?: string;
  CROWDSEC_API_KEY?: string;
  IPINFO_TOKEN?: string;
  /** IP Quality Score API key (free at ipqualityscore.com). Optional — the
   *  IP enrichment provider degrades to 'unsupported' when unset. Provides
   *  proxy/VPN/TOR detection, fraud scoring, and abuse velocity. */
  IPQS_API_KEY?: string;
  CRIMINALIP_API_KEY?: string;
  KASPERSKY_API_KEY?: string;
  SPUR_API_KEY?: string;
  /** Free VulnCheck Community token. The `vulncheck` provider degrades to
   *  'unsupported' when unset. */
  VULNCHECK_API_TOKEN?: string;
  /** Google Safe Browsing v4 API key. Free tier: 10K req/day. */
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
  /** ZoomEye API key. Free tier: 10K req/month. Host/port search + web fingerprinting. */
  ZOOMEYE_API_KEY?: string;
  /** IntoDNS.ai — optional. Public diagnostic endpoints don't require a key,
   *  but the upstream may rate-limit the Worker's egress IP; a key raises
   *  the abuse-protection ceiling. Unset = anonymous tier, still functional. */
  INTODNS_API_KEY?: string;
  /** PolySwarm API key (free at polyswarm.network/signup). Optional — the provider
   *  degrades to 'unsupported' when unset. */
  POLYSWARM_API_KEY?: string;
  /** FullHunt API key (free at fullhunt.io). Optional — the provider
   *  degrades to 'unsupported' when unset. Used for attack surface discovery. */
  FULLHUNT_API_KEY?: string;
  /** OpenSanctions API key (free for public-interest work at opensanctions.org).
   *  The hosted API has required `Authorization: ApiKey …` since 2025; the
   *  provider degrades to 'unsupported' (no_api_key) when unset. */
  OPENSANCTIONS_API_KEY?: string;
  /** StalkPhish.io API token (free at stalkphish.io/accounts/register/).
   *  Free plan is 50 req/day over a 4h window; the provider degrades to
   *  'unsupported' when unset. */
  STALKPHISH_API_KEY?: string;
  /** APIVoid API key (NoVirusThanks, paid plans, 1 credit/call).
   *  Powers the `apivoid` IP + domain reputation provider; degrades to
   *  'unsupported' when unset. Successor to the URLVoid/IPVoid web
   *  checkers, neither of which exposes its own API. */
  APIVOID_API_KEY?: string;
  /** MetaDefender Cloud API key (free community key via OPSWAT account,
   *  daily limits). Powers the `metadefender` hash reputation provider;
   *  degrades to 'unsupported' when unset. */
  METADEFENDER_API_KEY?: string;
  /** CTIWatch API key (free at ctiwatch.com/settings/api-keys; format
   *  `ctw_` + 64 hex). Optional — the `ctiwatch` IOC provider mints an
   *  anonymous session cookie when unset (see api/src/lib/ctiwatch.ts), so
   *  lookups work without it; a key lifts the anonymous request/row quotas. */
  CTIWATCH_API_KEY?: string;
  /** Static ASSETS binding (Worker) — used by the `dphish` provider to read
   *  the replicated dPhish indicator manifest (public/data/threat-intel/dphish/)
   *  with zero network egress. Optional so provider unit tests compile without
   *  the binding; the adapter degrades to 'unsupported' when absent. */
  ASSETS?: Fetcher;
}

export type ProviderAdapter = (indicator: Indicator, env: ProviderEnv, signal: AbortSignal) => Promise<ProviderResult>;

// Per-provider request timeout. Bumped from 5s to 8s after live observation
// of OTX timeouts on free-tier lookups. Providers run in parallel, so this
// only delays the response if EVERY provider is slow.
export const PROVIDER_TIMEOUT_MS = 8000;

/**
 * Per-provider timeout overrides for upstreams that are simply slower than
 * the shared budget. Webamon's search index answers in 10–15s on cold
 * queries, so at 8s every enrichment call aborted before the result
 * arrived and the provider reported `error` for every domain. Providers run
 * in parallel, so a single override does not slow anything else down.
 */
export const PROVIDER_TIMEOUT_OVERRIDES: Partial<Record<ProviderId, number>> = {
  webamon: 20_000,
};

/** Timeout for one provider, honoring {@link PROVIDER_TIMEOUT_OVERRIDES}. */
export function providerTimeoutMs(id: ProviderId): number {
  return PROVIDER_TIMEOUT_OVERRIDES[id] ?? PROVIDER_TIMEOUT_MS;
}

/** Which indicator types each provider supports. Used by the route to skip unsupported. */
export const PROVIDER_SUPPORT: Record<ProviderId, IndicatorType[]> = {
  virustotal: ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
  abuseipdb: ['ipv4', 'ipv6'],
  shodan: ['ipv4', 'ipv6', 'domain'],
  censys: ['ipv4', 'ipv6'],
  netlas: ['ipv4', 'ipv6'],
  opensourcemalware: ['ipv4', 'ipv6', 'domain', 'url'],
  otx: ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
  urlscan: ['url', 'domain'],
  hybridanalysis: ['hash'],
  spamhaus: ['ipv4'],
  tor: ['ipv4'],
  doh: ['domain'],
  openphish: ['url', 'domain'],
  threatfox: ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
  urlhaus: ['url', 'domain', 'ipv4'],
  malwarebazaar: ['hash'],
  malshare: ['hash'],
  hashlookup: ['hash'],
  cinsarmy: ['ipv4'],
  bitwire: ['ipv4'],
  blocklistde: ['ipv4'],
  binarydefense: ['ipv4'],
  ipsum: ['ipv4'],
  phishingArmy: ['domain', 'url'],
  tweetfeed: ['ipv4', 'domain', 'url', 'hash'],
  greynoise: ['ipv4', 'ipv6'],
  c2tracker: ['ipv4'],
  sslbl: ['ipv4'],
  yaraify: ['hash'],
  phishtank: ['url', 'domain'],
  malwareworld: ['ipv4', 'domain'],
  emailrep: ['email'],
  malpedia: ['hash'],
  pulsedive: ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
  'shodan-internetdb': ['ipv4', 'ipv6'],
  spur: ['ipv4', 'ipv6'],
  crowdsec: ['ipv4', 'ipv6'],
  ipinfo: ['ipv4', 'ipv6'],
  ipqs: ['ipv4', 'ipv6'],
  phishstats: ['url', 'domain'],
  digitalside: ['url', 'domain', 'hash', 'ipv4'],
  criminalip: ['ipv4', 'ipv6'],
  certpl: ['domain'],
  x4bnet: ['ipv4', 'ipv6'],
  kaspersky: ['ipv4', 'domain', 'url', 'hash'],
  vulncheck: ['ipv4'],
  maltiverse: ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
  secrets: ['url'],
  webamon: ['domain'],
  stopforumspam: ['ipv4', 'email'],
  dshield: ['ipv4'],
  safebrowsing: ['url', 'domain'],
  zoomeye: ['ipv4', 'ipv6', 'domain'],
  'tre-ge': ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
  intodns: ['domain'],
  polyswarm: ['hash'],
  fullhunt: ['ipv4', 'ipv6', 'domain'],
  opensanctions: ['ipv4', 'domain', 'email'],
  dehash: ['hash'],
  'fbi-wanted': ['ipv4', 'domain', 'email'],
  interpol: ['ipv4', 'domain', 'email'],
  'mozilla-tls': ['domain', 'ipv4', 'ipv6'],
  virushee: ['hash'],
  dphish: ['ipv4', 'ipv6', 'domain', 'url'],
  destroylist: ['domain', 'url'],
  stalkphish: ['url', 'domain', 'ipv4'],
  apivoid: ['ipv4', 'ipv6', 'domain', 'url'],
  metadefender: ['hash'],
  ctiwatch: ['ipv4', 'ipv6', 'domain', 'url', 'hash', 'email'],
};

/**
 * Provider tiers — used to skip low-value lookups and reduce rate-limit
 * pressure. Tier-1 providers always run. Tier-2 providers only run when
 * tier-1 returns no actionable signals (all clean / unknown) — reduces
 * subrequests from ~27 to ~12 for typical IOC checks.
 */
export type ProviderTier = 1 | 2;

export const PROVIDER_TIER: Record<ProviderId, ProviderTier> = {
  virustotal: 1,
  abuseipdb: 1,
  shodan: 1,
  greynoise: 1,
  crowdsec: 1,
  threatfox: 1,
  urlhaus: 1,
  openphish: 1,
  hybridanalysis: 1,
  malwarebazaar: 1,
  spamhaus: 1,
  tor: 1,
  phishtank: 1,
  safebrowsing: 1,
  kaspersky: 1,
  'shodan-internetdb': 1,
  pulsedive: 1,
  maltiverse: 1,
  censys: 1,
  netlas: 1,
  urlscan: 1,
  otx: 2,
  cinsarmy: 2,
  bitwire: 2,
  blocklistde: 2,
  binarydefense: 2,
  ipsum: 2,
  tweetfeed: 2,
  c2tracker: 2,
  sslbl: 2,
  malwareworld: 2,
  phishingArmy: 2,
  doh: 2,
  hashlookup: 2,
  malshare: 2,
  x4bnet: 2,
  certpl: 2,
  digitalside: 2,
  stopforumspam: 2,
  dshield: 2,
  intodns: 2,
  opensourcemalware: 2,
  secrets: 2,
  webamon: 2,
  zoomeye: 2,
  'tre-ge': 2,
  spur: 2,
  phishstats: 2,
  criminalip: 2,
  vulncheck: 2,
  emailrep: 2,
  malpedia: 2,
  ipinfo: 1,
  ipqs: 1,
  yaraify: 1,
  polyswarm: 1,
  fullhunt: 2,
  opensanctions: 2,
  dehash: 2,
  'fbi-wanted': 2,
  interpol: 2,
  'mozilla-tls': 2,
  virushee: 2,
  dphish: 1,
  destroylist: 1,
  // Tier 2: keyed + quota-tight (Free 50/day). Runs only when tier-1
  // returns no actionable signal, and repeat checks are absorbed by the
  // route's Cache API fronting.
  stalkphish: 2,
  // Tier 2: keyed + credit-metered (APIVoid 1 credit/call, MetaDefender
  // daily community limits). Same gating as stalkphish.
  apivoid: 2,
  metadefender: 2,
  // Tier 1: the IOC database behind the CVE digest's upstream (~96
  // aggregated collection sources, confidence-graded). One session-cached
  // lookup per check, result-cached by the shared batched KV, so it always
  // runs rather than waiting for tier-2 corroboration.
  ctiwatch: 1,
};
