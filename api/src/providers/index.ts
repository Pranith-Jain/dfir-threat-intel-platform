import type { ProviderId, ProviderAdapter, ProviderEnv } from './types';
import { PROVIDER_SUPPORT, PROVIDER_TIMEOUT_MS, PROVIDER_TIER, providerTimeoutMs } from './types';
import { virustotal } from './virustotal';
import { abuseipdb } from './abuseipdb';
import { shodan } from './shodan';
import { censys } from './censys';
import { netlas } from './netlas';
import { otx } from './otx';
import { urlscan } from './urlscan';
import { hybridanalysis } from './hybridanalysis';
import { spamhaus } from './spamhaus';
import { tor } from './tor';
import { doh } from './doh';
import { openphish } from './openphish';
import { threatfox } from './threatfox';
import { urlhaus } from './urlhaus';
import { malwarebazaar } from './malwarebazaar';
import { malshare } from './malshare';
import { hashlookup } from './hashlookup';
import { cinsarmy } from './cinsarmy';
import { bitwire } from './bitwire';
import { blocklistde } from './blocklistde';
import { binarydefense } from './binarydefense';
import { ipsum } from './ipsum';
import { phishingArmy } from './phishingArmy';
import { tweetfeed } from './tweetfeed';
import { greynoise } from './greynoise';
import { c2tracker } from './c2tracker';
import { sslbl } from './sslbl';
import { yaraify } from './yaraify';
import { phishtank } from './phishtank';
import { malwareworld } from './malwareworld';
import { emailrep } from './emailrep';
import { malpedia } from './malpedia';
import { pulsedive } from './pulsedive';
import { shodanInternetDB } from './shodan-internetdb';
import { spur } from './spur';
import { crowdsec } from './crowdsec';
import { ipinfo } from './ipinfo';
import { ipqs } from './ipqs';
import { phishstats } from './phishstats';
import { digitalside } from './digitalside';
import { criminalip } from './criminalip';
import { certpl } from './certpl';
import { x4bnet } from './x4bnet';
import { kaspersky } from './kaspersky';
import { vulncheck } from './vulncheck';
import { maltiverse } from './maltiverse';
import { secrets } from './secrets';
import { webamon } from './webamon';
import { stopforumspam } from './stopforumspam';
import { dshield } from './dshield';
import { safebrowsing } from './safebrowsing';
import { zoomeye } from './zoomeye';
import { trege } from './tre-ge';
import { intodns } from './intodns';
import { opensourcemalware } from './opensourcemalware';
import { polyswarm } from './polyswarm';
import { fullhunt } from './fullhunt';
import { opensanctions } from './opensanctions';
import { dehash } from './dehash';
import { fbiWanted } from './fbi-wanted';
import { interpol } from './interpol';
import { mozillaTls } from './mozilla-tls';
import { virushee } from './virushee';
import { dphish } from './dphish';
import { destroylist } from './destroylist';
import { stalkphish } from './stalkphish';
import { apivoid } from './apivoid';
import { metadefender } from './metadefender';
import { ctiwatch } from './ctiwatch';

export { PROVIDER_SUPPORT, PROVIDER_TIMEOUT_MS, PROVIDER_TIER, providerTimeoutMs };

export const ADAPTERS: Record<ProviderId, ProviderAdapter> = {
  virustotal,
  abuseipdb,
  shodan,
  censys,
  netlas,
  opensourcemalware,
  otx,
  urlscan,
  hybridanalysis,
  spamhaus,
  tor,
  doh,
  openphish,
  threatfox,
  urlhaus,
  malwarebazaar,
  malshare,
  hashlookup,
  cinsarmy,
  bitwire,
  blocklistde,
  binarydefense,
  ipsum,
  phishingArmy,
  tweetfeed,
  greynoise,
  c2tracker,
  sslbl,
  yaraify,
  phishtank,
  malwareworld,
  emailrep,
  malpedia,
  pulsedive,
  'shodan-internetdb': shodanInternetDB,
  spur,
  crowdsec,
  ipinfo,
  ipqs,
  phishstats,
  digitalside,
  criminalip,
  certpl,
  x4bnet,
  kaspersky,
  vulncheck,
  maltiverse,
  secrets,
  webamon,
  stopforumspam,
  dshield,
  safebrowsing,
  zoomeye,
  'tre-ge': trege,
  intodns,
  polyswarm,
  fullhunt,
  opensanctions,
  dehash,
  'fbi-wanted': fbiWanted,
  interpol,
  'mozilla-tls': mozillaTls,
  virushee,
  dphish,
  destroylist,
  stalkphish,
  apivoid,
  metadefender,
  ctiwatch,
};

/**
 * Bulk providers for the intel-bundle / report-analyzer enrichment path.
 *
 * Maltiverse is the sole bulk provider: its search API covers every
 * indicator type (ipv4, ipv6, domain, url, hash) and aggregates
 * classification + blacklist sources in a single request. This replaces
 * the previous 24-provider fan-out (threatfox, urlhaus, malwarebazaar,
 * etc.) with one API call per indicator — well within the free-plan
 * 50-subrequest budget.
 */
export const BULK_ADAPTERS: Partial<Record<ProviderId, ProviderAdapter>> = {
  maltiverse,
};

export const PROVIDER_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  shodan: 'Shodan',
  spamhaus: 'Spamhaus',
  threatfox: 'ThreatFox',
  urlhaus: 'URLhaus',
  otx: 'AlienVault OTX',
  greynoise: 'GreyNoise',
  openphish: 'OpenPhish',
  tor: 'TOR Exit Nodes',
  cinsarmy: 'CINS Army',
  bitwire: 'Bitwire',
  blocklistde: 'BlockList.de',
  binarydefense: 'BinaryDefense',
  ipsum: 'IPsum',
  malwareworld: 'MalwareWorld',
  tweetfeed: 'TweetFeed',
  crowdsec: 'CrowdSec',
  vulncheck: 'VulnCheck',
  kaspersky: 'Kaspersky',
  urlscan: 'urlscan.io',
  hybridanalysis: 'Hybrid Analysis',
  malwarebazaar: 'MalwareBazaar',
  malshare: 'MalShare',
  hashlookup: 'HashLookup',
  phishtank: 'PhishTank',
  pulsedive: 'PulseDive',
  maltiverse: 'Maltiverse',
  phishstats: 'PhishStats',
  'shodan-internetdb': 'Shodan InternetDB',
  emailrep: 'EmailRep',
  certpl: 'CERT.PL',
  x4bnet: 'X4B.net',
  c2tracker: 'C2 Tracker',
  sslbl: 'SSL Blacklist',
  yaraify: 'YARAify',
  malpedia: 'Malpedia',
  ipinfo: 'IPinfo',
  ipqs: 'IP Quality Score',
  spur: 'Spur',
  doh: 'DNS over HTTPS',
  phishingArmy: 'Phishing Army',
  secrets: 'Secrets Scan',
  censys: 'Censys',
  netlas: 'Netlas',
  opensourcemalware: 'OpenSourceMalware',
  criminalip: 'CriminalIP',
  digitalside: 'DigitalSide',
  webamon: 'Webamon Intel',
  stopforumspam: 'StopForumSpam',
  dshield: 'SANS ISC / DShield',
  safebrowsing: 'Google Safe Browsing',
  zoomeye: 'ZoomEye',
  'tre-ge': 'tre.ge',
  intodns: 'IntoDNS.ai',
  polyswarm: 'PolySwarm',
  fullhunt: 'FullHunt',
  opensanctions: 'OpenSanctions',
  dehash: 'Dehash.lt',
  'fbi-wanted': 'FBI Wanted',
  interpol: 'Interpol Red Notices',
  'mozilla-tls': 'Mozilla TLS Observatory',
  virushee: 'Virushee',
  dphish: 'dPhish',
  destroylist: 'Destroylist',
  stalkphish: 'StalkPhish',
  apivoid: 'APIVoid',
  metadefender: 'MetaDefender',
  ctiwatch: 'CTIWatch',
};

export function buildProviderEnv(env: {
  VT_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
  SHODAN_API_KEY?: string;
  CENSYS_PAT?: string;
  CENSYS_ORG_ID?: string;
  NETLAS_API_KEY?: string;
  OSM_API_KEY?: string;
  OTX_API_KEY?: string;
  URLSCAN_API_KEY?: string;
  HYBRID_ANALYSIS_API_KEY?: string;
  ABUSECH_AUTH_KEY?: string;
  MALSHARE_API_KEY?: string;
  CROWDSEC_API_KEY?: string;
  IPINFO_TOKEN?: string;
  IPQS_API_KEY?: string;
  CRIMINALIP_API_KEY?: string;
  KASPERSKY_API_KEY?: string;
  SPUR_API_KEY?: string;
  VULNCHECK_API_TOKEN?: string;
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
  ZOOMEYE_API_KEY?: string;
  INTODNS_API_KEY?: string;
  POLYSWARM_API_KEY?: string;
  FULLHUNT_API_KEY?: string;
  OPENSANCTIONS_API_KEY?: string;
  STALKPHISH_API_KEY?: string;
  APIVOID_API_KEY?: string;
  METADEFENDER_API_KEY?: string;
  CTIWATCH_API_KEY?: string;
  ASSETS?: Fetcher;
}): ProviderEnv {
  return {
    VT_API_KEY: env.VT_API_KEY ?? '',
    ABUSEIPDB_API_KEY: env.ABUSEIPDB_API_KEY ?? '',
    SHODAN_API_KEY: env.SHODAN_API_KEY ?? '',
    CENSYS_PAT: env.CENSYS_PAT ?? '',
    CENSYS_ORG_ID: env.CENSYS_ORG_ID ?? '',
    NETLAS_API_KEY: env.NETLAS_API_KEY ?? '',
    OSM_API_KEY: env.OSM_API_KEY,
    OTX_API_KEY: env.OTX_API_KEY ?? '',
    URLSCAN_API_KEY: env.URLSCAN_API_KEY ?? '',
    HYBRID_ANALYSIS_API_KEY: env.HYBRID_ANALYSIS_API_KEY ?? '',
    ABUSECH_AUTH_KEY: env.ABUSECH_AUTH_KEY,
    MALSHARE_API_KEY: env.MALSHARE_API_KEY,
    CROWDSEC_API_KEY: env.CROWDSEC_API_KEY,
    IPINFO_TOKEN: env.IPINFO_TOKEN,
    IPQS_API_KEY: env.IPQS_API_KEY,
    CRIMINALIP_API_KEY: env.CRIMINALIP_API_KEY,
    KASPERSKY_API_KEY: env.KASPERSKY_API_KEY,
    SPUR_API_KEY: env.SPUR_API_KEY,
    VULNCHECK_API_TOKEN: env.VULNCHECK_API_TOKEN,
    GOOGLE_SAFE_BROWSING_API_KEY: env.GOOGLE_SAFE_BROWSING_API_KEY,
    ZOOMEYE_API_KEY: env.ZOOMEYE_API_KEY,
    INTODNS_API_KEY: env.INTODNS_API_KEY,
    POLYSWARM_API_KEY: env.POLYSWARM_API_KEY,
    FULLHUNT_API_KEY: env.FULLHUNT_API_KEY,
    OPENSANCTIONS_API_KEY: env.OPENSANCTIONS_API_KEY,
    STALKPHISH_API_KEY: env.STALKPHISH_API_KEY,
    APIVOID_API_KEY: env.APIVOID_API_KEY,
    METADEFENDER_API_KEY: env.METADEFENDER_API_KEY,
    CTIWATCH_API_KEY: env.CTIWATCH_API_KEY,
    ASSETS: env.ASSETS,
  };
}
