/**
 * Passive pivot registry — ported from MANTIS (fareedfauzi/MANTIS,
 * backend/ai_pivot_registry.py, MIT licensed).
 *
 * Maps deterministic, passive (read-only) pivot archetypes for each
 * indicator input type: hash, domain, ip, url, infra (ASN/CIDR/cert),
 * keyword (CVE / actor / malware family), plus `auto` pivots that work
 * for any indicator.
 *
 * Enforced upstream properties preserved exactly:
 *  - 100% passive, read-only lookups (no fabricated providers, no active contact)
 *  - every pivot maps to proven provider adapters
 *
 * `preferredSources` names follow MANTIS provider IDs; the DFIR toolkit's
 * IOC Investigate provider keys map onto most of these (virustotal,
 * abuseipdb, shodan, otx, urlscan, malwaresbazaar(→malwarebazaar), …).
 */

export type PivotInputType = 'hash' | 'domain' | 'ip' | 'url' | 'infra' | 'keyword' | 'auto';

export interface PivotArchetype {
  pivotType: string;
  inputType: PivotInputType;
  description: string;
  preferredSources: string[];
  isPassive: boolean;
}

export const PIVOT_REGISTRY: Record<string, PivotArchetype> = {
  // ── Hash pivots ─────────────────────────────────────────────────
  hash_to_similar_samples: {
    pivotType: 'hash_to_similar_samples',
    inputType: 'hash',
    description: 'Query passive repositories for samples sharing code, imphash, visual features, or ssdeep similarity',
    preferredSources: ['malwarebazaar', 'virustotal', 'triage', 'hybrid-analysis', 'malshare'],
    isPassive: true,
  },
  hash_to_network_iocs: {
    pivotType: 'hash_to_network_iocs',
    inputType: 'hash',
    description: 'Query threat intelligence databases and sandbox detonations for associated C2s and contacted hosts',
    preferredSources: [
      'virustotal',
      'threatfox',
      'triage',
      'hybrid-analysis',
      'tip',
      'alienvault',
      'urlhaus',
      'threatminer',
    ],
    isPassive: true,
  },
  hash_to_yara_matches: {
    pivotType: 'hash_to_yara_matches',
    inputType: 'hash',
    description: 'Inspect community and provider YARA rule matches for signature corroboration',
    preferredSources: ['yaraify', 'malwarebazaar', 'virustotal', 'yara_forge', 'rwlive'],
    isPassive: true,
  },
  hash_to_family_context: {
    pivotType: 'hash_to_family_context',
    inputType: 'hash',
    description: 'Retrieve malware family labels, signatures, and tags across threat databases',
    preferredSources: [
      'malwarebazaar',
      'threatfox',
      'virustotal',
      'alienvault',
      'triage',
      'hybrid-analysis',
      'tip',
      'malware_news',
    ],
    isPassive: true,
  },
  hash_to_behavioral_signatures: {
    pivotType: 'hash_to_behavioral_signatures',
    inputType: 'hash',
    description:
      'Extract dynamic detonation behavioral signatures (process hollowing, evasion, persistence, network beacons)',
    preferredSources: ['triage', 'hybrid-analysis', 'virustotal'],
    isPassive: true,
  },
  hash_to_execution_parents: {
    pivotType: 'hash_to_execution_parents',
    inputType: 'hash',
    description: 'Discover dropper documents, archive wrappers, and parent binaries that execute or deploy this sample',
    preferredSources: ['virustotal', 'triage', 'alienvault', 'hybrid-analysis'],
    isPassive: true,
  },

  // ── Domain pivots ───────────────────────────────────────────────
  domain_to_passive_dns: {
    pivotType: 'domain_to_passive_dns',
    inputType: 'domain',
    description: 'Resolve historical IP resolutions and DNS records through passive telemetry',
    preferredSources: ['validin', 'virustotal', 'silentpush', 'dnsdumpster', 'driftnet', 'alienvault'],
    isPassive: true,
  },
  domain_to_ip: {
    pivotType: 'domain_to_ip',
    inputType: 'domain',
    description: 'Retrieve current and recent IP addresses hosting the domain',
    preferredSources: ['virustotal', 'dnsdumpster', 'driftnet', 'shodan', 'censys', 'validin', 'silentpush', 'fofa'],
    isPassive: true,
  },
  domain_to_certificate: {
    pivotType: 'domain_to_certificate',
    inputType: 'domain',
    description: 'Query certificate transparency logs and TLS history for the domain',
    preferredSources: ['crtsh', 'virustotal', 'censys', 'driftnet', 'validin', 'shodan', 'silentpush'],
    isPassive: true,
  },
  domain_to_related_domains: {
    pivotType: 'domain_to_related_domains',
    inputType: 'domain',
    description: 'Find sibling domains, subdomains, and co-hosted infrastructure',
    preferredSources: ['dnsdumpster', 'virustotal', 'alienvault', 'validin', 'silentpush', 'driftnet', 'leakix'],
    isPassive: true,
  },
  domain_to_web_reputation: {
    pivotType: 'domain_to_web_reputation',
    inputType: 'domain',
    description:
      'Profile domain web reputation, historical crawl snapshots, phishing telemetry, and blocklist presence',
    preferredSources: ['openphish', 'phishstats', 'reputation_feeds', 'urlscan', 'archive', 'virustotal'],
    isPassive: true,
  },
  domain_to_threat_pulses: {
    pivotType: 'domain_to_threat_pulses',
    inputType: 'domain',
    description:
      'Extract threat intelligence community pulses, incident reports, and threat actor associations referencing this domain',
    preferredSources: ['alienvault', 'orkl', 'malware_news', 'cti_articles', 'tweetfeed'],
    isPassive: true,
  },

  // ── IP pivots ──────────────────────────────────────────────────
  ip_to_domains: {
    pivotType: 'ip_to_domains',
    inputType: 'ip',
    description: 'Enumerate domains historically or currently resolving to this IP address',
    preferredSources: [
      'virustotal',
      'shodan',
      'censys',
      'validin',
      'silentpush',
      'driftnet',
      'alienvault',
      'threatbook',
      'dnsdumpster',
    ],
    isPassive: true,
  },
  ip_to_asn: {
    pivotType: 'ip_to_asn',
    inputType: 'ip',
    description: 'Identify autonomous system (ASN), hosting provider, and BGP routing context',
    preferredSources: [
      'ripe',
      'driftnet',
      'abuseipdb',
      'silentpush',
      'threatbook',
      'greynoise',
      'shodan',
      'censys',
      'virustotal',
    ],
    isPassive: true,
  },
  ip_to_certificates: {
    pivotType: 'ip_to_certificates',
    inputType: 'ip',
    description: 'Enumerate TLS/SSL certificates observed on this IP address across scan repositories',
    preferredSources: ['censys', 'shodan', 'driftnet', 'fofa', 'validin', 'virustotal', 'threatminer'],
    isPassive: true,
  },
  ip_to_services_and_ports: {
    pivotType: 'ip_to_services_and_ports',
    inputType: 'ip',
    description: 'Discover exposed ports, listening network services, banners, and operating system fingerprints',
    preferredSources: ['shodan', 'censys', 'threatbook', 'driftnet', 'fofa', 'leakix'],
    isPassive: true,
  },
  ip_to_abuse_and_noise: {
    pivotType: 'ip_to_abuse_and_noise',
    inputType: 'ip',
    description:
      'Query IP abuse reporting confidence, honeypot attack records, and opportunistic mass-scanning noise classification',
    preferredSources: ['abuseipdb', 'greynoise', 'sans'],
    isPassive: true,
  },
  ip_to_threat_pulses: {
    pivotType: 'ip_to_threat_pulses',
    inputType: 'ip',
    description:
      'Extract threat intelligence community pulses, adversary links, and downloaded payload records referencing this IP',
    preferredSources: ['tip', 'alienvault', 'threatbook', 'orkl', 'malware_news', 'cti_articles', 'tweetfeed'],
    isPassive: true,
  },

  // ── URL pivots ─────────────────────────────────────────────────
  url_to_telemetry: {
    pivotType: 'url_to_telemetry',
    inputType: 'url',
    description: 'Query URLhaus, URLscan, and reputation feeds for payload distributions and sandbox captures',
    preferredSources: [
      'urlhaus',
      'urlscan',
      'virustotal',
      'threatfox',
      'openphish',
      'phishstats',
      'alienvault',
      'triage',
      'hybrid-analysis',
      'archive',
    ],
    isPassive: true,
  },
  url_to_payload_hash: {
    pivotType: 'url_to_payload_hash',
    inputType: 'url',
    description: 'Identify malware binary hashes and dropped payloads delivered from this URL endpoint',
    preferredSources: ['urlhaus', 'urlscan', 'virustotal', 'triage', 'hybrid-analysis'],
    isPassive: true,
  },
  url_to_redirect_chain: {
    pivotType: 'url_to_redirect_chain',
    inputType: 'url',
    description:
      'Trace effective URL landing page, redirection hops, server responses, and final payload delivery location',
    preferredSources: ['urlscan', 'virustotal', 'urlhaus'],
    isPassive: true,
  },

  // ── Infrastructure (ASN / CIDR / cert) pivots ───────────────────
  asn_to_infrastructure: {
    pivotType: 'asn_to_infrastructure',
    inputType: 'infra',
    description: 'Enumerate announced BGP routing prefixes, subnets, and host assets under an Autonomous System',
    preferredSources: ['ripe', 'driftnet', 'shodan', 'censys', 'fofa', 'silentpush', 'urlscan'],
    isPassive: true,
  },
  cidr_to_exposed_hosts: {
    pivotType: 'cidr_to_exposed_hosts',
    inputType: 'infra',
    description: 'Scan network subnet block for listening services, open ports, and vulnerable edge banners',
    preferredSources: ['shodan', 'censys', 'driftnet', 'abuseipdb', 'fofa', 'dnsdumpster', 'validin'],
    isPassive: true,
  },
  certificate_to_infrastructure: {
    pivotType: 'certificate_to_infrastructure',
    inputType: 'infra',
    description: 'Enumerate hostnames, SANs, and infrastructure sharing the same TLS certificate fingerprint or serial',
    preferredSources: ['crtsh', 'censys', 'driftnet', 'shodan', 'validin', 'fofa'],
    isPassive: true,
  },

  // ── Threat actor / ransomware / malware-family pivots ───────────
  threat_actor_to_campaign: {
    pivotType: 'threat_actor_to_campaign',
    inputType: 'keyword',
    description: 'Retrieve adversary profile, known aliases, historical campaigns, and shared TTPs',
    preferredSources: [
      'alienvault',
      'misp_galaxy',
      'threat_actor_knowledge',
      'orkl',
      'cb',
      'malware_news',
      'github',
      'threatactorusernames',
    ],
    isPassive: true,
  },
  threat_actor_to_infrastructure: {
    pivotType: 'threat_actor_to_infrastructure',
    inputType: 'keyword',
    description: 'Identify known C2 IPs, domains, and registration infrastructure attributed to a threat actor',
    preferredSources: ['alienvault', 'pulsedive', 'threatfox', 'silentpush', 'orkl'],
    isPassive: true,
  },
  ransomware_group_to_victims: {
    pivotType: 'ransomware_group_to_victims',
    inputType: 'keyword',
    description: 'Enumerate extortion victim disclosures, affected sectors, countries, and ransom leak entries',
    preferredSources: ['rwlive', 'ransomlook', 'malware_news'],
    isPassive: true,
  },

  // ── Vulnerability (CVE) pivots ─────────────────────────────────
  cve_to_exploits_and_pocs: {
    pivotType: 'cve_to_exploits_and_pocs',
    inputType: 'keyword',
    description:
      'Identify public Proof-of-Concept (PoC) exploit scripts, GitHub repositories, and weaponization context',
    preferredSources: ['github', 'github_repos', 'cb', 'orkl', 'malware_news', 'cti_articles'],
    isPassive: true,
  },
  cve_to_wild_exploitation: {
    pivotType: 'cve_to_wild_exploitation',
    inputType: 'keyword',
    description: 'Correlate in-the-wild exploitation reports, active campaigns, and associated threat groups',
    preferredSources: ['orkl', 'alienvault', 'malware_news', 'rss_intel', 'tweetfeed'],
    isPassive: true,
  },

  // ── Malware family & social pivots ─────────────────────────────
  malware_family_to_samples: {
    pivotType: 'malware_family_to_samples',
    inputType: 'keyword',
    description: 'Retrieve indexed binary hashes, payloads, and delivery signatures for a malware family',
    preferredSources: [
      'malwarebazaar',
      'threatfox',
      'hybrid-analysis',
      'triage',
      'pulsedive',
      'malware_tools_knowledge',
    ],
    isPassive: true,
  },
  ioc_to_social_mentions: {
    pivotType: 'ioc_to_social_mentions',
    inputType: 'auto',
    description: 'Monitor real-time infosec community discussions, zero-day chatter, and shared IOC feeds',
    preferredSources: ['tweetfeed', 'twitter', 'x_monitor', 'rss_intel', 'malware_news'],
    isPassive: true,
  },
  ioc_to_threatfox: {
    pivotType: 'ioc_to_threatfox',
    inputType: 'auto',
    description: 'Check ThreatFox for correlated malware campaign IOCs and threat associations',
    preferredSources: ['threatfox', 'virustotal', 'alienvault'],
    isPassive: true,
  },
  ioc_to_malwarebazaar: {
    pivotType: 'ioc_to_malwarebazaar',
    inputType: 'auto',
    description: 'Query MalwareBazaar database for sample presence and related malware files',
    preferredSources: ['malwarebazaar', 'virustotal', 'triage'],
    isPassive: true,
  },
};

/** All valid passive pivot types. */
export function getSupportedPivotTypes(): string[] {
  return Object.keys(PIVOT_REGISTRY);
}

/** Registration metadata for one pivot type. */
export function getPivotDefinition(pivotType: string): PivotArchetype | undefined {
  return PIVOT_REGISTRY[String(pivotType).trim().toLowerCase()];
}

export function isValidPivotType(pivotType: string): boolean {
  return String(pivotType).trim().toLowerCase() in PIVOT_REGISTRY;
}

/** All pivot archetypes matching the given indicator input type (exact + `auto`). */
export function getPivotsForType(inputType: PivotInputType | string): PivotArchetype[] {
  const it = String(inputType || '')
    .trim()
    .toLowerCase() as PivotInputType;
  return Object.values(PIVOT_REGISTRY).filter((d) => d.inputType === it || d.inputType === 'auto');
}

/** Ordered preferred provider list for a pivot, intersected with available sources when given. */
export function resolveSourcesForPivot(pivotType: string, availableSources?: string[]): string[] {
  const defn = getPivotDefinition(pivotType);
  if (!defn) return [];
  if (!availableSources || availableSources.length === 0) return [...defn.preferredSources];
  const avail = new Set(availableSources.map((s) => s.trim().toLowerCase()));
  return defn.preferredSources.filter((s) => avail.has(s.toLowerCase()));
}

/**
 * Classify an arbitrary indicator string into the registry's input types.
 * Mirrors the IOC Investigate auto-detect lanes so callers can branch on it.
 */
export function classifyIndicator(value: string): PivotInputType | null {
  const t = value.trim();
  if (!t) return null;
  if (httpsUrlRe.test(t)) return 'url';
  if (certFpRe.test(t) || jarmRe.test(t)) return 'infra';
  if (shaRe.test(t) || sha1Re.test(t) || md5Re.test(t)) return 'hash';
  if (cidrRe.test(t) || asnRe.test(t)) return 'infra';
  if (ipv4Re.test(t)) return 'ip';
  if (cveRe.test(t)) return 'keyword';
  if (domainRe.test(t)) return 'domain';
  return null; // free-text keyword — callers decide (actor/family/CVE)
}

const shaRe = /^[a-f\d]{64}$/i;
const sha1Re = /^[a-f\d]{40}$/i;
const md5Re = /^[a-f\d]{32}$/i;
const certFpRe = /^[a-f\d]{64,128}$/i;
const jarmRe = /^[a-f\d]{62}$/i;
const ipv4Re = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const cidrRe = /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const asnRe = /^AS\d{1,10}$/i;
const cveRe = /^CVE-\d{4}-\d{4,7}$/i;
const domainRe = /^[a-zA-Z\d](?:[a-zA-Z\d-]*[a-zA-Z\d])?(?:\.[a-zA-Z\d](?:[a-zA-Z\d-]*[a-zA-Z\d])?)*\.[a-zA-Z]{2,}$/;
const httpsUrlRe = /^https?:\/\//i;
