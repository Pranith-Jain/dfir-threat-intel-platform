import type { Context } from 'hono';
import type { Env } from '../env';
import { bandConfidence, type BandedScore } from './score-band';

/**
 * NATO Admiralty Code — source reliability (A–F) and information credibility (1–6).
 * Standard in defence/national-security CTI; increasingly used in commercial TIPs.
 */
export type SourceReliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
export type InfoCredibility = 1 | 2 | 3 | 4 | 5 | 6;

export interface AdmiraltyGrade {
  reliability: SourceReliability;
  credibility: InfoCredibility;
  label: string; // human-readable summary e.g. "B-2: Usually reliable / Probably True"
}

export type Confidence = 'very_high' | 'high' | 'moderate' | 'low' | 'very_low' | 'unassessed';

export interface ConfidenceScore {
  level: Confidence;
  score: number; // 0–100
  /** Visual band for `score`, trust-polarity. Never render this red. */
  band: BandedScore;
  admiralty?: AdmiraltyGrade;
  sources_contributing: number;
  contradictory_sources: number;
  reasoning: string; // why this level was assigned
}

/**
 * Per-source reliability grading. Every collector/provider in the platform
 * gets a fixed Admiralty reliability ceiling based on track record, access,
 * and whether the source is primary/secondary/tertiary.
 */
export interface SourceReliabilityEntry {
  id: string;
  name: string;
  reliability: SourceReliability;
  category: 'primary' | 'secondary' | 'tertiary' | 'ai_generated' | 'inferred';
  description: string;
  known_bias?: string;
}

export const SOURCE_RELIABILITY_REGISTRY: Record<string, SourceReliabilityEntry> = {
  // ── Primary sources ─────────────────────────────────────────────────────
  ransomlook: {
    id: 'ransomlook',
    name: 'Ransomlook',
    reliability: 'B',
    category: 'primary',
    description: 'Direct leak-site scraping — posts from ransomware group onion sites',
    known_bias: 'Only claims posted to leak sites; misses private/extortion-only victims',
  },
  ransomwarelive: {
    id: 'ransomwarelive',
    name: 'ransomware.live PRO',
    reliability: 'B',
    category: 'primary',
    description: 'Authenticated API — ransom notes, negotiation logs, victim claims',
  },
  'cisa-kev': {
    id: 'cisa-kev',
    name: 'CISA KEV',
    reliability: 'A',
    category: 'primary',
    description: 'Known Exploited Vulnerabilities catalog — authoritative US govt source',
    known_bias: 'Only includes confirmed in-the-wild exploitation',
  },
  nvd: {
    id: 'nvd',
    name: 'NVD',
    reliability: 'A',
    category: 'primary',
    description: 'National Vulnerability Database — official CVE repository',
  },
  malpedia: {
    id: 'malpedia',
    name: 'Malpedia',
    reliability: 'B',
    category: 'primary',
    description: 'Curated malware family reference by Fraunhofer FKIE',
  },
  'abusech-urlhaus': {
    id: 'abusech-urlhaus',
    name: 'URLhaus',
    reliability: 'A',
    category: 'primary',
    description: 'abuse.ch URLhaus — confirmed malicious URLs',
    known_bias: 'URLs only, not host-level attribution',
  },
  'abusech-threatfox': {
    id: 'abusech-threatfox',
    name: 'ThreatFox',
    reliability: 'A',
    category: 'primary',
    description: 'abuse.ch ThreatFox — confirmed malicious IOCs with context',
  },
  'abusech-malwarebazaar': {
    id: 'abusech-malwarebazaar',
    name: 'MalwareBazaar',
    reliability: 'A',
    category: 'primary',
    description: 'abuse.ch MalwareBazaar — confirmed malware samples with hashes',
  },
  'phish-tank': {
    id: 'phish-tank',
    name: 'PhishTank',
    reliability: 'B',
    category: 'primary',
    description: 'Crowdsourced phishing verification — community-vetted URLs',
  },
  openphish: {
    id: 'openphish',
    name: 'OpenPhish',
    reliability: 'B',
    category: 'primary',
    description: 'Curated commercial phishing feed',
  },
  dphish: {
    id: 'dphish',
    name: 'dPhish Feed',
    reliability: 'B',
    category: 'primary',
    description:
      'OpenCTI-backed TAXII 2.1 phishing indicator collection — malicious domains, phishing URLs, sender IPs, phone numbers, attachment rules',
    known_bias: 'Public collection; indicator scope limited to what dphish.com publishes',
  },
  destroylist: {
    id: 'destroylist',
    name: 'Destroylist',
    reliability: 'B',
    category: 'secondary',
    description:
      'Real-time phishing & scam domain blacklist (phishdestroy/destroylist, MIT) — curated primary feed plus a 13+ source community aggregate with DNS/HTTP content verification',
    known_bias:
      'Community aggregate mixes feed quality; primary feed is curator-verified. Cloaking can hide live phishing from content checks.',
  },
  stalkphish: {
    id: 'stalkphish',
    name: 'StalkPhish',
    reliability: 'B',
    category: 'primary',
    description:
      'Commercial phishing URL intel (stalkphish.io) — kit-family attribution, targeted-brand, Telegram exfiltration tracking; recall follows the API key plan (Free: 50/day, 4h window)',
    known_bias:
      'Keyed plan window limits recall — a miss is unknown, not clean. OSINT-fed; short-lived campaigns may age out of range.',
  },
  apivoid: {
    id: 'apivoid',
    name: 'APIVoid',
    reliability: 'B',
    category: 'primary',
    description:
      'Commercial IP + domain reputation (NoVirusThanks APIVoid) — 70-80 blocklist engines, risk score, proxy/VPN/Tor/hosting flags; successor to the URLVoid/IPVoid web checkers',
    known_bias:
      'Keyed credit-metered plan limits recall — a miss is unknown, not clean. Blocklist aggregation can lag fresh infrastructure.',
  },
  metadefender: {
    id: 'metadefender',
    name: 'MetaDefender',
    reliability: 'B',
    category: 'primary',
    description:
      'Multi-engine file reputation (OPSWAT MetaDefender Cloud) — AV verdict aggregation for hashes; free community key with daily limits',
    known_bias:
      'Keyed daily limits bound recall — a miss is unknown, not clean. Zero-day files may be unscanned (unknown, not benign).',
  },
  'hudson-rock': {
    id: 'hudson-rock',
    name: 'Hudson Rock',
    reliability: 'C',
    category: 'secondary',
    description: 'Infostealer victim data — caveat emptor on completeness',
    known_bias: 'Only infostealer-compromised machines; not representative of all breaches',
  },
  'leak-check': {
    id: 'leak-check',
    name: 'LeakCheck',
    reliability: 'C',
    category: 'secondary',
    description: 'Breach database aggregator — aggregated from multiple dumps',
  },
  xposedornot: {
    id: 'xposedornot',
    name: 'XposedOrNot',
    reliability: 'C',
    category: 'secondary',
    description: 'Breach aggregation service — community-sourced corpus',
  },
  breachvip: {
    id: 'breachvip',
    name: 'BreachVIP',
    reliability: 'C',
    category: 'secondary',
    description: 'Free breach search engine — 10B+ records across 1000+ datasets',
    known_bias: 'Aggregated from public dumps; coverage skews toward widely-circulated breaches',
  },

  // ── Secondary sources ───────────────────────────────────────────────────
  'telegram-feed': {
    id: 'telegram-feed',
    name: 'Telegram Channel Feed',
    reliability: 'D',
    category: 'secondary',
    description: 'Public cybersec Telegram channels — IOC drops, leak announcements',
    known_bias: 'Self-selected channels; quality varies by channel',
  },
  'telegram-leak-monitor': {
    id: 'telegram-leak-monitor',
    name: 'Telegram Leak Monitor',
    reliability: 'D',
    category: 'secondary',
    description: 'Auto-scanned Telegram channels for credential/paste/file leaks',
    known_bias: 'Scanner heuristics produce false positives',
  },
  reddit: {
    id: 'reddit',
    name: 'Reddit Cybersec',
    reliability: 'D',
    category: 'secondary',
    description: '16 cybersec subreddits — discussion and link sharing',
    known_bias: 'Not verified; discussion may include unsubstantiated claims',
  },
  'x-twitter': {
    id: 'x-twitter',
    name: 'X/Twitter Cybersec',
    reliability: 'D',
    category: 'secondary',
    description: 'Cybersec researcher tweets — IOC drops, analysis threads',
  },
  bluesky: {
    id: 'bluesky',
    name: 'Bluesky Cybersec',
    reliability: 'D',
    category: 'secondary',
    description: 'Cybersec researcher posts — similar to X but smaller community',
  },
  ipsum: {
    id: 'ipsum',
    name: 'IPsum',
    reliability: 'C',
    category: 'secondary',
    description: 'Consensus-scored malicious IPs from 3+ source lists',
    known_bias: 'Consensus method reduces FPs but misses targeted/threshold attacks',
  },
  cinsarmy: {
    id: 'cinsarmy',
    name: 'CINS Army',
    reliability: 'C',
    category: 'secondary',
    description: 'Active malicious IP list — aggressive but high signal',
  },
  bitwire: {
    id: 'bitwire',
    name: 'Bitwire IP Blocklist',
    reliability: 'C',
    category: 'secondary',
    description: 'IP blocklist with moderate coverage',
  },
  mythreatintel: {
    id: 'mythreatintel',
    name: 'MyThreatIntel',
    reliability: 'C',
    category: 'secondary',
    description: 'Commercial CTI platform — IOCs, malware, CVEs, ransomware victims',
  },
  certspotter: {
    id: 'certspotter',
    name: 'Cert Spotter / crt.sh',
    reliability: 'B',
    category: 'primary',
    description: 'Certificate Transparency log search — authoritative for issued certs',
  },
  abuseipdb: {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    reliability: 'C',
    category: 'secondary',
    description: 'Crowdsourced IP reputation — community reports',
    known_bias: 'Community-vetted; can be gamed',
  },
  vulncheck: {
    id: 'vulncheck',
    name: 'VulnCheck',
    reliability: 'A',
    category: 'primary',
    description: 'Commercial exploit & IP intelligence — C2/initial-access attribution, exploitation-in-the-wild',
  },
  dbugs: {
    id: 'dbugs',
    name: 'dbu.gs',
    reliability: 'B',
    category: 'secondary',
    description: 'Public vulnerability database — vendor/product/CWE mapping plus exploit- and fix-availability flags',
    // Rows are largely mirrored from NVD/Mitre (its `cvss` block carries both,
    // often identically), so it adds normalization and exploit/fix flags
    // rather than new primary observations. Graded B, not A, for that reason.
    known_bias: 'Derived from NVD/Mitre data, so not independent of them; exploit-availability flags are self-reported',
  },
  exploitgrid: {
    id: 'exploitgrid',
    name: 'ExploitGrid',
    reliability: 'C',
    category: 'secondary',
    description: 'Public exploit repository index — proof-of-concept availability per CVE',
    // Existence of a PoC is a hard fact, but these are unreviewed submissions
    // (every live row carried status PENDING) and many are non-functional or
    // proof-of-concept-only. C, not B: treat as a lead, not a confirmed weapon.
    known_bias: 'Community submissions, no validation step; `severity` classifies the exploit, not a CVSS score',
  },
  vulntracker: {
    id: 'vulntracker',
    name: 'VulnTracker',
    reliability: 'C',
    category: 'secondary',
    description: 'Daily CVE digest counters, top criticals, and hand-written exploitation analysis',
    // The blog analysis is genuinely useful and human-written, but the digest
    // counters and top_cves are a subscription product's gated preview: only
    // 7 criticals/day are visible and vendor/product breakdowns are withheld,
    // so coverage is partial by design. C reflects that partial-by-design view.
    known_bias: 'Digest API is gated (top 7 criticals of the full day); most of the JSON API requires authentication',
  },
  ctiwatch: {
    id: 'ctiwatch',
    name: 'CTIWatch',
    reliability: 'B',
    category: 'secondary',
    description:
      'Public vulnerability database with a first-class published_after filter — the anchor for the 24h CVE digest, carrying CVSS, severity, exploit_status, KEV flag, EPSS and priority score',
    // Catalogue is genuinely complete (382k CVEs) and the docs are unusually
    // honest about their own footguns, but it is still a secondary aggregation
    // of NVD-sourced data rather than a primary disclosure venue. B, not A.
    known_bias: 'Anonymous scope caps at offset=1000; unknown query params are silently ignored upstream',
  },
  cvedetector: {
    id: 'cvedetector',
    name: 'CVE Detector (Telegram)',
    reliability: 'D',
    category: 'secondary',
    description: 'High-cadence Telegram CVE relay with structured publish timestamps but no severity data',
    known_bias: 'Relay, not primary disclosure; description-only, no CVSS',
  },
  cvemon: {
    id: 'cvemon',
    name: 'cvemon (Intruder) CVE trends',
    // A social-attention ranking, not a disclosure venue: Intruder derives
    // "trending" and a hype score from discussion volume across its own
    // community, with no severity, CVSS, or exploit data attached. Closer in
    // kind to cvedetector (a relay) than to NVD/KEV, so D rather than B — the
    // signal being surfaced is *attention*, which is a weak proxy for risk.
    reliability: 'D',
    category: 'secondary',
    description: 'Intruder social-trending CVE ranking with a proprietary hype score',
    known_bias:
      'Attention, not risk — a heavily discussed low-severity CVE can outrank an actively exploited one. No CVSS or exploit data; single upstream with no fallback',
  },
  'dwi-cve-alerts': {
    id: 'dwi-cve-alerts',
    name: 'DWI CVE Alerts (Telegram)',
    reliability: 'C',
    category: 'secondary',
    description: 'DarkWebInformer structured CVE advisories — explicit CVSS score, severity label and vector string',
    known_bias: 'Relay with editorial selection; coverage skews toward WordPress/plugin CVEs via Patchstack',
  },
  otx: {
    id: 'otx',
    name: 'AlienVault OTX',
    reliability: 'C',
    category: 'secondary',
    description: 'Open Threat Exchange — community pulses with IOCs',
  },
  virustotal: {
    id: 'virustotal',
    name: 'VirusTotal',
    reliability: 'B',
    category: 'secondary',
    description: 'Multi-engine file scanner — industry standard but opaque methodology',
  },

  // ── Tertiary / AI-generated / Inferred ──────────────────────────────────
  'ai-copilot': {
    id: 'ai-copilot',
    name: 'AI Copilot Analysis',
    reliability: 'F',
    category: 'ai_generated',
    description: 'LLM-generated assessment — must be verified by human analyst',
    known_bias: 'LLM may hallucinate attribution, IOCs, or citations',
  },
  'actor-dna': {
    id: 'actor-dna',
    name: 'Actor DNA Analysis',
    reliability: 'E',
    category: 'ai_generated',
    description: 'AI-driven actor profiling from TTP patterns',
    known_bias: 'Pattern-matching may produce false associations',
  },
  'heuristic-cve-link': {
    id: 'heuristic-cve-link',
    name: 'Heuristic CVE→Actor Link',
    reliability: 'E',
    category: 'inferred',
    description: 'Keyword-based matching between CVE descriptions and actor profiles',
    known_bias: 'Keyword matches may be coincidental',
  },
  predictive: {
    id: 'predictive',
    name: 'Predictive Intel',
    reliability: 'F',
    category: 'inferred',
    description: 'Forward-looking assessments based on historical patterns',
    known_bias: 'Extrapolation from past behaviour; novel TTPs not covered',
  },
  // ── New sources from repo analysis (2026-05-30) ─────────────────────────
  misp: {
    id: 'misp',
    name: 'MISP Feed System',
    reliability: 'B',
    category: 'secondary',
    description: 'Malware Information Sharing Platform — 200+ community-contributed feeds with STIX/TAXII output',
    known_bias: 'Quality varies by community feed; vetted by MISP instance admins',
  },
  'critical-path-feeds': {
    id: 'critical-path-feeds',
    name: 'CriticalPathSecurity Public Intelligence Feeds',
    reliability: 'B',
    category: 'secondary',
    description:
      'Curated, deduplicated aggregated feeds from Abuse.CH, AlienVault, Emerging Threats, SANS, ThreatFox, Tor, and others',
    known_bias: 'Aggregated source — inherits upstream biases; occasional false positives from community submissions',
  },
  'bert-jan-feed-catalog': {
    id: 'bert-jan-feed-catalog',
    name: 'Open-Source Threat-Intel-Feeds Catalog',
    reliability: 'C',
    category: 'secondary',
    description: 'CSV catalog of 145+ free threat intelligence feeds with vendor and type metadata',
    known_bias: 'Meta-catalog — accuracy depends on upstream feed maintenance',
  },
  yara_rules: {
    id: 'yara_rules',
    name: 'Community YARA Rules',
    reliability: 'C',
    category: 'secondary',
    description: 'Detection rules from YARAHub, InQuest/awesome-yara, and community YARA repositories',
    known_bias: 'Variable quality; some rules may produce false positives across different malware variants',
  },
  'gendigital-ioc': {
    id: 'gendigital-ioc',
    name: 'gendigitalinc IOC Repository',
    reliability: 'C',
    category: 'secondary',
    description:
      'Per-malware-family IoC directories with YARA rules — organized by family name with IP, domain, and hash indicators',
    known_bias: 'Limited to families tracked by the repository maintainer',
  },
  intelmq: {
    id: 'intelmq',
    name: 'INTELMQ Feed Processor',
    reliability: 'C',
    category: 'secondary',
    description: 'CERT Austria feed processing framework — normalized output from 200+ upstream feed collectors',
    known_bias:
      'Processing-level transformations are neutral; downstream accuracy depends on original feed reliability',
  },
  'jstrosch-samples': {
    id: 'jstrosch-samples',
    name: 'jstrosch Malware Samples',
    reliability: 'C',
    category: 'secondary',
    description: 'Curated malware sample collection organized by family with analysis notes and config extractors',
    known_bias: 'Sample selection bias toward families of interest to the researcher',
  },
  'mthcht-rules': {
    id: 'mthcht-rules',
    name: 'Awesome Rules Detection Collection',
    reliability: 'C',
    category: 'secondary',
    description: 'Multiformat detection rules (YARA, SIGMA, KQL, SPL, EQL) categorized by MITRE ATT&CK technique',
    known_bias: 'Curated from diverse sources — quality and freshness vary by rule origin',
  },
  // ── New sources from feed catalog CSV (2026-05-30) ───────────────────────
  'blocklist-de': {
    id: 'blocklist-de',
    name: 'Blocklist.de',
    reliability: 'B',
    category: 'secondary',
    description: 'Blocklist.de IP reputation — attack sources reported by distributed server network',
    known_bias: 'Attack-source aggregation; may include false positives from NAT/Shared IPs',
  },
  cinsscore: {
    id: 'cinsscore',
    name: 'CINSscore Bad IP List',
    reliability: 'B',
    category: 'secondary',
    description: 'CINS Army malicious IP list — actively maintained blocklist from distributed honeypot sensors',
    known_bias: 'Automated collection; some false positives from dynamic IP ranges',
  },

  // ── Provider-adapter sources ────────────────────────────────────────────
  //
  // These grades were already being applied by `lib/admiralty.ts` (IOC
  // enrichment) and `lib/dfir/admiralty-quick.ts` (live-IOC rows), which
  // each carried their own table. Folding them in here means the enrichment
  // path, the live-IOC path and `computeConfidence` all grade a source
  // identically. Previously `abuseipdb` graded B on the IOC path and C here,
  // so the same indicator changed confidence depending on the endpoint.
  c2tracker: {
    id: 'c2tracker',
    name: 'C2IntelFeeds Tracker',
    reliability: 'B',
    category: 'secondary',
    description: 'Community-maintained C2 server list — IPs observed in live command-and-control traffic',
    known_bias: 'Requires active scanning; short-lived C2 nodes may be missed',
  },
  hashlookup: {
    id: 'hashlookup',
    name: 'Team Cymru Hashlookup',
    reliability: 'B',
    category: 'primary',
    description: 'Team Cymru registry of known-good file hashes',
  },
  hybridanalysis: {
    id: 'hybridanalysis',
    name: 'Hybrid Analysis',
    reliability: 'B',
    category: 'primary',
    description: 'Commercial sandbox with behavioural detonation reports',
    known_bias: 'Submission-based; coverage skews toward commodity malware',
  },
  kaspersky: {
    id: 'kaspersky',
    name: 'Kaspersky OpenTIP',
    reliability: 'B',
    category: 'secondary',
    description: 'Vendor sandbox verdicts and reputation lookups',
  },
  malshare: {
    id: 'malshare',
    name: 'MalShare',
    reliability: 'B',
    category: 'secondary',
    description: 'Community malware sample repository',
    known_bias: 'Community-submitted samples; requires account for full access',
  },
  malwarebazaar: {
    id: 'malwarebazaar',
    name: 'MalwareBazaar',
    reliability: 'B',
    category: 'primary',
    description: 'abuse.ch sample repository with family signatures and first/last-seen dates',
    known_bias: 'Samples are deduplicated by hash; signature drift possible',
  },
  'sans-isc': {
    id: 'sans-isc',
    name: 'SANS ISC',
    reliability: 'B',
    category: 'secondary',
    description: 'SANS Internet Storm Center — long-running curated IP/domain blocklists',
  },
  spamhaus: {
    id: 'spamhaus',
    name: 'Spamhaus',
    reliability: 'B',
    category: 'secondary',
    description: 'Long-established reputation lists for IPs and domains',
    known_bias: 'Policy changes historically removed large IP ranges from DNSBL',
  },
  sslbl: {
    id: 'sslbl',
    name: 'SSL Blacklist',
    reliability: 'B',
    category: 'secondary',
    description: 'abuse.ch list of hosts observed distributing malicious payloads',
  },
  threatfox: {
    id: 'threatfox',
    name: 'ThreatFox',
    reliability: 'B',
    category: 'primary',
    description: 'abuse.ch IOC feed with malware-family attribution and confidence values',
  },
  urlhaus: {
    id: 'urlhaus',
    name: 'URLhaus',
    reliability: 'B',
    category: 'primary',
    description: 'abuse.ch feed of malware distribution URLs',
  },
  'c2-intel': {
    id: 'c2-intel',
    name: 'C2IntelFeeds',
    reliability: 'C',
    category: 'secondary',
    description: 'Community C2 infrastructure feeds',
    known_bias: 'Framework-specific; staleness varies by list',
  },
  censys: {
    id: 'censys',
    name: 'Censys',
    reliability: 'C',
    category: 'secondary',
    description: 'Internet-wide scan data — open ports, banners, certificate observations',
  },
  greynoise: {
    id: 'greynoise',
    name: 'GreyNoise',
    reliability: 'C',
    category: 'secondary',
    description: 'Scanner classification separating benign research crawls from targeted activity',
    known_bias: 'Contextual tags reflect observed behaviour, not intent',
  },
  mti: {
    id: 'mti',
    name: 'Meta Threat Intelligence',
    reliability: 'C',
    category: 'secondary',
    description: 'Aggregated multi-source feed',
    known_bias: 'Aggregation inherits upstream error rates',
  },
  netlas: {
    id: 'netlas',
    name: 'Netlas',
    reliability: 'C',
    category: 'secondary',
    description: 'Internet scan index — hosts, certificates and service fingerprints',
  },
  shodan: {
    id: 'shodan',
    name: 'Shodan',
    reliability: 'C',
    category: 'secondary',
    description: 'Internet-wide scan index; InternetDB subset is keyless',
    known_bias: 'Banner-derived; exposure data, not threat attribution',
  },
  urlscan: {
    id: 'urlscan',
    name: 'URLScan',
    reliability: 'C',
    category: 'secondary',
    description: 'Public scan archive with page screenshots, DOM and network requests',
    known_bias: 'Scans are publicly indexed, which can reveal investigation targets',
  },
  yaraify: {
    id: 'yaraify',
    name: 'YARAify',
    reliability: 'C',
    category: 'inferred',
    description: 'Crowdsourced YARA rule repository with automated threat scoring',
    known_bias: 'Community rules of uneven quality — graded C, not B, for that reason',
  },
  tweetfeed: {
    id: 'tweetfeed',
    name: 'TweetFeed',
    reliability: 'D',
    category: 'tertiary',
    description: 'IOCs harvested from public social posts',
    known_bias: 'High volume, low curation; frequently stale or retracted',
  },

  // ── Dedicated AI / LLM threat intelligence ─────────────────────────────
  // Grading note: `ai-honeypots` is B rather than A despite being first-hand
  // telemetry. A first-hand observer sees only what reaches its own honeypots,
  // and its high-confidence tiers are hit-count thresholds, not analyst
  // judgement — the bulk of the feed is deliberately low-confidence scanners.
  // `llm-threatintel` is a single-analyst operation (TLP:CLEAR, "independent
  // project"), so its indicators are secondary reporting with named provenance
  // rather than primary ground truth.
  'ai-honeypots': {
    id: 'ai-honeypots',
    name: 'AI Honeypot Observatory',
    reliability: 'B',
    category: 'primary',
    description:
      'First-hand LLM honeypot telemetry — IPs observed probing Ollama/LiteLLM/OpenAI-compatible endpoints, with ATT&CK mapping and actor-category classification',
    known_bias:
      'Only sees sources that scan its own honeypot network; 84% of indicators are RELAY-CUSTOMER end-users of shadow API relay pools rather than attackers',
  },
  'llm-threatintel': {
    id: 'llm-threatintel',
    name: 'LLM ThreatIntel',
    reliability: 'C',
    category: 'secondary',
    description:
      'Independent analyst tracking of LLM-abuse campaigns — ClickFix lures, malicious MCP servers, supply-chain prompt injection, each indicator tied to a named campaign',
    known_bias:
      'Single-analyst operation with a 7-day campaign half-life; indicators are stood down (status != active) as campaigns are resolved',
  },
  // Curated open-source C2 feeds (see feed-curation.ts).
  'foxit-cobaltstrike': {
    id: 'foxit-cobaltstrike',
    name: 'Fox-IT Cobalt Strike servers',
    reliability: 'B',
    category: 'secondary',
    description:
      'Internet-wide scan for Cobalt Strike team-server response artifacts — high-precision C2 infrastructure',
    known_bias:
      'Response artifact matching, so a server is only listed once it has been seen serving; misses staged/never-beaconed infrastructure',
  },
  'carbonblack-c2': {
    id: 'carbonblack-c2',
    name: 'Carbon Black active C2',
    reliability: 'B',
    category: 'secondary',
    description: 'Vendor-researched Cobalt Strike C2 attributed to a named intrusion set (actor-specific CSVs)',
    known_bias: 'Manual, campaign-scoped curation — coverage stops when the campaign ends',
  },
  'threatview-c2': {
    id: 'threatview-c2',
    name: 'Threatview.io Cobalt Strike C2',
    reliability: 'C',
    category: 'secondary',
    description: 'Proactive-hunter output listing high-confidence Cobalt Strike C2 with per-host beacon configuration',
    known_bias: 'Regenerated wholesale on each scan, so the whole list shares one detection date',
  },
  'c2intel-domains': {
    id: 'c2intel-domains',
    name: 'C2IntelFeeds C2 domains',
    reliability: 'C',
    category: 'secondary',
    description: '30-day rolling window of domains attributed to Cobalt Strike and comparable C2 frameworks',
    known_bias:
      'Heavily overlaps CDNs and cloud providers (Tencent SCF, sslip.io), so domain-level FP rate is high without beacon evidence',
  },
  'threatfox-hostfile': {
    id: 'threatfox-hostfile',
    name: 'abuse.ch ThreatFox hostfile',
    reliability: 'B',
    category: 'secondary',
    description: 'Botnet C2 and payload-delivery hostnames from analyst-submitted ThreatFox reports',
  },
  'threatfox-urls': {
    id: 'threatfox-urls',
    name: 'abuse.ch ThreatFox recent URLs',
    reliability: 'B',
    category: 'secondary',
    description: 'Recent payload-delivery URLs with malware-family attribution (ClearFake and similar loaders)',
  },
  'threatcluster-ip': {
    id: 'threatcluster-ip',
    name: 'ThreatCluster public IOCs',
    reliability: 'C',
    category: 'tertiary',
    description: 'Community-submitted high-confidence malicious IPs, 30-day window',
    known_bias: 'Community submission with no analyst verification gate',
  },
  'threatcluster-domains': {
    id: 'threatcluster-domains',
    name: 'ThreatCluster public domains',
    reliability: 'C',
    category: 'tertiary',
    description: 'Community-submitted high-confidence malicious domains, 30-day window',
    known_bias: 'Community submission with no analyst verification gate',
  },
  'sslbl-ja3': {
    id: 'sslbl-ja3',
    name: 'abuse.ch SSLBL JA3 fingerprints',
    reliability: 'B',
    category: 'secondary',
    description:
      'JA3 TLS client fingerprints observed in SSL/TLS-fingerprinted botnet C2, with malware-family attribution',
    known_bias:
      'JA3 fingerprints are coarse — popular client libraries collide across benign and malicious traffic alike, so this is a corroborating signal, never a standalone verdict',
  },
  greensnow: {
    id: 'greensnow',
    name: 'GreenSnow',
    reliability: 'C',
    category: 'secondary',
    description: 'Curated SSH brute-force and scanning source list',
    known_bias: 'SSH-centric; carries no protocol or campaign attribution',
  },
  siberkapan: {
    id: 'siberkapan',
    name: 'SiberKapan',
    reliability: 'C',
    category: 'secondary',
    description: 'High-volume attack-source IP list',
    known_bias: 'No per-entry context — a bare address list, useful for blocking not for attribution',
  },
  'bruteforce-login': {
    id: 'bruteforce-login',
    name: 'Blocklist.de bruteforcelogin',
    reliability: 'C',
    category: 'secondary',
    description: 'Blocklist.de brute-force / credential-stuffing source list',
  },
  'bl-de-ssh': {
    id: 'bl-de-ssh',
    name: 'Blocklist.de SSH attackers',
    reliability: 'C',
    category: 'secondary',
    description: 'Blocklist.de SSH attack source list',
  },
  'tsirolnik-spam': {
    id: 'tsirolnik-spam',
    name: 'tsirolnik spam domains',
    reliability: 'C',
    category: 'tertiary',
    description: 'Long-maintained community list of spam and malvertising domains',
    known_bias: 'Spam-weighted rather than malware-weighted — expect ad/malvertising domains, not C2',
  },
  'botvrij-domain': {
    id: 'botvrij-domain',
    name: 'Botvrij.eu domains',
    reliability: 'C',
    category: 'secondary',
    description: 'Curated malicious domain list with upstream decay scoring',
  },
};

// ─── Canonical Admiralty primitives ───────────────────────────────────────
//
// Single source of truth for A–F semantics. The decay engine
// (`lib/ioc-scoring.ts`) previously carried its own weight table, so the two
// scoring paths could disagree about the same source. Both now resolve
// through the helpers below.

/**
 * Admiralty tier → weight multiplier, normalised to 0–1.
 *
 * Used for multiplicative source weighting (decay/correlation scoring),
 * where a weight scales a contribution. Distinct from `reliabilityScore()`,
 * which is a linear 5–0 rank used for additive crediting.
 */
export const ADMIRALTY_WEIGHT: Record<SourceReliability, number> = {
  A: 1.0,
  B: 0.8,
  C: 0.6,
  D: 0.4,
  E: 0.2,
  F: 0.1,
};

/** Tier assigned to sources absent from the registry — "fairly reliable". */
export const DEFAULT_SOURCE_RELIABILITY: SourceReliability = 'C';

/**
 * Registry key aliases.
 *
 * The registry namespaces abuse.ch under `abusech-*`, but callers and
 * observation payloads refer to the bare provider name. Without this map the
 * decay engine silently graded `threatfox` as an unknown C instead of its
 * registered B.
 */
const SOURCE_ID_ALIASES: Record<string, string> = {
  threatfox: 'abusech-threatfox',
  urlhaus: 'abusech-urlhaus',
  malwarebazaar: 'abusech-malwarebazaar',
};

/** Linear A–F → 5–0 rank, used for additive credibility crediting. */
export function reliabilityScore(r: SourceReliability): number {
  return { A: 5, B: 4, C: 3, D: 2, E: 1, F: 0 }[r] ?? 0;
}

/**
 * Look up a registry entry by source id, tolerating case differences and the
 * `-feed` suffix convention used by `feed-status.ts`.
 */
export function lookupSourceReliability(id: string): SourceReliabilityEntry | undefined {
  if (!id) return undefined;
  const lower = id.toLowerCase();
  const alias = SOURCE_ID_ALIASES[lower];
  if (alias) return SOURCE_RELIABILITY_REGISTRY[alias];
  return (
    SOURCE_RELIABILITY_REGISTRY[lower] ?? SOURCE_RELIABILITY_REGISTRY[id] ?? SOURCE_RELIABILITY_REGISTRY[`${id}-feed`]
  );
}

/** Multiplicative weight for a tier, defaulting to the unrated tier. */
export function reliabilityWeight(r?: SourceReliability): number {
  return ADMIRALTY_WEIGHT[r ?? DEFAULT_SOURCE_RELIABILITY] ?? ADMIRALTY_WEIGHT[DEFAULT_SOURCE_RELIABILITY] ?? 0.6;
}

/**
 * Resolve a source to its Admiralty tier.
 *
 * An explicit tier always wins (callers may know better than the registry).
 * Otherwise the tier comes from `SOURCE_RELIABILITY_REGISTRY`, falling back
 * to `DEFAULT_SOURCE_RELIABILITY` for sources that are not registered.
 */
export function resolveSourceReliability(sourceId: string, explicit?: string): SourceReliability {
  if (explicit) {
    const upper = explicit.toUpperCase();
    if (upper in ADMIRALTY_WEIGHT) return upper as SourceReliability;
  }
  return lookupSourceReliability(sourceId)?.reliability ?? DEFAULT_SOURCE_RELIABILITY;
}

/**
 * Compute a confidence score for a finding based on source reliabilities,
 * number of corroborating sources, and whether contradictory sources exist.
 */
export function computeConfidence(params: {
  sourceIds: string[];
  contradictorySourceIds?: string[];
  findingType: 'ioc' | 'attribution' | 'vulnerability' | 'campaign' | 'apt_activity' | 'ransomware_claim' | 'general';
}): ConfidenceScore {
  const { sourceIds, contradictorySourceIds = [], findingType } = params;

  // Resolution goes through `lookupSourceReliability` so aliases and the
  // `-feed` suffix resolve identically to every other caller.
  const entryFor = (id: string): SourceReliabilityEntry | undefined => lookupSourceReliability(id);

  // Reliability-weighted count
  let weightedCredibility = 0;
  for (const id of sourceIds) {
    const e = entryFor(id);
    if (e) {
      const w = reliabilityScore(e.reliability);
      weightedCredibility += w;
      // Primary sources get extra weight
      if (e.category === 'primary') weightedCredibility += 2;
    } else {
      weightedCredibility += 1; // unknown source = minimal weight
    }
  }

  // Contradictory sources reduce confidence
  let contradictionPenalty = 0;
  for (const id of contradictorySourceIds) {
    const e = entryFor(id);
    if (e) {
      const w = reliabilityScore(e.reliability);
      contradictionPenalty += w > 0 ? w + 1 : 1;
    } else {
      contradictionPenalty += 1;
    }
  }

  const sourceCount = sourceIds.length;
  const contradictoryCount = contradictorySourceIds.length;

  // Base score from source reliability and corroboration
  let score = Math.min(100, weightedCredibility * 8 + sourceCount * 5);
  // Penalty for contradictions
  score = Math.max(0, score - contradictionPenalty * 10);

  // Finding-type adjustments
  const typeAdjustments: Record<string, number> = {
    ioc: 5, // IOCs are generally more reliable
    vulnerability: 5, // CVEs are well-documented
    ransomware_claim: 0, // Neutral
    attribution: -10, // Attribution is inherently uncertain
    campaign: -5, // Campaigns are analyst constructs
    apt_activity: -10, // APT tracking is uncertain
    general: 0,
  };
  score += typeAdjustments[findingType] ?? 0;
  score = Math.max(0, Math.min(100, score));

  // Admiralty grade
  let bestReliability: SourceReliability = 'F';
  for (const id of sourceIds) {
    const e = entryFor(id);
    if (e && reliabilityScore(e.reliability) > reliabilityScore(bestReliability)) {
      bestReliability = e.reliability;
    }
  }
  // Best credibility based on source count and contradictions
  let credibility: InfoCredibility = 6;
  if (sourceCount >= 3 && contradictoryCount === 0) credibility = 1;
  else if (sourceCount >= 2 && contradictoryCount === 0) credibility = 2;
  else if (sourceCount >= 1 && contradictoryCount === 0) credibility = 3;
  else if (contradictoryCount > 0 && sourceCount > contradictoryCount) credibility = 4;
  else if (contradictoryCount >= sourceCount) credibility = 5;
  else credibility = 6;

  const admiralty: AdmiraltyGrade = {
    reliability: bestReliability,
    credibility,
    label: `${bestReliability}-${credibility}: ${reliabilityLabel(bestReliability)} / ${credibilityLabel(credibility)}`,
  };

  // Confidence level
  let level: Confidence;
  if (score >= 85) level = 'very_high';
  else if (score >= 70) level = 'high';
  else if (score >= 45) level = 'moderate';
  else if (score >= 20) level = 'low';
  else level = 'very_low';

  // Reasoning
  const parts: string[] = [];
  parts.push(`${sourceCount} source(s), ${contradictoryCount} contradictory`);
  if (sourceCount >= 2) parts.push('corroborated');
  if (contradictoryCount > 0) parts.push(`conflict from ${contradictoryCount} source(s)`);
  if (bestReliability <= 'B') parts.push('authoritative primary source');
  else if (bestReliability === 'C' || bestReliability === 'D') parts.push('secondary/aggregated source');
  else parts.push('low-reliability source');

  return {
    level,
    score,
    // Visual band for the same number. Polarity is `confidence`: a high score
    // here means "we are sure", which is reassuring, not dangerous. Previously
    // every consumer re-derived its own colour ramp from `score`.
    band: bandConfidence(score, { sourceCount }),
    admiralty,
    sources_contributing: sourceCount,
    contradictory_sources: contradictoryCount,
    reasoning: parts.join('; ') || 'unassessed',
  };
}

export function reliabilityLabel(r: SourceReliability): string {
  const labels: Record<SourceReliability, string> = {
    A: 'Reliable',
    B: 'Usually reliable',
    C: 'Fairly reliable',
    D: 'Not usually reliable',
    E: 'Unreliable',
    F: 'Unassessed',
  };
  return labels[r];
}

export function credibilityLabel(c: InfoCredibility): string {
  const labels: Record<InfoCredibility, string> = {
    1: 'Confirmed',
    2: 'Probably True',
    3: 'Possibly True',
    4: 'Doubtful',
    5: 'Improbable',
    6: 'Cannot be judged',
  };
  return labels[c];
}

/**
 * Findings tagged with confidence — used across the platform for consistent
 * display. Every intel object that reaches the UI should carry this.
 */
export interface ConfidenceTagged {
  confidence: ConfidenceScore;
}

// ─── API handler ──────────────────────────────────────────────────────────

export async function sourceReliabilityHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  return c.json(
    {
      generated_at: new Date().toISOString(),
      total_sources: Object.keys(SOURCE_RELIABILITY_REGISTRY).length,
      sources: Object.values(SOURCE_RELIABILITY_REGISTRY).sort((a, b) => a.id.localeCompare(b.id)),
    },
    200,
    { 'Cache-Control': 'public, max-age=86400' }
  );
}
