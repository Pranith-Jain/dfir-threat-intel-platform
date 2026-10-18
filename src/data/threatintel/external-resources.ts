// src/data/threatintel/external-resources.ts
/**
 * External resources catalog - sites and dashboards I cross-reference outside
 * this repo. Mixed kinds (training, lab, tool, dashboard, directory, samples,
 * community, research) so a single pill row drives the filter.
 *
 * Each entry has ONE `kind`. Sites that legitimately span multiple categories
 * (e.g. OpenSourceMalware: samples AND community) are tagged by their dominant
 * artefact; the description mentions the secondary aspect.
 *
 * Last verified 2026-06-13.
 */

export type ResourceKind =
  'training' | 'lab' | 'tool' | 'dashboard' | 'directory' | 'samples' | 'community' | 'research';

export type ResourceTag =
  | 'malware'
  | 'threat-intel'
  | 'c2'
  | 'phishing'
  | 'osint'
  | 'dfir'
  | 'darkweb'
  | 'vulnerability'
  | 'ai-security'
  | 'blocklist'
  | 'sandbox'
  | 'telegram'
  | 'anonymity'
  | 'offensive'
  | 'evasion'
  | 'cve'
  | 'kev'
  | 'ioc'
  | 'threat-actors'
  | 'ai-enriched';

export interface ExternalResource {
  id: string;
  name: string;
  url: string;
  kind: ResourceKind;
  description: string;
  why?: string;
  /** Quality-content signal for research/discovery filtering. */
  featured?: true;
  /** Searchable tags for cross-category filtering. */
  tags?: ResourceTag[];
}

export const KIND_LABELS: Record<ResourceKind, string> = {
  training: 'Training',
  lab: 'Lab',
  tool: 'Tool',
  dashboard: 'Dashboard',
  directory: 'Directory',
  samples: 'Samples',
  community: 'Community',
  research: 'Research',
};

export const KIND_BLURB: Record<ResourceKind, string> = {
  training: 'Structured courses and learning paths.',
  lab: 'Interactive hands-on environments and playgrounds.',
  tool: 'Off-site utilities you run against an indicator or asset.',
  dashboard: 'Hosted dashboards and visual feeds you read.',
  directory: 'Curated indexes pointing at other resources.',
  samples: 'Datasets, malware corpora, and credential dumps.',
  community: 'Forums, Discords, and practitioner hubs.',
  research: 'Methodology, whitepapers, and adversarial-testing frameworks.',
};

export const KIND_PILL: Record<ResourceKind, string> = {
  training: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  lab: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  tool: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  dashboard: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  directory: 'border-slate-500/40 bg-slate-500/10 text-slate-700 dark:text-slate-300',
  samples: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  community: 'border-cyan-500/40 bg-cyan-500/10 text-sky-700 dark:text-sky-300',
  research: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
};

export const TAG_LABELS: Record<ResourceTag, string> = {
  malware: 'Malware',
  'threat-intel': 'Threat Intel',
  c2: 'C2',
  phishing: 'Phishing',
  osint: 'OSINT',
  dfir: 'DFIR',
  darkweb: 'Dark Web',
  vulnerability: 'Vuln',
  'ai-security': 'AI Sec',
  blocklist: 'Blocklist',
  sandbox: 'Sandbox',
  telegram: 'Telegram',
  anonymity: 'Anonymity',
  offensive: 'Offensive',
  evasion: 'Evasion',
  cve: 'CVE',
  kev: 'KEV',
  ioc: 'IOC',
  'threat-actors': 'Threat Actors',
  'ai-enriched': 'AI-Enriched',
};

export const TAG_PILL: Record<ResourceTag, string> = {
  malware: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  'threat-intel': 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  c2: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  phishing: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  osint: 'border-teal-500/40 bg-teal-500/10 text-teal-700 dark:text-teal-300',
  dfir: 'border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300',
  darkweb: 'border-purple-500/40 bg-purple-500/10 text-purple-700 dark:text-purple-300',
  vulnerability: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  'ai-security': 'border-indigo-500/40 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  blocklist: 'border-slate-500/40 bg-slate-500/10 text-slate-700 dark:text-slate-300',
  sandbox: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  telegram: 'border-cyan-500/40 bg-cyan-500/10 text-sky-700 dark:text-sky-300',
  anonymity: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  offensive: 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300',
  evasion: 'border-purple-500/40 bg-purple-500/10 text-purple-700 dark:text-purple-300',
  cve: 'border-blue-500/40 bg-blue-500/10 text-blue-700 dark:text-blue-300',
  kev: 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300',
  ioc: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300',
  'threat-actors': 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  'ai-enriched': 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

export const RESOURCES: ExternalResource[] = [
  // Migrated from src/pages/threatintel/Home.tsx (External Sources block, 2026-05-14).
  // Descriptions copied verbatim - no rewriting in this commit.
  {
    id: 'my-threat-intel',
    name: 'My Threat Intel',
    url: 'https://www.mythreatintel.com/?lang=en',
    kind: 'dashboard',
    description:
      'Live ransomware dashboard · country / sector / timeline charts · 180+ ransomware groups with ransom-note transcripts and leak-site screenshots',
  },
  {
    id: 'deepdark-cti',
    name: 'deepdarkCTI',
    url: 'https://github.com/fastfire/deepdarkCTI',
    kind: 'directory',
    description: 'Continuously updated repository of dark-web and CTI sources, by fastfire',
  },
  {
    id: 'threat-landscape-free-tools',
    name: 'Threat Landscape Free Tools',
    url: 'https://threatlandscape.io/free-tools',
    kind: 'directory',
    description: 'Curated free DFIR and threat-intel tools directory',
  },
  {
    id: 'vecert-analyzer',
    name: 'Vecert Analyzer',
    url: 'https://analyzer.vecert.io/index',
    kind: 'tool',
    description: 'Free file and indicator analyzer for incident response',
  },
  {
    id: 'world-monitor',
    name: 'World Monitor',
    url: 'https://www.worldmonitor.app',
    kind: 'dashboard',
    description: 'Real-time OSINT dashboard, news, markets, ADS-B and AIS tracking across 435+ sources',
  },
  {
    id: 'osint-tools',
    name: 'OSINT Tools',
    url: 'https://osinttools.io/tools',
    kind: 'directory',
    description: 'Curated OSINT directory',
  },
  {
    id: 'osintrack',
    name: 'OSINTrack',
    url: 'https://osintrack.com/',
    kind: 'tool',
    description: 'OSINT investigation tracker',
  },
  {
    id: 'ai-soc',
    name: 'AI SOC',
    url: 'https://aisoc.pplx.app/',
    kind: 'lab',
    description: 'AI-assisted SOC playground by Perplexity Labs.',
  },
  {
    id: 'aisecurity-zone',
    name: 'AISecurity.zone',
    url: 'https://aisecurity.zone/',
    kind: 'directory',
    featured: true,
    tags: ['ai-security', 'threat-intel'],
    description:
      'Community-curated hub of AI-security resources - adversarial ML, LLM red-teaming, model/data exfiltration, prompt-injection catalogues, governance frameworks, and AI-CTI tooling. Useful as a discovery surface when triaging AI-system risks or scoping AI red-team engagements.',
    why: 'Centralised AI-security starting point I cross-reference when scoping AI risk assessments or building detection content for LLM-adjacent threats.',
  },
  {
    id: 'syberseeker-certs',
    name: 'Syberseeker Free Certification Courses',
    url: 'https://start.me/p/xb2ReR/free-certification-courses-by-syberseeker',
    kind: 'directory',
    featured: true,
    description:
      'Curated start.me page by Syberseeker aggregating free certification tracks - security, cloud, networking, and blue-team paths from vendors, universities, and community programs. Mirrored in-platform at /threatintel/osint/certs with a daily auto-sync.',
    why: 'The single best free-cert starting point I have found. Direct mirror on the platform means the same link list is searchable, deep-linkable, and survives start.me outages.',
  },
  {
    id: 'leakradar',
    name: 'LeakRadar',
    url: 'https://leakradar.io/en/leaks',
    kind: 'tool',
    description:
      '290B+ leaked credentials indexed from stealer logs, combolists, and database dumps. REST API + Telegram/Slack/webhook alerts.',
  },
  {
    id: 'serus',
    name: 'Serus',
    url: 'https://serus.ai',
    kind: 'tool',
    description:
      'AI-powered data-exposure monitoring and dark-web surveillance for individuals and orgs. Combines breach search with takedown automation.',
  },

  // New entries (2026-05-14). Descriptions verified against each site.
  {
    id: 'opensourcemalware',
    name: 'OpenSourceMalware',
    url: 'https://opensourcemalware.com/',
    kind: 'samples',
    description: 'Community-driven platform for sharing and analysing malware samples and threat intelligence.',
  },
  {
    id: 'ai-goat',
    name: 'AI Goat',
    url: 'https://aigoat.co.in/learn/',
    kind: 'lab',
    featured: true,
    description:
      'Open-source AI security playground for hands-on LLM red teaming - prompt injection, RAG poisoning, OWASP LLM Top 10 - runs fully offline.',
  },
  {
    id: 'vulnos',
    name: 'VulnOS',
    url: 'https://learn.vulnos.tech/index.html',
    kind: 'training',
    featured: true,
    description: 'Cybersecurity learning platform with practical, interactive labs for hands-on skill building.',
  },
  {
    id: 'black-ledger-security',
    name: 'Black Ledger Security',
    url: 'https://blackledgersecurity.ai/',
    kind: 'research',
    featured: true,
    description:
      'Research portfolio publishing AI/LLM security findings and the SPECTRA framework for context-aware adversarial testing of production AI deployments.',
  },
  {
    id: 'webverse-labs-pro',
    name: 'WebVerse Labs Pro',
    url: 'https://webverselabs-pro.com/',
    kind: 'lab',
    featured: true,
    description:
      'Web-app pentest training platform - 36 labs across 5 difficulty tiers with XP, leaderboards, and vulnerability-chaining scenarios.',
  },
  {
    id: 'redteam-community',
    name: 'Red Team Community',
    url: 'https://www.redteam.community/',
    kind: 'community',
    description: 'Red-team practitioner community hub.',
  },
  {
    id: 'hunter-how',
    name: 'hunter.how',
    url: 'https://hunter.how/',
    kind: 'tool',
    description:
      'Internet asset search engine in the Shodan/Censys/FOFA family. Fingerprints 500+ network protocols across 2,000+ products with country, SSL-certificate, and subdomain filters. Free daily quota; paid plans for higher throughput.',
  },
  // ── New entries (2026-05-16) ─────────────────────────────────────────────
  {
    id: 'darkfeed-io',
    name: 'Darkfeed.io',
    url: 'https://darkfeed.io/free-dashboard/',
    kind: 'dashboard',
    description:
      'Real-time threat intelligence dashboard aggregating IOCs, dark-web activity, and adversary infrastructure indicators from multiple sources. Free tier available.',
  },
  {
    id: 'deepfind-me',
    name: 'DeepFind.Me',
    url: 'https://deepfind.me/tools',
    kind: 'tool',
    description:
      'Comprehensive OSINT toolkit - username search (50+ platforms), geolocation, email/domain recon, metadata extraction, dark-web link checker, crypto wallet tracking, and more. REST API available.',
  },
  {
    id: 'ai-supply-chain-observatory',
    name: 'AI Supply Chain Observatory',
    url: 'https://ai-supply-chain-observatory.vercel.app/',
    kind: 'dashboard',
    featured: true,
    description:
      'Visual dashboard tracking AI supply-chain risks, model provenance, and dependency vulnerabilities across the ML ecosystem.',
  },
  {
    id: 'darkweb-daily',
    name: 'DarkWebDaily',
    url: 'https://darkwebdaily.live/',
    kind: 'dashboard',
    description:
      'Curated dark-web news aggregator - breach announcements, ransomware claims, and underground forum highlights delivered in a daily digest format.',
  },
  {
    id: 'haxor-llm-security',
    name: 'LLM Security Slides',
    url: 'https://haxor44.github.io/llm-security-slides/#1',
    kind: 'research',
    featured: true,
    description:
      'Presentation covering LLM attack surfaces, prompt injection techniques, jailbreaking methodologies, and AI red-teaming tradecraft.',
  },
  {
    id: 'geniebot',
    name: 'GenieBot',
    url: 'https://geniebot.pro/',
    kind: 'tool',
    description: 'AI-powered security assistant and chatbot for threat intelligence queries and security automation.',
  },
  {
    id: 'web-check',
    name: 'Web Check',
    url: 'https://web-check.xyz/',
    kind: 'tool',
    featured: true,
    description:
      'All-in-one website analysis tool - DNS, SSL, headers, WHOIS, tech stack, performance, and security audit from a single URL input.',
  },
  {
    id: 'claude101',
    name: 'Claude 101',
    url: 'https://claude101.com/',
    kind: 'training',
    description:
      'Learning resource hub for Claude AI - prompt engineering guides, use-case examples, and best practices for Anthropic Claude.',
  },
  {
    id: 'appsec-master',
    name: 'AppSec Master',
    url: 'https://www.appsecmaster.net/en',
    kind: 'training',
    featured: true,
    description:
      'Interactive application security training platform - hands-on labs covering OWASP Top 10, API security, and secure coding practices.',
  },
  {
    id: 'osinttools-io',
    name: 'OSINT Tools',
    url: 'https://osinttools.io/',
    kind: 'directory',
    featured: true,
    description:
      'Curated directory of OSINT tools with community collections, featured tool listings, and new-tool discovery feed.',
  },
  {
    id: 'intelligenceonchain-osint',
    name: 'Intelligence on Chain',
    url: 'https://osint.intelligenceonchain.com/',
    kind: 'directory',
    featured: true,
    description:
      'Curated, filterable directory of blockchain/crypto OSINT tools - wallet tracing, transaction analysis, identity and infrastructure recon. Field-tested entries organized by cost, skill level, OPSEC sensitivity, and input type (address, hash, email, username).',
    why: 'On-chain OSINT companion to the crypto-trace / fund-flow tooling here.',
    tags: ['osint', 'threat-intel'],
  },
  {
    id: 'databreach-com',
    name: 'DataBreach.com',
    url: 'https://databreach.com/',
    kind: 'tool',
    description:
      'Data breach search platform - check if credentials or personal data have been exposed in known breaches. Also provides breach monitoring alerts.',
  },
  {
    id: 'malwareworld',
    name: 'MalwareWorld',
    url: 'https://malwareworld.com/',
    kind: 'dashboard',
    featured: true,
    description:
      'Aggregated threat intelligence from 100+ public blacklists. Search IPs/domains, view threat maps, download categorized blocklists (bad reputation, malware, spam, phishing, cryptocurrency, DGA).',
  },
  {
    id: 'hacktricks-tools',
    name: 'HackTricks Tools',
    url: 'https://tools.hacktricks.wiki/',
    kind: 'tool',
    featured: true,
    description:
      'Interactive security tools by HackTricks - domain/DNS auditor, host checker, clickjacking PoC generator, GitHub leaks scanner, AI chatbot, and cloud IAM auditor (PEASS).',
  },
  {
    id: 'osv-dev',
    name: 'OSV.dev',
    url: 'https://osv.dev/list',
    kind: 'tool',
    featured: true,
    description:
      'Open Source Vulnerabilities database - Google-backed, API-first vulnerability feed covering PyPI, npm, Go, Maven, and other ecosystems with ecosystem-agnostic schema.',
  },
  {
    id: 'digital-defense',
    name: 'Digital Defense',
    url: 'https://digital-defense.io/',
    kind: 'tool',
    description:
      'OPSEC and privacy toolkit - guides and checklists for operational security, digital footprint reduction, and secure communications.',
  },
  {
    id: 'awesome-privacy',
    name: 'Awesome Privacy',
    url: 'https://awesome-privacy.xyz/',
    kind: 'directory',
    description:
      'Curated list of privacy-focused tools and services - VPNs, encrypted messaging, password managers, analytics alternatives, and privacy hardware.',
  },
  {
    id: 'bitwire-blocklist',
    name: 'BitWire IP Blocklist (stats)',
    url: 'https://bitwire.it/blocklist-stats',
    kind: 'dashboard',
    tags: ['blocklist', 'threat-intel'],
    description:
      'Upstream stats dashboard for bitwire-it/ipblocklist - live counters, growth history and source attribution. Pairs with the in-platform mirror at /threatintel/bitwire-blocklist.',
  },
  {
    id: 'crowdthreat',
    name: 'CrowdThreat',
    url: 'https://www.crowdthreat.com/',
    kind: 'dashboard',
    description:
      'Threat intelligence dashboard - cross-references IOCs, threat actor profiles, and campaign tracking. Includes OSINT tools section at /osint_tools.',
  },
  {
    id: 'ti-mindmap-hub',
    name: 'TI Mindmap Hub',
    url: 'https://ti-mindmap-hub.com/',
    kind: 'tool',
    description:
      'Interactive threat intelligence mindmap - visual navigation of TTPs, threat actors, campaigns, and detection strategies mapped to the MITRE ATT&CK framework.',
  },
  {
    id: 'insider-threat-matrix',
    name: 'Insider Threat Matrix',
    url: 'https://insiderthreatmatrix.org/',
    kind: 'research',
    featured: true,
    description:
      'Comprehensive insider threat framework covering indicators, detection methods, mitigation strategies, and case studies across personas and attack vectors.',
  },
  {
    id: 'orca-osintcti',
    name: 'Orca OSINT/CTI',
    url: 'https://orca.osintcti.com/',
    kind: 'tool',
    description:
      'OSINT and cyber threat intelligence platform - unified search across multiple data sources for indicators, threat actors, and infrastructure discovery.',
  },
  {
    id: 'redhunt-labs-research',
    name: 'RedHunt Labs Research',
    url: 'https://research.redhuntlabs.com/',
    kind: 'research',
    featured: true,
    description:
      'Security research blog from RedHunt Labs - attack surface management insights, vulnerability disclosures, and adversary infrastructure tracking write-ups.',
  },
  {
    id: 'aidefend',
    name: 'AIDefend',
    url: 'https://aidefend.net/',
    kind: 'tool',
    description:
      'AI-powered cybersecurity defense platform - automated threat detection, response orchestration, and security posture management.',
  },
  {
    id: 'cyber-laws',
    name: 'Cyber Laws',
    url: 'https://cyber-laws.com/en/',
    kind: 'research',
    description:
      'Legal reference platform for cybersecurity regulations worldwide - GDPR, CCPA, HIPAA, DPDP, and cross-border data protection frameworks with jurisdictional analysis.',
  },
  {
    id: 'kongsec-osai-notes',
    name: 'KongSec OSAI Notes',
    url: 'https://kongsec.github.io/OSAINotesResearch/',
    kind: 'research',
    featured: true,
    description:
      'Research notes on offensive AI security - prompt injection, LLM red-teaming, AI supply-chain attacks, and adversarial ML techniques.',
  },
  {
    id: 'mjolnir-intel',
    name: 'Mjolnir Intelligence',
    url: 'https://intel.mjolnirsecurity.com/',
    kind: 'dashboard',
    description:
      'Threat intelligence dashboard - IOC feeds, campaign tracking, and real-time security event monitoring from Mjolnir Security.',
  },
  {
    id: 'mjolnir-vulnot',
    name: 'Mjolnir VulnOT',
    url: 'https://vulnot.mjolnirlabs.com/',
    kind: 'tool',
    description:
      'Vulnerability notes and OT/IoT security advisory aggregator - CVE tracking, exploit POC references, and remediation guidance for operational technology.',
  },
  {
    id: 'owasp-ai-visualizer',
    name: 'OWASP AI Security Visualizer',
    url: 'https://ricokomenda.github.io/owasp-ai-security-visualizer/',
    kind: 'tool',
    featured: true,
    description:
      'Interactive visualizer for the OWASP AI Security landscape - maps AI-specific threats, vulnerabilities, and controls across the ML lifecycle.',
  },
  {
    id: 'cybersectools',
    name: 'CyberSecTools',
    url: 'https://cybersectools.com/',
    kind: 'directory',
    featured: true,
    description:
      'Curated catalog of cybersecurity tools organized by category - penetration testing, forensics, OSINT, red teaming, and blue team operations.',
  },
  {
    id: 'sigma-nasbench',
    name: 'Sigma Rule Explorer (nasbench)',
    url: 'https://sigma.nasbench.dev/',
    kind: 'tool',
    featured: true,
    description:
      'Interactive Sigma rule browser - search, filter, and explore Sigma detection rules with SIEM conversion previews for Splunk, Elastic, QRadar, and more.',
  },
  {
    id: 'ghostint-tools',
    name: 'Ghostint Tools',
    url: 'https://cyberz7.github.io/Ghostint-Tools/',
    kind: 'directory',
    featured: true,
    description:
      'Curated OSINT and cybersecurity tools directory - categorized tools for reconnaissance, social media investigation, and digital forensics.',
  },
  {
    id: 'arcanum-ai-sec',
    name: 'Arcanum AI Security Resources',
    url: 'https://arcanum-sec.github.io/ai-sec-resources/',
    kind: 'research',
    featured: true,
    description:
      'Curated resources on AI/ML security - papers, tools, frameworks, and CTF challenges focused on adversarial ML, LLM security, and AI red teaming.',
  },
  {
    id: 'extsentry-feeds',
    name: 'ExtSentry Feeds',
    url: 'https://extsentry.github.io/#feeds/malicious',
    kind: 'tool',
    description:
      'Browser extension threat feeds - curated list of malicious browser extensions tracked via abuse reports and security research.',
  },
  {
    id: 'hocsec',
    name: 'HOCSEC',
    url: 'https://hackersonlineclub.com/hocsec/',
    kind: 'directory',
    description:
      'Cybersecurity tools and resources directory by Hackers Online Club - categorized security tools, learning resources, and community projects.',
  },
  {
    id: 'quanqiuchongtu',
    name: 'Quanqiuchongtu',
    url: 'https://quanqiuchongtu.com/',
    kind: 'dashboard',
    description:
      'Global cybersecurity conflict monitoring dashboard - tracks nation-state cyber operations, hacktivist campaigns, and geopolitical cyber events.',
  },
  {
    id: 'map-wddadk',
    name: 'Cyber Threat Map (wddadk)',
    url: 'https://map.wddadk.com/',
    kind: 'dashboard',
    description:
      'Live cyber threat attack map - real-time visualization of cyber attacks, DDoS events, and scanning activity across global infrastructure.',
  },
  {
    id: 'apt28-victimology',
    name: 'APT28 Victimology',
    url: 'https://apt-28.victimology.infrawatch.com/',
    kind: 'dashboard',
    featured: true,
    description:
      'APT28 (Fancy Bear) victimology dashboard - tracks known targets, campaigns, and infrastructure attribution for the Russian state-sponsored threat actor.',
  },
  {
    id: 'kilaz-net',
    name: 'Kilaz.net',
    url: 'https://kilaz.net/',
    kind: 'research',
    featured: true,
    description:
      'Security research and threat intelligence blog - APT analysis, malware reverse engineering, and cybercrime ecosystem investigations.',
  },
  {
    id: 'mail-thc',
    name: 'THC Mail',
    url: 'https://mail.thc.org/',
    kind: 'tool',
    description:
      'The Hackers Choice mail service - privacy-focused email with security features for the infosec community.',
  },
  {
    id: 'crowdthreat-osint',
    name: 'CrowdThreat OSINT Tools',
    url: 'https://www.crowdthreat.com/osint_tools',
    kind: 'directory',
    description:
      'Curated OSINT tools section within CrowdThreat - categorized open-source intelligence tools for digital investigations.',
  },
  {
    id: 'dmarc-labs',
    name: 'DMARC Labs',
    url: 'https://www.dmarclabsds1.xyz/',
    kind: 'tool',
    description:
      'Free DMARC RUA report analyzer - privacy-first, in-memory XML parsing with IP enrichment, SPF/DKIM/DMARC alignment per sender. See also /dfir/dmarc-analyzer on this site.',
  },
  {
    id: 'osv-api',
    name: 'OSV.dev API',
    url: 'https://osv.dev/#use-the-api',
    kind: 'tool',
    description:
      'Open Source Vulnerabilities REST API - query by package/version or commit hash to identify known vulnerabilities across open-source ecosystems.',
  },
  {
    id: 'hudsonrock-free-tools',
    name: 'Hudson Rock Free Tools',
    url: 'https://www.hudsonrock.com/free-tools',
    kind: 'tool',
    description:
      'Free infostealer exposure check - search by email, domain, or username for compromised credentials from infostealer infections. By Hudson Rock.',
  },
  {
    id: 'infostealers-victims',
    name: 'InfoStealers.com Victims',
    url: 'https://www.infostealers.com/infostealer-victims/',
    kind: 'dashboard',
    description:
      'Infostealer victims dashboard by Hudson Rock - browse compromised machines, employees, and domains per infostealer family.',
  },
  // ── Open Directory Search Tools (2026-05-27) ─────────────────────────────
  {
    id: 'opendirsearch-abifog',
    name: 'OpenDirSearch (abifog)',
    url: 'https://opendirsearch.abifog.com/',
    kind: 'tool',
    description:
      'Open directory search engine - find publicly accessible directory listings for OSINT recon and file discovery.',
  },
  {
    id: 'odcrawler-xyz',
    name: 'ODCrawler',
    url: 'http://odcrawler.xyz/',
    kind: 'tool',
    description:
      'Open directory crawler and search engine - indexes publicly accessible directory listings for OSINT investigations.',
  },
  {
    id: 'odfinder-github',
    name: 'ODFinder',
    url: 'https://odfinder.github.io/',
    kind: 'tool',
    description:
      'Open directory finder tool - search engine for finding open directory listings across the web for OSINT data gathering.',
  },
  {
    id: 'lendx-org',
    name: 'LendX',
    url: 'https://lendx.org/',
    kind: 'tool',
    description:
      'Open directory search engine - discover exposed directory listings and publicly accessible files for intelligence gathering.',
  },
  {
    id: 'palined-search',
    name: 'Palined Search',
    url: 'https://palined.com/search/',
    kind: 'tool',
    description:
      'Open directory search tool - search across publicly accessible directory listings for OSINT and reconnaissance.',
  },
  {
    id: 'ewasion-od-finder',
    name: 'Ewasion Open Directory Finder',
    url: 'https://ewasion.github.io/opendirectory-finder/',
    kind: 'tool',
    description:
      'Open directory finder tool - browser-based tool for discovering and searching open directory listings.',
  },
  {
    id: 'expde-od-finder',
    name: 'Expde Open Directory Finder',
    url: 'https://expde.github.io/OpenDirectoryFinder/',
    kind: 'tool',
    description:
      'Open directory search tool - find exposed directory listings and publicly accessible file indexes for OSINT collection.',
  },
  {
    id: 'eyedex-org',
    name: 'EyeDex',
    url: 'https://eyedex.org/',
    kind: 'tool',
    description:
      'Open directory index and search engine - browse and search across publicly accessible directory listings worldwide.',
  },
  {
    id: 'newsmap',
    name: 'Newsmap',
    url: 'https://newsmap.cc/',
    kind: 'dashboard',
    description:
      'Geographic heatmap of global news by category - visualize breaking news trends, media bias, and coverage density across regions.',
  },
  {
    id: 'ransomware-interviews',
    name: 'Ransomware Operator Interviews',
    url: 'https://ransomware-interviews.base44.app/',
    kind: 'research',
    description:
      'First-person conversations with ransomware operators. Negotiation tactics, affiliate economics, and the human side of the ransomware ecosystem.',
    featured: true,
  },
  // ── Telegram OSINT / Search Tools (2026-05-28) ────────────────────────────
  {
    id: 'telemetryapp',
    name: 'TelemetryApp',
    url: 'https://telemetryapp.com/',
    kind: 'tool',
    featured: true,
    description:
      "Telegram search and analytics platform - search channels, messages, groups, and media across Telegram's public surface. Built for OSINT analysts and threat hunters.",
  },
  {
    id: 'lyzem',
    name: 'LYZEM',
    url: 'https://lyzem.com/',
    kind: 'tool',
    description:
      "Telegram search engine - full-text search across public channels and messages. Indexes content beyond Telegram's native search for OSINT discovery.",
  },
  {
    id: 'telegago',
    name: 'Telegago',
    url: 'https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg',
    kind: 'tool',
    description:
      "Google Custom Search Engine scoped to Telegram public content - search indexed Telegram channels, groups, and messages via Google's crawler.",
  },
  {
    id: 'xtea',
    name: 'XTEA',
    url: 'https://xtea.io/',
    kind: 'tool',
    featured: true,
    description:
      'Telegram intelligence and search platform - advanced search across channels, messages, and media. Designed for OSINT researchers, investigators, and threat analysts.',
  },
  {
    id: 'tgstat',
    name: 'TGStat',
    url: 'https://tgstat.com/',
    kind: 'dashboard',
    featured: true,
    description:
      'Telegram analytics and statistics platform - channel rankings, subscriber growth, engagement metrics, and content search across millions of public Telegram channels.',
  },
  {
    id: 'tgdb',
    name: 'TGDB',
    url: 'https://tgdb.io/',
    kind: 'directory',
    description:
      'Telegram database and directory - browse and search public Telegram channels, groups, and bots. Categorized index for OSINT discovery and channel enumeration.',
  },
  // ── Malware Sample Repositories (2026-05-28) ────────────────────────────
  {
    id: 'vx-underground',
    name: 'vx-underground',
    url: 'https://vx-underground.org/',
    kind: 'samples',
    featured: true,
    tags: ['malware', 'dfir'],
    description:
      'The largest collection of malware source code, samples, and papers on the internet. Curated corpus spanning decades of malware families, APT tools, and reverse-engineering research.',
  },
  {
    id: 'malwarebazaar',
    name: 'MalwareBazaar',
    url: 'https://bazaar.abuse.ch/',
    kind: 'samples',
    featured: true,
    tags: ['malware', 'threat-intel', 'dfir'],
    description:
      "abuse.ch project - crowdsourced malware sample repository. Upload and download samples, search by hash/tag/family, API access. Integrated into this platform's IOC checker.",
  },
  {
    id: 'virushare',
    name: 'VirusShare',
    url: 'https://virusshare.com/',
    kind: 'samples',
    tags: ['malware', 'dfir'],
    description:
      'Malware sample repository maintained by VirusTotal contributor. 40M+ samples available for download. Free registration required. Password-protected ZIP archives.',
  },
  {
    id: 'malshare',
    name: 'MalShare',
    url: 'https://malshare.com/',
    kind: 'samples',
    featured: true,
    tags: ['malware', 'threat-intel'],
    description:
      "Free malware sample repository with REST API. 1000+ daily samples from 30+ sources. Search by hash, file type, or keyword. API key available with free registration. Integrated into this platform's IOC checker.",
  },
  {
    id: 'thezoo',
    name: 'theZoo',
    url: 'https://github.com/ytisf/theZoo',
    kind: 'samples',
    tags: ['malware', 'dfir'],
    description:
      'Open-source live malware repository on GitHub. Curated samples organized by family with encrypted archives. CLI tool for downloading and analysing samples. Educational purpose.',
  },
  {
    id: 'polyswarm',
    name: 'PolySwarm',
    url: 'https://polyswarm.io/',
    kind: 'samples',
    tags: ['malware', 'sandbox', 'threat-intel'],
    description:
      'Decentralized malware marketplace - submit samples for scanning by multiple competing engines. Free tier available. Real-time threat intelligence from 40+ anti-malware engines.',
  },
  {
    id: 'inquest-labs',
    name: 'InQuest Labs',
    url: 'https://labs.inquest.net/',
    kind: 'samples',
    featured: true,
    tags: ['malware', 'dfir', 'threat-intel'],
    description:
      'Malware research lab - IOC database, YARA rule repository, retrohunt, and sample analysis. Free tier with API access. Specialises in document-based malware (Office, PDF, LNK).',
  },
  // ── abuse.ch Projects (2026-05-28) ──────────────────────────────────────
  {
    id: 'threatfox',
    name: 'ThreatFox',
    url: 'https://threatfox.abuse.ch/',
    kind: 'dashboard',
    featured: true,
    tags: ['threat-intel', 'c2', 'malware'],
    description:
      "abuse.ch IOC sharing platform - community-submitted IOCs (IPs, domains, URLs, hashes) mapped to malware families. Searchable database with API. Integrated into this platform's live IOCs feed.",
  },
  {
    id: 'urlhaus',
    name: 'URLhaus',
    url: 'https://urlhaus.abuse.ch/',
    kind: 'dashboard',
    featured: true,
    tags: ['threat-intel', 'malware', 'phishing'],
    description:
      "abuse.ch URL tracking - community-submitted malicious URLs serving malware payloads. Searchable database with API and downloadable blocklists. Integrated into this platform's live IOCs feed.",
  },
  {
    id: 'sslbl',
    name: 'SSL Blacklist',
    url: 'https://sslbl.abuse.ch/',
    kind: 'dashboard',
    tags: ['threat-intel', 'c2', 'blocklist'],
    description:
      'abuse.ch SSL/TLS certificate blacklist - tracks malicious SSL certificates used by botnet C2 servers. Downloadable IP and certificate SHA1 blacklists.',
  },
  {
    id: 'yaraify',
    name: 'YARAify',
    url: 'https://yaraify.abuse.ch/',
    kind: 'tool',
    tags: ['malware', 'dfir', 'threat-intel'],
    description:
      'abuse.ch YARA scanning platform - submit samples for YARA rule matching, search by YARA rule, upload custom rules. Community-driven detection rule testing.',
  },
  // ── Sandboxes & Analysis Platforms (2026-05-28) ─────────────────────────
  {
    id: 'anyrun',
    name: 'ANY.RUN',
    url: 'https://any.run/',
    kind: 'lab',
    featured: true,
    tags: ['sandbox', 'malware', 'dfir'],
    description:
      'Interactive malware sandbox - real-time behavioural analysis with Windows VMs. Free tier with public submissions. Process tree, network captures, MITRE ATT&CK mapping.',
  },
  {
    id: 'joe-sandbox',
    name: 'Joe Sandbox',
    url: 'https://www.joesecurity.org/',
    kind: 'lab',
    tags: ['sandbox', 'malware', 'dfir'],
    description:
      'Commercial malware analysis sandbox with free community tier. Deep behavioural analysis, YARA rules, sigma detection, and network IOCs extraction.',
  },
  {
    id: 'hybrid-analysis',
    name: 'Hybrid Analysis',
    url: 'https://www.hybrid-analysis.com/',
    kind: 'lab',
    featured: true,
    tags: ['sandbox', 'malware', 'threat-intel'],
    description:
      'Free malware analysis sandbox by CrowdStrike. Static + dynamic analysis, MITRE mapping, network IOCs, and community verdicts. API access available.',
  },
  // ── Threat Intel Feeds & Dashboards (2026-05-28) ────────────────────────
  {
    id: 'virustotal',
    name: 'VirusTotal',
    url: 'https://www.virustotal.com/',
    kind: 'tool',
    featured: true,
    tags: ['malware', 'threat-intel', 'dfir', 'sandbox'],
    description:
      'The definitive malware and IOC analysis platform. 70+ AV engine scan, behavioural sandbox, YARA search, graph analysis, community comments. Free API with rate limits.',
  },
  {
    id: 'otx-alienvault',
    name: 'AlienVault OTX',
    url: 'https://otx.alienvault.com/',
    kind: 'dashboard',
    featured: true,
    tags: ['threat-intel', 'c2', 'blocklist'],
    description:
      "Open Threat Exchange - community-driven threat intelligence. IOC pulses, reputation data, endpoint telemetry. Free API. Integrated into this platform's IOC checker.",
  },
  {
    id: 'c2-tracker-feeds',
    name: 'C2IntelFeeds',
    url: 'https://github.com/drb-ra/C2IntelFeeds',
    kind: 'dashboard',
    tags: ['c2', 'threat-intel', 'blocklist'],
    description:
      "Automated C2 infrastructure feeds - IP and domain lists for Cobalt Strike, Sliver, Brute Ratel, and other C2 frameworks. Updated daily via GitHub. Integrated into this platform's live IOCs feed.",
  },
  {
    id: 'khaos-c2',
    name: 'KHAOS C2',
    url: 'https://khaos.khaotic.fr',
    kind: 'tool',
    tags: ['c2', 'offensive', 'evasion'],
    description:
      'Modern post-exploitation C2 framework with 5 covert channels (Teams, GitHub Gist, DoH, HTTPS, SMB). C agent with indirect syscalls, ETW/AMSI patching via hardware breakpoints, BOF/COFF loading, token theft, LSASS dump, Kerberoasting, SOCKS5, and WMI lateral movement. MIT license.',
  },
  {
    id: 'openphish',
    name: 'OpenPhish',
    url: 'https://openphish.com/',
    kind: 'dashboard',
    tags: ['phishing', 'threat-intel', 'blocklist'],
    description:
      "Automated phishing intelligence - real-time phishing URL feed. Community feed is free; premium adds targeted brand analysis. Integrated into this platform's live IOCs feed.",
  },
  {
    id: 'phishtank',
    name: 'PhishTank',
    url: 'https://phishtank.org/',
    kind: 'dashboard',
    tags: ['phishing', 'threat-intel'],
    description:
      'Community phishing verification platform - submit and verify suspected phishing URLs. Free API and downloadable database. Operated by OpenDNS/Cisco.',
  },
  // ── New entries (2026-05-28) ─────────────────────────────────────────────
  {
    id: 'opengraph-intel',
    name: 'OpenGraph Intel',
    url: 'https://ogi.khas.app/',
    kind: 'tool',
    featured: true,
    tags: ['osint', 'threat-intel'],
    description:
      'Open-source visual intelligence platform for OSINT link analysis and graph-based investigation workflows. Investigate entities, map relationships, and run graph-native transforms. Features username search, domain-to-IP pivoting, email-to-domain extraction, and HTTP header analysis.',
  },
  {
    id: 'crowdsec-cti',
    name: 'CrowdSec CTI',
    url: 'https://www.crowdsec.net/cti-api',
    kind: 'tool',
    tags: ['threat-intel', 'c2', 'blocklist'],
    description:
      "Crowd-sourced threat intelligence API. IP reputation, attack categories, behaviors, and community trust scores. Free tier: 1000 lookups/month. Integrated into this platform's IOC checker.",
  },
  {
    id: 'spur-us',
    name: 'Spur.us',
    url: 'https://spur.us/',
    kind: 'tool',
    tags: ['osint', 'threat-intel'],
    description:
      "VPN, proxy, and residential IP detection service. Identifies anonymization services and their providers. Free community endpoint available. Integrated into this platform's IP enrichment.",
  },
  {
    id: 'ipinfo-io',
    name: 'IPinfo.io',
    url: 'https://ipinfo.io/',
    kind: 'tool',
    tags: ['osint'],
    description:
      "IP geolocation, ASN, company, and privacy detection API. 50k requests/month on free tier. Integrated into this platform's IP enrichment.",
  },
  {
    id: 'criminalip',
    name: 'CriminalIP',
    url: 'https://www.criminalip.io/',
    kind: 'tool',
    tags: ['threat-intel', 'vulnerability'],
    description:
      'IP reputation and vulnerability scanning platform. Detects malware, botnets, phishing, mining, and remote access. Free tier: 100 lookups/month.',
  },
  {
    id: 'shodan-internetdb',
    name: 'Shodan InternetDB',
    url: 'https://internetdb.shodan.io/',
    kind: 'tool',
    tags: ['osint', 'vulnerability'],
    description:
      "Free, keyless IP intelligence API from Shodan. Returns open ports, CVEs, hostnames, and tags for any IP address. Unlimited lookups. Integrated into this platform's IOC checker.",
  },
  {
    id: 'phishstats',
    name: 'PhishStats.info',
    url: 'https://phishstats.info/',
    kind: 'dashboard',
    tags: ['phishing', 'threat-intel'],
    description:
      "Phishing URL statistics and reputation data. Score, first/last seen, target brand, hosting country. Free API, no authentication required. Integrated into this platform's IOC checker.",
  },
  {
    id: 'offseq-radar',
    name: 'OffSeq Threat Radar',
    url: 'https://radar.offseq.com/',
    kind: 'dashboard',
    tags: ['threat-intel', 'vulnerability', 'ai-security', 'osint'],
    description:
      "Aggregated threat-intel feed (~40 upstream sources) with AI-enriched summaries, KEV correlation and Mirage honeypot exploitation telemetry. Free public API; integrated into this platform's 24h CVE digest and as a replicated threat feed vertical.",
  },
  {
    id: 'ctiwatch',
    name: 'CTIWatch',
    url: 'https://ctiwatch.com/',
    kind: 'dashboard',
    tags: ['threat-intel', 'vulnerability', 'osint', 'dfir'],
    description:
      "Public vulnerability + IOC database (2M+ IOCs, 400k+ CVEs, 4k+ KEV, 10k+ threat actors). Free anonymous API with session bootstrap; integrated into this platform's IOC checker and as a replicated threat feed vertical.",
  },
  {
    id: 'digitalside-intel',
    name: 'Digital Side Threat Intel',
    url: 'https://github.com/davidonzo/Threat-Intel',
    kind: 'dashboard',
    tags: ['threat-intel', 'phishing', 'blocklist'],
    description:
      "Free threat intelligence feeds on GitHub - malware URLs, phishing URLs, C2 domains, and file hashes. Updated regularly. Integrated into this platform's IOC checker.",
  },
  // ── Threat Intel Platforms & Frameworks (2026-05-30) ───────────────────
  {
    id: 'misp-platform',
    name: 'MISP · Malware Information Sharing Platform',
    url: 'https://www.misp-project.org/',
    kind: 'tool',
    featured: true,
    tags: ['threat-intel', 'dfir'],
    description:
      'Open-source threat intelligence platform for sharing, storing and correlating IOCs. 200+ default feeds from public sources. STIX/TAXII support, feed system, API, and MISP taxii server integration. De facto standard for CTI sharing.',
  },
  {
    id: 'intelowl',
    name: 'IntelOwl',
    url: 'https://github.com/intelowlproject/IntelOwl',
    kind: 'tool',
    featured: true,
    tags: ['threat-intel', 'malware', 'sandbox', 'dfir'],
    description:
      'Open-source threat intelligence analysis orchestration - submits files, URLs, hashes, IPs to 200+ analyzers (VirusTotal, AbuseIPDB, Shodan, YARA, etc.). REST API, web UI, Celery-based job queue.',
  },
  {
    id: 'opencti-platform',
    name: 'OpenCTI',
    url: 'https://github.com/OpenCTI-Platform/opencti',
    kind: 'tool',
    featured: true,
    tags: ['threat-intel', 'dfir'],
    description:
      'Open-source threat intelligence platform by Filigran. Knowledge graph for threat actors, TTPs, campaigns, IOCs. STIX/TAXII native, 20+ connectors, MITRE ATT&CK mapping. Self-hosted or cloud.',
  },
  {
    id: 'intelmq-framework',
    name: 'INTELMQ · Feed Processing Framework',
    url: 'https://github.com/certtools/intelmq',
    kind: 'tool',
    tags: ['threat-intel', 'dfir'],
    description:
      'Python framework by CERT Austria for collecting, processing, and correlating threat intelligence feeds. Modular bots (collectors, parsers, experts, outputs). Handles 200+ feed formats at scale.',
  },
  // ── Aggregated Intel Feeds & Directories (2026-05-30) ──────────────────
  {
    id: 'critical-path-feeds',
    name: 'CriticalPathSecurity · Public Intelligence Feeds',
    url: 'https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds',
    kind: 'dashboard',
    featured: true,
    tags: ['threat-intel', 'blocklist', 'c2', 'malware'],
    description:
      'Curated, deduplicated threat intelligence feeds combining Abuse.CH, AlienVault, BinaryDefense, CobaltStrike, Emerging Threats, SANS, ThreatFox, Tor, and more. Standardized TXT format with versioned files.',
  },
  {
    id: 'bert-jan-feed-catalog',
    name: 'Bert-JanP · Open Source Threat Intel Feeds',
    url: 'https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds',
    kind: 'directory',
    tags: ['threat-intel', 'blocklist'],
    description:
      'CSV catalog of 145+ free threat intelligence feeds organized by type (IP, DNS, URL, MD5, SHA256, CVE, JA3) with vendor metadata. Reference directory for discovering new feed sources.',
  },
  {
    id: 'hslatman-awesome-ti',
    name: 'Awesome Threat Intelligence',
    url: 'https://github.com/hslatman/awesome-threat-intelligence',
    kind: 'directory',
    featured: true,
    tags: ['threat-intel', 'dfir', 'osint', 'malware'],
    description:
      'Curated list of 1,000+ threat intelligence resources - feeds, tools, frameworks, platforms, YARA rules, SIGMA rules, standards, books, and courses. 10,000+ GitHub stars.',
  },
  {
    id: 'muchdogesec-awesome-ti',
    name: 'Awesome Threat Intel',
    url: 'https://github.com/muchdogesec/awesome-threat-intel',
    kind: 'directory',
    tags: ['threat-intel'],
    description:
      'Extended directory of threat intelligence projects, tools, and data sources. Covers STIX/TAXII, MISP, YARA, SIGMA, OpenCTI connectors, and CTI automation pipelines.',
  },
  {
    id: '0x4d31-threat-detection',
    name: 'Awesome Threat Detection',
    url: 'https://github.com/0x4D31/awesome-threat-detection',
    kind: 'directory',
    tags: ['threat-intel', 'dfir', 'vulnerability'],
    description:
      'Curated list of open-source threat detection resources - detection engineering, SIGMA rules, YARA rules, queries (KQL, SPL, EQL), threat hunting, and adversary emulation.',
  },
  // ── YARA & Detection Rules (2026-05-30) ────────────────────────────────
  {
    id: 'yarahub-platform',
    name: 'YARAHub',
    url: 'https://yarahub.org/',
    kind: 'community',
    tags: ['malware', 'dfir', 'threat-intel'],
    description:
      'Open YARA rule sharing platform. Community-submitted detection rules with metadata, testing, and indexed search. Covers malware families, C2 frameworks, and file formats.',
  },
  {
    id: 'awesome-yara',
    name: 'InQuest · Awesome YARA',
    url: 'https://github.com/InQuest/awesome-yara',
    kind: 'directory',
    tags: ['malware', 'dfir'],
    description:
      'Curated list of YARA rules, tools, and resources - rule repositories, testing frameworks, IDE plugins, and learning materials for YARA-based detection engineering.',
  },
  {
    id: 'mthcht-awesome-rules',
    name: 'Awesome Rules · Detection Rules Collection',
    url: 'https://github.com/mthcht/awesome-rules',
    kind: 'directory',
    tags: ['threat-intel', 'dfir', 'malware'],
    description:
      'Massive collection of detection rules across YARA, SIGMA, KQL, SPL, and EQL formats. Categorised by MITRE ATT&CK technique. Curated from multiple open-source rule repositories.',
  },
  // ── Per-Family IoCs & Samples (2026-05-30) ─────────────────────────────
  {
    id: 'gendigital-ioc',
    name: 'gendigitalinc · IOC Repository',
    url: 'https://github.com/gendigitalinc/ioc',
    kind: 'samples',
    tags: ['malware', 'threat-intel', 'c2'],
    description:
      'Per-malware-family IoC directories with YARA rules and indicators. Organized by malware name with IPs, domains, hashes, and rule files for each family.',
  },
  {
    id: 'jstrosch-malware-samples',
    name: 'jstrosch · Malware Samples & Sources',
    url: 'https://github.com/jstrosch/malware-samples',
    kind: 'samples',
    tags: ['malware', 'sandbox'],
    description:
      'Curated malware sample collection organized by family. Includes analysis notes, configuration extractors, and references to original sources. Regularly updated with new campaigns.',
  },
  // ── DFIR & OSINT Collections (2026-05-30) ──────────────────────────────
  {
    id: 'cpuu-awesome-forensic-extreme',
    name: 'Awesome Forensics Extreme Collection',
    url: 'https://github.com/cpuu/awesome-forensicextremecollection',
    kind: 'directory',
    tags: ['dfir', 'osint'],
    description:
      'Comprehensive DFIR and OSINT tool collection - disk forensics, memory analysis, network forensics, timeline analysis, triage, and reporting tools. Community-maintained resource list.',
  },
  {
    id: 'leonov-av-awesome-forensics',
    name: 'Awesome Forensics',
    url: 'https://github.com/leonov-av/awesome-forensics',
    kind: 'directory',
    tags: ['dfir', 'osint'],
    description:
      'Curated list of digital forensics resources - forensic tools, analysis frameworks, artifact collections, CTF challenges, and educational materials for DFIR practitioners.',
  },
  {
    id: 'shevacyber-osint-collectors',
    name: 'OSINT Collectors',
    url: 'https://github.com/shevacyber/OSINT-Collectors',
    kind: 'directory',
    tags: ['osint'],
    description:
      'Curated collection of OSINT data collectors - web scraping templates, API wrappers, and data extraction scripts for open-source intelligence gathering across platforms.',
  },
  {
    id: 'osint-for-countries',
    name: 'OSINT for Countries',
    url: 'https://github.com/wddadk/OSINT-for-countries',
    kind: 'directory',
    tags: ['osint'],
    description:
      'Per-country OSINT resource directory - 1,500+ curated tools and data sources across 247 countries. Covers government registries, news, maps, people search, social media, transportation, utilities, and crime data. Powers the interactive country OSINT map on this platform.',
  },
  // ── Incident Response & Cloud Security (2026-05-30) ────────────────────
  {
    id: 'aws-ir-samples',
    name: 'AWS Incident Response Samples',
    url: 'https://github.com/aws-samples/aws-incident-response-samples',
    kind: 'tool',
    tags: ['dfir', 'vulnerability'],
    description:
      'Official AWS incident response playbook samples - CloudFormation templates, Lambda functions, and runbooks for automating IR workflows in AWS. Pre-built response actions for common scenarios.',
  },
  {
    id: 'taxii-server',
    name: 'TAXII 2.1 Server',
    url: 'https://pranithjain.qzz.io/api/taxii2/',
    kind: 'tool',
    tags: ['threat-intel'],
    description:
      "This platform's TAXII 2.1 server for automated threat intelligence sharing. Compatible with MISP, OpenCTI, Splunk SOAR, and other TAXII clients. Collections: IOCs, actors, malware, vulnerabilities, briefings.",
  },
  {
    id: 'nexus-osint',
    name: 'Nexus OSINT',
    url: 'https://nexusosint.fr/',
    kind: 'dashboard',
    tags: ['osint', 'threat-intel'],
    description:
      'French open-source intelligence platform - real-time aggregation across geopolitics, cyber, and military domains. Multi-source dashboard surfacing breaking events with structured metadata for analysts tracking hybrid threats.',
  },
  {
    id: 'cloak-matrix',
    name: 'CLOAK Matrix',
    url: 'https://opsectechniques.com/',
    kind: 'research',
    tags: ['dfir', 'osint'],
    description:
      'OPSEC techniques and procedures reference - tactic → technique → sub-technique → procedure hierarchy modeled after MITRE ATT&CK but scoped to operational-security tradecraft. Useful for blue teams mapping counter-surveillance controls and red teams modelling adversary OPSEC gaps.',
  },
  // ── Anonymity & OpSec tools ──────────────────────────────────────
  {
    id: 'onionscan',
    name: 'OnionScan',
    url: 'https://onionscan.org/',
    kind: 'tool',
    tags: ['anonymity', 'osint', 'darkweb'],
    description:
      'Tor hidden-service scanner that probes .onion operators for opsec leaks and misconfiguration that could deanonymize them. Reports on exposed server banners, EXIF in page assets, open ports, Apache mod_status leaks, and other metadata that has historically been used to identify Silk Road-style operators. MIT, Go, s-rah/onionscan.',
  },
  {
    id: 'onionscout',
    name: 'OnionScout',
    url: 'https://pypi.org/project/onionscout/',
    kind: 'tool',
    tags: ['anonymity', 'osint', 'darkweb'],
    description:
      'Lightweight Python CLI for auditing Tor hidden services for clearnet dependencies, metadata leaks, fingerprinting indicators, and basic de-anonymization risks. Modern (2026) alternative to OnionScan, pip-installable.',
  },
  {
    id: 'droidfs',
    name: 'DroidFS',
    url: 'https://github.com/hardcore-sushi/DroidFS',
    kind: 'tool',
    tags: ['anonymity', 'dfir'],
    description:
      'Android encrypted overlay filesystem using gocryptfs (and CryFS). Mounts volumes as virtual disks without root, keeping data invisible to other apps and media scanners. AGPL-3.0, on F-Droid. Critical for mobile OpSec - encrypted photo capture, internal file viewer, fingerprint unlock, auto-lock on background.',
  },
  {
    id: 'macchangerx',
    name: 'MacChangerX',
    url: 'https://github.com/ramad0na/MACChangerX',
    kind: 'tool',
    tags: ['anonymity'],
    description:
      'Python Linux MAC changer with random / spoof / anti-fingerprint modes. Bundles log clearing, hostname spoofing, DNS cache flushing, and Bluetooth MAC rotation - all-in-one L2 fingerprint erasure. MIT, requires root. (Small but free and works.)',
  },
  {
    id: 'spoofdpi',
    name: 'SpoofDPI',
    url: 'https://github.com/xvzc/spoofdpi',
    kind: 'tool',
    tags: ['anonymity'],
    description:
      'Go-based anti-censorship proxy that bypasses Deep Packet Inspection without root/admin by modifying the length of the first packets in the TLS handshake, defeating packet-based DPI used by ISPs to censor the web. Apache-2.0, 4.6k, install via Homebrew or single binary from GitHub releases.',
  },
  {
    id: 'kloak',
    name: 'kloak',
    url: 'https://github.com/Whonix/kloak',
    kind: 'tool',
    tags: ['anonymity'],
    description:
      'Keystroke and mouse anti-fingerprinting tool. Emulates an average typing rhythm by randomizing inter-key intervals + speed, defeating keystroke-biometric identification. Also obfuscates mouse path/timing. BSD-3-Clause, Wayland-native, ships in Whonix / Tails. Original vmonaco/kloak archived; Whonix fork is the active branch.',
  },
  {
    id: 'proxychains-ng',
    name: 'ProxyChains-NG',
    url: 'https://github.com/rofl0r/proxychains-ng',
    kind: 'tool',
    tags: ['anonymity'],
    description:
      "LD_PRELOAD hook that routes any dynamically-linked program's TCP traffic through a proxy cascade. Fork of the classic proxychains adding IPv6 support, mixed SOCKS4/5 + HTTP/HTTPS chaining, and automatic failover to live nodes. GPL-2.0, available in apt/brew/Arch.",
  },
  {
    id: 'raspiblitz',
    name: 'RaspiBlitz',
    url: 'https://github.com/raspiblitz/raspiblitz',
    kind: 'tool',
    tags: ['anonymity', 'osint'],
    description:
      "DIY Bitcoin + Lightning full node on a Raspberry Pi with integrated Tor, Electrum server, and physical-key HD wallet isolation. Self-sovereign hardware node with zero cloud dependence. MIT, but the hardware (Pi 4/5 + 1-2 TB SSD + PSU) costs ~$200-400 - software is free, the appliance isn't.",
  },
  // ── AI Security & Agent Skills (2026-06-07) ─────────────────────────
  {
    id: 'anthropic-cybersecurity-skills',
    name: 'Anthropic Cybersecurity Skills',
    url: 'https://github.com/mukul975/Anthropic-Cybersecurity-Skills',
    kind: 'directory',
    featured: true,
    tags: ['ai-security', 'threat-intel', 'dfir'],
    description:
      '754 structured cybersecurity skills for AI agents across 26 security domains. Mapped to 5 frameworks: MITRE ATT&CK v19.1, NIST CSF 2.0, MITRE ATLAS, D3FEND, and NIST AI RMF. Works with Claude Code, Copilot, Codex CLI, Cursor, Gemini CLI, and 20+ platforms. 14,000+ GitHub stars.',
  },
  {
    id: 'awesome-agent-skills',
    name: 'Awesome Agent Skills',
    url: 'https://github.com/VoltAgent/awesome-agent-skills',
    kind: 'directory',
    featured: true,
    tags: ['ai-security'],
    description:
      'Collection of 1,400+ AI agent skills from official dev teams (Anthropic, Google, Vercel, Stripe, Cloudflare, Trail of Bits) and the community. Compatible with Claude Code, Codex, Gemini CLI, Cursor, and agentskills.io standard. 24,000+ GitHub stars.',
  },
  {
    id: 'awesome-ai-security',
    name: 'Awesome AI Security',
    url: 'https://github.com/ottosulin/awesome-ai-security',
    kind: 'directory',
    featured: true,
    tags: ['ai-security', 'threat-intel'],
    description:
      'Curated list of AI security resources - frameworks, standards, red teaming tools, LLM attack techniques, agentic AI security, MCP security, adversarial ML, and AI governance. 1,000+ GitHub stars.',
  },
  {
    id: 'openosint-agent',
    name: 'OpenOSINT',
    url: 'https://github.com/OpenOSINT/OpenOSINT',
    kind: 'tool',
    tags: ['osint', 'threat-intel', 'ai-security'],
    description:
      'AI-powered OSINT agent with interactive REPL, CLI, MCP server, and Web UI. 16 tools for email, username, breach, WHOIS, IP, subdomain, Shodan, VirusTotal, Censys, and DNS intelligence. Supports Claude, GPT-4, and local Ollama models. Apache 2.0.',
  },
  // ── Pentesting & Web Security (2026-06-07) ──────────────────────────
  {
    id: 'awesome-pentest',
    name: 'Awesome Pentest',
    url: 'https://github.com/enaqx/awesome-pentest',
    kind: 'directory',
    featured: true,
    tags: ['dfir', 'osint', 'malware'],
    description:
      'Comprehensive curated collection of 10,000+ penetration testing resources - tools, books, frameworks, CTF platforms, network tools, exploit development, OSINT, web exploitation, reverse engineering, and security conferences. 26,000+ GitHub stars.',
  },
  {
    id: 'owasp-web-checklist',
    name: 'OWASP Web Security Testing Checklist',
    url: 'https://github.com/0xRadi/OWASP-Web-Checklist',
    kind: 'directory',
    tags: ['vulnerability', 'threat-intel'],
    description:
      'Structured OWASP checklist covering 100+ web application security tests - info gathering, config management, authentication, session management, authorization, data validation, cryptography, and business logic. 2,000+ GitHub stars.',
  },
  {
    id: 'cti-as-a-code',
    name: 'CTI as a Code',
    url: 'https://anpa1200.github.io/CTI_as_a_Code/',
    kind: 'training',
    featured: true,
    tags: ['threat-intel', 'dfir'],
    description:
      'Version-controlled CTI methodology with 8 structured training assignments covering reactive, proactive, and full-cycle intelligence. Docker Compose lab stack (OpenCTI, TheHive, Cortex, Elastic SIEM). Evidence-traced analysis with deployable Sigma rule output.',
    why: 'Practitioner-grade CTI training that treats investigations like software engineering - version-controlled, template-driven, evidence-traced, and reproducible.',
  },
  // ── Geopolitical OSINT & News Monitoring (2026-06-12) ───────────────────
  {
    id: 'redroom-live',
    name: 'Redroom',
    url: 'https://redroom.live/',
    kind: 'dashboard',
    featured: true,
    tags: ['osint', 'threat-intel'],
    description:
      'CIA-style real-time geopolitical news monitoring platform - live map visualization, news crawler, facilities database, and Neo4j network graph explorer. MENA region focus with interactive map overlays and dark/light mode.',
  },
  {
    id: 'worldwideview',
    name: 'WorldWideView',
    url: 'https://demo.worldwideview.dev/',
    kind: 'dashboard',
    featured: true,
    tags: ['osint', 'threat-intel'],
    description:
      'Geospatial intelligence platform - real-time 3D globe with live data feeds, entity filters, and infrastructure tracking. AI-powered news aggregation, geopolitical monitoring, and infrastructure visualization.',
  },
  // ── YARA Rules & Detection Sources (2026-06-12) ────────────────────────
  {
    id: 'signature-base',
    name: 'signature-base',
    url: 'https://github.com/Neo23x0/signature-base',
    kind: 'samples',
    featured: true,
    tags: ['malware', 'dfir', 'threat-intel'],
    description:
      'Comprehensive YARA rules and IOC signatures by Florian Roth. 1,000+ rules covering APT groups, malware families, web shells, and exploitation tools. Updated regularly. MIT licensed.',
  },
  {
    id: 'threathunter-playbook',
    name: 'ThreatHunter-Playbook',
    url: 'https://github.com/OTRF/ThreatHunter-Playbook',
    kind: 'research',
    featured: true,
    tags: ['threat-intel', 'dfir'],
    description:
      'Detection logic mapped to MITRE ATT&CK - Jupyter notebooks with Sigma rules, Splunk queries, and threat-hunting methodologies for each technique. Community-driven, regularly updated.',
  },
  {
    id: 'ransomwatch',
    name: 'ransomwatch',
    url: 'https://github.com/joshhighet/ransomwatch',
    kind: 'dashboard',
    tags: ['threat-intel', 'malware'],
    description:
      "Ransomware group monitoring - tracks 100+ ransomware operations, scrapes leak sites, and publishes structured JSON of new victim posts. MIT licensed. Integrated into this platform's live IOCs feed.",
  },
  {
    id: 'misp-galaxy',
    name: 'MISP Galaxy',
    url: 'https://www.misp-galaxy.org/',
    kind: 'research',
    featured: true,
    tags: ['threat-intel', 'malware'],
    description:
      'Open knowledge base of threat actor clusters, malware, ransomware, tools, and ATT&CK matrices. 200+ clusters covering threat actors, backdoors, bankers, exploit kits, ransomware, RATs, and surveillance vendors. CC0-licensed - importable into any threat intelligence platform.',
    why: 'Definitive open-source repository of structured threat intelligence clusters - the reference for actor naming, tool tracking, and cross-platform STIX-compatible sharing.',
  },
  {
    id: 'osint-vault',
    name: 'The OSINT Vault',
    url: 'https://theosintvault.io',
    kind: 'tool',
    tags: ['osint'],
    description:
      'Complete OSINT platform with 4,577+ verified public records sources across all 50 US states, multi-search launcher (80+ platforms), Google dork generator, report composer, bookmarklet library (60+ one-click tools), and investigation notebook. All browser-based, no registration required.',
    why: 'The OSINT Grid (4,577 public records sources) is a unique structured dataset. Multi-search launcher and dork generator complement our existing /dfir/google-dorks and /dfir/osint-map tools.',
  },
  {
    id: 'threatsignal',
    name: 'ThreatSignal',
    url: 'https://threatsignal.in',
    kind: 'dashboard',
    tags: ['threat-intel'],
    description:
      'Threat intelligence dashboard - live IOC feeds, campaign tracking, and real-time security event monitoring from Mjolnir Security.',
  },
  {
    id: 'bamqam',
    name: 'BAMQAM',
    url: 'https://bamqam.com',
    kind: 'dashboard',
    featured: true,
    tags: ['threat-intel', 'osint'],
    description:
      'Live military/geopolitical operations dashboard by Nehemia Gershuni-Aylho. ADS-B aircraft tracking, AIS ship tracking, satellite tracking, GPS jamming overlays, fire/thermal detection, UKMTO maritime incidents, Gulf civil defense alerts, NOTAM data, and time-machine replay. Real-time CENTCOM theater visualization.',
    why: 'Bridges the gap between civilian CTI and military OSINT. The GPS jamming overlay, time-machine replay, and UKMTO maritime incident feed are unique capabilities not found in other open dashboards. Strong complement to our GlobalPulse war-room and aircraft layers.',
  },
  {
    id: 'pathfinding-cloud',
    name: 'pathfinding.cloud',
    url: 'https://pathfinding.cloud',
    kind: 'lab',
    featured: true,
    tags: ['vulnerability', 'dfir'],
    description:
      'AWS IAM privilege escalation attack paths and hands-on labs by Datadog Security Labs. Comprehensive library of IAM escalation techniques with exploitation guides, detection coverage maps, and deployable lab scenarios (Stratus Red Team meets IAM Vulnerable).',
    why: 'The only open-source resource mapping complete AWS IAM privilege escalation chains with both offensive and defensive coverage. Essential for cloud security assessments and detection engineering.',
  },
  {
    id: 'osiris',
    name: 'OSIRIS',
    url: 'https://www.osirisai.live/',
    kind: 'dashboard',
    featured: true,
    tags: ['osint', 'threat-intel'],
    description:
      'Open-source Palantir alternative - 3D globe tracking 10,000+ aircraft (ADS-B), 2,000+ satellites, and worldwide CCTV. Built-in browser tools: Nmap, DNS, WHOIS, SSL cert, BGP/ASN lookups, IP reputation. 20+ live feeds (earthquakes, wildfires, nuclear facilities, cyber threats, conflicts, GPS jamming).',
    why: 'Unifies the OSINT + CTI + GEOINT experience into a single browser dashboard - closest open-source analogue to commercial intelligence platforms. Strong complement to our GlobalPulse war-room and our aircraft/satellite layers.',
  },
  {
    id: 'personal-security-checklist',
    name: 'Personal Security Checklist',
    url: 'https://github.com/lissy93/personal-security-checklist',
    kind: 'directory',
    featured: true,
    tags: ['osint'],
    description:
      "Lissy93's curated checklist of 300+ tips for protecting digital security and privacy - 21k+ stars on GitHub. Structured as a YAML knowledge base with categories covering accounts, devices, networks, communications, physical, and OPSEC. CC0-licensed.",
    why: 'The de-facto open-source personal security checklist. The structured YAML makes it a natural complement to a local interactive checklist implementation.',
  },
  {
    id: 'mastering-ti-platforms',
    name: 'Mastering Threat Intelligence Platforms',
    url: 'https://start.me/p/gGj8gn/mastering-threat-intelligence-platforms',
    kind: 'directory',
    tags: ['threat-intel', 'osint'],
    description:
      'Curated start.me page aggregating threat-intelligence platform resources, tooling, and references. Useful for discovering adjacent CTI sources and community-maintained watchlists.',
  },
  {
    id: 'startme-dark-web-data-breach',
    name: 'Dark Web Data Breach (start.me)',
    url: 'https://start.me/p/xjvDyJ/dark-web-data-breach',
    kind: 'directory',
    tags: ['darkweb', 'osint', 'dfir'],
    description:
      'Curated start.me page aggregating dark-web data-breach resources - leak-site monitors, paste-site scrapers, ransomware-tracker dashboards, exposed-credential search portals, and underground-market intelligence feeds. Useful for monitoring breach disclosures and pivoting into compromised-asset investigations.',
  },
  {
    id: 'bitwire-repo',
    name: 'Bitwire IP Blocklist (GitHub)',
    url: 'https://github.com/bitwire-it/ipblocklist',
    kind: 'directory',
    featured: true,
    tags: ['threat-intel', 'blocklist'],
    description:
      'Bitwire-it/ipblocklist - 338-star GitHub repo aggregating 30+ IP blocklists (AbuseIPDB, FireHOL, ipsum, ThreatFox, Spamhaus DROP, Binary Defense, SANS, CINSscore) into two curated feeds updated every 2h. inbound.txt (~2M IPs) for WAN-IN drops, outbound.txt (~150K IPs) for LAN-OUT blocks. CC BY-NC-SA 4.0.',
    why: 'Best open-source single-source-of-truth for compiled malicious IP feeds. Reflected in /threatintel/bitwire-blocklist (in-platform dashboard), /dfir/blocklists (consolidated pfSense/iptables/Suricata) and /api/v1/feeds/ioc-summary?source=bitwire-inbound|bitwire.',
  },
  {
    id: 'ifconfig-co',
    name: 'ifconfig.co',
    url: 'https://ifconfig.co/',
    kind: 'tool',
    tags: ['osint'],
    description:
      'Minimal "what is my IP" service with JSON / plain-text / user-agent / port-aware endpoints. Useful as a sanity check during egress filtering tests, IP-reputation triage, and to confirm whether a VPN / proxy / Tor exit is in use.',
  },
  {
    id: 'gonzosint-fingerprinter',
    name: 'Gonzosint Fingerprinter',
    url: 'https://gonzosint.github.io/fingerprinter/',
    kind: 'tool',
    tags: ['osint'],
    description:
      'Comprehensive browser-fingerprint demo from Gonzosint. Loads ThumbmarkJS, ImprintJS and 8+ other fingerprinting libraries side-by-side so analysts can see what each library leaks: canvas hash, audio context, WebGL renderer, font enumeration, hardware concurrency, etc.',
    why: 'Side-by-side comparison of every major fingerprint library is unique - useful for /dfir/privacy-hub follow-up: see exactly what your own browser is leaking and which library would be the most effective adversary tool.',
  },
  {
    id: 'osintnewsletter-tools',
    name: 'OSINT Newsletter - OSINT Tools Library',
    url: 'https://tools.osintnewsletter.com/osint-tools',
    kind: 'directory',
    tags: ['osint'],
    description:
      'Curated GitBook catalog of OSINT tools maintained by the OSINT Newsletter community. Grouped by category (people search, geolocation, social, infra) with one-page summaries, screenshots, and quick links. A more editorial / human-curated alternative to the OSINT Framework.',
  },
  {
    id: 'urlscan',
    name: 'URLScan.io',
    url: 'https://urlscan.io/',
    kind: 'tool',
    featured: true,
    tags: ['osint', 'phishing', 'threat-intel'],
    description:
      'Free public URL sandbox - 100 scans/day without auth. Captures screenshot, rendered DOM, network requests, TLS chain, and verdicts for any submitted URL. Used by /api/v1/url-preview and as enrichment in /dfir/phishing.',
  },
  {
    id: 'greynoise',
    name: 'GreyNoise Community',
    url: 'https://www.greynoise.io/',
    kind: 'tool',
    tags: ['osint', 'threat-intel'],
    description:
      'Free community API classifies IPs as benign / malicious / unknown by tracking internet-wide scanner/mass-exploitation traffic. Tag-based filter lets analysts separate targeted from opportunistic noise. Strong complement to AbuseIPDB.',
  },
  {
    id: 'leakix',
    name: 'LeakIX',
    url: 'https://leakix.net/',
    kind: 'tool',
    tags: ['osint', 'vulnerability'],
    description:
      'Open search engine for exposed services and leaked credentials. Free public API. Used by /api/v1/breach/leakix to surface internet-exposed hosts with CVE / version context.',
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    url: 'https://www.abuseipdb.com/',
    kind: 'tool',
    tags: ['osint', 'threat-intel'],
    description:
      'Community IP-reputation database - 1000 free lookups/day. Confidence-scored abuse reports per IP. Used as enrichment in /api/v1/ioc-check.',
  },
  {
    id: 'shodan',
    name: 'Shodan',
    url: 'https://www.shodan.io/',
    kind: 'tool',
    tags: ['osint', 'vulnerability'],
    description:
      "Internet-wide device / service / banner search engine. Free tier exposes the most popular queries. Used in the platform's enrichment providers for service fingerprinting and CVE/CPE lookup.",
  },
  {
    id: 'apt-tracker',
    name: 'APT Tracker',
    url: 'https://onuroktay14.github.io/APTTracker/',
    kind: 'directory',
    tags: ['threat-intel', 'osint'],
    description:
      'Open-source APT groups and operations database - tracks 411 groups across 9 regions with aliases, attributed malware, known operations, and country-level mapping. CC BY 4.0 licensed, compiled from public threat intelligence sources.',
  },
  {
    id: 'vxdb',
    name: 'vxdb.sh',
    url: 'https://vxdb.sh/',
    kind: 'research',
    tags: ['threat-intel', 'osint'],
    description:
      'Threat intelligence and cybercrime news blog - deep-dive investigations into organized crime, crypto heists, infostealers, piracy takedowns, and underground markets. Ghost-powered, CC BY 4.0.',
  },
  {
    id: 'h3ad-sec',
    name: 'H3AD-SEC',
    url: 'https://h3ad-sec.github.io/',
    kind: 'tool',
    featured: true,
    tags: ['threat-intel', 'dfir', 'osint'],
    description:
      'Operational cyber defense platform with 20+ live tools across 7 domains: Threat Exchange (VERDIKT, X-VERDIKT, PARSE-X, DNSCOPE, MAILSCOPE), AI-powered runbooks (INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI, PROMPTVAULT, VERDIKT-AI), Detection Engineering (TRACERULES), Threat Hunting (HYPOS, PIVEX, TRACEPULSE), SOC Ops (QUICKTRACE, PHISHOPS, SHIFTLOG), Digital Forensics (REGSCOPE, MALBRIEF-AI), and IR (PHISHBOOK).',
    why: 'Comprehensive platform with tools across the full kill chain. Several tools are directly integrated into this platform (FPLENS, QUERYCRAFT, CHRONO, MALBRIEF, VERDIKT, PHISHOPS, PIVEX, TRACEPULSE, QUICKTRACE, PHISHBOOK).',
  },
  // ── External resource additions (2026-06-30) ─────────────────────────
  {
    id: 'mitre-shahrukh',
    name: 'MITRE ATT&CK (Shahrukh)',
    url: 'https://mitre.heyshahrukh.me/',
    kind: 'dashboard',
    tags: ['threat-intel', 'dfir'],
    description:
      'Interactive MITRE ATT&CK navigation dashboard - browse techniques, sub-techniques, and mitigations across all ATT&CK domains (Enterprise, Mobile, ICS) with a clean card-based UI. Useful for rapid technique lookup and kill-chain mapping during threat-intel analysis.',
  },
  {
    id: 'llm-pentest-hub',
    name: 'LLMPenTestHub - AI/ML Roadmap for Pentesters',
    url: 'https://anmolksachan.github.io/LLMPenTestHub/ai-ml-roadmap-for-pentester.html#phases',
    kind: 'training',
    tags: ['ai-security', 'vulnerability'],
    description:
      'Structured 7-phase roadmap for pentesters entering AI/ML security. Covers LLM fundamentals, prompt injection, jailbreaking, model extraction, poisoning, evasion, and AI red-teaming playbooks. Hands-on exercises with real-world attack scenarios and defense bypasses.',
  },
  {
    id: 'soc-chef',
    name: 'SOC Chef',
    url: 'https://github.com/mr-r3b00t/soc_chef',
    kind: 'tool',
    tags: ['dfir', 'threat-intel'],
    description:
      'Detection engineering and SOC automation cookbook by mr-r3b00t. Collection of Sigma rules, YARA signatures, Splunk / KQL searches, and incident-response runbooks. Practical recipes for detection engineers building out their SIEM content library.',
  },
  {
    id: 'cti-guide-2026',
    name: 'CTI 2026 - The Ultimate Guide',
    url: 'https://undercodetesting.com/cyber-threat-intelligence-2026-the-ultimate-guide-to-mastering-cti-ai-driven-defense-and-proactive-threat-hunting-video/',
    kind: 'training',
    tags: ['threat-intel', 'dfir', 'ai-security'],
    description:
      'Comprehensive 2026 guide to mastering Cyber Threat Intelligence - covers AI-driven defense, proactive threat hunting, CTI frameworks (Diamond Model, Kill Chain, ATT&CK), intelligence lifecycle, and practical tradecraft. Includes companion video walkthrough.',
  },
  {
    id: 'x-force-exchange',
    name: 'IBM X-Force Exchange (archive)',
    url: 'https://exchange.xforce.ibmcloud.com/',
    kind: 'research',
    tags: ['threat-intel'],
    description:
      'IBM threat-intel sharing platform (threat reports, collections). Reaching end-of-life in 2026 with paid-tier-only API — kept as a research archive reference, not a live feed. Migrate X-Force workflows to OTX / ThreatFox / Malpedia.',
  },
  {
    id: 'onion-tree',
    name: 'Onion Tree (archived directory)',
    url: 'https://oniontree.org/',
    kind: 'directory',
    tags: ['darkweb', 'osint'],
    description:
      'Verified onion-service directory, unmaintained since 2022. Kept as a historical reference only — use dark.fail for uptime/phishing verification, Ahmia for hidden-service search, and OnionWatch for live monitoring.',
  },
  {
    id: 'yeti-platform',
    name: 'Yeti Threat Intel Platform (self-hosted)',
    url: 'https://yeti-platform.io/',
    kind: 'tool',
    tags: ['threat-intel', 'dfir'],
    description:
      'Lightweight self-hosted TIP for IoC/TTP storage (Yeti). No SaaS API to integrate — run your own instance alongside MISP/OpenCTI; export via its API into StixBuilder for correlation here.',
  },
  // ── Evaluated 2026-09-30, reference-only. See each `why` for the blocker. ──
  {
    id: 'ai-security-playbook',
    name: 'The AI Security Playbook',
    url: 'https://aisecurity.zone/',
    kind: 'research',
    tags: ['ai-security', 'threat-intel'],
    featured: true,
    description:
      'A 44-chapter practitioner field manual on attacking and defending AI systems (~91k words, one author, Iaroslav Mezin). Organised in eight layers — model, context window, agent loop, protocol/MCP, infrastructure, assessment, security program, governance — with a risk-ID scheme (LLM01, ASI06) and 49 mapped CVEs. Pairs well with the CAIRN/NOVA/Denali rule verticals, which cover detection mechanics rather than the narrative and governance layer.',
    why: 'Robots.txt allows crawling ("AI crawlers welcome") but the site carries no reuse licence: /terms/ and /license/ both 404, no LICENSE file, and the repository named in its CONTRIBUTING page (github.com/anguiz7z/aisecurity-zone) returns 404. All rights reserved by default, so the prose cannot be replicated. Link and read it; if the author publishes a CC-BY-SA licence this becomes replicable immediately.',
  },
  {
    id: 'darknyx',
    name: 'DarkNyx — dark web search & threat intel',
    url: 'https://darknyx.com/',
    kind: 'directory',
    tags: ['darkweb', 'osint', 'threat-intel'],
    description:
      'Onion search engine with a safety-rated directory (Verified / Unrated / Suspicious / Dangerous), ransomware-activity and Telegram monitoring, marketplace trends, and free checkers for fake shops, scam messages, phishing mail and crypto sanctions addresses. Operated by NexVision Lab.',
    why: 'No public API — API access sits behind a paid Pro tier, and the free crawl is Tor-only, which Workers cannot reach (the same constraint that makes OnionWatch reachability probes unavailable here). Its directory and ransomware-victim content would also duplicate the darknetlist and breach-watch verticals already running. robots.txt additionally disallows /previews/ and /api/preview/.',
  },
  {
    id: 'vulnsocial',
    name: 'VulnSocial — attention-driven CVE intelligence',
    url: 'https://vulnsocial.com/',
    kind: 'dashboard',
    tags: ['vulnerability', 'threat-intel'],
    description:
      'Ranks CVEs by attention and momentum rather than CVSS — mention volume and trend across researchers, advisories, exploit references and community discussion, with vendor/product (CPE) scoping and exploitation / PoC / patch indicators.',
    why: 'Redundant with the CISA KEV + NVD pipeline already synced into public/data/threat-intel. Its headline ranked CVEs (e.g. CVE-2026-87902, CVE-2025-39682, CVE-2026-85046, CVE-2026-88771, CVE-2026-85706) are all already present in the local KEV feed, and the underlying data is "AI-classified social media analysis" of the same advisory sources. Its robots.txt also carries explicit content-signal licensing conditions.',
  },
  {
    id: 'marginalia-search',
    name: 'Marginalia Search',
    url: 'https://marginalia-search.com/',
    kind: 'tool',
    tags: ['osint'],
    description:
      'Independent search engine prioritising non-commercial and long-tail web content — useful for finding overlooked blogs, personal research pages and legacy sites that commercial engines bury. Open source (AGPL), no AI in the ranking, and its crawler and index software are public.',
    why: 'robots.txt disallows /search, /explore, /site, /links and /wiki — effectively the whole product surface — and there is no public API without a key, so there is no compliant way to replicate results. Worth using manually for OSINT; not integrable here.',
  },
  {
    id: 'lupovis-insights',
    name: 'Lupovis Insights',
    url: 'https://insights.lupovis.io/',
    kind: 'dashboard',
    tags: ['threat-intel'],
    description:
      'Threat-intelligence and cyber-risk monitoring dashboard (client-side SPA, purple-branded) surfaced during a source-evaluation sweep on 2026-09-30.',
    why: 'No reachable data surface: the app is a JavaScript SPA whose page body renders empty without a browser, it returns an HTML page rather than a robots.txt at /robots.txt (so no published crawl policy), and no API or licence is advertised. Nothing can be replicated or verified programmatically.',
  },
  {
    id: 'webwiebe-invisible-prompt',
    name: 'WebWiebe — Invisible Prompt Injection (tag characters)',
    url: 'https://webwiebe.nl/en/tools/invisible-prompt',
    kind: 'lab',
    tags: ['ai-security', 'evasion', 'offensive'],
    description:
      'Demonstrates the Unicode tag-character vector: mapping each ASCII character to U+E0000+codePoint produces text that renders blank to a human but decodes back to the original instruction for any model or tokenizer reading it. Survives copy-paste through most editors, terminals and chat clients.',
    why: 'Not replicated as data — the technique is a published Unicode mechanism, so it is implemented locally instead. See src/lib/invisible-prompt.ts: decode/strip/scan for the U+E0000 block, zero-width characters and bidi overrides, with detection wired into the Web Server Log Analyzer. Use the live tool to confirm behaviour; use ours to defend.',
  },
];
