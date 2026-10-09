/**
 * Canonical registry of every page in the threat-intel area.
 *
 * Pages are grouped by category ("hub"). Each page has its own direct
 * URL (/threatintel/<hub-id>/<tab-id>) which renders the page
 * component directly - no hub wrapper, no tab bar, no /threatintel/<hub>
 * landing page in between.
 *
 * The /threatintel/catalog page is the single navigation surface for
 * browsing a category. It accepts ?cat=<hub-id> to pre-filter to a
 * single category. The sidebar lists direct page URLs grouped by
 * hub for at-a-glance scanning.
 *
 * Why this exists:
 *   The original design used a tab-bar pattern where /threatintel/<hub>
 *   was a single page that switched between sub-pages via query params
 *   (e.g. ?tab=directory) or path params (e.g. /<hub>/<tab>). The tabs
 *   were real React components but not real URLs - the user couldn't
 *   bookmark them, share them, or use Cmd+K to jump to them.
 *
 *   This file is the single source of truth that drives:
 *     - App.tsx route registration
 *     - Sidebar nav (auto-generated from HUB_META)
 *     - Catalog page (groups + search)
 *     - Prerender manifest (scripts/prerender.mjs)
 *     - Sitemap (public/sitemap.xml)
 *
 *   When you add a new page:
 *     1. Create the .tsx component.
 *     2. Add a HubPage entry to the right hub's `pages` array.
 *     3. Add the route to App.tsx.
 *     4. (Optional) add a redirect for any legacy alias.
 */

import {
  AlertTriangle,
  Bell,
  Brain,
  Bug,
  Cloud,
  ExternalLink,
  FileText,
  GitBranch,
  Globe,
  LineChart,
  type LucideIcon,
  Radio,
  Rss,
  Search,
  Shield,
  ShieldAlert,
  Target,
  Users,
  Wrench,
} from 'lucide-react';

export type HubPageBadge = 'live' | 'new' | 'beta';

export interface HubPage {
  /** Direct URL the page is reachable at. */
  path: string;
  /** The tab id used in the legacy hub-tab URL pattern. */
  tabId: string;
  /** Display label for the tile and sidebar. */
  label: string;
  /** One-line description. */
  desc: string;
  /** Lazily-loaded component variable name (from App.tsx). */
  compVar: string;
  /** Optional live/new badge. */
  badge?: HubPageBadge;
  /** Extra search keywords. */
  keywords?: readonly string[];
  /** Optional per-page icon. Falls back to hub icon when absent. */
  icon?: LucideIcon;
}

export interface HubMeta {
  /** Unique id for the hub. Used in URLs (/threatintel/<id>). */
  id: string;
  /** Display label. */
  label: string;
  /** One-line description for the hub landing page. */
  blurb: string;
  /** Lucide icon name. */
  icon: LucideIcon;
  /** Tailwind tone classes. */
  tone: string;
  /** All pages that belong to this hub. */
  pages: readonly HubPage[];
}

/* ------------------------------------------------------------------ */
/*  Hub definitions                                                   */
/* ------------------------------------------------------------------ */

export const HUB_META: readonly HubMeta[] = [
  {
    id: 'actors',
    label: 'Actors & Threat Groups',
    blurb: 'Threat-actor profiles, attribution, DNA, timelines, and APT tracking.',
    icon: Users,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10',
    pages: [
      {
        path: '/threatintel/actors/hub',
        tabId: 'actor-hub',
        label: 'Actor Hub',
        desc: 'Threat actor intelligence - directory, timelines, DNA, usernames, profiles, and relationship graphs.',
        compVar: 'ActorHub',
        keywords: [
          'actor',
          'directory',
          'timeline',
          'dna',
          'usernames',
          'profiles',
          'graph',
          'apt',
          'mitre',
          'catalog',
          'knowledge base',
        ],
      },
    ],
  },
  {
    id: 'campaigns',
    label: 'Campaigns & Briefings',
    blurb: 'Active and historical campaigns, attribution, briefings, and assessments.',
    icon: GitBranch,
    tone: 'text-orange-700 dark:text-orange-300 border-orange-500/30 bg-orange-500/10',
    pages: [
      {
        path: '/threatintel/campaigns/cross',
        tabId: 'cross',
        label: 'Cross-Campaign',
        desc: 'Find connections across campaigns, actors, and IOCs.',
        compVar: 'CrossCampaignCorrelation',
      },
      {
        path: '/threatintel/campaigns/reference',
        tabId: 'reference',
        label: 'Campaign Reference',
        desc: 'Curated tracker of active/dormant/concluded campaigns with writeup links and TTPs.',
        compVar: 'CampaignsReference',
        badge: 'new',
      },
      {
        path: '/threatintel/briefings',
        tabId: 'briefings',
        label: 'Daily & Weekly Briefings',
        desc: 'Tactical digests with IOCs, severity, and detection guidance.',
        compVar: 'Briefings',
      },
    ],
  },
  {
    id: 'iocs',
    label: 'IOCs & Threat Intel',
    blurb: 'Live indicator streams, enrichment, C2 tracking, and supply-chain intel.',
    icon: Target,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    pages: [
      {
        path: '/threatintel/iocs/live',
        tabId: 'live',
        label: 'Live IOC Stream',
        desc: 'Real-time IOC feed from 12+ providers - IP, domain, hash, URL.',
        compVar: 'LiveIocs',
        badge: 'live',
      },
      {
        path: '/threatintel/iocs/enrichment',
        tabId: 'enrichment',
        label: 'IOC Enrichment',
        desc: 'Pivot and enrich any indicator across VT, AbuseIPDB, Shodan, OTX.',
        compVar: 'IocEnrichment',
      },
      {
        path: '/threatintel/iocs/feeds',
        tabId: 'feeds',
        label: 'IOC Feeds',
        desc: 'Structured indicator feeds ready for SIEM, EDR, or CTI ingestion.',
        compVar: 'IocFeedsPage',
      },
      {
        path: '/threatintel/iocs/entity',
        tabId: 'entity',
        label: 'Entity Resolution',
        desc: 'Resolve entities across intel sources - actor, malware, campaign.',
        compVar: 'EntityResolution',
      },
      {
        path: '/threatintel/iocs/c2',
        tabId: 'c2',
        label: 'C2 Tracker',
        desc: 'Live C2 infrastructure tracker - Cobalt Strike, Sliver, Mythic, 30+ families.',
        compVar: 'C2Tracker',
        badge: 'live',
      },
      {
        path: '/threatintel/iocs/map',
        tabId: 'map',
        label: 'Threat Map',
        desc: 'Geo-visualization of IOCs by country and ASN.',
        compVar: 'ThreatMap',
      },
      {
        path: '/threatintel/iocs/correlation',
        tabId: 'correlation',
        label: 'IOC Correlation',
        desc: 'IOC correlation analysis with timeline.',
        compVar: 'IocCorrelation',
      },
    ],
  },
  {
    id: 'cves',
    label: 'CVEs & Vulnerabilities',
    blurb: 'CVE intel, KEV catalog, GitHub advisories, and exploit tracking.',
    icon: AlertTriangle,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10',
    pages: [
      {
        path: '/threatintel/cves/cves',
        tabId: 'cves',
        label: 'CVE Intel',
        desc: 'Unified CVE intelligence - NVD + KEV + EPSS + exploit availability.',
        compVar: 'CveIntel',
      },
      {
        path: '/threatintel/cves/advisories',
        tabId: 'advisories',
        label: 'GitHub Advisories',
        desc: 'GitHub security advisories with affected versions and patches.',
        compVar: 'GithubAdvisories',
      },
      {
        path: '/threatintel/cves/resources',
        tabId: 'resources',
        label: 'CVE Resources',
        desc: 'CVE resource catalogs - patch priority, exploit DB, vendor bulletins.',
        compVar: 'CveResourcesCatalog',
      },
    ],
  },
  {
    id: 'malware',
    label: 'Malware & Samples',
    blurb: 'Malware IOCs, sandbox, sample vault, malicious packages, and family encyclopedia.',
    icon: Bug,
    tone: 'text-emerald-700 dark:text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
    pages: [
      {
        path: '/threatintel/malware/iocs',
        tabId: 'iocs',
        label: 'Malware IOCs',
        desc: 'Malware IOC feeds across 50+ families.',
        compVar: 'MalwareIocs',
      },
      {
        path: '/threatintel/malware/sandbox',
        tabId: 'sandbox',
        label: 'Malware Sandbox',
        desc: 'Hash lookup across 10+ sandbox platforms - consensus verdict.',
        compVar: 'MalwareSandbox',
        badge: 'new',
      },
      {
        path: '/threatintel/supply-chain',
        tabId: 'supply-chain',
        label: 'Supply-Chain Incidents',
        desc: 'Confirmed supply-chain compromise incidents - npm · PyPI · containers · AI agents. Data: supplychainattack.org.',
        compVar: 'SupplyChainHub',
      },

      {
        path: '/threatintel/malware/malpedia',
        tabId: 'malpedia',
        label: 'Malpedia',
        desc: 'Malpedia malware encyclopedia - families, YARA, references.',
        compVar: 'MalpediaPage',
      },
      {
        path: '/threatintel/malware/maltrail',
        tabId: 'maltrail',
        label: 'Maltrail Trails',
        desc: 'Maltrail detection trails for known malware.',
        compVar: 'MaltrailTrails',
      },
    ],
  },
  {
    id: 'feeds',
    label: 'Feeds & Sources',
    blurb: 'Feed catalog, sources, quality, scheduler, and reliability tracking.',
    icon: Rss,
    tone: 'text-sky-700 dark:text-sky-300 border-sky-500/30 bg-sky-500/10',
    pages: [
      {
        path: '/threatintel/feeds/catalog',
        tabId: 'catalog',
        label: 'Feed Catalog',
        desc: 'Feed file browser with format and sample preview.',
        compVar: 'FeedCatalog',
      },
      {
        path: '/threatintel/feeds/sources',
        tabId: 'sources',
        label: 'Feed Sources',
        desc: 'Feed source registry with enabled/disabled state.',
        compVar: 'FeedSources',
      },
      {
        path: '/threatintel/feeds/quality',
        tabId: 'quality',
        label: 'Feed Quality',
        desc: 'Feed quality metrics - freshness, accuracy, FP rate.',
        compVar: 'FeedQuality',
      },
      {
        path: '/threatintel/feeds/scheduler',
        tabId: 'scheduler',
        label: 'Feed Scheduler',
        desc: 'Feed scheduling and orchestration - cron, retry, backoff.',
        compVar: 'FeedScheduler',
      },
      {
        path: '/threatintel/feeds/threatfeeds',
        tabId: 'threatfeeds',
        label: 'Threat Feeds',
        desc: 'Curated threat intelligence feeds from 50+ providers.',
        compVar: 'ThreatFeeds',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/mythreatintel',
        tabId: 'mythreatintel',
        label: 'My Threat Intel',
        desc: 'My curated threat-intel feed - personal bookmarks and follows.',
        compVar: 'MyThreatIntel',
      },
      {
        path: '/threatintel/source-health',
        tabId: 'grades',
        label: 'Feed Reliability',
        desc: 'Reliability scoring for each feed provider - uptime, freshness, accuracy, and NATO Admiralty trust grades.',
        compVar: 'FeedReliability',
      },
      {
        path: '/threatintel/feeds/threatcluster',
        tabId: 'threatcluster',
        label: 'ThreatCluster Feeds',
        desc: 'Replicated ThreatCluster feeds - trending clusters, CVEs, exploits, dark-web victims, IOC blocklist, MISP events.',
        compVar: 'ThreatClusterFeeds',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/threatcluster/entities',
        tabId: 'tc-entities',
        label: 'Entity Intelligence',
        desc: 'ThreatCluster-derived entity profiles - actors, ransomware groups, malware, CVEs, and sectors with frequency charts and a weighted co-occurrence relationship graph.',
        compVar: 'ThreatClusterEntities',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/threaticon',
        tabId: 'threaticon',
        label: 'Threaticon',
        desc: 'Replicated threaticon.com STIX 2.1 catalog - threat-actor profiles, malware family dictionary, ATT&CK detection coverage, and a country-level threat map.',
        compVar: 'ThreaticonFeeds',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/dphish',
        tabId: 'dphish',
        label: 'dPhish Phishing Feed',
        desc: 'Public dPhish TAXII 2.1 phishing indicator feed - malicious domains, phishing URLs, sender IPs, phone numbers, and attachment rules with active/revoked status.',
        compVar: 'DphishFeeds',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/destroylist',
        tabId: 'destroylist',
        label: 'Destroylist Blacklist',
        desc: 'Phishing & scam domain blacklist (MIT) - curated primary feed with local membership checks, root-domain search, and Pi-hole/AdGuard-ready roots.txt.',
        compVar: 'DestroylistFeeds',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/living-threat',
        tabId: 'living-threat',
        label: 'Living Threat Repository',
        desc: 'Real-world incidents continuously mapped to MITRE ATT&CK tactic/technique chains - per-kill-chain-stage detection + remediation notes, CVEs, actors, and hunting guidance.',
        compVar: 'LivingThreatFeeds',
        badge: 'live',
      },
      {
        path: '/threatintel/feeds/malwareanalyzer',
        tabId: 'malwareanalyzer',
        label: 'MalwareAnalyzer by Cyble',
        desc: 'Free keyless multi-engine malware analysis - live malicious / newly-observed URL feeds plus on-demand IOC reputation lookups.',
        compVar: 'MalwareAnalyzerFeeds',
        badge: 'live',
      },
    ],
  },
  {
    id: 'social',
    label: 'Social & Live Feeds',
    blurb: 'Telegram, X/Bluesky, Reddit, and crypto-scam streams.',
    icon: Radio,
    tone: 'text-violet-700 dark:text-violet-300 border-violet-500/30 bg-violet-500/10',
    pages: [
      {
        path: '/threatintel/social/firehose',
        tabId: 'firehose',
        label: 'Social Firehose',
        desc: 'Multi-platform social media firehose.',
        compVar: 'SocialFirehose',
        badge: 'live',
      },
      {
        path: '/threatintel/social/news',
        tabId: 'news',
        label: 'Tech & AI News',
        desc: 'Tech and AI news aggregation.',
        compVar: 'TechAiNews',
      },
      {
        path: '/threatintel/social/crypto-scam',
        tabId: 'crypto-scam',
        label: 'Crypto Scam Feed',
        desc: 'Crypto scam feed - wallet addresses, drainers, phishing sites.',
        compVar: 'CryptoScamFeed',
        badge: 'live',
      },
      {
        path: '/threatintel/telegram',
        tabId: 'telegram-hub',
        label: 'Telegram Intelligence Hub',
        desc: 'Unified Telegram CTI workspace - free cross-source search, KPIs, and entry points to all Telegram surfaces (leak monitor, IOC pipeline, channel discovery, settings).',
        compVar: 'TelegramHub',
        badge: 'new',
      },
    ],
  },
  {
    id: 'darkweb',
    label: 'Dark Web & Cybercrime',
    blurb: 'Dark-web monitoring, ransomware activity, breach forums, and infostealer logs.',
    icon: Globe,
    tone: 'text-slate-700 dark:text-slate-300 border-slate-500/30 bg-slate-500/10',
    pages: [
      {
        path: '/threatintel/darkweb/watch',
        tabId: 'watch',
        label: 'Dark Web Watch',
        desc: 'Dark-web monitoring dashboard.',
        compVar: 'DarkWeb',
      },
      {
        path: '/threatintel/darkweb/markets',
        tabId: 'markets',
        label: 'Darknet Markets Timeline',
        desc: 'Darknet market timelines - Empire, Genesis, Hydra successors.',
        compVar: 'DarknetMarketsTimeline',
      },
      {
        path: '/threatintel/darkweb/darknetlist',
        tabId: 'darknetlist',
        label: 'Darknet Directory',
        desc: 'Live Tor site directory from darknetlist.is - 108 sites across 9 categories with up/down status and onion URLs.',
        compVar: 'DarknetList',
      },
      {
        path: '/threatintel/breach-hub?tab=forums',
        tabId: 'forums',
        label: 'Breach Forums',
        desc: 'Breach forum tracker - posts, threads, user activity.',
        compVar: 'BreachForums',
      },
      {
        path: '/threatintel/darkweb/deepdark',
        tabId: 'deepdark',
        label: 'DeepDarkCTI',
        desc: 'DeepDark CTI sources - vetted onion feeds.',
        compVar: 'DeepDarkCTI',
      },
      {
        path: '/threatintel/darkweb/crime',
        tabId: 'crime',
        label: 'Cybercrime',
        desc: 'Cybercrime ecosystem intelligence - actors, services, pricing.',
        compVar: 'CyberCrime',
      },
      {
        path: '/threatintel/darkweb/infostealer',
        tabId: 'infostealer',
        label: 'Infostealer Logs',
        desc: 'Infostealer log analysis - credentials, cookies, system fingerprints.',
        compVar: 'Infostealer',
        badge: 'live',
      },
      {
        path: '/threatintel/darkweb/leaks',
        tabId: 'leaks',
        label: 'Secret Leaks',
        desc: 'Secret and credential leak monitoring across paste sites.',
        compVar: 'SecretLeaks',
        badge: 'live',
      },
      {
        path: '/threatintel/breach-hub?tab=disclosures',
        tabId: 'disclosures',
        label: 'Breach Disclosures',
        desc: 'Breach disclosure feed - official statements and regulatory filings.',
        compVar: 'BreachDisclosures',
      },
      {
        path: '/threatintel/breach-hub?tab=watch',
        tabId: 'breach-watch',
        label: 'Breach Watch',
        desc: 'Aggregated breach and leak corpus from 6 public trackers - ransomware leaks, data breaches, combo lists.',
        compVar: 'BreachWatch',
        badge: 'new',
      },
      {
        path: '/threatintel/ransomware-hub',
        tabId: 'ransomware-hub',
        label: 'Ransomware Hub',
        desc: 'Ransomware tracking - activity feed, map, ransomwhere, and negotiation reports.',
        compVar: 'RansomwareHub',
        keywords: ['ransomware', 'activity', 'map', 'ransomwhere', 'report'],
      },
      {
        path: '/threatintel/exposure',
        tabId: 'exposure',
        label: 'Exposure Check',
        desc: 'One search across ransomware victims, sender blocklist, and phishing blacklists.',
        compVar: 'ExposureCheck',
        badge: 'new',
        keywords: ['exposure', 'domain', 'ransomware', 'blocklist', 'search'],
      },
      {
        path: '/threatintel/ransomware-groups',
        tabId: 'ransomware-groups',
        label: 'Ransomware Groups',
        desc: 'Directory of every tracked ransomware leak site - status, recent victims, and profiles (620 groups).',
        compVar: 'RansomwareGroups',
        badge: 'new',
        keywords: ['ransomware', 'groups', 'leak site', 'directory', 'status', 'profile'],
      },

      {
        path: '/threatintel/darkweb/recon',
        tabId: 'recon',
        label: 'Dark Web Recon',
        desc: 'Search .onion sites, look up hidden service metadata, check BTC addresses for abuse, and scan Tor exit nodes.',
        keywords: [
          'tor',
          'onion',
          'ahmia',
          'dark web search',
          'bitcoin',
          'btc abuse',
          'exit node',
        ] as readonly string[],
        compVar: 'DarkWebRecon',
      },
      {
        path: '/threatintel/darkweb/playbook',
        tabId: 'playbook',
        label: 'Research Playbook',
        desc: 'Dark-web research methodology - the AI pipeline, operational realities, OPSEC protocol, and investigator workflow.',
        keywords: [
          'robin',
          'networkchuck',
          'methodology',
          'opsec',
          'safety',
          'tor',
          'onion',
          'pipeline',
          'sock puppet',
        ] as readonly string[],
        badge: 'new',
        compVar: 'DarkWebPlaybook',
      },

      {
        path: '/threatintel/onion-watch',
        tabId: 'onion-watch',
        label: 'Onion Watch',
        desc: 'Dark web .onion service monitoring - uptime, content changes, and new service discovery.',
        compVar: 'OnionWatch',
      },
    ],
  },
  {
    id: 'phishing',
    label: 'Phishing & Email Defense',
    blurb: 'Phish feed, wordlists, scam watch, and email-defense analysis.',
    icon: ShieldAlert,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10',
    pages: [
      {
        path: '/threatintel/phishing/phish',
        tabId: 'phish',
        label: 'Phish Feed',
        desc: 'Phishing feed aggregation - fresh URLs and lure analysis.',
        compVar: 'PhishFeed',
        badge: 'live',
      },
      {
        path: '/threatintel/phishing/urls',
        tabId: 'urls',
        label: 'Phishing Wordlists',
        desc: 'Phishing hunting wordlists - brand, gift-card, sextortion, BEC.',
        compVar: 'PhishingWordlists',
      },
      {
        path: '/threatintel/phishing/scam',
        tabId: 'scam',
        label: 'Scam Watch',
        desc: 'Scam watch and monitoring - pig-butchering, romance, investment.',
        compVar: 'ScamWatch',
      },
    ],
  },
  {
    id: 'infra',
    label: 'Infrastructure & Cloud',
    blurb: 'Cloud threat landscape, infrastructure intel, web assets, and domain monitoring.',
    icon: Cloud,
    tone: 'text-sky-700 dark:text-sky-300 border-cyan-500/30 bg-cyan-500/10',
    pages: [
      {
        path: '/threatintel/infra/cloud',
        tabId: 'cloud',
        label: 'Cloud Threat Landscape',
        desc: 'Cloud threat landscape - AWS, Azure, GCP, Kubernetes, SaaS.',
        compVar: 'CloudThreatLandscape',
      },
      {
        path: '/threatintel/infra/infra',
        tabId: 'infra',
        label: 'Infrastructure Intel',
        desc: 'Infrastructure intelligence - ASN, IP, certificate, hosting pivots.',
        compVar: 'InfraIntel',
      },
      {
        path: '/threatintel/infra/webamon',
        tabId: 'webamon',
        label: 'Webamon',
        desc: 'Web asset monitoring - external footprint, exposed services, drift detection.',
        compVar: 'Webamon',
      },
      {
        path: '/threatintel/webamon-dtb',
        tabId: 'webamon-dtb',
        label: 'Webamon Daily Threat Brief',
        desc: 'Daily campaign intelligence - phishing/malware estate tracking, domain growth, takedowns, infra rotation, emerging clusters.',
        compVar: 'WebamonDtb',
        badge: 'new',
        keywords: ['webamon', 'dtb', 'phishing', 'campaign', 'takedown', 'daily brief'],
      },
      {
        path: '/threatintel/pcmedicalist',
        tabId: 'pcmedicalist',
        label: 'PCMedicalist Feed',
        desc: 'Daily security-intel digest from the PCMedicalist Intelligence Network - 38+ feeds deduplicated into an 11-layer taxonomy with trust scoring and CVE tracking.',
        compVar: 'PcMedicalist',
        badge: 'new',
        keywords: ['pcmedicalist', 'digest', 'cve', 'kev', 'ai security', 'vulnerability intel', 'daily brief'],
      },
      {
        path: '/threatintel/infra/domain',
        tabId: 'domain',
        label: 'Domain Monitor',
        desc: 'Domain monitoring - typosquats, lookalikes, certificate transparency.',
        compVar: 'DomainMonitor',
      },
      {
        path: '/threatintel/infra/ai-honeypot',
        tabId: 'ai-honeypot',
        label: 'AI Honeypot Observatory',
        desc: 'LLM/AI endpoint honeypot intelligence - attacker categories, top IPs, and attack volume from ai-honeypots.com.',
        compVar: 'AiHoneypotObservatory',
      },
      {
        path: '/threatintel/infra/ai-llm-intel',
        tabId: 'ai-llm-intel',
        label: 'AI/LLM Threat Intel',
        desc: 'Campaigns, ATT&CK techniques, trends, and analyst write-ups on LLM-specific abuse.',
        compVar: 'AiLlmIntel',
      },
    ],
  },
  {
    id: 'detections',
    label: 'Detection & Response',
    blurb: 'Detection rules, ATT&CK mapping, YARA, and threat signal feeds.',
    icon: Shield,
    tone: 'text-indigo-700 dark:text-indigo-300 border-indigo-500/30 bg-indigo-500/10',
    pages: [
      {
        path: '/threatintel/detection-wiki',
        tabId: 'detection-wiki',
        label: 'Detection Wiki',
        desc: 'Mirrored detection.wiki — 15,957 Sigma/Elastic/Splunk/Kusto/YARA-L/Panther/Sublime rules mapped to 218 ATT&CK techniques, 1,518 Windows providers (103k events), 426 Security-Auditing events, 17 platforms, 6 labs.',
        compVar: 'DetectionWiki',
        keywords: [
          'detection.wiki',
          'sigma',
          'elastic',
          'splunk',
          'kusto',
          'yara-l',
          'panther',
          'sublime',
          'att&ck',
          'windows',
          'security-auditing',
          'platforms',
          'labs',
          'rules',
        ],
        badge: 'new',
      },
      {
        path: '/threatintel/detections/detections',
        tabId: 'detections',
        label: 'Detection Rules',
        desc: 'Detection rule catalog - Sigma, YARA, Suricata, KQL.',
        compVar: 'Detections',
      },
      {
        path: '/threatintel/detections/disarm',
        tabId: 'disarm',
        label: 'DISARM Framework',
        desc: 'DISARM red-team framework mapping.',
        compVar: 'DisarmFramework',
      },
      {
        path: '/threatintel/detections/yara',
        tabId: 'yara',
        label: 'YARA Hub',
        desc: 'YARA rule hub - community and curated rules.',
        compVar: 'YaraPage',
      },
      {
        path: '/threatintel/detections/signal',
        tabId: 'signal',
        label: 'Threat Signal RSS',
        desc: 'Threat-signal RSS feed with auto-classified indicators.',
        compVar: 'ThreatSignalRss',
      },
      {
        path: '/threatintel/cairn',
        tabId: 'cairn',
        label: 'CAIRN AI-Malware Rules',
        desc: 'Cisco-Talos cognitive artifact intel (MIT) — 26 tiered YARA rules (T1/T2/T3) spotting AI artifacts in malware, 10 family reports, A0–A11 archetypes, edge scanner.',
        compVar: 'Cairn',
        keywords: ['cairn', 'cisco', 'talos', 'ai malware', 'yara', 'llm', 'promptlock', 'family', 'archetype'],
        badge: 'new',
      },
      {
        path: '/threatintel/nova',
        tabId: 'nova',
        label: 'NOVA Prompt Hunting',
        desc: 'Prompt pattern matching (MIT) — 69 .nov rules hunting jailbreaks, injections, and exfiltration prompts with an edge keyword scanner and 4-category taxonomy.',
        compVar: 'Nova',
        keywords: ['nova', 'prompt', 'jailbreak', 'injection', 'prompt hunting', 'llm security'],
        badge: 'new',
      },
      {
        path: '/threatintel/ai-playbook',
        tabId: 'ai-playbook',
        label: 'AI Security Playbook',
        desc: 'Taxonomy layer from aisecurity.zone — 8 system divisions, 20 risk identifiers (OWASP LLM01-10 + ASI01-10), cited CVEs joined to KEV. Structure only; deep-links to the original.',
        compVar: 'AiSecurityPlaybook',
        keywords: ['ai security', 'playbook', 'taxonomy', 'owasp llm', 'agentic', 'risk id'],
        badge: 'new',
      },
      {
        path: '/threatintel/denali',
        tabId: 'denali',
        label: 'Denali AI Security',
        desc: 'Evidence-led AI security reference (Apache-2.0) — 9 deterministic rules, 16-kind asset taxonomy, 38 ADRs, plus stateless runtime-activity checks.',
        compVar: 'Denali',
        keywords: ['denali', 'ai security', 'evidence', 'adr', 'coverage', 'runtime detection'],
        badge: 'new',
      },
    ],
  },
  {
    id: 'research-hub',
    label: 'Research & Reports',
    blurb: 'Research posts, intelligence reports, write-ups, and external research.',
    icon: FileText,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    pages: [
      {
        path: '/threatintel/research-hub/reports',
        tabId: 'reports',
        label: 'Threat Intel Reports',
        desc: 'Original research reports with IOCs, detections, severity scoring.',
        compVar: 'Reports',
      },
      {
        path: '/threatintel/research-hub/ai',
        tabId: 'ai',
        label: 'AI Reports',
        desc: 'AI-generated research reports from LLM analysis.',
        compVar: 'AIReportShowcase',
        badge: 'new',
      },
      {
        path: '/threatintel/research-hub/writeups',
        tabId: 'writeups',
        label: 'Write-ups',
        desc: 'Security write-ups and post-mortems.',
        compVar: 'Writeups',
      },
      {
        path: '/threatintel/research-hub/signal',
        tabId: 'signal',
        label: 'Research Signal',
        desc: 'Research-signal feed - what changed since last visit.',
        compVar: 'ResearchSignal',
      },
      {
        path: '/threatintel/research-hub/redhunt',
        tabId: 'redhunt',
        label: 'RedHunt Insights',
        desc: 'RedHunt Labs threat-intel insights.',
        compVar: 'RedHuntInsights',
      },
      {
        path: '/threatintel/research-hub/volexity',
        tabId: 'volexity',
        label: 'Volexity Threat Intel',
        desc: 'Volexity threat-intelligence posts.',
        compVar: 'VolexityThreatIntel',
      },
      {
        path: '/threatintel/research-hub/post',
        tabId: 'post',
        label: 'Research Post',
        desc: 'Individual research post (template page).',
        compVar: 'ResearchPost',
      },
      {
        path: '/threatintel/research-hub/attack-flow',
        tabId: 'attack-flow',
        label: 'Attack Flow Library',
        desc: 'ATT&CK attack-flow library with reusable patterns.',
        compVar: 'AttackFlowLibrary',
      },
      {
        path: '/threatintel/flowviz',
        tabId: 'flowviz',
        label: 'FlowViz',
        desc: 'AI attack-flow visualizer: report URL/text → ATT&CK graph with PNG/STIX/.afb export.',
        compVar: 'FlowViz',
      },

      {
        path: '/threatintel/research-hub/knowledge',
        tabId: 'knowledge',
        label: 'Knowledge Graph',
        desc: 'Knowledge graph of actors, malware, campaigns, IOCs.',
        compVar: 'KnowledgeGraph',
      },
      {
        path: '/threatintel/research-hub/ach',
        tabId: 'ach',
        label: 'ACH',
        desc: 'Analysis of Competing Hypotheses.',
        compVar: 'ACH',
      },
      {
        path: '/threatintel/research-hub/agentic',
        tabId: 'agentic',
        label: 'Agentic Research',
        desc: 'AI agent-driven research generation - automated threat intelligence briefs and analysis.',
        compVar: 'AgenticResearch',
      },
      {
        path: '/threatintel/research-hub/redhunt-labs',
        tabId: 'redhunt-labs',
        label: 'RedHunt Labs Research',
        desc: 'RedHunt Labs research publications - vulnerability disclosures, threat reports, and tool releases.',
        compVar: 'RedhuntLabs',
      },
    ],
  },
  {
    id: 'wiki',
    label: 'Knowledge & Frameworks',
    blurb: 'Wiki, MITRE ATT&CK, F3EAD, insider threat, OWASP AI, and LLM atlas.',
    icon: Brain,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10',
    pages: [
      {
        path: '/threatintel/wiki/wiki',
        tabId: 'wiki',
        label: 'Threat Intel Wiki',
        desc: 'Long-form articles on Telegram OSINT, dark-web monitoring.',
        compVar: 'Wiki',
      },
      {
        path: '/threatintel/wiki/mitre',
        tabId: 'mitre',
        label: 'MITRE ATT&CK',
        desc: 'MITRE ATT&CK matrix with technique pivots.',
        compVar: 'MitreMatrix',
      },
      {
        path: '/threatintel/wiki/f3ead',
        tabId: 'f3ead',
        label: 'F3EAD',
        desc: 'F3EAD intelligence workflow framework.',
        compVar: 'F3ead',
      },
      {
        path: '/threatintel/wiki/threat-led-defence',
        tabId: 'threat-led-defence',
        label: 'Threat Led Defence',
        desc: 'BS5055 cyber resilience standard: understand threats, design controls, validate controls.',
        compVar: 'ThreatLedDefence',
      },
      {
        path: '/threatintel/wiki/f2t2ea',
        tabId: 'f2t2ea',
        label: 'F2T2EA',
        desc: 'F2T2EA joint targeting cycle (Find, Fix, Track, Target, Engage, Assess).',
        compVar: 'F2t2ea',
      },
      {
        path: '/threatintel/wiki/ooda',
        tabId: 'ooda',
        label: 'OODA Loop',
        desc: 'OODA decision cycle (Observe, Orient, Decide, Act) - the tempo layer under targeting frameworks.',
        compVar: 'Ooda',
      },
      {
        path: '/threatintel/wiki/kill-chain-v2',
        tabId: 'kill-chain-v2',
        label: 'Kill Chain v2',
        desc: 'Cyber Kill Chain v2 - the 7-phase chain plus lateral movement and a campaign overlay.',
        compVar: 'KillChainV2',
      },
      {
        path: '/threatintel/wiki/unified-kill-chain',
        tabId: 'unified-kill-chain',
        label: 'Unified Kill Chain',
        desc: 'Unified Kill Chain - 18 phases across In / Through / Out cycles (Pols 2017).',
        compVar: 'UnifiedKillChain',
      },
      {
        path: '/threatintel/wiki/insider',
        tabId: 'insider',
        label: 'Insider Threat Matrix',
        desc: 'Insider threat matrix and detection guidance.',
        compVar: 'InsiderThreatMatrix',
      },
      {
        path: '/threatintel/wiki/owasp',
        tabId: 'owasp',
        label: 'OWASP AI Landscape',
        desc: 'OWASP AI security landscape and LLM top-10.',
        compVar: 'OwaspAiLandscape',
      },
      {
        path: '/threatintel/wiki/llm',
        tabId: 'llm',
        label: 'LLM Threat Atlas',
        desc: 'MITRE ATLAS - LLM/AI threat atlas.',
        compVar: 'LlmThreatAtlas',
      },
      {
        path: '/threatintel/ai-escape',
        tabId: 'ai-escape',
        label: 'AI Escape Watch',
        desc: 'Registry of AI agent containment failures - indexed by the failed control, with containment chains and guardrail analysis.',
        compVar: 'AiEscape',
        badge: 'new',
        keywords: ['ai', 'agent', 'containment', 'escape', 'guardrail', 'sandbox', 'cbs'],
      },
      {
        path: '/threatintel/about',
        tabId: 'about',
        label: 'About the Platform',
        desc: 'What is covered, data principles, and the analyst-first design intent behind the surface.',
        compVar: 'ThreatIntelAbout',
      },
    ],
  },
  {
    id: 'ai-security',
    label: 'AI Security',
    blurb:
      'Rogue agents, AI incidents, offensive tooling, live vulns, advisories, and NHI identities — one tracking surface.',
    icon: ShieldAlert,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10',
    pages: [
      {
        path: '/threatintel/ai-security',
        tabId: 'ai-security',
        label: 'AI Security Hub',
        desc: 'Tracking hub for AI escape, AI incidents, security-matrix tools, live vulns, advisories, and NHI scanner.',
        compVar: 'AiSecurityHub',
        badge: 'new',
        keywords: ['ai', 'security', 'hub', 'incidents', 'rogue', 'nhi', 'llm', 'matrix', 'vuln', 'kev'],
      },
      {
        path: '/threatintel/ai-incidents',
        tabId: 'ai-incidents',
        label: 'AI Incidents',
        desc: 'Daily mirror of incidentdatabase.ai reports — AI harms in the wild, tracked per cite.',
        compVar: 'AiIncidents',
        badge: 'new',
        keywords: ['ai', 'incident', 'database', 'harm', 'cite', 'rss'],
      },
      {
        path: '/threatintel/ai-security-matrix',
        tabId: 'ai-security-matrix',
        label: 'AI Security Matrix',
        desc: 'Daily mirror of aisecuritymatrix.com — AI-enabled pentest, scanner, MCP, and skill tooling.',
        compVar: 'AiSecurityMatrix',
        badge: 'new',
        keywords: ['ai', 'matrix', 'pentest', 'scanner', 'mcp', 'tools'],
      },
      {
        path: '/threatintel/ai-vulns',
        tabId: 'ai-vulns',
        label: 'AI Vulns',
        desc: 'Realtime AI vulnerability tracking — EUVD + NVD + OSV watchlist with KEV overlap and EPSS scoring.',
        compVar: 'AiVulns',
        badge: 'new',
        keywords: ['ai', 'vuln', 'cve', 'kev', 'epss', 'euvd', 'nvd', 'osv', 'litellm', 'mcp'],
      },
      {
        path: '/threatintel/ai-advisories',
        tabId: 'ai-advisories',
        label: 'Advisories & Research',
        desc: 'CVE firehose, tool release trains, ExploitDB PoCs, plus Hacktron/Unit42/CSA research.',
        compVar: 'AiAdvisories',
        badge: 'new',
        keywords: ['ai', 'advisory', 'release', 'exploit', 'research', 'hacktron', 'cvelist'],
      },
    ],
  },
  {
    id: 'osint',
    label: 'OSINT',
    blurb: 'OSINT frameworks, CLI tools, country map, and curated toolbox.',
    icon: Search,
    tone: 'text-teal-700 dark:text-teal-300 border-teal-500/30 bg-teal-500/10',
    pages: [
      {
        path: '/threatintel/osint/framework',
        tabId: 'framework',
        label: 'OSINT Framework',
        desc: 'OSINT framework browser - 70+ tools organized by category.',
        compVar: 'OsintFramework',
      },
      {
        path: '/threatintel/osint/cli',
        tabId: 'cli',
        label: 'OSINT CLI Tools',
        desc: 'Curated CLI tools - username, email, domain, social, recon.',
        compVar: 'OsintCliTools',
        badge: 'new',
      },
      {
        path: '/threatintel/osint/map',
        tabId: 'map',
        label: 'OSINT Country Map',
        desc: 'Country-based OSINT map - sources by jurisdiction.',
        compVar: 'OsintCountryMap',
      },
      {
        path: '/threatintel/osint/toolbox',
        tabId: 'toolbox',
        label: 'Curated Toolbox',
        desc: 'Curated security toolbox - hand-picked, vetted, well-maintained.',
        compVar: 'CuratedToolbox',
      },
      {
        path: '/threatintel/osint/certs',
        tabId: 'certs',
        label: 'Free Cert Courses',
        desc: 'Syberseeker’s start.me hub of free certification tracks - security, cloud, blue team, OSINT, GRC.',
        compVar: 'CuratedCerts',
        badge: 'new',
      },
      {
        path: '/threatintel/osint/secops',
        tabId: 'secops',
        label: 'SecOps Tools',
        desc: 'SecOps tools catalog - SIEM, EDR, SOAR, log shippers.',
        compVar: 'SecopsCatalog',
      },

      {
        path: '/threatintel/osint/directory',
        tabId: 'directory',
        label: 'OSINT Portal Directory',
        desc: 'Curated directory of 40 OSINT portals and resources filtered by category.',
        compVar: 'OsintDirectory',
        badge: 'new',
      },
      {
        path: '/threatintel/cti-bookmarks',
        tabId: 'cti-bookmarks',
        label: 'CTI Bookmarks',
        desc: '387 curated CTI links across intel levels, tagged by platform integration status.',
        compVar: 'CtiBookmarks',
        badge: 'new',
      },
    ],
  },
  {
    id: 'tools',
    label: 'Tools & Utilities',
    blurb: 'AI copilot, MCP search, MISP, STIX, investigations, and watches.',
    icon: Wrench,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    pages: [
      {
        path: '/threatintel/tools/copilot',
        tabId: 'copilot',
        label: 'Threat Intel Copilot',
        desc: 'AI copilot - ask, pivot, summarize, draft.',
        compVar: 'Copilot',
        badge: 'new',
      },
      {
        path: '/threatintel/entity-graph',
        tabId: 'entity-graph',
        label: 'Entity Graph',
        desc: 'Interactive topology of CVEs, actors, IOCs, sectors, and techniques.',
        compVar: 'EntityGraphPage',
        badge: 'new',
      },
      {
        path: '/threatintel/vera',
        tabId: 'vera',
        label: 'Vera',
        desc: 'Vera - AI-powered investigative assistant for threat intelligence workflows.',
        compVar: 'VeraChat',
        badge: 'new',
      },
      {
        path: '/threatintel/mcp-search',
        tabId: 'mcp',
        label: 'MCP Search · TI Mindmap Hub',
        desc: 'Search 1,628+ reports, CVEs, IOCs, briefings, STIX bundles, and knowledge graph via 25 MCP tools on ti-mindmap-hub.com — with a full per-tool reference (names, descriptions, parameters).',
        compVar: 'McpSearch',
        badge: 'new',
      },
      // NOTE: the old /threatintel/tools/mcp hub entry was merged into
      // /threatintel/mcp-search above (single canonical MCP page).
      {
        path: '/threatintel/tools/stix-hub',
        tabId: 'stix-hub',
        label: 'STIX Hub',
        desc: 'STIX 2.1 bundle browsing, IP enrichment, and API access.',
        compVar: 'StixHub',
        keywords: ['stix', 'bundle', 'browser', 'ip', 'enrichment'],
      },

      {
        path: '/threatintel/cves/cves?tab=kev',
        tabId: 'kev',
        label: 'CISA KEV Catalog',
        desc: 'Search and filter the CISA Known Exploited Vulnerabilities catalog (tab of CVE Intel).',
        compVar: 'CveIntelKev',
        badge: 'new',
      },

      {
        path: '/threatintel/tools/tg-intel-search',
        tabId: 'tg-intel-search',
        label: 'TG Intel Search',
        desc: 'Boolean search across Telegram messages - AND/OR/NOT, field qualifiers, IOC extraction.',
        compVar: 'TgIntelSearch',
        badge: 'new',
      },
      {
        path: '/threatintel/tools/socradar-tools',
        tabId: 'socradar-tools',
        label: 'Tactical Radar Tools',
        desc: 'DDoS intelligence, FortiGate breach check, healthcare breach tracking.',
        compVar: 'SocradarTools',
        badge: 'new',
      },
      {
        path: '/threatintel/tools/unified-search',
        tabId: 'unified-search',
        label: 'Unified Search',
        desc: 'Cross-source search across the entire platform.',
        compVar: 'UnifiedSearch',
      },
      {
        path: '/threatintel/tools/directory',
        tabId: 'directory',
        label: 'Security Tools Directory',
        desc: 'Curated catalog of 53 security tools organized by category.',
        compVar: 'ToolsDirectory',
        badge: 'new',
      },
      {
        path: '/threatintel/tools/darknet-intel',
        tabId: 'darknet-intel',
        label: 'Darknet Intel',
        desc: '42 tools across 13 providers - IP reputation, malware analysis, vulnerability lookup, ransomware tracking, breach intelligence.',
        compVar: 'DarknetIntel',
        badge: 'new',
      },
    ],
  },
  {
    id: 'external',
    label: 'External Resources',
    blurb: 'External directories, supply-chain intel, and awesome lists.',
    icon: ExternalLink,
    tone: 'text-stone-700 dark:text-stone-300 border-stone-500/30 bg-stone-500/10',
    pages: [
      {
        path: '/threatintel/external/external',
        tabId: 'external',
        label: 'External Resources',
        desc: 'Off-site cross-references - dashboards, OSINT directories, training labs.',
        compVar: 'ExternalResources',
      },

      {
        path: '/threatintel/external/awesome',
        tabId: 'awesome',
        label: 'Awesome Lists',
        desc: 'Curated awesome-security list - vetted, ranked, kept current.',
        compVar: 'AwesomeLists',
      },
      {
        path: '/threatintel/external/cerast',
        tabId: 'cerast',
        label: 'Cerast Intelligence',
        desc: 'OSINT domain exposure search - exposed paths, staging, misconfigs.',
        compVar: 'Cerast',
      },
      {
        path: '/threatintel/external/threatmon',
        tabId: 'threatmon',
        label: 'ThreatMon Infostealer',
        desc: 'Infostealer log search - compromised credentials by domain.',
        compVar: 'ThreatMonInfostealer',
      },
    ],
  },
  {
    id: 'predictive',
    label: 'Predictive & Dashboards',
    blurb: 'Intel dashboard, predictions, metrics, and predictive analysis.',
    icon: LineChart,
    tone: 'text-purple-700 dark:text-purple-300 border-purple-500/30 bg-purple-500/10',
    pages: [
      {
        path: '/threatintel/predictive/dashboard',
        tabId: 'dashboard',
        label: 'Intel Dashboard',
        desc: 'Program health, feed reliability, snapshot metrics, maturity, and quick actions.',
        compVar: 'IntelDashboard',
      },
      {
        path: '/threatintel/soc-dashboard',
        tabId: 'soc-dashboard',
        label: 'SOC Dashboards',
        desc: 'Red/cyan/purple panels - ransomware activity, vulnerability index, and IOC stream with consensus scoring.',
        compVar: 'SocDashboard',
        keywords: ['soc', 'security operations', 'ransomware', 'vulnerability', 'ioc', 'stream', 'dashboard'],
      },
      {
        path: '/threatintel/predictive/global-pulse',
        tabId: 'global-pulse',
        label: 'Global Pulse',
        desc: 'Live 3D globe - 700+ events across 21 layers.',
        compVar: 'GlobalPulse',
        badge: 'live',
      },
      {
        path: '/threatintel/cyberpulse',
        tabId: 'cyberpulse',
        label: 'CyberPulse',
        desc: 'Live breach/leak/intel incident tracker - ransomware, leaks, extortion, supply chain from X, Telegram, Reddit, Bluesky.',
        compVar: 'CyberPulse',
        badge: 'live',
        keywords: ['cyberpulse', 'breach', 'leak', 'incident', 'ransomware', 'extortion'],
      },
      {
        path: '/threatintel/predictive/threat-pulse',
        tabId: 'threat-pulse',
        label: 'Threat Pulse',
        desc: 'Threat-pulse tracking - actor activity, campaign spikes, geo shifts.',
        compVar: 'ThreatPulse',
        badge: 'live',
      },
      {
        path: '/threatintel/predictive/certstream',
        tabId: 'certstream',
        label: 'CertStream',
        desc: 'Certificate transparency live feed.',
        compVar: 'CertStreamLive',
        badge: 'live',
      },
      {
        path: '/threatintel/predictive/metrics',
        tabId: 'metrics',
        label: 'Metrics',
        desc: 'Ten-panel metrics board.',
        compVar: 'Metrics',
      },
      {
        path: '/threatintel/predictive/predictions',
        tabId: 'predictions',
        label: 'Predictions',
        desc: 'Forward-looking threat predictions with confidence.',
        compVar: 'Predictions',
      },
      {
        path: '/threatintel/predictive/predictive',
        tabId: 'predictive',
        label: 'Predictive Intel',
        desc: 'AI-driven threat forecasting from current trends.',
        compVar: 'PredictiveIntel',
      },

      {
        path: '/threatintel/live-center',
        tabId: 'live-center',
        label: 'Live Center - Web OSINT',
        desc: 'Browser-based live OSINT tools with install, example, and reference URL per tool.',
        compVar: 'LiveCenter',
      },
    ],
  },
  {
    id: 'monitoring-estate',
    label: 'Monitoring & Estate',
    blurb: 'Noise-filtered alert feed, ransomware monitoring, and estate configuration.',
    icon: Bell,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    pages: [
      {
        path: '/threatintel/threat-actor-monitor',
        tabId: 'threat-actor-monitor',
        label: 'Threat Actor Monitor',
        desc: 'Real-time APT monitoring across 81 groups, 108 techniques, 39 OSINT feeds with MITRE ATT&CK + Kill Chain mapping — replication of hero-itsme/Global-Threat-Actor-Monitor expanded (40→81 groups, 29→108 techniques, 30→39 feeds).',
        compVar: 'ThreatActorMonitor',
        keywords: [
          'apt',
          'threat actor',
          'monitor',
          'kill chain',
          'mitre',
          'osint',
          'hero-itsme',
          'groups',
          'techniques',
          'feeds',
        ],
        badge: 'live',
      },
      {
        path: '/threatintel/alerts',
        tabId: 'alerts',
        label: 'Alert Feed',
        desc: 'Prioritised threat intelligence alerts - noise-filtered, confidence-scored, and matched to your estate.',
        compVar: 'AlertFeed',
      },
      {
        path: '/threatintel/ransomware-live',
        tabId: 'ransomware-live',
        label: 'Ransomware Live',
        desc: 'Live ransomware victim and group monitoring with sector/region filtering.',
        compVar: 'RansomwareLive',
        badge: 'live',
      },
    ],
  },
];

/* ------------------------------------------------------------------ */
/*  Lookup helpers                                                     */
/* ------------------------------------------------------------------ */

const HUB_BY_ID = new Map(HUB_META.map((h) => [h.id, h]));
const PAGE_BY_PATH = new Map<string, { hub: HubMeta; page: HubPage }>();
// slug → hub id. The slug for a page is the LAST segment of its path
// (e.g. `/threatintel/iocs/cross` → `cross`). The hub itself is the slug
// for flat 2-segment pages (e.g. `/threatintel/detections`). Both
// contribute entries here. When the same slug appears in two hubs
// (e.g. `cross` is a tab under both `iocs` and `campaigns`) the first
// write wins; the resolver still returns the correct hub for 3-segment
// paths because it uses the hub part, not the slug. A drift test in
// `src/data/threatintel-hubs.test.ts` asserts that the resulting map
// is well-formed (every entry points to a real hub).
const SLUG_TO_HUB = new Map<string, string>();
// Set of all valid 2-segment paths (flat tool pages) - used by the
// back-link resolver to disambiguate `/threatintel/<hub-id>` (the hub
// landing page) from `/threatintel/<flat-tool-slug>` (a tool that just
// happens to share its name with a tab elsewhere).
const FLAT_TOOL_PATHS = new Set<string>();
for (const hub of HUB_META) {
  // 2-segment page: /threatintel/<hub>  → the slug is the hub id itself.
  SLUG_TO_HUB.set(hub.id, hub.id);
  for (const page of hub.pages) {
    const rel = page.path.replace(/^\/threatintel\//, '');
    const parts = rel.split('/');
    const slug = parts[parts.length - 1];
    if (slug && !SLUG_TO_HUB.has(slug)) SLUG_TO_HUB.set(slug, hub.id);
    if (parts.length === 1) FLAT_TOOL_PATHS.add(page.path);
    PAGE_BY_PATH.set(page.path, { hub, page });
  }
}

/** Look up the hub id for a tool slug (the last path segment after
 *  /threatintel/). Returns `undefined` when the slug is not registered. */
export function hubIdForSlug(slug: string): string | undefined {
  return SLUG_TO_HUB.get(slug);
}

/** True when `path` is a registered flat 2-segment tool page
 *  (e.g. `/threatintel/briefings` lives directly under the campaigns
 *  hub and is a real tool, not a hub landing). */
export function isFlatToolPath(path: string): boolean {
  return FLAT_TOOL_PATHS.has(path);
}

export function getHub(id: string): HubMeta | undefined {
  return HUB_BY_ID.get(id);
}

export function getPageByPath(path: string): { hub: HubMeta; page: HubPage } | undefined {
  return PAGE_BY_PATH.get(path);
}

export function getAllPages(): Array<{ hub: HubMeta; page: HubPage }> {
  return Array.from(PAGE_BY_PATH.values());
}

export function flattenPages(): Array<HubPage & { hub: HubMeta }> {
  const out: Array<HubPage & { hub: HubMeta }> = [];
  for (const hub of HUB_META) {
    for (const page of hub.pages) {
      out.push({ ...page, hub });
    }
  }
  return out;
}
