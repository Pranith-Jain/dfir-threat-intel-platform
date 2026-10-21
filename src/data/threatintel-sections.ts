import {
  AlertTriangle,
  BarChart3,
  BookOpen,
  Bug,
  Compass,
  Database,
  FileText,
  Globe,
  GitBranch,
  LayoutDashboard,
  Newspaper,
  Radio,
  Rss,
  Scale,
  Search,
  Shield,
  ShieldAlert,
  Skull,
  Target,
  Terminal,
  TrendingUp,
  Users,
  type LucideIcon,
} from 'lucide-react';

export interface Tool {
  to: string;
  label: string;
  desc: string;
  icon: LucideIcon;
  badge?: string;
  /** When true, the tile links out via <a target="_blank"> instead of an in-app <Link>. */
  external?: boolean;
}

export interface Section {
  id: string;
  label: string;
  blurb: string;
  tools: Tool[];
}

export const SECTIONS: Section[] = [
  // ── 1. Threat Intelligence ─────────────────────────────────────
  {
    id: 'threat-intel',
    label: 'Threat Intelligence',
    blurb: 'Landscape overview, actor profiles, campaign tracking, and intelligence briefings.',
    tools: [
      {
        to: '/threatintel/catalog',
        label: 'Page Catalog',
        desc: 'Every routable page in the threat-intel area - searchable, filterable, with deep links.',
        icon: Search,
        badge: 'new',
      },
      {
        to: '/threatintel/predictive',
        label: 'Threat Landscape',
        desc: 'Key stats, trending actors, top malware, emerging threats, and attack vector distribution.',
        icon: LayoutDashboard,
        badge: 'new',
      },
      {
        to: '/threatintel/threat-actor-catalog',
        label: 'Threat Actor Catalog',
        desc: 'Curated profiles of 15 major groups - aliases, countries, malware, TTPs, campaigns, MITRE mapping.',
        icon: Skull,
        badge: 'new',
      },
      {
        to: '/threatintel/actors',
        label: 'Actor Directory',
        desc: 'Unified actor browser - MITRE ATT&CK, MISP Galaxy, and platform database with search.',
        icon: Users,
      },
      {
        to: '/threatintel/campaigns',
        label: 'Campaigns & Attribution',
        desc: 'Campaign lifecycle tracking, cross-campaign correlation, and multi-signal attribution framework.',
        icon: GitBranch,
      },
      {
        to: '/threatintel/briefings',
        label: 'Briefings & Reports',
        desc: 'Daily/weekly tactical digests, threat landscape reports, and published assessments.',
        icon: Newspaper,
      },
    ],
  },
  // ── 2. Live Intelligence ───────────────────────────────────────
  {
    id: 'live-intel',
    label: 'Live Intelligence',
    blurb: 'Real-time feeds, social monitoring, dark web tracking, and SOC dashboards.',
    tools: [
      {
        to: '/threatintel/live-feed',
        label: 'Live Threat Feed',
        desc: 'Unified real-time feed — 30+ sources, CVE, IOC, ransomware, actor activity, MITRE mapping, STIX export. Inspired by threatintelligence.dk.',
        icon: Radio,
        badge: 'live',
      },
      {
        to: '/threatintel/social',
        label: 'Social & Telegram Feeds',
        desc: 'Cybersec Telegram firehose, Reddit, X/Bluesky, Mastodon, prediction markets, and scam watch.',
        icon: Radio,
        badge: 'live',
      },
      {
        to: '/threatintel/darkweb',
        label: 'Dark Web Watch',
        desc: 'Aggregated leak-site, ransomware, breach activity, keyword watchlist, and per-source separation.',
        icon: Globe,
      },
      {
        to: '/threatintel/iocs',
        label: 'IOC Hub',
        desc: 'Live IOC stream, cross-source correlation, C2 tracker, supply chain intelligence, and ransomware activity.',
        icon: Target,
        badge: 'live',
      },
      {
        to: '/threatintel/soc-dashboard',
        label: 'SOC Dashboards',
        desc: 'Red/cyan/purple panels - ransomware activity, vulnerability index, and IOC stream with consensus scoring.',
        icon: LayoutDashboard,
        badge: 'live',
      },
      {
        to: '/threatintel/predictive/dashboard',
        label: 'Intel Dashboard',
        desc: 'Program health, feed reliability, snapshot metrics, CVE landscape, and quick actions.',
        icon: LayoutDashboard,
        badge: 'live',
      },
      {
        to: '/threatintel/feeds',
        label: 'Feed Management',
        desc: 'Feed sources (50+ RSS), feed scheduler, alert engine, feed file catalog, and aggregated feeds.',
        icon: Rss,
      },
    ],
  },
  // ── 3. Detection & Response ────────────────────────────────────
  {
    id: 'detection',
    label: 'Detection & Response',
    blurb: 'Detection rules, CVE tracking, malware analysis, and phishing defense.',
    tools: [
      {
        to: '/threatintel/detections',
        label: 'Detection Hub',
        desc: 'Detection rules (Sigma/YARA/Suricata), GoXDR KQL library, CVE feeds, KEV catalog, malware IOC browser, and YARA rules.',
        icon: Shield,
      },
      {
        to: '/threatintel/detection-wiki',
        label: 'Detection Wiki',
        desc: '15,957 detection rules from Sigma, Elastic, Splunk, Kusto mapped to MITRE ATT&CK — plus detection labs.',
        icon: Database,
      },
      {
        to: '/threatintel/cves',
        label: 'CVE Hub',
        desc: 'Live CVE updates, exploitable CVEs, CISA KEV catalog, GitHub advisories, and Kubernetes CVE feed.',
        icon: AlertTriangle,
      },
      {
        to: '/threatintel/malware',
        label: 'Malware Hub',
        desc: 'Malware IOC browser (50+ families), Malpedia, and Maltrail APT trails.',
        icon: Bug,
      },
      {
        to: '/threatintel/malware-sandbox',
        label: 'Malware Sandbox',
        desc: 'Hash lookup across 10+ public sandbox platforms - consensus verdict, family attribution, one-click detonation.',
        icon: Bug,
        badge: 'new',
      },
      {
        to: '/threatintel/phishing',
        label: 'Phishing Defense',
        desc: 'Phishing hunting wordlists, phish feed, email defense analysis, and domain impersonation monitoring.',
        icon: ShieldAlert,
      },
    ],
  },
  // ── 4. Analysis Tools ──────────────────────────────────────────
  {
    id: 'analysis',
    label: 'Analysis Tools',
    blurb: 'OSINT frameworks, AI copilot, data search, and investigative utilities.',
    tools: [
      {
        to: '/threatintel/osint',
        label: 'OSINT Hub',
        desc: 'Username search (291k handles), OSINT framework (70+ tools), OSINT country map, and tool directories.',
        icon: Search,
      },
      {
        to: '/threatintel/osint-cli-tools',
        label: 'OSINT CLI Tools',
        desc: '55+ curated CLI tools across 10 categories - username, email, domain, social, dorking, recon.',
        icon: Terminal,
        badge: 'new',
      },
      {
        to: '/threatintel/tools',
        label: 'Frameworks & Tools',
        desc: 'MITRE ATT&CK, ATLAS, insider threat matrix, ACH, F3EAD, AI copilot, and analysis orchestration.',
        icon: Compass,
      },
      {
        to: '/threatintel/stix-bundles',
        label: 'STIX Bundle Browser',
        desc: 'Browse and download STIX 2.1 bundles - import into OpenCTI, MISP, or any STIX-aware platform.',
        icon: GitBranch,
        badge: 'new',
      },
      {
        to: '/threatintel/ioc-feeds',
        label: 'IOC Feeds',
        desc: 'Structured indicator feeds ready for SIEM, EDR, or CTI platform ingestion.',
        icon: Rss,
        badge: 'new',
      },
    ],
  },
  // ── 5. Reports & Knowledge ─────────────────────────────────────
  {
    id: 'reports',
    label: 'Reports & Knowledge',
    blurb: 'Research reports, knowledge base, external resources, and curated catalogs.',
    tools: [
      {
        to: '/threatintel/reports',
        label: 'Threat Intel Reports',
        desc: 'Original research reports with IOCs, detection rules, and severity scoring.',
        icon: FileText,
        badge: 'new',
      },
      {
        to: '/threatintel/wiki',
        label: 'Knowledge Base',
        desc: 'Long-form articles on Telegram OSINT, dark-web monitoring, MITRE workflows, and briefing methodology.',
        icon: BookOpen,
      },
      {
        to: '/threatintel/external',
        label: 'External Resources',
        desc: 'Off-site cross-references - dashboards, OSINT directories, training labs, malware samples, research portfolios.',
        icon: Globe,
      },
      {
        to: '/threatintel/about',
        label: 'About the Platform',
        desc: "What's covered, data principles, and the analyst-first design intent behind the surface.",
        icon: Scale,
      },
    ],
  },
  // ── 6. Export & Operations ─────────────────────────────────────
  {
    id: 'operations',
    label: 'Export & Operations',
    blurb: 'IOC export, alert management, source health, and operational dashboards.',
    tools: [
      {
        to: '/threatintel/tools',
        label: 'Operations Hub',
        desc: 'Metrics, feed status, collection SLO, source reliability, intelligence requirements, and feed quality scorecard.',
        icon: BarChart3,
      },
      {
        to: '/threatintel/predictive',
        label: 'Predictive Intelligence',
        desc: 'AI-driven threat forecasting based on current intelligence trends and historical data.',
        icon: TrendingUp,
      },
    ],
  },
  // ── 7. Darknet Intel ─────────────────────────────────────────────
  {
    id: 'darknet-intel',
    label: 'Darknet Intel',
    blurb:
      'Live threat lookups - IP reputation, malware analysis, vulnerability search, ransomware tracking, breach intelligence.',
    tools: [
      {
        to: '/threatintel/tools/darknet-intel',
        label: 'Darknet Intel Hub',
        desc: '43 tools across 13 providers - GreyNoise, Pulsedive, Vulners, IntelX, AbuseIPDB, ransomware, HIBP, abuse.ch, OTX, Hybrid Analysis.',
        icon: Shield,
        badge: 'new',
      },
      {
        to: '/threatintel/darkweb/darknetlist',
        label: 'Darknet Directory',
        desc: 'Live Tor site directory from darknetlist.is - 108 sites across 9 categories (markets, forums, news, security, comms, crypto, tools, AI) with up/down status, onion URLs, and fingerprints.',
        icon: Globe,
        badge: 'live',
      },
    ],
  },
];

// ── Helper functions ──────────────────────────────────────────────

export function flattenTools(sections: Section[]): Array<Tool & { section: Section }> {
  return sections.flatMap((s) => s.tools.map((t) => ({ ...t, section: s })));
}

export function matchesQuery(tool: Tool & { section: Section }, query: string): boolean {
  const q = query.toLowerCase();
  return (
    tool.label.toLowerCase().includes(q) ||
    tool.desc.toLowerCase().includes(q) ||
    tool.section.label.toLowerCase().includes(q)
  );
}
