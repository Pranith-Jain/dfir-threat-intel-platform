/**
 * Canonical registry of every routable page in the DFIR / security toolkit area.
 *
 * Mirrors `data/threatintel-hubs.ts` - the threat-intel area was consolidated
 * onto this pattern in commit 6f7d055b (2026-06-17); this file is the same
 * shape for the DFIR section so both apps share a navigation system.
 *
 * Each "hub" is a category of related pages. Pages live at their own direct
 * URL (/dfir/<hub-id>/<tab-id>). There is no /dfir/<hub-id> landing page in
 * between - the /dfir/catalog page is the single navigation surface for
 * browsing a category, and accepts ?cat=<hub-id> to pre-filter.
 */

import {
  AlertTriangle,
  AtSign,
  Bot,
  Bug,
  Cloud,
  Code2,
  Compass,
  Crosshair,
  FileText,
  FolderTree,
  Globe,
  Mail,
  Scale,
  ScrollText,
  Server,
  Share2,
  Shield,
  Sparkles,
  Workflow,
  type LucideIcon,
} from 'lucide-react';

export type HubPageBadge = 'live' | 'new' | 'beta';

export interface HubPage {
  path: string;
  tabId: string;
  label: string;
  desc: string;
  compVar: string;
  badge?: HubPageBadge;
  keywords?: readonly string[];
  icon?: LucideIcon;
}

export interface HubMeta {
  id: string;
  label: string;
  blurb: string;
  icon: LucideIcon;
  tone: string;
  pages: readonly HubPage[];
}

export const HUB_META: readonly HubMeta[] = [
  {
    id: 'overview',
    label: 'Overview',
    blurb: 'Catalog and entry points for the DFIR / security toolkit area.',
    icon: Compass,
    tone: 'text-brand-700 dark:text-brand-300 border-brand-500/30 bg-brand-500/10',
    pages: [
      {
        path: '/dfir/catalog',
        tabId: 'catalog',
        label: 'DFIR Catalog',
        desc: 'Every DFIR tool, searchable, grouped by category.',
        compVar: 'DfirCatalog',
      },
    ],
  },
  {
    id: 'ioc-triage',
    label: 'IOC Triage',
    blurb:
      'Check, extract, and track indicators across 60+ sources - IP, domain, URL, hash pivots with cross-source consensus.',
    icon: Crosshair,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10',
    pages: [
      {
        path: '/dfir/ioc-investigate',
        tabId: 'ioc-investigate',
        label: 'IOC Investigator',
        desc: 'Cross-source investigation hub - paste any indicator type and pivot across all sources.',
        compVar: 'IocInvestigate',
      },

      {
        path: '/dfir/extract',
        tabId: 'extract',
        label: 'IOC Extractor',
        desc: 'Pull IOCs from any text blob - refang-aware.',
        compVar: 'IocExtractor',
      },
      {
        path: '/dfir/ct-monitor',
        tabId: 'ct-monitor',
        label: 'Certificate Transparency Monitor',
        desc: 'Watch CT logs for new certificates matching your watchlist.',
        compVar: 'CtMonitor',
      },
      {
        path: '/dfir/oss-feeds',
        tabId: 'oss-feeds',
        label: 'OSS Feed Registry',
        desc: 'Curated catalog of 145+ free open-source threat intel feeds - IP, DNS, URL, hash, CVE, JA3, and more. Search by vendor, category, or keyword.',
        compVar: 'OssFeeds',
        badge: 'new',
        keywords: ['feed', 'ioc', 'threat intel', 'open source', 'catalog', 'ip', 'dns', 'url', 'hash', 'cve', 'ja3'],
      },
      {
        path: '/dfir/orkl',
        tabId: 'orkl',
        label: 'ORKL Library Search',
        desc: 'Search the ORKL open-source threat intelligence library - reports, actors, CVEs from hundreds of sources.',
        compVar: 'OrklPage',
        keywords: ['orkl', 'threat intelligence', 'library', 'reports'],
      },
      {
        path: '/dfir/traceix',
        tabId: 'traceix',
        label: 'Traceix Hash Lookup',
        desc: 'SHA-256 hash reputation lookup via Traceix - per-engine antivirus/AV verdicts (Safe/Malicious/Unknown).',
        compVar: 'TraceixPage',
      },
      {
        path: '/dfir/url-risk',
        tabId: 'url-risk',
        label: 'URL Risk Analyzer',
        desc: 'Multi-source URL risk scoring - static signals + VirusTotal, Safe Browsing, URLScan, AbuseIPDB and WHOIS-age correlation (IntelX framework port). 0-100 score with evidence chain.',
        compVar: 'UrlRiskPage',
        badge: 'new',
        keywords: ['url', 'risk', 'phishing', 'virustotal', 'safe browsing', 'urlscan', 'abuseipdb', 'whois', 'score'],
      },
      {
        path: '/dfir/whoxy',
        tabId: 'whoxy',
        label: 'Whoxy Reverse WHOIS',
        desc: 'Reverse WHOIS lookup via Whoxy - find all domains registered by an email, name, company, or keyword.',
        compVar: 'WhoxyPage',
      },
    ],
  },
  {
    id: 'malware',
    label: 'Malware Analysis',
    blurb: 'Triage, parse, and deobfuscate samples - stealer logs, packed binaries, malicious documents, and PCAPs.',
    icon: Bug,
    tone: 'text-orange-700 dark:text-orange-300 border-orange-500/30 bg-orange-500/10',
    pages: [
      {
        path: '/dfir/malware-analyzer',
        tabId: 'malware-analyzer',
        label: 'Malware Analyzer',
        desc: 'PE / ELF / Mach-O static analysis with import hashing + section entropy.',
        compVar: 'MalwareAnalyzer',
      },
      {
        path: '/dfir/stealer-parser',
        tabId: 'stealer-parser',
        label: 'Infostealer Log Parser',
        desc: 'Parse RedLine / Raccoon / Vidar / LummaC stealer logs - credentials, system, browser data.',
        compVar: 'StealerParser',
      },

      {
        path: '/dfir/infostealer-intel',
        tabId: 'infostealer-intel',
        label: 'Infostealer Intelligence',
        desc: 'Infostealer-specific intelligence dashboard - prevalent families, log types, and compromised credential tracking.',
        compVar: 'InfostealerIntel',
      },
      {
        path: '/dfir/malapi',
        tabId: 'malapi',
        label: 'MalAPI',
        desc: 'Windows APIs abused by attackers - attack categories, libraries, and MS docs links.',
        compVar: 'Malapi',
        keywords: ['winapi', 'malapi', 'imports', 'capabilities'],
      },
    ],
  },
  {
    id: 'file-analysis',
    label: 'File & Binary Analysis',
    blurb: 'Decode, hash, and inspect binaries, encoded payloads, and document formats - runs entirely in the browser.',
    icon: FileText,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    pages: [
      {
        path: '/dfir/codec',
        tabId: 'codec',
        label: 'Codec Hub',
        desc: 'Decode and encode across base64, hex, URL, rot13, zlib, gzip with auto-detection.',
        compVar: 'CodecHub',
        keywords: ['decode', 'encode', 'base64', 'hex', 'url', 'rot13', 'zlib', 'gzip'],
      },

      {
        path: '/dfir/hash-calc',
        tabId: 'hash-calc',
        label: 'Hash Calculator',
        desc: 'MD5 - SHA1 - SHA256 - SHA512 - SSDEEP - TLSH - drag a file in.',
        compVar: 'HashCalculator',
      },
      {
        path: '/dfir/timestamp',
        tabId: 'timestamp',
        label: 'Timestamp Converter',
        desc: 'Epoch - Windows FILETIME - Unix - human - bidirectional.',
        compVar: 'TimestampConverter',
      },
      {
        path: '/dfir/apk-analyzer',
        tabId: 'apk-analyzer',
        label: 'APK Analyzer',
        desc: 'Manifest + permissions + signing certs + native libs.',
        compVar: 'ApkAnalyzer',
      },
      {
        path: '/dfir/exif',
        tabId: 'exif',
        label: 'EXIF / Metadata Parser',
        desc: 'EXIF - IPTC - XMP - MakerNotes - camera, GPS, software fingerprints.',
        compVar: 'ExifParse',
      },
      {
        path: '/dfir/plist-protobuf',
        tabId: 'plist-protobuf',
        label: 'Plist & Protobuf Decoder',
        desc: 'Apple binary plist + protobuf human-readable view.',
        compVar: 'PlistProtobuf',
      },
      {
        path: '/dfir/punycode',
        tabId: 'punycode',
        label: 'Punycode / Homoglyph Viewer',
        desc: 'Visualise IDN homograph attacks - Cyrillic vs Latin lookalikes.',
        compVar: 'Punycode',
      },
      {
        path: '/dfir/powershell-deobf',
        tabId: 'powershell-deobf',
        label: 'PowerShell Deobfuscator',
        desc: 'Unroll encoded / base64 / invoke-expression chains - step by step.',
        compVar: 'PowershellDeobf',
      },
      {
        path: '/dfir/powershell-analyzer',
        tabId: 'powershell-analyzer',
        label: 'PowerShell Security Analyzer',
        desc: 'Static-analysis a PowerShell script for malicious behavior - 250+ signatures, MITRE ATT&CK mapping, IOC extraction, obfuscation scoring, risk score, 100% client-side.',
        compVar: 'PowershellAnalyzer',
        badge: 'new',
        keywords: ['powershell', 'malware', 'obfuscation', 'ioc', 'mitre', 'static analysis', 'script'],
      },
      {
        path: '/dfir/hex-workbench',
        tabId: 'hex-workbench',
        label: 'Hex Workbench',
        desc: 'Browser-side hex viewer for artifact triage - inspect bytes, search hex/ASCII, jump to offsets, magic-byte family detection + entropy.',
        compVar: 'HexWorkbench',
        badge: 'new',
        keywords: ['hex', 'binary', 'viewer', 'bytes', 'entropy', 'magic bytes', 'offset', 'artifact'],
      },
    ],
  },
  {
    id: 'artifacts',
    label: 'Artifact Parsers',
    blurb: 'Endpoint forensic artifacts - PCAP, registry, EVTX, SQLite, browser, mobile, and web logs.',
    icon: FolderTree,
    tone: 'text-emerald-700 dark:text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
    pages: [
      {
        path: '/dfir/pcap-triage',
        tabId: 'pcap-triage',
        label: 'PCAP Triage',
        desc: 'Protocol breakdown - top talkers - DNS / HTTP / TLS summaries.',
        compVar: 'PcapTriage',
      },
      {
        path: '/dfir/registry-hive',
        tabId: 'registry-hive',
        label: 'Registry Hive Explorer',
        desc: 'Browse - search - diff Windows registry hives offline.',
        compVar: 'RegistryHive',
      },
      {
        path: '/dfir/evtx',
        tabId: 'evtx',
        label: 'EVTX Parser Lite',
        desc: 'Parse Windows Event Log files - event IDs, channels, time-range filter.',
        compVar: 'EvtxParser',
      },
      {
        path: '/dfir/sqlite',
        tabId: 'sqlite',
        label: 'SQLite Artifact Explorer',
        desc: 'Browser profile - chat history - mobile backups - query in-browser via WASM.',
        compVar: 'SqliteExplorer',
      },
      {
        path: '/dfir/ios-backup',
        tabId: 'ios-backup',
        label: 'iOS Backup Explorer',
        desc: 'Manifest.db - plists - SQLite artifacts from a local iTunes backup.',
        compVar: 'IosBackupExplorer',
      },

      {
        path: '/dfir/web-log',
        tabId: 'web-log',
        label: 'Web Server Log Analyzer',
        desc: 'Apache - nginx - IIS access logs - anomaly detection + pivots.',
        compVar: 'WebLogAnalyzer',
      },
      {
        path: '/dfir/prefetch',
        tabId: 'prefetch',
        label: 'Prefetch Analyzer Lite',
        desc: 'Parse Windows Prefetch files - execution evidence, run count, last run time.',
        compVar: 'PrefetchAnalyzer',
      },
      {
        path: '/dfir/procedure-extract',
        tabId: 'procedure-extract',
        label: 'Procedure Extraction',
        desc: 'Threat report → reviewed x-procedure STIX bundles with Attack-Flow sequencing.',
        compVar: 'ProcedureExtract',
      },
      {
        path: '/dfir/winreg',
        tabId: 'winreg',
        label: 'Windows Registry Artifacts Reference',
        desc: 'Windows Registry Forensic Artifact Reference - 292 artifacts, 16 categories, 10 hive types, 77 MITRE techniques.',
        compVar: 'WinRegPage',
      },
      {
        path: '/dfir/sigbase',
        tabId: 'sigbase',
        label: 'Signature-Base YARA + IOCs',
        desc: 'Neo23x0 signature-base - 746 YARA rule files (5,784 rules) + 4 IOC lists (hashes, C2, filenames, keywords).',
        compVar: 'SigBasePage',
        keywords: ['yara', 'ioc', 'signature', 'rule', 'hash', 'c2'],
      },
      {
        path: '/dfir/dfir-ref',
        tabId: 'dfir-ref',
        label: 'DFIR Reference',
        desc: 'Event IDs, memory forensics, browser artifacts, evidence collection phases — practitioner reference.',
        compVar: 'DfirRef',
        badge: 'new',
        keywords: ['event ids', 'memory', 'volatility', 'browser', 'evidence', 'forensics'],
      },
      {
        path: '/dfir/coc-generator',
        tabId: 'coc-generator',
        label: 'Chain of Custody Generator',
        desc: 'Build a defensible custody timeline — evidence inventory with hashes, transfer handlers, timestamps.',
        compVar: 'CoCGenerator',
        badge: 'new',
        keywords: ['chain of custody', 'evidence', 'forensic', 'timeline'],
      },
    ],
  },
  {
    id: 'domain-network',
    label: 'Domain & Network',
    blurb:
      'WHOIS, DNS, reputation, certificates, and infrastructure pivots - passive reconnaissance, no active scanning.',
    icon: Globe,
    tone: 'text-sky-700 dark:text-sky-300 border-cyan-500/30 bg-cyan-500/10',
    pages: [
      {
        path: '/dfir/domain-investigator',
        tabId: 'domain-investigator',
        label: 'Domain Investigator',
        desc: 'Cross-source domain investigation hub - 6 aliases route here (domain-rep, webcheck, etc.).',
        compVar: 'DomainInvestigator',
      },
      {
        path: '/dfir/whois-history',
        tabId: 'whois-history',
        label: 'WHOIS History Explorer',
        desc: 'Historical WHOIS pivots - registrant, nameserver, status changes.',
        compVar: 'WhoisHistory',
      },
      {
        path: '/dfir/asn',
        tabId: 'asn',
        label: 'ASN Lookup',
        desc: 'ASN details - prefix ranges - peer relationships.',
        compVar: 'AsnLookup',
      },
      {
        path: '/dfir/cert-search',
        tabId: 'cert-search',
        label: 'Certificate Search',
        desc: 'crt.sh-style CT log search for a domain - subdomains - cert chain.',
        compVar: 'CertSearch',
      },

      {
        path: '/dfir/dnscope',
        tabId: 'dnscope',
        label: 'DNSCOPE Infrastructure Map',
        desc: "Graph view of a domain's nameservers, mail servers, and cross-delegations",
        compVar: 'Dnscope',
        badge: 'new',
        keywords: ['dns', 'infrastructure', 'graph', 'nameserver'],
      },
      {
        path: '/dfir/host-graph',
        tabId: 'host-graph',
        label: 'Host Graph',
        desc: 'Graph of related domains, IPs, and ASNs for a target.',
        compVar: 'HostGraph',
      },
      {
        path: '/dfir/wayback',
        tabId: 'wayback',
        label: 'Wayback Machine',
        desc: 'Search historical snapshots for a URL - changes over time.',
        compVar: 'Wayback',
      },
      {
        path: '/dfir/passive-dns',
        tabId: 'passive-dns',
        label: 'Passive DNS',
        desc: 'Historical DNS resolution data for infrastructure tracking - migrations + fast-flux detection.',
        compVar: 'PassiveDns',
        badge: 'new',
        keywords: ['passive dns', 'pdns', 'infrastructure', 'fast-flux', 'migration'],
      },
    ],
  },
  {
    id: 'asset-attack',
    label: 'Asset & Attack Surface',
    blurb:
      'Exposed-host analysis, asset intelligence, and web vulnerability scanning - see what an attacker would see.',
    icon: Server,
    tone: 'text-sky-700 dark:text-sky-300 border-sky-500/30 bg-sky-500/10',
    pages: [
      {
        path: '/dfir/estate',
        tabId: 'estate',
        label: 'External Estate',
        desc: 'ASN ownership and announced address space - the internet-facing footprint.',
        compVar: 'EstateWatch',
      },
      {
        path: '/dfir/asset-intel',
        tabId: 'asset-intel',
        label: 'Asset Intelligence',
        desc: 'Aggregate asset inventory - domains, subdomains, services, certificates.',
        compVar: 'AssetIntel',
      },
      {
        path: '/dfir/exposed-host',
        tabId: 'exposed-host',
        label: 'Exposed Host',
        desc: 'Per-host exposure score and evidence - services, versions, CVEs.',
        compVar: 'ExposedHostPage',
      },
      {
        path: '/dfir/open-directory',
        tabId: 'open-directory',
        label: 'Open Directory Scanner',
        desc: 'Detect misconfigured web servers exposing file listings.',
        compVar: 'OpenDirectory',
      },

      {
        path: '/dfir/url-preview',
        tabId: 'url-preview',
        label: 'URL Preview',
        desc: 'Safe, sandboxed preview of a URL - headers, redirects, screenshot.',
        compVar: 'UrlPreview',
      },
      {
        path: '/dfir/subdomain-takeover',
        tabId: 'subdomain-takeover',
        label: 'Subdomain Takeover Scanner',
        desc: 'Detect dangling CNAMEs pointing to expired or unclaimed third-party services.',
        compVar: 'SubdomainTakeover',
        keywords: ['subdomain', 'takeover', 'cname', 'dangling', 'attack-surface'],
      },
      {
        path: '/dfir/exposure',
        tabId: 'exposure',
        label: 'Exposure Analysis',
        desc: 'External attack surface exposure - open ports, services, certificates, and misconfigurations.',
        compVar: 'ExposureAnalyzer',
      },
    ],
  },
  {
    id: 'email',
    label: 'Email Security',
    blurb:
      'Phishing analysis, BEC defense, and email authentication audits - SPF / DKIM / DMARC / BIMI without sending data off-host.',
    icon: Mail,
    tone: 'text-indigo-700 dark:text-indigo-300 border-indigo-500/30 bg-indigo-500/10',
    pages: [
      {
        path: '/dfir/email-defense',
        tabId: 'email-defense',
        label: 'Email Defense',
        desc: 'SPF / DKIM / DMARC / BIMI audit with failure modes called out.',
        compVar: 'EmailDefense',
      },
      {
        path: '/dfir/phishing',
        tabId: 'phishing',
        label: 'Phishing Analyzer',
        desc: 'URL + sender + header analysis with risk score.',
        compVar: 'Phishing',
      },
      {
        path: '/dfir/dmarc-analyzer',
        tabId: 'dmarc-analyzer',
        label: 'DMARC Analyzer',
        desc: 'Parse a DMARC aggregate report (RUA) - alignment, volume, failures.',
        compVar: 'DmarcAnalyzer',
      },
      {
        path: '/dfir/eml',
        tabId: 'eml',
        label: 'EML Extractor',
        desc: 'Headers - body - attachments - URL / hash extraction from a .eml file.',
        compVar: 'EmlExtractor',
      },
      {
        path: '/dfir/email-rep',
        tabId: 'email-rep',
        label: 'Email Reputation',
        desc: 'Sender domain + IP reputation with deliverability signals.',
        compVar: 'EmailReputation',
      },
      {
        path: '/dfir/email-osnit',
        tabId: 'email-osnit',
        label: 'Email OSINT Profile',
        desc: 'Build digital identity from email - GitHub, Gravatar, breach, reputation, DNS, PGP.',
        compVar: 'EmailOsnit',
        badge: 'new',
      },
      {
        path: '/dfir/phishbook',
        tabId: 'phishbook',
        label: 'PhishBook',
        desc: 'Curated playbook of phishing patterns, lures, and IOCs.',
        compVar: 'PhishBook',
      },
      {
        path: '/dfir/phishops',
        tabId: 'phishops',
        label: 'PHISHOPS',
        desc: 'Phishing-as-a-service operator catalog and tracking.',
        compVar: 'PhishOps',
        keywords: ['phishing', 'paas', 'operator'],
      },
    ],
  },
  {
    id: 'identity-osint',
    label: 'Identity & OSINT',
    blurb: 'Username, email, phone, image, and social reconnaissance - cross-platform pivots for a single subject.',
    icon: AtSign,
    tone: 'text-violet-700 dark:text-violet-300 border-violet-500/30 bg-violet-500/10',
    pages: [
      {
        path: '/dfir/username-investigator',
        tabId: 'username-investigator',
        label: 'Username Investigator (alias)',
        desc: 'Alias of /dfir/username - the canonical page.',
        compVar: 'UsernameInvestigator',
      },

      {
        path: '/dfir/phone-hub',
        tabId: 'phone-hub',
        label: 'Phone Intelligence',
        desc: 'Phone number OSINT - carrier lookup, line type, breach presence, and AI-powered risk scoring.',
        compVar: 'PhoneHub',
        keywords: ['phone', 'osint', 'carrier', 'intel', 'risk'],
      },

      {
        path: '/dfir/wifi-investigation',
        tabId: 'wifi-investigation',
        label: 'Wi-Fi / BSSID Investigation',
        desc: 'Wireless network - BSSID vendor lookup, SSID analysis, security flags.',
        compVar: 'WifiInvestigation',
      },
      {
        path: '/dfir/socmint',
        tabId: 'socmint',
        label: 'SOCMINT',
        desc: 'Social-media intelligence - X / Reddit / Telegram / Mastodon pivots.',
        compVar: 'Socmint',
      },
      {
        path: '/dfir/osint-mapper',
        tabId: 'osint-mapper',
        label: 'OSINT Mapper',
        desc: 'Build a mind-map of an investigation - nodes are entities, edges are pivots.',
        compVar: 'OsintMapper',
      },
      {
        path: '/dfir/breach',
        tabId: 'breach',
        label: 'Breach Lookup',
        desc: 'Email / username / domain - cross-correlate public breach corpora.',
        compVar: 'Breach',
      },
      {
        path: '/dfir/image-intel',
        tabId: 'image-intel',
        label: 'Image Intelligence',
        desc: 'Image analysis - reverse search, perceptual fingerprinting, and OCR screenshot intelligence.',
        compVar: 'ImageIntel',
        keywords: ['image', 'reverse', 'fingerprint', 'phash', 'dhash', 'screenshot', 'ocr'],
      },
      {
        path: '/dfir/brand-impersonation',
        tabId: 'brand-impersonation',
        label: 'Brand Impersonation',
        desc: 'Detect typosquats / look-alike domains targeting your brand.',
        compVar: 'BrandImpersonation',
      },
      {
        path: '/dfir/intelx',
        tabId: 'intelx',
        label: 'IntelligenceX Search',
        desc: 'Leaked data + phonebook search via IntelligenceX — emails, domains, BTC, IBANs, paste sites, breach archives.',
        compVar: 'IntelXPage',
        keywords: ['intelx', 'leak', 'breach', 'phonebook', 'email', 'domain', 'btc', 'iban'],
      },
      {
        path: '/dfir/truecaller',
        tabId: 'truecaller',
        label: 'Truecaller Lookup',
        desc: 'Reverse phone lookup via Truecaller — caller name, carrier, spam score, and location data.',
        compVar: 'TruecallerPage',
        keywords: ['truecaller', 'phone', 'reverse', 'caller', 'spam', 'carrier'],
      },
      {
        path: '/dfir/nhi-scan',
        tabId: 'nhi-scan',
        label: 'NHI Scanner',
        desc: 'Inventory and risk-tier non-human & agent identities (service accounts, API keys, AI agents) against the OWASP NHI Top 10 - deterministic Tier 1-4 rules with least-privilege remediation for every finding.',
        compVar: 'NhiScanPage',
        badge: 'new',
        keywords: [
          'nhi',
          'non-human identity',
          'agent',
          'service account',
          'api key',
          'secret',
          'owasp',
          'tier',
          'risk',
          'iam',
          'governance',
        ],
      },
    ],
  },
  {
    id: 'vuln',
    label: 'Vulnerabilities',
    blurb: 'CVE lookup, prioritisation, exploit intel, and dependency scanning - know what to patch first.',
    icon: AlertTriangle,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    pages: [
      {
        path: '/dfir/cve',
        tabId: 'cve',
        label: 'CVE Lookup',
        desc: 'Single-CVE detail - NVD, KEV, EPSS, exploit availability.',
        compVar: 'Cve',
      },
      {
        path: '/dfir/cve-prioritizer',
        tabId: 'cve-prioritizer',
        label: 'CVE Prioritizer',
        desc: 'CVSS + EPSS + KEV + ransomware-use - single patch-priority call.',
        compVar: 'CvePrioritizer',
      },
      {
        path: '/dfir/vuln-toolkit',
        tabId: 'vuln-toolkit',
        label: 'CVE Resources Catalog',
        desc: 'Curated list of CVE databases, exploit trackers, vendor PSIRTs.',
        compVar: 'VulnToolkitCatalog',
      },
      {
        path: '/dfir/osv-scan',
        tabId: 'osv-scan',
        label: 'OSV Dependency Scan',
        desc: 'Paste a manifest.json / package-lock / requirements.txt - known vulns.',
        compVar: 'OsvScanner',
      },
      {
        path: '/dfir/cve-risk-matrix',
        tabId: 'cve-risk-matrix',
        label: 'CVE Risk Matrix',
        desc: 'CTI priority score (CVSS + EPSS + KEV + recency) plotted against CVSS — quadrant scatter plot + sortable table + SSVC-V decisions.',
        compVar: 'CveRiskMatrix',
        badge: 'new',
        keywords: ['cve', 'risk', 'matrix', 'scoring', 'epss', 'kev', 'ssvc'],
      },
    ],
  },
  {
    id: 'detection',
    label: 'Detection Engineering',
    blurb: 'Author, convert, and test detection rules - Sigma, KQL, SPL, YARA, ATT&CK mapping, hunting queries.',
    icon: Shield,
    tone: 'text-brand-700 dark:text-brand-300 border-brand-500/30 bg-brand-500/10',
    pages: [
      {
        path: '/dfir/rule-converter',
        tabId: 'rule-converter',
        label: 'Rule Converter',
        desc: 'Sigma - KQL - SPL - YARA via one canonical IR.',
        compVar: 'RuleConverter',
      },

      {
        path: '/dfir/yara-workbench',
        tabId: 'yara-workbench',
        label: 'YARA Workbench',
        desc: 'Collaborative YARA editor with malware test corpus.',
        compVar: 'YaraWorkbench',
      },

      {
        path: '/dfir/threat-graph',
        tabId: 'threat-graph',
        label: 'Threat Graph',
        desc: 'Indicator - relationship graph - visual pivot from any node.',
        compVar: 'ThreatGraph',
      },
      {
        path: '/dfir/detection-chokepoints',
        tabId: 'detection-chokepoints',
        label: 'Detection Chokepoints',
        desc: 'Invariant detection points - prerequisites attackers cannot bypass, mapped to MITRE ATT&CK.',
        compVar: 'DetectionChokepoints',
        keywords: ['chokepoint', 'detection', 'mitre', 'kill-chain'],
      },
      {
        path: '/dfir/ir-playbooks',
        tabId: 'ir-playbooks',
        label: 'IR Playbooks',
        desc: 'Step-by-step playbooks for common incident types.',
        compVar: 'IrPlaybooks',
      },
      {
        path: '/dfir/car',
        tabId: 'car',
        label: 'MITRE CAR',
        desc: 'Cyber Analytics Repository - validated detection analytics mapped to ATT&CK.',
        compVar: 'Car',
        keywords: ['car', 'analytics', 'detections', 'mitre'],
      },
      {
        path: '/dfir/capec',
        tabId: 'capec',
        label: 'MITRE CAPEC',
        desc: 'Attack patterns - how weaknesses get exploited, with CWE and ATT&CK links.',
        compVar: 'Capec',
        keywords: ['capec', 'attack patterns', 'cwe'],
      },
      {
        path: '/dfir/engage',
        tabId: 'engage',
        label: 'MITRE Engage',
        desc: 'Adversary engagement - deception and denial approaches by goal and phase.',
        compVar: 'Engage',
        keywords: ['engage', 'deception', 'honeypot', 'denial'],
      },

      {
        path: '/dfir/siem-library',
        tabId: 'siem-library',
        label: 'SIEM Use-Case Library',
        desc: '60 detection use-cases across 16 categories — KQL + SPL starter rules with MITRE mapping.',
        compVar: 'SiemLibrary',
        badge: 'new',
        keywords: ['siem', 'detection', 'kql', 'spl', 'use-case', 'rule'],
      },
      {
        path: '/dfir/hunt-hypotheses',
        tabId: 'hunt-hypotheses',
        label: 'Hunting Hypothesis Library',
        desc: '154 hunt hypotheses across 12 MITRE tactics — technique-driven, data-source-aware starter queries.',
        compVar: 'HuntHypotheses',
        badge: 'new',
        keywords: ['hunting', 'hypothesis', 'mitre', 'kql', 'spl', 'starter query'],
      },
      {
        path: '/dfir/sysmon-config',
        tabId: 'sysmon-config',
        label: 'Sysmon Config Generator',
        desc: 'Build v15 Sysmon XML configs — verbose, baseline, and lean presets with field-level exclude mode.',
        compVar: 'SysmonConfig',
        badge: 'new',
        keywords: ['sysmon', 'xml', 'config', 'detection', 'endpoint'],
      },
    ],
  },
  {
    id: 'stix-taxii',
    label: 'STIX / TAXII',
    blurb: 'STIX 2.1 bundle builder, TAXII server, and viewable graph - interoperable CTI artefacts.',
    icon: Share2,
    tone: 'text-teal-700 dark:text-teal-300 border-teal-500/30 bg-teal-500/10',
    pages: [
      {
        path: '/dfir/stix-workbench',
        tabId: 'stix-workbench',
        label: 'STIX Workbench',
        desc: 'Build, view, and export STIX 2.x bundles (canonical entry - /dfir/stix, /dfir/stix-builder, /dfir/taxii, /dfir/report-ingest all redirect here).',
        compVar: 'StixWorkbench',
      },
    ],
  },
  {
    id: 'cloud',
    label: 'Cloud Security',
    blurb: 'IAM, network, secrets, and configuration analysis for AWS, GCP, Azure, and Kubernetes.',
    icon: Cloud,
    tone: 'text-brand-700 dark:text-brand-300 border-brand-500/30 bg-brand-500/10',
    pages: [
      {
        path: '/dfir/iam-hub',
        tabId: 'iam-hub',
        label: 'IAM & RBAC Hub',
        desc: 'Cloud identity analysis - AWS, GCP, Azure, and Kubernetes RBAC policy analyzers.',
        compVar: 'IamHub',
        keywords: ['iam', 'rbac', 'aws', 'gcp', 'azure', 'k8s', 'kubernetes', 'privilege', 'escalation'],
      },

      {
        path: '/dfir/sg-analyzer',
        tabId: 'sg-analyzer',
        label: 'Security Group Analyzer',
        desc: 'AWS security group visualizer - 0.0.0.0/0 + port exposure heatmap.',
        compVar: 'SecurityGroupAnalyzer',
      },
      {
        path: '/dfir/cloudtrail-triage',
        tabId: 'cloudtrail-triage',
        label: 'CloudTrail Triage',
        desc: 'Filter CloudTrail logs for an incident timeframe - IAM, EC2, S3, KMS.',
        compVar: 'CloudTrailTriage',
      },

      {
        path: '/dfir/terraform-scan',
        tabId: 'terraform-scan',
        label: 'Terraform Scanner',
        desc: 'Static analysis of HCL - misconfigurations + drift.',
        compVar: 'TerraformScanner',
      },
      {
        path: '/dfir/nhi',
        tabId: 'nhi',
        label: 'Non-Human Identity (NHI)',
        desc: 'Catalogue service accounts, API keys, OAuth grants.',
        compVar: 'Nhi',
      },
      {
        path: '/dfir/zero-trust-ai-agents',
        tabId: 'zero-trust-ai-agents',
        label: 'Zero-Trust AI Agents',
        desc: 'Verify identity + intent for autonomous agent actions.',
        compVar: 'ZeroTrustAiAgents',
        keywords: ['zero trust', 'agent', 'identity'],
      },
    ],
  },
  {
    id: 'ai-security',
    label: 'AI Security',
    blurb: 'LLM red-teaming, prompt-injection defense, MCP audit, and agent attack-surface analysis.',
    icon: Sparkles,
    tone: 'text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/30 bg-fuchsia-500/10',
    pages: [
      {
        path: '/dfir/prompt-injection',
        tabId: 'prompt-injection',
        label: 'Prompt Injection',
        desc: 'Test a prompt against a curated set of injection payloads.',
        compVar: 'PromptInjection',
      },
      {
        path: '/dfir/pi-taxonomy',
        tabId: 'pi-taxonomy',
        label: 'PI Taxonomy',
        desc: 'Arcanum Prompt Injection Taxonomy - 172 classified attack nodes.',
        compVar: 'PiTaxonomy',
      },
      {
        path: '/dfir/mcp-audit',
        tabId: 'mcp-audit',
        label: 'MCP Audit',
        desc: 'Audit a Model Context Protocol server for tool-poisoning vectors.',
        compVar: 'McpAudit',
      },
      {
        path: '/dfir/agent-suite',
        tabId: 'agent-suite',
        label: 'Agent Suite',
        desc: 'AI agent investigation - tool-call analysis, observable enrichment, and attack-surface mapping.',
        compVar: 'AgentSuite',
        keywords: ['agent', 'investigator', 'enrich', 'map', 'ai', 'tool calls', 'exfil'],
      },

      {
        path: '/dfir/ai-threats',
        tabId: 'ai-threats',
        label: 'AI Threat Actors',
        desc: 'Tracked real-world threat-actor uses of AI/LLMs - 79 entries, MITRE ATT&CK mapped, from the Cybershujin tracker.',
        compVar: 'AIThreats',
        badge: 'new',
        keywords: ['ai', 'llm', 'threat actor', 'apt', 'ttps', 'cybershujin'],
      },
      {
        path: '/dfir/ai-suite',
        tabId: 'ai-suite',
        label: 'AI Suite',
        desc: 'AI-assisted investigation - incident summarisation, query generation, timeline reconstruction, malware briefing, and IOC verdicts.',
        compVar: 'AiSuite',
        keywords: ['ai', 'insight', 'querycraft', 'chrono', 'malbrief', 'verdikt', 'llm', 'copilot'],
      },
    ],
  },
  {
    id: 'api',
    label: 'API & Application Security',
    blurb: 'OpenAPI, GraphQL, JWT, secrets, and headers - application-layer security analysis.',
    icon: Code2,
    tone: 'text-emerald-700 dark:text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
    pages: [
      {
        path: '/dfir/openapi-audit',
        tabId: 'openapi-audit',
        label: 'OpenAPI Auditor',
        desc: 'Lint an OpenAPI spec - missing auth, schema issues, PII exposure.',
        compVar: 'OpenApiAuditor',
      },
      {
        path: '/dfir/graphql-audit',
        tabId: 'graphql-audit',
        label: 'GraphQL Auditor',
        desc: 'Introspection + query depth/complexity + authz analysis.',
        compVar: 'GraphqlAuditor',
      },
      {
        path: '/dfir/jwt',
        tabId: 'jwt',
        label: 'JWT Inspector',
        desc: 'Decode - verify - alg-confusion check - claim analysis.',
        compVar: 'JwtInspect',
      },

      {
        path: '/dfir/sec-headers-live',
        tabId: 'sec-headers-live',
        label: 'Live Security Headers',
        desc: 'Third-party live HSTS/CSP/X-Frame-Options scan via IntoDNS.ai with ready-to-paste Nginx/Apache/Caddy/Cloudflare configs.',
        compVar: 'SecHeadersLive',
      },
      {
        path: '/dfir/secret-scan',
        tabId: 'secret-scan',
        label: 'Secret Scanner',
        desc: 'Scan a text blob / repo for API keys, tokens, private keys.',
        compVar: 'SecretScanner',
      },
      {
        path: '/dfir/medusa-scan',
        tabId: 'medusa-scan',
        label: 'Medusa Scanner',
        desc: 'AI-first security scanner - SAST (Python/JS/Go/Rust/PHP), secrets, prompt injection detection. 140+ rules, runs entirely in browser.',
        compVar: 'MedusaScanner',
        badge: 'new',
        keywords: ['sast', 'secrets', 'prompt injection', 'ai security', 'static analysis', 'medusa', 'code scan'],
      },
      {
        path: '/dfir/google-dorks',
        tabId: 'google-dorks',
        label: 'Google Dorks Builder',
        desc: 'Compose a Google dork for a target - site:, inurl:, filetype:.',
        compVar: 'GoogleDorks',
      },

      {
        path: '/dfir/log-parser',
        tabId: 'log-parser',
        label: 'Log Parser',
        desc: 'Generic log parser - pattern detection + anomaly highlighting.',
        compVar: 'LogParser',
      },
    ],
  },
  {
    id: 'copilot',
    label: 'AI Copilot & Investigation',
    blurb: 'Conversational copilots and AI-assisted investigation workbenches - natural-language pivots.',
    icon: Bot,
    tone: 'text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/30 bg-fuchsia-500/10',
    pages: [
      {
        path: '/dfir/copilot',
        tabId: 'copilot',
        label: 'DFIR Copilot',
        desc: 'Conversational copilot - ask in plain English, get a runbook.',
        compVar: 'DfirCopilotPage',
      },
    ],
  },
  {
    id: 'reports',
    label: 'Reports & Export',
    blurb: 'Draft investigation reports, ingest external reports, and export IOCs to any standard format.',
    icon: ScrollText,
    tone: 'text-pink-700 dark:text-pink-300 border-pink-500/30 bg-pink-500/10',
    pages: [
      {
        path: '/dfir/report-hub',
        tabId: 'report-hub',
        label: 'Report Hub',
        desc: 'Analyze external reports and compose investigation reports - AI summarisation, IOC extraction, MITRE mapping, PDF/DOCX export.',
        compVar: 'ReportHub',
        keywords: ['report', 'analyzer', 'composer', 'ioc', 'mitre', 'stix', 'pdf', 'docx'],
      },

      {
        path: '/dfir/blocklists',
        tabId: 'blocklists',
        label: 'Blocklist Export',
        desc: 'Generate network blocklists (pfSense, MikroTik, Cisco) from IOCs.',
        compVar: 'Blocklists',
      },
    ],
  },
  {
    id: 'grc',
    label: 'GRC & Posture',
    blurb: 'Compliance, maturity, tabletop exercises, and reference frameworks - policy and posture.',
    icon: Scale,
    tone: 'text-emerald-700 dark:text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
    pages: [
      {
        path: '/dfir/grc',
        tabId: 'grc',
        label: 'GRC Toolkit',
        desc: 'Control mapping - risk register - vendor assessment.',
        compVar: 'Grc',
      },
      {
        path: '/dfir/lolbins',
        tabId: 'lolbins',
        label: 'LOLBins',
        desc: 'Living-off-the-land binaries - search by binary or behaviour.',
        compVar: 'Lolbins',
      },
      {
        path: '/dfir/lots',
        tabId: 'lots',
        label: 'Living Off Trusted Sites',
        desc: 'Legitimate domains abused for phishing, C2, exfiltration, and downloads.',
        compVar: 'Lots',
        keywords: ['lots', 'trusted sites', 'c2 domains'],
      },
      {
        path: '/dfir/hijacklibs',
        tabId: 'hijacklibs',
        label: 'HijackLibs',
        desc: 'DLL hijacking candidates - sideloading targets with vulnerable executables.',
        compVar: 'Hijacklibs',
        keywords: ['hijacklibs', 'dll sideloading', 't1574'],
      },
      {
        path: '/dfir/veris',
        tabId: 'veris',
        label: 'VERIS Taxonomy',
        desc: 'Incident taxonomy - Actor/Action/Asset/Attribute vocabulary for coding incidents.',
        compVar: 'Veris',
        keywords: ['veris', 'taxonomy', 'incident classification'],
      },
      {
        path: '/dfir/data-classification',
        tabId: 'data-classification',
        label: 'Data Classification',
        desc: 'Tag data with sensitivity + handling requirements.',
        compVar: 'DataClassification',
      },
      {
        path: '/dfir/privacy-hub',
        tabId: 'privacy-hub',
        label: 'Privacy Hub',
        desc: 'GDPR / CCPA references, DPIA templates, privacy notice generator.',
        compVar: 'PrivacyHub',
      },
      {
        path: '/dfir/dlp-scan',
        tabId: 'dlp-scan',
        label: 'DLP Scan',
        desc: 'Data-loss-prevention scan for files + clipboard + screenshots.',
        compVar: 'DlpScan',
      },
      {
        path: '/dfir/linux-triage',
        tabId: 'linux-triage',
        label: 'Linux IR Triage',
        desc: 'Bash one-liners for live Linux incident response.',
        compVar: 'LinuxTriage',
      },
      {
        path: '/dfir/grc-checklists',
        tabId: 'grc-checklists',
        label: 'GRC Checklists',
        desc: 'Control checklists for NIST CSF, ISO 27001, SOC 2, PCI DSS v4, DPDP 2023, CERT-In, SEBI — plus cross-framework mapper.',
        compVar: 'GrcChecklists',
        badge: 'new',
        keywords: ['grc', 'checklist', 'nist', 'iso27001', 'soc2', 'pci', 'dpdp', 'cert-in', 'sebi'],
      },
      {
        path: '/dfir/pqc',
        tabId: 'pqc',
        label: 'Post-Quantum Cryptography',
        desc: 'Algorithm profiles, HNDL threat model, crypto-class readiness assessment, and migration checklist.',
        compVar: 'Pqc',
        badge: 'new',
        keywords: ['post-quantum', 'pqc', 'nist', 'mlkem', 'ml-dsa', 'slh-dsa', 'hndl'],
      },
    ],
  },
  {
    id: 'frameworks',
    label: 'Frameworks & Models',
    blurb:
      'Reference frameworks, attack models, and visual matrices analysts use to structure intrusions and security programs.',
    icon: Workflow,
    tone: 'text-indigo-700 dark:text-indigo-300 border-indigo-500/30 bg-indigo-500/10',
    pages: [
      {
        path: '/dfir/attack-navigator',
        tabId: 'attack-navigator',
        label: 'MITRE ATT&CK Navigator',
        desc: 'Layered ATT&CK matrix - coverage heatmap, gap analysis.',
        compVar: 'AttackNavigator',
        keywords: ['mitre', 'att&ck', 'matrix', 'technique', 'coverage', 'heatmap'],
      },
      {
        path: '/dfir/kill-chain',
        tabId: 'kill-chain',
        label: 'Cyber Kill Chain',
        desc: 'Lockheed Martin 7-phase kill chain with ATT&CK cross-links.',
        compVar: 'KillChain',
      },
      {
        path: '/dfir/diamond',
        tabId: 'diamond',
        label: 'Diamond Model',
        desc: 'Adversary - capability - infrastructure - victim - reference.',
        compVar: 'Diamond',
      },
      {
        path: '/dfir/owasp',
        tabId: 'owasp',
        label: 'OWASP Top 10',
        desc: 'Web 2021 - API 2023 - LLM 2025 reference + checklist.',
        compVar: 'Owasp',
      },
      {
        path: '/dfir/cloak',
        tabId: 'cloak',
        label: 'CLOAK — Anonymity Framework',
        desc: 'Concealment Layers for Online Anonymity and Knowledge — adversary tactics, techniques, sub-techniques, and procedures.',
        compVar: 'Cloak',
        badge: 'new',
        keywords: ['cloak', 'anonymity', 'tor', 'privacy', 'obfuscation'],
      },
      {
        path: '/dfir/frameworks/tid-cmm',
        tabId: 'tid-cmm',
        label: 'TID-CMM — Detection Maturity',
        desc: 'Threat-Informed Detection Capability Maturity Model v1.5 — 8 domains, 58 sub-capabilities, ATT&CK v19.2. Interactive browser-only assessment with C1–C5 ceilings.',
        compVar: 'TidCmm',
        badge: 'new',
        keywords: [
          'tid-cmm',
          'detection maturity',
          'threat-informed',
          'att&ck',
          'maturity model',
          'utiom',
          'reza adineh',
        ],
      },
      {
        path: '/dfir/frameworks/utiom',
        tabId: 'utiom',
        label: 'UTIOM — Operations Model',
        desc: 'Unified Threat-Informed Operations Model v1.3 — 7 phases, 3 pillars, V-model validation. Interactive 7-phase self-check plus doctrine.',
        compVar: 'Utiom',
        badge: 'new',
        keywords: ['utiom', 'soc operating model', 'lifecycle', 'threat-informed', 'crown jewels', 'v-model'],
      },
    ],
  },
];

/* ------------------------------------------------------------------ */
/*  Lookup helpers                                                     */
/* ------------------------------------------------------------------ */

const HUB_BY_ID = new Map(HUB_META.map((h) => [h.id, h]));
const PAGE_BY_PATH = new Map<string, { hub: HubMeta; page: HubPage }>();
for (const hub of HUB_META) {
  for (const page of hub.pages) {
    PAGE_BY_PATH.set(page.path, { hub, page });
  }
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
