/**
 * Auto-extracted from ToolGrid.tsx so the component file can satisfy the
 * react-refresh/only-export-components rule - Fast Refresh only works when
 * a file exports components and nothing else. Data (SECTIONS, EXTERNAL,
 * Tool / Section types, TOOL_COUNT) lives here; the renderer lives in
 * ToolGrid.tsx and imports from this module.
 */
import {
  Hash,
  ShieldAlert,
  Globe,
  Radar,
  Clock,
  Users,
  Lock,
  Search,
  Shield,
  Sparkles,
  Eye,
  Network,
  Code2,
  Image as ImageIcon,
  Filter,
  KeyRound,
  Type,
  Unplug,
  Share2,
  ShieldCheck,
  Cloud,
  Plug,
  Crosshair,
  Diamond,
  Mail,
  Terminal,
  ScrollText,
  FileCheck,
  FolderTree,
  Paperclip,
  Scale,
  History,
  Coins,
  Database,
  Smartphone,
  Phone,
  ScanLine,
  ScanSearch,
  Server,
  Activity,
  Fingerprint,
  GitBranch,
  Target,
  BookOpen,
  FolderOpen,
  Map as MapIcon,
  Bot,
  Bug,
  FileText,
  type LucideIcon,
} from 'lucide-react';
import type { FeatureFlag } from '../../lib/features';

export interface Tool {
  path: string;
  label: string;
  desc: string;
  icon: LucideIcon;
  /** One-line example use-case shown on the rich landing card. */
  useCase?: string;
  external?: boolean;
  /**
   * Mark a tool as a "utility" - duplicative of well-known online tools
   * (timestamp converters, hex/base64 decoders, hash calculators,
   * homoglyph viewers). The hub hides utilities behind a toggle so the
   * count of "real" tools reads as the actual depth of the toolkit, not
   * a padded list. The routes still resolve - nothing is deleted, only
   * de-emphasised on the landing.
   */
  utility?: boolean;
  /**
   * What this tool CAN'T do - kept honest. Surfaced on the tool page so
   * a visitor doesn't bounce when they realise the tool isn't a Splunk
   * replacement. Optional; absent means no panel renders.
   */
  cantDo?: string;
  /** Typical 1-line workflow hint (e.g. "Paste IOC → review consensus
   *  → pivot to /threatintel/correlation"). Optional. */
  workflow?: string;
  /**
   * Hide this tool from all nav + search until the named deployment
   * feature flag is enabled (see `GET /api/v1/features` and
   * `src/lib/features.tsx`). Used for dormant self-hosted bridges that
   * only work once an operator sets the matching `*_BRIDGE_URL` secret -
   * no point advertising a tool that just returns a 503 setup hint. The
   * route still exists; direct navigation is handled by a page-level
   * guard that redirects when the flag is off.
   */
  requiresFlag?: FeatureFlag;
}

/**
 * Top-level tool group. Each section belongs to exactly one group so the
 * grid can be sliced into dedicated, less-overwhelming category pages
 * (separate OSINT / AI-sec / Data-security / GRC surfaces) while the
 * full /dfir grid stays as the power-user index.
 */
export type ToolGroup = 'core-dfir' | 'investigation' | 'intelligence' | 'recon' | 'specialized' | 'grc' | 'aisec';

export const GROUP_META: Record<ToolGroup, { label: string; blurb: string }> = {
  'core-dfir': {
    label: 'Core DFIR',
    blurb: 'Triage & analysis - IOC checks, malware triage, file analysis, artifact parsers.',
  },
  investigation: {
    label: 'Investigation',
    blurb: 'Infrastructure & identity - domain/network, assets, email security, vulnerabilities.',
  },
  intelligence: {
    label: 'Intelligence',
    blurb: 'Detection & standards - rule converters, STIX/TAXII, IR playbooks, hunting tools.',
  },
  recon: {
    label: 'Recon & OSINT',
    blurb: 'Identity, network intel, image analysis, dark web, privacy checks.',
  },
  specialized: {
    label: 'Specialized',
    blurb: 'AI security, cloud, API, data security, GRC, case management, deception, platform.',
  },
  grc: {
    label: 'GRC & Posture',
    blurb: 'Compliance, maturity assessments, tabletop exercises, kill chain, OWASP.',
  },
  aisec: {
    label: 'AI Security',
    blurb: 'LLM red-teaming, prompt injection, MCP audit, agent attack surface, ATLAS.',
  },
};

export interface Section {
  id: string;
  label: string;
  /** One-line hint shown under the section heading. */
  blurb: string;
  /** Which dedicated category page this section belongs to. */
  group: ToolGroup;
  tools: Tool[];
}

/**
 * Sections are ordered by typical investigation flow:
 * triage first, then infra, email, intel, detection-engineering, frameworks,
 * AI security, vulns/identity, reference. External resources sit at the end.
 */
export const SECTIONS: Section[] = [
  // ── DFIR / Forensics group ───────────────────────────────────────
  {
    id: 'ioc-triage',
    group: 'core-dfir',
    label: 'IOC Triage',
    blurb: 'Check, extract, and track indicators across 60+ sources.',
    tools: [
      {
        path: '/dfir/ioc-investigate',
        useCase: 'Investigate any indicator across 60+ sources in one place.',
        label: 'IOC Investigator',
        desc: 'Cross-source investigation hub · 3 tabs (check · pivot · hunt) · 60+ sources · IPs · domains · URLs · hashes · emails',
        icon: Crosshair,
      },
      {
        path: '/dfir/extract',
        useCase: 'Pull every IOC out of a threat report instantly.',
        label: 'IOC Extractor',
        desc: 'Pull IOCs from any text blob · refang-aware',
        icon: Filter,
      },
      {
        path: '/dfir/ct-monitor',
        useCase: 'Monitor CT logs for new subdomains on your domains.',
        label: 'Certificate Transparency Monitor',
        desc: 'Watch domains for new certificates · detects suspicious patterns, typosquatting, wildcard certs · crt.sh integration · free unlimited lookups',
        icon: ShieldCheck,
      },
    ],
  },
  {
    id: 'malware-triage',
    group: 'core-dfir',
    label: 'Malware Triage',
    blurb: 'Analyse files, parse stealer logs, and check breach corpora.',
    tools: [
      {
        path: '/dfir/malware-analyzer',
        useCase: 'Static + dynamic analysis of any suspicious file.',
        label: 'Malware Analyzer',
        desc: '4 tabs (scan · capabilities · sample · sandbox) · PE / ELF / Mach-O / scripts · import hashing · section entropy · 11 engines',
        icon: Shield,
      },
      {
        path: '/dfir/stealer-parser',
        useCase: 'Parse infostealer logs (Redline, Raccoon, Vidar, Lumma).',
        label: 'Infostealer Log Parser',
        desc: 'Paste stealer log dumps · auto-detects format (Redline, Raccoon, Vidar, Lumma, StealC) · extracts credentials, cookies, autofill, crypto wallets, system info · 100% client-side',
        icon: Database,
      },
      {
        path: '/dfir/linux-triage',
        useCase: 'Triage a Linux box from its auth.log + bash_history.',
        label: 'Linux IR Triage',
        desc: 'Paste auth.log / secure / crontab / bash_history · flags SSH brute force, success-after-failure, root login, new sudoers, cron persistence, reverse-shell & download-cradle one-liners · 100% client-side',
        icon: Terminal,
      },
    ],
  },
  {
    id: 'file-analysis',
    group: 'core-dfir',
    label: 'File Analysis',
    blurb: 'Decode, hash, and inspect binaries and encoded payloads.',
    tools: [
      {
        path: '/dfir/codec',
        useCase: 'Decode an obfuscated payload string fast.',
        label: 'Decoder',
        desc: 'Base64 · URL · multi-pass',
        icon: Code2,
        utility: true,
      },
      {
        path: '/dfir/codec',
        useCase: 'Build and round-trip an encoding chain.',
        label: 'Encoder',
        desc: 'Reverse of Decoder. base64 / url / hex / binary / rot13 with chain builder + round-trip',
        icon: Type,
        utility: true,
      },
      {
        path: '/dfir/powershell-deobf',
        useCase: 'Unwrap an encoded PowerShell command.',
        label: 'PowerShell Deobfuscator',
        desc: 'EncodedCommand · char-arrays · format-strings · multi-pass with diff trace',
        icon: Terminal,
      },
      {
        path: '/dfir/powershell-analyzer',
        useCase: 'Static-analyze a PowerShell script for malicious behavior.',
        label: 'PowerShell Security Analyzer',
        desc: '250+ signatures · MITRE ATT&CK mapping · IOC extraction · obfuscation scoring · risk score · 100% client-side',
        icon: ShieldCheck,
      },
      {
        path: '/dfir/apk-analyzer',
        useCase: 'Analyze an Android APK for malware indicators.',
        label: 'APK Analyzer',
        desc: 'Drop .apk · permissions · package info · DEX count · strings · IOCs · suspicious patterns · hashes · client-side',
        icon: Smartphone,
      },
      {
        path: '/dfir/hash-calc',
        useCase: 'Verify a file hash against a known IOC.',
        label: 'Hash Calculator',
        desc: 'MD5 · SHA-1/256/384/512 for text or a dropped file · client-side',
        icon: Hash,
        utility: true,
      },
      {
        path: '/dfir/timestamp',
        useCase: 'Decode a FILETIME from a registry artifact.',
        label: 'Timestamp Converter',
        desc: 'Unix s/ms/µs · Windows FILETIME · WebKit/Chrome · Apple Cocoa · ISO 8601. all at once',
        icon: Clock,
        utility: true,
      },
      {
        path: '/dfir/plist-protobuf',
        useCase: 'Preview a plist manifest or protobuf blob.',
        label: 'Plist & Protobuf Decoder',
        desc: 'Apple binary/XML plists + schema-less protobuf · hand-rolled parsers · client-side',
        icon: Code2,
        utility: true,
      },
    ],
  },
  {
    id: 'artifact-parsers',
    group: 'core-dfir',
    label: 'Artifact Parsers & Logs',
    blurb: 'PCAP, registry, EVTX, SQLite, browser and mobile artifacts.',
    tools: [
      {
        path: '/dfir/pcap-triage',
        useCase: 'Extract DNS and HTTP from a capture quickly.',
        label: 'PCAP Triage',
        desc: '.pcap/.pcapng → protocol mix · top talkers · conversations · DNS + HTTP extraction · client-side',
        icon: Network,
      },
      {
        path: '/dfir/registry-hive',
        useCase: 'Pull autoruns and USB history from a hive.',
        label: 'Registry Hive Explorer',
        desc: 'Raw regf hive (SYSTEM/SOFTWARE/NTUSER.DAT) → key/value tree · hand-rolled parser · client-side',
        icon: FolderTree,
      },
      {
        path: '/dfir/evtx',
        useCase: 'Review key Windows security events from an export.',
        label: 'EVTX Parser Lite',
        desc: 'Windows .evtx → per-record timestamp + readable BinXML strings · triage view · client-side',
        icon: ScrollText,
      },
      {
        path: '/dfir/sqlite',
        useCase: 'Inspect browser history without uploading it.',
        label: 'SQLite Artifact Explorer',
        desc: 'Open browser/app SQLite DBs · schema + row browse + read queries · lazy WASM · client-side',
        icon: Database,
      },
      {
        path: '/dfir/ios-backup',
        useCase: 'Review an iOS backup file inventory for triage.',
        label: 'iOS Backup Explorer',
        desc: 'iOS Manifest.db → backed-up file inventory by domain/path · lazy WASM · client-side',
        icon: Smartphone,
      },
      {
        path: '/dfir/web-log',
        useCase: 'Triage web logs and export suspicious hits.',
        label: 'Web Server Log Analyzer',
        desc: 'Apache/Nginx access logs → SQLi/XSS/traversal/scanner heuristics · CSV export · client-side',
        icon: FileCheck,
      },
      {
        path: '/dfir/prefetch',
        useCase: 'Recover execution metadata from a .pf artifact.',
        label: 'Prefetch Analyzer Lite',
        desc: 'Windows .pf incl. Win10+ MAM/LZXPRESS-Huffman · exe · run count · last runs · referenced files',
        icon: Activity,
      },
      {
        path: '/dfir/blocklists',
        useCase: 'Download daily-generated firewall blocklists from cross-source IOC consensus.',
        label: 'Blocklist Export',
        desc: 'pfSense · iptables · Suricata · IPs from 2+ independent feeds · daily cron generation · one-click download',
        icon: Shield,
      },
    ],
  },
  // ── IR group ──────────────────────────────────────────────────────
  {
    id: 'domain-network',
    group: 'investigation',
    label: 'Domain & Network',
    blurb: 'WHOIS, DNS, reputation, and infrastructure lookups.',
    tools: [
      {
        path: '/dfir/domain-investigator',
        useCase: 'Investigate any domain across 6+ tools in one place.',
        label: 'Domain Investigator',
        desc: 'Cross-source domain hub · 6 tabs (lookup · webcheck · reputation · full-spectrum · web-scan) · WHOIS · DNS · CT · TLS · Shodan',
        icon: Globe,
      },
      {
        path: '/dfir/whois-history',
        useCase: 'Track ownership changes and find related domains.',
        label: 'WHOIS History Explorer',
        desc: 'Registration timeline · ownership transfers · registrar changes · pivot by registrant email/org/nameserver · inspired by etugen.io',
        icon: Globe,
      },
      {
        path: '/dfir/asn',
        useCase: 'Map an IP to its ASN and abuse contacts.',
        label: 'ASN Lookup',
        desc: 'BGP · prefixes · abuse contacts',
        icon: Network,
      },
      {
        path: '/dfir/exposure',
        useCase: 'Enumerate subdomains and open ports fast.',
        label: 'Exposure Scanner',
        desc: 'Subdomains + open ports',
        icon: Radar,
      },
      {
        path: '/dfir/subdomain-takeover',
        useCase: 'Detect a dangling subdomain takeover.',
        label: 'Subdomain Takeover',
        desc: 'CNAME chain + 15 dangling-service fingerprints',
        icon: Unplug,
      },
      {
        path: '/dfir/cert-search',
        useCase: 'Find subdomains via certificate transparency.',
        label: 'Certificate Search',
        desc: 'CT log enumeration via SSLMate Cert Spotter. find subdomains by their issued certs',
        icon: ShieldCheck,
      },
      {
        path: '/dfir/dnscope',
        useCase: 'Deep-dive domain infrastructure across 14 data dimensions.',
        label: 'DNSCOPE Infrastructure Map',
        desc: 'WHOIS · DNS · email · ASN · passive DNS · certificates · subdomains · lookalikes · ports · fingerprints · cloud · CDN · URLScan · 14 parallel modules',
        icon: Globe,
      },
    ],
  },
  {
    id: 'asset-surface',
    group: 'investigation',
    label: 'Asset & Attack Surface',
    blurb: 'Exposed-host analysis, asset intel, and web scanning.',
    tools: [
      {
        path: '/dfir/asset-intel',
        useCase: 'Unified IP and domain asset reconnaissance - exposed host, WHOIS history, and artifact analysis.',
        label: 'Asset Intelligence',
        desc: 'IP → exposed host with open ports, CVEs, artifacts · domain → WHOIS timeline, registration changes, related domains · auto-detects input type',
        icon: ScanLine,
      },
      {
        path: '/dfir/open-directory',
        useCase: 'Scan for exposed open directories and malware staging.',
        label: 'Open Directory Scanner',
        desc: 'Detect directory listings · classify files by risk · identify credential dumps, configs, malware · inspired by etugen.io trashpile',
        icon: FolderOpen,
      },
      {
        path: '/dfir/exposed-host',
        useCase: 'Map every exposed service on a host.',
        label: 'Exposed Host',
        desc: 'Shodan + Censys + port scan + HTTP banner + service fingerprint + linked CVEs, all stitched into one host card.',
        icon: Server,
      },
    ],
  },
  // ── Email Security ────────────────────────────────────────────────
  {
    id: 'email',
    group: 'investigation',
    label: 'Email Security',
    blurb: 'Phishing analysis and BEC-defense for the domain you protect.',
    tools: [
      {
        path: '/dfir/phishing',
        useCase: 'Triage a phishing email in seconds.',
        label: 'Phishing Analyzer',
        desc: 'Email headers · auth · embedded URLs · URL auto-analysis · kit fingerprint',
        icon: ShieldAlert,
      },
      {
        path: '/dfir/phishing#fingerprint',
        useCase: 'Identify phishing kits by structural page hash.',
        label: 'Phishing Kit Fingerprint',
        desc: 'Server-side fetch → browser-side SHA-256 → KV-backed kit lookup · 30-day retention',
        icon: Fingerprint,
      },
      {
        path: '/dfir/eml',
        useCase: 'Pull attachments and IOCs from an .eml.',
        label: 'EML Attachment Extractor',
        desc: 'Drop a raw .eml · decode multipart · SHA-256 / SHA-1 / MD5 each attachment · one-click pivot to file lookup',
        icon: Paperclip,
      },
      {
        path: '/dfir/email-rep',
        useCase: 'Check a domain email reputation.',
        label: 'Email Reputation',
        desc: 'MX · SPF · DKIM · DMARC · BIMI · MTA-STS · TLS-RPT · 13 IP blacklists · 6 domain blacklists · live DNSBL via DoH · composite score',
        icon: Mail,
      },
      {
        path: '/dfir/email-defense',
        useCase: 'Score BEC risk for the domain you protect.',
        cantDo:
          "Reads DNS only - won't catch a domain that auths correctly but sends from a compromised mailbox. The score is the floor of attacker effort, not the ceiling of your safety.",
        workflow:
          'Enter your domain → review the rule failures with attack-scenario context → fix in DNS → recheck → set DMARC p=reject when alignment is clean.',
        label: 'Email Defense / BEC Score',
        desc: 'SPF · DMARC · DKIM · MTA-STS · spoofability score · attack scenarios per gap',
        icon: Mail,
      },
      {
        path: '/dfir/dmarc-analyzer',
        useCase: 'Parse DMARC RUA XML reports instantly.',
        label: 'DMARC RUA Analyzer',
        desc: 'Upload XML · in-browser parse · per-IP SPF/DKIM/DMARC · pass rate · CSV export · zero server storage',
        icon: ShieldCheck,
      },
    ],
  },
  {
    id: 'vulns-identity',
    group: 'investigation',
    label: 'Vulnerabilities & Identity',
    blurb: 'CVE triage, breach exposure, and identity verification.',
    tools: [
      {
        path: '/dfir/cve',
        useCase: 'Look up a CVE with KEV and EPSS context.',
        label: 'CVE Lookup',
        desc: 'NVD · CVSS · EPSS · KEV · combined patch-priority score with rationale',
        icon: Search,
      },
      {
        path: '/dfir/vuln-toolkit',
        useCase: 'Browse CVE exploit toolkits and PoC releases for patch prioritization.',
        label: 'Vulnerability Toolkit Catalog',
        desc: 'Curated CVE exploit catalog · severity/vendor/type filtering · CVSS scoring · NVD/vendor advisory links · exploit availability flags',
        icon: Bug,
      },
      {
        path: '/dfir/breach',
        useCase: 'Check a password against breach corpora.',
        label: 'Breach Checker',
        desc: 'Pwned password · k-anonymity',
        icon: Shield,
      },
      {
        path: '/dfir/jwt',
        useCase: 'Decode a JWT and flag weak claims.',
        label: 'JWT Inspector',
        desc: 'Decode + flag alg=none, exp, weak claims',
        icon: KeyRound,
      },
    ],
  },
  // ── OSINT group ───────────────────────────────────────────────────
  {
    id: 'identity-search',
    group: 'recon',
    label: 'Identity & Search',
    blurb: 'Username pivots, Google dorking, archive recon.',
    tools: [
      {
        path: '/dfir/username-investigator',
        useCase: 'Investigate a username across 60+ platforms in one place.',
        label: 'Username Investigator',
        desc: 'Cross-platform identity hub · 3 tabs (lookup · pivot · osint) · KagamiID-style profiles · Sherlock 50+ · 60+ server-side',
        icon: Users,
      },
      {
        path: '/dfir/phone-hub',
        useCase: 'Investigate a phone number - reverse lookup, carrier, geolocation, messaging presence.',
        label: 'Phone OSINT',
        desc: 'E.164 parser · 20+ lookup services (TrueCaller, NumLookup, NumVerify, WhatsApp/Telegram check) · reverse lookup, carrier, geolocation, breach, social · category filtering',
        icon: Phone,
      },
      {
        path: '/dfir/google-dorks',
        useCase: 'Run Google search with operator hints to surface OSINT leads.',
        label: 'Google Dorks',
        desc: 'SerpAPI-backed · `site:` `inurl:` `filetype:` `intitle:` · 6 quick-start presets (exposed .env, paste leaks, SQL dumps, S3, GitHub) · edge-cached 1h to stretch the free SerpAPI tier',
        icon: Search,
      },
      {
        path: '/dfir/wayback',
        useCase: 'Build an archive timeline for a URL.',
        label: 'Wayback Machine Pivot',
        desc: 'Internet Archive CDX timeline · first/last seen · status-code distribution · snapshot links',
        icon: History,
      },
      {
        path: '/dfir/socmint',
        useCase: 'Pivot an email or handle to OSINT sources.',
        label: 'SOCMINT Pivots',
        desc: 'Email/domain/handle/name → categorised OSINT lookup links · breach + B2B (ZoomInfo, Apollo, Hunter, RocketReach) + social + dev + paste dorks',
        icon: Users,
      },
      {
        path: '/dfir/osint-mapper',
        useCase: 'Map identifiers and locations for an investigation.',
        label: 'OSINT Mapper',
        desc: 'Node graph of identifiers (social/phone/plate/person/vehicle) + Leaflet street map · click-to-pin w/ Nominatim geocoding · cross-link identifiers↔locations · local-only · .osint.json import/export',
        icon: MapIcon,
      },
    ],
  },
  {
    id: 'network-url-intel',
    group: 'recon',
    label: 'Network & URL Intel',
    blurb: 'IP geo, URL reputation, crypto tracing.',
    tools: [
      {
        path: '/dfir/host-graph',
        useCase: 'Map an IP to its ASN, prefix, abuse contact, and peers.',
        label: 'Host Graph',
        desc: 'IP / ASN / CIDR enrichment · RDAP · abuse contact · prefix tree · clickable graph to pivot across network footprint',
        icon: Network,
      },
      {
        path: '/dfir/url-preview',
        useCase: 'Safely preview a suspicious link.',
        label: 'URL Preview',
        desc: 'Server-side metadata · safe fetch · screenshot',
        icon: Eye,
      },
      {
        path: '/dfir/punycode',
        useCase: 'Catch a homograph lookalike domain.',
        label: 'Homograph Detector',
        desc: 'IDN · mixed scripts · brand lookalikes · paste a domain to inspect',
        icon: Type,
        utility: true,
      },
      {
        // Removed 2026-10-11 with the /dfir/tracer route + its 8 API handlers.
        // The card rendered a <Link> to a route that no longer exists, so it
        // was a guaranteed 404 from the DFIR catalog. Redirects preserve the
        // URL for inbound links; the catalog entry has no such need.
        path: '/dfir/catalog',
        useCase: 'Trace fund flows hop-by-hop and map an actor’s on-chain footprint.',
        workflow:
          'Seed an address → click nodes to expand counterparties → confirm hops → inspect tx calldata / find the cash-out path → save, export, or pin to an investigation → watch the address for new movement.',
        cantDo:
          'Not Chainalysis - entity labels are a curated seed + on-the-fly Blockscout/ENS, not an 800M-label index; save / label / watch are admin-gated; native-only value moves (no token-transfer) are not monitored.',
        label: 'Fund-Flow Tracer',
        desc: 'EVM + BTC + Tron fund-flow graph · entity labels + risk score · calldata/TxDataHiding inspector · BTC common-input clustering · auto-path to CEX/Mixer · save/export (JSON/CSV/PNG) + investigation pinning · OSINT identity pivot · address monitoring & alerts',
        icon: Coins,
      },
      {
        path: '/dfir/image-intel',
        useCase: 'OCR a screenshot and pull entities from the text.',
        label: 'Screenshot Intelligence',
        desc: 'OCR (self-hosted Tesseract) + QR decode + EXIF/GPS · extract URL/IP/email/crypto entities · client-side',
        icon: ScanLine,
      },
    ],
  },
  {
    id: 'image-brand',
    group: 'recon',
    label: 'Image & Brand',
    blurb: 'EXIF, reverse-image search, brand impersonation monitoring.',
    tools: [
      {
        path: '/dfir/exif',
        useCase: 'Extract GPS and camera data from an image.',
        label: 'EXIF Parser',
        desc: 'GPS · camera · client-only · drop image to extract metadata',
        icon: ImageIcon,
      },
      {
        path: '/dfir/image-intel',
        useCase: 'Generate reverse-image search links fast.',
        label: 'Reverse Image Search',
        desc: 'Paste image URL → Google Lens / Bing / Yandex / TinEye / Baidu · pure URL generator · pairs with Phishing',
        icon: ImageIcon,
      },
      {
        path: '/dfir/image-intel',
        useCase: 'Detect a re-uploaded or near-duplicate image.',
        label: 'Image Fingerprint',
        desc: 'In-browser aHash + dHash · compare two images for near-duplicate / re-upload detection',
        icon: ImageIcon,
      },
      {
        path: '/dfir/brand-impersonation',
        useCase: 'Generate lookalike domains to monitor.',
        label: 'Brand Impersonation Explorer',
        desc: 'Typosquat · homoglyph · affix · TLD-swap variants of a brand domain · crt.sh pivots · cross-link to /threatintel/domain-monitor',
        icon: ShieldAlert,
      },
    ],
  },
  {
    id: 'data-sec',
    group: 'specialized',
    label: 'Data Security & DLP',
    blurb: 'Find sensitive data; decide how to handle it.',
    tools: [
      {
        path: '/dfir/dlp-scan',
        useCase: 'Spot sensitive data before it leaks.',
        label: 'Sensitive Data Detector',
        desc: '28 patterns · Luhn / IBAN / Verhoeff / NHS verified · severity + confidence · redact-and-copy',
        icon: ShieldAlert,
      },
      {
        path: '/dfir/data-classification',
        useCase: 'Classify data and pick a handling tier.',
        label: 'Data Classification & Handling',
        desc: 'Tier policies · dataset inventory · matrix view · markdown export',
        icon: FolderTree,
      },
      {
        path: '/dfir/privacy-hub',
        useCase: 'Review data-protection posture quickly.',
        label: 'Privacy & Data-Protection Hub',
        desc: 'GDPR · CCPA / CPRA · DPDP · HIPAA Privacy Rule · PCI DSS · breach-notification timelines',
        icon: Scale,
      },
    ],
  },
  {
    id: 'det-rules',
    group: 'intelligence',
    label: 'Detection Rules & Converters',
    blurb: 'Build, convert, and test detection rules across formats.',
    tools: [
      {
        path: '/dfir/rule-converter',
        useCase: 'Translate a detection between Sigma, KQL, SPL, EQL, YARA.',
        cantDo:
          'Heuristic, not pySigma - reverse-parsing query languages back into the IR recovers only flat `field op "value"` predicates. YARA / DLP / supply-chain carry no field semantics; every lossy step is flagged in the warnings panel.',
        workflow:
          'Pick the source format (Sigma is the most-faithful) → pick a SIEM field-map preset (Defender / ECS / CIM) → paste a rule or load a starter → copy the emitted target.',
        label: 'Rule Converter',
        desc: 'Universal any-to-any detection translation · Sigma · KQL · Splunk SPL · Elastic Lucene/EQL · YARA · DLP regex · supply-chain Semgrep · 100% client-side',
        icon: ScanLine,
      },
      {
        path: '/dfir/yara-workbench',
        useCase: 'Author and test YARA / Sigma rules with a live test corpus.',
        label: 'YARA Workbench',
        desc: 'YARA + Sigma + rule-converter + detection-lab + AI-rule-gen · collaborative editor · 100% client-side',
        icon: ShieldCheck,
      },
      {
        path: '/dfir/cve-prioritizer',
        useCase: 'Decide which CVEs to actually patch this week.',
        label: 'CVE Exploit Prioritizer',
        desc: 'NVD CVSS + FIRST EPSS + CISA KEV → ACT-NOW / SCHEDULE / MONITOR / DEFER verdict · bulk mode',
        icon: Crosshair,
      },
    ],
  },
  {
    id: 'stix-taxii',
    group: 'intelligence',
    label: 'STIX & TAXII',
    blurb: 'Threat intelligence standards, graph analysis, and attack chain mapping.',
    tools: [
      {
        path: '/dfir/stix-workbench',
        useCase: 'In-browser STIX 2.1 workbench for bundles, viewers, servers, and AI-assisted build.',
        label: 'STIX Workbench',
        desc: '3 tabs (viewer · builder · taxii-server) + AI report-ingest · OpenCTI/MISP compatible · client-side',
        icon: Share2,
      },
      {
        path: '/dfir/threat-graph',
        useCase: 'Visualize IOC relationships and discover threat communities.',
        label: 'Threat Intelligence Graph',
        desc: 'Graph DB for threat intel · BFS shortest path · community detection · relationship mapping',
        icon: GitBranch,
      },
      {
        path: '/dfir/insight-ai',
        useCase: 'Generate AI-powered investigation runbooks from alert descriptions.',
        label: 'INSIGHT-AI Runbook Generator',
        desc: 'Paste alert text → multi-mode runbook (triage, playbook, queries, ATT&CK, timeline) · SIEM format selector · export MD/JSON/YAML/TXT',
        icon: Sparkles,
      },
      {
        path: '/dfir/querycraft-ai',
        useCase: 'Build detection queries from natural language descriptions.',
        label: 'QUERYCRAFT-AI Query Builder',
        desc: 'Describe what to detect → KQL, SPL, Sigma, XQL · DETECT/HUNT track · MITRE-mapped · query history',
        icon: Crosshair,
      },
      {
        path: '/dfir/chrono-ai',
        useCase: 'Reconstruct a kill chain timeline from log events.',
        label: 'CHRONO-AI Timeline Reconstruction',
        desc: 'Paste mixed-format logs → visual timeline · kill chain phases · color-coded events · MITRE technique mapping',
        icon: Clock,
      },
      {
        path: '/dfir/malbrief-ai',
        useCase: 'Submit behavioral indicators for AI-powered malware analysis.',
        label: 'MALBRIEF-AI Malware Briefing',
        desc: 'Behavioral indicators → malware classification · MITRE mapping · detection signatures · hunting pivots',
        icon: Bug,
      },
      {
        path: '/dfir/verdikt-ai',
        useCase: 'Combine IOC enrichment with AI analysis for higher-confidence verdicts.',
        label: 'VERDIKT-AI IOC + AI Analysis',
        desc: 'IP/domain/URL/hash → multi-source enrichment + AI narrative · MITRE mapping · detection queries',
        icon: Shield,
      },
    ],
  },
  {
    id: 'ir-hunting',
    group: 'intelligence',
    label: 'IR & Hunting Tools',
    blurb: 'LOLBins reference, log analysis, sandbox queries, and IR playbooks.',
    tools: [
      {
        path: '/dfir/lolbins',
        useCase: 'Look up a living-off-the-land binary.',
        label: 'LOLBins / GTFOBins',
        desc: 'Curated living-off-the-land catalog · ATT&CK-mapped · detection ideas',
        icon: Terminal,
      },
      {
        path: '/dfir/lots',
        useCase: 'Check if a trusted domain is abused by attackers.',
        label: 'Living Off Trusted Sites',
        desc: '175 legitimate domains · phishing / C2 / exfil / download abuse · provider attribution',
        icon: Globe,
      },
      {
        path: '/dfir/malapi',
        useCase: 'Look up what a Windows API is abused for.',
        label: 'MalAPI',
        desc: '370 Windows APIs · attack categories · DLL libraries · MS docs links',
        icon: Bug,
      },
      {
        path: '/dfir/hijacklibs',
        useCase: 'Check if a DLL is a known hijacking candidate.',
        label: 'HijackLibs',
        desc: '608 DLLs · sideloading / phantom / search-order · vulnerable executables',
        icon: Database,
      },
      {
        path: '/dfir/log-parser',
        useCase: 'Build a timeline from raw log text.',
        label: 'Log Parser',
        desc: 'WinEvent / Sysmon / syslog / JSON-line / key=value · MITRE tagging · Splunk + Elastic queries',
        icon: ScrollText,
      },
      {
        path: '/dfir/ir-playbooks',
        useCase: 'Get a step-by-step IR playbook for any incident type.',
        label: 'IR Playbooks',
        desc: '10 incident types · step-by-step workflows · tool integration · severity-rated',
        icon: BookOpen,
      },
      {
        path: '/dfir/netdraw',
        useCase: 'Map your network topology for incident-response analysis.',
        label: 'NetDraw',
        desc: 'Network topology diagram editor · drag-and-drop nodes · draw connections · add zones & swimlanes · guided journey walkthroughs',
        icon: Network,
      },
    ],
  },
  {
    id: 'frameworks',
    group: 'grc',
    label: 'Frameworks & Posture',
    blurb: 'Models analysts use to structure intrusions and security programs.',
    tools: [
      {
        path: '/dfir/kill-chain',
        useCase: 'Map an intrusion to the kill chain.',
        label: 'Cyber Kill Chain',
        desc: '7 phases · 28 techniques · ATT&CK cross-links',
        icon: Crosshair,
      },
      {
        path: '/dfir/attack-navigator',
        useCase: 'Visualize adversary techniques on the MITRE ATT&CK matrix.',
        label: 'MITRE ATT&CK Navigator',
        desc: '14 tactics · ~200 techniques · ARiES risk scores + % actor use + prevalence modes · drawer with technique detail · live from mitre/cti',
        icon: Target,
      },
      {
        path: '/dfir/attack-navigator?matrix=a3m',
        useCase: 'Map AI-agent attacks across the A3M kill chain.',
        label: 'A3M Agentic AI Matrix',
        desc: '17-phase Agentic AI Attack Matrix · 167 techniques · purple-violet tile map · live from cyberriskevaluator.com/A3M',
        icon: Sparkles,
      },
      {
        path: '/dfir/attack-navigator?matrix=d3fend',
        useCase: 'Browse the MITRE D3FEND defensive-technique ontology.',
        label: 'MITRE D3FEND Matrix',
        desc: '7 defensive tactics (Model · Harden · Detect · Isolate · Deceive · Evict · Restore) · 250+ techniques with definitions · live from d3fend.mitre.org',
        icon: ShieldCheck,
      },
      {
        path: '/dfir/diamond',
        useCase: 'Model an intrusion with the Diamond model.',
        label: 'Diamond Model',
        desc: '4 vertices · meta-features · interactive event template',
        icon: Diamond,
      },
      {
        path: '/dfir/owasp',
        useCase: 'Reference the OWASP Top 10 fast.',
        label: 'OWASP Top 10',
        desc: 'Web 2021 · API 2023 · LLM 2025 · self-assessment + MITRE links',
        icon: ShieldCheck,
      },
      {
        path: '/dfir/nhi',
        useCase: 'Inventory non-human identities and risk.',
        label: 'NHI Inventory & Top 10',
        desc: 'OWASP NHI Top 10 (2025) · service-account / OAuth / MCP-token inventory · per-NHI risk',
        icon: KeyRound,
      },
      {
        path: '/dfir/grc',
        useCase: 'Score compliance and maturity quickly.',
        label: 'GRC Compliance & Maturity',
        desc: 'NIST CSF 2.0 · ISO 27001 · ISO 42001 (AI) · CIS · SOC 2 · SOC-CMM · cross-mapping',
        icon: FileCheck,
      },
      {
        path: '/dfir/car',
        useCase: 'Find validated analytics for an ATT&CK technique.',
        label: 'MITRE CAR Analytics',
        desc: '102 analytics · ATT&CK coverage · D3FEND mappings · Splunk/EQL implementations',
        icon: Search,
      },
      {
        path: '/dfir/capec',
        useCase: 'Learn how attackers exploit a weakness.',
        label: 'MITRE CAPEC Patterns',
        desc: '559 attack patterns · CWE + ATT&CK cross-references · likelihood and severity',
        icon: Crosshair,
      },
      {
        path: '/dfir/veris',
        useCase: 'Code an incident with standard vocabulary.',
        label: 'VERIS Taxonomy',
        desc: '68 taxonomy fields · Actor / Action / Asset / Attribute · DBIR vocabulary',
        icon: FileText,
      },
      {
        path: '/dfir/engage',
        useCase: 'Plan deception and denial operations.',
        label: 'MITRE Engage',
        desc: '53 approaches · Prepare / Engage / Understand · lures, personas, honeypots',
        icon: Eye,
      },
    ],
  },
  {
    id: 'ai-sec',
    group: 'aisec',
    label: 'AI Security',
    blurb: 'AI-system threat surface. prompts, agents, MCP servers.',
    tools: [
      {
        path: '/dfir/prompt-injection',
        useCase: 'Red-team a prompt for injection.',
        label: 'Prompt Injection & Red-Team',
        desc: 'Detect 28 patterns · 26-prompt red-team library · OWASP LLM Top 10 · JSON export',
        icon: Sparkles,
      },
      {
        path: '/dfir/mcp-audit',
        useCase: 'Audit an MCP server attack surface.',
        label: 'MCP & Claude Code Auditor',
        desc: 'MCP configs + Claude Code settings · hooks · permission rules · tool poisoning',
        icon: Plug,
      },
      {
        path: '/dfir/agent-suite',
        useCase: 'Enrich any IOC (IP, hash, domain, URL) using 30+ threat intel providers.',
        label: 'Agent Enrich',
        desc: 'Fast deterministic IOC enrichment across 30+ providers · deep autonomous mode for full investigation with report',
        icon: Shield,
      },
      {
        path: '/dfir/agent-suite',
        useCase: 'Map an AI agent attack surface.',
        label: 'AI Agent Attack-Surface Mapper',
        desc: 'Capability graph from MCP/CC config · flags exfil + RCE chains · SVG visual',
        icon: Network,
      },
      {
        path: '/dfir/agent-suite',
        useCase: 'Let an autonomous agent plan and run CTI tools to answer a query.',
        label: 'Agent Investigator',
        desc: 'Autonomous CTI investigator · plans steps · runs server-side tools via WebSocket · streams STIX bundle + step-by-step trace · LLM synthesis',
        icon: Bot,
      },
      {
        path: '/dfir/zero-trust-ai-agents',
        useCase: 'Read the reference card for securing AI agent identities and tool calls.',
        label: 'Zero Trust for AI Agents',
        desc: 'Static reference card / infographic recasting Zero Trust principles (verify explicitly, least privilege, assume breach) for the AI-agent threat surface - identity, prompts, tool calls, memory, exfil paths. Phase-by-phase workflow, model + data + supply-chain control matrix, and detection signals.',
        icon: ShieldCheck,
      },
    ],
  },
  {
    id: 'reference',
    group: 'recon',
    label: 'Personal & Privacy',
    blurb: 'Your own state and privacy hygiene.',
    tools: [
      {
        path: '/dfir/privacy-hub',
        useCase: 'Check your own IP and fingerprint exposure.',
        label: 'Privacy Check',
        desc: 'IP · WebRTC · fingerprint',
        icon: Lock,
      },
    ],
  },
  {
    id: 'cloud',
    group: 'specialized',
    label: 'Cloud Security',
    blurb: 'Cloud posture & least-privilege review. runs entirely in your browser.',
    tools: [
      {
        path: '/dfir/iam-hub',
        useCase: 'Catch wildcard-admin / public-access before it ships.',
        label: 'AWS IAM Policy Analyzer',
        desc: 'Paste an AWS IAM / S3 bucket / role-trust policy · flags wildcard admin, public principals, NotAction/NotResource, privilege-escalation actions, broad secret access & confused-deputy trust · 100% client-side',
        icon: Cloud,
      },
      {
        path: '/dfir/iam-hub',
        useCase: 'Find the allUsers binding / owner role on a GCP project.',
        label: 'GCP IAM Policy Analyzer',
        desc: 'Paste a GCP allow policy or custom role · flags allUsers/allAuthenticatedUsers, primitive owner/editor, SA impersonation & key creation, setIamPolicy, wildcard custom-role permissions · 100% client-side',
        icon: Shield,
      },
      {
        path: '/dfir/iam-hub',
        useCase: 'Find the SP that is Owner on the whole subscription.',
        label: 'Azure RBAC Analyzer',
        desc: 'Paste az role assignment / definition list JSON · flags privileged roles at root/MG/subscription scope, SP & guest grants, legacy co-admins, custom-role escalation (roleAssignments/write, elevateAccess, VM run-command, listKeys) · 100% client-side',
        icon: Lock,
      },
      {
        path: '/dfir/sg-analyzer',
        useCase: 'Find the database port someone left open to the world.',
        label: 'Security Group / NSG Analyzer',
        desc: 'Paste AWS describe-security-groups JSON or an Azure NSG · flags inbound rules open to 0.0.0.0/0 · ::/0 · "Internet", severity-ranked by service (SSH/RDP/DB/admin planes) · 100% client-side',
        icon: Network,
      },
      {
        path: '/dfir/cloudtrail-triage',
        useCase: 'Spot the no-MFA login + log-tampering in a CloudTrail dump.',
        label: 'CloudTrail Triage',
        desc: 'Paste CloudTrail JSON (file / lookup-events / array) · scores no-MFA & root logins, log/guardrail tampering, IAM changes, public exposure, snapshot sharing, recon bursts · 100% client-side',
        icon: ScrollText,
      },
      {
        path: '/dfir/iam-hub',
        useCase: 'Catch the service account that is secretly cluster-admin.',
        label: 'Kubernetes RBAC Analyzer',
        desc: 'Paste kubectl RBAC -o json · flags wildcard verbs/resources, escalate/bind/impersonate, cluster-wide secret read, pod exec, cluster-admin & anonymous bindings · 100% client-side',
        icon: KeyRound,
      },
      {
        path: '/dfir/terraform-scan',
        useCase: 'Block the public S3 bucket before terraform apply.',
        label: 'Terraform / IaC Plan Scanner',
        desc: 'Paste terraform show -json (plan/state) · flags public S3/RDS, world-open security groups, unencrypted storage, IMDSv1, wildcard IAM, public resource policies & hardcoded secrets · 100% client-side',
        icon: FileCheck,
      },
    ],
  },
  {
    id: 'api-sec',
    group: 'specialized',
    label: 'API Security',
    blurb: 'Spec, header, secret & GraphQL review. OWASP API Top 10, runs entirely in your browser.',
    tools: [
      {
        path: '/dfir/openapi-audit',
        useCase: 'Find the unauthenticated endpoint before it ships.',
        label: 'OpenAPI / Swagger Auditor',
        desc: 'Paste an OpenAPI 3 / Swagger 2 spec · OWASP API Top 10. unauth & BOLA-prone endpoints, query-string API keys, Basic/no-scope auth, plaintext HTTP, mass assignment, debug paths · 100% client-side',
        icon: Plug,
      },
      {
        path: '/dfir/sec-headers-live',
        useCase: 'Grade a site’s response headers in one paste.',
        label: 'HTTP Security Headers Analyzer',
        desc: 'Paste raw response headers · graded CSP / HSTS / framing / CORS / Set-Cookie flags + Server/X-Powered-By leakage, A–F score · 100% client-side',
        icon: Globe,
      },
      {
        path: '/dfir/secret-scan',
        useCase: 'Catch the leaked key in a config / log paste.',
        label: 'Secret / API-Key Scanner',
        desc: 'Paste code/.env/logs · detects AWS/GCP/Azure keys, GitHub/Slack/Stripe/SendGrid tokens, private keys, DB URIs, JWTs + high-entropy assignments · redacted · 100% client-side',
        icon: KeyRound,
      },
      {
        path: '/dfir/graphql-audit',
        useCase: 'Spot the passwordHash field in a GraphQL schema.',
        label: 'GraphQL Security Analyzer',
        desc: 'Paste introspection JSON or SDL · flags introspection exposure, sensitive/PII fields, auth-less mutations/subscriptions, recursive-type DoS surface · 100% client-side',
        icon: Share2,
      },
      {
        path: '/dfir/osv-scan',
        useCase: 'Find known CVEs in a lockfile before you ship it.',
        label: 'OSV Dependency Scanner',
        desc: 'Paste package-lock.json / package.json / requirements.txt / go.mod / Cargo.lock / Gemfile.lock · checks each package against OSV.dev · parsing client-side, fixed-version aware',
        icon: Database,
      },
    ],
  },
  // ─── Reporting ─────────────────────────────────────────────────────
  {
    id: 'reporting',
    label: 'Reporting',
    blurb: 'Draft multi-section investigation reports and export findings to partner formats.',
    group: 'specialized',
    tools: [
      {
        path: '/dfir/report-composer',
        useCase: 'Draft a multi-section investigation report in the browser.',
        label: 'Report Composer',
        desc: 'Cover · summary · findings · IOCs · sources · TLP marking · export to PDF (jsPDF) or DOCX (OOXML via JSZip) · localStorage autosave · 100% client-side',
        icon: FileText,
      },
      {
        path: '/dfir/report-analyzer',
        useCase: 'Paste a report URL/text and extract IOCs, TTPs, CVEs, and a STIX bundle in one round-trip.',
        label: 'Report Analyzer',
        desc: 'AI summary · IOC extraction (allowlist + confidence) · MITRE ATT&CK TTP mapping · 5W context · CVE extraction · image-OCR for embedded IOCs · STIX 2.1 bundle + mindmap',
        icon: ScanSearch,
      },
    ],
  },
];

/**
 * Off-site sources / catalogs the External-Resources block used to render.
 * Moved to /threatintel as part of the 2026-05-11 split - see
 * `EXTERNAL_SOURCES` in `src/pages/threatintel/Home.tsx`. Kept here as
 * an empty array so the page renderer below doesn't need a conditional.
 */
const EXTERNAL: Tool[] = [];

/**
 * Total tool count includes everything (utilities + main tools). Kept as
 * the headline number elsewhere but the hub landing also computes the
 * "main" count (excluding utility-flagged tools) so the front door isn't
 * padded by hash-calculators and timestamp converters.
 */
export const TOOL_COUNT = SECTIONS.reduce((n, s) => n + s.tools.length, 0);

/** Tools that aren't flagged with `utility: true`. */
export const MAIN_TOOL_COUNT = SECTIONS.reduce((n, s) => n + s.tools.filter((t) => !t.utility).length, 0);

/** Just the utility tools, flat. The hub renders these under a separate
 *  "Utilities & converters" collapsible at the bottom of the tool grid. */
export const UTILITY_TOOLS: Tool[] = SECTIONS.flatMap((s) => s.tools.filter((t) => t.utility));

export { EXTERNAL };
