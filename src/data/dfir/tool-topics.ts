/**
 * Wiki topic → tool map. Used by WikiArticle.tsx to insert auto-links
 * from prose mentions of common DFIR concepts to the relevant tool
 * page. Order matters: longer/more-specific phrases come first so
 * "MITRE ATT&CK" doesn't get partially-matched as "MITRE".
 *
 * Each entry can include a `prefill` field for query-string preset that
 * the destination tool reads (e.g. /dfir/cve?q= for the search box).
 *
 * Add new entries as wiki articles grow - keep this list curated; we
 * don't want every common word turning into a link.
 */

export interface ToolTopic {
  /** Match this term (case-insensitive, whole-word). */
  term: string;
  /** Where to send the user. */
  href: string;
  /** Tooltip shown on hover so the auto-link is self-explanatory. */
  blurb: string;
}

export const TOOL_TOPICS: ToolTopic[] = [
  // Authoritative concepts → matrix / lookup pages
  {
    term: 'MITRE ATT&CK',
    href: '/threatintel/tools',
    blurb: 'Browse the ATT&CK matrix and tag your detection coverage',
  },
  { term: 'ATT&CK', href: '/threatintel/tools', blurb: 'Browse the ATT&CK matrix and tag your detection coverage' },
  { term: 'CISA KEV', href: '/dfir/cve', blurb: 'Search the Known Exploited Vulnerabilities catalog' },
  { term: 'EPSS', href: '/dfir/cve', blurb: 'Look up Exploit Prediction Scoring System scores' },
  {
    term: 'CVE',
    href: '/threatintel/cve-resources',
    blurb: 'Curated CVE resources catalog - databases, exploits, PSIRTs, scoring, feeds',
  },
  {
    term: 'PSIRT',
    href: '/threatintel/cve-resources?cat=vendor-psirt',
    blurb: 'Vendor-PSIRT subset of the CVE resources catalog',
  },
  {
    term: 'Exploit-DB',
    href: '/threatintel/cve-resources?cat=exploit-poc',
    blurb: 'Exploit/PoC subset of the CVE resources catalog',
  },
  {
    term: 'CVSS',
    href: '/threatintel/cve-resources?cat=scoring-prioritization',
    blurb: 'Scoring + prioritisation subset of the CVE resources catalog',
  },

  // Email-auth → domain inspector
  { term: 'SPF', href: '/dfir/domain', blurb: 'Check SPF, DKIM, DMARC, MX, and TXT for any domain' },
  { term: 'DKIM', href: '/dfir/domain', blurb: 'Check SPF, DKIM, DMARC, MX, and TXT for any domain' },
  { term: 'DMARC', href: '/dfir/domain', blurb: 'Check SPF, DKIM, DMARC, MX, and TXT for any domain' },
  { term: 'DMARC report', href: '/dfir/dmarc-analyzer', blurb: 'Parse DMARC RUA XML reports - in-browser, no upload' },
  { term: 'RUA', href: '/dfir/dmarc-analyzer', blurb: 'Parse DMARC aggregate XML reports in your browser' },
  {
    term: 'DMARC aggregate',
    href: '/dfir/dmarc-analyzer',
    blurb: 'Parse DMARC RUA XML reports - in-browser, no upload',
  },
  { term: 'BIMI', href: '/dfir/domain', blurb: 'Check email-auth records for any domain' },

  // Detection authoring
  { term: 'Sigma rule', href: '/threatintel/rules', blurb: 'Browse curated Sigma + YARA rule repositories' },
  { term: 'YARA', href: '/threatintel/rules', blurb: 'Browse curated Sigma + YARA rule repositories' },
  { term: 'Sigma', href: '/threatintel/rules', blurb: 'Browse curated Sigma + YARA rule repositories' },

  // IOC + STIX + threat intel
  { term: 'STIX', href: '/dfir/stix', blurb: 'View STIX 2.1 bundles in a structured graph' },
  { term: 'TAXII', href: '/dfir/stix', blurb: 'View STIX 2.1 bundles in a structured graph' },
  { term: 'IOC', href: '/dfir/extract', blurb: 'Extract indicators from raw text with refanging' },

  // PowerShell + malware analysis
  { term: 'PowerShell', href: '/dfir/powershell-deobf', blurb: 'Multi-pass deobfuscator for PowerShell loaders' },
  { term: 'EncodedCommand', href: '/dfir/powershell-deobf', blurb: 'Decode PowerShell -EncodedCommand payloads' },
  { term: 'LOLBin', href: '/dfir/lolbins', blurb: 'Browse Living-Off-the-Land Binary technique catalogue' },
  { term: 'LOLBAS', href: '/dfir/lolbins', blurb: 'Browse Living-Off-the-Land Binary technique catalogue' },
  { term: 'LOTS', href: '/dfir/lots', blurb: 'Check trusted sites abused for phishing, C2, and exfiltration' },
  { term: 'trusted sites', href: '/dfir/lots', blurb: 'Living Off Trusted Sites abused by attackers' },
  { term: 'MalAPI', href: '/dfir/malapi', blurb: 'Look up Windows APIs abused by attackers' },
  { term: 'WinAPI', href: '/dfir/malapi', blurb: 'Windows API abuse catalogue by attack category' },
  { term: 'HijackLibs', href: '/dfir/hijacklibs', blurb: 'DLL hijacking candidates and vulnerable executables' },
  { term: 'DLL sideloading', href: '/dfir/hijacklibs', blurb: 'Known DLL hijacking candidates (T1574.001)' },
  { term: 'CAR', href: '/dfir/car', blurb: 'MITRE Cyber Analytics Repository detection ideas by technique' },
  { term: 'CAPEC', href: '/dfir/capec', blurb: 'MITRE attack patterns with CWE and ATT&CK links' },
  { term: 'VERIS', href: '/dfir/veris', blurb: 'Incident taxonomy vocabulary (Actor/Action/Asset/Attribute)' },
  { term: 'Engage', href: '/dfir/engage', blurb: 'MITRE adversary engagement and deception approaches' },
  { term: 'deception', href: '/dfir/engage', blurb: 'Denial and deception operations planning' },

  // Phishing + email
  { term: 'phishing', href: '/dfir/phishing', blurb: 'Analyse email headers + URL/IOC extraction from raw .eml' },
  { term: 'EML', href: '/dfir/eml', blurb: 'Extract attachments from raw .eml + hash each (SHA-256/SHA-1/MD5)' },
  {
    term: 'Passive DNS',
    href: '/dfir/passive-dns',
    blurb: 'Query historical DNS resolution data for infrastructure tracking',
  },
  {
    term: 'malware analysis',
    href: '/dfir/malware-scan',
    blurb: 'Drop a file → client-side static analysis + multi-engine dispatcher',
  },
  {
    term: 'sample scan',
    href: '/dfir/sample-scan',
    blurb: 'Free multi-engine hash verdict + one-click public-sandbox detonation',
  },
  {
    term: 'lite 0x12',
    href: '/dfir/sample-scan',
    blurb: 'Free alternative to 0x12darksandbox - hash fan-out + public sandbox links',
  },
  {
    term: 'sandbox',
    href: '/dfir/malware-scan',
    blurb: 'Multi-engine sandbox dispatcher (VT, MB, ANY.RUN, Joe, Hybrid)',
  },
  { term: 'security headers', href: '/dfir/web-scan', blurb: 'HTTP security-header audit (CSP, HSTS, XCTO, XFO, etc)' },
  { term: 'CSP', href: '/dfir/web-scan', blurb: 'Content-Security-Policy audit + common exposed-path probes' },
  { term: '.eml', href: '/dfir/eml', blurb: 'Extract attachments from raw .eml + hash each (SHA-256/SHA-1/MD5)' },
  { term: 'reverse image search', href: '/dfir/image-intel', blurb: 'Multi-engine reverse-image search dispatcher' },

  // Crypto
  { term: 'OFAC', href: '/dfir/crypto-trace', blurb: 'Sanctions-check any BTC/EVM/Solana address' },
  { term: 'wallet drainer', href: '/dfir/crypto-trace', blurb: 'ScamSniffer-flagged drainer addresses surface here' },

  // Breach + exposure
  { term: 'HIBP', href: '/dfir/breach', blurb: 'Check breach exposure for an email or password hash' },
  { term: 'Have I Been Pwned', href: '/dfir/breach', blurb: 'Check breach exposure for an email or password hash' },
  { term: 'subdomain takeover', href: '/dfir/subdomain-takeover', blurb: 'Check a domain for subdomain-takeover risk' },

  // Privacy
  { term: 'GDPR', href: '/dfir/privacy-hub', blurb: 'Browse the privacy & data-protection hub' },
  { term: 'CCPA', href: '/dfir/privacy-hub', blurb: 'Browse the privacy & data-protection hub' },

  // OSINT
  { term: 'OSINT', href: '/threatintel/osint-framework', blurb: 'Open-source intelligence framework' },
  {
    term: 'SecOps tools',
    href: '/threatintel/secops-tools',
    blurb: '~140 curated security tools across 14 categories',
  },
  {
    term: 'detection engineering',
    href: '/threatintel/secops-tools?cat=detection-engineering',
    blurb: 'Detection-engineering tooling subset of the catalog',
  },
  { term: 'Wayback Machine', href: '/dfir/wayback', blurb: 'Wayback Machine timeline pivot' },
  { term: 'EXIF', href: '/dfir/exif', blurb: 'EXIF metadata parser for images' },
  { term: 'SOCMINT', href: '/dfir/socmint', blurb: 'Categorised OSINT pivots for email/domain/handle/name' },
  { term: 'IP geolocation', href: '/dfir/ioc-investigate', blurb: 'Country, ASN, ISP + AbuseIPDB reputation' },

  // Watch tools (.onion / Telegram)
  { term: '.onion', href: '/threatintel/onion-watch', blurb: 'Live .onion leak-site mirror inventory + reachability' },
  {
    term: 'onion mirrors',
    href: '/threatintel/onion-watch',
    blurb: 'Live .onion leak-site mirror inventory + reachability',
  },
  {
    term: 'Tor',
    href: '/threatintel/onion-watch',
    blurb: 'Top ransomware leak-site .onion mirrors with reachability flags',
  },
  { term: 'Ransomlook', href: '/threatintel/onion-watch', blurb: 'Ransomlook-backed .onion mirror inventory' },
  {
    term: 'Telegram',
    href: '/threatintel/telegram',
    blurb: 'Curated threat-intel & cybercrime Telegram channel index',
  },
  {
    term: 'deepdarkCTI',
    href: '/threatintel/telegram',
    blurb: 'See the deepdarkCTI-backed Telegram catalogue + cybercrime channel index',
  },
];
