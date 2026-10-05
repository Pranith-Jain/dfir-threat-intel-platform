import type { CategoryRule, Severity } from './types';

export const NVD_UA = 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)';
export const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export function nvdHeaders(apiKey?: string): Record<string, string> {
  const h: Record<string, string> = { 'user-agent': NVD_UA, accept: 'application/json' };
  if (apiKey) h.apiKey = apiKey;
  return h;
}

export const KEV_FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// 5 days. NVD/KEV data for a past day is stable after ~48h, and briefings
// only ever query the last ~5 days. The previous 14-day TTL kept up to 14
// per-date-range `briefing-nvd?s=…&e=…` keys (~1 MB each) resident in KV
// (~14 MB). 5 days caps that at ~5 keys (~5 MB) while still covering the
// full briefing window + a safety margin for re-runs.
export const LASTGOOD_TTL_SEC = 60 * 60 * 24 * 5;

export const CATEGORY_RULES: CategoryRule[] = [
  {
    id: 'rce',
    title: 'Critical Remote Code Execution Vulnerabilities',
    blurb: 'Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately.',
    cwes: ['CWE-94', 'CWE-913', 'CWE-1336'],
    match:
      /\b(remote code execution|\bRCE\b|arbitrary code execution|unauthenticated code execution|pre-?auth(?:entication)? rce|code injection|template injection|expression language injection)\b/i,
  },
  {
    id: 'command-injection',
    title: 'Command Injection',
    blurb: 'OS / shell command injection enabling attacker-controlled execution.',
    cwes: ['CWE-77', 'CWE-78', 'CWE-88'],
    match: /\b(command injection|os command|shell injection|argument injection|special elements used in a command)\b/i,
  },
  {
    id: 'auth-bypass',
    title: 'Authentication & Authorization Bypass',
    blurb: 'Missing or broken authentication / authorisation enabling unauthorised actions.',
    cwes: [
      'CWE-287',
      'CWE-288',
      'CWE-289',
      'CWE-290',
      'CWE-294',
      'CWE-303',
      'CWE-304',
      'CWE-305',
      'CWE-306',
      'CWE-862',
      'CWE-863',
      'CWE-639',
    ],
    match:
      /\b(authentication bypass|auth(?:orisation| bypass)|missing authorization|missing authentication|improper access control|insecure direct object reference|broken access control|IDOR)\b/i,
  },
  {
    id: 'privesc',
    title: 'Privilege Escalation',
    blurb: 'Vulnerabilities enabling escalation to higher privileges.',
    cwes: ['CWE-269', 'CWE-250', 'CWE-272', 'CWE-273'],
    match:
      /\b(privilege escalation|priv(?:ilege)? esc|elevation of privilege|escalate privileges|incorrect privilege assignment)\b/i,
  },
  {
    id: 'sql-injection',
    title: 'SQL & NoSQL Injection',
    blurb: 'Database injection vulnerabilities exposing or modifying stored data.',
    cwes: ['CWE-89', 'CWE-943'],
    match: /\b(sql injection|sqli|nosql injection|blind sql|database injection)\b/i,
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting',
    blurb: 'Reflected, stored, or DOM-based XSS in web applications.',
    cwes: ['CWE-79', 'CWE-80', 'CWE-83', 'CWE-87'],
    match: /\b(cross-?site scripting|\bXSS\b|stored xss|reflected xss|html injection)\b/i,
  },
  {
    id: 'memory-corruption',
    title: 'Memory Corruption',
    blurb: 'Buffer overflows, use-after-free, type confusion enabling crashes or RCE.',
    cwes: [
      'CWE-119',
      'CWE-120',
      'CWE-121',
      'CWE-122',
      'CWE-125',
      'CWE-787',
      'CWE-415',
      'CWE-416',
      'CWE-476',
      'CWE-843',
      'CWE-190',
      'CWE-191',
      'CWE-200',
      'CWE-787',
    ],
    match:
      /\b(buffer overflow|heap overflow|stack overflow|use-after-free|use after free|type confusion|out-of-bounds (read|write)|double free|integer overflow|null pointer dereference)\b/i,
  },
  {
    id: 'deserialization',
    title: 'Insecure Deserialization',
    blurb: 'Unsafe deserialization of attacker-controlled data leading to RCE.',
    cwes: ['CWE-502'],
    match: /\b(deserialization|deserialisation|insecure (un|de)?serialization|unsafe object creation)\b/i,
  },
  {
    id: 'path-traversal',
    title: 'Path Traversal & File Disclosure',
    blurb: 'Directory traversal and arbitrary file read/write vulnerabilities.',
    cwes: [
      'CWE-22',
      'CWE-23',
      'CWE-24',
      'CWE-25',
      'CWE-26',
      'CWE-27',
      'CWE-28',
      'CWE-29',
      'CWE-30',
      'CWE-31',
      'CWE-32',
      'CWE-33',
      'CWE-34',
      'CWE-35',
      'CWE-36',
      'CWE-37',
      'CWE-38',
      'CWE-39',
      'CWE-40',
      'CWE-41',
      'CWE-73',
      'CWE-98',
    ],
    match:
      /\b(path traversal|directory traversal|arbitrary file (read|write|disclosure|upload|delete)|local file inclusion|remote file inclusion|\bLFI\b|\bRFI\b)\b/i,
  },
  {
    id: 'ssrf-csrf',
    title: 'SSRF, CSRF & Open Redirect',
    blurb: 'Server-side request forgery, cross-site request forgery, and redirect issues.',
    cwes: ['CWE-352', 'CWE-918', 'CWE-601'],
    match:
      /\b(server-?side request forgery|\bSSRF\b|cross-?site request forgery|\bCSRF\b|open redirect|url redirect)\b/i,
  },
  {
    id: 'crypto',
    title: 'Cryptographic Weaknesses',
    blurb: 'Broken cryptography, weak hashes, or insecure key management.',
    cwes: [
      'CWE-310',
      'CWE-326',
      'CWE-327',
      'CWE-328',
      'CWE-329',
      'CWE-330',
      'CWE-331',
      'CWE-335',
      'CWE-340',
      'CWE-916',
      'CWE-321',
    ],
    match:
      /\b(weak (cryptography|cipher|hash)|broken (cryptography|encryption)|insecure (random|prng)|hardcoded (key|password|credentials)|use of (hard-?coded )?credentials)\b/i,
  },
  {
    id: 'info-disclosure',
    title: 'Information Disclosure',
    blurb: 'Exposure of sensitive information through error messages, logs, or responses.',
    cwes: ['CWE-200', 'CWE-201', 'CWE-209', 'CWE-532', 'CWE-538', 'CWE-548'],
    match: /\b(information (disclosure|exposure|leak)|sensitive data exposure|verbose error|debug (output|info))\b/i,
  },
  {
    id: 'dos',
    title: 'Denial of Service',
    blurb: 'Vulnerabilities causing service disruption, resource exhaustion, or crashes.',
    cwes: ['CWE-400', 'CWE-401', 'CWE-770', 'CWE-834', 'CWE-835', 'CWE-674', 'CWE-1325'],
    match:
      /\b(denial of service|\bDoS\b|resource exhaustion|infinite loop|stack overflow loop|uncontrolled recursion)\b/i,
  },
  {
    id: 'iot-network',
    title: 'Network Infrastructure & IoT Device Vulnerabilities',
    blurb: 'Vulnerabilities in routers, firewalls, and IoT devices on the network edge.',
    match:
      /\b(router|firewall|edge gateway|VPN gateway|gateway appliance|D-Link|TP-Link|Netgear|Tenda|Cisco|Juniper|Fortinet|Palo Alto|SonicWall|MikroTik|IoT|embedded device|firmware)\b/i,
  },
  {
    id: 'browser',
    title: 'Browser & Application Memory Corruption',
    blurb: 'Memory-corruption vulnerabilities specific to browsers and rendering engines.',
    match:
      /\b(Chrome|Chromium|Firefox|Safari|WebKit|Blink|Gecko|V8|JavaScriptCore|browser)\b.*\b(memory|corruption|use-after-free|type confusion)\b/i,
  },
  {
    id: 'social-eng',
    title: 'Social Engineering & Phishing',
    blurb: 'Active phishing campaigns, lures, and social-engineering tradecraft.',
    match: /\b(phish(ing)?|social engineering|impersonation lure|smishing|quishing)\b/i,
  },
];

export const SEVERITY_CATEGORIES: Record<Severity, { id: string; title: string; blurb: string } | null> = {
  critical: {
    id: 'critical-other',
    title: 'Critical-Severity Vulnerabilities',
    blurb: 'Critical-severity issues that did not fit a more specific category — review urgently.',
  },
  high: {
    id: 'high-other',
    title: 'High-Severity Vulnerabilities',
    blurb: 'High-severity vulnerabilities across miscellaneous products and services.',
  },
  medium: {
    id: 'medium-other',
    title: 'Medium-Severity Vulnerabilities',
    blurb: 'Medium-severity issues across miscellaneous products and services.',
  },
  low: {
    id: 'low-other',
    title: 'Low-Severity Vulnerabilities',
    blurb: 'Low-severity issues across miscellaneous products and services.',
  },
  unknown: null,
};

export const FALLBACK_CATEGORY = {
  id: 'other',
  title: 'Other Vulnerabilities',
  blurb: 'Additional vulnerabilities observed across products and services.',
};

export const MITRE_RULES: Array<{ pattern: RegExp; technique: string }> = [
  { pattern: /\b(remote code execution|\bRCE\b|arbitrary code|public-?facing|exploit public)\b/i, technique: 'T1190' },
  { pattern: /\b(command injection|os command)\b/i, technique: 'T1059' },
  { pattern: /\b(privilege escalation|elevation of privilege)\b/i, technique: 'T1068' },
  { pattern: /\b(authentication bypass|missing authentication)\b/i, technique: 'T1078' },
  { pattern: /\b(deserialization|insecure deserialization)\b/i, technique: 'T1059.007' },
  { pattern: /\b(buffer overflow|memory corruption)\b/i, technique: 'T1203' },
  { pattern: /\b(sql injection)\b/i, technique: 'T1190' },
  { pattern: /\b(cross-?site scripting|\bxss\b)\b/i, technique: 'T1059.007' },
  { pattern: /\bphishing\b/i, technique: 'T1566' },
  { pattern: /\bbotnet\b/i, technique: 'T1583.005' },
];

export const VICTIM_CORPORATE_SUFFIXES = [
  's.a. de c.v.',
  'pte. ltd.',
  'pte ltd',
  'co., inc.',
  'co., ltd.',
  'co. ltd.',
  ', inc.',
  ', llc.',
  ', llc',
  ', ltd.',
  ', ltd',
  ', s.a.',
  ', s.r.l.',
  ' inc.',
  ' inc',
  ' llc',
  ' ltd.',
  ' ltd',
  ' gmbh',
  ' corp.',
  ' corp',
  ' s.a.',
  ' s.r.l.',
  ' srl',
  ' sas',
  ' sa',
];

export const VICTIM_TRAILING_DESCRIPTORS = [
  'free data',
  'leaked data',
  'data leak',
  'data dump',
  'all data',
  'full database',
  'database leak',
];

/**
 * Feed labels that mark a briefing as IOC-carrying. Keys must match the
 * `iocSources` labels pushed in `build.ts`, or the daily-briefs index stops
 * treating LLM-abuse briefings as IOC briefings.
 */
export const IOC_FEED_SOURCES = new Set([
  'URLhaus',
  'MalwareBazaar',
  'ThreatFox',
  'TweetFeed',
  'AI Honeypot Observatory',
  'LLM ThreatIntel',
]);

export const BRIEFING_MAX_AGE_DAYS = 30;

// Case-triage linkage bounds (see related.ts). Kept small: the stamp runs on
// every briefing write inside the daily cron, and scans bounded by
// RELATED_MAX_CANDIDATES recent rows via json_extract (never full bodies).
export const RELATED_LIMIT = 5;
export const RELATED_MAX_CANDIDATES = 40;
