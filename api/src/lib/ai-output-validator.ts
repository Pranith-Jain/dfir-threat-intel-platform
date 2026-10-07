/**
 * Shared AI output validation — anti-hallucination, grounding, and quality.
 *
 * Used by: copilot, ACH, IR playbooks, hunting queries, AI summary,
 * briefing builder. NOT used by the blog pipeline (which has its own
 * post-process.ts with richer IOC-specific validation).
 *
 * Design goals:
 *   1. Ground every verifiable claim (CVE IDs, ATT&CK IDs, URLs) against
 *      the source data that was fed to the LLM.
 *   2. Strip fabricated reference URLs (the #1 hallucination class).
 *   3. Detect and flag AI-slop phrases.
 *   4. Score output quality (length, structure, citations).
 *   5. Never throw — return partial results so callers can degrade gracefully.
 */

// ── Reference URL allowlist ──────────────────────────────────────────────

const TRUSTED_HOSTS = new Set([
  // Canonical authorities
  'nvd.nist.gov',
  'cve.mitre.org',
  'cve.org',
  'cisa.gov',
  'attack.mitre.org',
  'atlas.mitre.org',
  'first.org',
  // abuse.ch family
  'urlhaus.abuse.ch',
  'threatfox.abuse.ch',
  'bazaar.abuse.ch',
  'abuse.ch',
  // Threat intel platforms
  'otx.alienvault.com',
  'virustotal.com',
  'abuseipdb.com',
  'shodan.io',
  'censys.io',
  'greynoise.io',
  'urlscan.io',
  'malpedia.caad.fkie.fraunhofer.de',
  'hybrid-analysis.com',
  'any.run',
  'triage.cloud',
  'joesandbox.com',
  'recordedfuture.com',
  'riskiq.com',
  'securitytrails.com',
  'intelx.io',
  'dehashed.com',
  'hudsonrock.com',
  // Ransomware tracking
  'ransomware.live',
  'ransomlook.io',
  'ransomwatch.io',
  'ransom.wiki',
  // Breach / OSINT
  'haveibeenpwned.com',
  // Vendor research labs
  'unit42.paloaltonetworks.com',
  'paloaltonetworks.com',
  'sentinelone.com',
  'sentinellabs.com',
  'mandiant.com',
  'crowdstrike.com',
  'cloud.google.com',
  'research.checkpoint.com',
  'huntress.com',
  'sygnia.co',
  'sophos.com',
  'news.sophos.com',
  'microsoft.com',
  'docs.microsoft.com',
  'learn.microsoft.com',
  'cisco.com',
  'blog.talosintelligence.com',
  'talosintelligence.com',
  'fortinet.com',
  'kaspersky.com',
  'securelist.com',
  'eset.com',
  'welivesecurity.com',
  'tenable.com',
  'rapid7.com',
  'redcanary.com',
  'snyk.io',
  'splunk.com',
  'elastic.co',
  'symantec.com',
  'mcafee.com',
  'trendmicro.com',
  'akamai.com',
  'imperva.com',
  'sucuri.net',
  'cloudflare.com',
  'blog.cloudflare.com',
  // Security news / write-ups
  'krebsonsecurity.com',
  'bleepingcomputer.com',
  'therecord.media',
  'thehackernews.com',
  'hackread.com',
  'theregister.com',
  'arstechnica.com',
  'wired.com',
  'reuters.com',
  // Standards bodies
  'nist.gov',
  'csrc.nist.gov',
  'iana.org',
  'ietf.org',
  'datatracker.ietf.org',
  // OWASP / AI security
  'owasp.org',
  'genai.owasp.org',
  // Code / research
  'github.com',
  'gist.github.com',
  'arxiv.org',
  'scholar.google.com',
  // Sandboxes / enrichment
  'payloads.online',
  'chaos.projectdiscovery.io',
  'zoomeye.org',
  'fofa.info',
  'binaryedge.io',
  'wigle.net',
  'dnsdumpster.com',
  'crt.sh',
  // Reference
  'wikipedia.org',
  'en.wikipedia.org',
  'commons.wikimedia.org',
]);

export function isTrustedUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    return TRUSTED_HOSTS.has(host) || [...TRUSTED_HOSTS].some((h) => host.endsWith('.' + h));
  } catch {
    return false;
  }
}

/**
 * Strip URLs from text that are not on the trusted allowlist.
 * Returns the cleaned text and a list of stripped URLs.
 */
export function stripUntrustedUrls(text: string): { cleaned: string; stripped: string[] } {
  const stripped: string[] = [];
  const urlRegex = /https?:\/\/[^\s\])>"']+/g;
  const cleaned = text.replace(urlRegex, (match) => {
    const cleanUrl = match.replace(/[.,;:!?)]+$/, '');
    if (isTrustedUrl(cleanUrl)) return match;
    stripped.push(cleanUrl);
    return '[unverified-link]';
  });
  return { cleaned, stripped };
}

// ── CVE grounding ────────────────────────────────────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d{4,}/g;

/**
 * Extract all CVE IDs from text.
 */
export function extractCves(text: string): string[] {
  return [...new Set((text.match(CVE_REGEX) ?? []).map((c) => c.toUpperCase()))];
}

/**
 * Check which CVEs in the output are NOT in the source data.
 * Returns the list of ungrounded (likely hallucinated) CVE IDs.
 */
export function findUngroundedCves(output: string, sourceData: string): string[] {
  const outputCves = extractCves(output);
  if (outputCves.length === 0) return [];
  const sourceCves = new Set(extractCves(sourceData));
  return outputCves.filter((c) => !sourceCves.has(c));
}

// ── MITRE ATT&CK ID validation ──────────────────────────────────────────

const MITRE_ID_REGEX = /\bT\d{4}(?:\.\d{3})?\b/g;

/** All valid ATT&CK technique IDs (enterprise, v19.1). */
const VALID_ATTACK_IDS = new Set([
  'T1001',
  'T1003',
  'T1005',
  'T1006',
  'T1007',
  'T1008',
  'T1010',
  'T1011',
  'T1012',
  'T1014',
  'T1016',
  'T1018',
  'T1020',
  'T1021',
  'T1025',
  'T1027',
  'T1029',
  'T1030',
  'T1033',
  'T1036',
  'T1037',
  'T1039',
  'T1040',
  'T1041',
  'T1046',
  'T1047',
  'T1048',
  'T1049',
  'T1053',
  'T1055',
  'T1056',
  'T1057',
  'T1059',
  'T1068',
  'T1069',
  'T1070',
  'T1071',
  'T1072',
  'T1074',
  'T1078',
  'T1080',
  'T1082',
  'T1083',
  'T1087',
  'T1090',
  'T1091',
  'T1092',
  'T1095',
  'T1098',
  'T1102',
  'T1104',
  'T1105',
  'T1106',
  'T1110',
  'T1111',
  'T1112',
  'T1113',
  'T1114',
  'T1115',
  'T1119',
  'T1120',
  'T1123',
  'T1124',
  'T1125',
  'T1127',
  'T1129',
  'T1132',
  'T1133',
  'T1134',
  'T1135',
  'T1136',
  'T1137',
  'T1140',
  'T1176',
  'T1185',
  'T1187',
  'T1189',
  'T1190',
  'T1195',
  'T1197',
  'T1199',
  'T1200',
  'T1201',
  'T1202',
  'T1203',
  'T1204',
  'T1205',
  'T1210',
  'T1211',
  'T1212',
  'T1213',
  'T1216',
  'T1217',
  'T218',
  'T1219',
  'T1220',
  'T1221',
  'T1222',
  'T1480',
  'T1482',
  'T1484',
  'T1485',
  'T1486',
  'T1489',
  'T1490',
  'T1491',
  'T1495',
  'T1496',
  'T1497',
  'T1498',
  'T1499',
  'T1505',
  'T1525',
  'T1526',
  'T1527',
  'T1528',
  'T1529',
  'T1530',
  'T1531',
  'T1534',
  'T1535',
  'T1537',
  'T1538',
  'T1539',
  'T1542',
  'T1543',
  'T1546',
  'T1547',
  'T1548',
  'T1550',
  'T1552',
  'T1553',
  'T1554',
  'T1555',
  'T1556',
  'T1557',
  'T1558',
  'T1559',
  'T1560',
  'T1561',
  'T1562',
  'T1563',
  'T1564',
  'T1565',
  'T1566',
  'T1567',
  'T1568',
  'T1569',
  'T1570',
  'T1571',
  'T1572',
  'T1573',
  'T1574',
  'T1578',
  'T1580',
  'T1583',
  'T1584',
  'T1585',
  'T1586',
  'T1587',
  'T1588',
  'T1589',
  'T1590',
  'T1591',
  'T1592',
  'T1593',
  'T1594',
  'T1595',
  'T1596',
  'T1597',
  'T1598',
  'T1599',
  'T1600',
  'T1601',
  'T1602',
  'T1606',
  'T1608',
  'T1609',
  'T1610',
  'T1611',
  'T1612',
  'T1613',
  'T1614',
  'T1615',
  'T1619',
  'T1620',
  'T1621',
  'T1622',
  // Sub-techniques (common ones)
  'T1003.001',
  'T1003.002',
  'T1003.003',
  'T1003.004',
  'T1003.005',
  'T1003.006',
  'T1021.001',
  'T1021.002',
  'T1021.003',
  'T1021.004',
  'T1021.005',
  'T1021.006',
  'T1027.001',
  'T1027.002',
  'T1027.003',
  'T1027.004',
  'T1027.005',
  'T1027.006',
  'T1036.001',
  'T1036.002',
  'T1036.003',
  'T1036.004',
  'T1036.005',
  'T1036.006',
  'T1036.007',
  'T1036.008',
  'T1053.002',
  'T1053.003',
  'T1053.005',
  'T1053.006',
  'T1053.007',
  'T1055.001',
  'T1055.002',
  'T1055.003',
  'T1055.004',
  'T1055.005',
  'T1055.008',
  'T1055.009',
  'T1055.011',
  'T1055.012',
  'T1055.013',
  'T1055.014',
  'T1055.015',
  'T1059.001',
  'T1059.002',
  'T1059.003',
  'T1059.004',
  'T1059.005',
  'T1059.006',
  'T1059.007',
  'T1059.008',
  'T1070.001',
  'T1070.002',
  'T1070.003',
  'T1070.004',
  'T1070.005',
  'T1070.006',
  'T1070.007',
  'T1070.008',
  'T1070.009',
  'T1070.010',
  'T1071.001',
  'T1071.002',
  'T1071.003',
  'T1071.004',
  'T1078.001',
  'T1078.002',
  'T1078.003',
  'T1078.004',
  'T1105.001',
  'T1110.001',
  'T1110.002',
  'T1110.003',
  'T1110.004',
  'T1127.001',
  'T1127.002',
  'T1134.001',
  'T1134.002',
  'T1134.003',
  'T1134.004',
  'T1134.005',
  'T1137.001',
  'T1137.002',
  'T1137.003',
  'T1137.004',
  'T1137.005',
  'T1137.006',
  'T1140.001',
  'T1190.001',
  'T1204.001',
  'T1204.002',
  'T1204.003',
  'T1218.001',
  'T1218.002',
  'T1218.003',
  'T1218.004',
  'T1218.005',
  'T1218.007',
  'T1218.008',
  'T1218.009',
  'T1218.010',
  'T1218.011',
  'T1218.012',
  'T1218.013',
  'T1218.014',
  'T1484.001',
  'T1484.002',
  'T1486.001',
  'T1486.002',
  'T1486.003',
  'T1497.001',
  'T1497.002',
  'T1497.003',
  'T1505.001',
  'T1505.002',
  'T1505.003',
  'T1505.004',
  'T1505.005',
  'T1543.001',
  'T1543.002',
  'T1543.003',
  'T1543.004',
  'T1546.001',
  'T1546.002',
  'T1546.003',
  'T1546.004',
  'T1546.005',
  'T1546.006',
  'T1546.007',
  'T1546.008',
  'T1546.009',
  'T1546.010',
  'T1546.011',
  'T1546.012',
  'T1546.013',
  'T1546.014',
  'T1546.015',
  'T1546.016',
  'T1547.001',
  'T1547.002',
  'T1547.003',
  'T1547.004',
  'T1547.005',
  'T1547.006',
  'T1547.007',
  'T1547.008',
  'T1547.009',
  'T1547.010',
  'T1547.011',
  'T1547.012',
  'T1547.013',
  'T1547.014',
  'T1548.001',
  'T1548.002',
  'T1548.003',
  'T1548.004',
  'T1548.005',
  'T1550.001',
  'T1550.002',
  'T1550.003',
  'T1550.004',
  'T1552.001',
  'T1552.002',
  'T1552.003',
  'T1552.004',
  'T1552.005',
  'T1552.006',
  'T1552.007',
  'T1552.008',
  'T1553.001',
  'T1553.002',
  'T1553.003',
  'T1553.004',
  'T1553.005',
  'T1553.006',
  'T1555.001',
  'T1555.002',
  'T1555.003',
  'T1555.004',
  'T1555.005',
  'T1555.006',
  'T1556.001',
  'T1556.002',
  'T1556.003',
  'T1556.004',
  'T1556.005',
  'T1556.006',
  'T1556.007',
  'T1556.008',
  'T1557.001',
  'T1557.002',
  'T1557.003',
  'T1558.001',
  'T1558.002',
  'T1558.003',
  'T1558.004',
  'T1559.001',
  'T1559.002',
  'T1559.003',
  'T1560.001',
  'T1560.002',
  'T1560.003',
  'T1562.001',
  'T1562.002',
  'T1562.003',
  'T1562.004',
  'T1562.006',
  'T1562.007',
  'T1562.008',
  'T1562.009',
  'T1562.010',
  'T1562.011',
  'T1562.012',
  'T1563.001',
  'T1563.002',
  'T1564.001',
  'T1564.002',
  'T1564.003',
  'T1564.004',
  'T1564.005',
  'T1564.006',
  'T1564.007',
  'T1564.008',
  'T1564.009',
  'T1564.010',
  'T1564.011',
  'T1564.012',
  'T1564.013',
  'T1565.001',
  'T1565.002',
  'T1565.003',
  'T1566.001',
  'T1566.002',
  'T1566.003',
  'T1567.001',
  'T1567.002',
  'T1568.001',
  'T1568.002',
  'T1568.003',
  'T1569.001',
  'T1569.002',
  'T1570.001',
  'T1571.001',
  'T1572.001',
  'T1573.001',
  'T1573.002',
  'T1574.001',
  'T1574.002',
  'T1574.004',
  'T1574.005',
  'T1574.006',
  'T1574.007',
  'T1574.008',
  'T1574.009',
  'T1574.010',
  'T1574.011',
  'T1574.012',
  'T1574.013',
  'T1578.001',
  'T1578.002',
  'T1578.003',
  'T1578.004',
  'T1578.005',
  'T1580.001',
  'T1583.001',
  'T1583.002',
  'T1583.003',
  'T1583.004',
  'T1583.005',
  'T1583.006',
  'T1583.007',
  'T1584.001',
  'T1584.002',
  'T1584.003',
  'T1584.004',
  'T1584.005',
  'T1584.006',
  'T1584.007',
  'T1585.001',
  'T1585.002',
  'T1585.003',
  'T1586.001',
  'T1586.002',
  'T1586.003',
  'T1586.004',
  'T1587.001',
  'T1587.002',
  'T1587.003',
  'T1587.004',
  'T1588.001',
  'T1588.002',
  'T1588.003',
  'T1588.004',
  'T1588.005',
  'T1588.006',
  'T1589.001',
  'T1589.002',
  'T1589.003',
  'T1590.001',
  'T1590.002',
  'T1590.003',
  'T1590.004',
  'T1590.005',
  'T1590.006',
  'T1591.001',
  'T1591.002',
  'T1591.003',
  'T1591.004',
  'T1592.001',
  'T1592.002',
  'T1592.003',
  'T1592.004',
  'T1593.001',
  'T1593.002',
  'T1595.001',
  'T1595.002',
  'T1595.003',
  'T1596.001',
  'T1596.002',
  'T1596.003',
  'T1596.004',
  'T1596.005',
  'T1597.001',
  'T1597.002',
  'T1598.001',
  'T1598.002',
  'T1598.003',
  'T1600.001',
  'T1600.002',
  'T1601.001',
  'T1601.002',
  'T1602.001',
  'T1602.002',
  'T1606.001',
  'T1606.002',
  'T1608.001',
  'T1608.002',
  'T1608.003',
  'T1608.004',
  'T1608.005',
  'T1608.006',
  'T1609.001',
  'T1610.001',
  'T1611.001',
  'T1612.001',
  'T1613.001',
  'T1613.002',
  'T1614.001',
  'T1615.001',
  'T1619.001',
  'T1620.001',
  'T1621.001',
  // Pre-ATT&CK
  'T1398',
  'T1401',
  'T1418',
  'T1422',
  'T1426',
  'T1429',
  'T1430',
  'T1432',
  'T1435',
  'T1437',
  'T1438',
  'T1444',
  'T1447',
  'T1448',
  'T1452',
  'T1456',
  'T1461',
  'T1464',
]);

export function extractMitreIds(text: string): string[] {
  return [...new Set(text.match(MITRE_ID_REGEX) ?? [])];
}

export function findInvalidMitreIds(text: string): string[] {
  return extractMitreIds(text).filter((id) => !VALID_ATTACK_IDS.has(id));
}

// ── Quality scoring ──────────────────────────────────────────────────────
//
// SCOPE NOTE: the slop-phrase detector that used to live here (`SLOP_PATTERNS`
// / `detectSlop`, 26 regexes for "unlock", "dive into", "in today's landscape",
// "best practices", …) has been removed, along with the `slopCount` deduction
// in `scoreQuality` and the corresponding field in `QualityScore`.
//
// Two reasons it was hurting more than helping:
//
//  1. It punished legitimate security writing. "In today's threat landscape"
//     is bad filler, but "leverage" and "ecosystem" appear in vendor
//     advisories and MITRE technique descriptions that this pipeline quotes
//     verbatim. Scoring a faithful quotation as slop teaches the model to
//     paraphrase sources, which is exactly how quoted version strings and
//     affected-build tables get corrupted.
//  2. It was measuring the wrong thing. Fluency and phrasing tell you nothing
//     about whether a CVE id is real. The checks that remain below
//     (`ungroundedCveCount`, `invalidMitreCount`, `untrustedUrlCount`) all
//     test facts against an external source of truth, which is the only
//     thing worth detecting here.
//
// Grounding is now prevented primarily upstream — the research stage feeds
// the writer verified facts — with these checks as the backstop.

// ── Quality scoring ──────────────────────────────────────────────────────

export interface QualityScore {
  score: number; // 0-100
  wordCount: number;
  hasSections: boolean;
  hasCitations: boolean;
  citationCount: number;
  untrustedUrlCount: number;
  ungroundedCveCount: number;
  invalidMitreCount: number;
  issues: string[];
}

/**
 * Score an AI-generated output.
 *
 * Every deduction below tests a FACT against an external source of truth:
 * does this CVE exist in the input, is this ATT&CK id real, is this host on
 * the allowlist. Nothing here judges phrasing, length targets, or style.
 *
 * @param text The LLM output.
 * @param sourceData The source data that was fed to the LLM (for grounding checks).
 * @param opts Optional overrides for scoring thresholds.
 */
export function scoreQuality(
  text: string,
  sourceData: string = '',
  opts?: { minWords?: number; requireCitations?: boolean }
): QualityScore {
  const minWords = opts?.minWords ?? 80;
  const requireCitations = opts?.requireCitations ?? true;

  const words = text.split(/\s+/).filter(Boolean);
  const wordCount = words.length;
  const hasSections = /^##\s/m.test(text);
  const citationMatches = text.match(/\[\d+\]/g) ?? [];
  const citationCount = citationMatches.length;
  const { stripped } = stripUntrustedUrls(text);
  const ungrounded = sourceData ? findUngroundedCves(text, sourceData) : [];
  const invalidMitre = findInvalidMitreIds(text);

  const issues: string[] = [];
  if (wordCount < minWords) issues.push(`Too short (${wordCount} words, min ${minWords})`);
  if (!hasSections) issues.push('No section headings (##)');
  if (requireCitations && citationCount === 0) issues.push('No inline citations [N]');
  if (stripped.length > 0) issues.push(`${stripped.length} untrusted URLs stripped`);
  if (ungrounded.length > 0)
    issues.push(`${ungrounded.length} ungrounded CVE IDs: ${ungrounded.slice(0, 5).join(', ')}`);
  if (invalidMitre.length > 0)
    issues.push(`${invalidMitre.length} invalid ATT&CK IDs: ${invalidMitre.slice(0, 5).join(', ')}`);

  // Score: start at 100, deduct only for factual problems.
  let score = 100;
  if (wordCount < minWords) score -= 30;
  if (!hasSections) score -= 10;
  if (requireCitations && citationCount === 0) score -= 20;
  score -= Math.min(15, stripped.length * 5);
  score -= Math.min(20, ungrounded.length * 10);
  score -= Math.min(10, invalidMitre.length * 5);
  score = Math.max(0, Math.min(100, score));

  return {
    score,
    wordCount,
    hasSections,
    hasCitations: citationCount > 0,
    citationCount,
    untrustedUrlCount: stripped.length,
    ungroundedCveCount: ungrounded.length,
    invalidMitreCount: invalidMitre.length,
    issues,
  };
}

// ── Full validation pipeline ─────────────────────────────────────────────

export interface ValidationResult {
  /** Cleaned output text (untrusted URLs replaced, slop flagged). */
  cleaned: string;
  /** Quality score. */
  quality: QualityScore;
  /** Whether the output passes minimum quality thresholds. */
  passed: boolean;
  /** Human-readable summary of issues. */
  summary: string;
}

/**
 * Run the full validation pipeline on AI output.
 * @param output The raw LLM output.
 * @param sourceData The source data fed to the LLM (for grounding).
 * @param opts Options for scoring thresholds.
 */
export function validateAiOutput(
  output: string,
  sourceData: string = '',
  opts?: { minWords?: number; requireCitations?: boolean }
): ValidationResult {
  // 1. Strip untrusted URLs
  const { cleaned } = stripUntrustedUrls(output);

  // 2. Score quality
  const quality = scoreQuality(cleaned, sourceData, opts);

  // 3. Determine pass/fail (score >= 40 and no critical issues)
  const hasCritical = quality.ungroundedCveCount > 3 || quality.invalidMitreCount > 3;
  const passed = quality.score >= 40 && !hasCritical;

  // 4. Build summary
  const summary =
    quality.issues.length > 0
      ? `Quality ${quality.score}/100: ${quality.issues.join('; ')}`
      : `Quality ${quality.score}/100: clean`;

  return { cleaned, quality, passed, summary };
}
