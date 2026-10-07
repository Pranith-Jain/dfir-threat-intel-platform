import type { CaseStudyType, PostIOC, PostAudit } from '../types';
import { stripConnectorEmDashes } from '../../lib/prose-style';

/**
 * Output normalisation.
 *
 * SCOPE NOTE — this file used to be the quality gate. It scored output on
 * length, section count, sentences-per-section, a keyword list for
 * "technical" content, and a filler-phrase penalty; it then failed the
 * publish below 45/100. It also ran a slop-phrase stripper that deleted
 * whole sentences for containing a banned word, and a "You"-hook rewriter
 * that cut the first sentence of a hook.
 *
 * All of that is gone. Here is why it was worth removing rather than tuning:
 *
 *  - The score measured the WRITER, not the piece. "Depth" was sentences per
 *    section, so the cheapest way to pass was to write more sentences. That
 *    is precisely the padding behaviour the rules existed to prevent, and
 *    the model found it.
 *  - Word-level filters are trivially defeated and mostly produce damage.
 *    Stripping a sentence containing "tapestry" also removed the one fact in
 *    it. Rewriting a "You" hook removed the hook.
 *  - Length gates incentivised the opposite of what we want. watchTowr's
 *    best explainers are long because they answer many questions, not
 *    because they hit a word count.
 *
 * What remains here is normalisation, not judgement. Fix markdown that the
 * model got slightly wrong, drop sections that are genuinely empty, remove
 * reference bullets pointing at hosts nobody has heard of, and extract the
 * indicators. Every one of those is a correctness fix. None of them decides
 * whether the piece is good — that is now the research dossier's job on the
 * way in, and a human's job in /admin on the way out.
 *
 * Grounding that materially affects SAFETY of the output is still enforced,
 * because a fabricated CVE id or a dead citation link is a factual error, not
 * a style problem. Those surface as warnings for the reviewer.
 */

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const REF_LINK_RE = /\[[^\]]+\]\(https?:\/\/[^)]+\)/g;

export interface PostProcessInput {
  type: CaseStudyType;
  raw: string;
  /** Serialised research dossier — the grounding source of truth. */
  factsText: string;
}

export interface PostProcessOutput {
  /** True when the output is structurally usable (has sections). Never a
   *  quality verdict — see the scope note above. */
  ok: boolean;
  body: string;
  iocs: PostIOC[];
  /** Grounding warnings for the reviewer. Non-blocking. */
  errors: string[];
  /** Factual counters for the admin. Never a publish gate. */
  audit?: PostAudit;
}

/** Raw FACTS blocks the model occasionally emits despite instructions. */
const FACTS_BLOCK_RE = /^FACTS:.*$/gm;

/** Section headings used bare, without the `## ` prefix. */
const ALL_HEADINGS = [
  'TL;DR',
  'FAQ',
  'Summary',
  'Key takeaways',
  'Updates',
  'Status',
  'What is this vulnerability',
  'Affected products',
  'Affected versions',
  'How it works',
  'How the attack works',
  'CVSS score breakdown',
  'CVSS breakdown',
  'Why this matters',
  'Exploitation in the wild',
  'Detection & mitigation',
  'Detection and mitigation',
  'Detection & response',
  'Detection and response',
  'IOCs',
  'IOC',
  'Indicators of compromise',
  'References',
  'Get more information',
  'Further reading',
  'Origin and attribution',
  'Known campaigns',
  'TTPs',
  'TTP',
  'Targeted sectors',
  'Recent activity',
  'Defensive guidance',
  'Defensive recommendations',
  'Defensive takeaways',
  'Capabilities',
  'Delivery',
  'Infrastructure',
  'Detection',
  'Related families',
  'Group profile',
  'What was exposed',
  'How it happened',
  'Impact and affected parties',
  'Lessons learned',
  'How the scam works',
  'Lures and channels',
  'Indicators and red flags',
  'Who is targeted',
  'Protective guidance',
  'Affected AI/ML system',
  'Attack technique',
  'Attack mechanism',
  'Real-world impact',
  'Mitigations',
  'Key findings',
  'Technical analysis',
  'Tool overview',
  'Data sources',
  'Use cases',
  'Results & findings',
  'Results and findings',
  'Limitations',
  'Problem statement',
  'Approach',
  'Implementation',
  'Results',
  'Data sources & methodology',
  'Data sources and methodology',
  'Key metrics',
  'Observed trends',
  'Correlations',
  'Implications',
];

const ESCAPED = ALL_HEADINGS.map((h) => h.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'));
const SECTION_NAME_RE = new RegExp(`^(${ESCAPED.join('|')})[\\s:\\-]*$`, 'im');

/** Any ATX heading (h1-h6) that carries content. */
const ATX_HEADING_RE = /^(#{1,6})\s+(.+)$/;
/** The level every downstream consumer expects for a top-level section. */
const TOP_SECTION_LEVEL = 2;
/** Deepest level the table of contents renders (see content-utils.ts). */
const MAX_TOC_LEVEL = 3;

/** Promote a bare section name to a real markdown heading. */
function ensureMdHeaders(body: string): string {
  return body.replace(SECTION_NAME_RE, '## $1');
}

/**
 * True when the body carries at least one usable section heading at any level.
 *
 * This used to test `/^##\s+.+/` — level 2 only. That is narrower than what
 * the generator actually emits and narrower than what the renderer accepts
 * (`marked.parse` handles h1-h6). A body written with `###` headings was
 * therefore rejected with "output contained no section headings" even though it
 * was perfectly well structured.
 */
function hasSectionHeadings(body: string): boolean {
  return body.split('\n').some((line) => {
    const m = ATX_HEADING_RE.exec(line);
    return m !== null && (m[2] ?? '').trim().length > 0;
  });
}

/**
 * Lift a body whose headings all sit below `##` up to the canonical level.
 *
 * Only fires when the shallowest heading in the document is deeper than a top
 * section, so genuine nesting is preserved: a body with a real `##` keeps its
 * `###` subsections as subsections, while an all-`###` body is promoted to
 * proper top-level sections. Levels are clamped to the depth the table of
 * contents renders so nothing silently disappears from the sidebar.
 */
function normalizeSectionDepth(body: string): string {
  const levels: number[] = [];
  for (const line of body.split('\n')) {
    const m = ATX_HEADING_RE.exec(line);
    if (m) levels.push(m[1]!.length);
  }
  if (levels.length === 0) return body;

  const shallowest = Math.min(...levels);
  if (shallowest <= TOP_SECTION_LEVEL) return body;

  return body
    .split('\n')
    .map((line) => {
      const m = ATX_HEADING_RE.exec(line);
      if (!m) return line;
      const lifted = Math.min(m[1]!.length - (shallowest - TOP_SECTION_LEVEL), MAX_TOC_LEVEL);
      return `${'#'.repeat(lifted)} ${m[2]!}`;
    })
    .join('\n');
}

/**
 * Promote bold pseudo-headings when the body has no real headings at all.
 *
 * Question-shaped headings are explicitly encouraged by the prompt ("Which
 * versions are affected?", "Is it being exploited?"), and models often emit
 * them emphasised rather than as ATX headings. Only applies when there is no
 * ATX heading to begin with, so a body that already has structure is never
 * touched.
 */
function promoteBoldPseudoHeadings(body: string): string {
  if (hasSectionHeadings(body)) return body;
  return body
    .split('\n')
    .map((line) => {
      const m = /^\s*\*\*([^*\n]{3,80}\?)\*\*:?\s*$/.exec(line);
      return m ? `## ${m[1]!.trim()}` : line;
    })
    .join('\n');
}

/** Remove a section whose body carries no content at all. */
function stripEmptySections(body: string): string {
  const lines = body.split('\n');
  const result: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? '';
    if (ATX_HEADING_RE.test(line)) {
      const heading = line;
      const sectionBody: string[] = [];
      const headingLevel = (ATX_HEADING_RE.exec(line)?.[1] ?? '#').length;
      i++;
      while (i < lines.length) {
        const cur = lines[i] ?? '';
        // Break on a heading at this level or shallower. Previously this was
        // `cur.startsWith('##')`, which also stopped at a DEEPER `###`
        // subsection — so a `###` ended its parent `##` section's body, and
        // the subsection was then re-emitted as loose content with the rest of
        // the section orphaned behind it.
        const curMatch = ATX_HEADING_RE.exec(cur);
        if (curMatch && curMatch[1]!.length <= headingLevel) break;
        sectionBody.push(cur);
        i++;
      }
      if (sectionBody.join('').trim()) {
        result.push(heading, '', ...sectionBody);
      }
    } else {
      result.push(line);
      i++;
    }
  }
  return result
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Blank line after a list block so the next paragraph isn't swallowed. */
function fixListBlocks(body: string): string {
  return body.replace(/^(\s*(?:[-*+]|\d+\.)\s.+)\n(?=\S)/gm, '$1\n\n');
}

/** Blank line before a bolded closing paragraph that follows a list. */
function fixClosingBoldParagraph(body: string): string {
  return body.replace(/^(\s*(?:[-+*]|\d+\.)\s.+\n)(\*\*[^*]+\*\*)/gm, '$1\n$2');
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

function isPlaceholderDomain(domain: string): boolean {
  const d = domain.toLowerCase();
  if (d === 'localhost') return true;
  if (/^example\.(com|net|org|test|local|edu)$/.test(d)) return true;
  if (/\.(test|local|invalid|example|localhost)$/.test(d)) return true;
  if (/^(www\.)?(example|test|placeholder|sample|dummy|foobar|fake)\./.test(d)) return true;
  return false;
}

/**
 * Hosts permitted in a References bullet, in addition to whatever the
 * dossier recorded as read. This is a hallucination guard, not a quality
 * gate: a link to a domain no source mentions is a fabricated citation
 * regardless of how well-written the prose is.
 */
const REFERENCE_HOST_ALLOWLIST = new Set<string>([
  // Canonical authorities
  'nvd.nist.gov',
  'cisa.gov',
  'www.cisa.gov',
  'attack.mitre.org',
  'cve.mitre.org',
  'cve.org',
  'www.cve.org',
  'first.org',
  'www.first.org',
  'cvemon.intruder.io',
  'github.com',
  'gist.github.com',
  // abuse.ch family
  'abuse.ch',
  'threatfox.abuse.ch',
  'urlhaus.abuse.ch',
  'bazaar.abuse.ch',
  // Vendor / research labs
  'unit42.paloaltonetworks.com',
  'sentinelone.com',
  'sentinelone.labs',
  'sentinellabs.com',
  'mandiant.com',
  'cloud.google.com',
  'research.checkpoint.com',
  'huntress.com',
  'crowdstrike.com',
  'sygnia.co',
  'sophos.com',
  'news.sophos.com',
  'microsoft.com',
  'www.microsoft.com',
  'msrc.microsoft.com',
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
  'trendmicro.com',
  'proofpoint.com',
  'watchtowr.com',
  'labs.watchtowr.com',
  'horizon3.ai',
  'wiz.io',
  'orca.security',
  'netlify.com',
  'security.vulncheck.com',
  'citrix.com',
  'support.citrix.com',
  'community.citrix.com',
  // Security news / write-ups
  'krebsonsecurity.com',
  'bleepingcomputer.com',
  'www.bleepingcomputer.com',
  'therecord.media',
  'thehackernews.com',
  'hackread.com',
  'theregister.com',
  'arstechnica.com',
  'wired.com',
  'reuters.com',
  'securityweek.com',
  'darkreading.com',
  'infosecurity-magazine.com',
  'cyberscoop.com',
  'thecyberwire.com',
  'zero-day.cz',
  'wiz.io',
  'vulncheck.com',
  // Breach / OSINT references
  'haveibeenpwned.com',
  'hudsonrock.com',
  'shodan.io',
  'search.censys.io',
  'censys.io',
  'virustotal.com',
  'www.virustotal.com',
  'otx.alienvault.com',
  'urlscan.io',
  'exploit-db.com',
  'www.exploit-db.com',
  // Standards bodies
  'nist.gov',
  'csrc.nist.gov',
  'iana.org',
  'ietf.org',
  'datatracker.ietf.org',
  // Public AI/ML security
  'owasp.org',
  'genai.owasp.org',
  'atlas.mitre.org',
  'llmstxt.org',
]);

/**
 * Drop reference bullets pointing at hosts that are neither on the allowlist
 * nor present in the dossier. This is the one citation rule kept from the
 * old pipeline, because a dead or invented citation is a factual error the
 * reader can detect.
 */
function stripUnknownRefHosts(body: string, dossierText: string): string {
  const refsIdx = body.search(/^##\s+(References|Get more information|Further reading)\b/im);
  if (refsIdx < 0) return body;

  const dossierHosts = new Set<string>();
  for (const m of dossierText.match(/https?:\/\/[^\s)"'<>]+/gi) ?? []) {
    const h = hostOf(m);
    if (h) dossierHosts.add(h);
  }

  const before = body.slice(0, refsIdx);
  const after = body.slice(refsIdx);
  const refLine = /^(\s*[-*+]\s*)\[([^\]]+)\]\(([^)]+)\)([^\n]*)\n?/gm;
  const filtered = after.replace(refLine, (match, _b, _label, url) => {
    const host = hostOf(String(url));
    if (!host) return '';
    if (REFERENCE_HOST_ALLOWLIST.has(host) || dossierHosts.has(host)) return match;
    return '';
  });
  return before + filtered;
}

/** Reserved / documentation ranges that are never real indicators. */
function isPlaceholderIp(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a = -1, b = -1, c = -1] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  // RFC 5737 documentation ranges. These are /24s, so the first two octets
  // are the whole test — checking the third octet against 2/100/113 was a
  // bug that let 203.0.113.5 and 198.51.100.7 through as "real" indicators.
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 198 && b === 51) return true; // TEST-NET-2
  if (a === 203 && b === 0) return true; // TEST-NET-3
  if (a >= 224) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 198 && b >= 18 && b <= 19) return true;
  return false;
}

function isPlaceholderHash(hash: string): boolean {
  const h = hash.toLowerCase();
  if (/^([0-9a-f])\1{63}$/.test(h)) return true;
  if (/^(deadbeef|cafebabe|baadf00d|feedface|abad1dea)/i.test(h)) return true;
  if (/^(0123456789abcdef){4}$/.test(h)) return true;
  return false;
}

/**
 * Extract indicators from the body, excluding reference hosts and anything
 * that appears in the dossier's exclusion set.
 *
 * The result is a convenience for the post's IOC list and the platform's
 * IOC search. It is not verified against any provider here — an indicator
 * extracted from prose is a lead, and the admin treats it as one.
 */
function extractIocs(body: string, dossierText: string, type: CaseStudyType): PostIOC[] {
  const iocs: PostIOC[] = [];
  const seen = new Set<string>();
  const add = (t: PostIOC['type'], value: string) => {
    const key = `${t}:${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ type: t, value });
  };

  const exclude = new Set<string>();
  for (const u of dossierText.match(/https?:\/\/([^/\s"'\\)]+)/gi) ?? []) {
    const h = /https?:\/\/([^/\s"'\\)]+)/i.exec(u)?.[1];
    if (h) exclude.add(h.toLowerCase().replace(/^www\./, ''));
  }
  for (const d of dossierText.match(DOMAIN_RE) ?? []) exclude.add(d.toLowerCase().replace(/^www\./, ''));

  // Strip link targets and bare URLs so reference hosts never become IOCs.
  const bodyNoLinks = body.replace(/\[[^\]]*\]\(https?:\/\/[^)]+\)/g, ' ').replace(/https?:\/\/\S+/g, ' ');

  for (const m of bodyNoLinks.match(IPV4_RE) ?? []) {
    if (!isPlaceholderIp(m)) add('ipv4', m);
  }
  for (const m of bodyNoLinks.match(SHA256_RE) ?? []) {
    const h = m.toLowerCase();
    if (!isPlaceholderHash(h)) add('sha256', h);
  }
  // Victim names and leak-site hosts are not indicators; skip for types whose
  // body is names rather than observables.
  if (type !== 'breach' && type !== 'darkweb') {
    for (const m of bodyNoLinks.match(DOMAIN_RE) ?? []) {
      const host = m.toLowerCase().replace(/^www\./, '');
      if (isPlaceholderDomain(host) || exclude.has(host)) continue;
      add('domain', host);
    }
  }
  return iocs;
}

/** Factual counters for the admin reviewer. Deliberately not a score. */
function buildAudit(body: string, iocs: PostIOC[], warnings: string[]): PostAudit {
  return {
    words: body.split(/\s+/).filter(Boolean).length,
    // Counts every heading level the structural check accepts, so the reviewer
    // sees the same number the validator used to decide.
    sections: body.split('\n').filter((line) => hasSectionHeadings(line)).length,
    references: (body.match(REF_LINK_RE) ?? []).length,
    iocs: iocs.length,
    warnings,
  };
}

export function postProcess(input: PostProcessInput): PostProcessOutput {
  const warnings: string[] = [];

  let body = input.raw;

  // 1. Normalise markdown structure.
  body = ensureMdHeaders(body);
  body = body.replace(FACTS_BLOCK_RE, '').trim();
  // Heading shape is normalised EARLY, before stripUnknownRefHosts. That helper
  // locates the References section with /^##\s+(References|…)/, so if a body
  // expressed its sections as `###` the lookup would miss and untrusted citation
  // hosts would survive the allowlist filter — a factual-integrity control
  // silently skipped.
  body = promoteBoldPseudoHeadings(body);
  body = normalizeSectionDepth(body);
  body = stripUnknownRefHosts(body, input.factsText);
  body = fixListBlocks(body);
  body = stripEmptySections(body);
  body = fixClosingBoldParagraph(body);

  // 2. Typography normalisation. Connector em-dashes are rewritten to a
  //    period or comma by `stripConnectorEmDashes`; curly quotes are
  //    straightened. Table glyphs and numeric ranges are preserved by that
  //    helper.
  body = stripConnectorEmDashes(body)
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/\s*…\s*/g, '... ')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();

  // 3. Grounding warnings. These describe facts the dossier cannot confirm.
  //    They are surfaced to the reviewer and never block publication — an
  //    unexplained CVE id is worth a human glance, not an automatic failure.
  const lowerDossier = input.factsText.toLowerCase();
  // Compare case-insensitively but report the ids as the author wrote them —
  // a CVE id is conventionally uppercase, and an admin scanning the warning
  // needs something they can paste into a search box.
  const bodyCves = [...new Set(body.match(CVE_RE) ?? [])];
  const ungrounded = bodyCves.filter((c) => !lowerDossier.includes(c.toLowerCase()));
  if (ungrounded.length > 0) {
    warnings.push(
      `${ungrounded.length} CVE(s) in the body are not in the research dossier: ${ungrounded.slice(0, 4).join(', ')}`
    );
  }

  // 4. Structural check. A body with no section headings cannot be rendered
  //    as an article, so this is the one thing that legitimately fails.
  //
  //    Accepts any ATX level, not just `##`. The previous level-2-only test
  //    rejected well-formed bodies whose sections happened to be `###`, which
  //    the renderer and the table of contents both handle happily.
  if (!hasSectionHeadings(body)) {
    return { ok: false, body, iocs: [], errors: ['output contained no section headings'], audit: undefined };
  }

  const iocs = extractIocs(body, input.factsText, input.type);

  // An IP or hash in the body that is absent from the dossier is likely
  // invented. Surfaced as a warning: indicator lists get curated by a human.
  const invented = iocs.filter(
    (i) => (i.type === 'ipv4' || i.type === 'sha256') && !lowerDossier.includes(i.value.toLowerCase())
  );
  if (invented.length > 0) {
    warnings.push(
      `${invented.length} indicator(s) in the body are not in the dossier: ${invented
        .slice(0, 4)
        .map((i) => i.value)
        .join(', ')}`
    );
  }

  return { ok: true, body, iocs, errors: warnings, audit: buildAudit(body, iocs, warnings) };
}
