import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../../env';
import { type IocEntry } from '../ioc-feed-parsers';
import { normalizeGroup } from '../group-normalize';
import { runCompletion } from '../../case-study/generation/ai-client';
import { findUngroundedCves } from '../ai-output-validator';
import { fenceUntrusted, neutralizeUntrusted, UNTRUSTED_DATA_SYSTEM_NOTE } from '../prompt-fence';
import {
  CATEGORY_RULES,
  SEVERITY_CATEGORIES,
  FALLBACK_CATEGORY,
  MITRE_RULES,
  VICTIM_CORPORATE_SUFFIXES,
  VICTIM_TRAILING_DESCRIPTORS,
} from './config';
import type {
  BriefingType,
  BriefingFinding,
  Briefing,
  BriefingSection,
  BriefingIocBuckets,
  BriefingStats,
  Severity,
  NvdCve,
  KevEntry,
  WeeklyDailyRollup,
  WeeklyMergeInput,
} from './types';

export function severityFromCvss(score: number | undefined): Severity {
  if (score === undefined) return 'unknown';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function extractCwes(nvd: NvdCve | undefined): string[] {
  if (!nvd?.weaknesses) return [];
  const out = new Set<string>();
  for (const w of nvd.weaknesses) {
    for (const d of w.description ?? []) {
      const m = /CWE-\d+/i.exec(d.value);
      if (m) out.add(m[0].toUpperCase());
    }
  }
  return Array.from(out);
}

function categorizeFinding(args: { title: string; description: string; severity: Severity; cwes: string[] }) {
  const haystack = `${args.title} ${args.description}`;
  if (args.cwes.length > 0) {
    for (const rule of CATEGORY_RULES) {
      if (!rule.cwes) continue;
      if (rule.cwes.some((c) => args.cwes.includes(c))) return rule;
    }
  }
  for (const rule of CATEGORY_RULES) {
    if (rule.match && rule.match.test(haystack)) return rule;
  }
  const sevBucket = SEVERITY_CATEGORIES[args.severity];
  if (sevBucket) return sevBucket;
  return FALLBACK_CATEGORY;
}

export function deriveMitreTechniques(description: string): string[] {
  const found = new Set<string>();
  for (const r of MITRE_RULES) if (r.pattern.test(description)) found.add(r.technique);
  return Array.from(found);
}

export function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function isoYearWeek(d: Date): string {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil(((dt.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return `${dt.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`;
}

export function startOfIsoWeek(d: Date): Date {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() - (day - 1));
  return dt;
}

export function expectedWeeklySlug(anchor: Date = new Date()): string {
  const start = new Date(startOfIsoWeek(anchor).getTime() - 7 * 86400_000);
  return `weekly-${isoYearWeek(start)}`;
}

export function withinRange(timestamp: string | undefined, startMs: number, endMs: number): boolean {
  if (!timestamp) return false;
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return false;
  return t >= startMs && t < endMs;
}

function stripVictimNoise(lower: string): string {
  // Trackers alternate between "Encore Enterprises, Inc." and
  // "Encore-Enterprises-Inc." — treat hyphens/underscores as spaces so the
  // suffix/descriptor stripping below applies to both spellings and the
  // semantic dedup key collapses them.
  let s = lower.replace(/[-_]+/g, ' ').replace(/\s+/g, ' ').trim();
  for (let pass = 0; pass < 2; pass += 1) {
    for (const desc of VICTIM_TRAILING_DESCRIPTORS) {
      const escaped = desc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`(^|\\s)${escaped}[\\s.,;:!?]*$`);
      s = s.replace(re, '').trim();
    }
    for (const suffix of VICTIM_CORPORATE_SUFFIXES) {
      if (s.endsWith(suffix)) {
        s = s.slice(0, -suffix.length).trim();
      }
    }
    s = s.replace(/[.,;:!?\s]+$/, '');
  }
  return s;
}

export function normalizeVictimKey(raw: string): string {
  const decoded = raw
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'");
  const stripped = stripVictimNoise(decoded.toLowerCase());
  return stripped.replace(/[^a-z0-9]/g, '');
}

export function canonicalGangKeys(raw: string): string[] {
  const lower = raw.toLowerCase().trim();
  if (!lower) return [];
  const keys = new Set<string>();
  const outer = lower
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const outerKey = outer.replace(/[^a-z0-9]/g, '');
  if (outerKey) keys.add(outerKey);
  for (const m of lower.matchAll(/\(([^)]+)\)/g)) {
    const inner = m[1]!.replace(/[^a-z0-9]/g, '');
    if (inner) keys.add(inner);
  }
  return [...keys];
}

export function findingFromNvd(nvd: NvdCve): BriefingFinding {
  const cvss =
    nvd.metrics?.cvssMetricV31?.[0]?.cvssData.baseScore ??
    nvd.metrics?.cvssMetricV30?.[0]?.cvssData.baseScore ??
    nvd.metrics?.cvssMetricV2?.[0]?.cvssData.baseScore;
  const description = nvd.descriptions?.find((d) => d.lang === 'en')?.value ?? '';
  const firstSentence = description.split(/(?<=[.!?])\s/)[0] ?? description;
  const excerpt = firstSentence.length > 90 ? `${firstSentence.slice(0, 87)}…` : firstSentence;
  const title = excerpt ? `${nvd.id}: ${excerpt}` : nvd.id;
  return {
    id: nvd.id,
    title,
    description,
    severity: severityFromCvss(cvss),
    cvss,
    cwes: extractCwes(nvd),
    source: 'NVD',
    source_url: `https://nvd.nist.gov/vuln/detail/${nvd.id}`,
    mitre_techniques: deriveMitreTechniques(`${title} ${description}`),
  };
}

export function findingFromKev(kev: KevEntry, nvd: NvdCve | undefined): BriefingFinding {
  const cvss =
    nvd?.metrics?.cvssMetricV31?.[0]?.cvssData.baseScore ??
    nvd?.metrics?.cvssMetricV30?.[0]?.cvssData.baseScore ??
    nvd?.metrics?.cvssMetricV2?.[0]?.cvssData.baseScore;
  const description =
    nvd?.descriptions?.find((d) => d.lang === 'en')?.value ?? kev.shortDescription ?? kev.vulnerabilityName ?? '';
  const title =
    `${kev.cveID}: ${kev.vendorProject ?? ''} ${kev.product ?? ''} — ${kev.vulnerabilityName ?? 'Vulnerability'}`
      .replace(/\s+/g, ' ')
      .trim();
  const cwes = extractCwes(nvd);
  return {
    id: kev.cveID,
    title,
    description,
    severity: severityFromCvss(cvss),
    cvss,
    cwes,
    source: 'CISA KEV',
    source_url: `https://nvd.nist.gov/vuln/detail/${kev.cveID}`,
    mitre_techniques: deriveMitreTechniques(`${title} ${description}`),
    added: kev.dateAdded,
    vendor: kev.vendorProject,
    product: kev.product,
  };
}

export function buildSections(findings: BriefingFinding[]): BriefingSection[] {
  const groups = new Map<string, { rule: { id: string; title: string; blurb: string }; findings: BriefingFinding[] }>();
  for (const f of findings) {
    const cat = categorizeFinding({
      title: f.title,
      description: f.description,
      severity: f.severity,
      cwes: f.cwes ?? [],
    });
    const slot = groups.get(cat.id) ?? { rule: cat, findings: [] };
    slot.findings.push(f);
    groups.set(cat.id, slot);
  }
  const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const sectionOrder = [
    ...CATEGORY_RULES.map((r) => r.id),
    'critical-other',
    'high-other',
    'medium-other',
    'low-other',
    FALLBACK_CATEGORY.id,
  ];
  return sectionOrder
    .map((id) => groups.get(id))
    .filter((s): s is NonNullable<typeof s> => !!s && s.findings.length > 0)
    .map((s) => ({
      id: s.rule.id,
      title: s.rule.title,
      blurb: s.rule.blurb,
      count: s.findings.length,
      findings: s.findings.slice().sort((a, b) => sevRank[a.severity] - sevRank[b.severity]),
    }));
}

export function bucketIocs(entries: IocEntry[]): BriefingIocBuckets {
  const buckets: BriefingIocBuckets = { urls: [], domains: [], ipv4s: [], hashes: [] };
  for (const e of entries) {
    if (e.type === 'url') buckets.urls.push(e);
    else if (e.type === 'domain') buckets.domains.push(e);
    else if (e.type === 'ipv4') buckets.ipv4s.push(e);
    else if (e.type === 'hash') buckets.hashes.push(e);
  }
  // No truncation here — the brief page surfaces the IOC list as a single
  // txt dump via buildIocDump(), and that dump includes every deduped entry
  // (capping was removed; the user wants the FULL list as a blocklist seed).
  // Inline buckets are kept just so the JSON payload still has a structured
  // per-type view for any other consumer.
  return buckets;
}

/**
 * Build the plain-text IOC dump attached to each briefing. Includes EVERY
 * deduped indicator (urls -> domains -> ipv4s -> hashes, in the order they
 * were deduped upstream). Each line includes the IOC value plus its type
 * prefix and a timestamp/context when available, so the dump is usable as
 * a copy-paste blocklist seed.
 *
 * Returns undefined when the bucket is empty so the field is omitted on
 * briefs that have no in-window IOCs (cleaner payload, and the page hides
 * the section entirely).
 */
export function buildIocDump(
  iocs: BriefingIocBuckets,
  rawTotal: number
): { count: number; rawTotal: number; content: string } | undefined {
  const lines: string[] = [];
  const collect = (kind: string, entries: IocEntry[]) => {
    for (const e of entries) {
      const ctx = e.context ? `  # ${e.context}` : '';
      const ts = e.timestamp ? `  @ ${e.timestamp}` : '';
      lines.push(`${kind}  ${e.value}${ctx}${ts}`);
    }
  };
  collect('url', iocs.urls);
  collect('domain', iocs.domains);
  collect('ipv4', iocs.ipv4s);
  collect('hash', iocs.hashes);
  if (lines.length === 0) return undefined;
  return {
    count: lines.length,
    rawTotal,
    content: lines.join('\n'),
  };
}

function topVendors(findings: BriefingFinding[], n: number): string[] {
  const counts = new Map<string, number>();
  for (const f of findings) {
    if (!f.vendor) continue;
    counts.set(f.vendor, (counts.get(f.vendor) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([v]) => v);
}

export function buildExecutiveSummary(args: {
  type: BriefingType;
  range_label: string;
  findings: BriefingFinding[];
  iocs: BriefingIocBuckets;
  iocsRawTotal: number;
  iocSources: string[];
  iocPerSource?: Record<string, number>;
  ransomwareGroups?: Array<{ group: string; count: number }>;
  ransomwareSectors?: Array<{ sector: string; count: number; pct: number }>;
  ransomwareTotal?: number;
}): string {
  const { type, range_label, findings, iocs, iocsRawTotal, iocSources, iocPerSource } = args;
  const span = type === 'weekly' ? 'This week' : 'In the past 24 hours';
  const critCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const vendors = topVendors(findings, 3);
  const vendorStr = vendors.length > 0 ? `affecting ${vendors.join(', ')}` : 'across multiple vendors';
  const kevCount = findings.filter((f) => f.source === 'CISA KEV').length;
  const nvdOnlyCount = findings.length - kevCount;
  const parts: string[] = [];
  if (findings.length > 0) {
    const severityClause =
      critCount > 0
        ? `, including ${critCount} critical-severity`
        : highCount > 0
          ? `, with ${highCount} high-severity`
          : '';
    if (kevCount > 0 && nvdOnlyCount > 0) {
      parts.push(
        `${span} (${range_label}), CISA added ${kevCount} new KEV ${kevCount === 1 ? 'entry' : 'entries'} and ${nvdOnlyCount} additional high/critical ${nvdOnlyCount === 1 ? 'CVE was' : 'CVEs were'} published (NVD, cvefeed.io, MyThreatIntel)${severityClause} ${vendorStr}.`
      );
    } else if (kevCount > 0) {
      parts.push(
        `${span} (${range_label}), CISA's Known Exploited Vulnerabilities catalog added ${kevCount} new ${kevCount === 1 ? 'entry' : 'entries'}${severityClause} ${vendorStr}.`
      );
    } else {
      parts.push(
        `${span} (${range_label}), ${nvdOnlyCount} high/critical ${nvdOnlyCount === 1 ? 'CVE was' : 'CVEs were'} published across NVD, cvefeed.io and MyThreatIntel${severityClause}; none have been added to CISA KEV yet.`
      );
    }
  } else {
    parts.push(
      `${span} (${range_label}), no new high/critical CVEs were observed across NVD, cvefeed.io, MyThreatIntel, and no entries were added to CISA's Known Exploited Vulnerabilities catalog.`
    );
  }
  const sampledBits: string[] = [];
  if (iocs.urls.length > 0) sampledBits.push(`${iocs.urls.length} malware-distribution URLs`);
  if (iocs.domains.length > 0) sampledBits.push(`${iocs.domains.length} malicious domains`);
  if (iocs.ipv4s.length > 0) sampledBits.push(`${iocs.ipv4s.length} suspicious IPs`);
  if (iocs.hashes.length > 0) sampledBits.push(`${iocs.hashes.length} malware sample hashes`);
  if (iocsRawTotal > 0) {
    const breakdown = iocPerSource
      ? Object.entries(iocPerSource)
          .filter(([, n]) => n > 0)
          .sort((a, b) => b[1] - a[1])
          .map(([k, n]) => `${k} ${n.toLocaleString()}`)
          .join(', ')
      : iocSources.length === 0
        ? 'tracked feeds'
        : iocSources.length <= 3
          ? iocSources.join(', ')
          : `${iocSources.slice(0, -1).join(', ')}, and ${iocSources[iocSources.length - 1]}`;
    const sampledTotal = iocs.urls.length + iocs.domains.length + iocs.ipv4s.length + iocs.hashes.length;
    parts.push(
      `Active threat indicators ${iocPerSource ? 'per source' : 'across'} ${breakdown} — ${iocsRawTotal.toLocaleString()} unique after cross-source dedup; all ${sampledTotal} indicators (${sampledBits.join(', ')}) are included in the IOC dump.`
    );
  }
  parts.push(
    'Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.'
  );
  return parts.join(' ');
}

export async function buildLlmExecutiveSummary(
  args: Parameters<typeof buildExecutiveSummary>[0],
  env?: Env
): Promise<string> {
  const templateSummary = buildExecutiveSummary(args);
  if (!env) return templateSummary;
  const {
    type,
    range_label,
    findings,
    iocsRawTotal,
    iocSources,
    ransomwareGroups,
    ransomwareSectors,
    ransomwareTotal,
  } = args;
  const critCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const kevCount = findings.filter((f) => f.source === 'CISA KEV').length;
  const topFindings = findings.slice(0, 15).map((f) => {
    const parts = [f.id];
    if (f.cvss) parts.push(`CVSS ${f.cvss}`);
    parts.push(f.severity);
    if (f.vendor) parts.push(neutralizeUntrusted(f.vendor));
    parts.push(neutralizeUntrusted(f.title.slice(0, 120)));
    return parts.join(' | ');
  });
  const iocSummary =
    iocSources.length > 0
      ? `IoC feeds: ${iocSources.join(', ')} — ${iocsRawTotal} unique indicators.`
      : 'No IoC data this window.';
  const ransomwareSummary =
    ransomwareTotal && ransomwareTotal > 0
      ? `Ransomware activity: ${ransomwareTotal} in-window victim claims across ` +
        (ransomwareGroups
          ?.slice(0, 5)
          .map((g) => `${neutralizeUntrusted(g.group)} (${g.count})`)
          .join(', ') ?? 'multiple groups') +
        (ransomwareSectors && ransomwareSectors.length > 0
          ? `. Top sectors: ${ransomwareSectors
              .filter((s) => s.sector !== 'Unknown')
              .slice(0, 3)
              .map((s) => `${neutralizeUntrusted(s.sector)} ${s.pct}%`)
              .join(', ')}.`
          : '.')
      : 'No in-window ransomware victim claims.';
  const userPrompt = [
    `Generate a 2-3 sentence executive summary for a ${type} threat intelligence briefing (${range_label}).`,
    ``,
    `Stats: ${findings.length} findings (${critCount} critical, ${highCount} high), ${kevCount} CISA KEV entries. ${iocSummary}`,
    ``,
    `${ransomwareSummary}`,
    ``,
    `Top findings:`,
    fenceUntrusted(topFindings.map((f) => `- ${f}`).join('\n'), 'FINDINGS'),
    ``,
    `Requirements: Be specific — cite CVE IDs and vendor names. If there is ransomware activity, name the most active groups and the top targeted sectors. Professional CTI tone. No speculation.`,
  ].join('\n');
  try {
    const result = await Promise.race([
      runCompletion(
        env.AI,
        {
          system:
            'You are a senior CTI analyst writing executive summaries for threat intelligence briefings. Be concise, specific, and actionable. Reference actual CVE IDs and vendor names from the data. 2-3 sentences maximum.\n\n' +
            UNTRUSTED_DATA_SYSTEM_NOTE,
          user: userPrompt,
          maxTokens: 400,
          temperature: 0.3,
        },
        {
          googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: env.GROQ_API_KEY,
          quality: true,
        }
      ),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('llm-summary-timeout')), 8000)),
    ]);
    const text = result.text?.trim();
    if (text && text.length > 50 && text.length < 2000) {
      const findingsText = findings.map((f) => `${f.id} ${f.title}`).join(' ');
      // Only grounding is checked here. A summary that cites CVEs not in the
      // findings is wrong; one that uses the word "leverage" is merely
      // inelegant, and falling back to a template over that throws away a
      // usable summary.
      const ungrounded = findUngroundedCves(text, findingsText);
      if (ungrounded.length > 2) {
        return templateSummary;
      }
      return text;
    }
  } catch {
    /* noop */
  }
  return templateSummary;
}

export function buildStats(
  findings: BriefingFinding[],
  sections: BriefingSection[],
  iocsTotal: number,
  ransomwareVictims = 0
): BriefingStats {
  const totalFindings = sections.reduce((n, s) => n + (s.findings?.length ?? 0), 0);
  return {
    findings: totalFindings,
    sections: sections.length,
    cves: findings.length,
    kevs: findings.filter((f) => f.source === 'CISA KEV').length,
    iocs: iocsTotal,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    ransomware_victims: ransomwareVictims,
  };
}

function isRansomwareFinding(sectionId: string, f: BriefingFinding): boolean {
  return sectionId === 'ransomware-activity' || f.id.startsWith('rw-') || f.source === 'ransomware.live';
}

function dedupeCveFindings(findings: BriefingFinding[]): BriefingFinding[] {
  const byId = new Map<string, BriefingFinding>();
  for (const f of findings) {
    const key = f.id.toUpperCase();
    const existing = byId.get(key);
    if (!existing) {
      byId.set(key, f);
      continue;
    }
    if (!Number.isFinite(existing.cvss) && Number.isFinite(f.cvss)) byId.set(key, f);
  }
  return [...byId.values()];
}

/**
 * Semantic ransomware dedup. The `f.id` for ransomware findings is built from
 * a slugified victim name (`rw-<group>-<victim-slug-40>-<day>`), which is
 * fragile across daily heal runs: the same victim can appear as "Acme Corp"
 * in one build and "Acme Corp." in another, producing different slugs and
 * slipping past a plain by-id dedup. This extracts a stable key from the
 * finding's structured fields (group from the title, victim from the title,
 * day from the id suffix) using `normalizeVictimKey` so punctuation/casing
 * drift collapses to the same key. Falls back to `f.id` when extraction fails.
 */
function dedupeRansomwareFindings(findings: BriefingFinding[]): BriefingFinding[] {
  const seen = new Set<string>();
  const out: BriefingFinding[] = [];
  for (const f of findings) {
    let key = f.id;
    // Title format: "${victim} — claimed by ${group}${location}"
    const m = /^(.+?)\s+—\s+claimed by\s+([^(]+?)(?:\s*\(.*\))?\s*$/.exec(f.title);
    if (m?.[1] && m?.[2]) {
      const victim = normalizeVictimKey(m[1]);
      const group = normalizeGroup(m[2].trim());
      const day = f.id.slice(-10);
      if (victim && group && /^\d{4}-\d{2}-\d{2}$/.test(day)) {
        key = `rw-${group}-${victim}-${day}`;
      }
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

function mergeIocBuckets(a: BriefingIocBuckets, b: BriefingIocBuckets): BriefingIocBuckets {
  const merge = (xs: IocEntry[], ys: IocEntry[]): IocEntry[] => {
    const seen = new Set<string>();
    const out: IocEntry[] = [];
    for (const e of [...xs, ...ys]) {
      const k = `${e.type}|${e.value.trim().toLowerCase()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(e);
    }
    return out;
  };
  return {
    urls: merge(a.urls, b.urls),
    domains: merge(a.domains, b.domains),
    ipv4s: merge(a.ipv4s, b.ipv4s),
    hashes: merge(a.hashes, b.hashes),
  };
}

export function mergeWeeklyWithDailies(live: WeeklyMergeInput, rollup: WeeklyDailyRollup): WeeklyMergeInput {
  if (rollup.dailyCount === 0) return live;
  return {
    findings: dedupeCveFindings([...live.findings, ...rollup.findings]),
    ransomwareFindings: dedupeRansomwareFindings([...live.ransomwareFindings, ...rollup.ransomwareFindings]),
    iocsRawTotal: Math.max(live.iocsRawTotal, rollup.iocsTotal),
    iocBuckets: mergeIocBuckets(live.iocBuckets, rollup.iocBuckets),
    sources: [...new Set([...live.sources, ...rollup.sources])],
  };
}

export async function aggregateWeeklyFromDailies(
  db: D1Database,
  rangeStartIso: string,
  rangeEndIso: string
): Promise<WeeklyDailyRollup> {
  const res = await db
    .prepare(
      'SELECT slug, stats_json, body FROM briefings WHERE type = ? AND date >= ? AND date <= ? ORDER BY date ASC'
    )
    .bind('daily', rangeStartIso, rangeEndIso)
    .all<{ slug: string; stats_json: string; body: string }>();
  const rows = res.results ?? [];
  const cveFindings: BriefingFinding[] = [];
  const ransomwareFindings: BriefingFinding[] = [];
  const sources = new Set<string>();
  let iocBuckets: BriefingIocBuckets = { urls: [], domains: [], ipv4s: [], hashes: [] };
  let maxDailyRawTotal = 0;
  for (const row of rows) {
    const b = safeJsonParse<Briefing | null>(row.body, null);
    if (!b) continue;
    for (const section of b.sections ?? []) {
      for (const f of section.findings ?? []) {
        if (isRansomwareFinding(section.id, f)) ransomwareFindings.push(f);
        else cveFindings.push(f);
      }
    }
    if (b.iocs) iocBuckets = mergeIocBuckets(iocBuckets, b.iocs);
    // The stored buckets may have been trimmed by capBriefingForStorage on a
    // very large day; rawTotal holds that day's pre-trim unique count. Keep
    // the largest so the weekly total never undercounts a capped day.
    maxDailyRawTotal = Math.max(maxDailyRawTotal, b.ioc_dump?.rawTotal ?? b.stats?.iocs ?? 0);
    for (const s of b.sources ?? []) sources.add(s);
  }
  // IOC total is the count of the MERGED (deduped) buckets, not the sum of
  // per-daily stats — the same indicator can appear in multiple daily
  // briefings within a weekly window, and summing `stats.iocs` double-counts.
  const mergedIocCount =
    iocBuckets.urls.length + iocBuckets.domains.length + iocBuckets.ipv4s.length + iocBuckets.hashes.length;
  const iocsTotal = Math.max(mergedIocCount, maxDailyRawTotal);
  return {
    findings: dedupeCveFindings(cveFindings),
    ransomwareFindings: dedupeRansomwareFindings(ransomwareFindings),
    iocsTotal,
    iocBuckets,
    sources: [...sources],
    dailyCount: rows.length,
  };
}

export async function weeklyUndercountsDailies(
  db: D1Database,
  weeklySlug: string,
  rangeStartIso: string,
  rangeEndIso: string
): Promise<boolean> {
  const weeklyRow = await db
    .prepare('SELECT stats_json FROM briefings WHERE slug = ?')
    .bind(weeklySlug)
    .first<{ stats_json?: string }>();
  if (!weeklyRow) return false;
  const weekly = safeJsonParse<{ findings?: number; iocs?: number }>(weeklyRow.stats_json, {});
  const res = await db
    .prepare('SELECT stats_json FROM briefings WHERE type = ? AND date >= ? AND date <= ?')
    .bind('daily', rangeStartIso, rangeEndIso)
    .all<{ stats_json: string }>();
  const rows = res.results ?? [];
  if (rows.length === 0) return false;
  let sumFindings = 0;
  let sumIocs = 0;
  for (const r of rows) {
    const s = safeJsonParse<{ findings?: number; iocs?: number }>(r.stats_json, {});
    sumFindings += s.findings ?? 0;
    sumIocs += s.iocs ?? 0;
  }
  const wFindings = weekly.findings ?? 0;
  const wIocs = weekly.iocs ?? 0;
  return wFindings * 4 < sumFindings || (wIocs === 0 && sumIocs > 0);
}

export function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function isBriefingRich(statsJson: string | null | undefined): boolean {
  const s = safeJsonParse<{ findings?: number; iocs?: number }>(statsJson, {});
  return (s.findings ?? 0) > 0 || (s.iocs ?? 0) > 0;
}

export function isBriefingDegraded(body: string | null | undefined): boolean {
  return safeJsonParse<{ degraded?: boolean }>(body, {}).degraded === true;
}

export function briefingNeedsHeal(
  row: { stats_json?: string | null; body?: string | null } | null | undefined,
  opts: { now: number; cooldownMs?: number }
): boolean {
  if (!row) return true;
  if (!isBriefingDegraded(row.body)) {
    return !isBriefingRich(row.stats_json);
  }
  const cooldownMs = opts.cooldownMs ?? 0;
  if (cooldownMs <= 0) return true;
  const last = Date.parse(safeJsonParse<{ generated_at?: string }>(row.body, {}).generated_at ?? '');
  if (!Number.isFinite(last)) return true;
  return opts.now - last >= cooldownMs;
}

export function dailyNeedsCveReenrich(
  row: { stats_json?: string | null; body?: string | null } | null | undefined,
  opts: { now: number; cooldownMs?: number }
): boolean {
  if (!row) return false;
  const s = safeJsonParse<{ findings?: number; iocs?: number }>(row.stats_json, {});
  if ((s.findings ?? 0) > 0 || (s.iocs ?? 0) <= 0) return false;
  const cooldownMs = opts.cooldownMs ?? 0;
  if (cooldownMs <= 0) return true;
  const last = Date.parse(safeJsonParse<{ generated_at?: string }>(row.body, {}).generated_at ?? '');
  if (!Number.isFinite(last)) return true;
  return opts.now - last >= cooldownMs;
}

/**
 * Re-heal a daily that is otherwise "rich" (has CVE findings + IOCs) but the
 * ransomware section is empty. The original 00:30 build can land a 0-ransom
 * row for two real-world reasons that the basic `briefingNeedsHeal` won't
 * catch:
 *   1. Transient upstream failure on the first build: ransomware.live or
 *      ransomlook returned 5xx/timeout and the .catch(() => []) left us
 *      with an empty bundle, but the rest of the build still wrote a
 *      non-empty row. The heal's primary gate then never fires again
 *      because the row is "rich" (findings>0 or iocs>0).
 *   2. A retry of just the ransomware fetch later in the day would land
 *      fresh data — the trackers' 7-day window still includes the date.
 * Triggers a full rebuild via the same path the CVE-reenrich uses, which
 * re-fetches all 8 sources and overwrites the row. Cooldown mirrors the
 * CVE variant (default 3h) so we don't thrash within an hour.
 */
export function dailyNeedsRansomwareReenrich(
  row: { stats_json?: string | null; body?: string | null } | null | undefined,
  opts: { now: number; cooldownMs?: number }
): boolean {
  if (!row) return false;
  const s = safeJsonParse<{ findings?: number; iocs?: number; ransomware_victims?: number }>(row.stats_json, {});
  // Only worth re-running if the rest of the briefing is rich AND the
  // ransomware section came back empty. A truly empty daily still falls
  // through to briefingNeedsHeal's primary path.
  if ((s.findings ?? 0) <= 0 && (s.iocs ?? 0) <= 0) return false;
  if ((s.ransomware_victims ?? 0) > 0) return false;
  const cooldownMs = opts.cooldownMs ?? 0;
  if (cooldownMs <= 0) return true;
  const last = Date.parse(safeJsonParse<{ generated_at?: string }>(row.body, {}).generated_at ?? '');
  if (!Number.isFinite(last)) return true;
  return opts.now - last >= cooldownMs;
}
