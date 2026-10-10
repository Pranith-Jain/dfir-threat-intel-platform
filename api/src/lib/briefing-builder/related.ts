import type { D1Database } from '@cloudflare/workers-types';
import type { IocEntry } from '../ioc-feed-parsers';
import type { Briefing, BriefingType, RelatedBriefingRef, Severity } from './types';

/**
 * Related-briefing linkage — a TS port of the case-queue "related case"
 * matching from reindrops86/Agentic-Cyber-Threat-Intelligence-Researcher
 * (CTIcode.py, CaseTriageManager.find_related_cases), adapted to the
 * briefing pipeline.
 *
 * Semantics preserved from upstream:
 *   1. Two briefings are related when their normalized IOC sets overlap
 *      (domains/IPs/hashes (+ URL hosts, mirroring upstream's URL→domain
 *      enrichment step)).
 *   2. If the indicator overlap is zero, they can still be related when the
 *      executive summaries share a tactic keyword (upstream
 *      MATCH_KEYWORDS; here adapted to CTI vocabulary).
 *   3. Matches rank by (match_count desc, severity rank desc, most recent
 *      first) and are capped (default 5).
 *
 * Deterministic, no LLM — computed at write time (stamped into the brief
 * body) and available live via the /api/v1/briefings/related route + the
 * `briefings_related` MCP tool.
 */

/** Keyword vocabulary for the summary-overlap fallback (upstream MATCH_KEYWORDS, CTI-adapted). */
export const RELATED_KEYWORDS = [
  'phishing',
  'malware',
  'ransomware',
  'loader',
  'credential',
  'apt',
  'c2',
  'exploit',
  'campaign',
];

export interface RelatedBriefingOptions {
  /** Max matches returned. */
  limit?: number;
  /** Max candidate rows scanned (recent first). */
  maxCandidates?: number;
}

/** Fast pure ranker + normalizers — unit-testable without D1. */

/** Normalize one IOC value to a comparable key. Domains, URL hosts, IPs and
 *  hashes all collapse into plain lowercase strings (upstream semantics —
 *  a URL host overlaps the same domain observed bare, and 32/64-hex hashes
 *  can't collide with domains in practice). */
export function normalizeIocValue(type: string, value: string): string {
  const v = value.trim().toLowerCase();
  switch (type) {
    case 'domain':
      return v.replace(/\.+$/, '');
    case 'url': {
      try {
        return new URL(v).hostname.toLowerCase().replace(/\.+$/, '');
      } catch {
        return v.replace(/\.+$/, '');
      }
    }
    case 'ipv4':
      return v;
    default:
      return v;
  }
}

/** Normalized IOC key set of a briefing (domains, IPs, hashes + URL hosts). */
export function briefingIocKeySet(briefing: Briefing): Set<string> {
  const set = new Set<string>();
  const buckets = briefing.iocs;
  if (!buckets) return set;
  for (const entry of buckets.domains) if (entry?.value) set.add(normalizeIocValue('domain', entry.value));
  for (const entry of buckets.urls) if (entry?.value) set.add(normalizeIocValue('url', entry.value));
  for (const entry of buckets.ipv4s) if (entry?.value) set.add(normalizeIocValue('ipv4', entry.value));
  for (const entry of buckets.hashes) if (entry?.value) set.add(normalizeIocValue('hash', entry.value));
  return set;
}

/** True when both summaries share at least one RELATED_KEYWORDS term. */
export function summaryKeywordOverlap(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const al = a.toLowerCase();
  const bl = b.toLowerCase();
  return RELATED_KEYWORDS.some((k) => al.includes(k) && bl.includes(k));
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

/** Top severity present in a briefing's stats (critical > high > medium > low). */
export function severityFromStats(stats?: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}): Severity {
  if (!stats) return 'unknown';
  if ((stats.critical ?? 0) > 0) return 'critical';
  if ((stats.high ?? 0) > 0) return 'high';
  if ((stats.medium ?? 0) > 0) return 'medium';
  if ((stats.low ?? 0) > 0) return 'low';
  return 'unknown';
}

/** Pure match + rank over candidate briefings (upstream find_related_cases). */
export function rankRelatedBriefings(
  current: Briefing,
  candidates: Array<{ briefing: Briefing; severity: Severity }>,
  limit = 5
): RelatedBriefingRef[] {
  const currentKeys = briefingIocKeySet(current);
  const currentSummary = current.executive_summary;
  const matches: Array<{ ref: RelatedBriefingRef; matchCount: number; severityRank: number; rangeEnd: string }> = [];

  for (const { briefing, severity } of candidates) {
    if (briefing.slug === current.slug) continue;
    let matchCount = 0;
    let keywordMatch = false;
    for (const key of briefingIocKeySet(briefing)) {
      if (currentKeys.has(key)) matchCount += 1;
    }
    if (matchCount === 0 && summaryKeywordOverlap(currentSummary, briefing.executive_summary)) {
      keywordMatch = true;
      matchCount = 1;
    }
    if (matchCount > 0) {
      matches.push({
        ref: {
          slug: briefing.slug,
          type: briefing.type,
          title: briefing.title,
          date_range: briefing.date_range,
          range_end: briefing.range_end,
          severity,
          match_count: keywordMatch ? 1 : matchCount,
          keyword_match: keywordMatch,
        },
        matchCount,
        severityRank: SEVERITY_RANK[severity] ?? 0,
        rangeEnd: briefing.range_end,
      });
    }
  }

  matches.sort(
    (a, b) =>
      b.matchCount - a.matchCount ||
      b.severityRank - a.severityRank ||
      (a.rangeEnd < b.rangeEnd ? 1 : a.rangeEnd > b.rangeEnd ? -1 : 0)
  );
  return matches.slice(0, limit).map((m) => m.ref);
}

/** D1-backed lookup: fetch candidate rows (recent first, bounded), parse the
 *  slim extract (exec summary + IOC buckets via json_extract — never the full
 *  multi-MB body), and run rankRelatedBriefings. */
export async function findRelatedBriefings(
  db: D1Database,
  current: Briefing,
  options?: RelatedBriefingOptions
): Promise<RelatedBriefingRef[]> {
  const limit = Math.min(Math.max(options?.limit ?? 5, 1), 20);
  /**
   * Candidate pool for the "related briefings" stamp.
   *
   * Every candidate has all four IOC buckets pulled out with json_extract and
   * JSON.parse'd. With an average stored body of ~800 KB that is roughly 20 MB
   * of JSON parsed per build, and it ran the daily briefing past the
   * free-plan 10ms CPU limit ("Worker exceeded CPU time limit").
   *
   * Ranking keeps only `limit` (5) matches, newest-first, so a deep pool buys
   * almost nothing — the extra 35 candidates are parsed only to be discarded.
   * 12 still spans several weeks of dailies plus the recent weeklies, which is
   * more than enough to find real overlap. Raise it only alongside a cheaper
   * scoring path (e.g. comparing hashes, not every indicator).
   */
  const maxCandidates = Math.min(Math.max(options?.maxCandidates ?? 12, 1), 200);

  const rows = await db
    .prepare(
      `SELECT slug, type, title, date_range, range_end, stats_json,
              json_extract(body, '$.executive_summary') AS executive_summary,
              json_extract(body, '$.iocs.domains') AS domains,
              json_extract(body, '$.iocs.urls') AS urls,
              json_extract(body, '$.iocs.ipv4s') AS ipv4s,
              json_extract(body, '$.iocs.hashes') AS hashes
       FROM briefings
       WHERE slug != ?
       ORDER BY range_end DESC, created_at DESC
       LIMIT ?`
    )
    .bind(current.slug, maxCandidates)
    .all<{
      slug: string;
      type: BriefingType;
      title: string;
      date_range: string;
      range_end: string;
      stats_json: string | null;
      executive_summary: string | null;
      domains: string | null;
      urls: string | null;
      ipv4s: string | null;
      hashes: string | null;
    }>();

  const candidates: Array<{ briefing: Briefing; severity: Severity }> = [];
  for (const row of rows.results ?? []) {
    let stats: Partial<{ critical: number; high: number; medium: number; low: number }> | null = null;
    try {
      stats = row.stats_json ? JSON.parse(row.stats_json) : null;
    } catch {
      /* stats_json corruption → severity unknown, still matchable */
    }
    const parseBucket = (raw: string | null): IocEntry[] => {
      if (!raw) return [];
      try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];
        return parsed.filter(
          (item): item is IocEntry =>
            typeof item === 'object' &&
            item !== null &&
            typeof (item as IocEntry).value === 'string' &&
            (item as IocEntry).type !== undefined
        );
      } catch {
        return [];
      }
    };
    candidates.push({
      briefing: {
        slug: row.slug,
        type: row.type,
        title: row.title,
        date: '',
        date_range: row.date_range,
        range_start: '',
        range_end: row.range_end,
        generated_at: '',
        executive_summary: row.executive_summary ?? '',
        stats: {} as Briefing['stats'],
        sections: [],
        mitre_techniques: [],
        sources: [],
        iocs: {
          domains: parseBucket(row.domains),
          urls: parseBucket(row.urls),
          ipv4s: parseBucket(row.ipv4s),
          hashes: parseBucket(row.hashes),
        },
      },
      severity: severityFromStats(stats ?? undefined),
    });
  }

  return rankRelatedBriefings(current, candidates, limit);
}

/** Write-time hook: stamp related links into the body before INSERT so the
 *  stored briefing (and every reader, incl. the SPA) carries them without a
 *  per-read scan. Best-effort — never fails the write. */
export async function stampRelatedBriefings(
  db: D1Database,
  briefing: Briefing,
  options?: RelatedBriefingOptions
): Promise<void> {
  try {
    briefing.related_briefings = await findRelatedBriefings(db, briefing, options);
  } catch {
    briefing.related_briefings = [];
  }
}
