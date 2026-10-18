/**
 * Threat Landscape Report — monthly strategic product.
 *
 * Distinct from the daily/weekly briefings, which are tactical and event-driven.
 * The landscape report is a leadership-facing synthesis of the prior month's
 * threat activity, with sections for: top threats, trending actors, key
 * incidents, recommended actions, and outlook. Patterned on zsazsa's
 * "Threat landscape report" CTI product.
 *
 * Slug format: `landscape-YYYY-MM` (one per calendar month, anchored on the
 * first of the month UTC).
 *
 * Storage reuses the existing `briefings` D1 table with `type='landscape'`,
 * so no schema migration is required.
 */
import type { D1Database } from '@cloudflare/workers-types';
import { fetchRansomwareRecent } from '../routes/ransomware-recent';
import { runCompletion } from '../case-study/generation/ai-client';
import type { Env } from '../env';

export type LandscapeSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface LandscapeSection {
  id: string;
  title: string;
  blurb: string;
  count: number;
  findings: Array<{
    id: string;
    title: string;
    description: string;
    severity: LandscapeSeverity;
    source: string;
    source_url?: string;
    count?: number;
  }>;
}

export interface ThreatLandscapeReport {
  slug: string;
  type: 'landscape';
  title: string;
  date: string; // ISO YYYY-MM-01
  date_range: string; // e.g. "2026-05-01 – 2026-05-31"
  range_start: string;
  range_end: string;
  generated_at: string;
  executive_summary: string;
  top_threats: LandscapeSection;
  trending_actors: LandscapeSection;
  key_incidents: LandscapeSection;
  recommended_actions: LandscapeSection;
  outlook: LandscapeSection;
  stats: {
    ransomware_victims: number;
    top_groups: number;
    incidents_surfaced: number;
    recommendations: number;
    sources: number;
  };
  sources: string[];
}

export const BRIEFING_LANDSCAPE_TYPE = 'landscape' as const;

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/**
 * Slug for the landscape report covering the calendar month containing
 * `anchor` (default: now). e.g. anchor=2026-05-15 → "landscape-2026-05".
 */
export function expectedLandscapeSlug(anchor: Date = new Date()): string {
  return `landscape-${anchor.getUTCFullYear()}-${pad2(anchor.getUTCMonth() + 1)}`;
}

/**
 * Build a landscape report for the calendar month containing `anchor`. Pulls
 * the merged ransomware-victim feed (the broadest single signal we have) to
 * drive the top-threats/trending-actors/key-incidents sections, and asks the
 * LLM to write the prose.
 *
 * Falls back to a deterministic, source-cited summary if the LLM is
 * unavailable — same pattern as buildBriefing's executive summary. This
 * keeps the product shippable even on a full AI outage.
 */
export async function buildLandscapeReport(
  anchor: Date = new Date(),
  opts: { env?: Env } = {}
): Promise<ThreatLandscapeReport> {
  const start = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth(), 1));
  const end = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth() + 1, 1));
  const slug = `landscape-${start.getUTCFullYear()}-${pad2(start.getUTCMonth() + 1)}`;
  const rangeLabel = `${start.toISOString().slice(0, 10)} – ${new Date(end.getTime() - 86400_000)
    .toISOString()
    .slice(0, 10)}`;

  // Pull the last 30 days of ransomware activity. The merged feed carries
  // group, victim, country, sector, and per-row `discovered` timestamps
  // — everything the top-threats/actors sections need.
  let victims: Array<{
    group?: string;
    victim?: string;
    country?: string;
    sector?: string;
    discovered?: string;
    description?: string;
    source_url?: string;
    origin?: string;
  }> = [];
  if (opts.env) {
    try {
      const { body } = await fetchRansomwareRecent(opts.env);
      victims = (body.victims ?? []).slice(0, 1000);
    } catch {
      victims = [];
    }
  }

  const inWindow = victims.filter((v) => {
    if (!v.discovered) return false;
    const t = Date.parse(v.discovered);
    if (Number.isNaN(t)) return false;
    return t >= start.getTime() && t < end.getTime();
  });

  // Top groups by victim count (groups that claim a lot = "trending actor").
  const groupCounts = new Map<string, number>();
  for (const v of inWindow) {
    if (!v.group) continue;
    groupCounts.set(v.group, (groupCounts.get(v.group) ?? 0) + 1);
  }
  const topGroups = Array.from(groupCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Top sectors.
  const sectorCounts = new Map<string, number>();
  for (const v of inWindow) {
    if (!v.sector) continue;
    sectorCounts.set(v.sector, (sectorCounts.get(v.sector) ?? 0) + 1);
  }
  const topSectors = Array.from(sectorCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Top countries.
  const countryCounts = new Map<string, number>();
  for (const v of inWindow) {
    if (!v.country) continue;
    countryCounts.set(v.country, (countryCounts.get(v.country) ?? 0) + 1);
  }
  const topCountries = Array.from(countryCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const top_threats: LandscapeSection = {
    id: 'top-threats',
    title: 'Top Threat Categories',
    blurb: `Sectors and geographies most affected by ransomware activity in ${start.toISOString().slice(0, 7)}.`,
    count: topSectors.length + topCountries.length,
    findings: [
      ...topSectors.map(([sector, n], i) => ({
        id: `sector-${i}`,
        title: `${sector} (${n} victims)`,
        description: `Ransomware impact concentrated in the ${sector} sector this period.`,
        severity: 'high' as const,
        source: 'Merged ransomware feed',
        count: n,
      })),
      ...topCountries.map(([country, n], i) => ({
        id: `country-${i}`,
        title: `${country} (${n} victims)`,
        description: `${country} was the most-targeted geography for ransomware claims this period.`,
        severity: 'medium' as const,
        source: 'Merged ransomware feed',
        count: n,
      })),
    ],
  };

  const trending_actors: LandscapeSection = {
    id: 'trending-actors',
    title: 'Trending Threat Actors',
    blurb: `Ransomware groups ranked by claimed victim count for ${start.toISOString().slice(0, 7)}.`,
    count: topGroups.length,
    findings: topGroups.map(([group, n], i) => ({
      id: `actor-${i}`,
      title: `${group} (${n} claimed victims)`,
      description: `${group} claimed ${n} victims across leak-site posts this period.`,
      severity: (i < 3 ? 'high' : 'medium') as LandscapeSeverity,
      source: 'Ransomlook + ransomware.live + ransomwatch + ransomfeed.it',
      source_url: `https://www.ransomlook.io/group/${encodeURIComponent(group)}`,
      count: n,
    })),
  };

  const key_incidents: LandscapeSection = {
    id: 'key-incidents',
    title: 'Key Incidents',
    blurb: 'Notable victim claims from the period — chosen by recency and group activity.',
    count: Math.min(8, inWindow.length),
    findings: inWindow.slice(0, 8).map((v, i) => ({
      id: `incident-${i}`,
      title: v.victim ?? 'Unknown victim',
      description:
        v.description?.slice(0, 200) ??
        `${v.group ?? 'Unknown group'} claimed ${v.victim ?? 'an unnamed organisation'} in ${v.country ?? 'an undisclosed country'} (${v.sector ?? 'sector unreported'}).`,
      severity: 'high' as const,
      source: v.origin ?? 'Ransomware aggregator',
      source_url: v.source_url,
    })),
  };

  const recommended_actions: LandscapeSection = {
    id: 'recommended-actions',
    title: 'Recommended Actions',
    blurb: "Immediate and near-term actions informed by the period's activity.",
    count: 5,
    findings: [
      {
        id: 'rec-1',
        title: 'Patch the KEV-actively-exploited CVEs published this month',
        description:
          'CISA KEV additions during the period represent confirmed in-the-wild exploitation. Prioritise remediation across all internet-facing assets.',
        severity: 'critical',
        source: 'CISA KEV',
        source_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      },
      {
        id: 'rec-2',
        title: `Validate backups against ${topGroups[0]?.[0] ?? 'top groups'} TTPs`,
        description: `The most active group(s) this month: ${
          topGroups
            .slice(0, 3)
            .map((g) => g[0])
            .join(', ') || 'see trending actors'
        }. Test restore procedures against their known techniques.`,
        severity: 'high',
        source: 'Trending actors',
      },
      {
        id: 'rec-3',
        title: `Harden ${topSectors[0]?.[0] ?? 'high-impact'} sector exposure`,
        description: `The ${topSectors[0]?.[0] ?? 'most-affected'} sector saw the heaviest victim concentration this period. Review segment controls and supplier dependencies.`,
        severity: 'high',
        source: 'Top threats',
      },
      {
        id: 'rec-4',
        title: 'Subscribe to the top-3 groups for monitoring',
        description: `Add ${
          topGroups
            .slice(0, 3)
            .map((g) => g[0])
            .join(', ') || 'the trending groups'
        } to the watch engine for IOC pivots and dark-web chatter.`,
        severity: 'medium',
        source: 'Watch engine',
      },
      {
        id: 'rec-5',
        title: 'Review out-of-cycle briefing coverage',
        description:
          'Cross-reference the daily/weekly briefings from this period for any patterns the landscape view may have smoothed over.',
        severity: 'low',
        source: 'Internal — briefings',
      },
    ],
  };

  const outlook: LandscapeSection = {
    id: 'outlook',
    title: 'Outlook',
    blurb: 'What the next month likely looks like, based on observed patterns.',
    count: 3,
    findings: [
      {
        id: 'out-1',
        title: 'Continued activity from the top-3 groups',
        description: `Based on the volume trajectory, ${
          topGroups
            .slice(0, 3)
            .map((g) => g[0])
            .join(', ') || 'the top groups'
        } are likely to remain the dominant threat through the next period.`,
        severity: 'medium',
        source: 'Trend extrapolation',
      },
      {
        id: 'out-2',
        title: 'Watch for copycat leak-site posts',
        description:
          'When a top group rebrands or splits, copycat leak sites often appear within days. The watch engine should detect new onion mirrors automatically.',
        severity: 'medium',
        source: 'Onion watch',
      },
      {
        id: 'out-3',
        title: "Anticipate KEV additions tied to this month's high-CVSS NVD entries",
        description:
          'CISA typically adds CVEs to KEV within 2-4 weeks of confirmed exploitation. CVEs with CVSS >= 9.0 published this month are the highest-priority candidates.',
        severity: 'low',
        source: 'CISA KEV / NVD correlation',
      },
    ],
  };

  // LLM-generated executive summary; falls back to a deterministic one.
  const executive_summary = await buildLandscapeExecutiveSummary({
    env: opts.env,
    rangeLabel,
    topGroups,
    topSectors,
    topCountries,
    totalVictims: inWindow.length,
  });

  const sources = [
    'Ransomlook',
    'ransomware.live',
    'ransomfeed.it',
    'ransomwatch',
    'andreafortuna',
    'mythreatintel',
    'CISA KEV',
    'NVD',
  ];

  return {
    slug,
    type: 'landscape',
    title: `Threat Landscape Report — ${start.toISOString().slice(0, 7)}`,
    date: start.toISOString().slice(0, 10),
    date_range: rangeLabel,
    range_start: start.toISOString().slice(0, 10),
    range_end: new Date(end.getTime() - 86400_000).toISOString().slice(0, 10),
    generated_at: new Date().toISOString(),
    executive_summary,
    top_threats,
    trending_actors,
    key_incidents,
    recommended_actions,
    outlook,
    stats: {
      ransomware_victims: inWindow.length,
      top_groups: topGroups.length,
      incidents_surfaced: key_incidents.count,
      recommendations: recommended_actions.count,
      sources: sources.length,
    },
    sources,
  };
}

async function buildLandscapeExecutiveSummary(input: {
  env?: Env;
  rangeLabel: string;
  topGroups: Array<[string, number]>;
  topSectors: Array<[string, number]>;
  topCountries: Array<[string, number]>;
  totalVictims: number;
}): Promise<string> {
  const fallback = `Threat landscape for ${input.rangeLabel}: ${input.totalVictims} ransomware victims were claimed across the merged feed (Ransomlook + ransomware.live + ransomwatch + ransomfeed.it + andreafortuna). The most active group was ${input.topGroups[0]?.[0] ?? 'unattributed'} (${input.topGroups[0]?.[1] ?? 0} claims), with the ${input.topSectors[0]?.[0] ?? 'mixed'} sector and ${input.topCountries[0]?.[0] ?? 'multi-country'} geography most affected. Recommended actions prioritise KEV-driven patching, backup validation against the top groups' TTPs, and sector-specific hardening.`;

  if (!input.env) return fallback;
  const env = input.env;
  const prompt = `Write a 2-3 sentence executive summary for a monthly threat landscape report.

Period: ${input.rangeLabel}
Total ransomware victims claimed: ${input.totalVictims}
Top 3 groups: ${
    input.topGroups
      .slice(0, 3)
      .map(([g, n]) => `${g} (${n})`)
      .join(', ') || 'no group data'
  }
Top 3 sectors: ${
    input.topSectors
      .slice(0, 3)
      .map(([s, n]) => `${s} (${n})`)
      .join(', ') || 'no sector data'
  }
Top 3 countries: ${
    input.topCountries
      .slice(0, 3)
      .map(([c, n]) => `${c} (${n})`)
      .join(', ') || 'no country data'
  }

Constraints: be specific (use group/sector/country names from above), be concise (2-3 sentences, max 60 words), focus on what a CISO needs to know.`;
  try {
    const result = await Promise.race([
      runCompletion(
        env.AI,
        {
          system:
            'You are a senior CTI analyst writing the executive summary of a monthly threat landscape report for a CISO audience. Be specific, concise, and actionable. Do not invent CVE IDs, actors, or sectors — use only the data provided.',
          user: prompt,
          maxTokens: 200,
          temperature: 0.3,
        },
        {
          googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: env.GROQ_API_KEY,
          quality: true,
        }
      ),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('llm-landscape-timeout')), 6000)),
    ]);
    const text = (result as { text?: string }).text?.trim();
    return text && text.length > 20 ? text : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Persist a landscape report. Reuses the same `briefings` D1 table — the
 * `type` column carries 'landscape' so it can coexist with daily/weekly
 * rows and is excluded from those types' `listBriefings()` filters when
 * they specify a type.
 */
export async function writeLandscapeReport(
  db: D1Database,
  report: ThreatLandscapeReport
): Promise<{ written: boolean; reason?: string }> {
  const existing = await db
    .prepare('SELECT slug, body FROM briefings WHERE slug = ?')
    .bind(report.slug)
    .first<{ slug: string; body: string }>();
  if (existing) {
    return { written: false, reason: 'already_exists' };
  }
  await db
    .prepare(
      `INSERT INTO briefings (slug, type, title, date, date_range, range_start, range_end, body)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      report.slug,
      report.type,
      report.title,
      report.date,
      report.date_range,
      report.range_start,
      report.range_end,
      JSON.stringify(report)
    )
    .run();
  return { written: true };
}
