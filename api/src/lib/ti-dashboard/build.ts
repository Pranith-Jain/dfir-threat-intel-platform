import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../../env';
import {
  collectNewsArticles,
  persistArticles,
  fetchRecentArticles,
  fetchSupplyChainIncidents,
  persistSupplyChainIncidents,
  fetchRecentSupplyChainIncidents,
} from './feeds';
import type {
  TiDashboardReport,
  Article,
  ThreatStory,
  ActorProfile,
  HuntingLead,
  DashboardStats,
  SupplyChainIncident,
} from './types';
import { runCompletion } from '../../case-study/generation/ai-client';
import { fenceUntrusted, UNTRUSTED_DATA_SYSTEM_NOTE } from '../prompt-fence';
import { extractJson } from '../llm-json';

function isoYearWeek(d: Date): string {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil(((dt.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return `${dt.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`;
}

function startOfIsoWeek(d: Date): Date {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() - (day - 1));
  return dt;
}

async function enrichWithLlm(
  articles: Article[],
  supplyChain: SupplyChainIncident[],
  env?: Env
): Promise<{
  executive_brief: string;
  threat_stories: ThreatStory[];
  actor_profiles: ActorProfile[];
  hunting_leads: HuntingLead[];
  statistics: DashboardStats;
}> {
  const empty = {
    executive_brief: '',
    threat_stories: [] as ThreatStory[],
    actor_profiles: [] as ActorProfile[],
    hunting_leads: [] as HuntingLead[],
    statistics: {
      top_actors: [] as [string, number][],
      top_targeted_industries: [] as [string, number][],
      emerging_trends: [] as string[],
      declining_threats: [] as string[],
      key_changes: '',
    } as DashboardStats,
  };

  if (!env || articles.length === 0) return empty;

  const articleSummaries = articles
    .slice(0, 40)
    .map((a, i) => {
      const s = (a.summary || '').slice(0, 200);
      return `[${i + 1}] ${a.title} (${a.source_type}, ${a.published_date.slice(0, 10)})${s ? `\n    ${s}` : ''}`;
    })
    .join('\n\n');

  const supplyChainSummary = supplyChain
    .slice(0, 20)
    .map(
      (s) =>
        `- ${s.title} [${s.ecosystem}] severity=${s.severity} status=${s.status}${s.threat_actor ? ` actor=${s.threat_actor}` : ''}`
    )
    .join('\n');

  const prompt = [
    'You are a senior CTI analyst. Given the weekly security news articles and supply chain incidents below, generate a structured threat intelligence report as valid JSON. No markdown fences, no commentary — ONLY the JSON object.',
    '',
    'The response must be parseable JSON with exactly this shape:',
    JSON.stringify(
      {
        executive_brief: '2-3 paragraph markdown summary of the week in threat intel',
        threat_stories: [
          {
            headline: 'short title',
            narrative: 'detailed markdown narrative with context and analysis',
            impact_assessment: 'Critical/High/Medium',
            action_required: 'specific remediation or monitoring advice',
            timeline: [{ date: 'YYYY-MM-DD', event: 'what happened', significance: 'why it matters' }],
            sources: [1, 2, 3],
          },
        ],
        actor_profiles: [
          {
            name: 'actor name',
            motivation: 'Espionage/Financial/Disruption',
            recent_activity: 'description of recent campaigns',
            aliases: ['alias1'],
            targets: ['government', 'energy'],
            ttps: ['T1190', 'T1566'],
            sources: [1],
          },
        ],
        hunting_leads: [
          {
            title: 'hunt name',
            context: 'why this hunt matters now',
            query: 'KQL or Sigma query',
            indicators: ['indicator1'],
            sources: [1],
          },
        ],
        statistics: {
          top_actors: [['ActorName', 3]],
          top_targeted_industries: [['Technology', 5]],
          emerging_trends: ['trend1'],
          declining_threats: ['threat1'],
          key_changes: 'notable shift in TTPs or targeting',
        },
      },
      null,
      2
    ),
    '',
    'Articles this week:',
    fenceUntrusted(articleSummaries, 'ARTICLES'),
    '',
    supplyChainSummary ? `Supply chain incidents:\n${fenceUntrusted(supplyChainSummary, 'SUPPLY_CHAIN')}` : '',
    '',
    'Requirements: Stories must cite specific articles as sources (use the [N] index). Impact assessment must be Critical, High, or Medium. Keep threat_stories to 3-5 most important. Actor profiles should only include actors mentioned in articles. Hunting leads should suggest concrete detection queries. Timelines are optional — only include when there are dated events to list.',
  ]
    .filter(Boolean)
    .join('\n');

  try {
    const result = await Promise.race([
      runCompletion(
        env.AI,
        {
          system:
            'You are a senior CTI analyst. Output ONLY valid JSON matching the requested schema. No explanations, no markdown fences.\n\n' +
            UNTRUSTED_DATA_SYSTEM_NOTE,
          user: prompt,
          maxTokens: 4096,
          temperature: 0.3,
        },
        {
          googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: env.GROQ_API_KEY,
          quality: true,
        }
      ),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('llm-enrichment-timeout')), 30000)),
    ]);

    const text = result.text?.trim();
    if (!text) return empty;

    // extractJson repairs the common LLM defects (literal newlines inside
    // strings, trailing commas, fences) so a sloppy model response enriches
    // the report instead of silently producing an empty one.
    const parsed = extractJson<{
      executive_brief?: string;
      threat_stories?: ThreatStory[];
      actor_profiles?: ActorProfile[];
      hunting_leads?: HuntingLead[];
      statistics?: DashboardStats;
    }>(text);
    if (!parsed) return empty;
    return {
      executive_brief: parsed.executive_brief || '',
      threat_stories: Array.isArray(parsed.threat_stories) ? parsed.threat_stories : [],
      actor_profiles: Array.isArray(parsed.actor_profiles) ? parsed.actor_profiles : [],
      hunting_leads: Array.isArray(parsed.hunting_leads) ? parsed.hunting_leads : [],
      statistics: parsed.statistics || empty.statistics,
    };
  } catch {
    return empty;
  }
}

export async function buildWeeklyDashboard(env: Env, anchor: Date = new Date()): Promise<TiDashboardReport> {
  const weekStart = startOfIsoWeek(anchor);
  const weekEnd = new Date(weekStart.getTime() + 7 * 86400_000);
  const weekStartStr = weekStart.toISOString().slice(0, 10);
  const weekEndStr = weekEnd.toISOString().slice(0, 10);
  const _weekLabel = `${weekStartStr} – ${weekEndStr}`;
  const slug = `ti-dashboard-weekly-${isoYearWeek(weekStart)}`;

  const db = env.BRIEFINGS_DB;

  const [articles, supplyChainIncidents] = await Promise.all([collectNewsArticles(), fetchSupplyChainIncidents()]);

  const _articleInserted = db ? await persistArticles(db, articles) : 0;
  const _scInserted = db ? await persistSupplyChainIncidents(db, supplyChainIncidents) : 0;

  const _recentArticles = db ? await fetchRecentArticles(db, 100) : articles;
  const recentSc = db
    ? await fetchRecentSupplyChainIncidents(db, 50)
    : supplyChainIncidents.map((r, i) => ({ ...r, id: i }));

  const scForReport: SupplyChainIncident[] = recentSc.map((s) => ({
    title: s.title,
    ecosystem: s.ecosystem,
    attack_vector: s.attack_vector,
    severity: s.severity,
    status: s.status,
    threat_actor: s.threat_actor,
    url: s.url,
    summary: s.summary,
  }));

  const sources = articles.slice(0, 200).map((a, i) => ({
    id: i + 1,
    title: a.title,
    url: a.url,
    published_date: a.published_date,
    source_type: a.source_type,
  }));

  const enrichment = await enrichWithLlm(articles, scForReport, env);

  return {
    slug,
    week_start: weekStartStr,
    week_end: weekEndStr,
    generated_at: new Date().toISOString(),
    metadata: {
      documents_analyzed: articles.length + supplyChainIncidents.length,
      reading_time_minutes: Math.max(1, Math.ceil((articles.length + supplyChainIncidents.length) / 20)),
      time_period_days: 7,
    },
    sources,
    executive_brief: enrichment.executive_brief,
    threat_stories: enrichment.threat_stories,
    actor_profiles: enrichment.actor_profiles,
    critical_vulnerabilities: [],
    hunting_leads: enrichment.hunting_leads,
    supply_chain_incidents: scForReport,
    statistics: enrichment.statistics,
  };
}

export async function persistDashboard(db: D1Database, report: TiDashboardReport): Promise<void> {
  await db
    .prepare('INSERT OR REPLACE INTO weekly_reports (slug, week_start, week_end, body) VALUES (?, ?, ?, ?)')
    .bind(report.slug, report.week_start, report.week_end, JSON.stringify(report))
    .run();
}

export async function readDashboard(db: D1Database, slug?: string): Promise<TiDashboardReport | null> {
  if (slug) {
    const row = await db.prepare('SELECT body FROM weekly_reports WHERE slug = ?').bind(slug).first<{ body: string }>();
    if (!row) return null;
    return JSON.parse(row.body) as TiDashboardReport;
  }
  const row = await db
    .prepare('SELECT body FROM weekly_reports ORDER BY week_start DESC LIMIT 1')
    .first<{ body: string }>();
  if (!row) return null;
  return JSON.parse(row.body) as TiDashboardReport;
}
