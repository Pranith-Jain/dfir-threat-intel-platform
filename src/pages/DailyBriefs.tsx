import { useMemo, useState } from 'react';
import { useDataFetch } from '../hooks/useDataFetch';
import { DataPageLayout } from '../components/DataPageLayout';
import { AiSummaryCard } from '../components/intel/AiSummaryCard';
import { Shield, AlertTriangle, Cloud, Anchor, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';

type Tab = 'cyber' | 'deepfake' | 'disaster' | 'maritime';

interface DbIndexSummary {
  counts: { cyber: number; deepfake: number; disaster: number; maritime: number };
  source: string;
  license: string;
  generatedAt: string;
}

interface BriefEntry {
  type: string;
  date: string;
  sizeBytes: number;
}

interface CyberBrief {
  type: string;
  date: string;
  threatLevel: string;
  executiveSummary: string;
  keyFindings: { title: string; summary: string }[];
  dashboard: {
    kpis: { value: string; label: string }[];
    activelyExploited: string[];
    vendors: string[];
    sectors: string[];
  };
  topThreats: { title: string; action: string }[];
  threatActors: { category: string; items: string[] }[];
  cveWatch: { category: string; items: string[] }[];
  events: {
    title: string;
    severity: string;
    text: string;
    chips: string[];
    sources: { url: string; label: string }[];
  }[];
  ttps: { descriptions: string[]; mitreIds: string[] };
  relatedCves: string[];
  outlook72h: string;
}

interface DeepfakeBrief {
  type: string;
  date: string;
  riskOutlook: string;
  executiveSummary: string;
  keyFindings: { title: string; summary: string }[];
  incidents: {
    title: string;
    badges: string[];
    fields: Record<string, string>;
    summary: string;
    sources: { url: string; label: string }[];
  }[];
  emergingTrends: string[];
  geographicObservations: string[];
  detectionDevelopments: string[];
}

interface DisasterBrief {
  type: string;
  date: string;
  overallThreat: string;
  executiveSummary: string;
  dashboard: { kpis: { value: string; label: string }[] };
  topEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[];
  escalateEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[];
  monitorEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[];
  outlook72h: string;
  regionalTrends: string[];
}

const SEV_STYLES: Record<string, string> = {
  red: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  escalate: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  orange:
    'text-orange-700 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800',
  monitor:
    'text-orange-700 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800',
  green:
    'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  high: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  critical: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
};

function sevPill(s: string): string {
  return SEV_STYLES[s?.toLowerCase() ?? ''] ?? 'text-muted bg-slate-50 dark:bg-input-200/40 border-line-1';
}

const TAB_CONFIG: { id: Tab; label: string; icon: typeof Shield; color: string }[] = [
  { id: 'cyber', label: 'OT/ICS Cyber', icon: Shield, color: 'text-rose-600 dark:text-rose-400' },
  { id: 'deepfake', label: 'Deepfake & GenAI', icon: AlertTriangle, color: 'text-violet-600 dark:text-violet-400' },
  { id: 'disaster', label: 'Global Disaster', icon: Cloud, color: 'text-amber-600 dark:text-amber-400' },
  { id: 'maritime', label: 'Maritime Cyber', icon: Anchor, color: 'text-cyan-600 dark:text-cyan-400' },
];

function Expandable({
  title,
  count,
  children,
  defaultOpen = false,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="surface-card rounded-xl overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between px-4 py-3 text-left">
        <span className="text-sm font-semibold text-heading">
          {title}
          {count !== undefined && <span className="ml-2 text-xs font-normal text-muted">({count})</span>}
        </span>
        {open ? <ChevronUp size={16} className="text-muted" /> : <ChevronDown size={16} className="text-muted" />}
      </button>
      {open && <div className="border-t border-line-1 px-4 py-3">{children}</div>}
    </div>
  );
}

/**
 * Extract feed-style items from any brief type for the AI summary card.
 * Each brief shape has different fields — this normalizes them into
 * { title, body, source } items the AiSummaryCard can summarize.
 */
function briefToSummaryItems(
  brief: CyberBrief | DeepfakeBrief | DisasterBrief
): Array<{ title: string; body: string; source?: string }> {
  const items: Array<{ title: string; body: string; source?: string }> = [];
  if (brief.type === 'cyber' || brief.type === 'maritime') {
    const b = brief as CyberBrief;
    items.push({ title: `${b.threatLevel ?? 'Threat'} — Executive Summary`, body: b.executiveSummary ?? '' });
    // Maritime keyFindings are strings; cyber keyFindings are {title, summary}.
    // Handle both shapes so a string finding doesn't produce an undefined title
    // (which fails the /api/v1/ai-summary schema's title min(1) validation → 400).
    for (const f of (b.keyFindings ?? []) as Array<{ title?: string; summary?: string } | string>) {
      if (typeof f === 'string') {
        items.push({ title: 'Key Finding', body: f });
      } else {
        items.push({ title: f.title ?? 'Key Finding', body: f.summary ?? '' });
      }
    }
    for (const e of b.events ?? []) items.push({ title: e.title, body: e.text ?? '', source: e.sources?.[0]?.label });
    if (b.outlook72h) items.push({ title: '72h Outlook', body: b.outlook72h });
  } else if (brief.type === 'deepfake') {
    const b = brief as DeepfakeBrief;
    items.push({ title: 'Deepfake Risk Outlook', body: b.riskOutlook ?? b.executiveSummary ?? '' });
    for (const f of b.keyFindings ?? []) items.push({ title: f.title, body: f.summary ?? '' });
    for (const inc of b.incidents ?? [])
      items.push({ title: inc.title, body: inc.summary ?? '', source: inc.sources?.[0]?.label });
    for (const t of b.emergingTrends ?? []) items.push({ title: 'Emerging Trend', body: t });
  } else if (brief.type === 'disaster') {
    const b = brief as DisasterBrief;
    items.push({ title: `${b.overallThreat ?? 'Disaster'} — Executive Summary`, body: b.executiveSummary ?? '' });
    for (const e of [...(b.escalateEvents ?? []), ...(b.topEvents ?? []), ...(b.monitorEvents ?? [])]) {
      items.push({ title: e.title, body: e.text ?? '', source: e.sources?.[0]?.label });
    }
    if (b.outlook72h) items.push({ title: '72h Outlook', body: b.outlook72h });
  }
  return items;
}

export default function DailyBriefs() {
  const [tab, setTab] = useState<Tab>('cyber');
  const [selectedDate, setSelectedDate] = useState<string | null>(null);

  const {
    data: indexData,
    loading: indexLoading,
    error: indexError,
    refetch: refetchIndex,
  } = useDataFetch<DbIndexSummary & { briefs: BriefEntry[] }>({
    url: '/api/v1/daily-briefs/',
  });

  const cyberBriefs = useMemo(() => indexData?.briefs?.filter((b) => b.type === 'cyber') ?? [], [indexData]);
  const deepfakeBriefs = useMemo(() => indexData?.briefs?.filter((b) => b.type === 'deepfake') ?? [], [indexData]);
  const disasterBriefs = useMemo(() => indexData?.briefs?.filter((b) => b.type === 'disaster') ?? [], [indexData]);
  const maritimeBriefs = useMemo(() => indexData?.briefs?.filter((b) => b.type === 'maritime') ?? [], [indexData]);

  const currentList =
    tab === 'cyber'
      ? cyberBriefs
      : tab === 'deepfake'
        ? deepfakeBriefs
        : tab === 'disaster'
          ? disasterBriefs
          : maritimeBriefs;

  const currentDate = useMemo(() => {
    if (selectedDate) return selectedDate;
    return currentList[0]?.date ?? null;
  }, [selectedDate, currentList]);

  const {
    data: brief,
    loading: briefLoading,
    error: briefError,
    refetch: refetchBrief,
  } = useDataFetch<CyberBrief | DeepfakeBrief | DisasterBrief>({
    url: currentDate ? `/api/v1/daily-briefs/${tab}/${currentDate}` : '',
  });

  const availableDates = useMemo(() => currentList.map((b) => b.date), [currentList]);

  const isLoading = indexLoading || briefLoading;
  // Surface fetch failures as errors (with retry), not as the "no data yet"
  // empty state — an ops message like "run the sync pipeline" is misleading
  // when the request itself failed.
  const loadError = indexError ?? briefError;
  const retry = indexError && !briefError ? refetchIndex : refetchBrief;

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<Shield size={20} />}
      title="Daily Intelligence Briefs"
      description="AI-generated daily intelligence assessments covering OT/ICS cyber threats, deepfake/GenAI risks, and global disaster monitoring."
      error={loadError}
      onRetry={retry}
    >
      {/* Header */}
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-heading">Daily Intelligence Briefs</h1>
          <p className="mt-1 text-sm text-muted">
            Source: {indexData?.source ?? 'agentic-ai-daily-reports.netlify.app'} &middot; Generated{' '}
            {indexData?.generatedAt ?? '-'}
          </p>
        </div>
        <div className="flex gap-2">
          {Object.entries(indexData?.counts ?? {}).map(([type, count]) => (
            <span key={type} className="rounded-full bg-surface-300 px-3 py-1 text-xs font-medium text-muted">
              {type}: {count}
            </span>
          ))}
        </div>
      </div>

      {/* Tabs */}
      {/* The tab row is wider than a phone. Without an explicit scroll
          container it stretches the page instead of scrolling, which pushed
          /daily-briefs 110px past the viewport on a 375px screen. The row
          now scrolls sideways inside its own box; the page does not move. */}
      <div className="mb-6 flex flex-nowrap gap-1 overflow-x-auto rounded-xl bg-surface-300 p-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {TAB_CONFIG.map(({ id, label, icon: Icon, color }) => (
          <button
            key={id}
            onClick={() => {
              setTab(id);
              setSelectedDate(null);
            }}
            className={`flex flex-1 items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-medium transition-colors ${
              tab === id
                ? 'bg-white text-slate-900 shadow-sm dark:bg-surface-300 dark:text-white'
                : 'text-slate-500 hover:text-slate-700 dark:text-muted dark:hover:text-slate-200'
            }`}
          >
            <Icon size={16} className={tab === id ? color : ''} />
            {label}
          </button>
        ))}
      </div>

      {/* Date selector */}
      {availableDates.length > 0 && (
        <div className="mb-4 flex gap-2 overflow-x-auto pb-2">
          {availableDates.map((d: string) => (
            <button
              key={d}
              onClick={() => setSelectedDate(d)}
              className={`whitespace-nowrap rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                currentDate === d
                  ? 'bg-brand-600 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-surface-200 dark:text-slate-300 dark:hover:bg-surface-300'
              }`}
            >
              {d}
            </button>
          ))}
        </div>
      )}

      {/* Content */}
      {briefLoading || isLoading ? (
        <div className="flex items-center justify-center py-20 text-muted">Loading brief...</div>
      ) : !brief ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted">
          <AlertTriangle size={40} className="mb-3 opacity-40" />
          <p>
            No brief available for {tab} on {currentDate ?? '-'}
          </p>
          <p className="mt-1 text-xs">Run the sync pipeline to populate data.</p>
        </div>
      ) : tab === 'cyber' || tab === 'maritime' ? (
        <CyberBriefView brief={brief as CyberBrief} />
      ) : tab === 'deepfake' ? (
        <DeepfakeBriefView brief={brief as DeepfakeBrief} />
      ) : (
        <DisasterBriefView brief={brief as DisasterBrief} />
      )}
    </DataPageLayout>
  );
}

// ─── Cyber Brief ──────────────────────────────────────────────────────

function CyberBriefView({ brief }: { brief: CyberBrief }) {
  return (
    <div className="space-y-6">
      {/* Threat Level */}
      {brief.threatLevel && (
        <div className={`rounded-xl border p-4 ${sevPill('red')}`}>
          <span className="text-sm font-semibold">{brief.threatLevel}</span>
        </div>
      )}

      {/* Executive Summary */}
      <section className="surface-card rounded-xl p-5">
        <h2 className="mb-2 text-lg font-bold text-heading">Executive Summary</h2>
        <p className="text-sm leading-relaxed text-body">{brief.executiveSummary}</p>
      </section>

      {/* AI Analysis */}
      <AiSummaryCard
        surface={`Daily Brief — ${brief.type.toUpperCase()} (${brief.date})`}
        dayKey={brief.date}
        items={briefToSummaryItems(brief)}
        requireAdmin={false}
      />

      {/* KPIs */}
      {brief.dashboard?.kpis?.length > 0 && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {brief.dashboard.kpis.map((kpi, i) => (
            <div key={i} className="surface-card rounded-xl p-4 text-center">
              <div className="text-3xl font-extrabold text-heading">{kpi.value}</div>
              <div className="mt-1 text-xs text-muted">{kpi.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Key Findings */}
      {brief.keyFindings?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Key Findings</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {brief.keyFindings.map((f, i) => (
              <div key={i} className="rounded-xl border border-line-1 p-3">
                <h3 className="text-sm font-semibold text-heading">{f.title}</h3>
                <p className="mt-1 text-xs text-muted">{f.summary}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Top Priority Threats */}
      {brief.topThreats?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Top Priority Threats</h2>
          <div className="space-y-3">
            {brief.topThreats.map((t, i) => (
              <div key={i} className="rounded-xl border border-line-1 p-3">
                <div className="flex items-center gap-2">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-rose-100 text-mini font-bold text-rose-700 dark:bg-rose-950/60 dark:text-rose-300">
                    {i + 1}
                  </span>
                  <h3 className="text-sm font-semibold text-heading">{t.title}</h3>
                </div>
                {t.action && <p className="mt-1.5 ml-8 text-xs text-muted">{t.action}</p>}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Actively Exploited */}
      {brief.dashboard?.activelyExploited?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Actively Exploited</h2>
          <div className="flex flex-wrap gap-2">
            {brief.dashboard.activelyExploited.map((item, i) => (
              <span
                key={i}
                className="rounded-full bg-rose-50 px-3 py-1 text-xs font-medium text-rose-700 border border-rose-200 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-800"
              >
                {item}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* Vendors + Sectors grid */}
      {(brief.dashboard?.vendors?.length > 0 || brief.dashboard?.sectors?.length > 0) && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {brief.dashboard.vendors?.length > 0 && (
            <section className="surface-card rounded-xl p-5">
              <h2 className="mb-3 text-sm font-bold uppercase tracking-wider text-muted">Affected Vendors</h2>
              <div className="flex flex-wrap gap-1.5">
                {brief.dashboard.vendors.map((v, i) => (
                  <span key={i} className="rounded-md bg-surface-300 px-2 py-1 text-xs text-body">
                    {v}
                  </span>
                ))}
              </div>
            </section>
          )}
          {brief.dashboard.sectors?.length > 0 && (
            <section className="surface-card rounded-xl p-5">
              <h2 className="mb-3 text-sm font-bold uppercase tracking-wider text-muted">Sectors at Risk</h2>
              <div className="flex flex-wrap gap-1.5">
                {brief.dashboard.sectors.map((s, i) => (
                  <span
                    key={i}
                    className="rounded-md bg-amber-50 px-2 py-1 text-xs font-medium text-amber-700 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* Threat Actor Activity */}
      {brief.threatActors?.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-bold text-heading">Threat Actor Activity</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {brief.threatActors.map((cat, i) => (
              <div key={i} className="surface-card rounded-xl p-4">
                <h3 className="mb-2 text-sm font-bold text-heading">{cat.category}</h3>
                <ul className="space-y-1.5">
                  {cat.items.map((item, j) => (
                    <li key={j} className="text-xs text-muted">
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* CVE Watch */}
      {brief.cveWatch?.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-bold text-heading">Vulnerability &amp; CVE Watch</h2>
          <div className="space-y-3">
            {brief.cveWatch.map((cat, i) => (
              <Expandable key={i} title={cat.category} count={cat.items.length} defaultOpen={i === 0}>
                <ul className="space-y-1.5">
                  {cat.items.map((item, j) => (
                    <li key={j} className="flex items-start gap-2 text-xs text-muted">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-400 dark:bg-slate-500" />
                      {item}
                    </li>
                  ))}
                </ul>
              </Expandable>
            ))}
          </div>
        </section>
      )}

      {/* MITRE ATT&CK */}
      {brief.ttps?.mitreIds?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">MITRE ATT&amp;CK Observations</h2>
          <div className="flex flex-wrap gap-1.5">
            {brief.ttps.mitreIds.map((id, i) => (
              <a
                key={i}
                // Sub-techniques (T1059.003) link to their own page, not the parent.
                href={`https://attack.mitre.org/techniques/${id.split('.')[0]}/${id.includes('.') ? id.split('.')[1] : ''}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 rounded-md bg-surface-300 px-2 py-1 text-xs font-mono text-body hover:bg-track dark:hover:bg-surface-300 transition-colors"
              >
                {id} <ExternalLink size={10} />
              </a>
            ))}
          </div>
          {brief.ttps.descriptions?.length > 0 && (
            <ul className="mt-3 space-y-1">
              {brief.ttps.descriptions.map((d, i) => (
                <li key={i} className="text-xs text-muted">
                  {d}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {/* Related CVEs */}
      {brief.relatedCves?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Related CVEs ({brief.relatedCves.length})</h2>
          <div className="flex flex-wrap gap-1.5">
            {brief.relatedCves.map((cve, i) => (
              <a
                key={i}
                href={`/dfir/cve?cve=${cve}`}
                className="inline-flex items-center gap-1 rounded-md bg-blue-50 px-2 py-1 text-xs font-mono text-brand-700 hover:bg-blue-100 dark:bg-blue-950/40 dark:text-brand-300 dark:hover:bg-blue-950/60 transition-colors"
              >
                {cve} <ExternalLink size={10} />
              </a>
            ))}
          </div>
        </section>
      )}

      {/* Event Cards */}
      {brief.events?.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-bold text-heading">Event Cards ({brief.events.length})</h2>
          <div className="space-y-3">
            {brief.events.map((ev, i) => (
              <Expandable key={i} title={ev.title} defaultOpen={ev.severity === 'red' && i < 3}>
                <div className="flex items-center gap-2 mb-2">
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-micro font-bold uppercase tracking-wider border ${sevPill(ev.severity)}`}
                  >
                    {ev.severity}
                  </span>
                </div>
                <p className="text-xs leading-relaxed text-muted">{ev.text}</p>
                {ev.chips?.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {ev.chips.map((c, j) => (
                      <span key={j} className="rounded-full bg-surface-300 px-2 py-0.5 text-micro text-muted">
                        {c}
                      </span>
                    ))}
                  </div>
                )}
                {ev.sources?.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {ev.sources.map((s, j) => (
                      <a
                        key={j}
                        href={s.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-micro text-brand-600 hover:underline dark:text-brand-400 transition-colors"
                      >
                        {s.label || s.url.slice(0, 50)} <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                )}
              </Expandable>
            ))}
          </div>
        </section>
      )}

      {/* Outlook */}
      {brief.outlook72h && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-2 text-lg font-bold text-heading">Next 72-Hour Outlook</h2>
          <p className="text-sm leading-relaxed text-body">{brief.outlook72h}</p>
        </section>
      )}
    </div>
  );
}

// ─── Deepfake Brief ──────────────────────────────────────────────────

function DeepfakeBriefView({ brief }: { brief: DeepfakeBrief }) {
  return (
    <div className="space-y-6">
      {/* Risk Outlook */}
      {brief.riskOutlook && (
        <div
          className={`rounded-xl border p-4 ${brief.riskOutlook.toLowerCase() === 'worsening' ? sevPill('red') : sevPill('orange')}`}
        >
          <span className="text-sm font-semibold">Overall Outlook: {brief.riskOutlook}</span>
        </div>
      )}

      {/* Executive Summary */}
      <section className="surface-card rounded-xl p-5">
        <h2 className="mb-2 text-lg font-bold text-heading">Executive Summary</h2>
        <p className="text-sm leading-relaxed text-body">{brief.executiveSummary}</p>
      </section>

      {/* AI Analysis */}
      <AiSummaryCard
        surface={`Daily Brief — ${brief.type.toUpperCase()} (${brief.date})`}
        dayKey={brief.date}
        items={briefToSummaryItems(brief)}
        requireAdmin={false}
      />

      {/* Key Findings */}
      {brief.keyFindings?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Key Findings</h2>
          <ul className="space-y-2">
            {brief.keyFindings.map((f, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-body">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-violet-500" />
                <span>
                  <span className="font-semibold">{f.title}:</span> {f.summary}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Incidents */}
      {brief.incidents?.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-bold text-heading">Priority Incidents ({brief.incidents.length})</h2>
          <div className="space-y-3">
            {brief.incidents.slice(0, 15).map((inc, i) => (
              <Expandable
                key={i}
                title={inc.title}
                defaultOpen={inc.badges.some((b) => b.toLowerCase() === 'escalate') && i < 3}
              >
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {inc.badges.map((b, j) => (
                    <span
                      key={j}
                      className={`whitespace-nowrap rounded-full px-2 py-0.5 text-micro font-bold uppercase border ${sevPill(b.toLowerCase())}`}
                    >
                      {b}
                    </span>
                  ))}
                </div>
                {inc.fields && Object.keys(inc.fields).length > 0 && (
                  <div className="mb-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-3">
                    {Object.entries(inc.fields).map(([k, v]) => (
                      <div key={k}>
                        <span className="text-muted">{k}:</span> <span className="text-body">{v}</span>
                      </div>
                    ))}
                  </div>
                )}
                {inc.summary && <p className="text-xs leading-relaxed text-muted">{inc.summary}</p>}
                {inc.sources?.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {inc.sources.map((s, j) => (
                      <a
                        key={j}
                        href={s.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-micro text-brand-600 hover:underline dark:text-brand-400 transition-colors"
                      >
                        {s.label || s.url.slice(0, 50)} <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                )}
              </Expandable>
            ))}
          </div>
        </section>
      )}

      {/* Emerging Trends */}
      {brief.emergingTrends?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Emerging Trends</h2>
          <ul className="space-y-2">
            {brief.emergingTrends.map((t, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-body">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-violet-500" />
                {t}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Geographic Observations */}
      {brief.geographicObservations?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Geographic Observations</h2>
          <ul className="space-y-2">
            {brief.geographicObservations.map((obs, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-body">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500" />
                {obs}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Detection Developments */}
      {brief.detectionDevelopments?.length > 0 && (
        <Expandable title="Detection &amp; Defensive Developments" count={brief.detectionDevelopments.length}>
          <ul className="space-y-1.5">
            {brief.detectionDevelopments.map((d, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-muted">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" />
                {d}
              </li>
            ))}
          </ul>
        </Expandable>
      )}
    </div>
  );
}

// ─── Disaster Brief ──────────────────────────────────────────────────

function DisasterBriefView({ brief }: { brief: DisasterBrief }) {
  return (
    <div className="space-y-6">
      {/* Threat Level */}
      {brief.overallThreat && (
        <div
          className={`rounded-xl border p-4 ${sevPill(brief.overallThreat.toLowerCase() === 'high' ? 'red' : 'orange')}`}
        >
          <span className="text-sm font-semibold">Overall Threat: {brief.overallThreat}</span>
        </div>
      )}

      {/* Executive Summary */}
      <section className="surface-card rounded-xl p-5">
        <h2 className="mb-2 text-lg font-bold text-heading">Executive Summary</h2>
        <p className="text-sm leading-relaxed text-body">{brief.executiveSummary}</p>
      </section>

      {/* AI Analysis */}
      <AiSummaryCard
        surface={`Daily Brief — ${brief.type.toUpperCase()} (${brief.date})`}
        dayKey={brief.date}
        items={briefToSummaryItems(brief)}
        requireAdmin={false}
      />

      {/* KPIs */}
      {brief.dashboard?.kpis?.length > 0 && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {brief.dashboard.kpis.map((kpi, i) => (
            <div key={i} className="surface-card rounded-xl p-4 text-center">
              <div className="text-3xl font-extrabold text-heading">{kpi.value}</div>
              <div className="mt-1 text-xs text-muted">{kpi.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Top Events */}
      {brief.topEvents?.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-bold text-heading">Top Critical Events</h2>
          <div className="space-y-3">
            {brief.topEvents.map((ev, i) => (
              <div key={i} className="surface-card rounded-xl overflow-hidden">
                {' '}
                <div className="flex items-center justify-between border-b border-line-1 px-4 py-3">
                  <span className="text-sm font-semibold text-heading">{ev.title}</span>
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-micro font-bold uppercase tracking-wider border ${sevPill(ev.severity)}`}
                  >
                    {ev.severity}
                  </span>
                </div>
                <div className="px-4 py-3">
                  <p className="text-xs leading-relaxed text-muted">{ev.text}</p>
                  {ev.sources?.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {ev.sources.map((s, j) => (
                        <a
                          key={j}
                          href={s.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-micro text-brand-600 hover:underline dark:text-brand-400 transition-colors"
                        >
                          {s.label || s.url.slice(0, 50)} <ExternalLink size={10} />
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Escalate Events */}
      {brief.escalateEvents?.length > 0 && (
        <Expandable title={`Escalate Events`} count={brief.escalateEvents.length} defaultOpen={true}>
          <div className="space-y-2">
            {brief.escalateEvents.map((ev, i) => (
              <div
                key={i}
                className="rounded-xl border border-rose-200 bg-rose-50/50 px-4 py-3 dark:border-rose-900 dark:bg-rose-950/20"
              >
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-rose-500" />
                  <span className="text-sm font-medium text-heading">{ev.title}</span>
                </div>
                {ev.text && <p className="mt-1 ml-4 text-xs text-muted">{ev.text}</p>}
                {ev.sources?.length > 0 && (
                  <div className="mt-1.5 ml-4 flex flex-wrap gap-2">
                    {ev.sources.map((s, j) => (
                      <a
                        key={j}
                        href={s.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-micro text-brand-600 hover:underline dark:text-brand-400 transition-colors"
                      >
                        {s.label || s.url.slice(0, 50)} <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Expandable>
      )}

      {/* Monitor Events */}
      {brief.monitorEvents?.length > 0 && (
        <Expandable title={`Monitor Events`} count={brief.monitorEvents.length}>
          <div className="space-y-2">
            {brief.monitorEvents.map((ev, i) => (
              <div
                key={i}
                className="rounded-xl border border-orange-200 bg-orange-50/50 px-4 py-3 dark:border-orange-900 dark:bg-orange-950/20"
              >
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-orange-500" />
                  <span className="text-sm font-medium text-heading">{ev.title}</span>
                </div>
                {ev.text && <p className="mt-1 ml-4 text-xs text-muted">{ev.text}</p>}
                {ev.sources?.length > 0 && (
                  <div className="mt-1.5 ml-4 flex flex-wrap gap-2">
                    {ev.sources.map((s, j) => (
                      <a
                        key={j}
                        href={s.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-micro text-brand-600 hover:underline dark:text-brand-400 transition-colors"
                      >
                        {s.label || s.url.slice(0, 50)} <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Expandable>
      )}

      {/* Regional Trends */}
      {brief.regionalTrends?.length > 0 && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-3 text-lg font-bold text-heading">Regional &amp; Hazard Trends</h2>
          <ul className="space-y-2">
            {brief.regionalTrends.map((t, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-body">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500" />
                {t}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Outlook */}
      {brief.outlook72h && (
        <section className="surface-card rounded-xl p-5">
          <h2 className="mb-2 text-lg font-bold text-heading">Next 72-Hour Outlook</h2>
          <p className="text-sm leading-relaxed text-body">{brief.outlook72h}</p>
        </section>
      )}
    </div>
  );
}
