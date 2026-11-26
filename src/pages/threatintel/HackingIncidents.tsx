import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { CalendarDays, ExternalLink, Filter, Loader2, Search, ShieldAlert, ShieldCheck, Target } from 'lucide-react';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

/**
 * Hacking Incidents ledger — sourced cyberattacks where AI use is stated or
 * credibly suspected (hackingincidents.ai, 286 reports, Jan 2023 → Nov 2026).
 * Reads the replicated manifest through the platform API:
 *   GET /api/v1/hi/               slim index (counts, stats, rows)
 *   GET /api/v1/hi/incidents/:id  full record (summary, sources, upstream link)
 *   GET /api/v1/hi/stats          computed stats
 * Upstream publishes no reuse licence — metadata and deep links only.
 */

interface IncidentSlim {
  id: string;
  title: string;
  date: string;
  year: string;
  month: string;
  actor: string | null;
  actorType: string | null;
  targets: string | null;
  aiRole: string[];
  models: string[];
  autonomy: string | null;
  confidence: string;
  sourceCount: number;
  primarySourceCount: number;
  modelNamed: boolean;
  harnessUsed: boolean;
  harnessNames: string[];
  sectors: string[];
}

interface IncidentBody extends IncidentSlim {
  outcome: string | null;
  confidenceReason: string | null;
  summary: string;
  quote: string | null;
  sources: Array<{
    title: string | null;
    publisher: string | null;
    url: string;
    primary: boolean;
    quoteFound: boolean;
  }>;
  upstreamUrl: string;
}

interface HiIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  upstreamUpdated: string | null;
  counts: {
    records: number;
    months: number;
    confirmed: number;
    strong: number;
    suspected: number;
    namedModels: number;
    harnessUse: number;
    sourceLinks: number;
  };
  stats: HiStats;
  months: string[];
  incidents: IncidentSlim[];
  webPages: Record<string, string>;
}

interface HiStats {
  byYear: Record<string, number>;
  byConfidence: Record<string, number>;
  byAutonomy: Record<string, number>;
  byRole: Record<string, number>;
  bySector: Record<string, number>;
  byCountry: Record<string, number>;
  sources: { links: number; primary: number; uniqueUrls: number };
  namedModels: number;
  harnessUse: number;
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500';

const CONFIDENCE_STYLES: Record<string, string> = {
  confirmed:
    'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  strong: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  suspected:
    'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
};

const AUTONOMY_LABELS: Record<string, string> = {
  assist: 'Assisted a human',
  'semi-autonomous': 'Semi-autonomous',
  autonomous: 'Ran on its own',
};

type Tab = 'ledger' | 'stats' | 'about';

function badge(text: string, cls?: string): JSX.Element {
  return (
    <span
      className={`text-[11px] font-bold px-2 py-0.5 rounded border ${cls ?? 'text-muted bg-surface-100 border-line-1'}`}
    >
      {text}
    </span>
  );
}

function StatGrid({ title, data }: { title: string; data: Record<string, number> }): JSX.Element {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, n]) => n));
  return (
    <div className="surface-card p-4">
      <h3 className="text-sm font-semibold text-heading mb-3">{title}</h3>
      <div className="space-y-1.5">
        {rows.map(([name, n]) => (
          <div key={name} className="flex items-center gap-2 text-xs">
            <span className="w-36 truncate text-muted" title={name}>
              {name}
            </span>
            <div className="flex-1 h-2 rounded-full bg-surface-100 overflow-hidden">
              <div className="h-full bg-brand-500/70" style={{ width: `${(n / max) * 100}%` }} />
            </div>
            <span className="w-8 text-right font-mono text-heading">{n}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function HackingIncidents(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<HiIndex>({ url: '/api/v1/hi/', ttl: 300_000 });
  const { data: statsData } = useDataFetch<{ stats: HiStats }>({ url: '/api/v1/hi/stats', ttl: 300_000 });
  const [tab, setTab] = useState<Tab>('ledger');
  const [confidence, setConfidence] = useState('');
  const [autonomy, setAutonomy] = useState('');
  const [role, setRole] = useState('');
  const [year, setYear] = useState('');
  const [q, setQ] = useState('');
  const [body, setBody] = useState<IncidentBody | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.incidents ?? []).filter((r) => {
      if (confidence && r.confidence !== confidence) return false;
      if (autonomy && r.autonomy !== autonomy) return false;
      if (role && !r.aiRole.includes(role)) return false;
      if (year && r.year !== year) return false;
      if (
        needle &&
        !`${r.title} ${r.actor ?? ''} ${r.targets ?? ''} ${r.aiRole.join(' ')}`.toLowerCase().includes(needle)
      )
        return false;
      return true;
    });
  }, [data, confidence, autonomy, role, year, q]);

  const byMonth = useMemo(() => {
    const map = new Map<string, IncidentSlim[]>();
    for (const r of rows) {
      if (!map.has(r.month)) map.set(r.month, []);
      map.get(r.month)!.push(r);
    }
    return [...map.entries()].sort((a, b) => (a[0] < b[0] ? 1 : -1));
  }, [rows]);

  const briefingItems = useMemo(
    () =>
      (data?.incidents ?? []).slice(0, 50).map((r) => ({
        title: r.title,
        body: `${r.date} · ${r.confidence} evidence${r.actor ? ` · ${r.actor}` : ''}${
          r.targets ? ` targeting ${r.targets}` : ''
        } · ${r.aiRole.slice(0, 3).join(', ') || 'AI role unrecorded'}${r.sourceCount ? ` · ${r.sourceCount} sources` : ''}`,
        source: r.id,
      })),
    [data]
  );

  const stats = statsData?.stats ?? data?.stats;
  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'ledger', label: `Ledger (${data?.counts.records ?? '…'})` },
    { id: 'stats', label: 'Stats' },
    { id: 'about', label: 'About' },
  ];

  async function open(id: string) {
    setBodyLoading(true);
    setBody(null);
    try {
      setBody(await api.get<IncidentBody>(`/api/v1/hi/incidents/${encodeURIComponent(id)}`));
    } catch {
      setBody(null);
    } finally {
      setBodyLoading(false);
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldAlert size={28} />}
      title="AI Hacking Incidents"
      description={
        <>
          A sourced ledger of cyberattacks where AI use is stated or credibly suspected, from{' '}
          <a
            href={data?.sourceUrl ?? 'https://hackingincidents.ai/'}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            hackingincidents.ai
          </a>
          . {data?.counts.records ?? '…'} published reports graded <b>confirmed</b> / <b>strong</b> / <b>suspected</b>,
          each with its primary sources. Counts describe what got reported, not everything that happened.
        </>
      }
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-500/15 text-brand-600 dark:text-brand-300 border-brand-400/40'
                : 'text-muted hover:text-heading border-line-1'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <DetectionAiBriefing
        surface="AI Hacking Incidents"
        source="hacking-incidents"
        items={briefingItems}
        dayKey={data?.builtAt?.slice(0, 10)}
        label="incidents"
      />

      {tab === 'ledger' && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-5">
            {[
              ['Reports', data?.counts.records],
              ['Confirmed', data?.counts.confirmed],
              ['Strong', data?.counts.strong],
              ['Suspected', data?.counts.suspected],
              ['Named models', data?.counts.namedModels],
              ['Source links', data?.counts.sourceLinks],
            ].map(([label, value]) => (
              <div key={String(label)} className="surface-card p-3">
                <div className="text-2xl font-bold text-heading">{value ?? '…'}</div>
                <div className="text-xs text-muted">{label}</div>
              </div>
            ))}
          </div>

          <div className="surface-card p-3 mb-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
            <div className="flex items-center gap-2 text-xs text-muted col-span-1 lg:col-span-1">
              <Filter size={14} /> Filters
            </div>
            <select
              className={inputCls}
              value={confidence}
              onChange={(e) => setConfidence(e.target.value)}
              aria-label="Evidence grade"
            >
              <option value="">All grades</option>
              <option value="confirmed">Confirmed</option>
              <option value="strong">Strong</option>
              <option value="suspected">Suspected</option>
            </select>
            <select
              className={inputCls}
              value={autonomy}
              onChange={(e) => setAutonomy(e.target.value)}
              aria-label="Autonomy"
            >
              <option value="">All autonomy</option>
              {Object.entries(AUTONOMY_LABELS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
            <select className={inputCls} value={role} onChange={(e) => setRole(e.target.value)} aria-label="AI role">
              <option value="">All roles</option>
              {(data?.stats ? Object.keys(data.stats.byRole) : []).map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <select className={inputCls} value={year} onChange={(e) => setYear(e.target.value)} aria-label="Year">
              <option value="">All years</option>
              {(data?.months ?? [])
                .map((m) => m.slice(0, 4))
                .filter((v, i, a) => a.indexOf(v) === i)
                .map((y) => (
                  <option key={y} value={y}>
                    {y}
                  </option>
                ))}
            </select>
            <div className="relative lg:col-span-4">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                className={`${inputCls} pl-9`}
                placeholder="Search actors, targets, roles…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
          </div>

          <p className="text-xs text-muted mb-3">
            Showing {rows.length} of {data?.counts.records ?? '…'} reports · newest first
          </p>
          <div className="space-y-5">
            {byMonth.map(([month, items]) => (
              <div key={month}>
                <div className="flex items-center gap-2 text-xs font-semibold text-muted mb-2">
                  <CalendarDays size={13} /> {month} <span className="font-normal">({items.length})</span>
                </div>
                <div className="space-y-2">
                  {items.map((r) => (
                    <button
                      key={r.id}
                      onClick={() => void open(r.id)}
                      className="surface-card w-full text-left p-3 hover:border-brand-400 transition-colors"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        {badge(r.confidence, CONFIDENCE_STYLES[r.confidence])}
                        <span className="text-xs text-muted">{AUTONOMY_LABELS[r.autonomy ?? ''] ?? r.autonomy}</span>
                        {r.harnessUsed &&
                          badge(
                            'harness',
                            'text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 border-violet-300 dark:border-violet-800'
                          )}
                        <span className="text-xs text-muted ml-auto flex items-center gap-1">
                          <ShieldCheck size={11} /> {r.sourceCount} sources
                        </span>
                      </div>
                      <p className="text-sm font-medium text-heading mt-1.5">{r.title}</p>
                      <div className="flex flex-wrap gap-1.5 mt-1.5 text-[11px] text-muted">
                        {r.actor && (
                          <span className="inline-flex items-center gap-1">
                            <Target size={11} /> {r.actor}
                          </span>
                        )}
                        {r.targets && <span>· {r.targets}</span>}
                        {r.aiRole.slice(0, 3).map((roleName) => (
                          <span key={roleName}>· {roleName}</span>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {tab === 'stats' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <StatGrid title="Evidence grade" data={stats?.byConfidence ?? {}} />
          <StatGrid title="Autonomy" data={stats?.byAutonomy ?? {}} />
          <StatGrid title="Reported by year" data={stats?.byYear ?? {}} />
          <StatGrid title="AI role" data={stats?.byRole ?? {}} />
          <StatGrid title="Sector" data={stats?.bySector ?? {}} />
          <StatGrid title="Country" data={stats?.byCountry ?? {}} />
          <div className="surface-card p-4 md:col-span-2 text-sm text-muted space-y-1">
            <p>
              <b className="text-heading">{stats?.sources.links ?? '…'}</b> source links across{' '}
              <b className="text-heading">{stats?.sources.uniqueUrls ?? '…'}</b> unique URLs (
              <b className="text-heading">{stats?.sources.primary ?? '…'}</b> primary).
            </p>
            <p>
              <b className="text-heading">{stats?.namedModels ?? '…'}</b> name a model;{' '}
              <b className="text-heading">{stats?.harnessUse ?? '…'}</b> mention an offensive harness.
            </p>
            <p>Upstream data current to {data?.upstreamUpdated ?? '…'}.</p>
          </div>
        </div>
      )}

      {tab === 'about' && (
        <div className="surface-card p-5 prose prose-sm dark:prose-invert max-w-none text-sm text-muted space-y-3">
          <p>
            Every entry is one operation that a model provider, security firm, government or the press published, where
            AI use is stated or credibly suspected. Grade reflects evidence strength, not attack severity:
            <b> confirmed</b> means a primary party states AI was used with evidence; <b>strong</b> means a credible
            firm attributes it from artifacts; <b>suspected</b> means thin or second-hand evidence.
          </p>
          <p>
            These are counts of published reports — they show what got noticed and written up, which is not the same as
            what happened. This replication stores structured metadata and short factual summaries only; every record
            links to its upstream incident page and primary sources. The upstream site publishes no reuse licence.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            <a
              href={data?.webPages.ledger ?? 'https://hackingincidents.ai/'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Upstream ledger <ExternalLink size={13} />
            </a>
            <a
              href={data?.webPages.method ?? 'https://hackingincidents.ai/method/'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Grading method <ExternalLink size={13} />
            </a>
            <a
              href={data?.webPages.data ?? 'https://hackingincidents.ai/data/'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Upstream data <ExternalLink size={13} />
            </a>
          </div>
        </div>
      )}

      <Modal open={bodyLoading || body !== null} onClose={() => setBody(null)} title={body?.id ?? 'Loading…'} size="lg">
        {bodyLoading && (
          <div className="flex items-center gap-2 py-8 justify-center text-muted">
            <Loader2 size={18} className="animate-spin" /> Loading record…
          </div>
        )}
        {body && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              {badge(body.confidence, CONFIDENCE_STYLES[body.confidence])}
              <span className="text-xs text-muted">{body.date}</span>
              {body.primarySourceCount > 0 && (
                <span className="text-xs text-muted">{body.primarySourceCount} primary sources</span>
              )}
            </div>
            <h3 className="text-lg font-semibold text-heading leading-snug">{body.title}</h3>
            {body.summary && <p className="text-sm text-muted leading-relaxed">{body.summary}</p>}
            {body.outcome && (
              <div className="surface-card p-3">
                <div className="text-xs font-semibold text-heading mb-1">Outcome</div>
                <p className="text-sm text-muted">{body.outcome}</p>
              </div>
            )}
            {body.confidenceReason && (
              <div className="surface-card p-3">
                <div className="text-xs font-semibold text-heading mb-1">Why this grade</div>
                <p className="text-sm text-muted">{body.confidenceReason}</p>
              </div>
            )}
            <div className="flex flex-wrap gap-1.5">
              {body.aiRole.map((r) => (
                <span key={r} className="text-[11px] px-2 py-0.5 rounded bg-surface-100 text-muted">
                  {r}
                </span>
              ))}
              {body.models.map((m) => (
                <span key={m} className="text-[11px] px-2 py-0.5 rounded bg-surface-100 text-muted">
                  {m}
                </span>
              ))}
              {body.sectors.map((s) => (
                <span key={s} className="text-[11px] px-2 py-0.5 rounded bg-surface-100 text-muted">
                  {s}
                </span>
              ))}
            </div>
            <div>
              <div className="text-xs font-semibold text-heading mb-2">Sources</div>
              <ul className="space-y-1.5">
                {body.sources.map((s, i) => (
                  <li key={i} className="text-sm">
                    <a
                      href={s.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-brand-500 hover:underline inline-flex items-center gap-1"
                    >
                      {s.publisher ?? s.title ?? s.url} <ExternalLink size={11} />
                      {s.primary && (
                        <span className="text-[10px] text-emerald-600 dark:text-emerald-400">(primary)</span>
                      )}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
            <a
              href={body.upstreamUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              View upstream incident <ExternalLink size={13} />
            </a>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
