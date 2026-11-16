import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { renderMarkdown } from '../../components/dfir/report-view-helpers';
import {
  Bot,
  CalendarDays,
  ExternalLink,
  FileWarning,
  GitCommitHorizontal,
  Landmark,
  Loader2,
  Scale,
  Search,
  ShieldAlert,
} from 'lucide-react';

/**
 * ORCA AI Incident Archive — open database of real-world AI agent security
 * incidents (Continuum-AI-Corp, CC BY 4.0), auto-synced weekly from upstream.
 *
 * The three upstream triage fields drive the whole page:
 *   kind            — incident / vulnerability / research / report / policy
 *   real_harm       — was there a confirmed victim (vs. a research demo)
 *   ai_involvement  — confirmed / unverified / disputed / not-applicable
 *
 * Reads the replicated manifest through the platform API:
 *   GET  /api/v1/orca/               → slim index (counts, stats, rows)
 *   GET  /api/v1/orca/incidents/:id  → full record (summary, sources)
 *   GET  /api/v1/orca/stats          → upstream stats pass-through
 */

interface IncidentSlim {
  id: string;
  title: string;
  date: string;
  dateEnd: string | null;
  month: string;
  kind: string;
  types: string[];
  severity: string;
  confidence: string;
  realHarm: boolean | null;
  aiInvolvement: string;
  regions: string[];
  landmark: boolean;
  disputed: boolean;
  sourceCount: number;
}

interface IncidentBody extends IncidentSlim {
  datePrecision: string;
  dateRaw: string | null;
  summary: string;
  sources: Array<{ url: string; label: string }>;
  upstreamUrl: string;
}

interface OrcaIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  upstreamVersion: string;
  counts: {
    records: number;
    months: number;
    realHarm: number;
    critical: number;
    incidents: number;
    disputed: number;
    landmark: number;
    sources: number | null;
  };
  months: string[];
  incidents: IncidentSlim[];
  lastCommit: string | null;
  lastCommitSha: string | null;
  recentCommits: Array<{ sha: string; date: string | null; author: string | null; message: string }>;
  webPages: { repo: string; commits: string; offlineViewer: string; primarySources: string };
}

interface OrcaStats {
  count: number;
  months: Record<string, number>;
  by_severity: Record<string, number>;
  by_kind: Record<string, number>;
  by_type: Record<string, number>;
  by_region: Record<string, number>;
  real_harm: { true: number; false: number; null: number };
  ai_involvement: Record<string, number>;
  sources: { links: number; unique_urls: number };
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  high: 'text-orange-700 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800',
  medium: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  low: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  info: 'text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/40 border-slate-300 dark:border-slate-700',
};

const KIND_LABELS: Record<string, string> = {
  incident: 'Incident',
  vulnerability: 'Vulnerability',
  research: 'Research',
  report: 'Report',
  policy: 'Policy',
};

function harmBadge(realHarm: boolean | null): { label: string; cls: string } {
  if (realHarm === true)
    return {
      label: 'real harm',
      cls: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
    };
  if (realHarm === false)
    return {
      label: 'no confirmed harm',
      cls: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
    };
  return {
    label: 'n/a (policy/report)',
    cls: 'text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/40 border-slate-300 dark:border-slate-700',
  };
}

function fmtDate(d: string | null): string {
  if (!d) return '';
  const t = new Date(`${d}T00:00:00Z`);
  return Number.isNaN(t.getTime())
    ? d
    : t.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

type Tab = 'timeline' | 'critical' | 'stats' | 'activity';

export default function OrcaIncidents(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<OrcaIndex>({ url: '/api/v1/orca/', ttl: 300_000 });
  const { data: statsData } = useDataFetch<{ stats: OrcaStats }>({ url: '/api/v1/orca/stats', ttl: 300_000 });
  const { data: commitsData } = useDataFetch<{
    commits: Array<{ sha: string; date: string | null; author: string | null; message: string }>;
  }>({ url: '/api/v1/orca/commits', ttl: 300_000 });
  const [tab, setTab] = useState<Tab>('timeline');
  const [kind, setKind] = useState('');
  const [severity, setSeverity] = useState('');
  const [harm, setHarm] = useState('');
  const [type, setType] = useState('');
  const [month, setMonth] = useState('');
  const [q, setQ] = useState('');
  const [body, setBody] = useState<IncidentBody | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const base =
      tab === 'critical' ? (data?.incidents ?? []).filter((r) => r.severity === 'critical') : (data?.incidents ?? []);
    return base.filter((r) => {
      if (kind && r.kind !== kind) return false;
      if (severity && r.severity !== severity) return false;
      if (harm && !(harm === 'null' ? r.realHarm === null : String(r.realHarm) === harm)) return false;
      if (type && !r.types.includes(type)) return false;
      if (month && r.month !== month) return false;
      if (needle && `${r.title} ${r.types.join(' ')} ${r.regions.join(' ')}`.toLowerCase().includes(needle) === false)
        return false;
      return true;
    });
  }, [data, tab, kind, severity, harm, type, month, q]);

  // Group by month for the timeline view.
  const byMonth = useMemo(() => {
    const map = new Map<string, IncidentSlim[]>();
    for (const r of rows) {
      if (!map.has(r.month)) map.set(r.month, []);
      map.get(r.month)!.push(r);
    }
    return [...map.entries()].sort((a, b) => (a[0] < b[0] ? 1 : -1));
  }, [rows]);

  const typeOptions = useMemo(() => {
    const s = statsData?.stats.by_type ?? {};
    return Object.entries(s).sort((a, b) => b[1] - a[1]);
  }, [statsData]);

  async function open(id: string) {
    setBodyLoading(true);
    setBody(null);
    try {
      setBody(await api.get<IncidentBody>(`/api/v1/orca/incidents/${encodeURIComponent(id)}`));
    } catch {
      setBody(null);
    } finally {
      setBodyLoading(false);
    }
  }

  const stats = statsData?.stats;

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'timeline', label: `Timeline (${data?.counts.records ?? '…'})` },
    { id: 'critical', label: `Critical (${data?.counts.critical ?? '…'})` },
    { id: 'stats', label: 'Stats' },
    { id: 'activity', label: 'Activity' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Bot size={28} />}
      title="ORCA AI Incident Archive"
      description={
        <>
          Open database of real-world AI agent security incidents (CC BY 4.0), auto-synced weekly from{' '}
          <a
            href="https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive"
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            Continuum-AI-Corp/Orca-AI-Incident-Archive
          </a>
          . {data?.counts.records ?? '…'} records, {data?.counts.months ?? '…'} months, {data?.counts.realHarm ?? '…'}{' '}
          with confirmed real-world harm. An agent that actually caused damage is not the same thing as a researcher
          showing that it could — <code className="text-xs">kind</code>, <code className="text-xs">real_harm</code> and{' '}
          <code className="text-xs">ai_involvement</code> separate the two.
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
            className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-600 text-white border-brand-600'
                : 'text-muted border-line-1 hover:border-brand-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab !== 'stats' && (
        <div className="flex flex-col sm:flex-row flex-wrap gap-2 mb-4">
          <select value={kind} onChange={(e) => setKind(e.target.value)} className={`${inputCls} sm:w-44`}>
            <option value="">All kinds</option>
            {Object.entries(KIND_LABELS).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={`${inputCls} sm:w-36`}>
            <option value="">All severity</option>
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select value={harm} onChange={(e) => setHarm(e.target.value)} className={`${inputCls} sm:w-44`}>
            <option value="">Any harm state</option>
            <option value="true">Confirmed harm</option>
            <option value="false">No confirmed harm</option>
            <option value="null">n/a (policy/report)</option>
          </select>
          <select value={type} onChange={(e) => setType(e.target.value)} className={`${inputCls} sm:w-36`}>
            <option value="">All types</option>
            {typeOptions.map(([t, n]) => (
              <option key={t} value={t}>
                {t} ({n})
              </option>
            ))}
          </select>
          <select value={month} onChange={(e) => setMonth(e.target.value)} className={`${inputCls} sm:w-40`}>
            <option value="">All months</option>
            {(data?.months ?? [])
              .slice()
              .reverse()
              .map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
          </select>
          <div className="relative flex-1 min-w-48">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search titles, types, regions…"
              className={`${inputCls} pl-9`}
            />
          </div>
        </div>
      )}

      {tab === 'timeline' &&
        byMonth.map(([m, list]) => (
          <div key={m} className="mb-6">
            <div className="flex items-center gap-2 mb-2">
              <CalendarDays size={15} className="text-muted" />
              <h2 className="font-semibold text-heading">{m}</h2>
              <span className="text-xs text-muted">
                {list.length} record{list.length === 1 ? '' : 's'}
                {list.some((r) => r.severity === 'critical') &&
                  ` · ${list.filter((r) => r.severity === 'critical').length} critical`}
              </span>
            </div>
            <div className="grid gap-2">
              {list.map((r) => (
                <IncidentRow key={r.id} r={r} onOpen={() => open(r.id)} />
              ))}
            </div>
          </div>
        ))}

      {tab === 'critical' && (
        <div className="grid gap-2">
          {rows.map((r) => (
            <IncidentRow key={r.id} r={r} onOpen={() => open(r.id)} />
          ))}
        </div>
      )}

      {tab !== 'stats' && rows.length === 0 && !loading && (
        <p className="text-sm text-muted">No records match the current filters.</p>
      )}

      {tab === 'stats' && stats && (
        <div className="grid gap-4 md:grid-cols-2">
          <StatCard
            title="Records"
            rows={[
              ['Total records', stats.count],
              ['Confirmed real harm', stats.real_harm.true],
              ['No confirmed harm', stats.real_harm.false],
              ['n/a (policy/report)', stats.real_harm.null],
              ['Critical severity', stats.by_severity.critical ?? 0],
            ]}
          />
          <StatCard title="Record kind" rows={Object.entries(stats.by_kind)} />
          <StatCard title="Attack type" rows={Object.entries(stats.by_type).sort((a, b) => b[1] - a[1])} />
          <StatCard title="Region" rows={Object.entries(stats.by_region).sort((a, b) => b[1] - a[1])} />
          <StatCard title="Severity" rows={Object.entries(stats.by_severity)} />
          <StatCard
            title="AI involvement"
            rows={Object.entries(stats.ai_involvement)}
            foot={`${stats.sources.links} source links · ${stats.sources.unique_urls} unique URLs · every record has ≥1 clickable primary source`}
          />
        </div>
      )}

      {tab === 'activity' && (
        <div className="grid gap-3">
          <div className="surface-card p-4">
            <h3 className="text-sm font-semibold text-heading mb-2">Upstream web pages</h3>
            <ul className="space-y-1.5 text-sm">
              <li>
                <a
                  href={data?.webPages?.repo ?? data?.sourceUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1.5"
                >
                  GitHub repository <ExternalLink size={12} />
                </a>
              </li>
              <li>
                <a
                  href={data?.webPages?.commits ?? `${data?.sourceUrl ?? ''}/commits/main`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1.5"
                >
                  Commit history (all record sweeps) <ExternalLink size={12} />
                </a>
              </li>
              <li>
                <a
                  href={data?.webPages?.offlineViewer ?? `${data?.sourceUrl ?? ''}/blob/main/index.html`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1.5"
                >
                  Offline interactive viewer (single-file index.html, 7 languages) <ExternalLink size={12} />
                </a>
              </li>
              <li>
                <a
                  href={data?.webPages?.primarySources ?? `${data?.sourceUrl ?? ''}/blob/main/dist/README.md`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1.5"
                >
                  Machine-readable export docs (dist/) <ExternalLink size={12} />
                </a>
              </li>
            </ul>
            <p className="text-xs text-muted mt-3">
              Upstream version stamp: {data?.upstreamVersion ?? '…'} · last commit {fmtDate(data?.lastCommit ?? null)}
              {data?.lastCommitSha ? ` (${data.lastCommitSha})` : ''} · CC BY 4.0 — attribution required. No hosted
              GitHub Pages site exists; the repository's index.html is the canonical viewer.
            </p>
          </div>
          <div className="grid gap-2">
            <p className="text-xs text-muted">
              Recent upstream commits — the weekly sync rebuilds this manifest, so new record sweeps and corrections
              surface here automatically.
            </p>
            {(commitsData?.commits ?? data?.recentCommits ?? []).map((c) => (
              <a
                key={c.sha}
                href={`${data?.sourceUrl ?? 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive'}/commit/${c.sha}`}
                target="_blank"
                rel="noreferrer"
                className="surface-card p-3 hover:border-brand-400 transition-colors"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <GitCommitHorizontal size={14} className="text-brand-500" />
                  <span className="font-mono text-xs text-heading">{c.sha}</span>
                  <span className="text-xs text-muted">{fmtDate(c.date)}</span>
                  <span className="text-xs text-muted ml-auto">{c.author}</span>
                </div>
                <p className="text-sm text-body mt-1">{c.message}</p>
              </a>
            ))}
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
            <h3 className="text-lg font-semibold text-heading leading-snug">{body.title}</h3>
            <div className="flex flex-wrap gap-1.5">
              <span
                className={`text-[11px] font-bold px-2 py-0.5 rounded border ${SEVERITY_STYLES[body.severity] ?? SEVERITY_STYLES.info}`}
              >
                {body.severity}
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded border text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 border-violet-300 dark:border-violet-800">
                {KIND_LABELS[body.kind] ?? body.kind}
              </span>
              <span className={`text-[11px] px-2 py-0.5 rounded border ${harmBadge(body.realHarm).cls}`}>
                {harmBadge(body.realHarm).label}
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded border text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800">
                confidence {body.confidence}
              </span>
              {body.aiInvolvement !== 'confirmed' && (
                <span className="text-[11px] px-2 py-0.5 rounded border text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800">
                  ai_involvement: {body.aiInvolvement}
                </span>
              )}
              {body.disputed && (
                <span className="text-[11px] px-2 py-0.5 rounded border text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800">
                  disputed
                </span>
              )}
              {body.landmark && (
                <span className="text-[11px] px-2 py-0.5 rounded border text-brand-700 dark:text-brand-300 bg-brand-50 dark:bg-brand-950/40 border-brand-300 dark:border-brand-800">
                  landmark
                </span>
              )}
              {body.types.map((t) => (
                <span
                  key={t}
                  className="text-[11px] px-2 py-0.5 rounded border text-heading bg-surface-100 border-line-1"
                >
                  {t}
                </span>
              ))}
            </div>
            <p className="text-sm text-muted">
              {fmtDate(body.date)}
              {body.dateEnd ? ` → ${fmtDate(body.dateEnd)}` : ''}
              {body.dateRaw && body.dateRaw !== body.date ? ` · ${body.dateRaw}` : ''} · {body.regions.join(', ')}
            </p>
            <div className="prose-sm text-body [&_p]:my-2 [&_strong]:text-heading">{renderMarkdown(body.summary)}</div>
            <div>
              <h4 className="text-sm font-semibold text-heading mb-1.5 flex items-center gap-1.5">
                <FileWarning size={14} /> Primary sources ({body.sources.length})
              </h4>
              <ul className="space-y-1">
                {body.sources.map((s) => (
                  <li key={s.url}>
                    <a
                      href={s.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sm text-brand-600 dark:text-brand-400 hover:underline break-all"
                    >
                      {s.label} <ExternalLink size={11} className="inline" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
            <a
              href={body.upstreamUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-sm text-brand-600 dark:text-brand-400 hover:underline"
            >
              <Landmark size={14} /> Full upstream record (Markdown)
            </a>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}

function IncidentRow({ r, onOpen }: { r: IncidentSlim; onOpen: () => void }): JSX.Element {
  const harm = harmBadge(r.realHarm);
  return (
    <button onClick={onOpen} className="surface-card text-left p-3 hover:border-brand-400 transition-colors w-full">
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className={`text-[11px] font-bold px-2 py-0.5 rounded border ${SEVERITY_STYLES[r.severity] ?? SEVERITY_STYLES.info}`}
        >
          {r.severity}
        </span>
        <span className="text-xs text-muted font-mono">{r.date}</span>
        {r.landmark && (
          <span title="landmark" className="text-brand-500 inline-flex">
            <Landmark size={12} />
          </span>
        )}
        {r.disputed && (
          <span title="disputed" className="text-amber-500 inline-flex">
            <FileWarning size={12} />
          </span>
        )}
        <span className="text-xs text-muted ml-auto flex items-center gap-1">
          <Scale size={11} /> {harm.label}
        </span>
      </div>
      <p className="text-sm font-medium text-heading mt-1.5">{r.title}</p>
      <div className="flex flex-wrap gap-1.5 mt-1.5">
        <span className="text-[11px] px-2 py-0.5 rounded border text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 border-violet-300 dark:border-violet-800">
          {KIND_LABELS[r.kind] ?? r.kind}
        </span>
        {r.types.map((t) => (
          <span key={t} className="text-[11px] px-2 py-0.5 rounded border text-heading bg-surface-100 border-line-1">
            {t}
          </span>
        ))}
        {r.regions.map((g) => (
          <span key={g} className="text-[11px] px-2 py-0.5 rounded border text-muted bg-surface-100 border-line-1">
            {g}
          </span>
        ))}
        <span className="text-[11px] text-muted self-center ml-1">
          {r.sourceCount} source{r.sourceCount === 1 ? '' : 's'}
        </span>
      </div>
    </button>
  );
}

function StatCard({ title, rows, foot }: { title: string; rows: Array<[string, number]>; foot?: string }): JSX.Element {
  return (
    <div className="surface-card p-4">
      <h3 className="text-sm font-semibold text-heading mb-2 flex items-center gap-1.5">
        <ShieldAlert size={14} /> {title}
      </h3>
      <table className="w-full text-sm">
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k} className="border-b border-line-1 last:border-0">
              <td className="py-1 text-muted">{k}</td>
              <td className="py-1 text-right font-mono text-heading">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {foot && <p className="text-xs text-muted mt-2">{foot}</p>}
    </div>
  );
}
