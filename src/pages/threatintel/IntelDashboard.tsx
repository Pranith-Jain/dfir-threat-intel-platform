import { Suspense, lazy, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { MaturityPanel } from '../../components/threatintel/MaturityPanel';
import { errMessage } from '../../lib/log';
// recharts (~540KB) lives behind the `cves` tab only — a static import here
// would make every IntelDashboard visit parse it even on `tab==='overview'`.
const CveLandscapePanel = lazy(() => import('./ThreatIntelDashboard').then((m) => ({ default: m.CveLandscapePanel })));
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bug,
  CheckCircle2,
  Clock,
  Globe2,
  Radio,
  RefreshCw,
  Shield,
  Skull,
  Target,
  TrendingUp,
  XCircle,
} from 'lucide-react';

interface DashboardData {
  generated_at: string;
  telegram_monitor: {
    total_leaks: number;
    leaks_24h: number;
    watched_channels: number;
    unreviewed_channels: number;
  };
  leaks_7d: number;
  feed_health: string;
  feed_count: number;
}

interface FeedRow {
  id: string;
  label: string;
  page_path: string;
  status: 'ok' | 'degraded' | 'down' | 'cold';
  reason: string;
  upstream_age_s?: number;
  reliability?: string;
  category?: string;
  info_credibility?: number;
  admiralty_grade?: string;
  metrics?: Record<string, number>;
}

interface FeedStatusData {
  generated_at: string;
  rows: FeedRow[];
  overall: 'ok' | 'degraded' | 'down' | 'cold';
  total_sources: number;
  healthy: number;
  degraded: number;
  down: number;
  cold: number;
  reliability_distribution: Record<string, number>;
  degraded_sources: Array<{ id: string; status: string; reason: string; page_path: string }>;
}

interface SnapshotData {
  generated_at?: string;
  ioc_count?: number;
  ransomware_claims_24h?: number;
  cve_kev_count?: number;
  [key: string]: unknown;
}

const SOURCES = [
  {
    key: 'ransomware',
    href: '/threatintel/iocs',
    label: 'Ransomware',
    icon: AlertTriangle,
    desc: 'Victim claims, leak-site activity, extortion tracking',
  },
  {
    key: 'cve',
    href: '/threatintel/cve-list',
    label: 'CVE & Vulns',
    icon: Bug,
    desc: 'NVD, CISA KEV, MyThreatIntel, cvefeed.io, CVE Telegram channels, FIRST EPSS',
  },
  {
    key: 'phishing',
    href: '/dfir/phishing',
    label: 'Phishing URLs',
    icon: Target,
    desc: 'OpenPhish + PhishTank - 80+ targeted brands',
  },
  {
    key: 'malware',
    href: '/threatintel/malware-vault',
    label: 'Malware Samples',
    icon: Radio,
    desc: 'MalwareBazaar - hashes, signatures, tags',
  },
  {
    key: 'telegram',
    href: '/threatintel/social',
    label: 'Telegram Intel',
    icon: Globe2,
    desc: '22 channels + custom - IOC drops, leak announcements',
  },
  {
    key: 'telegram_leaks',
    href: '/threatintel/telegram',
    label: 'Leak Monitor',
    icon: Shield,
    desc: 'Credential leaks, file drops, auto-scanned channels',
  },
  {
    key: 'breach',
    href: '/threatintel/iocs',
    label: 'Breach Database',
    icon: Activity,
    desc: '7 breach sources - email + domain search',
  },
  {
    key: 'ioc',
    href: '/threatintel/correlation',
    label: 'IOC Correlation',
    icon: TrendingUp,
    desc: '21 sources cross-referenced - high-signal indicators',
  },
];

const STATUS_ICON: Record<string, typeof CheckCircle2> = {
  ok: CheckCircle2,
  degraded: AlertTriangle,
  down: XCircle,
  cold: Clock,
};

const STATUS_COLOR: Record<string, string> = {
  ok: 'text-emerald-600 dark:text-emerald-400',
  degraded: 'text-amber-600 dark:text-amber-400',
  down: 'text-rose-600 dark:text-rose-400',
  cold: 'text-muted',
};

const STATUS_BG: Record<string, string> = {
  ok: 'bg-emerald-500/10 border-emerald-500/30',
  degraded: 'bg-amber-500/10 border-amber-500/30',
  down: 'bg-rose-500/10 border-rose-500/30',
  cold: 'bg-slate-500/10 border-slate-500/30',
};

function formatAge(seconds?: number): string {
  if (seconds === undefined) return '-';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function reliabilityColor(grade?: string): string {
  if (!grade) return 'text-muted';
  const letter = grade.charAt(0);
  if (letter === 'A') return 'text-emerald-600 dark:text-emerald-400';
  if (letter === 'B') return 'text-sky-600 dark:text-sky-400';
  if (letter === 'C') return 'text-amber-600 dark:text-amber-400';
  return 'text-rose-600 dark:text-rose-400';
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }): JSX.Element {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="h-1.5 w-full rounded-full bg-track overflow-hidden">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export default function IntelDashboard(): JSX.Element {
  const [tab, setTab] = useState<'overview' | 'cves'>('overview');
  const [data, setData] = useState<DashboardData | null>(null);
  const [feedData, setFeedData] = useState<FeedStatusData | null>(null);
  const [snapshotData, setSnapshotData] = useState<SnapshotData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    const opts = { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) };

    Promise.all([
      fetch('/api/v1/intel-dashboard', opts).then((r) => {
        if (!r.ok) throw new Error(`Couldn't load the dashboard (HTTP ${r.status}).`);
        return r.json() as Promise<DashboardData>;
      }),
      fetch('/api/v1/snapshot', opts)
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`snapshot ${r.status}`))))
        .catch(() => null),
      fetch('/api/v1/feed-status', opts)
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`feed-status ${r.status}`))))
        .catch(() => null),
    ])
      .then(([dash, snapshot, feed]) => {
        if (cancelled) return;
        setData(dash as DashboardData);
        setSnapshotData(snapshot as SnapshotData | null);
        setFeedData(feed as FeedStatusData | null);
        setLoading(false);
      })
      .catch((e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return;
        if (cancelled) return;
        setError(errMessage(e, 'Failed to load the dashboard'));
        setLoading(false);
      });

    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const categoryBreakdown = useMemo(() => {
    if (!feedData) return [];
    const cats: Record<string, { ok: number; degraded: number; down: number; cold: number; total: number }> = {};
    for (const row of feedData.rows) {
      const cat = row.category ?? 'other';
      if (!cats[cat]) cats[cat] = { ok: 0, degraded: 0, down: 0, cold: 0, total: 0 };
      cats[cat][row.status]++;
      cats[cat].total++;
    }
    return Object.entries(cats)
      .map(([name, counts]) => ({ name, ...counts }))
      .sort((a, b) => b.total - a.total);
  }, [feedData]);

  const topMetrics = useMemo(() => {
    if (!feedData) return [];
    const withMetrics = feedData.rows
      .filter((r) => r.metrics && Object.keys(r.metrics).length > 0)
      .flatMap((r) =>
        Object.entries(r.metrics!).map(([key, value]) => ({
          source: r.label,
          key,
          value,
          status: r.status,
        }))
      )
      .sort((a, b) => b.value - a.value);
    return withMetrics.slice(0, 12);
  }, [feedData]);

  const handleRefresh = () => {
    setLoading(true);
    setError(null);
    setRefreshKey((k) => k + 1);
  };

  return (
    <DataPageLayout
      title="Intel Dashboard &amp; Ops"
      icon={<BarChart3 size={28} />}
      backTo="/threatintel"
      description="Consolidated view across all sources - program health, feed reliability, snapshot metrics, and quick actions."
      loading={loading}
      error={error}
      onRetry={handleRefresh}
      maxWidthClass="max-w-6xl"
      headerExtra={
        feedData?.generated_at ? (
          <span className="text-mini font-mono text-muted">
            feeds {new Date(feedData.generated_at).toLocaleTimeString()}
            <button
              type="button"
              onClick={handleRefresh}
              className="ml-3 text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 transition-colors"
            >
              <RefreshCw size={11} /> refresh
            </button>
          </span>
        ) : undefined
      }
    >
      {/* ── Tab switcher ────────────────────────────────────────── */}
      <div className="mb-6 flex flex-wrap gap-1.5">
        {[
          { id: 'overview' as const, label: 'Overview' },
          { id: 'cves' as const, label: 'CVE Landscape' },
        ].map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`text-mini font-mono rounded-full border px-3 py-1.5 transition-colors ${
              tab === t.id
                ? 'border-rose-500 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-slate-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && data && (
        <>
          {/* ── KPI row ──────────────────────────────────────────── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
            <KpiCard
              label="Leaks indexed"
              value={String(data.telegram_monitor.total_leaks)}
              sub={`${data.telegram_monitor.leaks_24h} in 24h`}
            />
            <KpiCard
              label="Watched channels"
              value={String(data.telegram_monitor.watched_channels)}
              sub={`${data.telegram_monitor.unreviewed_channels} unreviewed`}
            />
            <KpiCard label="New leaks (7d)" value={String(data.leaks_7d)} />
            <KpiCard
              label="Feed health"
              value={data.feed_health}
              accent={
                data.feed_health === 'ok'
                  ? 'text-emerald-500'
                  : data.feed_health === 'degraded'
                    ? 'text-amber-500'
                    : 'text-rose-500'
              }
              sub={`${data.feed_count} sources`}
            />
          </div>

          {/* ── Platform health KPIs ─────────────────────────────── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
            <KpiCard
              icon={<CheckCircle2 size={18} />}
              label="Feeds Healthy"
              value={`${feedData?.healthy ?? 0}/${feedData?.total_sources ?? 0}`}
              accent="text-emerald-600 dark:text-emerald-400"
            />
            <KpiCard
              icon={<AlertTriangle size={18} />}
              label="Degraded"
              value={String(feedData?.degraded ?? 0)}
              accent="text-amber-600 dark:text-amber-400"
            />
            <KpiCard
              icon={<XCircle size={18} />}
              label="Down"
              value={String(feedData?.down ?? 0)}
              accent="text-rose-600 dark:text-rose-400"
            />
            <KpiCard
              icon={<Clock size={18} />}
              label="Cold (unprobed)"
              value={String(feedData?.cold ?? 0)}
              accent="text-muted"
            />
          </div>

          {/* ── ISAC snapshot row ────────────────────────────────── */}
          {snapshotData && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
              {snapshotData.ransomware_claims_24h !== undefined && (
                <KpiCard
                  icon={<Skull size={18} />}
                  label="Ransomware 24h"
                  value={String(snapshotData.ransomware_claims_24h)}
                  accent="text-rose-600 dark:text-rose-400"
                  href="/threatintel/iocs"
                />
              )}
              {snapshotData.ioc_count !== undefined && (
                <KpiCard
                  icon={<Target size={18} />}
                  label="Live IOCs"
                  value={
                    snapshotData.ioc_count > 1000
                      ? `${(snapshotData.ioc_count / 1000).toFixed(1)}k`
                      : String(snapshotData.ioc_count)
                  }
                  accent="text-rose-600 dark:text-rose-400"
                  href="/threatintel/iocs"
                />
              )}
              {snapshotData.cve_kev_count !== undefined && (
                <KpiCard
                  icon={<Bug size={18} />}
                  label="CVE KEV"
                  value={String(snapshotData.cve_kev_count)}
                  accent="text-amber-600 dark:text-amber-400"
                  href="/threatintel/cves/cves"
                />
              )}
              {data.telegram_monitor && (
                <KpiCard
                  icon={<Radio size={18} />}
                  label="Telegram 24h"
                  value={String(data.telegram_monitor.leaks_24h)}
                  accent="text-sky-600 dark:text-sky-400"
                  href="/threatintel/social/firehose"
                />
              )}
            </div>
          )}
        </>
      )}

      {tab === 'overview' && (
        <>
          {/* ── Reliability Distribution ─────────────────────────────── */}
          {feedData?.reliability_distribution && (
            <section className="mb-8">
              <h2 className="font-display font-semibold text-lg text-body mb-3">Source Reliability (NATO Admiralty)</h2>
              <div className="grid grid-cols-3 sm:grid-cols-7 gap-2">
                {(['A', 'B', 'C', 'D', 'E', 'F', 'ungraded'] as const).map((grade) => {
                  const count = feedData.reliability_distribution[grade] ?? 0;
                  return (
                    <div key={grade} className="surface-card p-3 text-center">
                      <div className={`text-2xl font-display font-bold ${reliabilityColor(grade)}`}>
                        {grade === 'ungraded' ? '-' : grade}
                      </div>
                      <div className="text-mini font-mono text-muted mt-1">
                        {count} {count === 1 ? 'source' : 'sources'}
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* ── Category Health ──────────────────────────────────────── */}
          {categoryBreakdown.length > 0 && (
            <section className="mb-8">
              <h2 className="font-display font-semibold text-lg text-body mb-3">Health by Category</h2>
              <div className="surface-card divide-y divide-line-1">
                {categoryBreakdown.map((cat) => (
                  <div key={cat.name} className="flex items-center gap-4 px-4 py-3">
                    <span className="font-mono text-sm text-body w-32 shrink-0 capitalize">{cat.name}</span>
                    <div className="flex-1">
                      <MiniBar value={cat.ok} max={cat.total} color="bg-emerald-500" />
                    </div>
                    <div className="flex items-center gap-2 text-mini font-mono text-muted shrink-0">
                      <span className="text-emerald-600">{cat.ok}</span>
                      <span className="text-amber-600">{cat.degraded}</span>
                      <span className="text-rose-600">{cat.down}</span>
                      <span className="text-muted">{cat.cold}</span>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ── Feed Detail Table ────────────────────────────────────── */}
          {feedData?.rows && feedData.rows.length > 0 && (
            <section className="mb-8">
              <h2 className="font-display font-semibold text-lg text-body mb-3">
                All Sources ({feedData.rows.length})
              </h2>
              <div className="surface-card overflow-hidden">
                <div className="overflow-x-auto">
                  <DataTable
                    columns={
                      [
                        {
                          key: 'status',
                          header: 'Status',
                          sortValue: (row: (typeof feedData.rows)[number]) => row.status,
                          render: (row) => {
                            const Icon = STATUS_ICON[row.status] ?? Clock;
                            return (
                              <span className={`inline-flex items-center gap-1.5 ${STATUS_COLOR[row.status]}`}>
                                <Icon size={14} />
                                <span className="font-mono text-xs capitalize">{row.status}</span>
                              </span>
                            );
                          },
                        },
                        {
                          key: 'source',
                          header: 'Source',
                          sortValue: (row: (typeof feedData.rows)[number]) => row.label,
                          render: (row) =>
                            row.page_path ? (
                              <Link
                                to={row.page_path}
                                className="font-mono text-sm text-heading hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                              >
                                {row.label}
                              </Link>
                            ) : (
                              <span className="font-mono text-sm text-body">{row.label}</span>
                            ),
                        },
                        {
                          key: 'category',
                          header: 'Category',
                          sortValue: (row: (typeof feedData.rows)[number]) => row.category ?? '',
                          className: 'hidden sm:table-cell',
                          render: (row) => (
                            <span className="font-mono text-xs text-muted capitalize">{row.category ?? '-'}</span>
                          ),
                        },
                        {
                          key: 'grade',
                          header: 'Grade',
                          sortValue: (row: (typeof feedData.rows)[number]) => row.admiralty_grade ?? '',
                          className: 'hidden md:table-cell',
                          render: (row) => (
                            <span
                              className={`font-mono text-xs font-semibold ${reliabilityColor(row.admiralty_grade)}`}
                            >
                              {row.admiralty_grade ?? '-'}
                            </span>
                          ),
                        },
                        {
                          key: 'age',
                          header: 'Age',
                          sortValue: (row: (typeof feedData.rows)[number]) => row.upstream_age_s ?? 0,
                          className: 'hidden lg:table-cell',
                          render: (row) => (
                            <span className="font-mono text-xs text-muted">{formatAge(row.upstream_age_s)}</span>
                          ),
                        },
                        {
                          key: 'reason',
                          header: 'Reason',
                          render: (row) => <span className="text-xs text-muted line-clamp-1">{row.reason}</span>,
                        },
                      ] as DataTableColumn<(typeof feedData.rows)[number]>[]
                    }
                    rows={feedData.rows}
                    rowKey={(row) => row.id}
                    rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-surface-300/50'}
                  />
                </div>
              </div>
            </section>
          )}

          {/* ── Degraded Sources Alert ───────────────────────────────── */}
          {feedData?.degraded_sources && feedData.degraded_sources.length > 0 && (
            <section className="mb-8">
              <h2 className="font-display font-semibold text-lg text-body mb-3">
                Degraded Sources ({feedData.degraded_sources.length})
              </h2>
              <div className="rounded-xl border border-amber-300/50 dark:border-amber-800/50 bg-amber-50/50 dark:bg-amber-950/20 p-4 space-y-2">
                {feedData.degraded_sources.map((src) => (
                  <div key={src.id} className="flex items-start gap-2">
                    <AlertTriangle size={14} className="text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
                    <div>
                      <span className="font-mono text-sm font-semibold text-heading">{src.id}</span>
                      <span className="text-xs text-muted ml-2">({src.status})</span>
                      <p className="text-xs text-muted mt-0.5">{src.reason}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ── Top Metrics ──────────────────────────────────────────── */}
          {topMetrics.length > 0 && (
            <section className="mb-8">
              <h2 className="font-display font-semibold text-lg text-body mb-3">Top Feed Metrics</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {topMetrics.map((m, i) => (
                  <div key={`${m.source}-${m.key}-${i}`} className={`rounded-xl border p-3 ${STATUS_BG[m.status]}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-xs text-muted">{m.source}</span>
                      <span className="font-mono text-xs text-muted">{m.key}</span>
                    </div>
                    <div className="font-display font-bold text-xl text-heading">{m.value.toLocaleString()}</div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ── Program health: CTI-CMM maturity ─────────────────────── */}
          <section id="maturity" className="mb-8">
            <h2 className="text-sm font-bold uppercase tracking-[0.15em] text-rose-600 dark:text-rose-400 font-mono mb-2">
              Program Health
            </h2>
            <MaturityPanel />
          </section>

          {/* ── Source cards ─────────────────────────────────────────── */}
          <section className="mb-8">
            <h2 className="text-sm font-bold uppercase tracking-[0.15em] text-rose-600 dark:text-rose-400 font-mono mb-2">
              Threat Intelligence Sources
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {SOURCES.map((s) => {
                const Icon = s.icon;
                return (
                  <Link key={s.key} to={s.href} className="surface-card card-hover block p-4 group">
                    <div className="flex items-start gap-3">
                      <Icon size={18} className="text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <h3 className="font-display font-semibold text-sm group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors">
                          {s.label}
                        </h3>
                        <p className="text-meta text-muted mt-0.5 leading-relaxed">{s.desc}</p>
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          </section>

          {/* ── Quick links ──────────────────────────────────────────── */}
          <section className="surface-card p-5">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted mb-3">Quick Actions</h2>
            <div className="flex flex-wrap gap-2">
              {[
                { label: 'Telegram Leaks', href: '/threatintel/telegram' },
                { label: 'Leak Stats', href: '/threatintel/telegram?tab=stats' },
                { label: 'Discovered Channels', href: '/threatintel/telegram?tab=channels' },
                { label: 'Breach Search', href: '/threatintel/iocs' },
                { label: 'IOC Correlation', href: '/threatintel/correlation' },
                { label: 'Threat Map', href: '/threatintel/threat-map' },
                { label: 'Feed Status', href: '/threatintel/status' },
                { label: 'Live IOCs', href: '/threatintel/iocs' },
                { label: 'Ransomware', href: '/threatintel/iocs' },
                { label: 'CVE List', href: '/threatintel/cve-list' },
                { label: 'Malware Samples', href: '/threatintel/malware-vault' },
                { label: 'Phishing Monitor', href: '/dfir/phishing' },
                { label: 'Threat Hunt', href: '/dfir/threat-hunt' },
                { label: 'Collection SLO', href: '/threatintel/collection-slo' },
                { label: 'Source Reliability', href: '/threatintel/source-reliability' },
                { label: 'Intel Requirements (PIRs)', href: '/threatintel/pir-dashboard' },
                { label: 'ACH Generator', href: '/threatintel/ach' },
                { label: 'Cross-Correlate', href: '/threatintel/cross-correlate' },
                { label: 'Assessments', href: '/threatintel/assessments' },
                { label: 'Entity Resolution', href: '/threatintel/relationship-graph' },
              ].map((link) => (
                <Link
                  key={link.href}
                  to={link.href}
                  className="text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                >
                  {link.label}
                </Link>
              ))}
            </div>
          </section>

          {/* ── Analytics Engine Note ────────────────────────────────── */}
          <section className="mt-8 rounded-xl border border-dashed border-line-2 p-5 text-center">
            <p className="text-sm text-muted">
              Visitor analytics (page views, geographic distribution, response times) are tracked in Cloudflare
              Analytics Engine. Query them from the{' '}
              <a
                href="https://dash.cloudflare.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
              >
                Cloudflare dashboard
              </a>{' '}
              → Analytics → Workers Analytics Engine.
            </p>
          </section>
        </>
      )}

      {tab === 'cves' && (
        <Suspense fallback={<div className="py-8 text-center text-sm text-muted">Loading charts…</div>}>
          <CveLandscapePanel />
        </Suspense>
      )}
    </DataPageLayout>
  );
}

function KpiCard({
  icon,
  label,
  value,
  sub,
  accent = 'text-heading',
  href,
}: {
  icon?: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  accent?: string;
  href?: string;
}): JSX.Element {
  const inner = (
    <>
      {icon ? <div className={`${accent} mb-1`}>{icon}</div> : null}
      <div className={`font-display font-bold text-2xl ${accent}`}>{value}</div>
      <div className="text-mini font-mono text-muted mt-0.5">{label}</div>
      {sub ? <div className="text-mini text-muted mt-0.5">{sub}</div> : null}
    </>
  );

  const cardClass = 'surface-card p-4 transition hover:-translate-y-0.5 hover:shadow-e2';

  if (href) {
    return (
      <Link to={href} className={`${cardClass} block`}>
        {inner}
      </Link>
    );
  }
  return <div className={cardClass}>{inner}</div>;
}
