import { useEffect, useMemo, useState } from 'react';
import { useTheme } from '../../hooks';
import { useLiveFeed } from '../../hooks/useLiveFeed';
import {
  Search as SearchIcon,
  RefreshCw,
  AlertTriangle,
  Skull,
  Globe2,
  Filter,
  BarChart3,
  PieChart as PieIcon,
  TrendingUp,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  LineChart,
  Line,
  ResponsiveContainer,
} from 'recharts';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

interface CveEntry {
  cveId: string;
  description: string;
  publishedAt: string;
  cvssV3Score: number | null;
  cvssV3Severity: string;
  inKev: boolean;
  priorityScore: number;
  vendor?: string;
  product?: string;
  family?: string;
  cna?: string;
  exploited?: boolean;
  impactType?: string;
}

type ViewTab =
  'severity' | 'cvss' | 'impact' | 'product-family' | 'product' | 'cna' | 'exploited' | 'month' | 'over-time';
type ChartType = 'bar' | 'column' | 'line' | 'pie';

const VIEW_TABS: { id: ViewTab; label: string }[] = [
  { id: 'severity', label: 'Severity' },
  { id: 'cvss', label: 'CVSS score band' },
  { id: 'impact', label: 'Impact type' },
  { id: 'product-family', label: 'Product family' },
  { id: 'product', label: 'Product' },
  { id: 'cna', label: 'Issuing CNA' },
  { id: 'exploited', label: 'Exploited / disclosed' },
  { id: 'month', label: 'Update month' },
  { id: 'over-time', label: 'Over time' },
];

function normalizeSeverity(s: string | null | undefined): string {
  if (!s) return '(none)';
  const low = s.toLowerCase();
  if (low === 'critical' || low === 'crítica') return 'Critical';
  if (low === 'high' || low === 'important') return 'Important';
  if (low === 'medium' || low === 'moderate') return 'Moderate';
  if (low === 'low') return 'Low';
  return '(none)';
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  Important: '#f97316',
  Moderate: '#eab308',
  Low: '#3b82f6',
  '(none)': '#6b7280',
};

const SEV_ORDER = ['Critical', 'Important', 'Moderate', 'Low', '(none)'];

const BAR_PALETTE = [
  '#06b6d4',
  '#a78bfa',
  '#f472b6',
  '#fb923c',
  '#4ade80',
  '#60a5fa',
  '#facc15',
  '#c084fc',
  '#f87171',
  '#34d399',
  '#818cf8',
  '#fb7185',
  '#a3e635',
  '#38bdf8',
  '#e879f9',
  '#fbbf24',
  '#2dd4bf',
  '#f43f5e',
  '#8b5cf6',
  '#22d3ee',
];

const CARD = 'surface-card';
const INPUT =
  'w-full rounded-xl border border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-input-200 px-3 py-2 text-sm text-heading placeholder:text-slate-400 focus:outline-none focus:border-rose-500';

const SEVERITY_PILL: Record<string, string> = {
  Critical: 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800',
  Important:
    'bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800',
  Moderate:
    'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800',
  Low: 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-800',
};

function StatCard({
  label,
  value,
  color,
  icon,
}: {
  label: string;
  value: number | string;
  color: string;
  icon: React.ReactNode;
}) {
  return (
    <div className={`${CARD} px-4 py-3 flex items-center gap-3`}>
      <div className={`rounded-xl p-2 ${color}`}>{icon}</div>
      <div>
        <div className="text-xl font-bold text-heading">{value}</div>
        <div className="text-mini font-mono uppercase tracking-wider text-muted">{label}</div>
      </div>
    </div>
  );
}

function DataSummaryTable({ data, label }: { data: Array<{ name: string; count: number }>; label: string }) {
  const total = data.reduce((s, d) => s + d.count, 0);
  return (
    <div className={`${CARD} overflow-hidden mt-4`}>
      <div className="px-4 py-2 border-b border-line-1">
        <span className="text-mini font-mono uppercase tracking-wider text-muted">Data Summary</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="border-b border-line-1 text-left text-mini uppercase tracking-wider text-muted">
            <tr>
              <th className="py-2 px-4 font-medium">{label}</th>
              <th className="py-2 px-4 font-medium text-right">Count</th>
              <th className="py-2 px-4 font-medium text-right">% of Total</th>
              <th className="py-2 px-4 font-medium">Distribution</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => {
              const pct = total > 0 ? (row.count / total) * 100 : 0;
              return (
                <tr key={row.name} className="border-b border-line-1 last:border-0">
                  <td className="py-2 px-4 text-sm text-heading">{row.name}</td>
                  <td className="py-2 px-4 text-sm font-mono text-right text-rose-600 dark:text-rose-400">
                    {row.count.toLocaleString()}
                  </td>
                  <td className="py-2 px-4 text-sm text-right text-muted">{pct.toFixed(1)}%</td>
                  <td className="py-2 px-4">
                    <div className="w-full bg-surface-300 rounded-full h-2 overflow-hidden">
                      <div className="h-full bg-rose-500 rounded-full transition-all" style={{ width: `${pct}%` }} />
                    </div>
                  </td>
                </tr>
              );
            })}
            <tr className="font-semibold border-t border-line-1">
              <td className="py-2 px-4 text-sm text-heading">Total</td>
              <td className="py-2 px-4 text-sm font-mono text-right text-rose-600 dark:text-rose-400">
                {total.toLocaleString()}
              </td>
              <td className="py-2 px-4 text-sm text-right text-muted">100%</td>
              <td />
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function PieView({ data, title }: { data: Array<{ name: string; count: number }>; title: string }) {
  return (
    <div>
      <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-4">{title}</h3>
      <div className="flex justify-center">
        <ResponsiveContainer width="100%" height={350}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={80}
              outerRadius={140}
              paddingAngle={2}
              dataKey="count"
              nameKey="name"
              label
              labelLine
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={SEVERITY_COLORS[entry.name] ?? BAR_PALETTE[i % BAR_PALETTE.length]} />
              ))}
            </Pie>
            <Tooltip formatter={(value) => [`${Number(value).toLocaleString()}`, 'Count']} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <DataSummaryTable data={data} label={title} />
    </div>
  );
}

function BarView({
  data,
  title,
  horizontal = true,
  isDark,
}: {
  data: Array<{ name: string; count: number }>;
  title: string;
  horizontal?: boolean;
  isDark: boolean;
}) {
  return (
    <div>
      <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-4">{title}</h3>
      <ResponsiveContainer width="100%" height={Math.max(350, data.length * 28 + 50)}>
        <BarChart
          data={data}
          layout={horizontal ? 'vertical' : 'horizontal'}
          margin={{ left: horizontal ? 120 : 20, right: 20, top: 5, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
          {horizontal ? (
            <>
              <XAxis type="number" tick={{ fill: isDark ? '#94a3b8' : '#64748b', fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: isDark ? '#cbd5e1' : '#475569', fontSize: 11 }}
                width={115}
              />
            </>
          ) : (
            <>
              <XAxis
                dataKey="name"
                tick={{ fill: isDark ? '#cbd5e1' : '#475569', fontSize: 10 }}
                angle={-45}
                textAnchor="end"
                height={80}
              />
              <YAxis tick={{ fill: isDark ? '#94a3b8' : '#64748b', fontSize: 11 }} />
            </>
          )}
          <Tooltip
            contentStyle={{
              backgroundColor: isDark ? 'rgb(15,23,42)' : 'white',
              border: `1px solid ${isDark ? 'rgba(148,163,184,0.2)' : 'rgb(226,232,240)'}`,
              borderRadius: 8,
              fontSize: 12,
              color: isDark ? '#e2e8f0' : '#1e293b',
            }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {data.map((_, i) => (
              <Cell key={i} fill={BAR_PALETTE[i % BAR_PALETTE.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <DataSummaryTable data={data} label={title} />
    </div>
  );
}

function LineView({
  data,
  title,
  isDark,
}: {
  data: Array<Record<string, string | number>>;
  title: string;
  isDark: boolean;
}) {
  const lines = ['Critical', 'Important', 'Moderate', 'Low'];
  return (
    <div>
      <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-4">{title}</h3>
      <ResponsiveContainer width="100%" height={380}>
        <LineChart data={data} margin={{ left: 10, right: 10, top: 5, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
          <XAxis dataKey="month" tick={{ fill: isDark ? '#94a3b8' : '#64748b', fontSize: 10 }} />
          <YAxis tick={{ fill: isDark ? '#94a3b8' : '#64748b', fontSize: 11 }} />
          <Tooltip
            contentStyle={{
              backgroundColor: isDark ? 'rgb(15,23,42)' : 'white',
              border: `1px solid ${isDark ? 'rgba(148,163,184,0.2)' : 'rgb(226,232,240)'}`,
              borderRadius: 8,
              fontSize: 12,
              color: isDark ? '#e2e8f0' : '#1e293b',
            }}
          />
          <Legend />
          {lines.map((sev) => (
            <Line key={sev} type="monotone" dataKey={sev} stroke={SEVERITY_COLORS[sev]} strokeWidth={2} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
      <DataSummaryTable
        data={data.map((d) => ({ name: String(d.month), count: lines.reduce((s, l) => s + (Number(d[l]) || 0), 0) }))}
        label="Over Time"
      />
    </div>
  );
}

function buildSeverityData(cves: CveEntry[]) {
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const sev = c.cvssV3Severity || '(none)';
    counts[sev] = (counts[sev] || 0) + 1;
  }
  return SEV_ORDER.filter((s) => counts[s]).map((s) => ({ name: s, count: counts[s] }));
}

function buildCvssData(cves: CveEntry[]) {
  const bands = ['Critical (9-10)', 'High (7-8.9)', 'Medium (4-6.9)', 'Low (0-3.9)', '(none)'];
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const s = c.cvssV3Score;
    if (s == null) {
      counts['(none)'] = (counts['(none)'] || 0) + 1;
    } else if (s >= 9) {
      counts['Critical (9-10)'] = (counts['Critical (9-10)'] || 0) + 1;
    } else if (s >= 7) {
      counts['High (7-8.9)'] = (counts['High (7-8.9)'] || 0) + 1;
    } else if (s >= 4) {
      counts['Medium (4-6.9)'] = (counts['Medium (4-6.9)'] || 0) + 1;
    } else {
      counts['Low (0-3.9)'] = (counts['Low (0-3.9)'] || 0) + 1;
    }
  }
  return bands.filter((b) => counts[b]).map((b) => ({ name: b, count: counts[b] }));
}

function buildProductFamilyData(cves: CveEntry[]) {
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const fam = c.family || c.product || 'Unknown';
    counts[fam] = (counts[fam] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([name, count]) => ({ name, count }));
}

function buildProductData(cves: CveEntry[]) {
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const prod = c.product || 'Unknown';
    counts[prod] = (counts[prod] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([name, count]) => ({ name, count }));
}

function buildCnaData(cves: CveEntry[]) {
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const cna = c.cna || 'Unknown';
    counts[cna] = (counts[cna] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([name, count]) => ({ name, count }));
}

function buildExploitedData(cves: CveEntry[]) {
  let exploited = 0;
  let notExploited = 0;
  for (const c of cves) {
    if (c.exploited || c.inKev) exploited++;
    else notExploited++;
  }
  return [
    { name: 'Exploited', count: exploited },
    { name: 'Not exploited', count: notExploited },
  ];
}

function buildMonthData(cves: CveEntry[]) {
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const d = c.publishedAt?.slice(0, 7);
    if (d) counts[d] = (counts[d] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([name, count]) => ({ name, count }));
}

function buildOverTimeData(cves: CveEntry[]) {
  const months: Record<string, Record<string, number>> = {};
  for (const c of cves) {
    const m = c.publishedAt?.slice(0, 7);
    if (!m) continue;
    if (!months[m]) months[m] = { Critical: 0, Important: 0, Moderate: 0, Low: 0 } as Record<string, number>;
    const rec = months[m]!;
    const sev = c.cvssV3Severity || 'Important';
    rec[sev] = (rec[sev] || 0) + 1;
  }
  return Object.entries(months)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([month, counts]) => ({ month, ...counts }));
}

function buildImpactData(cves: CveEntry[]) {
  const counts: Record<string, number> = {};
  for (const c of cves) {
    const impact = c.impactType || 'Unknown';
    counts[impact] = (counts[impact] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));
}

export function CveLandscapePanel(): JSX.Element {
  const { isDark } = useTheme();
  const { feeds, connected } = useLiveFeed();
  const [cves, setCves] = useState<CveEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<ViewTab>('severity');
  const [chartType, setChartType] = useState<ChartType>('pie');
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<string[]>([]);
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [topN, setTopN] = useState(20);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);

    const fetchAll = async () => {
      try {
        const results = await Promise.allSettled([
          fetch('/api/v1/threat-intel/cves?limit=1000', {
            signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(25000)]),
          }),
          fetch('/api/v1/cve-recent?limit=500', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(25000)]) }),
        ]);
        if (cancelled) return;
        const seen = new Set<string>();
        const allCves: CveEntry[] = [];
        for (const r of results) {
          if (r.status === 'fulfilled' && r.value.ok) {
            const d = await r.value.json();
            const items = d.cves ?? d.data ?? d.entries ?? [];
            for (const item of items) {
              const cveId = item.cveId ?? item.id ?? '';
              if (!cveId || seen.has(cveId)) continue;
              seen.add(cveId);
              const sev = normalizeSeverity(item.cvssV3Severity ?? item.severity);
              allCves.push({
                cveId,
                description: item.description ?? item.shortDescription ?? '',
                publishedAt: item.publishedAt ?? item.published ?? item.dateAdded ?? '',
                cvssV3Score: item.cvssV3Score ?? item.score ?? item.cvss ?? null,
                cvssV3Severity: sev,
                inKev: item.inKev ?? item.kev ?? false,
                priorityScore: item.priorityScore ?? 0,
                vendor: item.vendor ?? '',
                product: item.product ?? '',
                family: item.family ?? item.productFamily ?? '',
                cna: item.cna ?? item.issuingCna ?? item.origin ?? '',
                exploited: item.exploited ?? item.inKev ?? item.kev ?? false,
                impactType: item.impactType ?? item.impact ?? '',
              });
            }
          }
        }
        if (!cancelled) setCves(allCves);
      } catch (e) {
        if (!cancelled) setError(errMessage(e, 'fetch failed'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchAll();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    let rows = cves;
    const q = search.trim().toLowerCase();
    if (q) rows = rows.filter((c) => `${c.cveId} ${c.description} ${c.product} ${c.family}`.toLowerCase().includes(q));
    if (sevFilter.length > 0) rows = rows.filter((c) => sevFilter.includes(c.cvssV3Severity));
    if (exploitedOnly) rows = rows.filter((c) => c.exploited || c.inKev);
    if (kevOnly) rows = rows.filter((c) => c.inKev);
    return rows;
  }, [cves, search, sevFilter, exploitedOnly, kevOnly]);

  const viewData = useMemo(() => {
    switch (view) {
      case 'severity':
        return buildSeverityData(filtered);
      case 'cvss':
        return buildCvssData(filtered);
      case 'impact':
        return buildImpactData(filtered);
      case 'product-family':
        return buildProductFamilyData(filtered).slice(0, topN);
      case 'product':
        return buildProductData(filtered).slice(0, topN);
      case 'cna':
        return buildCnaData(filtered).slice(0, topN);
      case 'exploited':
        return buildExploitedData(filtered);
      case 'month':
        return buildMonthData(filtered);
      case 'over-time':
        return buildOverTimeData(filtered);
    }
  }, [filtered, view, topN]);

  const stats = useMemo(() => {
    const total = filtered.length;
    const critical = filtered.filter((c) => c.cvssV3Severity === 'Critical' || (c.cvssV3Score ?? 0) >= 9).length;
    const high = filtered.filter(
      (c) => c.cvssV3Severity === 'Important' || c.cvssV3Severity === 'High' || (c.cvssV3Score ?? 0) >= 7
    ).length;
    const geo = new Set(filtered.map((c) => c.vendor).filter(Boolean)).size;
    return { total, critical, high, geo };
  }, [filtered]);

  const titleText = useMemo(() => {
    const t = VIEW_TABS.find((t) => t.id === view);
    return t?.label ?? 'Severity';
  }, [view]);

  const isOverTime = view === 'over-time';

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16 text-sm text-muted">Loading CVE landscape&hellip;</div>
    );
  }
  if (error) {
    return (
      <div className="flex flex-col items-center gap-3 py-16 text-sm text-rose-600 dark:text-rose-400">
        <span>{error}</span>
        <button
          type="button"
          onClick={() => setRefreshKey((k) => k + 1)}
          className="text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 transition-colors"
        >
          <RefreshCw size={11} /> retry
        </button>
      </div>
    );
  }
  if (cves.length === 0) {
    return <div className="py-16 text-center text-sm text-muted">No CVE data available.</div>;
  }

  return (
    <>
      {/* Header row: refresh + scope */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-display font-semibold text-lg text-body">CVE Landscape</h2>
        <div className="flex items-center gap-3 text-xs text-muted">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 font-mono hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" /> refresh
          </button>
          <span className="font-mono">{filtered.length.toLocaleString()} CVEs in scope</span>
        </div>
      </div>

      {/* Stat pills */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <StatCard
          label="Entries / 24h"
          value={stats.total}
          color="bg-rose-100 dark:bg-rose-900/40"
          icon={<BarChart3 className="h-5 w-5 text-rose-600 dark:text-rose-400" />}
        />
        <StatCard
          label="Critical"
          value={stats.critical}
          color="bg-rose-100 dark:bg-rose-900/40"
          icon={<Skull className="h-5 w-5 text-rose-600 dark:text-rose-400" />}
        />
        <StatCard
          label="High"
          value={stats.high}
          color="bg-orange-100 dark:bg-orange-900/40"
          icon={<AlertTriangle className="h-5 w-5 text-orange-600 dark:text-orange-400" />}
        />
        <StatCard
          label="Geo"
          value={stats.geo}
          color="bg-emerald-100 dark:bg-emerald-900/40"
          icon={<Globe2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />}
        />
      </div>

      {/* Live feed status */}
      {connected && feeds.size > 0 && (
        <div className="flex flex-wrap items-center gap-3 mb-4 text-mini font-mono text-muted">
          <span className="inline-flex items-center gap-1.5">
            <span className="relative inline-flex h-1.5 w-1.5">
              <span className="absolute inset-0 rounded-full bg-emerald-500 live-pulse" />
              <span className="relative inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
            </span>
            Live feeds
          </span>
          {Array.from(feeds.entries()).map(([name, snap]) => (
            <span key={name} className="rounded border border-line-1 px-1.5 py-0.5">
              {name}: {snap.total.toLocaleString()}
            </span>
          ))}
        </div>
      )}

      {/* View tabs */}
      <div className="mb-3 flex flex-wrap gap-1.5">
        {VIEW_TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setView(t.id)}
            className={`inline-flex items-center gap-1.5 text-mini font-mono rounded-full border px-2.5 py-1 transition-colors ${view === t.id ? 'border-rose-500 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300' : 'border-slate-300 dark:border-line-1 text-muted hover:border-slate-400'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Filter bar */}
      <div className={`${CARD} p-4 mb-4`}>
        <div className="flex flex-col gap-3">
          <div className="relative flex-1">
            <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by CVE, title, product, family..."
              className={`${INPUT} pl-9 pr-3`}
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-muted"
              >
                ×
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-3.5 w-3.5 text-muted" />
            {['Critical', 'Important', 'Moderate', 'Low'].map((sev) => {
              const active = sevFilter.includes(sev);
              const cls = SEVERITY_PILL[sev] ?? '';
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSevFilter((p) => (active ? p.filter((s) => s !== sev) : [...p, sev]))}
                  className={`px-2 py-0.5 rounded-full text-mini font-mono border transition-colors ${active ? cls : 'bg-transparent text-muted border-slate-300 dark:border-line-1'}`}
                >
                  {sev}
                </button>
              );
            })}
            <div className="w-px h-5 bg-track dark:bg-line-1" />
            <button
              type="button"
              onClick={() => setExploitedOnly((p) => !p)}
              className={`px-2 py-0.5 rounded-full text-mini font-mono border transition-colors ${exploitedOnly ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800' : 'bg-transparent text-muted border-slate-300 dark:border-line-1'}`}
            >
              Exploited only
            </button>
            <button
              type="button"
              onClick={() => setKevOnly((p) => !p)}
              className={`px-2 py-0.5 rounded-full text-mini font-mono border transition-colors ${kevOnly ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800' : 'bg-transparent text-muted border-slate-300 dark:border-line-1'}`}
            >
              On KEV only
            </button>
            <div className="w-px h-5 bg-track dark:bg-line-1" />
            <select
              value={topN}
              onChange={(e) => setTopN(Number(e.target.value))}
              className="rounded-xl border border-line-2 bg-surface-200 px-2 py-1 text-mini font-mono text-body"
            >
              <option value={10}>Top 10</option>
              <option value={20}>Top 20</option>
              <option value={50}>Top 50</option>
            </select>
            <div className="w-px h-5 bg-track dark:bg-line-1" />
            <div className="flex gap-1">
              {[
                { type: 'pie' as ChartType, icon: <PieIcon className="h-3.5 w-3.5" /> },
                { type: 'bar' as ChartType, icon: <BarChart3 className="h-3.5 w-3.5" /> },
                { type: 'column' as ChartType, icon: <BarChart3 className="h-3.5 w-3.5 rotate-90" /> },
                { type: 'line' as ChartType, icon: <TrendingUp className="h-3.5 w-3.5" /> },
              ].map(({ type, icon }) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setChartType(type)}
                  className={`p-1.5 rounded transition-colors ${chartType === type ? 'bg-rose-100 dark:bg-rose-900/40 text-rose-600 dark:text-rose-400' : 'text-muted hover:text-slate-600 dark:hover:text-slate-300'}`}
                >
                  {icon}
                </button>
              ))}
            </div>
            {sevFilter.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  setSevFilter([]);
                  setExploitedOnly(false);
                  setKevOnly(false);
                }}
                className="text-mini text-muted hover:text-body dark:hover:text-inverted ml-1"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Chart area */}
      <div className={`${CARD} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-heading">{titleText}</h3>
          <div className="flex items-center gap-3">
            <span className="text-mini font-mono text-muted">{filtered.length.toLocaleString()} CVEs in scope</span>
            {viewData && viewData.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  if (!viewData) return;
                  const nonNull = viewData.filter(Boolean) as Record<string, unknown>[];
                  if (nonNull.length === 0) return;
                  const header = Object.keys(nonNull[0]!);
                  const rows = nonNull.map((r) => header.map((h) => String(r[h] ?? '')).join(','));
                  const csv = [header.join(','), ...rows].join('\n');
                  const blob = new Blob([csv], { type: 'text/csv' });
                  downloadBlob(blob, `threat-dashboard-${view}-${new Date().toISOString().slice(0, 10)}.csv`);
                }}
                className="text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 border border-line-2 rounded px-2 py-0.5 transition-colors"
              >
                ↓ CSV
              </button>
            )}
          </div>
        </div>

        {viewData && viewData.length === 0 ? (
          <div className="py-12 text-center text-sm text-muted">No data matches the current filters.</div>
        ) : (
          viewData && (
            <>
              {isOverTime ? (
                <LineView data={viewData as Array<Record<string, string | number>>} title={titleText} isDark={isDark} />
              ) : view === 'exploited' ? (
                <PieView data={viewData as Array<{ name: string; count: number }>} title={titleText} />
              ) : chartType === 'pie' ? (
                <PieView data={viewData as Array<{ name: string; count: number }>} title={titleText} />
              ) : chartType === 'bar' ? (
                <BarView
                  data={viewData as Array<{ name: string; count: number }>}
                  title={titleText}
                  horizontal
                  isDark={isDark}
                />
              ) : chartType === 'column' ? (
                <BarView
                  data={viewData as Array<{ name: string; count: number }>}
                  title={titleText}
                  horizontal={false}
                  isDark={isDark}
                />
              ) : (
                <BarView
                  data={viewData as Array<{ name: string; count: number }>}
                  title={titleText}
                  horizontal
                  isDark={isDark}
                />
              )}
            </>
          )
        )}
      </div>
    </>
  );
}
