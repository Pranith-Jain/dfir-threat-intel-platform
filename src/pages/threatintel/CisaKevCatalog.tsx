import { useCallback, useEffect, useMemo, useState } from 'react';
import { Shield, Search, Download, ExternalLink, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { fetchJson } from '../../lib/fetch-helpers';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { SeverityBadge } from '../../components/SeverityBadge';
import { normalizeSeverity } from '../../components/severity';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

interface KevEntry {
  cve_id: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  date_added: string;
  short_description: string;
  due_date: string;
  known_ransomware_campaign_use: string;
  cvss_score: number | null;
  severity: string | null;
}

interface KevResponse {
  total: number;
  vulnerabilities: KevEntry[];
  catalog_version: string;
  date_released: string;
  severity_stats: Record<string, number>;
  timestamp: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'bg-red-500 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-amber-500 text-white',
  Low: 'bg-emerald-500 text-white',
  '(none)': 'bg-slate-300 dark:bg-surface-300 text-body',
};

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'];

function downloadCsv(entries: KevEntry[]) {
  const header =
    'cve_id,severity,cvss_score,vendor_project,product,vulnerability_name,date_added,due_date,known_ransomware\n';
  const rows = entries.map((e) =>
    [
      e.cve_id,
      e.severity ?? '',
      e.cvss_score?.toString() ?? '',
      e.vendor_project,
      e.product,
      e.vulnerability_name,
      e.date_added,
      e.due_date,
      e.known_ransomware_campaign_use,
    ]
      .map((f) => `"${(f ?? '').replace(/"/g, '""')}"`)
      .join(',')
  );
  const blob = new Blob([header + rows.join('\n')], { type: 'text/csv' });
  downloadBlob(blob, `cisa-kev-${new Date().toISOString().slice(0, 10)}.csv`);
}

function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const bars = SEV_ORDER.map((s) => ({ sev: s, count: counts[s] ?? 0 }))
    .filter((b) => b.count > 0)
    .map((b) => ({ ...b, pct: (b.count / total) * 100 }));
  return (
    <div className="space-y-1">
      <div className="flex h-5 rounded-full overflow-hidden border border-line-1">
        {bars.map((b) => (
          <div
            key={b.sev}
            style={{ width: `${b.pct}%` }}
            className={`${(SEVERITY_COLORS[b.sev] || 'bg-slate-300').split(' ')[0]} flex items-center justify-center text-micro font-bold text-white transition-all`}
            title={`${b.sev}: ${b.count.toLocaleString()} (${b.pct.toFixed(1)}%)`}
          >
            {b.pct > 8 ? b.count.toLocaleString() : ''}
          </div>
        ))}
      </div>
      <div className="flex flex-wrap gap-3 text-xs">
        {bars.map((b) => (
          <span key={b.sev} className="flex items-center gap-1">
            <span
              className={`inline-block w-2.5 h-2.5 rounded-full ${(SEVERITY_COLORS[b.sev] || 'bg-slate-300').split(' ')[0]}`}
            />
            {b.sev} <strong>{b.count.toLocaleString()}</strong> ({b.pct.toFixed(1)}%)
          </span>
        ))}
      </div>
    </div>
  );
}

// The severity pill comes from the shared component. This file's local copy
// coloured Low emerald, which contradicted the ramp documented in
// components/severity.ts: low is intentionally slate, because a low-severity
// finding is still a finding and green reads as "safe/done".

const PAGE_SIZES = [25, 50, 100];

export default function CisaKevCatalog({ bare = false }: { bare?: boolean } = {}): JSX.Element {
  const [data, setData] = useState<KevResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [vendorFilter, setVendorFilter] = useState('');
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [daysFilter, setDaysFilter] = useState<number | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(100);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetchJson<KevResponse>('/api/v1/cisa-kev', { signal });
      setData(r);
    } catch (e) {
      console.error('CisaKevCatalog failed:', errMessage(e));
      if ((e as { name?: string }).name !== 'AbortError') {
        setError(errMessage(e, 'Failed to load KEV catalog.'));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    void load(ctrl.signal);
    return () => ctrl.abort();
  }, [load]);

  useEffect(() => {
    setPage(0);
  }, [query, vendorFilter, ransomwareOnly, daysFilter, severityFilter]);

  const filtered = useMemo(() => {
    let list = data?.vulnerabilities ?? [];
    if (query.trim()) {
      const q = query.toLowerCase();
      list = list.filter(
        (v) =>
          v.cve_id.toLowerCase().includes(q) ||
          v.vulnerability_name.toLowerCase().includes(q) ||
          v.product.toLowerCase().includes(q) ||
          v.vendor_project.toLowerCase().includes(q)
      );
    }
    if (vendorFilter.trim()) {
      const vf = vendorFilter.toLowerCase();
      list = list.filter((v) => v.vendor_project.toLowerCase().includes(vf));
    }
    if (ransomwareOnly) {
      list = list.filter((v) => v.known_ransomware_campaign_use === 'Known');
    }
    if (daysFilter) {
      const cutoff = new Date(Date.now() - daysFilter * 86_400_000).toISOString().slice(0, 10);
      list = list.filter((v) => v.date_added >= cutoff);
    }
    if (severityFilter) {
      list = list.filter((v) => v.severity === severityFilter);
    }
    return list;
  }, [data, query, vendorFilter, ransomwareOnly, daysFilter, severityFilter]);

  const pageCount = Math.ceil(filtered.length / pageSize);

  const pageEntries = useMemo(() => {
    const start = page * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  const vendors = useMemo(() => {
    const s = new Set<string>();
    (data?.vulnerabilities ?? []).forEach((v) => s.add(v.vendor_project));
    return [...s].sort();
  }, [data]);

  const stats = useMemo(() => {
    const all = data?.vulnerabilities ?? [];
    const ransomware = all.filter((v) => v.known_ransomware_campaign_use === 'Known').length;
    const last30 = all.filter(
      (v) => v.date_added >= new Date(Date.now() - 30 * 86_400_000).toISOString().slice(0, 10)
    ).length;
    return { total: all.length, ransomware, last30 };
  }, [data]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of filtered) {
      const s = v.severity || '(none)';
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [filtered]);

  const body = (
    <div className="space-y-4">
      {/* KPI cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { label: 'Total', value: stats.total, color: 'text-heading' },
          { label: 'Ransomware', value: stats.ransomware, color: 'text-red-600 dark:text-red-400' },
          { label: 'Last 30d', value: stats.last30, color: 'text-amber-600 dark:text-amber-400' },
          {
            label: 'With CVSS',
            value: filtered.filter((v) => v.cvss_score != null).length,
            color: 'text-brand-600 dark:text-brand-400',
          },
          { label: 'Showing', value: filtered.length, color: 'text-rose-600 dark:text-rose-400' },
        ].map((kpi) => (
          <div key={kpi.label} className="surface-card p-3">
            <div className="text-xs text-muted">{kpi.label}</div>
            <div className={`text-xl font-bold ${kpi.color}`}>{kpi.value.toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* Severity distribution bar */}
      {filtered.length > 0 && (
        <div className="surface-card p-3">
          <div className="text-xs font-mono text-muted mb-2">Severity Distribution</div>
          <SeverityBar counts={severityCounts} />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search CVE, product, name..."
            className="w-full pl-8 pr-3 py-2 text-sm surface-card text-heading placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-rose-500/50"
          />
        </div>
        <select
          value={vendorFilter}
          onChange={(e) => setVendorFilter(e.target.value)}
          className="text-sm surface-card text-heading px-3 py-2"
        >
          <option value="">All vendors</option>
          {vendors.slice(0, 100).map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <select
          value={daysFilter ?? ''}
          onChange={(e) => setDaysFilter(e.target.value ? Number(e.target.value) : null)}
          className="text-sm surface-card text-heading px-3 py-2"
        >
          <option value="">All time</option>
          <option value="7">Last 7 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
          <option value="365">Last year</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="text-sm surface-card text-heading px-3 py-2"
        >
          <option value="">All severity</option>
          {SEV_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <label className="inline-flex items-center gap-1.5 text-sm text-body cursor-pointer whitespace-nowrap">
          <input
            type="checkbox"
            checked={ransomwareOnly}
            onChange={(e) => setRansomwareOnly(e.target.checked)}
            className="rounded border-line-2"
          />
          <AlertTriangle size={12} className="text-red-500" /> Ransomware only
        </label>
      </div>

      {/* Table */}
      {!bare && filtered.length > 0 && (
        <div className="mb-4">
          <PostAnalysisButton
            title={`CISA KEV Digest \u2014 ${filtered.length} exploited CVEs`}
            description={filtered
              .slice(0, 20)
              .map(
                (e) =>
                  `${e.cve_id} — ${e.vulnerability_name}: ${e.vendor_project} ${e.product}, severity ${e.severity ?? 'n/a'}${e.cvss_score != null ? ` (CVSS ${e.cvss_score.toFixed(1)})` : ''}${e.known_ransomware_campaign_use === 'Known' ? ', ransomware campaign' : ''}`
              )
              .join('\n')}
            source="cisa.gov"
          />
        </div>
      )}
      {!bare && filtered.length > 0 && (
        <AiSummaryCard
          surface="CISA KEV Catalog"
          items={filtered.slice(0, 30).map((e) => ({
            title: `${e.cve_id} — ${e.vulnerability_name}`,
            body: `${e.vendor_project} ${e.product}\nseverity: ${e.severity ?? 'n/a'}${e.cvss_score != null ? ` (CVSS ${e.cvss_score.toFixed(1)})` : ''}${e.known_ransomware_campaign_use === 'Known' ? ' · ransomware campaign use' : ''}`,
            source: 'cisa.gov',
          }))}
          requireAdmin={false}
        />
      )}
      <div className="overflow-x-auto rounded-xl border border-line-1">
        <DataTable
          columns={
            [
              {
                key: 'date_added',
                header: 'Added',
                sortValue: (v: (typeof pageEntries)[number]) => v.date_added,
                render: (v) => <span className="text-muted whitespace-nowrap">{v.date_added}</span>,
              },
              {
                key: 'cve_id',
                header: 'CVE ID',
                sortValue: (v: (typeof pageEntries)[number]) => v.cve_id,
                render: (v) => (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-rose-600 dark:text-rose-400 hover:underline font-mono text-xs transition-colors"
                  >
                    {v.cve_id}
                  </a>
                ),
              },
              {
                key: 'severity',
                header: 'Severity',
                sortValue: (v: (typeof pageEntries)[number]) => v.severity,
                render: (v) => (
                  <span>
                    {/* A missing severity renders nothing. normalizeSeverity
                        falls back to 'low', which would label absent data as
                        a real low-severity finding. */}
                    {v.severity && <SeverityBadge severity={normalizeSeverity(v.severity)} />}
                    {v.cvss_score != null && (
                      <span className="ml-1.5 text-mini text-muted font-mono">{v.cvss_score.toFixed(1)}</span>
                    )}
                  </span>
                ),
              },
              {
                key: 'vendor_project',
                header: 'Vendor',
                sortValue: (v: (typeof pageEntries)[number]) => v.vendor_project,
                render: (v) => <span className="text-body">{v.vendor_project}</span>,
              },
              {
                key: 'product',
                header: 'Product',
                sortValue: (v: (typeof pageEntries)[number]) => v.product,
                render: (v) => <span className="text-body">{v.product}</span>,
              },
              {
                key: 'vulnerability_name',
                header: 'Vulnerability',
                sortValue: (v: (typeof pageEntries)[number]) => v.vulnerability_name,
                render: (v) => <span className="text-muted max-w-xs truncate">{v.vulnerability_name}</span>,
              },
              {
                key: 'due_date',
                header: 'Due',
                sortValue: (v: (typeof pageEntries)[number]) => v.due_date ?? '',
                render: (v) => {
                  const overdue = v.due_date && new Date(v.due_date) < new Date();
                  return (
                    <span
                      className={`whitespace-nowrap ${overdue ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-muted'}`}
                    >
                      {v.due_date}
                    </span>
                  );
                },
              },
              {
                key: 'ransomware',
                header: 'Ransomware',
                render: (v) =>
                  v.known_ransomware_campaign_use === 'Known' ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/30 px-2 py-0.5 rounded-full">
                      <AlertTriangle size={10} /> Yes
                    </span>
                  ) : (
                    <span className="text-xs text-muted">No</span>
                  ),
              },
              {
                key: 'analyze',
                header: '',
                render: (v) => (
                  <PostAnalysisButton
                    title={`${v.cve_id} — ${v.vulnerability_name}`}
                    description={`${v.vendor_project} ${v.product}: ${v.vulnerability_name}. Severity: ${v.severity ?? 'n/a'}${v.cvss_score != null ? ` (CVSS ${v.cvss_score.toFixed(1)})` : ''}${v.known_ransomware_campaign_use === 'Known' ? ' (ransomware campaign use)' : ''}. Due: ${v.due_date ?? 'n/a'}.`}
                    source="cisa.gov"
                    compact
                  />
                ),
              },
            ] as DataTableColumn<(typeof pageEntries)[number]>[]
          }
          rows={pageEntries}
          rowKey={(v) => v.cve_id}
          rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-slate-800/50'}
        />

        {/* Pagination */}
        {filtered.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 border-t border-line-1 text-xs text-muted">
            <span>
              {filtered.length.toLocaleString()} result{filtered.length !== 1 ? 's' : ''}
              {pageSize < filtered.length && ` - page ${page + 1} of ${pageCount} (${pageEntries.length} shown)`}
            </span>
            <div className="flex items-center gap-2">
              <span className="hidden sm:inline">Rows:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(0);
                }}
                className="text-xs rounded-xl border border-line-1 bg-surface-100 text-body px-2 py-1"
              >
                {PAGE_SIZES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
                <option value={filtered.length}>All</option>
              </select>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  disabled={page === 0}
                  onClick={() => setPage(Math.max(0, page - 1))}
                  className="p-1 rounded-xl hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-30 disabled:cursor-not-allowed"
                  aria-label="Previous page"
                >
                  <ChevronLeft size={14} />
                </button>
                <span className="min-w-[4ch] text-center text-body">
                  {page + 1}/{pageCount}
                </span>
                <button
                  type="button"
                  disabled={page >= pageCount - 1}
                  onClick={() => setPage(Math.min(pageCount - 1, page + 1))}
                  className="p-1 rounded-xl hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-30 disabled:cursor-not-allowed"
                  aria-label="Next page"
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
  if (bare) return body;
  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Shield size={28} />}
      title="CISA KEV Catalog"
      maxWidthClass="max-w-6xl"
      description={
        <>
          Known Exploited Vulnerabilities catalog - {stats.total.toLocaleString()} entries, {stats.ransomware} with
          ransomware use, {stats.last30} added in last 30 days.{' '}
          <a
            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            cisa.gov <ExternalLink size={11} className="inline" />
          </a>
        </>
      }
      headerExtra={
        <div className="flex items-center gap-2 mt-2">
          <button
            type="button"
            onClick={() => downloadCsv(filtered)}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 hover:border-emerald-500/70 transition-colors"
          >
            <Download size={12} /> Export CSV ({filtered.length})
          </button>
        </div>
      }
      loading={loading}
      error={error}
      onRetry={() => void load()}
      empty={filtered.length === 0 && !loading}
      emptyMessage="No KEV entries match your filters."
    >
      {body}
    </DataPageLayout>
  );
}
