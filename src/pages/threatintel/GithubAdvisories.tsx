import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataState } from '../../components/DataState';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import HexBrainLink from '../../components/HexBrainLink';
import { Bug, ExternalLink, Package, RefreshCw, Search } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';

interface GhsaAdvisory {
  ghsa_id: string;
  summary: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  identifiers: Array<{ type: string; value: string }>;
  references: string[];
  published_at: string;
  updated_at: string;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    severity: string;
    vulnerable_version_range: string;
    patched_versions: string[];
  }>;
}

interface AdvisoriesResponse {
  total: number;
  advisories: GhsaAdvisory[];
  query: string;
  query_type: string;
  timestamp: string;
  stale?: boolean;
}

interface MetaResponse {
  ok: boolean;
  total: number;
  ageSeconds: number;
  fetchedAt: string;
  meta: {
    source: string;
    fetchedAt: string;
    ok: boolean;
    error?: string;
    upstreamStatus?: number;
    rateLimited?: boolean;
  } | null;
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-rose-500/10', text: 'text-rose-700 dark:text-rose-300', border: 'border-rose-500/30' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-700 dark:text-orange-300', border: 'border-orange-500/30' },
  medium: { bg: 'bg-amber-500/10', text: 'text-amber-700 dark:text-amber-300', border: 'border-amber-500/30' },
  low: { bg: 'bg-slate-500/10', text: 'text-body', border: 'border-slate-500/30' },
};

const ECOSYSTEMS = ['npm', 'pip', 'maven', 'nuget', 'rubygems', 'composer', 'cargo', 'go', 'pub', 'swift'];

export default function GithubAdvisories(): JSX.Element {
  const [query, setQuery] = useState('');
  const [ecoFilter, setEcoFilter] = useState('');
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());
  const [refreshKey, setRefreshKey] = useState(0);

  const params = new URLSearchParams({ recent: 'true' });
  if (ecoFilter) params.set('ecosystem', ecoFilter);
  if (query.trim()) params.set('q', query.trim());

  const url = `/api/v1/github-security?${params}`;

  const { data, loading, error, refetch } = useDataFetch<AdvisoriesResponse>({
    url,
    ttl: 120_000,
    staleWhileRevalidate: true,
  });

  // Meta endpoint tells us the cache age and any upstream error so we can
  // surface "synced Nh ago" + a stale indicator without parsing the body.
  const { data: meta } = useDataFetch<MetaResponse>({
    url: '/api/v1/github-security/recent/meta',
    ttl: 60_000,
  });

  // useDataFetch already re-fetches when `url` changes (the dependency
  // is in its useEffect), so the previous explicit refetch on every
  // filter change was redundant and a rate-limit hazard (it doubled
  // the upstream calls per keystroke). Only `refreshKey` still needs
  // an explicit refetch - it bumps the same URL and asks the cache to
  // be invalidated.
  useEffect(() => {
    if (refreshKey > 0) refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!data) return [];
    if (sevFilter.size === 0) return data.advisories;
    return data.advisories.filter((a) => sevFilter.has(a.severity));
  }, [data, sevFilter]);

  const stats = useMemo(() => {
    if (!data) return { critical: 0, high: 0, medium: 0, low: 0, total: 0, ecosystems: 0 };
    const s = { critical: 0, high: 0, medium: 0, low: 0, total: data.total, ecosystems: 0 };
    const ecoSet = new Set<string>();
    for (const a of data.advisories) {
      s[a.severity as keyof typeof s] = (s[a.severity as keyof typeof s] as number) + 1;
      for (const v of a.vulnerabilities) ecoSet.add(v.package.ecosystem);
    }
    s.ecosystems = ecoSet.size;
    return s;
  }, [data]);

  const ecoBreakdown = useMemo(() => {
    if (!data) return [];
    const counts = new Map<string, number>();
    for (const a of data.advisories) {
      for (const v of a.vulnerabilities) {
        const eco = v.package.ecosystem || 'unknown';
        counts.set(eco, (counts.get(eco) ?? 0) + 1);
      }
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  }, [data]);

  const toggleSev = (s: string) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  return (
    <DataPageLayout
      title="GitHub Advisories Feed"
      icon={<Bug size={28} />}
      backTo="/threatintel"
      description="Live GitHub Security Advisory feed - reviewed vulnerabilities normalized into a CVE-style view."
    >
      {/* Stats */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 mb-5">
        {[
          { label: 'Total', value: stats.total, cls: 'text-slate-500' },
          { label: 'Critical', value: stats.critical, cls: 'text-rose-600 dark:text-rose-400' },
          { label: 'High', value: stats.high, cls: 'text-orange-600 dark:text-orange-400' },
          { label: 'Medium', value: stats.medium, cls: 'text-amber-600 dark:text-amber-400' },
          { label: 'Low', value: stats.low, cls: 'text-slate-500' },
          { label: 'Ecosystems', value: stats.ecosystems, cls: 'text-sky-600 dark:text-sky-400' },
        ].map(({ label, value, cls }) => (
          <div key={label} className="surface-card/50 shadow-e1 p-2.5">
            <div className={`text-mini uppercase tracking-wider mb-0.5 ${cls}`}>{label}</div>
            <div className="text-lg font-bold text-heading">{value}</div>
          </div>
        ))}
      </div>

      <AiSummaryCard
        surface="GitHub Advisories"
        items={(data?.advisories ?? []).slice(0, 15).map((a) => ({
          title: a.summary ?? a.ghsa_id,
          body: `${a.ghsa_id} · ${a.severity} · ${a.published_at?.slice(0, 10) ?? ''} · ${(a.vulnerabilities ?? [])
            .map((v) => `${v.package.ecosystem}/${v.package.name}`)
            .slice(0, 3)
            .join(', ')}`,
          source: a.references?.[0],
        }))}
        requireAdmin={false}
      />

      {/* Severity filter pills */}
      <div className="flex flex-wrap items-center gap-1.5 mb-4">
        <span className="text-xs text-muted mr-1 font-mono">severity:</span>
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => {
          const active = sevFilter.has(s);
          const colors = SEVERITY_COLORS[s]!;
          return (
            <button
              type="button"
              key={s}
              onClick={() => toggleSev(s)}
              className={`px-2 py-1 rounded text-xs font-mono font-medium border flex items-center gap-1 transition ${
                active
                  ? `${colors.bg} ${colors.text} ${colors.border}`
                  : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'
              }`}
            >
              {s}
            </button>
          );
        })}
        <span className="text-xs text-muted ml-3 mr-1 font-mono">ecosystem:</span>
        <select
          value={ecoFilter}
          onChange={(e) => setEcoFilter(e.target.value)}
          className="px-2 py-1 rounded text-xs font-mono border border-line-2 bg-surface-100 text-body focus:outline-none focus:border-rose-500"
        >
          <option value="">All</option>
          {ECOSYSTEMS.map((e) => (
            <option key={e} value={e}>
              {e}
            </option>
          ))}
        </select>
        {(sevFilter.size > 0 || ecoFilter) && (
          <button
            type="button"
            onClick={() => {
              setSevFilter(new Set());
              setEcoFilter('');
            }}
            className="text-xs text-rose-600 dark:text-rose-400 hover:underline ml-2"
          >
            clear filters
          </button>
        )}
      </div>

      {/* Search + refresh */}
      <div className="flex gap-3 mb-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            type="text"
            placeholder="Search package name…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
          />
        </div>
        <button
          type="button"
          onClick={() => {
            setRefreshKey((k) => k + 1);
            refetch();
          }}
          className="px-3 py-2 rounded-xl border border-line-2 text-muted hover:border-line-3 dark:hover:border-slate-600 text-sm flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {data && (
        <div className="flex items-center justify-between text-xs text-muted mb-3 font-mono">
          <span>
            {filtered.length} advisories
            {data.stale && (
              <span className="ml-2 text-amber-600 dark:text-amber-400">
                (stale - upstream temporarily unavailable, showing cached list)
              </span>
            )}
          </span>
          <span>synced {meta?.fetchedAt ? relativeAgo(meta.fetchedAt) : relativeAgo(data.timestamp)}</span>
        </div>
      )}

      {meta && !meta.ok && meta.meta?.error && (
        <p className="text-micro font-mono text-amber-600 dark:text-amber-400 mb-3">
          ! last sync failed: {meta.meta.error}
          {meta.meta.upstreamStatus ? ` (upstream HTTP ${meta.meta.upstreamStatus})` : ''}
        </p>
      )}

      <DataState
        loading={loading}
        error={error}
        empty={filtered.length === 0}
        emptyLabel={
          query.trim() || ecoFilter
            ? `No reviewed advisories match the current filters (${[query.trim(), ecoFilter].filter(Boolean).join(' · ')}).`
            : 'No reviewed advisories available right now. The GitHub Advisory Database feed may be temporarily rate-limited or empty - try the filters or refresh in a minute.'
        }
        onRetry={refetch}
        rows={8}
      >
        <div className="space-y-2">
          {filtered.map((a) => {
            const colors = SEVERITY_COLORS[a.severity] || SEVERITY_COLORS.medium!;
            const cveId = a.identifiers.find((i) => i.type === 'CVE')?.value;
            return (
              <div
                key={a.ghsa_id}
                className={`rounded-xl border border-l-4 ${colors.border} border-l-current bg-surface-100 dark:bg-surface-200/50 p-3 hover:shadow-e1 transition`}
              >
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <a
                        href={`https://github.com/advisories/${a.ghsa_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-semibold font-mono text-heading hover:text-rose-600 dark:hover:text-rose-400 flex items-center gap-1 transition-colors"
                      >
                        {a.ghsa_id} <ExternalLink className="w-3 h-3" />
                      </a>
                      <span
                        className={`px-1.5 py-0.5 text-micro font-mono uppercase rounded border ${colors.bg} ${colors.text} ${colors.border}`}
                      >
                        {a.severity}
                      </span>
                      {cveId && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                        >
                          {cveId}
                        </a>
                      )}
                      {cveId && (
                        <HexBrainLink
                          cve={cveId}
                          className="px-1.5 py-0.5 text-micro font-mono rounded border border-orange-500/30 text-orange-600 dark:text-orange-300 hover:bg-orange-500/10 transition-colors inline-flex items-center gap-1"
                        />
                      )}
                    </div>
                    <p className="text-xs text-body leading-relaxed mb-1.5">{a.summary}</p>
                    <div className="flex items-center gap-2 flex-wrap text-mini text-muted">
                      {a.vulnerabilities.map((v, i) => (
                        <span
                          key={i}
                          className="flex items-center gap-1 px-1.5 py-0.5 rounded border border-line-1 bg-surface-200/50 font-mono"
                        >
                          <Package className="w-2.5 h-2.5" /> {v.package.ecosystem}/{v.package.name}
                          {v.vulnerable_version_range && (
                            <span className="text-muted">({v.vulnerable_version_range})</span>
                          )}
                        </span>
                      ))}
                      <span>{relativeAgo(a.published_at)}</span>
                      {a.references.length > 0 && (
                        <a
                          href={a.references[0]}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-rose-600 dark:text-rose-400 hover:underline flex items-center gap-0.5 transition-colors"
                        >
                          <ExternalLink className="w-2.5 h-2.5" /> ref
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </DataState>

      {/* Ecosystem breakdown */}
      {ecoBreakdown.length > 0 && (
        <div className="mt-8 surface-card/50 p-4">
          <h3 className="text-sm font-semibold text-heading mb-3">Ecosystem Breakdown</h3>
          <div className="space-y-1.5">
            {ecoBreakdown.map(([eco, count]) => (
              <div key={eco} className="flex items-center gap-2 text-xs">
                <span className="font-mono text-body w-24">{eco}</span>
                <div className="flex-1 h-2 bg-surface-300 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-rose-500 rounded-full"
                    style={{ width: `${Math.min(100, (count / Math.max(...ecoBreakdown.map(([, c]) => c))) * 100)}%` }}
                  />
                </div>
                <span className="font-mono text-muted w-8 text-right">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
        Source: GitHub Advisory Database via Worker API
      </div>
    </DataPageLayout>
  );
}
