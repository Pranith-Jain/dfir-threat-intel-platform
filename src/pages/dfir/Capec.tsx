import { useEffect, useMemo, useState } from 'react';
import { Crosshair, ExternalLink, RefreshCw } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';

interface CapecPattern {
  slug: string;
  capecId: string;
  name: string;
  abstraction: string;
  status: string;
  likelihood: string;
  severity: string;
  domains: string[];
  description: string;
  cweIds: string[];
  attackIds: string[];
  url: string;
}

interface CapecResponse {
  count: number;
  total: number;
  patterns: CapecPattern[];
}

export default function Capec(): JSX.Element {
  const [data, setData] = useState<CapecResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'Stable' | 'Draft' | 'Deprecated'>('all');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();

    setLoading(true);
    setError(null);
    fetch('/api/v1/capec?limit=200', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => (r.ok ? (r.json() as Promise<CapecResponse>) : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => {
        if (cancelled) return;
        setData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message ?? 'fetch failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.patterns.filter((p) => {
      if (statusFilter !== 'all' && p.status !== statusFilter) return false;
      if (!q) return true;
      const hay =
        `${p.capecId} ${p.name} ${p.description} ${p.cweIds.join(' ')} ${p.attackIds.join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [data, query, statusFilter]);

  return (
    <DataPageLayout
      backTo="/dfir"
      backLabel="back to dfir"
      icon={<Crosshair className="h-6 w-6" />}
      title="MITRE CAPEC — Attack Patterns"
      description={`${data?.total ?? 615} attack patterns with CWE weakness and ATT&CK technique cross-references. Pivot from a CWE (e.g. CWE-79) to how attackers exploit it, or from a pattern to its mitigations.`}
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" /> refresh
          </button>
          {data && (
            <span className="rounded border border-line-2 px-2 py-1 text-muted font-mono">{data.total} patterns</span>
          )}
        </div>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      empty={!loading && !data}
      emptyMessage="No CAPEC data available."
      maxWidthClass="max-w-6xl"
    >
      {data && (
        <>
          <section className="surface-card p-4 mb-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative flex-1">
                <Crosshair className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={`Search ${data.total} patterns (try “CWE-79”)…`}
                  className="w-full rounded-xl border border-line-2 bg-surface-100 py-2 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
                />
              </div>
              <div className="flex gap-2">
                {(['all', 'Stable', 'Draft', 'Deprecated'] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setStatusFilter(v)}
                    className={`text-mini font-mono rounded border px-2.5 py-1 transition-colors ${
                      statusFilter === v
                        ? 'border-rose-500/50 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400'
                        : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </div>
          </section>

          <section className="grid gap-3 sm:grid-cols-2">
            {filtered.map((p) => (
              <article key={p.slug} className="surface-card p-3.5">
                <div className="flex items-start justify-between gap-2">
                  <a
                    href={p.url}
                    target="_blank"
                    rel="noreferrer"
                    className="font-medium text-heading hover:text-rose-500 text-sm inline-flex items-center gap-1"
                  >
                    {p.capecId} — {p.name} <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                  <span className="shrink-0 text-micro font-mono text-muted">{p.abstraction}</span>
                </div>
                {p.description && <p className="mt-1 text-xs text-muted">{p.description}</p>}
                <div className="mt-2 flex flex-wrap items-center gap-1.5 text-micro font-mono text-muted">
                  {p.cweIds.slice(0, 5).map((c) => (
                    <span key={c} className="rounded border border-line-2 px-1.5 py-0.5">
                      {c}
                    </span>
                  ))}
                  {p.attackIds.slice(0, 3).map((t) => (
                    <span key={t} className="text-purple-600 dark:text-purple-400">
                      {t}
                    </span>
                  ))}
                  {p.likelihood && <span className="px-1">likelihood: {p.likelihood}</span>}
                </div>
              </article>
            ))}
          </section>
          {filtered.length === 0 && (
            <p className="mt-6 text-center text-sm text-muted">No patterns match the current filters.</p>
          )}
          <p className="mt-6 text-center text-micro font-mono text-muted">
            source: github.com/mitre/cti CAPEC STIX 2.0 · summaries only
          </p>
        </>
      )}
    </DataPageLayout>
  );
}
