import { useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { ExternalLink, Flame, Loader2, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { errMessage } from '../../lib/log';

/**
 * CveNow — cve.now aggregate vulnerability feed explorer
 * (https://cve.now, github.com/sazabi/cve.now; entry summaries CC-BY 4.0).
 *
 * cve.now merges CVE List, NVD, CISA KEV, GitHub Advisory Database, OSV,
 * ENISA EUVD, FIRST EPSS, Exploit-DB, Metasploit, Nuclei and PoC-in-GitHub
 * into one deduplicated entry per vulnerability. The newest ~240 entries are
 * replicated locally through the platform API:
 *
 *   GET /api/v1/threat-intel/cve-now           → index + counts + source health
 *   GET /api/v1/threat-intel/cve-now/entries   → filtered list
 *   GET /api/v1/threat-intel/cve-now/entries/:id → one entry
 */

interface CveNowEntry {
  id: string;
  title: string | null;
  publishedAt: string | null;
  cvss: number | null;
  severity: string;
  kev: boolean;
  hasFix: boolean;
  product: string | null;
}

interface CveNowResponse {
  source: string;
  sourceUrl: string;
  repoUrl: string;
  syncedAt: string;
  counts: {
    entries: number;
    kev: number;
    withFix: number;
    bySeverity: Record<string, number>;
  };
  topProducts: Array<{ product: string; count: number }>;
  sourcesHealth: {
    checkedAt: string | null;
    sources: Record<string, { ok: boolean; at: string }> | null;
  } | null;
}

interface ListResult {
  total: number;
  returned: number;
  entries: CveNowEntry[];
}

const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  HIGH: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  MEDIUM: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  LOW: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  NONE: 'border-slate-400/40 bg-slate-400/10 text-muted',
  UNKNOWN: 'border-line-2 bg-surface-100 text-muted',
};

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';

function fmt(n: number | null | undefined): string {
  return typeof n === 'number' ? n.toLocaleString() : '—';
}

function severityCls(sev: string): string {
  // SEVERITY_CLS keys are dynamic (severity bands from upstream), so indexed
  // access is not exhaustively typeable under noUncheckedIndexedAccess.
  return (
    SEVERITY_CLS[sev.toUpperCase()] ??
    SEVERITY_CLS['UNKNOWN' as keyof typeof SEVERITY_CLS] ??
    'border-line-2 bg-surface-100 text-muted'
  );
}

export default function CveNow(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<CveNowResponse>({
    url: '/api/v1/threat-intel/cve-now',
    ttl: 300_000,
  });

  // The index endpoint carries counts + health only; the rows live on the
  // entries endpoint. Fetch both in parallel so the page skims immediately.
  const {
    data: listData,
    loading: listLoading,
    error: listFetchError,
  } = useDataFetch<ListResult>({
    url: '/api/v1/threat-intel/cve-now/entries?limit=240',
    ttl: 120_000,
  });

  const [q, setQ] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [withFixOnly, setWithFixOnly] = useState(false);
  const [filtered, setFiltered] = useState<ListResult | null>(null);
  const [filterError, setFilterError] = useState<string | null>(null);
  const [listing, setListing] = useState(false);

  /** Any active filter → swap the default list for the filtered query. */
  const hasFilter = q.trim().length > 0 || kevOnly || withFixOnly;

  async function runList() {
    setListing(true);
    setFilterError(null);
    try {
      const params = new URLSearchParams();
      if (q.trim()) params.set('q', q.trim());
      if (kevOnly) params.set('kev', 'true');
      if (withFixOnly) params.set('has-fix', 'true');
      params.set('limit', '240');
      const res = await fetch(`/api/v1/threat-intel/cve-now/entries?${params.toString()}`, {
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFiltered((await res.json()) as ListResult);
    } catch (e) {
      setFilterError(errMessage(e));
    } finally {
      setListing(false);
    }
  }

  const listError = filterError ?? listFetchError;

  /** Filtered when a filter is applied, else the default replicated window. */
  const shownResult = hasFilter ? filtered : listData;

  const resultNote =
    hasFilter && filtered ? (
      <p className="mt-2 text-micro text-muted">
        {fmt(shownResult?.returned ?? 0)} of {fmt(filtered.total)} replicated entries match.
      </p>
    ) : shownResult && data ? (
      <p className="mt-2 text-micro text-muted">
        Newest {fmt(shownResult.entries.length)} upstream entries replicated. Apply a filter to narrow the wire.
      </p>
    ) : null;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Flame size={28} />}
      title="CVE.now Wire"
      description="Free, public, keyless vulnerability feed that merges CVE List, NVD, CISA KEV, GitHub Advisories, OSV, ENISA EUVD, FIRST EPSS, Exploit-DB, Metasploit, Nuclei and PoC-in-GitHub into ONE deduplicated entry per CVE — with severity, fix availability and affected product in a single row."
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      {/* Stats band */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        {[
          ['Entries replicated', fmt(data?.counts.entries)],
          ['KEV-listed', fmt(data?.counts.kev)],
          ['With known fix', fmt(data?.counts.withFix)],
          [
            'Upstream sources',
            fmt(data?.sourcesHealth?.sources ? Object.keys(data.sourcesHealth.sources).length : null),
          ],
        ].map(([label, value]) => (
          <div key={label} className="surface-card p-4 text-center">
            <div className="text-2xl font-display font-bold text-heading tabular-nums">{value}</div>
            <div className="text-micro font-mono uppercase tracking-wider text-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Upstream source health */}
      {data?.sourcesHealth?.sources && (
        <section className="surface-card p-5 mb-6">
          <h2 className="text-lg font-bold text-heading mb-3">
            Upstream source health
            {data.sourcesHealth.checkedAt && (
              <span className="text-sm font-normal text-muted ml-2">
                checked {relativeAgo(data.sourcesHealth.checkedAt)}
              </span>
            )}
          </h2>
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.sourcesHealth.sources).map(([name, s]) => (
              <span
                key={name}
                className={`inline-flex items-center gap-1.5 text-micro font-mono px-1.5 py-0.5 rounded border ${
                  s.ok
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                }`}
                title={`last poll: ${s.at}`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${s.ok ? 'bg-emerald-500' : 'bg-rose-500'}`}
                  aria-hidden="true"
                />
                {name}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* Filter + list */}
      <section className="surface-card p-5 mb-6">
        <h2 className="text-lg font-bold text-heading mb-3">Browse the wire</h2>
        <div className="flex flex-wrap gap-2 items-center">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void runList()}
            placeholder="keyword in id / title / product — e.g. WordPress"
            className={`${inputCls} flex-1 min-w-[200px]`}
            aria-label="Keyword filter for CVE.now entries"
          />
          <label className="text-sm text-body inline-flex items-center gap-1.5 whitespace-nowrap">
            <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
            KEV only
          </label>
          <label className="text-sm text-body inline-flex items-center gap-1.5 whitespace-nowrap">
            <input type="checkbox" checked={withFixOnly} onChange={(e) => setWithFixOnly(e.target.checked)} />
            has fix
          </label>
          <button
            onClick={() => void runList()}
            disabled={listing}
            className="px-4 py-2 bg-brand-600 text-on-fill rounded-xl text-sm font-medium hover:bg-brand-500 disabled:opacity-50 whitespace-nowrap inline-flex items-center gap-2"
          >
            {listing ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            Apply
          </button>
        </div>

        {listError && (
          <p role="alert" className="mt-3 text-sm text-rose-600 dark:text-rose-400">
            Fetch failed: {listError}
          </p>
        )}

        {shownResult === null && !loading && !listLoading && !listError && (
          <p className="mt-4 text-sm text-muted">No entries to show.</p>
        )}

        {shownResult && shownResult.entries.length === 0 && (
          <p className="mt-4 text-sm text-muted">No entries match the filter.</p>
        )}

        {shownResult && shownResult.entries.length > 0 && (
          <ul className="mt-4 divide-y divide-line-1 max-h-[560px] overflow-y-auto">
            {shownResult.entries.map((e) => (
              <li key={e.id} className="py-3">
                <div className="flex flex-wrap items-center gap-2">
                  {(() => {
                    const commonCls = 'text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border';
                    return (
                      <>
                        <span className={`${commonCls} ${severityCls(e.severity)}`}>{e.severity}</span>
                        {typeof e.cvss === 'number' && (
                          <span
                            className="text-micro font-mono text-muted"
                            title="CVSS score from upstream aggregation"
                          >
                            CVSS {e.cvss}
                          </span>
                        )}
                        {e.kev && (
                          <span
                            className={`${commonCls} border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300`}
                          >
                            KEV
                          </span>
                        )}
                        {e.hasFix && (
                          <span
                            className="text-micro font-mono inline-flex items-center gap-1 border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 rounded"
                            title="Upstream records a known fix version"
                          >
                            <ShieldCheck size={10} aria-hidden="true" /> fix
                          </span>
                        )}
                        {e.product && (
                          <span className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 bg-surface-100 text-muted truncate max-w-[240px]">
                            {e.product}
                          </span>
                        )}
                      </>
                    );
                  })()}
                </div>
                <a
                  href={`https://cve.now/${e.id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block mt-1 text-sm font-semibold text-heading hover:text-brand-600 dark:hover:text-brand-400 truncate"
                >
                  {e.id}: {e.title ?? '—'}
                </a>
                <div className="text-micro text-muted mt-0.5">
                  published {e.publishedAt ? relativeAgo(e.publishedAt) : '—'}
                </div>
              </li>
            ))}
          </ul>
        )}
        {resultNote}
      </section>

      {/* Top products */}
      {data && data.topProducts.length > 0 && (
        <section className="surface-card p-5 mb-6">
          <h2 className="text-lg font-bold text-heading mb-3">Most affected products (in this window)</h2>
          <ul className="space-y-2">
            {data.topProducts.map((p) => {
              const max = data.topProducts[0]?.count ?? 1;
              const pct = Math.round((p.count / max) * 100);
              return (
                <li key={p.product} className="flex items-center gap-3 text-sm">
                  <span className="w-64 shrink-0 truncate font-mono text-body" title={p.product}>
                    {p.product}
                  </span>
                  <span className="flex-1 h-2 rounded-full bg-surface-200 overflow-hidden">
                    <span
                      className="block h-full rounded-full bg-brand-500"
                      style={{ width: `${Math.max(4, pct)}%` }}
                    />
                  </span>
                  <span className="text-micro font-mono text-muted tabular-nums w-10 text-right">{p.count}</span>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Feed info footer */}
      <footer className="pt-6 border-t border-line-1 text-sm text-muted">
        <p className="flex items-start gap-1.5">
          <ShieldAlert size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
          The newest ~240 upstream entries are replicated; severity bands fall back to the CVSS band when upstream
          states none. One entry per CVE — upstream deduplicates across its sources, so nothing here is double-counted.
        </p>
        <p className="mt-2">
          Synced <strong>{data ? relativeAgo(data.syncedAt) : '—'}</strong> · entry summaries CC-BY 4.0 ·{' '}
          <a
            href="https://cve.now"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
          >
            upstream site <ExternalLink size={12} />
          </a>{' '}
          ·{' '}
          <a
            href="https://github.com/sazabi/cve.now"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
          >
            docs <ExternalLink size={12} />
          </a>{' '}
          ·{' '}
          <a
            href="https://cve.now/feed"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
          >
            RSS / Atom / JSON Feed <ExternalLink size={12} />
          </a>
        </p>
      </footer>
    </DataPageLayout>
  );
}
