import { useEffect, useMemo, useState } from 'react';
import { GitBranch, ExternalLink, Loader2, X } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { StixObjectTable, StixRelationshipGraph, type StixBundle } from '../../components/StixBundleViewer';
import { errMessage } from '../../lib/log';

interface FlowEntry {
  name: string;
  filename: string;
  size: number;
  sha: string;
  html_url: string;
  afb_url: string;
  stix_url: string;
}
interface ManifestResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  count: number;
  total: number;
  flows: FlowEntry[];
  stale?: boolean;
  upstream_error?: string;
}
interface FlowBundleResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  flow: {
    name: string;
    filename: string;
    html_url: string;
    afb_url: string;
    stix_url: string;
  };
  bundle: StixBundle;
}

/** Only render http(s) links - every URL here comes from an untrusted upstream
 *  (GitHub Contents API + a derived Pages URL), so never let a
 *  `javascript:`/`data:` URL reach an href. */
function safeHref(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch (_catchErr) {
    console.error('safeHref failed:', errMessage(_catchErr));
    return null;
  }
}

function fmtSize(bytes: number): string {
  if (!bytes) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function AttackFlowLibrary(): JSX.Element {
  const [data, setData] = useState<ManifestResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  // On-demand single-flow view state.
  const [activeFlow, setActiveFlow] = useState<string | null>(null);
  const [flowData, setFlowData] = useState<FlowBundleResponse | null>(null);
  const [flowLoading, setFlowLoading] = useState(false);
  const [flowError, setFlowError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/attack-flow-library', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<ManifestResponse>;
      })
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (!cancelled && e.name !== 'AbortError') setError(e.message ?? 'unknown');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  // Fetch exactly ONE STIX bundle when a flow is opened (on demand).
  useEffect(() => {
    if (!activeFlow) {
      setFlowData(null);
      setFlowError(null);
      return;
    }
    let cancelled = false;
    const ctrl = new AbortController();
    setFlowLoading(true);
    setFlowError(null);
    setFlowData(null);
    fetch(`/api/v1/attack-flow-library?flow=${encodeURIComponent(activeFlow)}`, {
      signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<FlowBundleResponse>;
      })
      .then((d) => {
        if (!cancelled) setFlowData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (!cancelled && e.name !== 'AbortError') setFlowError(e.message ?? 'unknown');
      })
      .finally(() => {
        if (!cancelled) setFlowLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [activeFlow]);

  const filtered = useMemo(() => {
    const list = data?.flows ?? [];
    const q = query.trim().toLowerCase();
    return q ? list.filter((f) => f.name.toLowerCase().includes(q)) : list;
  }, [data, query]);

  const description = (
    <>
      Real-incident attack-flows from the{' '}
      <a
        href="https://center-for-threat-informed-defense.github.io/attack-flow/"
        target="_blank"
        rel="noopener noreferrer"
        className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
      >
        Center for Threat-Informed Defense
      </a>{' '}
      Attack Flow corpus - Black Basta, Conti, NotPetya, SolarWinds, REvil, Equifax, Target, Uber, and more, each
      modeled as a sequence of ATT&amp;CK techniques and published as a STIX 2.1 bundle. This view lists the corpus from
      a single GitHub listing; opening a flow fetches just that one bundle on demand and renders its STIX objects +
      relationship graph. Apache-2.0; attribution to the Center for Threat-Informed Defense.
    </>
  );

  const headerExtra =
    data && !error ? (
      <div className="space-y-2">
        {data.stale && (
          <p className="text-micro font-mono text-amber-600 dark:text-amber-400">
            ! showing cached listing (upstream temporarily unavailable)
          </p>
        )}
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={`Filter ${data.total} flows…`}
          className="w-full max-w-sm text-sm font-mono px-3 py-1.5 rounded border border-line-2 bg-surface-100 text-heading focus:outline-none focus:border-rose-500/60"
        />
      </div>
    ) : undefined;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<GitBranch size={28} />}
      title="Attack Flow Library"
      description={description}
      headerExtra={headerExtra}
      loading={loading}
      error={error}
      empty={!loading && !error && !!data && filtered.length === 0}
      emptyMessage="No flows match the filter."
    >
      {/* On-demand single-flow STIX viewer */}
      {activeFlow && (
        <div className="mb-6 rounded-xl border border-rose-500/30 bg-rose-500/5 p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-heading">{activeFlow}</h2>
              {flowData && (
                <p className="text-micro font-mono text-muted mt-0.5">
                  {flowData.bundle.objects.length} STIX objects · spec{' '}
                  {(flowData.bundle as { spec_version?: string }).spec_version || '2.1'}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={() => setActiveFlow(null)}
              className="shrink-0 inline-flex items-center gap-1 text-micro font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
            >
              <X size={12} /> close
            </button>
          </div>

          {flowLoading && (
            <div className="flex items-center justify-center py-10" role="status" aria-live="polite">
              <Loader2 size={20} className="animate-spin text-muted" aria-hidden="true" />
              <span className="sr-only">Loading flow…</span>
            </div>
          )}

          {flowError && (
            <p className="mt-3 text-sm text-rose-600 dark:text-rose-400">
              Could not load this flow ({flowError}). The STIX export may be missing - try the raw source on GitHub.
            </p>
          )}

          {flowData && (
            <>
              {(() => {
                const links: Array<{ label: string; href: string | null }> = [
                  { label: 'View on GitHub', href: safeHref(flowData.flow.html_url) },
                  { label: 'STIX 2.1 bundle (.json)', href: safeHref(flowData.flow.stix_url) },
                  { label: 'Attack Flow Builder (.afb)', href: safeHref(flowData.flow.afb_url) },
                ];
                return (
                  <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
                    {links.map((l) =>
                      l.href ? (
                        <a
                          key={l.label}
                          href={l.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 transition-colors"
                        >
                          {l.label} <ExternalLink size={10} className="opacity-60" />
                        </a>
                      ) : null
                    )}
                  </div>
                );
              })()}
              <StixRelationshipGraph bundle={flowData.bundle} />
              <StixObjectTable bundle={flowData.bundle} />
            </>
          )}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {filtered.map((flow) => {
          const ghHref = safeHref(flow.html_url);
          const isActive = activeFlow === flow.name;
          return (
            <div
              key={flow.sha || flow.name}
              className={`rounded-xl border p-3 transition-colors ${
                isActive ? 'border-rose-500/60 bg-rose-500/5' : 'border-line-1 bg-slate-50 dark:bg-input-200'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-semibold text-sm text-heading leading-snug">{flow.name}</h3>
                {flow.size > 0 && (
                  <span className="shrink-0 text-micro font-mono text-muted">{fmtSize(flow.size)}</span>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-3 pt-2 border-t border-line-1">
                <button
                  type="button"
                  onClick={() => setActiveFlow(isActive ? null : flow.name)}
                  className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline"
                >
                  {isActive ? 'hide flow' : 'view flow →'}
                </button>
                {ghHref && (
                  <a
                    href={ghHref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-micro font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1 transition-colors"
                    title="View .afb source on GitHub"
                  >
                    GitHub <ExternalLink size={10} className="opacity-60" />
                  </a>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {data && (
        <p className="mt-6 text-micro font-mono text-muted text-center">
          Data:{' '}
          <a
            href={data.source_url}
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            {data.source}
          </a>{' '}
          - {data.license} · {data.total} flows · manifest + on-demand (no per-load fan-out)
        </p>
      )}
    </DataPageLayout>
  );
}
