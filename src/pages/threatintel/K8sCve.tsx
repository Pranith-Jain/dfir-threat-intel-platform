import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Bug, GitBranch } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface K8sCve {
  id: string;
  title: string;
  url: string;
  published: string;
  summary: string;
  cve_ids: string[];
  issue_url: string;
  status: string;
}
interface K8sCveResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  count: number;
  total: number;
  facets: {
    statuses: Record<string, number>;
  };
  items: K8sCve[];
  stale?: boolean;
  upstream_error?: string;
}

/** Only render http(s) links - the urls come from an untrusted upstream, so
 *  never let a `javascript:`/`data:` URL reach an href. */
function safeHref(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch (_catchErr) {
    console.error('safeHref failed:', errMessage(_catchErr));
    return null;
  }
}

const STATUS_TONE: Record<string, string> = {
  fixed: 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400',
  open: 'border-rose-500/50 text-rose-600 dark:text-rose-400',
  unfixed: 'border-rose-500/50 text-rose-600 dark:text-rose-400',
  pending: 'border-amber-500/50 text-amber-600 dark:text-amber-400',
};

function chip(active: boolean): string {
  return `text-xs font-mono px-2.5 py-1 rounded border transition-colors ${
    active
      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
  }`;
}

function fmtDate(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso.slice(0, 10) : d.toISOString().slice(0, 10);
}

export default function K8sCve({ bare = false }: { bare?: boolean } = {}): JSX.Element {
  const [data, setData] = useState<K8sCveResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState('all');

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/k8s-cve', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<K8sCveResponse>;
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

  const statuses = useMemo(() => Object.entries(data?.facets.statuses ?? {}).sort((a, b) => b[1] - a[1]), [data]);

  const filtered = useMemo(() => {
    const list = data?.items ?? [];
    const sorted = [...list].sort((a, b) => (b.published || '').localeCompare(a.published || ''));
    return sorted.filter((i) => status === 'all' || i.status === status);
  }, [data, status]);

  const description = (
    <>
      The official Kubernetes CVE feed - core-Kubernetes vulnerabilities (kube-apiserver, kubelet, CSI/CNI, and
      ecosystem components) published by the Kubernetes Security Response Committee. Data:{' '}
      <a
        href="https://kubernetes.io/docs/reference/issues-security/official-cve-feed/"
        target="_blank"
        rel="noopener noreferrer"
        className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
      >
        kubernetes.io
      </a>{' '}
      (CC-BY-4.0). Each CVE chip pivots into the platform CVE lookup; links go to the cve.org record and the upstream
      GitHub issue.
    </>
  );

  const headerExtra =
    data && !error ? (
      <div className="space-y-2">
        {data.stale && (
          <p className="text-micro font-mono text-amber-600 dark:text-amber-400">
            showing cached data (upstream temporarily unavailable)
          </p>
        )}
        <div className="flex flex-wrap gap-1.5">
          <button type="button" onClick={() => setStatus('all')} className={chip(status === 'all')}>
            All <span className="opacity-60">· {data.total}</span>
          </button>
          {statuses.map(([name, n]) => (
            <button type="button" key={name} onClick={() => setStatus(name)} className={chip(status === name)}>
              {name} <span className="opacity-60">· {n}</span>
            </button>
          ))}
        </div>
      </div>
    ) : undefined;

  const body = (
    <>
      <p className="text-base leading-relaxed text-muted max-w-3xl mb-6">{description}</p>
      {headerExtra}
      <div className="grid gap-3 lg:grid-cols-2">
        {filtered.slice(0, 600).map((cve) => {
          const recordHref = safeHref(cve.url);
          const issueHref = safeHref(cve.issue_url);
          return (
            <div key={cve.id} className="rounded-xl border border-line-1 bg-surface-200 p-3">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-semibold text-sm text-heading leading-snug">
                  {recordHref ? (
                    <a
                      href={recordHref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                    >
                      {cve.title} <ExternalLink size={12} className="inline align-baseline opacity-60" />
                    </a>
                  ) : (
                    cve.title
                  )}
                </h3>
                {cve.status && (
                  <span
                    className={`shrink-0 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                      STATUS_TONE[cve.status.toLowerCase()] ?? 'border-slate-400/50 text-slate-500'
                    }`}
                  >
                    {cve.status}
                  </span>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
                {cve.cve_ids.map((id) => (
                  <Link
                    key={id}
                    to={`/dfir/cve?id=${encodeURIComponent(id)}`}
                    className="text-micro font-mono px-1.5 py-0.5 rounded border border-rose-500/40 text-rose-600 dark:text-rose-400 hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400"
                    title="Pivot to CVE lookup"
                  >
                    {id} →
                  </Link>
                ))}
                {cve.published && (
                  <span className="text-micro font-mono text-muted ml-auto">{fmtDate(cve.published)}</span>
                )}
              </div>

              {cve.summary && cve.summary !== cve.title && (
                <p className="text-xs text-muted mt-2 leading-relaxed">{cve.summary}</p>
              )}

              {issueHref && (
                <div className="mt-2 pt-2 border-t border-line-1">
                  <a
                    href={issueHref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 transition-colors"
                  >
                    <GitBranch size={12} /> tracking issue
                  </a>
                </div>
              )}
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
          - {data.license} · {data.total} CVEs
        </p>
      )}
    </>
  );

  if (bare) return body;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Bug size={28} />}
      title="Kubernetes Official CVE Feed"
      description={description}
      headerExtra={headerExtra}
      loading={loading}
      error={error}
      empty={!loading && !error && !!data && filtered.length === 0}
      emptyMessage="No Kubernetes CVEs match the filter."
    >
      {body}
    </DataPageLayout>
  );
}
