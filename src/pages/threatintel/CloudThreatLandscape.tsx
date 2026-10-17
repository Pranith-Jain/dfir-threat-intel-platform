import { useEffect, useMemo, useState } from 'react';
import { Cloud, ExternalLink, Target } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';

interface ExternalRef {
  source_name: string;
  url: string;
}
interface Incident {
  id: string;
  name: string;
  type: string;
  description: string;
  objective: string;
  created: string;
  modified: string;
  labels: string[];
  external_refs: ExternalRef[];
}
interface CloudResponse {
  source: string;
  source_url: string;
  license: string;
  spec_version: string;
  bundle_id: string;
  generated_at: string;
  count: number;
  total: number;
  facets: {
    types: Record<string, number>;
    labels: Record<string, number>;
  };
  incidents: Incident[];
  stale?: boolean;
  upstream_error?: string;
}

/** Only render http(s) links - the external_references urls come from an
 *  untrusted upstream STIX bundle, so never let a `javascript:`/`data:` URL
 *  reach an href. */
function safeHref(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch (_catchErr) {
    console.error('safeHref failed:', errMessage(_catchErr));
    return null;
  }
}

const TYPE_TONE: Record<string, string> = {
  campaign: 'border-rose-500/50 text-rose-600 dark:text-rose-400 bg-rose-500/10',
  'intrusion-set': 'border-violet-500/50 text-violet-600 dark:text-violet-400 bg-violet-500/10',
  'threat-actor': 'border-orange-500/50 text-orange-600 dark:text-orange-400 bg-orange-500/10',
  report: 'border-sky-500/50 text-sky-600 dark:text-sky-400 bg-sky-500/10',
};

function chip(active: boolean): string {
  return `text-xs font-mono px-2.5 py-1 rounded border transition-colors ${
    active
      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
  }`;
}

function fmtDate(iso: string): string {
  return iso ? iso.slice(0, 10) : '';
}

export default function CloudThreatLandscape(): JSX.Element {
  const [data, setData] = useState<CloudResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [type, setType] = useState('all');

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/cloud-threat-landscape', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<CloudResponse>;
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

  const types = useMemo(() => Object.entries(data?.facets.types ?? {}).sort((a, b) => b[1] - a[1]), [data]);

  const filtered = useMemo(() => {
    const list = data?.incidents ?? [];
    return list.filter((i) => type === 'all' || i.type === type);
  }, [data, type]);

  const description = (
    <>
      Cloud-focused threat campaigns, intrusion sets, and actors curated by{' '}
      <a
        href="https://www.wiz.io/feed/cloud-threats-landscape"
        target="_blank"
        rel="noopener noreferrer"
        className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
      >
        Wiz Research
      </a>{' '}
      and published as a STIX 2.1 bundle - campaign objective, timeline, and the original Wiz blog reference per entry.
      Free to display and cite with attribution to Wiz Research.
    </>
  );

  const headerExtra =
    data && !error ? (
      <div className="space-y-2">
        {data.stale && (
          <p className="text-micro font-mono text-amber-600 dark:text-amber-400">
            ! showing cached data (upstream temporarily unavailable)
          </p>
        )}
        <div className="flex flex-wrap gap-1.5">
          <button type="button" onClick={() => setType('all')} className={chip(type === 'all')}>
            All types <span className="opacity-60">· {data.total}</span>
          </button>
          {types.map(([name, n]) => (
            <button type="button" key={name} onClick={() => setType(name)} className={chip(type === name)}>
              {name} <span className="opacity-60">· {n}</span>
            </button>
          ))}
        </div>
      </div>
    ) : undefined;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Cloud size={28} />}
      title="Wiz Cloud Threat Landscape"
      description={description}
      headerExtra={headerExtra}
      loading={loading}
      error={error}
      empty={!loading && !error && !!data && filtered.length === 0}
      emptyMessage="No entries match the filter."
    >
      {/* Page-level AI summary across the visible cloud threat entries.
          Public (requireAdmin={false}) so every visitor sees it. */}
      {filtered.length > 0 && (
        <AiSummaryCard
          surface="Wiz Cloud Threat Landscape"
          items={filtered.slice(0, 30).map((inc) => ({
            title: inc.name,
            body: `${inc.type} · ${inc.objective} · ${inc.description}`,
            source: inc.type,
          }))}
          requireAdmin={false}
        />
      )}
      <div className="grid gap-3 lg:grid-cols-2">
        {filtered.slice(0, 600).map((inc) => {
          const primaryRef = inc.external_refs.map((r) => safeHref(r.url)).find((h): h is string => Boolean(h));
          return (
            <div key={inc.id} className="rounded-xl border border-line-1 bg-surface-200 p-3">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-semibold text-sm text-heading leading-snug">
                  {primaryRef ? (
                    <a
                      href={primaryRef}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                    >
                      {inc.name} <ExternalLink size={12} className="inline align-baseline opacity-60" />
                    </a>
                  ) : (
                    inc.name
                  )}
                </h3>
                {inc.type && (
                  <span
                    className={`shrink-0 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                      TYPE_TONE[inc.type.toLowerCase()] ?? 'border-slate-400/50 text-slate-500 bg-slate-400/10'
                    }`}
                  >
                    {inc.type}
                  </span>
                )}
                <PostAnalysisButton title={inc.name} description={inc.description} source={inc.type} compact />
              </div>

              <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
                {inc.labels.map((l) => (
                  <span
                    key={l}
                    className="text-micro font-mono px-1.5 py-0.5 rounded border border-sky-500/40 text-sky-600 dark:text-sky-400"
                  >
                    {l}
                  </span>
                ))}
                {fmtDate(inc.modified || inc.created) && (
                  <span className="text-micro font-mono text-muted ml-auto">
                    {fmtDate(inc.modified || inc.created)}
                  </span>
                )}
              </div>

              {inc.objective && (
                <p className="text-micro font-mono text-muted mt-2 flex items-start gap-1">
                  <Target size={12} className="shrink-0 mt-0.5" /> {inc.objective}
                </p>
              )}

              {inc.description && (
                <p className="text-xs text-muted mt-2 leading-relaxed line-clamp-6">{inc.description}</p>
              )}

              {inc.external_refs.length > 0 && (
                <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 pt-2 border-t border-line-1">
                  {inc.external_refs.map((ref, i) => {
                    const href = safeHref(ref.url);
                    return href ? (
                      <a
                        key={i}
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                        title={ref.source_name}
                      >
                        {ref.source_name || 'source'}
                      </a>
                    ) : (
                      <span key={i} className="text-micro font-mono text-muted">
                        {ref.source_name}
                      </span>
                    );
                  })}
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
          - Wiz Cloud Threat Landscape; free to display and cite with attribution
          {data.spec_version ? ` · STIX ${data.spec_version}` : ''} · {data.total} entries
        </p>
      )}
    </DataPageLayout>
  );
}
