import { useEffect, useMemo, useState } from 'react';
import { ExternalLink, Megaphone, Target } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { StixObjectTable, type StixBundle } from '../../components/StixBundleViewer';
import { errMessage } from '../../lib/log';

interface ExternalRef {
  source_name: string;
  external_id: string;
  url: string;
}
interface DisarmEntry {
  id: string;
  type: string;
  name: string;
  description: string;
  external_id: string;
  phases: string[];
  created: string;
  modified: string;
  refs: ExternalRef[];
}
interface DisarmResponse {
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
  };
  entries: DisarmEntry[];
  bundle: StixBundle;
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
  'attack-pattern': 'border-violet-500/50 text-violet-600 dark:text-violet-400 bg-violet-500/10',
  'x-mitre-tactic': 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400 bg-emerald-500/10',
  'intrusion-set': 'border-orange-500/50 text-orange-600 dark:text-orange-400 bg-orange-500/10',
  'course-of-action': 'border-sky-500/50 text-sky-600 dark:text-sky-400 bg-sky-500/10',
};

/** Friendly label for an internal STIX type. */
const TYPE_LABEL: Record<string, string> = {
  'attack-pattern': 'technique',
  'x-mitre-tactic': 'tactic',
  'intrusion-set': 'intrusion set',
  'course-of-action': 'countermeasure',
};

function typeLabel(t: string): string {
  return TYPE_LABEL[t] ?? t.replace(/-/g, ' ');
}

function chip(active: boolean): string {
  return `text-xs font-mono px-2.5 py-1 rounded border transition-colors ${
    active
      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
  }`;
}

export default function DisarmFramework(): JSX.Element {
  const [data, setData] = useState<DisarmResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [type, setType] = useState('all');
  const [query, setQuery] = useState('');
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/disarm-framework', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<DisarmResponse>;
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
    const list = data?.entries ?? [];
    const needle = query.trim().toLowerCase();
    return list.filter((e) => {
      if (type !== 'all' && e.type !== type) return false;
      if (!needle) return true;
      return (
        e.name.toLowerCase().includes(needle) ||
        e.description.toLowerCase().includes(needle) ||
        e.external_id.toLowerCase().includes(needle)
      );
    });
  }, [data, type, query]);

  const description = (
    <>
      The{' '}
      <a
        href="https://github.com/DISARMFoundation/DISARMframeworks"
        target="_blank"
        rel="noopener noreferrer"
        className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
      >
        DISARM
      </a>{' '}
      framework for Foreign Information Manipulation &amp; Interference (FIMI) / disinformation, rendered from its
      published STIX 2.1 bundle - disinformation tactics (TA01–TA16) and the techniques (T0xxx) that ladder up to them,
      each with its description and DISARM reference. Licensed CC BY-SA 4.0 by the DISARM Foundation (attribution +
      ShareAlike).
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
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search techniques / tactics (name, description, T-id)…"
          className="w-full max-w-md rounded border border-line-2 bg-surface-100 px-3 py-1.5 text-sm font-mono text-body placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
        />
        <div className="flex flex-wrap gap-1.5">
          <button type="button" onClick={() => setType('all')} className={chip(type === 'all')}>
            All <span className="opacity-60">· {data.total}</span>
          </button>
          {types.map(([name, n]) => (
            <button type="button" key={name} onClick={() => setType(name)} className={chip(type === name)}>
              {typeLabel(name)} <span className="opacity-60">· {n}</span>
            </button>
          ))}
          <button type="button" onClick={() => setShowRaw((v) => !v)} className={chip(showRaw)}>
            {showRaw ? 'hide' : 'show'} raw STIX bundle
          </button>
        </div>
      </div>
    ) : undefined;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Megaphone size={28} />}
      title="DISARM (disinformation TTPs)"
      description={description}
      headerExtra={headerExtra}
      loading={loading}
      error={error}
      empty={!loading && !error && !!data && filtered.length === 0}
      emptyMessage="No techniques or tactics match the filter."
    >
      {data && showRaw && <StixObjectTable bundle={data.bundle} />}

      <div className="grid gap-3 lg:grid-cols-2">
        {filtered.slice(0, 800).map((entry) => {
          const primaryRef = entry.refs.map((r) => safeHref(r.url)).find((h): h is string => Boolean(h));
          const tone = TYPE_TONE[entry.type] ?? 'border-slate-400/50 text-slate-500 bg-slate-400/10';
          return (
            <div key={entry.id} className="rounded-xl border border-line-1 bg-surface-200 p-3">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-semibold text-sm text-heading leading-snug">
                  {primaryRef ? (
                    <a
                      href={primaryRef}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                    >
                      {entry.external_id && (
                        <span className="font-mono text-rose-600 dark:text-rose-400 mr-1.5">{entry.external_id}</span>
                      )}
                      {entry.name} <ExternalLink size={12} className="inline align-baseline opacity-60" />
                    </a>
                  ) : (
                    <>
                      {entry.external_id && (
                        <span className="font-mono text-rose-600 dark:text-rose-400 mr-1.5">{entry.external_id}</span>
                      )}
                      {entry.name}
                    </>
                  )}
                </h3>
                <span
                  className={`shrink-0 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${tone}`}
                >
                  {typeLabel(entry.type)}
                </span>
              </div>

              {entry.phases.length > 0 && (
                <p className="text-micro font-mono text-muted mt-1.5 flex items-start gap-1">
                  <Target size={12} className="shrink-0 mt-0.5" />
                  <span className="flex flex-wrap gap-1">
                    {entry.phases.map((p) => (
                      <span
                        key={p}
                        className="px-1.5 py-0.5 rounded border border-sky-500/40 text-sky-600 dark:text-sky-400"
                      >
                        {p}
                      </span>
                    ))}
                  </span>
                </p>
              )}

              {entry.description && (
                <p className="text-xs text-muted mt-2 leading-relaxed line-clamp-6">{entry.description}</p>
              )}

              {entry.refs.length > 0 && (
                <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 pt-2 border-t border-line-1">
                  {entry.refs.map((ref, i) => {
                    const href = safeHref(ref.url);
                    const label = ref.external_id
                      ? `${ref.source_name || 'ref'}:${ref.external_id}`
                      : ref.source_name || 'source';
                    return href ? (
                      <a
                        key={i}
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                        title={ref.source_name}
                      >
                        {label}
                      </a>
                    ) : (
                      <span key={i} className="text-micro font-mono text-muted">
                        {label}
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
          - DISARM Frameworks; CC BY-SA 4.0 (attribution + ShareAlike)
          {data.spec_version ? ` · STIX ${data.spec_version}` : ''} · {data.total} entries
        </p>
      )}
    </DataPageLayout>
  );
}
