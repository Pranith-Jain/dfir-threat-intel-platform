import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Flag, Search, Users } from 'lucide-react';
import { DataPageLayout, useInsideDataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface GalaxyActor {
  value: string;
  uuid: string;
  synonyms: string[];
  country: string;
  state_sponsor: string;
  description: string;
  refs: string[];
}
interface GalaxyResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  count: number;
  total: number;
  countries: Record<string, number>;
  actors: GalaxyActor[];
  stale?: boolean;
  upstream_error?: string;
}

/** Only render http(s) links - the ref urls come from an untrusted upstream,
 *  so never let a `javascript:`/`data:` URL reach an href. */
function safeHref(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch (_catchErr) {
    console.error('safeHref failed:', errMessage(_catchErr));
    return null;
  }
}

function chip(active: boolean): string {
  return `text-xs font-mono px-2.5 py-1 rounded border transition-colors ${
    active
      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
  }`;
}

export default function MispGalaxyActors(): JSX.Element {
  // Rendered as a tab inside ActorDirectory's DataPageLayout, so suppress this
  // page's own back link when nested to avoid a duplicate "back" control.
  const insideLayout = useInsideDataPageLayout();
  const [data, setData] = useState<GalaxyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [country, setCountry] = useState('all');

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    // Fetch a generous slice once and filter client-side (search box + country
    // chips) so typing never re-hits the edge - same-origin, plain fetch.
    fetch('/api/v1/misp-galaxy-actors?limit=1000', {
      signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<GalaxyResponse>;
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

  const countries = useMemo(() => Object.entries(data?.countries ?? {}).sort((a, b) => b[1] - a[1]), [data]);

  const filtered = useMemo(() => {
    const list = data?.actors ?? [];
    const needle = query.trim().toLowerCase();
    return list.filter((a) => {
      if (country !== 'all' && a.country !== country) return false;
      if (!needle) return true;
      return (
        a.value.toLowerCase().includes(needle) ||
        a.country.toLowerCase().includes(needle) ||
        a.state_sponsor.toLowerCase().includes(needle) ||
        a.synonyms.some((s) => s.toLowerCase().includes(needle))
      );
    });
  }, [data, query, country]);

  const description = (
    <>
      Searchable threat-actor alias directory - canonical name, known synonyms, suspected origin country, and reference
      links from the{' '}
      <a
        href="https://github.com/MISP/misp-galaxy"
        target="_blank"
        rel="noopener noreferrer"
        className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
      >
        MISP Galaxy
      </a>{' '}
      threat-actor cluster (CC0 / BSD-2). Search by any name or alias, then pivot a canonical actor into the actor
      catalogue or the IOC checker.
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
        <div className="relative max-w-md">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search actor or alias (e.g. APT28, Fancy Bear, Lazarus)…"
            aria-label="Search threat actor or alias"
            className="w-full pl-9 pr-3 py-2 text-sm rounded-xl border border-line-2 bg-surface-100 text-heading placeholder:text-muted focus:outline-none focus:border-rose-500/60"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button type="button" onClick={() => setCountry('all')} className={chip(country === 'all')}>
            All origins <span className="opacity-60">· {data.total}</span>
          </button>
          {countries.slice(0, 24).map(([name, n]) => (
            <button type="button" key={name} onClick={() => setCountry(name)} className={chip(country === name)}>
              {name} <span className="opacity-60">· {n}</span>
            </button>
          ))}
        </div>
      </div>
    ) : undefined;

  return (
    <DataPageLayout
      backTo="/threatintel"
      hideBack={insideLayout}
      icon={<Users size={28} />}
      title="Threat-actor alias directory"
      description={description}
      headerExtra={headerExtra}
      loading={loading}
      error={error}
      empty={!loading && !error && !!data && filtered.length === 0}
      emptyMessage="No actors match the search."
    >
      <p className="mb-3 text-micro font-mono text-muted">
        {filtered.length} of {data?.total ?? 0} actors{query.trim() || country !== 'all' ? ' (filtered)' : ''}
      </p>
      <div className="grid gap-3 lg:grid-cols-2">
        {filtered.slice(0, 600).map((actor) => (
          <div key={actor.uuid || actor.value} className="rounded-xl border border-line-1 bg-surface-200 p-3">
            <div className="flex items-start justify-between gap-2">
              <h3 className="font-semibold text-sm text-heading leading-snug">{actor.value}</h3>
              {actor.country && (
                <span className="shrink-0 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-sky-500/40 text-sky-600 dark:text-sky-400 flex items-center gap-1">
                  <Flag size={10} aria-hidden="true" /> {actor.country}
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
              <Link
                to={`/threatintel/actors?q=${encodeURIComponent(actor.value)}`}
                className="text-micro font-mono px-1.5 py-0.5 rounded border border-rose-500/40 text-rose-600 dark:text-rose-400 hover:bg-rose-500/10"
                title="Open in the threat-actor catalogue"
              >
                actors →
              </Link>
              <Link
                to={`/dfir/ioc-check?indicator=${encodeURIComponent(actor.value)}`}
                className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 text-body hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400"
                title="Pivot to IOC checker"
              >
                ioc-check →
              </Link>
              {actor.state_sponsor && (
                <span className="text-micro font-mono px-1.5 py-0.5 rounded border border-violet-500/40 text-violet-600 dark:text-violet-400">
                  sponsor: {actor.state_sponsor}
                </span>
              )}
            </div>

            {actor.synonyms.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {actor.synonyms.map((alias) => (
                  <span
                    key={alias}
                    className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 text-body"
                  >
                    {alias}
                  </span>
                ))}
              </div>
            )}

            {actor.description && (
              <p className="text-xs text-muted mt-2 leading-relaxed line-clamp-4">{actor.description}</p>
            )}

            {actor.refs.length > 0 && (
              <details className="mt-2 group">
                <summary className="text-micro font-mono text-muted cursor-pointer hover:text-rose-600 dark:hover:text-rose-400">
                  references · {actor.refs.length}
                </summary>
                <div className="flex flex-col gap-1 mt-1 ml-1">
                  {actor.refs.map((ref, i) => {
                    const href = safeHref(ref);
                    return href ? (
                      <a
                        key={i}
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline truncate transition-colors"
                      >
                        {ref} <ExternalLink size={10} className="inline align-baseline opacity-60" />
                      </a>
                    ) : (
                      <span key={i} className="text-micro font-mono text-muted truncate">
                        {ref}
                      </span>
                    );
                  })}
                </div>
              </details>
            )}
          </div>
        ))}
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
          - {data.license} · {data.total} actors
        </p>
      )}
    </DataPageLayout>
  );
}
