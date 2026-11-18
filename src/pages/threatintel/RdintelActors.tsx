import { useMemo, useState } from 'react';
import { ExternalLink, Globe2, RefreshCw, Search, Users } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';

/**
 * RD Intelligence actor roster mirror.
 *
 * rdintel.com/cve/actors publishes a public roster of 200 tracked groups:
 * name, country attribution, a short profile and known aliases. The per-actor
 * pages behind that roster (linked CVEs, articles, malware) are sign-in gated
 * upstream, so this surface deliberately mirrors only the public fields and
 * links out to the upstream record for the rest. Aliases that upstream
 * truncates with an ellipsis are dropped rather than shown as partial names.
 *
 * Snapshot built by scripts/sync-cve-intel.mjs (GitHub Actions, every 6h).
 */

interface ActorRecord {
  id: string;
  name: string;
  country: string | null;
  description: string;
  aliases: string[];
  url: string;
}

interface ActorDataset {
  generatedAt: string;
  upstream: { page: string; detail: string };
  count: number;
  stats: {
    withCountry: number;
    withAliases: number;
    countries: Array<{ code: string; count: number }>;
  };
  actors: ActorRecord[];
}

type SortMode = 'name' | 'country';

const PAGE_SIZE = 60;

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="surface-card rounded-xl border border-line-1 px-4 py-3" title={hint}>
      <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className="text-xl font-semibold tabular-nums text-heading">{value}</div>
    </div>
  );
}

export default function RdintelActors({ bare = false }: { bare?: boolean }): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<ActorDataset>({
    url: '/data/cve-intel/actors.json',
    ttl: 10 * 60_000,
  });

  const [query, setQuery] = useState('');
  const [country, setCountry] = useState('all');
  const [sort, setSort] = useState<SortMode>('name');
  const [visible, setVisible] = useState(PAGE_SIZE);

  const rows = useMemo(() => {
    const all = data?.actors ?? [];
    const q = query.trim().toLowerCase();
    const filtered = all.filter((a) => {
      if (country === 'unattributed' && a.country) return false;
      if (country !== 'all' && country !== 'unattributed' && a.country !== country) return false;
      if (!q) return true;
      return (
        a.name.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.aliases.some((alias) => alias.toLowerCase().includes(q))
      );
    });
    return filtered.sort((a, b) => {
      if (sort === 'country') {
        const byCountry = (a.country ?? 'zz').localeCompare(b.country ?? 'zz');
        return byCountry || a.name.localeCompare(b.name);
      }
      return a.name.localeCompare(b.name);
    });
  }, [data, query, country, sort]);

  const shown = rows.slice(0, visible);
  const topCountry = data?.stats.countries[0];

  const body = data ? (
    <div className="space-y-6">
      <section aria-labelledby="rdi-actors-stats">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 id="rdi-actors-stats" className="flex items-center gap-2 text-lg font-bold text-heading">
              <Users size={18} /> Tracked actors
            </h2>
            <p className="mt-1 text-[11px] text-muted">
              {data.count} APT groups, cybercriminal organizations and threat actors, sorted A-Z. Synced{' '}
              {relativeAgo(data.generatedAt)}.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void refetch()}
            className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 text-[11px] text-muted hover:text-heading"
          >
            <RefreshCw size={11} /> refresh
          </button>
        </div>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Tracked actors" value={data.count.toLocaleString('en-US')} />
          <Stat
            label="Country attributed"
            value={data.stats.withCountry.toLocaleString('en-US')}
            hint="Records where the upstream roster names an attributed country"
          />
          <Stat
            label="With aliases"
            value={data.stats.withAliases.toLocaleString('en-US')}
            hint="Known alternate names"
          />
          <Stat
            label="Countries"
            value={data.stats.countries.length.toLocaleString('en-US')}
            hint={topCountry ? `Most attributed: ${topCountry.code} (${topCountry.count})` : undefined}
          />
        </div>
      </section>

      <section aria-labelledby="rdi-actors-roster">
        <h2 id="rdi-actors-roster" className="mb-3 flex items-center gap-2 text-lg font-bold text-heading">
          <Globe2 size={18} /> Public roster
        </h2>

        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="relative min-w-[220px] flex-1">
            <span className="sr-only">Search actors</span>
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setVisible(PAGE_SIZE);
              }}
              placeholder="Actor name, alias, description…"
              className="w-full rounded-lg border border-line-1 bg-surface-100 py-2 pl-8 pr-3 text-sm text-body placeholder:text-muted focus:border-brand-500 focus:outline-none"
            />
          </label>
          <label className="flex items-center gap-1.5 text-[11px] text-muted">
            <span className="sr-only">Filter by country</span>
            <select
              value={country}
              onChange={(e) => {
                setCountry(e.target.value);
                setVisible(PAGE_SIZE);
              }}
              className="rounded-lg border border-line-1 bg-surface-100 px-2 py-2 text-xs text-body focus:border-brand-500 focus:outline-none"
            >
              <option value="all">All countries</option>
              <option value="unattributed">Unattributed</option>
              {data.stats.countries.map((c) => (
                <option key={c.code} value={c.code}>
                  {c.code} ({c.count})
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-[11px] text-muted">
            <span className="sr-only">Sort actors</span>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as SortMode)}
              className="rounded-lg border border-line-1 bg-surface-100 px-2 py-2 text-xs text-body focus:border-brand-500 focus:outline-none"
            >
              <option value="name">Sort: A-Z</option>
              <option value="country">Sort: country</option>
            </select>
          </label>
        </div>

        <p className="mb-2 font-mono text-[11px] text-muted">
          {rows.length.toLocaleString()} actor{rows.length === 1 ? '' : 's'} · showing {shown.length.toLocaleString()}
        </p>

        <ul className="grid gap-2 lg:grid-cols-2">
          {shown.map((actor) => (
            <li key={actor.id} className="surface-card rounded-lg border border-line-1 p-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <a
                    href={actor.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm font-bold text-heading hover:text-rose-600 dark:hover:text-rose-400"
                    title={`Open ${actor.name} on RD Intelligence`}
                  >
                    {actor.name} <ExternalLink size={10} />
                  </a>
                  {actor.country && (
                    <span className="rounded border border-line-1 bg-surface-300 px-1.5 py-0.5 font-mono text-[10px] text-muted">
                      {actor.country}
                    </span>
                  )}
                </div>
                <a
                  href={actor.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="shrink-0 font-mono text-[10px] text-muted underline hover:text-rose-600 dark:hover:text-rose-400"
                >
                  RDIntel record
                </a>
              </div>

              {actor.description && <p className="mt-1 text-xs leading-relaxed text-body">{actor.description}</p>}
              {actor.aliases.length > 0 && (
                <p className="mt-1.5 flex flex-wrap items-center gap-1 text-[10px] text-muted">
                  <span className="font-mono uppercase tracking-wider">aka</span>
                  {actor.aliases.slice(0, 6).map((alias) => (
                    <span key={alias} className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 font-mono">
                      {alias}
                    </span>
                  ))}
                  {actor.aliases.length > 6 && (
                    <span className="font-mono" title={actor.aliases.slice(6).join(', ')}>
                      +{actor.aliases.length - 6} more
                    </span>
                  )}
                </p>
              )}
            </li>
          ))}
        </ul>

        {rows.length === 0 && (
          <p className="mt-4 flex items-center gap-2 text-sm text-muted">
            <Search size={14} /> No actors match those filters.
          </p>
        )}

        {visible < rows.length && (
          <div className="mt-4 flex justify-center">
            <button
              type="button"
              onClick={() => setVisible((v) => v + PAGE_SIZE)}
              className="rounded border border-line-1 px-4 py-2 font-mono text-xs text-muted hover:border-rose-500/40 hover:text-heading"
            >
              load {Math.min(PAGE_SIZE, rows.length - visible)} more
            </button>
          </div>
        )}
      </section>

      <section className="surface-card rounded-xl border border-line-1 p-4 text-[11px] leading-relaxed text-muted">
        <p className="mb-1 font-semibold text-heading">Provenance</p>
        <p>
          Roster mirrored from{' '}
          <a
            href={data.upstream.page}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-accent"
          >
            rdintel.com/cve/actors
          </a>
          . Names, country attribution, descriptions and aliases are verbatim upstream values; aliases truncated
          upstream are omitted. Linked CVEs, articles and attribution detail are sign-in gated on RDIntel, so each
          record links out to its upstream page rather than duplicating gated content. Refreshed every 6 hours via
          GitHub Actions.
        </p>
      </section>
    </div>
  ) : null;

  if (bare) {
    if (loading && !data) return <p className="py-10 text-center text-sm text-muted">Loading actor roster…</p>;
    if (error && !data) {
      return (
        <p className="py-10 text-center text-sm text-rose-600 dark:text-rose-400">
          Actor roster snapshot unavailable: {error}
        </p>
      );
    }
    return <>{body}</>;
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Users size={28} />}
      title="RDIntel Actors"
      description="Public roster mirror of rdintel.com/cve/actors."
      loading={loading && !data}
      error={error}
      onRetry={() => void refetch()}
    >
      {body}
    </DataPageLayout>
  );
}
