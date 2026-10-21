import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowRight, Compass, Filter as FilterIcon, Search, Sparkles, X, type LucideIcon } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { CATALOG, catalogSearch, type HubMeta, type HubPage } from '../../data/threatintel-catalog';
import type { HubPageBadge } from '../../data/threatintel-hubs';

/**
 * The threat-intel catalog.
 *
 * Single source of truth for "where can I go in /threatintel/*?". Every
 * routable page in the threat-intel area is listed here, grouped by hub,
 * with a search box and category filter. The data is sourced from
 * `data/threatintel-hubs.ts` (re-exported as `data/threatintel-catalog.ts`)
 * so the home page tile grid and the sidebar stay in sync.
 *
 * URL params:
 *   ?q=<query>   pre-fills the search box
 *   ?cat=<id>    pre-selects a hub (filters the view)
 *   ?tag=<id>    same as cat (alias for tile-link deep-links)
 */
export default function CatalogPage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQ = searchParams.get('q') ?? '';
  const initialCat = searchParams.get('cat') ?? searchParams.get('tag') ?? '';
  const [query, setQuery] = useState(initialQ);
  const [activeCat, setActiveCat] = useState<string>(initialCat || 'all');

  useEffect(() => {
    const next = new URLSearchParams();
    if (query) next.set('q', query);
    if (activeCat && activeCat !== 'all') next.set('cat', activeCat);
    setSearchParams(next, { replace: true });
  }, [query, activeCat, setSearchParams]);

  const totalEntries = CATALOG.reduce((sum, h) => sum + h.pages.length, 0);

  const searchResults = useMemo(() => {
    if (!query.trim()) return null;
    return catalogSearch(query);
  }, [query]);

  const visibleCategories = useMemo<HubMeta[]>(() => {
    if (searchResults) {
      const matchingCatIds = new Set(searchResults.map((r) => r.category.id));
      return CATALOG.filter((c) => matchingCatIds.has(c.id));
    }
    if (activeCat === 'all') return CATALOG;
    return CATALOG.filter((c) => c.id === activeCat);
  }, [searchResults, activeCat]);

  return (
    <>
      <PageMeta
        title="Threat Intel Catalog"
        description="Every routable page in the threat-intel area - search by name, route, or keyword, or filter by category."
        section="Threat Intel"
        canonicalPath="/threatintel/catalog"
      />
      <DataPageLayout
        backTo="/threatintel"
        backLabel="Threat Intel home"
        icon={<Compass size={28} />}
        title="Threat Intel Catalog"
        description={
          <>
            Every routable page in the threat-intel area - {totalEntries} pages across {CATALOG.length} hubs. Search by
            name, route, or keyword, or filter by category. New pages are added to{' '}
            <Link to="/threatintel" className="text-rose-600 underline-offset-2 hover:underline">
              the home page
            </Link>{' '}
            and{' '}
            <Link to="/threatintel" className="text-rose-600 underline-offset-2 hover:underline">
              the sidebar
            </Link>{' '}
            automatically.
          </>
        }
        maxWidthClass="max-w-7xl"
        headerExtra={
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-micro uppercase tracking-wider text-amber-700 dark:text-amber-300">
              <Sparkles size={11} /> new
            </span>
            <span className="font-mono text-mini text-muted">
              {totalEntries} pages · {CATALOG.length} hubs · deep-linkable via{' '}
              <code className="font-mono text-tool bg-surface-300 rounded px-1.5 py-0.5">?q=…&cat=…</code>
            </span>
          </div>
        }
      >
        <div className="mb-6 space-y-3">
          <div className="relative">
            <Search
              size={14}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
              aria-hidden="true"
            />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by name, route, or keyword (e.g. 'ransomware', 'yara', '/iocs/c2')…"
              aria-label="Search catalog"
              className="w-full rounded-xl border border-line-1 bg-surface-100 py-2.5 pl-9 pr-20 font-mono text-tool text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/20 dark:placeholder:text-muted"
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                className="absolute right-2 top-1/2 inline-flex -translate-y-1/2 items-center gap-1 rounded px-1.5 py-0.5 font-mono text-micro text-muted hover:bg-surface-300 hover:text-heading dark:hover:bg-surface-300 dark:hover:text-slate-100"
                aria-label="Clear search"
              >
                <X size={11} /> clear
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2" role="tablist" aria-label="Catalog categories">
            <span className="inline-flex items-center gap-1 font-mono text-micro uppercase tracking-wider text-muted">
              <FilterIcon size={11} /> filter
            </span>
            <CategoryPill
              label="All"
              count={totalEntries}
              active={activeCat === 'all'}
              onClick={() => setActiveCat('all')}
              accent="text-body"
            />
            {CATALOG.map((c) => (
              <CategoryPill
                key={c.id}
                label={c.label}
                count={c.pages.length}
                active={activeCat === c.id}
                onClick={() => setActiveCat(c.id)}
                accent={c.tone}
              />
            ))}
          </div>

          {searchResults && (
            <div className="font-mono text-mini text-muted">
              {searchResults.length} {searchResults.length === 1 ? 'match' : 'matches'} for &ldquo;{query.trim()}&rdquo;
              {searchResults.length === 0 ? ' · try fewer or different keywords' : ''}
            </div>
          )}
        </div>

        <div className="space-y-8">
          {visibleCategories.length === 0 && (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <p className="text-sm text-muted">
                No pages match the current filter. Try a different category or clear the search box.
              </p>
            </div>
          )}
          {visibleCategories.map((cat) => {
            const entries =
              searchResults != null
                ? searchResults.filter((r) => r.category.id === cat.id).map((r) => r as HubPage)
                : cat.pages;
            return <CategorySection key={cat.id} category={cat} entries={entries} />;
          })}
        </div>
      </DataPageLayout>
    </>
  );
}

function CategoryPill({
  label,
  count,
  active,
  onClick,
  accent,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
  accent: string;
}): JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      role="tab"
      aria-selected={active}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-micro transition-colors ${
        active
          ? `${accent} border-current bg-current/10`
          : 'border-slate-300/60 bg-white text-slate-500 hover:border-slate-400 hover:text-slate-900 dark:border-line-1 dark:bg-surface-200 dark:text-muted dark:hover:border-slate-600 dark:hover:text-slate-100'
      }`}
    >
      {label}
      <span
        className={`rounded-full px-1.5 py-0.5 text-micro font-mono ${
          active ? 'bg-current/15' : 'bg-slate-100 dark:bg-surface-200'
        }`}
      >
        {count}
      </span>
    </button>
  );
}

function CategorySection({ category, entries }: { category: HubMeta; entries: readonly HubPage[] }): JSX.Element {
  if (entries.length === 0) return <></>;
  return (
    <section aria-labelledby={`hub-${category.id}`}>
      <div className="mb-3 flex items-baseline justify-between gap-2 border-b border-line-1 pb-2">
        <h2 id={`hub-${category.id}`} className="flex items-center gap-2 font-display text-lg font-semibold">
          <span className={`inline-flex items-center justify-center rounded border px-1.5 py-1 ${category.tone}`}>
            <category.icon size={16} aria-hidden="true" />
          </span>
          {category.label}
          <span className="font-mono text-micro text-muted">· {entries.length}</span>
        </h2>
        <p className="hidden text-tool text-muted sm:block">{category.blurb}</p>
      </div>
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {entries.map((e) => (
          <CatalogCard key={e.path} entry={e} hubIcon={category.icon} />
        ))}
      </ul>
    </section>
  );
}

const BADGE_STYLES: Record<NonNullable<HubPageBadge>, string> = {
  live: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  new: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  beta: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
};

function CatalogCard({ entry, hubIcon }: { entry: HubPage; hubIcon: LucideIcon }): JSX.Element {
  const Icon = entry.icon ?? hubIcon;
  return (
    // `min-w-0` lets the grid item shrink below its content's intrinsic
    // width. Without it the card's own padding plus the unbreakable path
    // text set a floor that pushed the grid 23px past a 375px viewport.
    <li className="min-w-0">
      <Link
        to={entry.path}
        className="group tile-reveal block h-full surface-card p-3 transition-[transform,border-color,box-shadow] duration-200 hover:-translate-y-0.5 hover:border-rose-500/40 hover:shadow-e2 focus-visible:-translate-y-0.5 focus-visible:border-rose-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/30 hover-rose"
      >
        <div className="flex items-start justify-between gap-2">
          <Icon
            size={16}
            className="mt-0.5 shrink-0 text-rose-600 dark:text-rose-400 transition-colors"
            aria-hidden="true"
          />
          {entry.badge && (
            <span
              className={`rounded border px-1.5 py-0.5 font-mono text-micro uppercase tracking-wider ${BADGE_STYLES[entry.badge]}`}
            >
              {entry.badge}
            </span>
          )}
        </div>
        <h3 className="mt-2 font-display text-sm font-semibold text-heading transition-colors group-hover:text-rose-600 dark:group-hover:text-rose-400">
          {entry.label}
        </h3>
        <p className="mt-0.5 line-clamp-2 text-tool text-muted">{entry.desc}</p>
        <div className="mt-2 flex items-center justify-between gap-2 font-mono text-micro text-muted">
          <code className="min-w-0 truncate font-mono">{entry.path}</code>
          <span className="inline-flex items-center gap-0.5 text-rose-600 dark:text-rose-400 opacity-0 transition-opacity group-hover:opacity-100">
            open <ArrowRight size={10} />
          </span>
        </div>
      </Link>
    </li>
  );
}
