import { lazy, Suspense, useEffect, useRef, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';
import {
  Search,
  Loader2,
  Building2,
  Globe,
  Zap,
  Map,
  MapPin,
  Shield,
  Plane,
  Cross,
  Anchor,
  Radiation,
  Fuel,
  Siren,
  GraduationCap,
} from 'lucide-react';

const InfraMap = lazy(() => import('../../components/threatintel/InfraMap'));

interface InfraResult {
  id: string;
  type: string;
  name: string;
  lat: number;
  lon: number;
  tags: Record<string, string>;
  category: string;
}

interface InfraSearchResponse {
  query: string;
  parsed: { types: string[]; region: string; country: string; near: string };
  bbox: [number, number, number, number] | null;
  total: number;
  results: InfraResult[];
  generated_at: string;
}

const CATEGORY_COLORS: Record<string, string> = {
  'Energy & Power': '#f59e0b',
  Telecom: '#3b82f6',
  'Oil & Gas': '#78716c',
  Water: '#06b6d4',
  Aviation: '#8b5cf6',
  Maritime: '#0ea5e9',
  'Rail & Transit': '#6366f1',
  Structures: '#64748b',
  Industrial: '#78716c',
  Military: '#ef4444',
  Government: '#10b981',
  Healthcare: '#ec4899',
  Education: '#f97316',
  Culture: '#a855f7',
  Tourism: '#14b8a6',
  Religious: '#eab308',
  Historic: '#a3a3a3',
  Agriculture: '#22c55e',
  Services: '#6366f1',
  Emergency: '#dc2626',
  'Cable Transport': '#0ea5e9',
  Monitoring: '#64748b',
  Community: '#10b981',
};

const QUICK_SEARCHES = [
  { label: 'Military bases in europe', icon: Shield },
  { label: 'Data centers in usa', icon: Building2 },
  { label: 'Power plants in india', icon: Zap },
  { label: 'Airports in germany', icon: Plane },
  { label: 'Hospitals in japan', icon: Cross },
  { label: 'Ports in china', icon: Anchor },
  { label: 'Nuclear sites', icon: Radiation },
  { label: 'Oil refineries near dubai', icon: Fuel },
  { label: 'Police stations in london', icon: Siren },
  { label: 'Universities in france', icon: GraduationCap },
];

export default function InfraSearch(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('q') ?? '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<InfraSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [catFilter, setCatFilter] = useState('All');
  const [mapGlobal, setMapGlobal] = useState(false);
  const [darkTiles, setDarkTiles] = useState(true);

  const ranOnMount = useRef(false);

  const runSearch = async (q: string) => {
    setInput(q);
    setSearchParams({ q }, { replace: true });
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/v1/infra-search?q=${encodeURIComponent(q)}`);
      if (!r.ok) {
        const body = await r.json().catch(() => null);
        throw new Error((body as { error?: string })?.error ?? `HTTP ${r.status}`);
      }
      setResult(await r.json());
    } catch (err) {
      console.error('InfraSearch failed:', errMessage(err));
      setError(errMessage(err, 'search failed'));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = async (e: FormEvent, overrideQuery?: string) => {
    e.preventDefault();
    const q = (overrideQuery ?? input).trim();
    if (!q) return;
    await runSearch(q);
  };

  useEffect(() => {
    if (ranOnMount.current) return;
    ranOnMount.current = true;
    const q = searchParams.get('q')?.trim();
    if (q) void runSearch(q);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = result?.results.filter((r) => catFilter === 'All' || r.category === catFilter) ?? [];
  const categoryCounts: Record<string, number> = {};
  for (const r of result?.results ?? []) {
    categoryCounts[r.category] = (categoryCounts[r.category] ?? 0) + 1;
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Building2 size={28} />}
      title="Infrastructure Search"
      description="Map real-world infrastructure from OpenStreetMap data - 200+ types across 30+ categories. Search by type, operator, or location with natural language."
      maxWidthClass="max-w-[1600px]"
      headerExtra={
        <p className="text-xs text-muted font-mono">
          Powered by Overpass API + Nominatim. Inspired by Sightline (MIT).
        </p>
      }
    >
      {/* Search bar */}
      <section className="surface-card p-4 mb-6">
        <form onSubmit={(e) => onSubmit(e)} className="flex gap-2">
          <div className="relative flex-1 min-w-[220px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="e.g. telecom towers in india, power plants near tokyo"
              className="w-full pl-9 pr-3 py-2.5 rounded-xl border border-line-1 bg-surface-200 font-mono text-sm text-heading focus:border-rose-500/60 focus:outline-none"
              autoComplete="off"
              spellCheck={false}
              aria-label="Infrastructure search query"
            />
          </div>
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="px-5 py-2.5 bg-rose-600 dark:bg-rose-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-rose-700 dark:hover:bg-rose-400 transition-colors"
          >
            <Search size={16} className="inline mr-2" />
            Search
          </button>
        </form>

        {/* Quick searches */}
        {!result && !loading && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            <Zap size={12} className="text-muted mt-0.5" />
            {QUICK_SEARCHES.map((qs) => {
              const Icon = qs.icon;
              return (
                <button
                  key={qs.label}
                  type="button"
                  onClick={(e) => onSubmit(e, qs.label)}
                  className="inline-flex items-center gap-1.5 text-xs font-mono px-2 py-0.5 rounded border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300 hover:text-body dark:hover:text-inverted transition"
                >
                  <Icon size={12} className="shrink-0" /> {qs.label}
                </button>
              );
            })}
          </div>
        )}
      </section>

      {loading && (
        <p className="text-sm font-mono text-muted mb-4 inline-flex items-center gap-2">
          <Loader2 size={14} className="animate-spin" /> Querying OpenStreetMap…
        </p>
      )}
      {error && (
        <p className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4 inline-flex items-center gap-2">
          error: {error}
        </p>
      )}

      {/* Results - side by side layout */}
      {result && (
        <div className="space-y-4">
          {/* Stats row */}
          <div className="flex flex-wrap items-center gap-3 font-mono text-sm">
            <span className="px-2 py-0.5 rounded-xl bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-500/20 font-semibold">
              {result.total} results
            </span>
            {result.parsed.types.length > 0 && (
              <span className="text-muted">
                Types: <span className="text-heading">{result.parsed.types.join(', ')}</span>
              </span>
            )}
            {result.parsed.country && (
              <span className="inline-flex items-center gap-1 text-muted">
                <MapPin size={12} />
                <span className="text-heading">{result.parsed.country}</span>
              </span>
            )}
            {result.parsed.region && (
              <span className="inline-flex items-center gap-1 text-muted">
                <MapPin size={12} />
                <span className="text-heading">{result.parsed.region}</span>
              </span>
            )}
          </div>

          {/* Map + Results side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-4">
            {/* Map */}
            <section className="surface-card overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 border-b border-line-1">
                <div className="flex items-center gap-2 text-xs font-mono text-muted">
                  <Map size={12} />
                  <span>{mapGlobal ? 'Global view' : 'Zoomed to results'}</span>
                  <span className="text-inverted dark:text-muted">·</span>
                  <span>{filtered.length} shown</span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setMapGlobal(!mapGlobal)}
                    className="text-xs font-mono px-2 py-0.5 rounded border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300 inline-flex items-center gap-1"
                  >
                    <Globe size={10} /> {mapGlobal ? 'Zoom in' : 'Global'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setDarkTiles(!darkTiles)}
                    className="text-xs font-mono px-2 py-0.5 rounded border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300"
                    title="Toggle map style"
                  >
                    {darkTiles ? 'Light' : 'Dark'}
                  </button>
                </div>
              </div>
              <div style={{ height: 520 }}>
                <Suspense
                  fallback={
                    <div className="flex items-center justify-center h-full text-muted font-mono text-sm">
                      <Loader2 className="animate-spin mr-2" /> Loading map…
                    </div>
                  }
                >
                  <InfraMap
                    results={filtered}
                    bbox={result.bbox}
                    global={mapGlobal}
                    darkTiles={darkTiles}
                    onToggleDark={() => setDarkTiles(!darkTiles)}
                  />
                </Suspense>
              </div>
            </section>

            {/* Results sidebar */}
            <div className="space-y-3">
              {/* Category filter */}
              {Object.keys(categoryCounts).length > 1 && (
                <div className="flex flex-wrap gap-1">
                  <button
                    type="button"
                    onClick={() => setCatFilter('All')}
                    className={`text-mini font-mono px-2 py-0.5 rounded border transition ${
                      catFilter === 'All'
                        ? 'bg-rose-600 text-white border-rose-600'
                        : 'border-line-1 text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
                    }`}
                  >
                    All ({result.results.length})
                  </button>
                  {Object.entries(categoryCounts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 12)
                    .map(([cat, count]) => (
                      <button
                        type="button"
                        key={cat}
                        onClick={() => setCatFilter(cat)}
                        className={`text-mini font-mono px-2 py-0.5 rounded border transition inline-flex items-center gap-1 ${
                          catFilter === cat
                            ? 'bg-rose-600 text-white border-rose-600'
                            : 'border-line-1 text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
                        }`}
                      >
                        <span
                          className="w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ background: CATEGORY_COLORS[cat] ?? '#6366f1' }}
                        />
                        {cat} ({count})
                      </button>
                    ))}
                </div>
              )}

              {/* Results list */}
              <section className="surface-card">
                <div className="px-4 py-2 border-b border-line-1 flex items-center justify-between">
                  <span className="text-xs font-mono text-muted">
                    {filtered.length} result{filtered.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="max-h-[480px] overflow-y-auto">
                  {filtered.slice(0, 200).map((r) => (
                    <div
                      key={r.id}
                      className="flex items-center gap-2.5 px-4 py-2 border-b border-line-1/50 last:border-0 hover:bg-surface-200 dark:hover:bg-surface-300/50 transition text-sm cursor-default"
                    >
                      <span
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ background: CATEGORY_COLORS[r.category] ?? '#6366f1' }}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="font-medium truncate text-heading text-tool">{r.name}</div>
                        <div className="text-mini text-muted font-mono">
                          {r.lat.toFixed(4)}, {r.lon.toFixed(4)}
                        </div>
                      </div>
                      <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted shrink-0">
                        {r.category}
                      </span>
                    </div>
                  ))}
                </div>
                {filtered.length > 200 && (
                  <div className="px-4 py-2 border-t border-line-1">
                    <p className="text-mini text-muted font-mono">Showing 200 of {filtered.length} · map shows all</p>
                  </div>
                )}
              </section>
            </div>
          </div>
        </div>
      )}

      {/* Empty state - global map when no search */}
      {!result && !loading && !error && (
        <section className="surface-card overflow-hidden">
          <div className="px-4 py-2 border-b border-line-1 flex items-center gap-2 text-xs font-mono text-muted">
            <Globe size={12} />
            Global infrastructure map - search above to populate
          </div>
          <div style={{ height: 500 }}>
            <Suspense
              fallback={
                <div className="flex items-center justify-center h-full text-muted font-mono text-sm">
                  <Loader2 className="animate-spin mr-2" /> Loading map…
                </div>
              }
            >
              <InfraMap
                results={[]}
                global={true}
                darkTiles={darkTiles}
                onToggleDark={() => setDarkTiles(!darkTiles)}
              />
            </Suspense>
          </div>
        </section>
      )}
    </DataPageLayout>
  );
}
