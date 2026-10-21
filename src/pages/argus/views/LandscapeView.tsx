import { useState, useMemo } from 'react';
import { ShieldAlert, Target, Globe2, TrendingUp, BarChart3, AlertCircle, Search, Filter, X } from 'lucide-react';
import type { Actor, FeedItem } from '../types';
import { NATION_PALETTE } from '../data/countries';

interface Props {
  actors: Actor[];
  feed: FeedItem[];
}

export function LandscapeView({ actors, feed }: Props) {
  const [search, setSearch] = useState('');
  const [sectorFilter, setSectorFilter] = useState<string | null>(null);
  const [motivationFilter, setMotivationFilter] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<'threat' | 'name' | 'date'>('threat');
  const [showFilters, setShowFilters] = useState(false);

  const filteredActors = useMemo(() => {
    let items = actors;
    if (sectorFilter) items = items.filter((a) => a.sectors.includes(sectorFilter));
    if (motivationFilter) items = items.filter((a) => a.motivation === motivationFilter);
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (a) =>
          a.name.toLowerCase().includes(q) ||
          a.apt?.toLowerCase().includes(q) ||
          a.description.toLowerCase().includes(q) ||
          a.agency.toLowerCase().includes(q) ||
          a.sectors.some((s) => s.toLowerCase().includes(q)) ||
          a.malware.some((m) => m.name.toLowerCase().includes(q))
      );
    }
    if (sortBy === 'name') items = [...items].sort((a, b) => a.name.localeCompare(b.name));
    else if (sortBy === 'date') items = [...items].sort((a, b) => b.last_seen - a.last_seen);
    else items = [...items].sort((a, b) => b.ttps.length + b.malware.length - (a.ttps.length + a.malware.length));
    return items;
  }, [actors, sectorFilter, motivationFilter, search, sortBy]);

  const allSectors = useMemo(() => {
    const s = new Set<string>();
    actors.forEach((a) => a.sectors.forEach((sec) => s.add(sec)));
    return [...s].sort();
  }, [actors]);

  const allMotivations = useMemo(() => [...new Set(actors.map((a) => a.motivation))].sort(), [actors]);
  const stats = useMemo(() => {
    const motivations: Record<string, number> = {};
    filteredActors.forEach((a) => {
      motivations[a.motivation] = (motivations[a.motivation] || 0) + 1;
    });

    const sectors: Record<string, number> = {};
    filteredActors.forEach((a) =>
      a.sectors.forEach((s) => {
        sectors[s] = (sectors[s] || 0) + 1;
      })
    );
    const sortedSectors = Object.entries(sectors)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    const nationCounts: Record<string, number> = {};
    filteredActors.forEach((a) => {
      nationCounts[a.country] = (nationCounts[a.country] || 0) + 1;
    });

    const avgActive =
      filteredActors.length > 0
        ? Math.round(
            filteredActors.reduce((s, a) => s + (new Date().getFullYear() - a.active_since), 0) / filteredActors.length
          )
        : 0;
    const totalTTPs = filteredActors.reduce((s, a) => s + a.ttps.length, 0);
    const totalMalware = filteredActors.reduce((s, a) => s + a.malware.length, 0);
    const totalCVEs = filteredActors.reduce((s, a) => s + a.cves.length, 0);
    const totalCampaigns = filteredActors.reduce((s, a) => s + a.campaigns.length, 0);

    return { motivations, sortedSectors, nationCounts, avgActive, totalTTPs, totalMalware, totalCVEs, totalCampaigns };
  }, [filteredActors]);

  const recentFeed = useMemo(() => {
    let items = feed.filter((f) => f.related_actors?.some((id) => filteredActors.some((a) => a.id === id)));
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.source.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
      );
    }
    return items.slice(0, 12);
  }, [feed, filteredActors, search]);

  const maxSector = stats.sortedSectors.length > 0 ? stats.sortedSectors[0]![1] : 1;

  return (
    <div className="absolute inset-0 overflow-y-auto">
      <div className="max-w-6xl mx-auto px-4 sm:px-8 py-6 space-y-6 animate-fade-in-up">
        <header>
          <div className="flex items-center gap-3 mb-1">
            <TrendingUp size={22} className="text-rose-600 dark:text-rose-400" />
            <h1 className="text-2xl font-bold tracking-tight text-heading">Threat Landscape</h1>
          </div>
          <p className="text-muted text-tool">
            Executive brief on {filteredActors.length} tracked actor{filteredActors.length !== 1 ? 's' : ''} ·{' '}
            {stats.avgActive}yr avg operational lifespan · {stats.totalCampaigns} known campaigns
          </p>
        </header>

        {/* Search & Filter Bar */}
        <div className="surface-card p-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search actors, sectors, malware, CVEs…"
                className="w-full h-9 pl-9 pr-3 rounded-lg text-tool text-muted placeholder:text-muted dark:placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-rose-500/30 transition-all"
                style={{ background: 'var(--ink-700)', border: '1px solid var(--edge)' }}
              />
              {search && (
                <button
                  onClick={() => setSearch('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-muted dark:hover:text-inverted"
                >
                  <X size={12} />
                </button>
              )}
            </div>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-mini font-medium border transition-colors"
              style={{
                borderColor: showFilters ? 'rgba(91,141,239,0.4)' : 'var(--edge)',
                color: showFilters ? 'var(--accent-blue)' : 'var(--text-secondary)',
                background: showFilters ? 'rgba(91,141,239,0.08)' : 'var(--ink-700)',
              }}
            >
              <Filter size={11} /> Filters
              {(sectorFilter || motivationFilter) && <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />}
            </button>
          </div>

          {showFilters && (
            <div
              className="mt-3 pt-3 border-t flex items-center gap-3 flex-wrap"
              style={{ borderColor: 'var(--edge)' }}
            >
              <div className="flex items-center gap-2">
                <span className="text-micro font-mono uppercase tracking-wider text-muted">Sector</span>
                <select
                  value={sectorFilter ?? ''}
                  onChange={(e) => setSectorFilter(e.target.value || null)}
                  className="h-6 px-2 rounded text-mini text-muted border border-line-1 bg-surface-100 outline-none"
                >
                  <option value="">All sectors</option>
                  {allSectors.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-micro font-mono uppercase tracking-wider text-muted">Motivation</span>
                <select
                  value={motivationFilter ?? ''}
                  onChange={(e) => setMotivationFilter(e.target.value || null)}
                  className="h-6 px-2 rounded text-mini text-muted border border-line-1 bg-surface-100 outline-none capitalize"
                >
                  <option value="">All motivations</option>
                  {allMotivations.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-micro font-mono uppercase tracking-wider text-muted">Sort</span>
                {(['threat', 'name', 'date'] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSortBy(s)}
                    className="px-2 py-0.5 rounded text-micro font-mono border capitalize transition-colors"
                    style={
                      sortBy === s
                        ? {
                            background: 'rgba(91,141,239,0.12)',
                            color: 'var(--accent-blue)',
                            borderColor: 'rgba(91,141,239,0.4)',
                          }
                        : { background: 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--edge)' }
                    }
                  >
                    {s}
                  </button>
                ))}
              </div>
              {(sectorFilter || motivationFilter || search) && (
                <button
                  onClick={() => {
                    setSectorFilter(null);
                    setMotivationFilter(null);
                    setSearch('');
                  }}
                  className="flex items-center gap-1 text-micro text-rose-500 hover:text-rose-600 transition-colors"
                >
                  <X size={10} /> Clear all
                </button>
              )}
            </div>
          )}
        </div>

        {/* KPI row */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <KPI label="Actors" value={filteredActors.length} icon={ShieldAlert} />
          <KPI label="TTPs" value={stats.totalTTPs} icon={Target} />
          <KPI label="Malware" value={stats.totalMalware} icon={Globe2} />
          <KPI label="CVEs" value={stats.totalCVEs} icon={BarChart3} />
          <KPI label="Campaigns" value={stats.totalCampaigns} icon={AlertCircle} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Sector heatmap */}
          <div className="surface-card p-5">
            <div className="text-eyebrow font-mono text-muted mb-4">Sector Targeting Heatmap</div>
            <div className="space-y-2.5">
              {stats.sortedSectors.map(([sector, count]) => {
                const pct = (count / maxSector) * 100;
                return (
                  <div key={sector}>
                    <div className="flex justify-between text-meta mb-1">
                      <span className="text-muted capitalize font-medium">{sector}</span>
                      <span className="text-muted font-mono">
                        {count} actor{count !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <div className="h-2.5 rounded-full overflow-hidden" style={{ background: 'var(--ink-600)' }}>
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, background: 'var(--accent-blue)' }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Motivation breakdown */}
          <div className="surface-card p-5">
            <div className="text-eyebrow font-mono text-muted mb-4">Motivation Breakdown</div>
            <div className="space-y-4">
              {Object.entries(stats.motivations)
                .sort((a, b) => b[1] - a[1])
                .map(([mot, count]) => {
                  const motivationActors = filteredActors.filter((a) => a.motivation === mot);
                  const pct = filteredActors.length > 0 ? (count / filteredActors.length) * 100 : 0;
                  return (
                    <div key={mot}>
                      <div className="flex items-center gap-3 mb-1.5">
                        <span className="text-meta text-muted capitalize font-medium w-28 shrink-0">{mot}</span>
                        <div
                          className="flex-1 h-2 rounded-full overflow-hidden"
                          style={{ background: 'var(--ink-600)' }}
                        >
                          <div
                            className="h-full rounded-full bg-accent/60 transition-all duration-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-mini font-mono text-muted w-8 text-right">{count}</span>
                      </div>
                      <div className="flex flex-wrap gap-1 ml-31">
                        {motivationActors.map((a) => (
                          <span
                            key={a.id}
                            className="text-micro font-mono px-1.5 py-0.5 rounded"
                            style={{
                              background: `${NATION_PALETTE[a.country]?.color}15`,
                              color: NATION_PALETTE[a.country]?.color,
                            }}
                          >
                            {a.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>

          {/* Nation attribution */}
          <div className="surface-card p-5">
            <div className="text-eyebrow font-mono text-muted mb-4">Nation Attribution</div>
            <div className="space-y-2">
              {Object.entries(stats.nationCounts)
                .sort((a, b) => b[1] - a[1])
                .map(([code, count]) => {
                  const n = NATION_PALETTE[code];
                  const nationActors = filteredActors.filter((a) => a.country === code);
                  return (
                    <div
                      key={code}
                      className="flex items-center gap-3 p-2 rounded-lg hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                    >
                      <span
                        className="h-7 w-9 rounded flex items-center justify-center text-micro font-mono font-bold shrink-0"
                        style={{ background: `${n?.color ?? '#555'}20`, color: n?.color ?? '#888' }}
                      >
                        {code}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="text-meta text-muted font-medium">{n?.name ?? code}</div>
                        <div className="text-micro font-mono text-muted truncate">
                          {nationActors.map((a) => a.name).join(', ')}
                        </div>
                      </div>
                      <span className="text-meta font-mono font-semibold text-heading shrink-0">{count}</span>
                    </div>
                  );
                })}
            </div>
          </div>

          {/* Recent related feed */}
          <div className="surface-card p-5">
            <div className="text-eyebrow font-mono text-muted mb-4">Recent Related Intel</div>
            <div className="space-y-2">
              {recentFeed.length === 0 && <p className="text-muted text-meta">No recent items match current actors.</p>}
              {recentFeed.map((f) => (
                <a
                  key={f.id}
                  href={f.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block p-2.5 rounded-lg hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors group"
                >
                  <div className="text-[12.5px] text-muted leading-snug group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors">
                    {f.title}
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-micro font-mono text-muted">{f.source}</span>
                    <span className="text-micro text-muted">·</span>
                    <span className="text-micro font-mono text-muted">{f.published}</span>
                  </div>
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function KPI({ label, value, icon: Icon }: { label: string; value: number; icon: typeof ShieldAlert }) {
  return (
    <div className="surface-card p-4 flex items-center gap-3">
      <span className="h-10 w-10 rounded-xl flex items-center justify-center shrink-0 bg-surface-300 text-muted">
        <Icon size={18} />
      </span>
      <div>
        <div className="text-xl sm:text-2xl font-bold font-mono text-heading">{value.toLocaleString()}</div>
        <div className="text-micro font-mono uppercase tracking-[0.18em] text-muted">{label}</div>
      </div>
    </div>
  );
}
