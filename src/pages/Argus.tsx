import { useEffect, useState, useCallback, useMemo, lazy, Suspense } from 'react';
import { Search } from 'lucide-react';
import './argus/argus.css';
import { TabBar } from '../components/ui/TabBar';
import { Spotlight } from './argus/components/Spotlight';
import { Dossier } from './argus/components/Dossier';
import { ACTORS } from './argus/data/actors';
import { FEED_ITEMS } from './argus/data/feed';
import { NATION_PALETTE } from './argus/data/countries';
import type { Actor, GroupType, ViewKey } from './argus/types';

// Each view is a separate chunk. Keeping the import in a named loader lets the
// tab bar warm the chunk on hover/focus, so switching views feels immediate.
const loadGlobe = () => import('./argus/views/GlobeView').then((m) => ({ default: m.GlobeView }));
const loadCluster = () => import('./argus/views/ClusterView').then((m) => ({ default: m.ClusterView }));
const loadDiamond = () => import('./argus/views/DiamondView').then((m) => ({ default: m.DiamondView }));
const loadLandscape = () => import('./argus/views/LandscapeView').then((m) => ({ default: m.LandscapeView }));
const loadFeed = () => import('./argus/views/FeedView').then((m) => ({ default: m.FeedView }));
const loadHunt = () => import('./argus/views/HuntView').then((m) => ({ default: m.HuntView }));

const VIEW_LOADERS: Record<ViewKey, () => Promise<unknown>> = {
  globe: loadGlobe,
  cluster: loadCluster,
  diamond: loadDiamond,
  landscape: loadLandscape,
  feed: loadFeed,
  hunt: loadHunt,
};

const GlobeView = lazy(loadGlobe);
const ClusterView = lazy(loadCluster);
const DiamondView = lazy(loadDiamond);
const LandscapeView = lazy(loadLandscape);
const FeedView = lazy(loadFeed);
const HuntView = lazy(loadHunt);

const VIEW_TABS: { id: ViewKey; label: string }[] = [
  { id: 'globe', label: 'Globe' },
  { id: 'cluster', label: 'Relations' },
  { id: 'diamond', label: 'Diamond' },
  { id: 'landscape', label: 'Landscape' },
  { id: 'feed', label: 'Feed' },
  { id: 'hunt', label: 'Hunt' },
];

const NATIONS = Object.fromEntries(Object.entries(NATION_PALETTE).map(([code, n]) => [code, n.name]));

const GROUP_TYPES: { value: GroupType; label: string }[] = [
  { value: 'nation-state', label: 'Nation-State' },
  { value: 'criminal', label: 'Criminal' },
  { value: 'collective', label: 'Collective' },
];

const selectCls =
  'h-9 px-2.5 rounded-control border border-line-input bg-surface-100 text-mini font-mono uppercase tracking-wider outline-none hover:border-line-3 focus:border-rose-400 cursor-pointer transition-colors';

/** A single lowercased haystack per actor, built once instead of per keystroke. */
function searchText(a: Actor): string {
  return [
    a.name,
    a.apt ?? '',
    a.mitre_id ?? '',
    a.agency,
    a.description,
    a.aka.join(' '),
    a.sectors.join(' '),
    a.targets.join(' '),
    a.ttps.map((t) => `${t.id} ${t.name} ${t.tactic}`).join(' '),
    a.malware.map((m) => `${m.name} ${m.type} ${m.platform}`).join(' '),
    a.cves.map((c) => `${c.id} ${c.product}`).join(' '),
    a.campaigns.map((c) => `${c.name} ${c.summary}`).join(' '),
    a.detections.map((d) => d.title).join(' '),
    a.infra_patterns.join(' '),
  ]
    .join(' ')
    .toLowerCase();
}

export default function ArgusPage() {
  const [view, setView] = useState<ViewKey>('globe');
  const [activeActor, setActiveActor] = useState<Actor | null>(null);
  const [spotlightOpen, setSpotlightOpen] = useState(false);
  const [regionFilter, setRegionFilter] = useState<string | null>(null);
  const [motivationFilter, setMotivationFilter] = useState<string | null>(null);
  const [groupTypeFilter, setGroupTypeFilter] = useState<GroupType | null>(null);
  const [sectorFilter, setSectorFilter] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const allSectors = useMemo(() => {
    const s = new Set<string>();
    ACTORS.forEach((a) => a.sectors.forEach((sec) => s.add(sec)));
    return [...s].sort();
  }, []);

  const searchIndex = useMemo(() => new Map(ACTORS.map((a) => [a.id, searchText(a)])), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isMod = e.metaKey || e.ctrlKey;
      if (isMod && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSpotlightOpen((o) => !o);
      }
      if (e.key === 'Escape') {
        setActiveActor(null);
        setSpotlightOpen(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const openActor = useCallback((a: Actor) => setActiveActor(a), []);
  const closeActor = useCallback(() => setActiveActor(null), []);

  const prefetchView = useCallback((id: string) => {
    const load = VIEW_LOADERS[id as ViewKey];
    if (load) void Promise.resolve(load()).catch(() => {});
  }, []);

  const onSpotlightSelect = (actorId: string) => {
    const a = ACTORS.find((x) => x.id === actorId);
    if (a) {
      setActiveActor(a);
      setSpotlightOpen(false);
    }
  };

  const visible = ACTORS.filter((a) => {
    if (regionFilter && a.country !== regionFilter) return false;
    if (motivationFilter && a.motivation !== motivationFilter) return false;
    if (groupTypeFilter && a.group_type !== groupTypeFilter) return false;
    if (sectorFilter && !a.sectors.includes(sectorFilter)) return false;
    if (searchQuery && !searchIndex.get(a.id)?.includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const hasFilters = Boolean(regionFilter || motivationFilter || groupTypeFilter || sectorFilter || searchQuery);
  const clearFilters = useCallback(() => {
    setSearchQuery('');
    setRegionFilter(null);
    setMotivationFilter(null);
    setGroupTypeFilter(null);
    setSectorFilter(null);
  }, []);

  const nationCount = new Set(ACTORS.map((a) => a.country)).size;
  const totalTtps = ACTORS.reduce((s, a) => s + a.ttps.length, 0);

  return (
    <div className="w-full py-6 sm:py-8 space-y-5">
      {/* ── Header ────────────────────────────────────────────────────
          Quiet by design: the counts read as one line of meta data instead
          of a four-tile hero-metric grid competing with the working views. */}
      <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-4 border-b border-line-1 pb-5">
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-mono text-micro uppercase tracking-[0.16em] text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-500" aria-hidden="true" />
            <span>Live</span>
            <span className="text-inverted">/</span>
            <span>Nation-state CTI</span>
          </div>
          <h1 className="mt-2.5 font-display text-3xl sm:text-4xl font-semibold leading-tight tracking-tight text-heading">
            Argus <span className="text-rose-600 dark:text-rose-400">Threat Nexus</span>
          </h1>
          <p className="mt-2 max-w-2xl text-tool leading-relaxed text-muted">
            Track {ACTORS.length} APT groups across {nationCount} nations, with {totalTtps} mapped MITRE TTPs,
            relationship graphs and a live intel feed.
          </p>
        </div>
        <p className="max-w-full font-mono text-micro uppercase tracking-[0.08em] text-muted tabular-nums sm:text-right">
          {ACTORS.length} groups <span className="text-inverted">·</span> {nationCount} nations{' '}
          <span className="text-inverted">·</span> {totalTtps} TTPs <span className="text-inverted">·</span>{' '}
          {FEED_ITEMS.length} items
        </p>
      </header>

      {/* ── View tabs ─────────────────────────────────────────────── */}
      <TabBar
        tabs={VIEW_TABS}
        active={view}
        onChange={(id) => setView(id as ViewKey)}
        label="ARGUS views"
        variant="underline"
        onPrefetch={prefetchView}
        className="mb-0"
      />

      {/* ── Filter toolbar ────────────────────────────────────────── */}
      <div className="surface-card p-3 flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search actors, CVEs, TTPs, malware…"
            aria-label="Search actors, CVEs, TTPs and malware"
            className="w-full h-9 pl-9 pr-3 rounded-control bg-input-200 border border-line-input text-tool text-heading placeholder:text-muted outline-none focus:border-rose-400 transition-colors"
          />
        </div>

        <select
          aria-label="Filter by nation"
          value={regionFilter ?? ''}
          onChange={(e) => setRegionFilter(e.target.value || null)}
          className={`${selectCls} ${regionFilter ? 'text-heading' : 'text-muted'}`}
        >
          <option value="">All nations</option>
          {Object.entries(NATIONS).map(([code, name]) => (
            <option key={code} value={code}>
              {name}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by motivation"
          value={motivationFilter ?? ''}
          onChange={(e) => setMotivationFilter(e.target.value || null)}
          className={`${selectCls} ${motivationFilter ? 'text-heading' : 'text-muted'}`}
        >
          <option value="">Any motive</option>
          <option value="espionage">Espionage</option>
          <option value="financial">Financial</option>
          <option value="destructive">Destructive</option>
          <option value="mixed">Mixed</option>
          <option value="surveillance">Surveillance</option>
        </select>

        <select
          aria-label="Filter by group type"
          value={groupTypeFilter ?? ''}
          onChange={(e) => setGroupTypeFilter((e.target.value as GroupType) || null)}
          className={`${selectCls} ${groupTypeFilter ? 'text-heading' : 'text-muted'}`}
        >
          <option value="">All groups</option>
          {GROUP_TYPES.map((gt) => (
            <option key={gt.value} value={gt.value}>
              {gt.label}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by sector"
          value={sectorFilter ?? ''}
          onChange={(e) => setSectorFilter(e.target.value || null)}
          className={`${selectCls} ${sectorFilter ? 'text-heading' : 'text-muted'}`}
        >
          <option value="">All sectors</option>
          {allSectors.map((s) => (
            <option key={s} value={s}>
              {s.replace(/-/g, ' ')}
            </option>
          ))}
        </select>

        {hasFilters && (
          <button
            type="button"
            onClick={clearFilters}
            className="h-9 px-2.5 rounded-control border border-line-input text-mini font-mono uppercase tracking-wider text-muted hover:text-heading hover:bg-surface-300 transition-colors"
          >
            Clear
          </button>
        )}

        <span className="ml-auto font-mono text-micro uppercase tracking-wider text-muted tabular-nums">
          {visible.length}/{ACTORS.length} actors
        </span>
      </div>

      {/* ── Active view ───────────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-panel border border-line-1 bg-surface-100 min-h-[520px]">
        <div className="relative h-[60vh] min-h-[480px] max-h-[760px]">
          <Suspense
            fallback={
              <div className="absolute inset-0 grid place-items-center">
                <div className="flex flex-col items-center gap-3 text-muted">
                  <span className="h-6 w-6 rounded-full border-2 border-line-2 border-t-rose-500 animate-spin" />
                  <span className="font-mono text-micro uppercase tracking-[0.16em]">Loading view</span>
                </div>
              </div>
            }
          >
            {view === 'globe' && <GlobeView actors={visible} onOpen={openActor} />}
            {view === 'cluster' && <ClusterView actors={visible} onOpen={openActor} />}
            {view === 'diamond' && <DiamondView actors={visible} onOpen={openActor} />}
            {view === 'landscape' && <LandscapeView actors={visible} feed={FEED_ITEMS} />}
            {view === 'feed' && <FeedView feed={FEED_ITEMS} actors={ACTORS} onOpen={openActor} />}
            {view === 'hunt' && <HuntView actors={visible} />}
          </Suspense>
        </div>
      </div>

      <Dossier actor={activeActor} onClose={closeActor} onOpen={openActor} />
      <Spotlight open={spotlightOpen} onClose={() => setSpotlightOpen(false)} onSelect={onSpotlightSelect} />
    </div>
  );
}
