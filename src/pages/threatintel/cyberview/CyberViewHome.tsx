import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  ArrowUpDown,
  Globe2,
  Home,
  Keyboard,
  Layers,
  List,
  MapPin,
  Maximize2,
  Minus,
  Plus,
  RefreshCw,
  Search,
  Table2,
  X,
  Zap,
} from 'lucide-react';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { relativeAgo } from '../../../lib/relativeTime';
import { ThreatGlobe3D, type GlobeMarker } from '../../../components/ThreatGlobe3D';
import { asArray, fmtDay, matches, text, topCounts } from './shared-utils';
import { Badge, CyberViewPage, Empty, OutLink } from './shared-ui';

/** Replication of the public CyberView home page (xanderhutch.github.io/CyberView).
 * Every number is derived from public/data/cyberview/data/events.json. */
interface CvValidation {
  state: string;
  note?: string;
  checked_at?: string;
}
interface CvSource {
  name: string;
  url: string;
}
interface CvEvent {
  id: string;
  category: string;
  severity: number;
  status: string;
  date: string;
  country: string;
  place: string;
  lat: number | null;
  lng: number | null;
  org: string;
  sector: string;
  title: string;
  summary: string;
  plain: string;
  exec: string;
  action: string;
  tags: string[];
  cves: string[];
  sources: CvSource[];
  source_tier: string;
  validation: CvValidation;
  first_seen: string;
  updated_at: string;
}
type View = 'globe' | 'timeline' | 'grid';
type PanelTab = 'feed' | 'exploited' | 'patterns' | 'insights' | 'brief';
type SeverityFilter = 'all' | 'med' | 'high';
const EMPTY: CvEvent[] = [];
const EMPTY_DATES: string[] = [];
const DAY_MS = 86_400_000;
const MAP_W = 1000;
const MAP_H = 500;
const VIEWS: Array<{ id: View; label: string; icon: typeof Globe2 }> = [
  { id: 'globe', label: 'Globe', icon: Globe2 },
  { id: 'timeline', label: 'Timeline', icon: List },
  { id: 'grid', label: 'Grid', icon: Table2 },
];
const TABS: Array<{ id: PanelTab; label: string }> = [
  { id: 'feed', label: 'Feed' },
  { id: 'exploited', label: 'Exploited' },
  { id: 'patterns', label: 'Patterns' },
  { id: 'insights', label: 'Insights' },
  { id: 'brief', label: 'Brief' },
];
const CATEGORIES: Array<{ id: string; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'incident', label: 'Incident' },
  { id: 'report', label: 'Threat report' },
  { id: 'vuln', label: 'Patch/advisory' },
  { id: 'policy', label: 'Law & policy' },
  { id: 'enforcement', label: 'Law enforcement' },
  { id: 'investment', label: 'Investment & vendors' },
  { id: 'outage', label: 'Outage' },
];
const CATEGORY_LABEL: Record<string, string> = {
  incident: 'Incident',
  report: 'Threat report',
  vuln: 'Patch / advisory',
  policy: 'Law / policy',
  enforcement: 'Law enforcement',
  investment: 'Investment / vendor',
  outage: 'Outage',
};
const SEVERITY_LABEL: Record<number, string> = { 1: 'Low', 2: 'Medium', 3: 'High' };
const SEVERITY_COLOR: Record<number, string> = { 1: '#0ea5e9', 2: '#f59e0b', 3: '#f43f5e' };
const SEVERITY_BADGE: Record<number, string> = {
  1: 'border-sky-500/40 text-sky-700 dark:text-sky-300',
  2: 'border-amber-500/40 text-amber-700 dark:text-amber-300',
  3: 'border-rose-500/40 text-rose-700 dark:text-rose-300',
};
const SEVERITY_OPTIONS: Array<[SeverityFilter, string]> = [
  ['all', 'All'],
  ['med', 'Med+'],
  ['high', 'High'],
];
/* Rough, hand-drawn continent outlines in [longitude, latitude] pairs. */
const CONTINENTS: Array<Array<[number, number]>> = [
  [
    [-168, 66],
    [-150, 70],
    [-130, 60],
    [-124, 48],
    [-117, 32],
    [-106, 24],
    [-97, 20],
    [-86, 21],
    [-81, 26],
    [-80, 10],
    [-90, 14],
    [-96, 17],
    [-106, 20],
    [-115, 29],
    [-124, 40],
    [-132, 54],
    [-150, 60],
    [-166, 60],
  ],
  [
    [-81, 10],
    [-72, 11],
    [-60, 6],
    [-50, 0],
    [-35, -6],
    [-39, -16],
    [-48, -25],
    [-53, -34],
    [-65, -55],
    [-73, -50],
    [-72, -38],
    [-71, -18],
    [-78, -5],
  ],
  [
    [-11, 36],
    [-9, 43],
    [-2, 48],
    [2, 51],
    [8, 54],
    [13, 55],
    [20, 55],
    [28, 60],
    [30, 68],
    [20, 70],
    [10, 60],
    [4, 52],
    [-5, 44],
  ],
  [
    [-17, 15],
    [-5, 20],
    [10, 22],
    [25, 32],
    [33, 31],
    [43, 12],
    [51, 12],
    [45, -12],
    [38, -18],
    [32, -28],
    [20, -35],
    [12, -18],
    [8, -2],
    [-5, 4],
    [-13, 8],
  ],
  [
    [26, 40],
    [35, 45],
    [45, 48],
    [55, 52],
    [70, 55],
    [85, 58],
    [100, 60],
    [115, 58],
    [130, 50],
    [142, 46],
    [140, 36],
    [128, 35],
    [122, 28],
    [110, 20],
    [100, 10],
    [95, 16],
    [88, 22],
    [78, 9],
    [70, 20],
    [60, 25],
    [50, 28],
    [40, 35],
  ],
  [
    [113, -22],
    [122, -18],
    [132, -12],
    [142, -11],
    [146, -19],
    [153, -27],
    [148, -38],
    [138, -38],
    [125, -34],
    [115, -30],
  ],
  [
    [-52, 60],
    [-40, 64],
    [-25, 70],
    [-20, 78],
    [-35, 83],
    [-55, 80],
    [-60, 70],
  ],
];
function project(lng: number, lat: number): [number, number] {
  return [((lng + 180) / 360) * MAP_W, ((90 - lat) / 180) * MAP_H];
}
function polygonPath(points: Array<[number, number]>): string {
  return (
    points
      .map(([lng, lat], i) => {
        const [x, y] = project(lng, lat);
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ') + ' Z'
  );
}
function dayMs(date: string): number {
  const t = Date.parse(`${date}T00:00:00Z`);
  return Number.isFinite(t) ? t : 0;
}
function isUnverified(event: CvEvent): boolean {
  const state = text(event.validation?.state);
  return state === 'unconfirmed_claim' || state === 'disputed' || event.status === 'claimed';
}
function sortEvents(events: CvEvent[], sort: 'priority' | 'recent'): CvEvent[] {
  return [...events].sort((a, b) =>
    sort === 'priority'
      ? b.severity - a.severity || b.date.localeCompare(a.date) || text(b.first_seen).localeCompare(text(a.first_seen))
      : text(b.first_seen).localeCompare(text(a.first_seen)) || b.date.localeCompare(a.date)
  );
}
/* Small presentational helpers for the repeated card/list/button markup. */
function Tag({ children, className = '' }: { children: ReactNode; className?: string }): JSX.Element {
  return <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${className}`}>{children}</span>;
}
function Choice({
  active,
  onClick,
  children,
  label,
  brand = false,
  className = '',
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
  label?: string;
  brand?: boolean;
  className?: string;
}): JSX.Element {
  const cls = brand ? 'rounded' : 'rounded-control border';
  const on = brand ? 'bg-brand-600 text-on-fill' : 'border-accent-text/50 bg-wash text-accent-text';
  return (
    <button
      type="button"
      aria-pressed={active}
      aria-label={label}
      onClick={onClick}
      className={`${cls} px-2 py-1 font-mono text-[11px] ${active ? on : 'border-line-1 text-muted hover:text-heading'} ${className}`}
    >
      {children}
    </button>
  );
}
function IconBtn({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
}): JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      className="grid h-7 w-7 place-items-center rounded-control border border-line-1 text-muted hover:bg-wash hover:text-heading"
    >
      {children}
    </button>
  );
}
function HeaderBtn({
  label,
  onClick,
  children,
  active,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
  active?: boolean;
}): JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      aria-pressed={active}
      className={`rounded-control border px-2 py-1.5 font-mono text-[11px] ${active ? 'border-accent-text/50 bg-wash text-accent-text' : 'border-line-1 text-muted hover:text-heading'}`}
    >
      {children}
    </button>
  );
}
function EventCard({
  event,
  selected,
  onSelect,
  compact,
}: {
  event: CvEvent;
  selected: boolean;
  onSelect: (id: string) => void;
  compact: boolean;
}): JSX.Element {
  const cves = asArray(event.cves);
  const source = asArray(event.sources)[0];
  return (
    <article
      className={`surface-card rounded-lg border ${selected ? 'border-accent-text/60 bg-wash' : 'border-line-1'} ${compact ? 'p-2' : 'p-3'}`}
    >
      <button type="button" aria-pressed={selected} onClick={() => onSelect(event.id)} className="w-full text-left">
        <span className="flex flex-wrap items-center gap-1.5">
          <Tag className="border-line-1 text-muted">{CATEGORY_LABEL[event.category] ?? text(event.category)}</Tag>
          <span className="font-mono text-[10px] text-muted">{fmtDay(event.date)}</span>
          <Tag className={`font-bold ${SEVERITY_BADGE[event.severity] ?? ''}`}>
            {SEVERITY_LABEL[event.severity] ?? 'Unknown'}
          </Tag>
          {event.source_tier === 'primary' && (
            <Tag className="border-emerald-500/40 text-emerald-700 dark:text-emerald-300">Primary source</Tag>
          )}
          {cves.length > 0 && (
            <Tag className="border-rose-500/40 text-rose-700 dark:text-rose-300">
              {cves.length} CVE{cves.length === 1 ? '' : 's'}
            </Tag>
          )}
        </span>
        <span className="mt-1.5 block text-sm font-semibold leading-snug text-heading">{text(event.title)}</span>
        {!compact && (
          <span className="mt-1 block line-clamp-2 text-xs leading-relaxed text-muted">{text(event.summary)}</span>
        )}
        <span className="mt-1 flex items-center gap-1 font-mono text-[10px] text-muted">
          <MapPin size={10} aria-hidden="true" /> {text(event.place) || text(event.country) || 'Location not stated'}
        </span>
        {event.action && (
          <span className="mt-2 block rounded border border-line-1 bg-surface-100 px-2 py-1.5 text-xs leading-relaxed text-body">
            <strong className="text-heading">Do: </strong>
            {text(event.action)}
          </span>
        )}
      </button>
      {source?.url && (
        <OutLink
          href={text(source.url)}
          className="mt-2 inline-flex items-center gap-1 font-mono text-[10px] text-accent-text hover:underline"
        >
          {text(source.name) || 'Source'}
        </OutLink>
      )}
    </article>
  );
}
function RankedList({ title, rows }: { title: string; rows: Array<[string, number]> }): JSX.Element {
  return (
    <div>
      <h3 className="font-mono text-[11px] font-bold uppercase tracking-wide text-heading">{title}</h3>
      <ol className="mt-1.5 space-y-1">
        {rows.map(([name, count], i) => (
          <li key={name} className="flex items-baseline gap-2 text-xs">
            <span className="w-4 font-mono text-[10px] text-muted">{i + 1}.</span>
            <span className="min-w-0 flex-1 truncate text-body" title={name}>
              {name}
            </span>
            <span className="font-mono text-[10px] text-muted">{count}</span>
          </li>
        ))}
      </ol>
      {rows.length === 0 && <p className="mt-1 font-mono text-[10px] text-muted">No data.</p>}
    </div>
  );
}

export default function CyberViewHome({ bare = false }: { bare?: boolean }): JSX.Element {
  const events = useDataFetch<CvEvent[]>({ url: '/data/cyberview/data/events.json', ttl: 600_000 });
  const [view, setView] = useState<View>('globe');
  const [category, setCategory] = useState('all');
  const [showUnverified, setShowUnverified] = useState(false);
  const [windowDays, setWindowDays] = useState(7);
  const [minSeverity, setMinSeverity] = useState<SeverityFilter>('all');
  const [query, setQuery] = useState('');
  const [dayFilter, setDayFilter] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>('feed');
  const [sort, setSort] = useState<'priority' | 'recent'>('priority');
  const [zoom, setZoom] = useState(1);
  const [map3d, setMap3d] = useState(true);
  const [showLayers, setShowLayers] = useState(false);
  const [wall, setWall] = useState(false);
  const [help, setHelp] = useState(false);
  const [patternBy, setPatternBy] = useState<'sector' | 'tag'>('sector');
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent): void {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      if (e.key === '?') setHelp((v) => !v);
      else if (e.key === 'Escape') {
        setSelectedId(null);
        setDayFilter(null);
      } else if (e.key === 'g') setView('globe');
      else if (e.key === 't') setView('timeline');
      else if (e.key === 'r') setView('grid');
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);
  const all = events.data ?? EMPTY;
  const maxDate = useMemo(() => all.reduce((m, e) => Math.max(m, dayMs(e.date)), 0), [all]);
  const builtAt = useMemo(
    () =>
      all.reduce((m, e) => {
        const v = text(e.updated_at);
        return v > m ? v : m;
      }, ''),
    [all]
  );
  const builtTime = Date.parse(builtAt);
  const builtLabel = Number.isFinite(builtTime)
    ? `${new Date(builtTime).toISOString().replace('T', ' ').slice(0, 16)} UTC`
    : 'unknown';
  const windowDates = useMemo(
    () =>
      maxDate
        ? Array.from({ length: windowDays }, (_, i) =>
            new Date(maxDate - (windowDays - 1 - i) * DAY_MS).toISOString().slice(0, 10)
          )
        : EMPTY_DATES,
    [maxDate, windowDays]
  );
  const windowSet = useMemo(() => new Set(windowDates), [windowDates]);
  const windowEvents = useMemo(() => all.filter((e) => windowSet.has(e.date)), [all, windowSet]);
  const preDay = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return windowEvents.filter((e) => {
      if (!showUnverified && isUnverified(e)) return false;
      if (minSeverity === 'med' && e.severity < 2) return false;
      if (minSeverity === 'high' && e.severity < 3) return false;
      if (needle && !matches(`${text(e.title)} ${text(e.summary)} ${text(e.country)} ${text(e.org)}`, needle))
        return false;
      return true;
    });
  }, [windowEvents, showUnverified, minSeverity, query]);
  const dayCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    windowDates.forEach((d) => {
      counts[d] = 0;
    });
    preDay.forEach((e) => {
      counts[e.date] = (counts[e.date] ?? 0) + 1;
    });
    return counts;
  }, [preDay, windowDates]);
  const base = useMemo(() => (dayFilter ? preDay.filter((e) => e.date === dayFilter) : preDay), [preDay, dayFilter]);
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = { all: base.length };
    base.forEach((e) => {
      counts[e.category] = (counts[e.category] ?? 0) + 1;
    });
    return counts;
  }, [base]);
  const filtered = useMemo(
    () => (category === 'all' ? base : base.filter((e) => e.category === category)),
    [base, category]
  );
  const plotted = useMemo(
    () =>
      filtered.filter(
        (e) => typeof e.lat === 'number' && typeof e.lng === 'number' && (showLayers || e.category !== 'outage')
      ),
    [filtered, showLayers]
  );
  const globeMarkers = useMemo<GlobeMarker[]>(
    () =>
      plotted.map((e) => ({
        id: text(e.id),
        lat: Number(e.lat),
        lng: Number(e.lng),
        color: SEVERITY_COLOR[e.severity] ?? SEVERITY_COLOR[2]!,
        label: `${text(e.title)} — ${SEVERITY_LABEL[e.severity] ?? 'unknown'} · ${text(e.country)}`,
        size: e.severity === 3 ? 1.25 : e.severity === 1 ? 0.8 : 1,
      })),
    [plotted]
  );
  const highCount = useMemo(() => filtered.filter((e) => e.severity === 3).length, [filtered]);
  const unverifiedHidden = useMemo(() => windowEvents.filter(isUnverified).length, [windowEvents]);
  const sorted = useMemo(() => sortEvents(filtered, sort), [filtered, sort]);
  const justAdded = useMemo(
    () => [...filtered].sort((a, b) => text(b.first_seen).localeCompare(text(a.first_seen))).slice(0, 5),
    [filtered]
  );
  const selected = selectedId ? (all.find((e) => e.id === selectedId) ?? null) : null;
  const exploited = useMemo(() => filtered.filter((e) => asArray(e.cves).length > 0 || e.severity === 3), [filtered]);
  const panelRows = useMemo(
    () => sortEvents(tab === 'exploited' ? exploited : filtered, sort),
    [tab, exploited, filtered, sort]
  );
  const panelTotal = tab === 'exploited' ? exploited.length : filtered.length;
  /* Grouping guards non-string sector/tag values — upstream can omit them. */
  const patternRows = useMemo(() => {
    const counts = new Map<string, number>();
    filtered.forEach((e) => {
      const values: Array<string | undefined> = patternBy === 'sector' ? [e.sector] : asArray(e.tags);
      values.forEach((v) => {
        const key = text(v).trim();
        if (key) counts.set(key, (counts.get(key) ?? 0) + 1);
      });
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  }, [filtered, patternBy]);
  const topCountries = useMemo(
    () =>
      topCounts(
        filtered.map((e) => e.country),
        8
      ),
    [filtered]
  );
  const topOrgs = useMemo(
    () =>
      topCounts(
        filtered.map((e) => e.org),
        8
      ),
    [filtered]
  );
  const brief = useMemo(() => {
    const withCve = filtered.filter((e) => asArray(e.cves).length > 0).length;
    const countries = new Set(filtered.map((e) => text(e.country)).filter(Boolean)).size;
    const lead = topCounts(
      filtered.map((e) => e.country),
      1
    )[0];
    const theme = topCounts(
      filtered.flatMap((e) => asArray(e.tags)),
      1
    )[0];
    return `Over the last ${windowDays} days, CyberView recorded ${filtered.length} cyber events across ${countries} countries and territories. ${highCount} were rated high priority and ${withCve} cite known CVEs. ${
      lead ? `${lead[0]} led with ${lead[1]} event${lead[1] === 1 ? '' : 's'}. ` : ''
    }${theme ? `The most common tag was “${theme[0]}” (${theme[1]} event${theme[1] === 1 ? '' : 's'}). ` : ''}Open any card below for the specific action CyberView recommends.`;
  }, [filtered, windowDays, highCount]);
  function toggleFullscreen(): void {
    try {
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => undefined);
      else void document.documentElement.requestFullscreen().catch(() => undefined);
    } catch {
      /* Fullscreen can be blocked by the embedding context; ignore. */
    }
  }
  function moveTab(direction: number): void {
    const index = TABS.findIndex((t) => t.id === tab);
    const next = TABS[(index + direction + TABS.length) % TABS.length]!;
    setTab(next.id);
    document.getElementById(`cv-tab-${next.id}`)?.focus();
  }
  const pad = wall ? 'p-2' : 'p-4';
  const gap = wall ? 'gap-2' : 'gap-4';
  const zoomTransform = `translate(${MAP_W / 2} ${MAP_H / 2}) scale(${zoom}) translate(${-MAP_W / 2} ${-MAP_H / 2})`;
  const markerR = 3.2 / zoom;
  const stage = (
    <section
      className={`surface-card overflow-hidden rounded-xl border border-line-1 bg-surface-100 ${wall ? 'p-2' : 'p-3'}`}
      aria-label="World map of cyber events"
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[11px] text-muted">
          <span className="font-semibold text-heading">World map</span> · {plotted.length} markers ·{' '}
          {map3d ? '3D globe (drag to turn, scroll to zoom)' : 'equirectangular'} · {fmtDay(windowDates[0] ?? '')}–
          {fmtDay(windowDates[windowDates.length - 1] ?? '')}
        </p>
        <div className="flex flex-wrap items-center gap-1">
          <Choice active={map3d} onClick={() => setMap3d(true)}>
            <Globe2 size={12} aria-hidden="true" /> 3D
          </Choice>
          <Choice active={!map3d} onClick={() => setMap3d(false)}>
            <MapPin size={12} aria-hidden="true" /> 2D
          </Choice>
          {!map3d && (
            <>
              <IconBtn label="Zoom in" onClick={() => setZoom((z) => Math.min(3, +(z + 0.4).toFixed(1)))}>
                <Plus size={14} />
              </IconBtn>
              <IconBtn label="Zoom out" onClick={() => setZoom((z) => Math.max(1, +(z - 0.4).toFixed(1)))}>
                <Minus size={14} />
              </IconBtn>
              <IconBtn label="Reset map view" onClick={() => setZoom(1)}>
                <Home size={13} />
              </IconBtn>
            </>
          )}
          <Choice active={showLayers} onClick={() => setShowLayers((v) => !v)} className="ml-1">
            <Layers size={12} aria-hidden="true" /> Map layers
          </Choice>
        </div>
      </div>
      {map3d ? (
        <div className="relative h-[min(62vh,620px)] w-full overflow-hidden rounded-lg border border-line-1 bg-[#050814]">
          <ThreatGlobe3D markers={globeMarkers} onSelect={setSelectedId} />
        </div>
      ) : (
        <svg
          viewBox={`0 0 ${MAP_W} ${MAP_H}`}
          className="w-full rounded-lg border border-line-1"
          role="img"
          aria-label="World map with event markers"
        >
          <rect width={MAP_W} height={MAP_H} className="fill-surface-100" />
          <g transform={zoomTransform}>
            <g className="text-line-1" stroke="currentColor" strokeWidth={0.7} fill="none" opacity={0.5}>
              {Array.from({ length: 11 }, (_, i) => (
                <line key={`v${i}`} x1={(i * MAP_W) / 10} y1={0} x2={(i * MAP_W) / 10} y2={MAP_H} />
              ))}
              {Array.from({ length: 7 }, (_, i) => (
                <line key={`h${i}`} x1={0} y1={(i * MAP_H) / 6} x2={MAP_W} y2={(i * MAP_H) / 6} />
              ))}
              <line x1={0} y1={MAP_H / 2} x2={MAP_W} y2={MAP_H / 2} strokeWidth={1} strokeDasharray="4 4" />
            </g>
            <g className="text-surface-200" fill="currentColor" stroke="currentColor" strokeWidth={0.8} opacity={0.95}>
              {CONTINENTS.map((poly, i) => (
                <path key={i} d={polygonPath(poly)} />
              ))}
            </g>
            {plotted.map((e) => {
              const [x, y] = project(e.lng as number, e.lat as number);
              const color = SEVERITY_COLOR[e.severity] ?? SEVERITY_COLOR[2];
              const active = selectedId === e.id;
              return (
                <g
                  key={e.id}
                  role="button"
                  tabIndex={0}
                  className="cursor-pointer focus:outline-none"
                  aria-label={`${text(e.title)} — ${SEVERITY_LABEL[e.severity] ?? 'unknown'} severity, ${text(e.country)}`}
                  onMouseEnter={() => setSelectedId(e.id)}
                  onFocus={() => setSelectedId(e.id)}
                  onClick={() => setSelectedId(e.id)}
                  onKeyDown={(ev) => {
                    if (ev.key === 'Enter' || ev.key === ' ') {
                      ev.preventDefault();
                      setSelectedId(e.id);
                    }
                  }}
                >
                  <title>{text(e.title)}</title>
                  <circle cx={x} cy={y} r={markerR * 2.8} fill={color} opacity={active ? 0.32 : 0.16} />
                  <circle
                    cx={x}
                    cy={y}
                    r={markerR}
                    fill={color}
                    stroke={active ? '#ffffff' : 'transparent'}
                    strokeWidth={active ? 1.6 : 0}
                  />
                </g>
              );
            })}
          </g>
        </svg>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] text-muted">
        {([3, 2, 1] as const).map((s) => (
          <span key={s} className="inline-flex items-center gap-1">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[s] }} /> {SEVERITY_LABEL[s]}
          </span>
        ))}
        <span className="ml-auto">
          Outage context {showLayers ? 'shown' : 'hidden'} · hover or click a marker for detail
        </span>
      </div>
    </section>
  );
  const dayMax = Math.max(1, ...windowDates.map((d) => dayCounts[d] ?? 0));
  const timeline = (
    <section
      className={`surface-card space-y-2 rounded-xl border border-line-1 ${pad}`}
      aria-label="Timeline of events per day"
    >
      <div className="flex items-center gap-2">
        <Activity size={14} className="text-accent-text" aria-hidden="true" />
        <h3 className="font-mono text-xs font-bold text-heading">Timeline · events per day</h3>
      </div>
      {windowDates.map((d) => {
        const count = dayCounts[d] ?? 0;
        const dayEvents = preDay.filter((e) => e.date === d);
        return (
          <div key={d} className="rounded-lg border border-line-1 p-2">
            <button
              type="button"
              onClick={() => setDayFilter(dayFilter === d ? null : d)}
              aria-pressed={dayFilter === d}
              className="flex w-full items-center gap-3 text-left"
            >
              <span className="w-16 shrink-0 font-mono text-[11px] font-bold text-heading">{fmtDay(d)}</span>
              <span className="h-3 flex-1 overflow-hidden rounded bg-surface-200">
                <span className="block h-full rounded bg-brand-600" style={{ width: `${(count / dayMax) * 100}%` }} />
              </span>
              <span className="w-8 text-right font-mono text-[11px] text-muted">{count}</span>
            </button>
            {dayEvents.length > 0 && (
              <ul className="mt-1.5 flex flex-wrap gap-1">
                {dayEvents.slice(0, 4).map((e) => (
                  <li key={e.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(e.id)}
                      title={text(e.title)}
                      className="max-w-[240px] truncate rounded border border-line-1 px-1.5 py-0.5 font-mono text-[10px] text-muted hover:text-accent-text"
                    >
                      {text(e.title)}
                    </button>
                  </li>
                ))}
                {dayEvents.length > 4 && (
                  <li className="font-mono text-[10px] text-muted">+{dayEvents.length - 4} more</li>
                )}
              </ul>
            )}
          </div>
        );
      })}
    </section>
  );
  const grid = (
    <section className={`surface-card overflow-hidden rounded-xl border border-line-1 ${pad}`} aria-label="Event grid">
      <div className="mb-2 flex items-center gap-2">
        <Table2 size={14} className="text-accent-text" aria-hidden="true" />
        <h3 className="font-mono text-xs font-bold text-heading">Grid · {sorted.length} events</h3>
      </div>
      <div className="max-h-[560px] overflow-auto">
        <table className="w-full border-collapse text-left">
          <thead className="sticky top-0 bg-surface-200 font-mono text-[10px] uppercase tracking-wide text-muted">
            <tr>
              {['Date', 'Severity', 'Category', 'Event', 'Country'].map((h) => (
                <th key={h} scope="col" className="px-2 py-2">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((e) => (
              <tr key={e.id} className="border-t border-line-1 align-top hover:bg-wash">
                <td className="whitespace-nowrap px-2 py-2 font-mono text-[10px] text-muted">{fmtDay(e.date)}</td>
                <td className="px-2 py-2">
                  <Tag className={`font-bold ${SEVERITY_BADGE[e.severity] ?? ''}`}>
                    {SEVERITY_LABEL[e.severity] ?? '?'}
                  </Tag>
                </td>
                <td className="whitespace-nowrap px-2 py-2 font-mono text-[10px] text-muted">
                  {CATEGORY_LABEL[e.category] ?? text(e.category)}
                </td>
                <td className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => setSelectedId(e.id)}
                    className="text-left text-xs font-semibold text-heading hover:text-accent-text"
                  >
                    {text(e.title)}
                  </button>
                </td>
                <td className="whitespace-nowrap px-2 py-2 font-mono text-[10px] text-muted">
                  {text(e.country) || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {sorted.length === 0 && <Empty>No events match these filters.</Empty>}
      </div>
    </section>
  );
  const selectedDetail = selected && (
    <div className="rounded-lg border border-accent-text/50 bg-wash p-3">
      <div className="flex items-start justify-between gap-2">
        <p className="font-mono text-[10px] uppercase tracking-wide text-accent-text">Selected event</p>
        <button
          type="button"
          onClick={() => setSelectedId(null)}
          aria-label="Close selected event"
          className="text-muted hover:text-heading"
        >
          <X size={13} />
        </button>
      </div>
      <h4 className="mt-1 text-sm font-bold text-heading">{text(selected.title)}</h4>
      <p className="mt-1 text-xs leading-relaxed text-body">{text(selected.plain) || text(selected.summary)}</p>
      <p className="mt-1.5 font-mono text-[10px] text-muted">
        {fmtDay(selected.date)} · {CATEGORY_LABEL[selected.category] ?? text(selected.category)} ·{' '}
        {SEVERITY_LABEL[selected.severity]} · {text(selected.place) || text(selected.country)}
      </p>
      {selected.action && (
        <p className="mt-2 rounded border border-line-1 bg-surface-100 p-2 text-xs leading-relaxed text-body">
          <strong className="text-heading">Do: </strong>
          {text(selected.action)}
        </p>
      )}
      {asArray(selected.cves).length > 0 && (
        <p className="mt-2 flex flex-wrap gap-1">
          {asArray(selected.cves).map((cve) => (
            <Tag key={cve} className="border-line-1 text-accent-text">
              {text(cve)}
            </Tag>
          ))}
        </p>
      )}
    </div>
  );
  const searchBox = (
    <div className="relative w-full sm:w-56">
      <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search events"
        aria-label="Search events"
        className="w-full rounded-control border border-line-input bg-input-200 py-1.5 pl-8 pr-2 font-mono text-xs text-heading placeholder:text-muted"
      />
    </div>
  );
  const filterRow = (
    <section className={`surface-card space-y-2 rounded-xl border border-line-1 ${pad}`} aria-label="Event filters">
      <div className="flex flex-wrap items-center gap-1">
        <span className="mr-1 font-mono text-[10px] uppercase tracking-wide text-muted">Event types</span>
        {CATEGORIES.map((c) => (
          <Choice key={c.id} active={category === c.id} onClick={() => setCategory(c.id)}>
            {c.label} <span className="opacity-60">{typeCounts[c.id] ?? 0}</span>
          </Choice>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Choice active={showUnverified} onClick={() => setShowUnverified((v) => !v)}>
          Show unverified claims {showUnverified ? '' : `(${unverifiedHidden} hidden)`}
        </Choice>
        <div role="group" aria-label="Time window" className="inline-flex rounded-control border border-line-1 p-0.5">
          {[2, 3, 7].map((n) => (
            <Choice
              key={n}
              brand
              active={windowDays === n}
              onClick={() => {
                setWindowDays(n);
                setDayFilter(null);
              }}
            >
              {n} days
            </Choice>
          ))}
        </div>
        <div
          role="group"
          aria-label="Minimum severity"
          className="inline-flex rounded-control border border-line-1 p-0.5"
        >
          {SEVERITY_OPTIONS.map(([id, label]) => (
            <Choice key={id} brand active={minSeverity === id} onClick={() => setMinSeverity(id)}>
              {label}
            </Choice>
          ))}
        </div>
        {searchBox}
      </div>
    </section>
  );
  const dayStrip = (
    <div role="group" aria-label="Events per day" className="flex flex-wrap items-center gap-1">
      <span className="mr-1 font-mono text-[10px] uppercase tracking-wide text-muted">Events per day</span>
      {windowDates.map((d) => (
        <Choice
          key={d}
          active={dayFilter === d}
          label={`${dayCounts[d] ?? 0} events on ${fmtDay(d)}`}
          onClick={() => setDayFilter(dayFilter === d ? null : d)}
        >
          <strong className="mr-1 text-heading">{dayCounts[d] ?? 0}</strong> {fmtDay(d)}
        </Choice>
      ))}
      {dayFilter && (
        <button
          type="button"
          onClick={() => setDayFilter(null)}
          className="font-mono text-[11px] text-accent-text hover:underline"
        >
          clear day
        </button>
      )}
    </div>
  );
  const panelHead = (
    <div className="border-b border-line-1 px-3 pt-3">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-bold text-heading">Events and insights</h2>
        <span className="font-mono text-[10px] text-muted">{filtered.length} in scope</span>
      </div>
      <div
        role="tablist"
        aria-label="Events and insights"
        onKeyDown={(e) => {
          if (e.key === 'ArrowRight') {
            e.preventDefault();
            moveTab(1);
          } else if (e.key === 'ArrowLeft') {
            e.preventDefault();
            moveTab(-1);
          }
        }}
        className="mt-2 flex flex-wrap gap-1"
      >
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            id={`cv-tab-${t.id}`}
            aria-controls={`cv-panel-${t.id}`}
            aria-selected={tab === t.id}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
            className={`rounded-t px-2 py-1.5 font-mono text-[11px] font-semibold ${tab === t.id ? 'border-b-2 border-accent-text text-accent-text' : 'text-muted hover:text-heading'}`}
          >
            {t.label}
            {t.id === 'exploited' && <span className="ml-1 opacity-60">{exploited.length}</span>}
          </button>
        ))}
      </div>
    </div>
  );
  let panelBody: JSX.Element;
  if (tab === 'feed' || tab === 'exploited') {
    panelBody = (
      <>
        <div className="flex flex-wrap items-center gap-2">
          {searchBox}
          <label className="relative">
            <ArrowUpDown
              size={12}
              className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-muted"
              aria-hidden="true"
            />
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as 'priority' | 'recent')}
              aria-label="Sort events"
              className="rounded-control border border-line-input bg-input-200 py-1.5 pl-7 pr-2 font-mono text-xs text-heading"
            >
              <option value="priority">Priority first</option>
              <option value="recent">Newest first</option>
            </select>
          </label>
        </div>
        <p className="font-mono text-[10px] text-muted">
          showing {panelRows.length} of {panelTotal}
        </p>
        {tab === 'feed' && justAdded.length > 0 && (
          <div className="rounded-lg border border-line-1 bg-surface-100 p-2">
            <h3 className="font-mono text-[11px] font-bold text-heading">Just added</h3>
            <ul className="mt-1 space-y-1">
              {justAdded.map((e) => (
                <li key={e.id} className="flex gap-2 text-[11px]">
                  <span className="shrink-0 font-mono text-muted">{relativeAgo(e.first_seen)}</span>
                  <button
                    type="button"
                    onClick={() => setSelectedId(e.id)}
                    className="line-clamp-1 text-left text-accent-text hover:underline"
                  >
                    {text(e.title)}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
        <ol className={gap}>
          {panelRows.map((e) => (
            <li key={e.id}>
              <EventCard event={e} selected={selectedId === e.id} onSelect={setSelectedId} compact={wall} />
            </li>
          ))}
        </ol>
        {panelRows.length === 0 && <Empty>No events match these filters.</Empty>}
      </>
    );
  } else if (tab === 'patterns') {
    panelBody = (
      <>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="font-mono text-[11px] text-muted">
            Grouped by {patternBy} across {filtered.length} events.
          </p>
          <div
            role="group"
            aria-label="Group patterns by"
            className="inline-flex rounded-control border border-line-1 p-0.5"
          >
            {(['sector', 'tag'] as const).map((p) => (
              <Choice key={p} brand active={patternBy === p} onClick={() => setPatternBy(p)}>
                {p === 'sector' ? 'Sector' : 'Tag'}
              </Choice>
            ))}
          </div>
        </div>
        <ul className="space-y-1.5">
          {patternRows.map(([name, count]) => (
            <li key={name} className="flex items-center gap-2">
              <span className="w-40 shrink-0 truncate font-mono text-[11px] text-heading" title={name}>
                {name}
              </span>
              <span className="h-2.5 flex-1 overflow-hidden rounded bg-surface-200">
                <span
                  className="block h-full rounded bg-brand-600"
                  style={{ width: `${(count / (patternRows[0]?.[1] || 1)) * 100}%` }}
                />
              </span>
              <span className="w-7 text-right font-mono text-[11px] text-muted">{count}</span>
            </li>
          ))}
        </ul>
        {patternRows.length === 0 && <Empty>Nothing to group yet.</Empty>}
      </>
    );
  } else if (tab === 'insights') {
    panelBody = (
      <div className="space-y-4">
        <RankedList title="Top countries" rows={topCountries} />
        <RankedList title="Top organisations" rows={topOrgs} />
      </div>
    );
  } else {
    panelBody = (
      <div className="space-y-3">
        <div className="rounded-lg border border-line-1 bg-surface-100 p-3">
          <p className="flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wide text-accent-text">
            <Zap size={12} aria-hidden="true" /> Plain-English brief
          </p>
          <p className="mt-2 text-xs leading-relaxed text-body">{brief}</p>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {(
            [
              ['Events', filtered.length],
              ['High priority', highCount],
              ['With CVEs', filtered.filter((e) => asArray(e.cves).length > 0).length],
              ['On map', plotted.length],
            ] as Array<[string, number]>
          ).map(([label, value]) => (
            <div key={label} className="rounded-lg border border-line-1 p-2">
              <p className="font-mono text-lg font-bold text-heading">{value}</p>
              <p className="font-mono text-[10px] text-muted">{label}</p>
            </div>
          ))}
        </div>
      </div>
    );
  }
  const body = (
    <>
      {events.loading && !events.data && <p className="font-mono text-xs text-muted">Loading CyberView events…</p>}
      {events.error && <p className="font-mono text-xs text-rose-500">error: {events.error}</p>}
      {events.data && (
        <div className="space-y-4">
          <header className={`surface-card rounded-xl border border-line-1 ${pad}`}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-lg font-bold text-heading">CyberView</h2>
                  <Badge tone="good" className="items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> Live data connection
                  </Badge>
                </div>
                <p className="mt-1 font-mono text-[11px] text-muted">
                  <strong className="text-heading">{filtered.length}</strong> events ·{' '}
                  <strong className="text-rose-600 dark:text-rose-400">{highCount}</strong> high priority ·{' '}
                  <strong className="text-heading">{plotted.length}</strong> on map · data built {builtLabel}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <HeaderBtn label="Refresh data" onClick={() => events.refetch()}>
                  <RefreshCw size={12} className={events.loading ? 'animate-spin' : ''} aria-hidden="true" /> Refresh
                </HeaderBtn>
                <HeaderBtn label="Wall mode" active={wall} onClick={() => setWall((v) => !v)}>
                  Wall mode
                </HeaderBtn>
                <HeaderBtn label="Full screen" onClick={toggleFullscreen}>
                  <Maximize2 size={12} className="inline" aria-hidden="true" /> Full screen
                </HeaderBtn>
                <HeaderBtn label="Keyboard shortcuts" active={help} onClick={() => setHelp((v) => !v)}>
                  <Keyboard size={12} className="inline" aria-hidden="true" /> ?
                </HeaderBtn>
                <div role="group" aria-label="View" className="inline-flex rounded-control border border-line-1 p-0.5">
                  {VIEWS.map((v) => (
                    <Choice
                      key={v.id}
                      brand
                      active={view === v.id}
                      onClick={() => setView(v.id)}
                      className="inline-flex items-center gap-1 py-1.5"
                    >
                      <v.icon size={12} aria-hidden="true" /> {v.label}
                    </Choice>
                  ))}
                </div>
              </div>
            </div>
            {help && (
              <div
                role="note"
                className="mt-3 rounded-lg border border-line-1 bg-surface-100 p-3 font-mono text-[11px] text-muted"
              >
                <p className="font-bold text-heading">Keyboard shortcuts</p>
                <p className="mt-1">
                  g — Globe · t — Timeline · r — Grid · ? — toggle this panel · Esc — clear selection and day filter
                </p>
              </div>
            )}
          </header>
          <div className={`grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(340px,400px)] ${gap}`}>
            <div className="min-w-0 space-y-3">
              {view === 'globe' ? stage : view === 'timeline' ? timeline : grid}
              {filterRow}
              {dayStrip}
            </div>
            <aside
              aria-label="Events and insights"
              className={`surface-card overflow-hidden rounded-xl border border-line-1 ${wall ? 'p-2' : 'p-3'}`}
            >
              {panelHead}
              <div
                role="tabpanel"
                id={`cv-panel-${tab}`}
                aria-labelledby={`cv-tab-${tab}`}
                className={`space-y-3 ${wall ? 'pt-2' : 'pt-3'}`}
              >
                {selectedDetail}
                {panelBody}
              </div>
            </aside>
          </div>
          <footer className="border-t border-line-1 pt-3 font-mono text-[11px] text-muted">
            Data mirrored from{' '}
            <OutLink href="https://xanderhutch.github.io/CyberView/">xanderhutch.github.io/CyberView</OutLink>; built{' '}
            {builtLabel}.
          </footer>
        </div>
      )}
    </>
  );
  return (
    <CyberViewPage
      bare={bare}
      icon={<Globe2 size={28} />}
      title="CyberView — Live cyber event map"
      description="Replication of the CyberView home page: a verified seven-day globe of cyber events, a live wire and severity/type filters."
      loading={events.loading}
      error={events.error}
      onRetry={() => events.refetch()}
      maxWidthClass="max-w-7xl"
    >
      {body}
    </CyberViewPage>
  );
}
