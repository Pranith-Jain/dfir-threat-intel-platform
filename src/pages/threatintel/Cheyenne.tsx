import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from 'react';
import Globe, { type GlobeInstance } from 'globe.gl';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import {
  buildFleet,
  groundTrack,
  locate,
  predictPasses,
  type CheyennePass,
  type GroundPoint,
  type SensorGeom,
  type TleSat,
  type TrackedSat,
} from '../../lib/cheyenne/orbit';
import {
  CalendarClock,
  Crosshair,
  ExternalLink,
  Github,
  Loader2,
  Pause,
  Play,
  RotateCcw,
  Satellite,
} from 'lucide-react';

/**
 * Cheyenne — working-tool replication of github.com/MJCruickshank/cheyenne.
 *
 * The upstream tool is a local Python server driving a WebGL board. This page
 * re-implements its core in the browser from the upstream fleet catalog and a
 * CelesTrak TLE snapshot (scripts/build-cheyenne-tool.mjs): live satellite
 * positions, ground tracks, sensor swaths, a time machine, and geometric pass
 * prediction over a chosen place. Features that need a backend, keys or live
 * third-party APIs (imagery tiles, ESA tasking, FIRMS, AIS, weather, Telegram)
 * are listed as live-only and deep-linked rather than faked.
 */

interface FleetMeta {
  id: string;
  name: string;
  group: string;
  operator: string;
  sensor: string;
  instrument: string;
  gsd: string;
  revisit: string;
  color: string;
  defaultVisible: boolean;
  access: string | null;
  geom: SensorGeom;
  links: Array<{ label: string; url: string }>;
  trackedSats: number;
}

interface ToolIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  groups: Array<{ id: string; label: string; note: string }>;
  constellations: FleetMeta[];
  counts: { groups: number; fleets: number; trackedSats: number };
  liveOnly: string[];
}

interface TleIndex {
  fetchedAt?: string;
  count: number;
  sats: TleSat[];
}

interface SatPoint {
  lat: number;
  lng: number;
  sat: TrackedSat;
  point: GroundPoint;
}

interface TrackLine {
  coords: number[][];
  color: string;
}

interface SwathPoly {
  geometry: { type: 'Polygon'; coordinates: number[][][] };
  color: string;
}

type Tab = 'board' | 'fleets' | 'about';
const HOUR = 3_600_000;

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] ?? c);
}

function fmtUtc(ms: number): string {
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + 'Z';
}

const inputCls =
  'w-full px-2.5 py-1.5 bg-white dark:bg-surface-200 border border-line-1 rounded-lg text-xs text-heading';

export default function Cheyenne(): JSX.Element {
  const {
    data: index,
    loading,
    error,
    refetch,
  } = useDataFetch<ToolIndex>({ url: '/data/cheyenne-tool/index.json', ttl: 600_000 });
  const { data: tle } = useDataFetch<TleIndex>({ url: '/data/cheyenne-tool/tle.json', ttl: 600_000 });

  const [tab, setTab] = useState<Tab>('board');
  const [fleetId, setFleetId] = useState('sentinel-2');
  const [simMs, setSimMs] = useState(() => Date.now());
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(60);
  const [target, setTarget] = useState<{ lat: number; lng: number }>({ lat: 15.5, lng: 32.5 });
  const [targetInput, setTargetInput] = useState('15.5, 32.5');
  const [showTracks, setShowTracks] = useState(true);
  const [showSwaths, setShowSwaths] = useState(true);
  const [selectedSat, setSelectedSat] = useState<TrackedSat | null>(null);
  const [passes, setPasses] = useState<CheyennePass[]>([]);
  const [passesLoading, setPassesLoading] = useState(false);
  const [globeError, setGlobeError] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef = useRef<GlobeInstance | null>(null);
  const simRef = useRef(simMs);
  simRef.current = simMs;

  const fleet = useMemo(() => {
    if (!tle?.sats?.length) return [];
    return buildFleet(tle.sats, simMs);
    // Fleet records are stable for the TLE snapshot; rebuild only on new data.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tle]);

  const meta = useMemo(() => index?.constellations.find((c) => c.id === fleetId) ?? null, [index, fleetId]);
  const fleetSats = useMemo(() => fleet.filter((s) => s.cid === fleetId), [fleet, fleetId]);
  const color = meta?.color ?? '#4fd8c4';

  // Clock
  useEffect(() => {
    if (!playing) return;
    const timer = window.setInterval(() => setSimMs((t) => t + speed * 1000), 1000);
    return () => window.clearInterval(timer);
  }, [playing, speed]);

  // Globe initialisation (mirrors the repo's CtiGlobe pattern)
  useEffect(() => {
    if (!containerRef.current || globeRef.current || tab !== 'board') return;
    try {
      const el = containerRef.current;
      const globe = new Globe(el, { animateIn: true })
        .width(el.clientWidth)
        .height(el.clientHeight)
        .globeImageUrl('/textures/earth-night.jpg')
        .bumpImageUrl('/textures/earth-topology.png')
        .backgroundImageUrl('')
        .backgroundColor('rgba(0,0,0,0)')
        .showAtmosphere(true)
        .atmosphereColor('#4f8fff')
        .atmosphereAltitude(0.18)
        .onGlobeClick((coords) => {
          setTarget({ lat: coords.lat, lng: coords.lng });
          setTargetInput(`${coords.lat.toFixed(2)}, ${coords.lng.toFixed(2)}`);
        })
        .pointLabel((p: object) => {
          const d = p as SatPoint;
          return `<div style="font:12px monospace;background:#06090e;padding:6px 8px;border:1px solid #334">${esc(d.sat.name)}<br/>${d.point.lat.toFixed(2)}°, ${d.point.lon.toFixed(2)}° · ${Math.round(d.point.alt)} km</div>`;
        })
        .onPointClick((p: object) => setSelectedSat((p as SatPoint).sat));
      globeRef.current = globe;
      globe.pointOfView({ lat: target.lat, lng: target.lng, altitude: 2.1 }, 0);
      const onResize = () => {
        if (!containerRef.current || !globeRef.current) return;
        globeRef.current.width(containerRef.current.clientWidth).height(containerRef.current.clientHeight);
      };
      window.addEventListener('resize', onResize);
      return () => {
        window.removeEventListener('resize', onResize);
        globe._destructor?.();
        globeRef.current = null;
      };
    } catch (err) {
      setGlobeError(err instanceof Error ? err.message : String(err));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  // Points, tracks, swaths, target marker
  const points = useMemo<SatPoint[]>(
    () =>
      fleetSats.slice(0, 60).flatMap((sat) => {
        const p = locate(sat, simMs);
        return p ? [{ lat: p.lat, lng: p.lon, sat, point: p }] : [];
      }),
    [fleetSats, simMs]
  );

  const tracks = useMemo<TrackLine[]>(() => {
    if (!showTracks) return [];
    const t0 = simMs - 45 * 60_000;
    const t1 = simMs + 45 * 60_000;
    return fleetSats
      .slice(0, 8)
      .flatMap((sat) => groundTrack(sat, t0, t1, 25_000).map((coords) => ({ coords, color })));
  }, [fleetSats, simMs, showTracks, color]);

  const swaths = useMemo<SwathPoly[]>(() => {
    if (!showSwaths || !meta) return [];
    const near = meta.geom.mode === 'side' ? (meta.geom.farKm ?? 0) : (meta.geom.swathKm ?? 0) / 2;
    return points.slice(0, 8).flatMap(({ sat }) => {
      const hdg = locate(sat, simMs + 2000);
      if (!hdg) return [];
      const here = locate(sat, simMs);
      if (!here) return [];
      const brg = (Math.atan2(Math.sin((hgLng(hdg.lon) - here.lon) * (Math.PI / 180)), 1) * 180) / Math.PI;
      const ring: number[][] = [];
      for (let step = 0; step < 24; step++) {
        const ang = (brg + (step / 24) * 360) * (Math.PI / 180);
        ring.push([
          here.lon + ((near / 111) * Math.sin(ang)) / Math.max(0.2, Math.cos((here.lat * Math.PI) / 180)),
          here.lat + (near / 111) * Math.cos(ang),
        ]);
      }
      return [{ geometry: { type: 'Polygon', coordinates: [ring] }, color }];
    });
  }, [points, showSwaths, meta, color, simMs]);

  useEffect(() => {
    const g = globeRef.current;
    if (!g || tab !== 'board') return;
    try {
      g.pointsData(points)
        .pointLat((p: object) => (p as SatPoint).lat)
        .pointLng((p: object) => (p as SatPoint).lng)
        .pointColor(() => color)
        .pointAltitude(() => 0.012)
        .pointRadius(() => 0.42)
        .ringsData([{ lat: target.lat, lng: target.lng, size: 2.2, color: '#ff4b36' }])
        .ringLat((r: object) => (r as { lat: number }).lat)
        .ringLng((r: object) => (r as { lng: number }).lng)
        .ringColor(() => '#ff4b36')
        .ringMaxRadius(() => 3)
        .ringPropagationSpeed(() => 1.5)
        .ringRepeatPeriod(() => 900)
        .pathsData(tracks)
        .pathPoints((d: object) => (d as TrackLine).coords)
        .pathColor((d: object) => (d as TrackLine).color)
        .pathStroke(() => 0.7)
        .polygonsData(swaths)
        .polygonGeoJsonGeometry((d: object) => (d as SwathPoly).geometry as never)
        .polygonCapColor((d: object) => (d as SwathPoly).color)
        .polygonAltitude(() => 0.003)
        .polygonStrokeColor(() => null);
    } catch {
      /* layer APIs differ between globe.gl releases — keep the board usable */
    }
  }, [points, tracks, swaths, target, color, tab]);

  const runPrediction = useCallback(() => {
    if (!meta || !fleetSats.length) return;
    setPassesLoading(true);
    window.setTimeout(() => {
      try {
        setPasses(predictPasses(fleetSats, meta.geom, [target.lng, target.lat], simMs, simMs + 24 * HOUR));
      } finally {
        setPassesLoading(false);
      }
    }, 20);
  }, [meta, fleetSats, target, simMs]);

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'board', label: 'Board' },
    { id: 'fleets', label: `Fleets (${index?.counts.fleets ?? '…'})` },
    { id: 'about', label: 'About' },
  ];

  const applyTarget = () => {
    const m = targetInput.match(/^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/);
    if (!m) return;
    const lat = Math.max(-85, Math.min(85, Number(m[1])));
    const lng = Math.max(-180, Math.min(180, Number(m[2])));
    setTarget({ lat, lng });
    globeRef.current?.pointOfView({ lat, lng, altitude: 1.6 }, 800);
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Satellite size={28} />}
      title="Cheyenne EO Board"
      description={
        <>
          A working in-site replica of{' '}
          <a
            href={index?.sourceUrl ?? 'https://github.com/MJCruickshank/cheyenne'}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            MJCruickshank/cheyenne
          </a>
          : {index?.counts.trackedSats ?? '…'} imaging satellites across {index?.counts.fleets ?? '…'} fleets, tracked
          from a CelesTrak orbital snapshot. Move the clock, pick a fleet, click the globe to set a place and predict
          when its sensors can see it.
        </>
      }
      onRetry={refetch}
      loading={loading && !index}
      error={error}
      maxWidthClass="max-w-7xl"
    >
      <div className="flex flex-wrap gap-2 mb-4">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-500/15 text-brand-600 dark:text-brand-300 border-brand-400/40'
                : 'text-muted hover:text-heading border-line-1'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'board' && (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4">
          <div className="surface-card relative overflow-hidden" style={{ height: 620 }}>
            <div ref={containerRef} className="absolute inset-0" />
            {globeError && (
              <div className="absolute inset-0 grid place-items-center text-sm text-rose-500">
                Globe failed: {globeError}
              </div>
            )}
            {!tle && (
              <div className="absolute inset-0 grid place-items-center text-muted">
                <Loader2 size={20} className="animate-spin" /> Loading orbital data…
              </div>
            )}
            <div className="absolute top-3 left-3 flex flex-wrap gap-1.5 max-w-[70%]">
              <span className="text-[10px] font-mono px-2 py-1 rounded bg-black/60 text-emerald-300 border border-line-2">
                {fmtUtc(simMs)}
              </span>
              {selectedSat && (
                <span className="text-[10px] font-mono px-2 py-1 rounded bg-black/60 text-heading border border-line-2">
                  {selectedSat.name} · {selectedSat.short} · {Math.round(selectedSat.periodMin)} min orbit
                </span>
              )}
            </div>
            <div className="absolute bottom-3 left-3 right-3 flex flex-wrap items-center gap-2 text-[10px] text-muted bg-black/50 rounded-lg px-3 py-2">
              <button
                onClick={() => setPlaying((p) => !p)}
                className="inline-flex items-center gap-1 text-brand-300 hover:text-heading"
              >
                {playing ? <Pause size={11} /> : <Play size={11} />} {playing ? 'Pause' : 'Play'}
              </button>
              <button
                onClick={() => setSimMs(Date.now())}
                className="inline-flex items-center gap-1 text-brand-300 hover:text-heading"
              >
                <RotateCcw size={11} /> Now
              </button>
              <select
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                className="bg-black/60 border border-line-2 rounded px-1.5 py-0.5 text-heading"
              >
                {[1, 10, 60, 600, 3600].map((s) => (
                  <option key={s} value={s}>
                    {s}×
                  </option>
                ))}
              </select>
              <input
                type="range"
                min={-12 * HOUR}
                max={12 * HOUR}
                step={60_000}
                value={Math.max(-12 * HOUR, Math.min(12 * HOUR, simMs - Date.now()))}
                onChange={(e) => setSimMs(Date.now() + Number(e.target.value))}
                className="flex-1 min-w-[120px] accent-brand-400"
              />
              <label className="flex items-center gap-1">
                <input type="checkbox" checked={showTracks} onChange={(e) => setShowTracks(e.target.checked)} /> tracks
              </label>
              <label className="flex items-center gap-1">
                <input type="checkbox" checked={showSwaths} onChange={(e) => setShowSwaths(e.target.checked)} /> swaths
              </label>
            </div>
          </div>

          <div className="space-y-3">
            <div className="surface-card p-3 space-y-2">
              <label className="text-xs font-semibold text-heading flex items-center gap-1">
                <Satellite size={13} /> Fleet
              </label>
              <select
                className={inputCls}
                value={fleetId}
                onChange={(e) => {
                  setFleetId(e.target.value);
                  setPasses([]);
                }}
              >
                {(index?.groups ?? []).map((g) => (
                  <optgroup key={g.id} label={g.label}>
                    {(index?.constellations ?? [])
                      .filter((c) => c.group === g.id)
                      .map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} ({c.trackedSats})
                        </option>
                      ))}
                  </optgroup>
                ))}
              </select>
              {meta && (
                <div className="text-[11px] text-muted space-y-1 pt-1">
                  <div>
                    <b className="text-heading">{meta.operator}</b> · {meta.instrument}
                  </div>
                  <div>
                    GSD {meta.gsd} · revisit {meta.revisit} · {meta.sensor}
                  </div>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {meta.links.map((l) => (
                      <a
                        key={l.url}
                        href={l.url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-0.5 text-brand-500 hover:underline"
                      >
                        {l.label} <ExternalLink size={9} />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="surface-card p-3 space-y-2">
              <label className="text-xs font-semibold text-heading flex items-center gap-1">
                <Crosshair size={13} /> Focus point
              </label>
              <div className="flex gap-1.5">
                <input
                  className={inputCls}
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && applyTarget()}
                  placeholder="lat, lon"
                />
                <button
                  onClick={applyTarget}
                  className="px-2 rounded-lg border border-line-1 text-xs text-muted hover:text-heading"
                >
                  Set
                </button>
              </div>
              <p className="text-[10px] text-muted">
                Click anywhere on the globe to set the target directly. Default: Khartoum.
              </p>
              <button
                onClick={runPrediction}
                disabled={passesLoading || !fleetSats.length}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-brand-500/15 border border-brand-400/40 text-brand-600 dark:text-brand-300 text-xs font-medium disabled:opacity-50"
              >
                {passesLoading ? <Loader2 size={12} className="animate-spin" /> : <CalendarClock size={12} />} Predict
                24 h passes
              </button>
            </div>

            <div className="surface-card p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-heading">Upcoming passes</span>
                <span className="text-[10px] text-muted">{passes.length} found</span>
              </div>
              <div className="space-y-1.5 max-h-72 overflow-y-auto">
                {passes.slice(0, 40).map((p, i) => (
                  <button
                    key={`${p.sat.id}-${p.time}-${i}`}
                    onClick={() => {
                      setSimMs(p.time);
                      setSelectedSat(p.sat);
                      globeRef.current?.pointOfView(
                        { lat: p.geometry[0]?.[1] ?? target.lat, lng: p.geometry[0]?.[0] ?? target.lng, altitude: 1.2 },
                        800
                      );
                    }}
                    className="w-full text-left px-2 py-1.5 rounded-lg hover:bg-surface-100 border border-line-1 text-[11px]"
                  >
                    <div className="flex justify-between gap-2">
                      <span className="font-medium text-heading">{p.sat.short}</span>
                      <span className="font-mono text-muted">{new Date(p.time).toISOString().slice(11, 16)}Z</span>
                    </div>
                    <div className="text-muted">
                      {Math.round(p.crossKm)} km cross-track · {Math.round(p.offNadir)}° off-nadir ·{' '}
                      {p.ascending ? 'asc' : 'desc'}
                      {p.sunEl > 3 ? ' · day' : ''}
                    </div>
                  </button>
                ))}
                {!passes.length && (
                  <p className="text-[11px] text-muted">Pick a fleet and a place, then run a prediction.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'fleets' && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {(index?.constellations ?? []).map((c) => (
            <div key={c.id} className="surface-card p-3">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: c.color }} />
                <span className="font-semibold text-heading text-sm">{c.name}</span>
                <span className="text-[10px] text-muted ml-auto">{c.trackedSats} sats</span>
              </div>
              <p className="text-xs text-muted mt-1.5">{c.instrument}</p>
              <div className="text-[11px] text-muted mt-1">
                GSD {c.gsd} · {c.revisit} · {c.sensor}
              </div>
              <div className="text-[10px] text-muted mt-1 line-clamp-2">{c.access}</div>
              <button
                onClick={() => {
                  setFleetId(c.id);
                  setTab('board');
                }}
                className="mt-2 text-[11px] text-brand-500 hover:underline"
              >
                Track this fleet →
              </button>
            </div>
          ))}
        </div>
      )}

      {tab === 'about' && (
        <div className="surface-card p-5 text-sm text-muted space-y-4">
          <p>
            This is a re-implementation of the <b className="text-heading">working tool</b>, not a documentation mirror.
            The browser computes satellite positions (SGP4 via satellite.js), ground tracks, sensor footprints and
            geometric access windows from the same public inputs the upstream tool uses: its fleet catalog and a
            CelesTrak GP orbital snapshot. Move the clock to see where a fleet was or will be; click the globe to set a
            place and predict when its sensors can reach it.
          </p>
          <p>
            Predicted passes show when a sensor <i>could</i> see a place, not whether an image will be taken — the same
            limitation the upstream tool documents. Orbit elements are a snapshot, so accuracy decays over days; the
            weekly sync refreshes them.
          </p>
          <div>
            <div className="text-xs font-semibold text-heading mb-2">
              Live-only upstream features (deep-linked, not mirrored)
            </div>
            <ul className="list-disc list-inside space-y-1 text-xs">
              {(index?.liveOnly ?? []).map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
          </div>
          <div className="flex flex-wrap gap-3 pt-1">
            <a
              href={index?.sourceUrl ?? 'https://github.com/MJCruickshank/cheyenne'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              <Github size={13} /> Upstream repository <ExternalLink size={12} />
            </a>
            <span className="text-xs">
              Orbit snapshot: {tle?.count ?? '…'} catalogued satellites · built{' '}
              {index?.builtAt ? new Date(index.builtAt).toISOString().slice(0, 10) : '…'}
            </span>
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}

/** Small helper to keep the swath bearing calculation readable. */
function hgLng(lng: number): number {
  return ((lng + 540) % 360) - 180;
}
