import { errMessage, logCatch } from '../../lib/log';
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type JSX } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import {
  Activity,
  Globe,
  Zap,
  Bug,
  Skull,
  AlertTriangle,
  Box,
  Crosshair,
  RefreshCw,
  Map,
  ExternalLink,
  Layers,
  Filter,
  X,
  Clock,
  Play,
  Pause,
  Brain,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ShareBar } from '../../components/intel/ShareBar';
import { CountUp } from '../../components/ui/CountUp';
import { Sparkline } from '../../components/threatintel/Sparkline';
import { SeverityPill } from '../../components/Badge';
import type { CtiArc, CtiPoint } from '../../components/threatintel/cti/geo';
import { synthesizeArcs, deriveKpis } from '../../components/threatintel/cti/geo';
import { ThreatAnalysisPanel } from '../../components/threatintel/ThreatAnalysisPanel';
import { CountryIntelPanel } from '../../components/threatintel/CountryIntelPanel';
import { useGlobalPulse } from '../../hooks/useGlobalPulse';
import type { PulseKind, PulseEvent, GlobalPulseResponse, LayerDef } from './global-pulse-types';
import { LAYER_DEFS, SEVERITY_CONFIG, ALL_KINDS, formatTime, formatTimeFull, signalRank } from './global-pulse-types';
import { downloadBlob } from '../../lib/download';

const PulseMap = lazy(() => import('./PulseMap'));
const CtiGlobe = lazy(() => import('../../components/threatintel/cti/CtiGlobe'));

/* ─── Component ─────────────────────────────────────────────────────────── */

export default function GlobalPulse(): JSX.Element {
  const [data, setData] = useState<GlobalPulseResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeLayers, setActiveLayers] = useState<Set<PulseKind>>(
    new Set([
      'ransomware',
      'cve',
      'ioc_activity',
      'cyber_attack',
      'c2_tracker',
      'cisa_advisory',
      'infostealer',
      'phishing',
      'malware',
      'blocklist',
      'breach',
      'cybercrime',
      'scam',
      'actor_sighting',
      'ioc_correlation',
      'secret_leak',
      'malicious_package',
      'exploit',
      'github_advisory',
      'kev',
      'supply_chain_attacks',
      'briefing',
      'honeypot',
      'cyberpulse',
      'rss',
    ])
  );
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<PulseEvent | null>(null);
  const [showAiAnalysis, setShowAiAnalysis] = useState(false);
  const [showCountryIntel, setShowCountryIntel] = useState(false);
  // Default to the 3D globe - it's the showpiece and the "wow" of this page (the
  // recruiter-facing first impression). It's lazy-loaded (globe.gl/three.js,
  // ~506KB gz, route-split to THIS page only) and renders behind a skeleton while
  // the chunk streams in. Switch to '2d' (PulseMap, ~2.3KB) via the toggle / '2'.
  // Auto-fallback to 2D if WebGL is unavailable (prevents globe.gl crash).
  const [mapMode, setMapMode] = useState<'2d' | '3d'>(() => {
    if (typeof document === 'undefined') return '3d';
    try {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl2') || c.getContext('webgl');
      if (!gl) return '2d';
    } catch {
      return '2d';
    }
    return '3d';
  });
  const [focus, setFocus] = useState<{ lat: number; lng: number } | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set(['critical', 'high', 'medium', 'low']));
  const [ctiFilter, setCtiFilter] = useState<'all' | 'ransomware' | 'cve' | 'ioc'>('all');
  const loadIdRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  // WebSocket real-time updates
  const { connected: wsConnected, generatedAt: wsGeneratedAt } = useGlobalPulse();

  // Auto-pan for 3D globe
  const [autoPan, setAutoPan] = useState(false);

  // Day/night terminator polygon for 2D map overlay. Recomputed every 5min
  // so the night shadow tracks the sun's actual position (the terminator
  // drifts ~1°/4min; 5min keeps it visually accurate without re-rendering
  // the polygon on every frame).
  const computeTerminator = useCallback((): [number, number][] => {
    const now = new Date();
    const dayOfYear = Math.floor((now.getTime() - new Date(now.getFullYear(), 0, 0).getTime()) / 86400000);
    const hourUTC = now.getUTCHours() + now.getUTCMinutes() / 60;
    const declination = -23.44 * Math.cos(((360 / 365) * (dayOfYear + 10) * Math.PI) / 180);
    const decRad = (declination * Math.PI) / 180;
    const sunLng = -(hourUTC - 12) * 15;

    const coords: [number, number][] = [];
    for (let lng = -180; lng <= 180; lng += 4) {
      const lngRad = ((lng - sunLng) * Math.PI) / 180;
      const lat = (Math.atan(-Math.cos(lngRad) / Math.tan(decRad)) * 180) / Math.PI;
      coords.push([lng, lat]);
    }

    const nightOnSouth = declination >= 0;
    const polygon: [number, number][] = [
      [-180, coords[0]![1]],
      ...coords,
      [180, coords[coords.length - 1]![1]],
      ...((nightOnSouth
        ? [
            [180, -90],
            [-180, -90],
          ]
        : [
            [180, 90],
            [-180, 90],
          ]) as [number, number][]),
      [-180, coords[0]![1]],
    ];

    return polygon;
  }, []);
  const [terminatorPolygon, setTerminatorPolygon] = useState<[number, number][]>(computeTerminator);
  useEffect(() => {
    const id = setInterval(() => setTerminatorPolygon(computeTerminator()), 5 * 60 * 1000);
    return () => clearInterval(id);
  }, [computeTerminator]);

  const load = useCallback(async (forceRefresh = false) => {
    const myId = ++loadIdRef.current;
    // Abort the previous in-flight fetch so a fast succession of refreshes
    // (WS push + poll firing together, or the user mashing refresh) doesn't
    // leave orphaned requests whose late responses could race the winner.
    // loadIdRef already guards setData, but aborting saves the network cost.
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(forceRefresh ? '/api/v1/global-pulse?force=1' : '/api/v1/global-pulse', {
        signal: ctrl.signal,
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const json: GlobalPulseResponse = await r.json();

      if (loadIdRef.current === myId) {
        setData(json);
        setLastUpdated(json.generated_at);
        try {
          localStorage.setItem('gp:last', JSON.stringify(json));
        } catch {}
      }
    } catch (e) {
      // AbortError is expected when a newer refresh superseded this one —
      // not a real error, don't surface it to the UI.
      if (e instanceof DOMException && e.name === 'AbortError') return;
      console.error('GlobalPulse load failed:', errMessage(e));
      if (loadIdRef.current === myId) setError((e as Error).message);
    } finally {
      if (loadIdRef.current === myId) setLoading(false);
      if (abortRef.current === ctrl) abortRef.current = null;
    }
  }, []);
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState<number>(0); // 0 = all time, hours
  const [isFullscreen, setIsFullscreen] = useState(false);
  const globeContainerRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const toggleFullscreen = useCallback(() => {
    if (!globeContainerRef.current) return;
    if (!document.fullscreenElement) {
      globeContainerRef.current
        .requestFullscreen()
        .then(() => setIsFullscreen(true))
        .catch(() => {});
    } else {
      document
        .exitFullscreen()
        .then(() => setIsFullscreen(false))
        .catch(() => {});
    }
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') return;

      switch (e.key.toLowerCase()) {
        case 'f':
          e.preventDefault();
          toggleFullscreen();
          break;
        case 'r':
          e.preventDefault();
          load(true);
          break;
        case 'escape':
          setSelectedEvent(null);
          setShowFilters(false);
          break;
        case 's':
          e.preventDefault();
          setShowFilters((prev) => !prev);
          break;
        case '1':
          setMapMode('3d');
          break;
        case '2':
          setMapMode('2d');
          break;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [load, toggleFullscreen]);

  // Listen for fullscreen changes
  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  const ctiPriority = useCallback((cti?: PulseEvent['cti']): number => {
    switch (cti) {
      case 'ransomware':
        return 5;
      case 'cve':
        return 4;
      case 'ioc':
        return 3;
      case 'threat':
        return 1;
      default:
        return 0;
    }
  }, []);

  const severityRank = useCallback((sev: PulseEvent['severity']): number => {
    switch (sev) {
      case 'critical':
        return 4;
      case 'high':
        return 3;
      case 'medium':
        return 2;
      case 'low':
        return 1;
    }
  }, []);

  const filteredEvents = useMemo(() => {
    if (!data) return [];
    const now = Date.now();
    const base = data.events.filter((e) => {
      if (!activeLayers.has(e.kind)) return false;
      if (!severityFilter.has(e.severity)) return false;
      if (timeRange > 0) {
        const eventTime = new Date(e.timestamp).getTime();
        if (now - eventTime > timeRange * 3600000) return false;
      }
      if (ctiFilter === 'ransomware' && e.cti !== 'ransomware') return false;
      if (ctiFilter === 'cve' && e.cti !== 'cve') return false;
      if (ctiFilter === 'ioc' && e.cti !== 'ioc') return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          e.title.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          e.source.toLowerCase().includes(q) ||
          e.kind.toLowerCase().includes(q)
        );
      }
      return true;
    });
    return base.sort((a, b) => {
      // 1. Severity first — critical events on top regardless of type
      const sa = severityRank(a.severity);
      const sb = severityRank(b.severity);
      if (sa !== sb) return sb - sa;
      // 2. Signal class — confirmed harm (ransom victims, KEV 0-days) above
      //    vulnerability records above infrastructure observations. Without
      //    this, "now"-stamped C2 rows permanently top every tier above real
      //    victims and 0-days with genuinely older timestamps.
      const ca = signalRank(a);
      const cb = signalRank(b);
      if (ca !== cb) return cb - ca;
      // 3. Recency — newest first within the same severity + signal tier
      const timeDiff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      if (Math.abs(timeDiff) > 60_000) return timeDiff;
      // 4. CTI priority as tiebreaker for events within the same minute
      const pa = ctiPriority(a.cti);
      const pb = ctiPriority(b.cti);
      return pb - pa;
    });
  }, [data, activeLayers, severityFilter, searchQuery, timeRange, ctiFilter, ctiPriority, severityRank]);

  // Export to CSV
  const exportToCsv = useCallback(() => {
    if (!filteredEvents.length) return;
    const headers = ['ID', 'Kind', 'Title', 'Description', 'Severity', 'Source', 'Timestamp', 'Latitude', 'Longitude'];
    const rows = filteredEvents.map((e) => [
      e.id,
      e.kind,
      e.title,
      e.description,
      e.severity,
      e.source,
      e.timestamp,
      e.lat,
      e.lng,
    ]);
    const csv = [
      headers.join(','),
      ...rows.map((r) => r.map((v) => (typeof v === 'string' ? '"' + v.replace(/"/g, '""') + '"' : v)).join(',')),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    downloadBlob(blob, 'global-pulse-' + new Date().toISOString().split('T')[0] + '.csv');
  }, [filteredEvents]);

  // Last-good: paint the previous response instantly on mount (client-only, so
  // SSR markup still matches and there's no hydration mismatch), then load()
  // refreshes in the background. Turns a 10-20s cold-spinner into an instant page.
  useEffect(() => {
    try {
      const cached = localStorage.getItem('gp:last');
      if (cached) setData((d) => d ?? (JSON.parse(cached) as GlobalPulseResponse));
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    }
  }, []);
  // Abort any in-flight refresh on unmount so a late response doesn't
  // attempt setState on a gone component (loadIdRef already guards it, but
  // aborting also saves the network + parse cost).
  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  // WebSocket-driven refresh: when the DO pushes new events, re-fetch the full
  // data so the map and feed stay in sync. Falls back to polling when WS is
  // disconnected or auto-refresh is paused.
  useEffect(() => {
    if (wsConnected && wsGeneratedAt && autoRefresh) {
      load();
    }
  }, [wsConnected, wsGeneratedAt, autoRefresh, load]);
  // Polling fallback — always poll every 60s when autoRefresh is on, even
  // if the WS is connected. The DO only broadcasts when the cache
  // generated_at changes; if the cache rebuild is delayed or the DO's
  // alarm isn't firing, the page would otherwise appear "stuck at 1 hour
  // ago". This guarantees the data stays fresh regardless of WS state.
  useEffect(() => {
    if (!autoRefresh) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }
    intervalRef.current = setInterval(() => {
      if (document.visibilityState === 'visible') load();
    }, 60_000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [autoRefresh, load, wsConnected]);

  const toggleLayer = useCallback((layer: PulseKind) => {
    setActiveLayers((prev) => {
      const next = new Set(prev);
      if (next.has(layer)) next.delete(layer);
      else next.add(layer);
      return next;
    });
  }, []);

  const geoPoints = useMemo(() => {
    return filteredEvents
      .filter((e) => e.lat !== 0 || e.lng !== 0)
      .map((e) => ({
        id: e.id,
        lat: e.lat,
        lng: e.lng,
        severity: e.severity,
        kind: e.kind,
        title: e.title,
        description: e.description,
        source: e.source,
      }));
  }, [filteredEvents]);

  const globePoints: CtiPoint[] = useMemo(() => {
    return geoPoints.map((p) => ({
      lat: p.lat,
      lng: p.lng,
      severity: p.severity as CtiPoint['severity'],
      count: 1,
      label: p.title,
      countryCode: '',
      kind: p.kind,
      source: p.source,
      description: p.description,
      magnitude: filteredEvents.find((e) => e.id === p.id)?.magnitude,
    }));
  }, [geoPoints, filteredEvents]);

  const globeArcs: CtiArc[] = useMemo(() => synthesizeArcs(globePoints), [globePoints]);
  const kpis = useMemo(() => deriveKpis(globePoints, filteredEvents.length), [globePoints, filteredEvents]);
  const filteredCritical = useMemo(
    () => filteredEvents.filter((e) => e.severity === 'critical').length,
    [filteredEvents]
  );

  // Trending now — corroborated across 2+ sources, critical/high only, top 5
  // in feed order (which already ranks them). Empty most hours; when it fires
  // it answers "what's hot" without scrolling the feed.
  const trendingNow = useMemo(
    () => filteredEvents.filter((e) => e.trending && (e.severity === 'critical' || e.severity === 'high')).slice(0, 5),
    [filteredEvents]
  );

  const handlePointClick = useCallback((point: CtiPoint) => {
    setFocus({ lat: point.lat, lng: point.lng });
  }, []);

  // Group layers by category
  const layerGroups = useMemo(() => {
    const groups: Record<string, Array<{ kind: PulseKind; def: LayerDef; count: number; active: boolean }>> = {
      intel: [],
      social: [],
    };
    for (const kind of ALL_KINDS) {
      const def = LAYER_DEFS[kind];
      const count = data?.layers[kind] ?? 0;
      groups[def.group]!.push({ kind, def, count, active: activeLayers.has(kind) });
    }
    return groups;
  }, [data, activeLayers]);

  // KPI stats
  const stats = useMemo(() => {
    if (!data) return null;
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const bySource: Record<string, number> = {};
    for (const e of filteredEvents) {
      bySeverity[e.severity]++;
      bySource[e.source] = (bySource[e.source] || 0) + 1;
    }
    const topSources = Object.entries(bySource)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);
    return { bySeverity, topSources, geoCount: geoPoints.length };
  }, [data, filteredEvents, geoPoints]);

  // One sample per refresh - drives the KPI deltas + sparklines so the page
  // reads as a live pulse, not a static scoreboard.
  const [trend, setTrend] = useState<{ total: number; critical: number }[]>([]);
  useEffect(() => {
    if (!data) return;
    setTrend((t) => [...t.slice(-23), { total: filteredEvents.length, critical: filteredCritical }]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastUpdated]);
  const lastTrend = trend[trend.length - 1];
  const prevTrend = trend[trend.length - 2];
  const totalDelta = lastTrend && prevTrend ? lastTrend.total - prevTrend.total : 0;
  const criticalDelta = lastTrend && prevTrend ? lastTrend.critical - prevTrend.critical : 0;

  return (
    <DataPageLayout
      backTo="/threatintel"
      backToOverride="/"
      icon={<Globe size={28} />}
      title="Global Pulse"
      description="A live map of worldwide cyber-threat activity - aggregating 20+ real-time intelligence feeds (ransomware, breaches, CVEs, dark-web chatter) and refreshing every minute."
      loading={loading && !data}
      error={error}
      onRetry={load}
      maxWidthClass="max-w-7xl"
    >
      {data && (
        <div className="space-y-5">
          {/* ─── Top Stats Bar ─── */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Total events */}
            <div className="relative rounded-2xl border border-line-1/60 dark:border-white/[0.06] bg-surface-100 dark:bg-surface-100/[0.02] p-4 shadow-sm">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="flex items-center gap-1.5 text-mini font-semibold uppercase tracking-wider text-muted">
                  <Activity size={13} className="text-muted" /> Total Events
                </span>
                {totalDelta !== 0 && (
                  <span
                    className={`inline-flex items-center text-micro font-mono px-1.5 py-0.5 rounded-full ${
                      totalDelta > 0
                        ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10'
                        : 'text-slate-500 bg-slate-500/10'
                    }`}
                  >
                    {totalDelta > 0 ? '+' : ''}
                    {totalDelta}
                  </span>
                )}
              </div>
              <div className="flex items-end justify-between gap-2">
                <CountUp
                  to={filteredEvents.length}
                  className="text-3xl font-display font-bold text-heading tabular-nums leading-none"
                />
                {trend.length > 1 && (
                  <Sparkline
                    values={trend.map((t) => t.total)}
                    className="text-rose-500/60 dark:text-rose-400/60 mb-0.5"
                  />
                )}
              </div>
              <div className="text-mini font-mono text-muted mt-2">{geoPoints.length} geo-located</div>
            </div>

            {/* Critical - the hero metric */}
            <div className="relative rounded-2xl border border-rose-500/20 dark:border-rose-500/10 bg-gradient-to-br from-rose-500/[0.04] to-transparent p-4 shadow-sm">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="flex items-center gap-1.5 text-mini font-semibold uppercase tracking-wider text-rose-500 dark:text-rose-400">
                  <AlertTriangle size={13} /> Critical
                </span>
                {criticalDelta !== 0 && (
                  <span
                    className={`inline-flex items-center text-micro font-mono px-1.5 py-0.5 rounded-full ${
                      criticalDelta > 0
                        ? 'text-rose-600 dark:text-rose-400 bg-rose-500/15'
                        : 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10'
                    }`}
                  >
                    {criticalDelta > 0 ? '+' : ''}
                    {criticalDelta}
                  </span>
                )}
              </div>
              <CountUp
                to={filteredCritical}
                className="block text-3xl font-display font-bold text-rose-600 dark:text-rose-400 tabular-nums leading-none"
              />
              {(() => {
                const bs = stats?.bySeverity ?? { critical: 0, high: 0, medium: 0, low: 0 };
                const tot = bs.critical + bs.high + bs.medium + bs.low || 1;
                return (
                  <div className="mt-3 flex h-1.5 gap-px overflow-hidden rounded-full bg-track/60 dark:bg-surface-100/[0.06]">
                    <div className="bg-rose-500" style={{ width: `${(bs.critical / tot) * 100}%` }} />
                    <div className="bg-orange-500" style={{ width: `${(bs.high / tot) * 100}%` }} />
                    <div className="bg-amber-500" style={{ width: `${(bs.medium / tot) * 100}%` }} />
                    <div className="bg-emerald-500" style={{ width: `${(bs.low / tot) * 100}%` }} />
                  </div>
                );
              })()}
              <div className="text-mini font-mono text-rose-400/70 dark:text-rose-400/60 mt-2">
                {stats?.bySeverity.high ?? 0} high severity
              </div>
            </div>

            {/* Active layers */}
            <div className="relative rounded-2xl border border-line-1/60 dark:border-white/[0.06] bg-surface-100 dark:bg-surface-100/[0.02] p-4 shadow-sm">
              <div className="flex items-center gap-1.5 text-mini font-semibold uppercase tracking-wider text-muted mb-3">
                <Layers size={13} className="text-muted" /> Active Layers
              </div>
              <CountUp
                to={activeLayers.size}
                className="block text-3xl font-display font-bold text-heading tabular-nums leading-none"
              />
              <div className="text-mini font-mono text-muted mt-2">{ALL_KINDS.length - activeLayers.size} hidden</div>
            </div>

            {/* Live status */}
            <div className="relative rounded-2xl border border-line-1/60 dark:border-white/[0.06] bg-surface-100 dark:bg-surface-100/[0.02] p-4 shadow-sm">
              <div className="flex items-center gap-1.5 text-mini font-semibold uppercase tracking-wider text-muted mb-3">
                <Clock size={13} className="text-muted" /> Last Update
              </div>
              <div className="text-2xl font-display font-bold text-heading tabular-nums leading-none">
                {lastUpdated ? formatTime(lastUpdated) : data ? formatTime(data.generated_at) : '-'}
              </div>
              <div className="mt-2.5">
                {loading && data ? (
                  <span className="inline-flex items-center gap-1.5" aria-label="Syncing latest data">
                    <RefreshCw size={11} className="animate-spin text-rose-500" />
                    <span className="text-mini font-semibold uppercase tracking-wider text-rose-600 dark:text-rose-400">
                      SYNCING
                    </span>
                  </span>
                ) : wsConnected ? (
                  <span className="inline-flex items-center gap-1.5" aria-label="Connected via WebSocket - real-time">
                    <Wifi size={11} className="text-emerald-500" />
                    <span className="text-mini font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                      REAL-TIME
                    </span>
                  </span>
                ) : autoRefresh ? (
                  <span className="inline-flex items-center gap-1.5" aria-label="Live - polling">
                    <span className="relative flex h-2 w-2">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                      <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                    </span>
                    <span className="text-mini font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                      LIVE
                    </span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5" aria-label="Paused">
                    <WifiOff size={11} className="text-muted" />
                    <span className="text-mini font-semibold uppercase tracking-wider text-muted">PAUSED</span>
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* ─── Controls Bar ─── */}
          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Search Bar */}
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <input
                type="text"
                placeholder="Search events..."
                aria-label="Search events"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2.5 text-xs font-mono rounded-xl border border-line-1/60 dark:border-white/[0.08] bg-surface-100 dark:bg-surface-100/[0.03] text-body placeholder-slate-400 focus:outline-none focus:border-rose-500/40 focus:ring-1 focus:ring-rose-500/20 transition-colors"
              />
              <svg
                className="absolute left-3 top-2.5 w-4 h-4 text-muted"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  aria-label="Clear event search"
                  className="absolute right-2.5 top-2.5 text-muted hover:text-muted dark:hover:text-inverted"
                >
                  <X size={14} />
                </button>
              )}
            </div>

            {/* Time Range Filter */}
            <div className="inline-flex rounded-xl border border-line-1/60 dark:border-white/[0.08] overflow-hidden">
              {[
                { hours: 0, label: 'All' },
                { hours: 1, label: '1h' },
                { hours: 6, label: '6h' },
                { hours: 24, label: '24h' },
                { hours: 168, label: '7d' },
              ].map((t) => (
                <button
                  key={t.hours}
                  type="button"
                  onClick={() => setTimeRange(t.hours)}
                  className={`text-micro font-mono px-2.5 py-2 transition-colors ${
                    timeRange === t.hours
                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
                      : 'bg-white dark:bg-white/[0.02] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Map Mode Toggle */}
            <div className="inline-flex rounded-xl border border-line-1/60 dark:border-white/[0.08] overflow-hidden">
              <button
                type="button"
                onClick={() => setMapMode('3d')}
                className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 transition-colors ${
                  mapMode === '3d'
                    ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
                    : 'bg-white dark:bg-white/[0.02] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                }`}
              >
                <Box size={14} /> 3D
              </button>
              <button
                type="button"
                onClick={() => setMapMode('2d')}
                className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 transition-colors ${
                  mapMode === '2d'
                    ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
                    : 'bg-white dark:bg-white/[0.02] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                }`}
              >
                <Map size={14} /> 2D
              </button>
            </div>

            {/* Auto-Pan Toggle (3D only) */}
            {mapMode === '3d' && (
              <button
                type="button"
                onClick={() => setAutoPan((p) => !p)}
                className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded-xl border transition-colors ${
                  autoPan
                    ? 'border-indigo-500/40 bg-indigo-500/10 text-indigo-600 dark:text-indigo-400'
                    : 'border-slate-200/60 dark:border-white/[0.08] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                }`}
                title="Auto-rotate globe"
              >
                {autoPan ? <Pause size={12} /> : <Play size={12} />}
                {autoPan ? 'Rotating' : 'Auto-Pan'}
              </button>
            )}

            {/* Filters Toggle */}
            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded-xl border transition-colors ${
                showFilters
                  ? 'border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                  : 'border-slate-200/60 dark:border-white/[0.08] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
              }`}
            >
              <Filter size={14} />
              Filters
              {activeLayers.size < ALL_KINDS.length && (
                <span className="ml-1 px-1.5 py-0.5 text-micro rounded-full bg-rose-500/15 text-rose-600 dark:text-rose-400">
                  {activeLayers.size}
                </span>
              )}
            </button>

            {/* Refresh Controls */}
            <div className="flex items-center gap-2 ml-auto">
              <button
                type="button"
                onClick={() => setAutoRefresh((p) => !p)}
                aria-pressed={autoRefresh}
                title={autoRefresh ? 'Streaming - click to pause' : 'Paused - click to resume'}
                className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-xl border transition-colors ${
                  autoRefresh
                    ? wsConnected
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                    : 'border-slate-200/60 dark:border-white/[0.08] text-slate-500'
                }`}
              >
                {autoRefresh ? (
                  wsConnected ? (
                    <Wifi size={12} className="text-emerald-500" />
                  ) : (
                    <span className="relative flex h-2 w-2">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" />
                      <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                    </span>
                  )
                ) : (
                  <WifiOff size={12} className="text-muted" />
                )}
                {autoRefresh ? (wsConnected ? 'Real-time' : 'Live') : 'Paused'}
              </button>
              <button
                type="button"
                onClick={() => load(true)}
                disabled={loading}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-xl border border-line-1/60 dark:border-white/[0.08] text-muted hover:bg-surface-200 dark:hover:bg-surface-100/[0.04] transition-colors disabled:opacity-50"
              >
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                Refresh
              </button>
              <button
                type="button"
                onClick={toggleFullscreen}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-xl border border-line-1/60 dark:border-white/[0.08] text-muted hover:bg-surface-200 dark:hover:bg-surface-100/[0.04] transition-colors"
                title="Toggle fullscreen (F)"
              >
                {isFullscreen ? (
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                ) : (
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"
                    />
                  </svg>
                )}
                {isFullscreen ? 'Exit' : 'Full'}
              </button>
              <button
                type="button"
                onClick={exportToCsv}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-xl border border-line-1/60 dark:border-white/[0.08] text-muted hover:bg-surface-200 dark:hover:bg-surface-100/[0.04] transition-colors"
                title="Export to CSV"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  />
                </svg>
                Export
              </button>
            </div>
          </div>

          {/* ─── Filters Panel ─── */}
          {showFilters && (
            <div className="rounded-2xl border border-line-1/60 dark:border-white/[0.06] bg-surface-100 dark:bg-surface-100/[0.02] p-5 animate-fade-in">
              {/* Severity Filter */}
              <div className="mb-5">
                <div className="flex items-center justify-between mb-2.5">
                  <h4 className="text-mini font-semibold uppercase tracking-wider text-muted">Severity</h4>
                  <button
                    type="button"
                    onClick={() => {
                      const isCriticalOnly = severityFilter.size === 1 && severityFilter.has('critical');
                      setSeverityFilter(
                        isCriticalOnly ? new Set(['critical', 'high', 'medium', 'low']) : new Set(['critical'])
                      );
                    }}
                    className="text-micro font-mono text-rose-500 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                  >
                    {severityFilter.size === 1 && severityFilter.has('critical') ? 'Show All' : 'Critical Only'}
                  </button>
                </div>
                <div className="flex gap-2">
                  {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                    const config = SEVERITY_CONFIG[sev];
                    const active = severityFilter.has(sev);
                    return (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => {
                          setSeverityFilter((prev) => {
                            const next = new Set(prev);
                            if (next.has(sev)) next.delete(sev);
                            else next.add(sev);
                            return next;
                          });
                        }}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-mini font-mono rounded-xl border transition-all ${
                          active
                            ? `${config.bg} border-current ${config.text}`
                            : 'border-slate-200/60 dark:border-white/[0.06] text-muted opacity-60'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${active ? config.dot : 'bg-slate-400'}`} />
                        {sev}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Layer Groups */}
              {(['intel', 'social'] as const).map((group) => {
                const layers = layerGroups[group]!;
                const activeCount = layers.filter((l) => l.active).length;
                const groupLabels = { intel: 'Threat Intel', social: 'Social / OSINT' };
                return (
                  <div key={group} className="mb-5 last:mb-0">
                    <div className="flex items-center justify-between mb-2.5">
                      <h4 className="text-mini font-semibold uppercase tracking-wider text-muted">
                        {groupLabels[group]}
                        <span className="ml-2 text-muted/70">
                          {activeCount}/{layers.length}
                        </span>
                      </h4>
                      <button
                        type="button"
                        onClick={() => {
                          setActiveLayers((prev) => {
                            const next = new Set(prev);
                            const allActive = layers.every((l) => next.has(l.kind));
                            for (const l of layers) {
                              if (allActive) next.delete(l.kind);
                              else next.add(l.kind);
                            }
                            return next;
                          });
                        }}
                        className="text-micro font-mono text-rose-500 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                      >
                        {activeCount === layers.length ? 'Clear' : 'Select All'}
                      </button>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {layers.map(({ kind, def, count, active }) => (
                        <button
                          key={kind}
                          type="button"
                          onClick={() => toggleLayer(kind)}
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-micro font-mono rounded-xl border transition-all ${
                            active
                              ? count > 0
                                ? `${def.bgColor} ${def.color} border-current`
                                : 'border-slate-200/60 dark:border-white/[0.06] bg-slate-50 dark:bg-white/[0.02] text-muted'
                              : 'border-slate-200/60 dark:border-white/[0.06] text-muted opacity-50'
                          }`}
                        >
                          <span className={active && count > 0 ? def.color : 'text-muted'}>{def.icon}</span>
                          {def.shortLabel}
                          {count > 0 && (
                            <span className={`text-micro ${active ? 'opacity-70' : 'opacity-40'}`}>{count}</span>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}

              {/* Preset Buttons */}
              <div className="flex flex-wrap items-center gap-2 pt-4 border-t border-line-1 dark:border-white/[0.04]">
                <button
                  type="button"
                  onClick={() => {
                    setActiveLayers(
                      new Set([
                        'ransomware',
                        'cve',
                        'ioc_activity',
                        'cyber_attack',
                        'c2_tracker',
                        'cisa_advisory',
                        'infostealer',
                        'phishing',
                        'malware',
                        'blocklist',
                        'breach',
                        'cybercrime',
                        'scam',
                        'actor_sighting',
                        'ioc_correlation',
                        'secret_leak',
                        'malicious_package',
                        'exploit',
                        'github_advisory',
                        'kev',
                        'supply_chain_attacks',
                        'briefing',
                        'honeypot',
                        'cyberpulse',
                        'rss',
                      ])
                    );
                    setSeverityFilter(new Set(['critical', 'high', 'medium', 'low']));
                    setCtiFilter('all');
                  }}
                  className="text-micro font-mono px-3 py-1.5 rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 border border-rose-500/20 transition-colors"
                >
                  CTI Defaults
                </button>
              </div>
            </div>
          )}

          {/* ─── Main Content: Globe + Feed ─── */}
          <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_380px] gap-4">
            {/* Globe/Map Container */}
            <div
              ref={globeContainerRef}
              className="relative rounded-2xl overflow-hidden border border-line-1/60 dark:border-white/[0.06] bg-surface-300 dark:bg-[#080c14]"
              style={{ minHeight: '600px', maxHeight: isFullscreen ? '100vh' : '750px' }}
            >
              {/* Globe Status Badge */}
              <div className="absolute top-3 right-3 z-20 flex items-center gap-1.5">
                <div className="backdrop-blur-sm bg-surface-100/80 dark:bg-surface-100/[0.06] rounded-xl border border-line-1/50 dark:border-white/[0.08] px-2.5 py-1.5 flex items-center gap-1.5">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${mapMode === '3d' ? 'bg-rose-500 animate-pulse' : 'bg-emerald-500'}`}
                  />
                  <span className="text-micro font-semibold uppercase tracking-wider text-muted">
                    {mapMode === '3d' ? '3D Globe' : '2D Map'}
                  </span>
                </div>
              </div>

              {/* Empty State */}
              {geoPoints.length === 0 && (
                <div className="absolute inset-0 z-10 flex items-center justify-center">
                  <div className="backdrop-blur-xl bg-surface-100/80 dark:bg-surface-100/[0.04] rounded-2xl px-10 py-8 text-center border border-line-1/50 dark:border-white/[0.08] max-w-sm">
                    <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-surface-300 dark:bg-surface-100/[0.04] flex items-center justify-center">
                      <Crosshair size={24} className="text-muted" />
                    </div>
                    <p className="text-sm font-semibold text-heading mb-1">No Geolocated Events</p>
                    <p className="text-xs text-muted mb-4">
                      Enable more layers in the Filters panel to see points on the globe
                    </p>
                    <button
                      type="button"
                      onClick={() => setShowFilters(true)}
                      className="text-xs font-mono px-4 py-2 rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 border border-rose-500/20 transition-colors"
                    >
                      Open Filters
                    </button>
                  </div>
                </div>
              )}

              {/* Globe/Map Component */}
              {mapMode === '3d' ? (
                <Suspense
                  fallback={
                    <div className="flex items-center justify-center h-full">
                      <div className="flex flex-col items-center gap-4">
                        <div className="relative">
                          <div className="w-16 h-16 rounded-full border-2 border-rose-500/20" />
                          <div className="absolute inset-0 w-16 h-16 rounded-full border-2 border-transparent border-t-rose-500 animate-spin" />
                        </div>
                        <div className="text-center">
                          <p className="text-sm font-medium text-heading dark:text-inverted">Loading Globe</p>
                          <p className="text-xs text-muted mt-1">Initializing 3D renderer…</p>
                        </div>
                      </div>
                    </div>
                  }
                >
                  <CtiGlobe
                    arcs={globeArcs}
                    points={globePoints}
                    focus={focus}
                    onPointClick={handlePointClick}
                    autoRotate={autoPan}
                  />
                </Suspense>
              ) : (
                <Suspense
                  fallback={
                    <div className="flex items-center justify-center h-full">
                      <div className="flex flex-col items-center gap-4">
                        <div className="relative">
                          <div className="w-16 h-16 rounded-full border-2 border-rose-500/20" />
                          <div className="absolute inset-0 w-16 h-16 rounded-full border-2 border-transparent border-t-rose-500 animate-spin" />
                        </div>
                        <div className="text-center">
                          <p className="text-sm font-medium text-heading dark:text-inverted">Loading Map</p>
                          <p className="text-xs text-muted mt-1">Initializing 2D renderer…</p>
                        </div>
                      </div>
                    </div>
                  }
                >
                  <PulseMap
                    markers={geoPoints}
                    focus={focus}
                    onMarkerClick={(m) => {
                      const event = filteredEvents.find((e) => e.id === m.id);
                      if (event) setSelectedEvent(event);
                    }}
                    terminatorPolygon={terminatorPolygon}
                  />
                </Suspense>
              )}

              {/* Legend Overlay */}
              <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 via-black/30 to-transparent px-4 py-3">
                <div className="flex items-center gap-4">
                  {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                    <div key={sev} className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${SEVERITY_CONFIG[sev].dot}`} />
                      <span className="text-micro font-mono text-white/70 capitalize">{sev}</span>
                    </div>
                  ))}
                  <span className="text-micro font-mono text-white/40 ml-auto">
                    {geoPoints.length} points · {globeArcs.length} arcs
                  </span>
                </div>
              </div>
            </div>

            {/* Event Feed */}
            <aside
              className="flex flex-col rounded-2xl border border-line-1/60 dark:border-white/[0.06] bg-surface-100 dark:bg-surface-100/[0.02] shadow-sm overflow-hidden"
              style={{ minHeight: '600px', maxHeight: '750px' }}
            >
              {/* Feed Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-line-1 dark:border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-60" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-500" />
                  </span>
                  <h3 className="text-xs font-semibold text-body">Live Feed</h3>
                  <span className="text-micro font-mono text-muted">{filteredEvents.length}</span>
                </div>
                <div className="flex items-center gap-1">
                  {(() => {
                    const ransomCount = filteredEvents.filter((e) => e.kind === 'ransomware').length;
                    const cveCount = filteredEvents.filter((e) => e.cti === 'cve').length;
                    const iocCount = filteredEvents.filter((e) => e.cti === 'ioc').length;
                    return (
                      <>
                        {ransomCount > 0 && (
                          <span className="text-micro font-mono px-1.5 py-0.5 rounded-md bg-rose-500/10 text-rose-600 dark:text-rose-400">
                            R{ransomCount}
                          </span>
                        )}
                        {cveCount > 0 && (
                          <span className="text-micro font-mono px-1.5 py-0.5 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400">
                            C{cveCount}
                          </span>
                        )}
                        {iocCount > 0 && (
                          <span className="text-micro font-mono px-1.5 py-0.5 rounded-md bg-sky-500/10 text-sky-600 dark:text-sky-400">
                            I{iocCount}
                          </span>
                        )}
                      </>
                    );
                  })()}
                </div>
              </div>

              {/* CTI Quick Filters */}
              <div className="flex items-center gap-1 px-4 py-2 border-b border-line-1 dark:border-white/[0.04]">
                {[
                  { key: 'all' as const, label: 'All' },
                  { key: 'ransomware' as const, label: 'Ransomware', icon: <Skull size={11} /> },
                  { key: 'cve' as const, label: 'CVEs', icon: <Bug size={11} /> },
                  { key: 'ioc' as const, label: 'IOCs', icon: <Zap size={11} /> },
                ].map((pill) => (
                  <button
                    key={pill.key}
                    type="button"
                    onClick={() => setCtiFilter(pill.key)}
                    className={`inline-flex items-center gap-1 px-2 py-1 text-micro font-mono rounded-md transition-colors ${
                      ctiFilter === pill.key
                        ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
                        : 'text-muted hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                    }`}
                  >
                    {pill.icon}
                    {pill.label}
                  </button>
                ))}
                {ctiFilter !== 'all' && (
                  <button
                    type="button"
                    onClick={() => setCtiFilter('all')}
                    className="ml-auto text-micro font-mono text-muted hover:text-muted dark:hover:text-inverted"
                  >
                    <X size={11} />
                  </button>
                )}
              </div>

              {/* Trending now — corroborated critical/highs, jumps to the event */}
              {trendingNow.length > 0 && (
                <div className="px-4 py-2 border-b border-line-1 dark:border-white/[0.04] bg-amber-500/[0.04]">
                  <div className="text-micro font-mono uppercase tracking-wider text-amber-600 dark:text-amber-400 mb-1.5">
                    ▲ Trending now
                  </div>
                  <div className="flex flex-col gap-1">
                    {trendingNow.map((e) => (
                      <button
                        key={`trend-${e.id}`}
                        type="button"
                        onClick={() => {
                          setSelectedEvent(e);
                          if (e.lat !== 0 || e.lng !== 0) setFocus({ lat: e.lat, lng: e.lng });
                        }}
                        className="text-left text-mini font-mono text-body hover:text-rose-500 truncate"
                        title={`${e.title} — ${e.description}`}
                      >
                        <span
                          className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${
                            e.severity === 'critical' ? 'bg-rose-500' : 'bg-orange-500'
                          }`}
                        />
                        {e.title}
                        <span className="text-muted/70 ml-1.5">{e.source}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Feed List */}
              <div className="flex-1 overflow-y-auto custom-scrollbar" aria-label="CTI live event feed">
                <span className="sr-only" role="status" aria-live="polite">
                  {filteredEvents.length} events in feed, {kpis.critical} critical
                </span>
                {filteredEvents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-center px-4">
                    <Filter size={28} className="text-inverted mb-4" />
                    <p className="text-xs font-medium text-muted">No events match filters</p>
                    <p className="text-mini text-muted mt-1">Adjust layers or severity</p>
                    <button
                      type="button"
                      onClick={() => {
                        setActiveLayers(new Set(ALL_KINDS));
                        setSeverityFilter(new Set(['critical', 'high', 'medium', 'low']));
                      }}
                      className="mt-4 text-mini font-mono px-3 py-1.5 rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 transition-colors"
                    >
                      Reset Filters
                    </button>
                  </div>
                ) : (
                  <div className="divide-y divide-line-1/80 dark:divide-white/[0.04]">
                    {filteredEvents.slice(0, 80).map((ev) => {
                      const def = LAYER_DEFS[ev.kind];
                      const sevConfig = SEVERITY_CONFIG[ev.severity];
                      const isSelected = selectedEvent?.id === ev.id;
                      const hasGeo = ev.lat !== 0 || ev.lng !== 0;
                      const isCti = ctiPriority(ev.cti) > 0;
                      const ctiBorder =
                        ev.cti === 'ransomware'
                          ? 'border-l-rose-500'
                          : ev.cti === 'cve'
                            ? 'border-l-amber-500'
                            : ev.cti === 'ioc'
                              ? 'border-l-sky-500'
                              : 'border-l-transparent';

                      return (
                        <button
                          key={ev.id}
                          type="button"
                          onClick={() => {
                            setSelectedEvent(isSelected ? null : ev);
                            if (hasGeo) setFocus({ lat: ev.lat, lng: ev.lng });
                          }}
                          className={`w-full text-left px-4 py-3 border-l-2 transition-all ${
                            isSelected
                              ? 'bg-rose-500/5 border-l-rose-500'
                              : `hover:bg-surface-200/80 dark:hover:bg-surface-100/[0.02] ${ctiBorder}`
                          }`}
                        >
                          <div className="flex items-start gap-2.5">
                            {/* Severity dot */}
                            <div className="shrink-0 mt-1 relative">
                              <span className={`w-2 h-2 rounded-full block ${sevConfig.dot}`} />
                              {sevConfig.pulse && (
                                <span className="absolute inset-0 w-2 h-2 rounded-full bg-rose-500 animate-ping opacity-40" />
                              )}
                            </div>

                            {/* Content */}
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-1.5 mb-0.5">
                                <span className={def?.color ?? 'text-muted'}>{def?.icon}</span>
                                <span className="text-micro font-mono uppercase tracking-wider text-muted">
                                  {def?.shortLabel}
                                </span>
                                <span className="text-micro font-mono text-muted/70 ml-auto">
                                  {formatTime(ev.timestamp)}
                                </span>
                              </div>
                              <p className="text-mini font-medium text-heading line-clamp-1">{ev.title}</p>
                              <p className="text-micro text-muted line-clamp-1 mt-0.5">{ev.description}</p>
                              <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                                <span className="text-micro font-mono text-muted/70">{ev.source}</span>
                                {ev.kev && (
                                  <span
                                    className="text-micro font-mono font-bold px-1 rounded bg-rose-500/15 text-rose-600 dark:text-rose-400"
                                    title="CISA KEV-listed — confirmed exploited in the wild"
                                  >
                                    0-DAY
                                  </span>
                                )}
                                {ev.exploitStatus && (
                                  <span
                                    className="text-micro font-mono px-1 rounded bg-orange-500/15 text-orange-600 dark:text-orange-400"
                                    title={`Public exploit code: ${ev.exploitStatus.replace(/_/g, ' ')}`}
                                  >
                                    PoC
                                  </span>
                                )}
                                {ev.trending && (
                                  <span
                                    className="text-micro font-mono px-1 rounded bg-amber-500/15 text-amber-600 dark:text-amber-400"
                                    title="Reported by 2+ distinct sources in this build"
                                  >
                                    ▲ trending
                                  </span>
                                )}
                                {ev.kind === 'cve' && ev.magnitude != null && (
                                  <span
                                    className={`text-micro font-mono font-bold px-1 rounded ${
                                      ev.magnitude >= 9.0
                                        ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400'
                                        : ev.magnitude >= 7.0
                                          ? 'bg-orange-500/15 text-orange-600 dark:text-orange-400'
                                          : ev.magnitude >= 4.0
                                            ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400'
                                            : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                                    }`}
                                  >
                                    CVSS {ev.magnitude.toFixed(1)}
                                  </span>
                                )}
                                {isCti && (
                                  <span
                                    className={`text-micro font-mono ${
                                      ev.cti === 'ransomware'
                                        ? 'text-rose-500'
                                        : ev.cti === 'cve'
                                          ? 'text-amber-500'
                                          : ev.cti === 'ioc'
                                            ? 'text-sky-500'
                                            : 'text-muted'
                                    }`}
                                  >
                                    {ev.cti}
                                  </span>
                                )}
                                {hasGeo && (
                                  <span className="text-micro font-mono text-rose-500/60 flex items-center gap-0.5">
                                    <Crosshair size={7} /> geo
                                  </span>
                                )}
                                {ev.url && (
                                  <a
                                    href={sanitizeUrl(ev.url) || undefined}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="text-micro font-mono text-rose-500/60 hover:text-rose-500 hover:underline ml-auto flex items-center gap-0.5"
                                  >
                                    <ExternalLink size={9} />
                                  </a>
                                )}
                              </div>
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </aside>
          </div>

          {/* ─── Selected Event Detail ─── */}
          {selectedEvent && (
            <div className="rounded-2xl border border-line-1/60 dark:border-white/[0.06] bg-surface-100 dark:bg-surface-100/[0.02] p-5 animate-fade-in">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className={LAYER_DEFS[selectedEvent.kind]?.color}>
                      {LAYER_DEFS[selectedEvent.kind]?.icon}
                    </span>
                    <h3 className="text-sm font-bold text-heading">{selectedEvent.title}</h3>
                    <SeverityPill severity={selectedEvent.severity} />
                  </div>
                  <p className="text-xs text-muted leading-relaxed mb-4">{selectedEvent.description}</p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div>
                      <span className="text-micro font-mono uppercase tracking-wider text-muted block mb-0.5">
                        Source
                      </span>
                      <span className="text-mini font-mono text-body">{selectedEvent.source}</span>
                    </div>
                    <div>
                      <span className="text-micro font-mono uppercase tracking-wider text-muted block mb-0.5">
                        Type
                      </span>
                      <span className="text-mini font-mono text-body">
                        {LAYER_DEFS[selectedEvent.kind]?.label ?? selectedEvent.kind}
                      </span>
                    </div>
                    <div>
                      <span className="text-micro font-mono uppercase tracking-wider text-muted block mb-0.5">
                        Time
                      </span>
                      <span className="text-mini font-mono text-body">{formatTimeFull(selectedEvent.timestamp)}</span>
                    </div>
                    {selectedEvent.country && (
                      <div>
                        <span className="text-micro font-mono uppercase tracking-wider text-muted block mb-0.5">
                          Country
                        </span>
                        <span className="text-mini font-mono text-body">{selectedEvent.country}</span>
                      </div>
                    )}
                    {(selectedEvent.lat !== 0 || selectedEvent.lng !== 0) && (
                      <div>
                        <span className="text-micro font-mono uppercase tracking-wider text-muted block mb-0.5">
                          Coordinates
                        </span>
                        <span className="text-mini font-mono text-body">
                          {selectedEvent.lat.toFixed(4)}, {selectedEvent.lng.toFixed(4)}
                        </span>
                      </div>
                    )}
                    {selectedEvent.magnitude != null && (
                      <div>
                        <span className="text-micro font-mono uppercase tracking-wider text-muted block mb-0.5">
                          Magnitude
                        </span>
                        <span className="text-mini font-mono text-body">{selectedEvent.magnitude.toFixed(1)}</span>
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-4">
                    {selectedEvent.url && (
                      <a
                        href={sanitizeUrl(selectedEvent.url) || undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                      >
                        <ExternalLink size={11} /> View source
                      </a>
                    )}
                    <button
                      type="button"
                      onClick={() => setShowAiAnalysis((p) => !p)}
                      className={`inline-flex items-center gap-1.5 text-mini font-mono px-3 py-1.5 rounded-xl border transition-colors ${
                        showAiAnalysis
                          ? 'border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                          : 'border-slate-200/60 dark:border-white/[0.08] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                      }`}
                    >
                      <Brain size={11} />
                      {showAiAnalysis ? 'Hide Analysis' : 'AI Analysis'}
                    </button>
                    {selectedEvent.country && (
                      <button
                        type="button"
                        onClick={() => setShowCountryIntel((p) => !p)}
                        className={`inline-flex items-center gap-1.5 text-mini font-mono px-3 py-1.5 rounded-xl border transition-colors ${
                          showCountryIntel
                            ? 'border-purple-500/40 bg-purple-500/10 text-purple-600 dark:text-purple-400'
                            : 'border-slate-200/60 dark:border-white/[0.08] text-slate-500 hover:bg-slate-50 dark:hover:bg-white/[0.04]'
                        }`}
                      >
                        <Globe size={11} />
                        {showCountryIntel ? 'Hide Intel' : `${selectedEvent.country} Intel`}
                      </button>
                    )}
                    <AlertShareRow event={selectedEvent} />
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedEvent(null);
                    setShowAiAnalysis(false);
                  }}
                  className="shrink-0 p-1.5 rounded-xl text-muted hover:text-muted dark:hover:text-inverted hover:bg-surface-300 dark:hover:bg-surface-100/[0.04] transition-colors"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
          )}

          {/* ─── AI Threat Analysis Panel ─── */}
          {selectedEvent && showAiAnalysis && (
            <ThreatAnalysisPanel
              type="event"
              title={selectedEvent.title}
              description={selectedEvent.description}
              country={selectedEvent.country}
              severity={selectedEvent.severity}
              kind={selectedEvent.kind}
              source={selectedEvent.source}
              onClose={() => setShowAiAnalysis(false)}
            />
          )}

          {/* ─── Country Intelligence Panel ─── */}
          {showCountryIntel && (
            <CountryIntelPanel
              country={selectedEvent?.country || 'Global'}
              events={filteredEvents
                .filter((e) => e.country === selectedEvent?.country)
                .slice(0, 10)
                .map((e) => ({
                  title: e.title,
                  kind: e.kind,
                  severity: e.severity,
                  source: e.source,
                }))}
              onClose={() => setShowCountryIntel(false)}
            />
          )}
        </div>
      )}
    </DataPageLayout>
  );
}

function AlertShareRow({ event }: { event: PulseEvent }) {
  const shareText = `${event.title} — ${event.source} #ThreatIntel #CyberSecurity`;
  return (
    <span className="ml-auto">
      <ShareBar shareText={shareText} size="sm" label="Share:" />
    </span>
  );
}
