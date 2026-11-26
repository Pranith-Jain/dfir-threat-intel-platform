/**
 * Global Hack Map — full-screen situation room.
 *
 * Re-implements the layout and information architecture of
 * globalhackmap.vercel.app (globe + top ticker + live HUD + patch dock +
 * dossier + check/brief/agents) with this platform's design tokens and live
 * APIs. No upstream code or prose is vendored.
 */
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type JSX } from 'react';
import { errMessage } from '../../lib/log';
import { useDataFetch } from '../../hooks/useDataFetch';
import type { CtiPoint } from '../../components/threatintel/cti/geo';
import { ThreatAnalysisPanel } from '../../components/threatintel/ThreatAnalysisPanel';
import { PageMeta } from '../../components/PageMeta';
import type { GlobalPulseResponse, PulseEvent } from './global-pulse-types';
import { EVIDENCE_STATUSES, STATUS_META, incidentStatus, type EvidenceStatus } from '../../lib/pulse-status';
import {
  AgentsPanel,
  BriefPanel,
  CheckPanel,
  DetailPanel,
  MobileSidebarToggle,
  PatchDock,
  StorySidebar,
  TopBar,
} from './global-hack-map/Panels';
import {
  WINDOW_MS,
  type GhmCve,
  type GhmCveFeed,
  type GhmIncident,
  type GhmIncidentFeed,
  type GhmFeedRow,
  type GhmPatchFeed,
  type GhmTab,
  type GhmTrending,
  type GhmWindow,
} from './global-hack-map/types';

const CtiGlobe = lazy(() => import('../../components/threatintel/cti/CtiGlobe'));

const SIDEBAR_W = 380;
const PANEL_W = 380;
/** Stable module-level reference: CtiGlobe's `arcsData` effect keys on this. */
const NO_ARCS: never[] = [];

/** Merge the live CVE feed with the Bluesky-attention mirror, once by id. */
function mergeCves(feed: GhmCveFeed | null, trending: GhmTrending | null): GhmCve[] {
  const out: GhmCve[] = [...(feed?.cves ?? [])];
  const seen = new Set(out.map((c) => c.id));
  for (const item of trending?.items ?? []) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    out.push({
      id: item.id,
      published: item.lastPostedAt ?? new Date().toISOString(),
      description: item.title,
      severity: item.severity === 'UNKNOWN' ? 'UNKNOWN' : (item.severity as GhmCve['severity']),
      score: item.cvss,
      kev: item.exploited,
      kev_ransomware: false,
      has_exploit: false,
      origin: 'vulntracker',
      listed_by_count: 1,
      epss: undefined,
    });
  }
  return out;
}

function loadStack(): string[] {
  try {
    const raw = localStorage.getItem('ghm:stack');
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string').slice(0, 20) : [];
  } catch {
    return [];
  }
}

export default function GlobalHackMap(): JSX.Element {
  const { data: pulse, error } = useDataFetch<GlobalPulseResponse>({ url: '/api/v1/global-pulse', ttl: 60_000 });
  const { data: cveFeed } = useDataFetch<GhmCveFeed>({ url: '/api/v1/cve-recent?limit=150', ttl: 5 * 60_000 });
  const { data: trending } = useDataFetch<GhmTrending>({
    url: '/data/cve-intel/vulntracker-trending.json',
    ttl: 10 * 60_000,
  });
  const { data: incidentFeed } = useDataFetch<GhmIncidentFeed>({
    url: '/data/global-hack-map/incidents.json',
    ttl: 10 * 60_000,
  });
  const { data: patchFeed } = useDataFetch<GhmPatchFeed>({
    url: '/data/global-hack-map/patches.json',
    ttl: 10 * 60_000,
  });
  const { data: malwarePkgs } = useDataFetch<{
    generated_at: string;
    packages: Array<{ name: string; ecosystem: string; ossf_url: string }>;
  }>({ url: '/api/v1/malicious-packages?ecosystem=npm', ttl: 15 * 60_000 });
  const { data: malwareSamples } = useDataFetch<{
    generated_at: string;
    samples: Array<{
      sha256: string;
      first_seen: string;
      signature: string;
      file_type: string;
      tags: string[];
      bazaar_url: string;
    }>;
  }>({ url: '/api/v1/malware-samples', ttl: 15 * 60_000 });
  const { data: maritime } = useDataFetch<{ incidents: Array<Record<string, unknown>> }>({
    url: '/api/v1/ukmto-incidents',
    ttl: 15 * 60_000,
  });

  // GHM opens on 7d — 24h is too narrow for incident feeds and leaves the map sparse.
  const [timeWindow, setTimeWindow] = useState<GhmWindow>('7d');
  const [statusFilter, setStatusFilter] = useState<Set<EvidenceStatus>>(new Set(EVIDENCE_STATUSES));
  const [query, setQuery] = useState('');
  const [tab, setTab] = useState<GhmTab>('cves');
  const [stack, setStack] = useState<string[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [checkOpen, setCheckOpen] = useState(false);
  const [briefOpen, setBriefOpen] = useState(false);
  const [agentsOpen, setAgentsOpen] = useState(false);
  const [showAnalysis, setShowAnalysis] = useState(false);
  const [patchOpen, setPatchOpen] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobile, setMobile] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  // Stack is the only visitor state we keep — locally, never uploaded.
  useEffect(() => {
    setStack(loadStack());
    const mq = window.matchMedia('(max-width: 767px)');
    const update = () => setMobile(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem('ghm:stack', JSON.stringify(stack));
    } catch (e) {
      errMessage(e);
    }
  }, [stack]);

  const cves = useMemo(() => mergeCves(cveFeed, trending), [cveFeed, trending]);
  const cveIndex = useMemo(() => new Map(cves.map((c) => [c.id, c])), [cves]);

  const windowEvents = useMemo(() => {
    const now = Date.now();
    const all = pulse?.events ?? [];
    return all.filter((e) => now - Date.parse(e.timestamp) <= WINDOW_MS[timeWindow]);
  }, [pulse, timeWindow]);

  const events = useMemo(
    () =>
      windowEvents.filter((e) => {
        const status = incidentStatus(e);
        return !status || statusFilter.has(status);
      }),
    [windowEvents, statusFilter]
  );

  // GHM's own incident dataset (RSS mirror) is the backbone: real victims,
  // honest statuses, records and locations. Global Pulse events supplement it.
  const windowIncidents = useMemo(() => {
    const now = Date.now();
    return (incidentFeed?.incidents ?? []).filter((i) => now - Date.parse(i.published) <= WINDOW_MS[timeWindow]);
  }, [incidentFeed, timeWindow]);
  const incidents = useMemo(
    () => windowIncidents.filter((i) => statusFilter.has(i.status)),
    [windowIncidents, statusFilter]
  );
  const orgCount = useMemo(() => new Set(incidents.map((i) => i.victim.toLowerCase())).size, [incidents]);

  const statusCounts = useMemo(() => {
    const counts = {} as Record<EvidenceStatus, number>;
    for (const status of EVIDENCE_STATUSES) counts[status] = 0;
    for (const i of windowIncidents) counts[i.status]++;
    // Only fall back to pulse-derived statuses when the incident feed is empty.
    if (!windowIncidents.length) {
      for (const e of windowEvents) {
        const status = incidentStatus(e);
        if (status) counts[status]++;
      }
    }
    return counts;
  }, [windowIncidents, windowEvents]);

  // Distinct organisations per 24h over the last 14 days — GHM's day bars.
  const dayBars = useMemo(() => {
    const DAY = 86_400_000;
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    return Array.from({ length: 14 }, (_, index) => {
      const start = today.getTime() - (13 - index) * DAY;
      const end = start + DAY;
      const victims = new Set(
        windowIncidents
          .filter((i) => {
            const t = Date.parse(i.published);
            return t >= start && t < end;
          })
          .map((i) => i.victim.toLowerCase())
      );
      return { date: new Date(start).toISOString().slice(0, 10), count: victims.size };
    });
  }, [windowIncidents]);

  const fresh = useMemo(
    () =>
      [...cves]
        .filter((c) => c.kev || c.has_exploit || (c.score ?? 0) >= 9)
        .sort((a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? 0) - (a.score ?? 0))
        .slice(0, 24),
    [cves]
  );
  const patchNow = useMemo(() => fresh.filter((c) => c.kev || c.has_exploit).slice(0, 8), [fresh]);

  // Malware + "outages" (maritime/connectivity) are their own live feeds —
  // they must not be derived from the CVE/incident rows, or the tabs stay empty.
  const malwareFeed = useMemo<GhmFeedRow[]>(() => {
    const samples: GhmFeedRow[] = (malwareSamples?.samples ?? []).slice(0, 25).map((s) => ({
      id: s.sha256,
      title: s.signature || s.tags?.[0] || 'Unnamed malware sample',
      description: `${s.file_type} · ${s.tags?.slice(0, 3).join(', ') || 'no family tag'} · SHA-256 ${s.sha256.slice(0, 16)}…`,
      source: 'MalwareBazaar',
      timestamp: s.first_seen,
      url: s.bazaar_url,
    }));
    const packages: GhmFeedRow[] = (malwarePkgs?.packages ?? []).slice(0, 25).map((p) => ({
      id: `${p.ecosystem}:${p.name}`,
      title: `${p.name} (${p.ecosystem})`,
      description: 'Malicious package published in the OpenSSF curated database.',
      source: 'OpenSSF',
      timestamp: malwarePkgs?.generated_at ?? '',
      url: p.ossf_url,
    }));
    return [...samples, ...packages];
  }, [malwareSamples, malwarePkgs]);

  const outageFeed = useMemo<GhmFeedRow[]>(() => {
    const rows = (maritime?.incidents ?? []).slice(0, 20);
    if (rows.length) {
      return rows.map((raw, index) => {
        const record = raw as Record<string, unknown>;
        const str = (key: string) => String(record[key] ?? '');
        return {
          id: str('id') || str('reference') || `ukmto-${index}`,
          title: str('title') || str('description') || 'Maritime incident',
          description: str('description') || str('advice') || 'Maritime security incident from the UKMTO feed.',
          source: 'UKMTO',
          timestamp: str('date') || str('timestamp') || str('published') || '',
          url: str('url') || undefined,
        };
      });
    }
    // UKMTO is often empty. Fall back to the connectivity / maritime / disaster
    // layers already present in Global Pulse so the tab is honest, not blank.
    return windowEvents
      .filter((e) => /firm|maritime|earthquake|outage|disaster/i.test(`${e.kind} ${e.title}`))
      .slice(0, 20)
      .map((e) => ({
        id: e.id,
        title: e.title,
        description: e.description,
        source: e.source,
        timestamp: e.timestamp,
        url: e.url,
      }));
  }, [maritime, windowEvents]);

  const selectedEvent = useMemo(() => events.find((e) => e.id === selectedId) ?? null, [events, selectedId]);
  const selectedCve = selectedCveId ? (cveIndex.get(selectedCveId) ?? null) : null;
  const selectedIncident = useMemo(
    () => incidents.find((i) => i.id === selectedIncidentId) ?? null,
    [incidents, selectedIncidentId]
  );

  const points: CtiPoint[] = useMemo(() => {
    const fromIncidents = incidents
      .filter((i) => i.lat !== 0 || i.lng !== 0)
      .map((i) => ({
        lat: i.lat,
        lng: i.lng,
        // Keep severity 'low': CtiGlobe draws a large animated ring for every
        // critical/high point, which turns a dense map into red blocks. Colour
        // still comes from kindColor(), so the dots stay meaningful.
        severity: 'low' as CtiPoint['severity'],
        count: 1,
        label: `${i.victim} · ${STATUS_META[i.status].label}`,
        countryCode: i.country ?? '',
        kind: 'breach',
        source: i.url,
        description: `${i.description.slice(0, 180)}${i.records ? ` · ${i.records.toLocaleString()} records` : ''}`,
      }));
    const fromEvents = events
      .filter((e) => e.lat !== 0 || e.lng !== 0)
      .slice(0, 300)
      .map((e) => ({
        lat: e.lat,
        lng: e.lng,
        severity: 'low' as CtiPoint['severity'],
        count: 1,
        label: e.title,
        countryCode: e.country ?? '',
        kind: e.kind,
        source: e.source,
        description: e.description,
        magnitude: e.magnitude,
      }));
    return [...fromIncidents, ...fromEvents].slice(0, 400);
  }, [incidents, events]);
  // No arcs: synthesizeArcs() draws every point to one fixed focal node, which
  // reads as a red starburst rather than a real incident globe.
  const arcs = NO_ARCS;

  const briefItems = useMemo(
    () => [
      ...incidents.slice(0, 12).map((i) => ({
        title: `${i.victim}: ${STATUS_META[i.status].label} ${i.type}`,
        body: i.description,
        source: 'Global Hack Map feed',
      })),
      ...events.slice(0, 8).map((e) => ({ title: e.title, body: e.description, source: e.source })),
      ...fresh.slice(0, 8).map((c) => ({ title: c.id, body: c.description, source: c.kev ? 'CISA KEV' : 'CVE feed' })),
    ],
    [incidents, events, fresh]
  );
  const dayKey = pulse?.generated_at?.slice(0, 10) ?? new Date().toISOString().slice(0, 10);

  const toggleStatus = useCallback((status: EvidenceStatus) => {
    setStatusFilter((prev) => {
      const next = new Set(prev);
      if (next.has(status)) next.delete(status);
      else next.add(status);
      return next.size ? next : new Set(EVIDENCE_STATUSES);
    });
  }, []);

  const selectEvent = useCallback((event: PulseEvent) => {
    setSelectedId(event.id);
    setSelectedCveId(null);
    setSelectedIncidentId(null);
    setShowAnalysis(false);
  }, []);
  const selectCve = useCallback((id: string) => {
    setSelectedCveId(id);
    setSelectedId(null);
    setSelectedIncidentId(null);
    setShowAnalysis(false);
  }, []);
  const selectIncident = useCallback((incident: GhmIncident) => {
    setSelectedIncidentId(incident.id);
    setSelectedId(null);
    setSelectedCveId(null);
    setShowAnalysis(false);
  }, []);
  const closeDossier = useCallback(() => {
    setSelectedId(null);
    setSelectedCveId(null);
    setSelectedIncidentId(null);
    setShowAnalysis(false);
  }, []);

  // Deep links: ?i=<incident/event> and ?cve=<id> open the same dossier the UI does.
  const allIncidents = useMemo(() => incidentFeed?.incidents ?? [], [incidentFeed]);
  const deepLinkApplied = useRef(false);
  useEffect(() => {
    if (deepLinkApplied.current) return;
    const params = new URLSearchParams(window.location.search);
    const cve = params.get('cve');
    const incident = params.get('i');
    if (cve) {
      // CVE deep links do not depend on any feed — resolve immediately.
      deepLinkApplied.current = true;
      setSelectedCveId(cve.toUpperCase());
      return;
    }
    if (!incident) return;
    // Wait for the incident mirror. Previously this ran on the first render
    // with an empty feed, missed the match, and marked the link applied — so
    // a breach URL silently fell back to a Pulse event id that did not exist.
    if (!incidentFeed) return;
    deepLinkApplied.current = true;
    const match = allIncidents.find((i) => i.id === incident);
    if (match) setSelectedIncidentId(match.id);
    else setSelectedId(incident);
  }, [allIncidents, incidentFeed]);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    // Do not round-trip away a deep link until it has been resolved above.
    // This effect used to strip `?i=` on mount, so the resolving effect could
    // never read it after the feed arrived.
    if (!deepLinkApplied.current && (params.has('cve') || params.has('i'))) return;
    params.delete('cve');
    params.delete('i');
    if (selectedCveId) params.set('cve', selectedCveId);
    else if (selectedIncidentId) params.set('i', selectedIncidentId);
    else if (selectedId) params.set('i', selectedId);
    const qs = params.toString();
    const url = `${window.location.pathname}${qs ? `?${qs}` : ''}`;
    if (url !== `${window.location.pathname}${window.location.search}`) window.history.replaceState(null, '', url);
  }, [selectedCveId, selectedId, selectedIncidentId]);

  // Keyboard: ⌘K // focuses search, Esc closes, j/k steps incidents.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) return;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setSidebarOpen(true);
        requestAnimationFrame(() => searchRef.current?.focus());
        return;
      }
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (event.key === '/') {
        event.preventDefault();
        setSidebarOpen(true);
        requestAnimationFrame(() => searchRef.current?.focus());
      } else if (event.key === 'Escape') {
        if (checkOpen) setCheckOpen(false);
        else if (briefOpen) setBriefOpen(false);
        else if (agentsOpen) setAgentsOpen(false);
        else closeDossier();
      } else if ((event.key === 'j' || event.key === 'k') && events.length) {
        const index = events.findIndex((e) => e.id === selectedId);
        const step = event.key === 'j' ? 1 : -1;
        selectEvent(events[(index + step + events.length) % events.length]!);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [events, selectedId, checkOpen, briefOpen, agentsOpen, closeDossier, selectEvent]);

  const panelOpen = Boolean(selectedEvent || selectedCve || selectedIncident);
  const globeStyle: React.CSSProperties = mobile
    ? { left: 0, right: 0, top: 72, bottom: patchOpen && panelOpen ? 210 : 64 }
    : {
        left: sidebarOpen ? SIDEBAR_W : 0,
        right: panelOpen ? PANEL_W : 0,
        top: 80,
        bottom: patchOpen ? 196 : 56,
      };

  return (
    <main
      className="relative h-dvh w-full overflow-hidden bg-surface-300 dark:bg-[#080c14]"
      aria-label="Global Hack Map situation room"
    >
      <PageMeta
        title="Global Hack Map"
        description="Live exploits, breaches and vulnerabilities on one globe - honest evidence statuses, patch-now cards, one-click agent fixes and an opt-in AI brief."
        section="Threat Intel"
        canonicalPath="/threatintel/global-hack-map"
      />
      {/* Globe fills the space left between the HUD panels. */}
      <div className="absolute transition-[left,right] duration-300" style={globeStyle}>
        {points.length ? (
          <Suspense
            fallback={
              <div className="flex h-full items-center justify-center">
                <div className="h-16 w-16 animate-pulse rounded-full border border-line-1 bg-surface-100/40" />
              </div>
            }
          >
            <CtiGlobe
              arcs={arcs}
              points={points}
              focus={null}
              autoRotate
              flatPoints
              onPointClick={(p) => {
                const incident = incidents.find((i) => p.label.startsWith(`${i.victim} ·`));
                if (incident) {
                  selectIncident(incident);
                  return;
                }
                const event = events.find((e) => e.title === p.label);
                if (event) selectEvent(event);
              }}
            />
          </Suspense>
        ) : (
          <div className="flex h-full items-center justify-center">
            <div className="max-w-sm rounded-2xl border border-line-1 bg-surface-100/70 px-8 py-6 text-center">
              <p className="text-sm font-semibold text-heading">
                {error ? 'The live picture is unavailable' : 'No geolocated events in this window'}
              </p>
              <p className="mt-1 text-mini text-muted">
                {error ??
                  'Widen the time window or clear the status filters — an empty map is a fact, not a guarantee.'}
              </p>
            </div>
          </div>
        )}
      </div>

      <TopBar
        generatedAt={pulse?.generated_at ?? null}
        fresh={fresh}
        onSelectCve={selectCve}
        onCheck={() => setCheckOpen(true)}
        onBrief={() => setBriefOpen(true)}
        onAgents={() => setAgentsOpen(true)}
        onMap={closeDossier}
      />

      {sidebarOpen && !mobile && (
        <div className="pointer-events-none absolute bottom-0 left-0 top-[72px] z-20 w-[380px] pt-2 pl-2 pb-2">
          <div className="pointer-events-auto h-full rounded-r-2xl overflow-hidden">
            <StorySidebar
              events={events}
              incidents={incidents}
              malwareRows={malwareFeed}
              outageRows={outageFeed}
              orgCount={orgCount}
              dayBars={dayBars}
              onSelectIncident={selectIncident}
              cves={cves}
              generatedAt={pulse?.generated_at ?? null}
              window={timeWindow}
              onWindow={setTimeWindow}
              statusFilter={statusFilter}
              onToggleStatus={toggleStatus}
              statusCounts={statusCounts}
              query={query}
              onQuery={setQuery}
              tab={tab}
              onTab={setTab}
              stack={stack}
              onStack={setStack}
              onSelectEvent={selectEvent}
              onSelectCve={selectCve}
              onCheck={() => setCheckOpen(true)}
              onBrief={() => setBriefOpen(true)}
              searchRef={searchRef}
            />
          </div>
        </div>
      )}

      {mobile && sidebarOpen && (
        <div className="pointer-events-auto absolute inset-x-2 bottom-12 top-[112px] z-20 overflow-hidden rounded-2xl">
          <StorySidebar
            events={events}
            incidents={incidents}
            malwareRows={malwareFeed}
            outageRows={outageFeed}
            orgCount={orgCount}
            dayBars={dayBars}
            onSelectIncident={selectIncident}
            cves={cves}
            generatedAt={pulse?.generated_at ?? null}
            window={timeWindow}
            onWindow={setTimeWindow}
            statusFilter={statusFilter}
            onToggleStatus={toggleStatus}
            statusCounts={statusCounts}
            query={query}
            onQuery={setQuery}
            tab={tab}
            onTab={setTab}
            stack={stack}
            onStack={setStack}
            onSelectEvent={(e) => {
              selectEvent(e);
              setSidebarOpen(false);
            }}
            onSelectCve={(id) => {
              selectCve(id);
              setSidebarOpen(false);
            }}
            onCheck={() => setCheckOpen(true)}
            onBrief={() => setBriefOpen(true)}
            searchRef={searchRef}
          />
        </div>
      )}
      <MobileSidebarToggle open={sidebarOpen} onClick={() => setSidebarOpen((o) => !o)} />

      {panelOpen && !mobile && (
        <div className="pointer-events-none absolute bottom-0 right-0 top-[72px] z-20 w-[380px] pb-2 pr-2 pt-2">
          <div className="pointer-events-auto h-full overflow-hidden rounded-l-2xl">
            <DetailPanel
              event={selectedEvent}
              cve={selectedCve}
              incident={selectedIncident}
              onClose={closeDossier}
              onAnalyze={() => setShowAnalysis((v) => !v)}
            />
          </div>
        </div>
      )}
      {panelOpen && mobile && (
        <div className="pointer-events-auto absolute inset-x-2 bottom-12 top-[112px] z-30 overflow-hidden rounded-2xl">
          <DetailPanel
            event={selectedEvent}
            cve={selectedCve}
            incident={selectedIncident}
            onClose={closeDossier}
            onAnalyze={() => setShowAnalysis((v) => !v)}
          />
        </div>
      )}

      <PatchDock
        cves={patchNow}
        patches={patchFeed?.patches ?? []}
        generatedAt={patchFeed?.generatedAt ?? null}
        onSelectCve={selectCve}
        open={patchOpen}
        onOpenChange={setPatchOpen}
      />

      {showAnalysis && (selectedEvent || selectedCve || selectedIncident) && (
        <div className="pointer-events-auto absolute bottom-4 right-4 z-30 w-[min(420px,calc(100%-2rem))]">
          <ThreatAnalysisPanel
            type="event"
            title={selectedCve?.id ?? selectedIncident?.title ?? selectedEvent!.title}
            description={selectedCve?.description ?? selectedIncident?.description ?? selectedEvent!.description}
            country={selectedIncident?.country ?? selectedEvent?.country}
            severity={
              selectedCve?.severity?.toLowerCase() === 'critical'
                ? 'critical'
                : (selectedEvent?.severity ?? (selectedIncident?.status === 'confirmed' ? 'high' : 'medium'))
            }
            kind={selectedEvent?.kind ?? 'breach'}
            source={
              selectedCve?.kev
                ? 'CISA KEV'
                : selectedIncident
                  ? 'Global Hack Map feed'
                  : (selectedEvent?.source ?? 'CVE feed')
            }
            onClose={() => setShowAnalysis(false)}
          />
        </div>
      )}

      {checkOpen && (
        <CheckPanel
          cves={cves}
          events={windowEvents}
          stack={stack}
          onStack={setStack}
          onSelectCve={selectCve}
          onClose={() => setCheckOpen(false)}
        />
      )}
      {briefOpen && <BriefPanel items={briefItems} dayKey={dayKey} onClose={() => setBriefOpen(false)} />}
      {agentsOpen && <AgentsPanel onClose={() => setAgentsOpen(false)} />}
    </main>
  );
}
