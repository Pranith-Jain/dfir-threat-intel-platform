/**
 * HUD panels for the Global Hack Map-style situation room.
 * Re-implements the information architecture of globalhackmap.vercel.app
 * (top bar + live HUD + globe + patch dock + dossier) using this platform's
 * design tokens and data — no upstream code or prose is vendored.
 */
import { useMemo, useState, type JSX, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ArrowUpRight,
  Bug,
  ChevronDown,
  ChevronUp,
  CircleHelp,
  ExternalLink,
  Flame,
  GitBranch,
  Globe2,
  Package,
  Radio,
  Search,
  ShieldAlert,
  Sparkles,
  Users,
  Wrench,
  X,
} from 'lucide-react';
import type { PulseEvent } from '../global-pulse-types';
import { EVIDENCE_STATUSES, STATUS_META, incidentStatus, type EvidenceStatus } from '../../../lib/pulse-status';
import { relativeAgo } from '../../../lib/relativeTime';
import { sanitizeUrl } from '../../../lib/sanitize-url';
import AgentFixLinks from '../../../components/threatintel/AgentFixLinks';
import { AiSummaryCard } from '../../../components/intel/AiSummaryCard';
import {
  cveFromText,
  cveSignal,
  epssPercent,
  productLabel,
  severityTone,
  type GhmCve,
  type GhmFeedRow,
  type GhmIncident,
  type GhmPatch,
  type GhmTab,
  type GhmWindow,
} from './types';

const SIGNAL_LABEL: Record<ReturnType<typeof cveSignal>, string> = {
  ransomware: 'Ransomware',
  exploited: 'Exploited',
  exploit: 'Public exploit',
  news: 'In the news',
};

const SIGNAL_TONE: Record<ReturnType<typeof cveSignal>, string> = {
  ransomware: 'text-rose-600 dark:text-rose-400',
  exploited: 'text-rose-600 dark:text-rose-400',
  exploit: 'text-orange-600 dark:text-orange-400',
  news: 'text-amber-600 dark:text-amber-400',
};

const STATUS_DOT: Record<EvidenceStatus, string> = {
  confirmed: 'bg-emerald-500',
  reported: 'bg-sky-500',
  claimed: 'bg-amber-500',
  precautionary: 'bg-violet-500',
  disputed: 'bg-rose-500',
};

const STATUS_TONE_INLINE: Record<EvidenceStatus, string> = {
  confirmed: 'text-emerald-600 dark:text-emerald-400',
  reported: 'text-sky-600 dark:text-sky-400',
  claimed: 'text-amber-600 dark:text-amber-400',
  precautionary: 'text-violet-600 dark:text-violet-400',
  disputed: 'text-rose-600 dark:text-rose-400',
};

function Eyebrow({ children, className = '' }: { children: ReactNode; className?: string }): JSX.Element {
  return <span className={`font-mono text-micro uppercase tracking-wider text-muted ${className}`}>{children}</span>;
}

/** ─── Top bar ───────────────────────────────────────────────────────────── */

export function TopBar({
  generatedAt,
  fresh,
  onSelectCve,
  onCheck,
  onBrief,
  onAgents,
  onMap,
}: {
  generatedAt: string | null;
  fresh: GhmCve[];
  onSelectCve: (id: string) => void;
  onCheck: () => void;
  onBrief: () => void;
  onAgents: () => void;
  onMap: () => void;
}): JSX.Element {
  const ticker = useMemo(() => fresh.slice(0, 20), [fresh]);
  return (
    <header className="pointer-events-auto absolute inset-x-0 top-0 z-30 flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-line-1/50 bg-surface-100/90 px-3 py-2 backdrop-blur-md sm:px-4">
      <button
        type="button"
        onClick={onMap}
        className="flex shrink-0 items-center gap-2 rounded-control py-1"
        aria-label="Global Hack Map home"
      >
        <Globe2 size={20} className="text-rose-500" aria-hidden />
        <span className="flex flex-col font-semibold leading-none tracking-tight text-heading sm:flex-row sm:gap-1.5">
          <span className="text-micro font-mono font-normal uppercase tracking-widest text-muted sm:text-sm sm:font-semibold sm:tracking-tight sm:text-heading">
            Global
          </span>
          <span className="text-sm sm:text-base">Hack Map</span>
        </span>
        <span className="hidden font-mono text-micro text-muted/70 lg:inline">/ DFIR platform</span>
      </button>

      <div className="order-last flex w-full min-w-0 items-center gap-2 md:order-none md:w-auto md:flex-1">
        <span className="flex shrink-0 items-center gap-1.5 font-mono text-micro uppercase tracking-wider text-muted">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60 [animation-duration:2.4s]" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
          </span>
          CVE watch
        </span>
        <span className="h-3.5 w-px shrink-0 bg-line-1" aria-hidden />
        <div className="group relative min-w-0 flex-1 overflow-hidden" aria-label="Critical and exploited CVE ticker">
          <div className="flex w-max animate-scroll-horizontal gap-4 group-hover:[animation-play-state:paused] motion-reduce:animate-none">
            {[0, 1].map((copy) => (
              <ul key={copy} className="flex shrink-0 items-center gap-4" aria-hidden={copy === 1}>
                {ticker.map((cve) => {
                  const signal = cveSignal(cve);
                  return (
                    <li key={`${copy}-${cve.id}`}>
                      <button
                        type="button"
                        tabIndex={copy === 1 ? -1 : undefined}
                        onClick={() => onSelectCve(cve.id)}
                        className="inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-mini text-muted transition-colors hover:text-heading"
                        title={cve.description}
                      >
                        <span className={`font-semibold ${SIGNAL_TONE[signal]}`}>{SIGNAL_LABEL[signal]}</span>
                        <span className="text-body">{cve.id}</span>
                        <span className="max-w-[180px] truncate">{productLabel(cve)}</span>
                        {cve.score != null && <span className="text-muted/70">{cve.score.toFixed(1)}</span>}
                      </button>
                    </li>
                  );
                })}
              </ul>
            ))}
          </div>
        </div>
      </div>

      <nav
        className="ml-auto flex shrink-0 items-center gap-0.5 rounded-full border border-line-1 bg-surface-100 p-0.5"
        aria-label="Situation room navigation"
      >
        <button
          type="button"
          onClick={onMap}
          className="hidden rounded-full px-2.5 py-1 text-mini text-muted hover:text-heading md:inline-flex"
        >
          Map
        </button>
        <button
          type="button"
          onClick={onCheck}
          className="rounded-full px-2.5 py-1 text-mini text-muted hover:text-heading"
        >
          <span className="sm:hidden">Check</span>
          <span className="hidden sm:inline">Am I affected?</span>
        </button>
        <button
          type="button"
          onClick={onBrief}
          className="hidden rounded-full px-2.5 py-1 text-mini text-muted hover:text-heading md:inline-flex"
        >
          Daily brief
        </button>
        <button
          type="button"
          onClick={onAgents}
          className="hidden rounded-full px-2.5 py-1 text-mini text-muted hover:text-heading lg:inline-flex"
        >
          Agents
        </button>
        <a
          href="https://github.com/yorkeccak/globalhackmap"
          target="_blank"
          rel="noopener noreferrer"
          className="hidden rounded-full p-1.5 text-muted hover:text-heading sm:inline-flex"
          aria-label="Global Hack Map source on GitHub"
          title="Original concept (MIT)"
        >
          <GitBranch size={13} />
        </a>
      </nav>
      {generatedAt && (
        <span className="hidden font-mono text-micro text-muted/60 xl:inline">{relativeAgo(generatedAt)}</span>
      )}
    </header>
  );
}

/** ─── Left HUD / story sidebar ─────────────────────────────────────────── */

export function StorySidebar({
  events,
  incidents,
  malwareRows,
  outageRows,
  orgCount,
  dayBars,
  onSelectIncident,
  cves,
  generatedAt,
  window,
  onWindow,
  statusFilter,
  onToggleStatus,
  statusCounts,
  query,
  onQuery,
  tab,
  onTab,
  stack,
  onStack,
  onSelectEvent,
  onSelectCve,
  onCheck,
  onBrief,
  searchRef,
}: {
  events: PulseEvent[];
  incidents: GhmIncident[];
  malwareRows: GhmFeedRow[];
  outageRows: GhmFeedRow[];
  orgCount: number;
  dayBars: Array<{ date: string; count: number }>;
  onSelectIncident: (incident: GhmIncident) => void;
  cves: GhmCve[];
  generatedAt: string | null;
  window: GhmWindow;
  onWindow: (w: GhmWindow) => void;
  statusFilter: Set<EvidenceStatus>;
  onToggleStatus: (s: EvidenceStatus) => void;
  statusCounts: Record<EvidenceStatus, number>;
  query: string;
  onQuery: (q: string) => void;
  tab: GhmTab;
  onTab: (t: GhmTab) => void;
  stack: string[];
  onStack: (s: string[]) => void;
  onSelectEvent: (e: PulseEvent) => void;
  onSelectCve: (id: string) => void;
  onCheck: () => void;
  onBrief: () => void;
  searchRef: React.RefObject<HTMLInputElement | null>;
}): JSX.Element {
  const [stackDraft, setStackDraft] = useState('');
  const q = query.trim().toLowerCase();

  const cveRows = useMemo(
    () =>
      cves
        // Telegram/cvefeed gap-filler rows are raw feed text without a vendor
        // or severity — GHM's list is curated advisories and exploitation.
        .filter((c) => !/^\[(cvenotify|tg|dbugs|cvefeed)\]/i.test(c.description))
        .filter((c) => c.kev || c.has_exploit || c.origin === 'vulntracker' || (c.score ?? 0) >= 7)
        .filter(
          (c) =>
            stack.length === 0 ||
            stack.some((s) =>
              `${c.vendor ?? ''} ${c.product ?? ''} ${c.description}`.toLowerCase().includes(s.toLowerCase())
            )
        )
        .filter((c) => !q || `${c.id} ${c.description} ${c.vendor ?? ''} ${c.product ?? ''}`.toLowerCase().includes(q))
        .sort((a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? 0) - (a.score ?? 0))
        .slice(0, 60),
    [cves, q, stack]
  );
  const eventRows = useMemo(
    () => events.filter((e) => !q || `${e.title} ${e.description} ${e.source}`.toLowerCase().includes(q)).slice(0, 60),
    [events, q]
  );
  const tabCounts: Record<GhmTab, number> = {
    cves: cveRows.length,
    breaches: incidents.length || eventRows.length,
    malware: malwareRows.length,
    outages: outageRows.length,
  };

  const addStack = () => {
    const value = stackDraft.trim();
    if (!value || stack.some((s) => s.toLowerCase() === value.toLowerCase())) return;
    onStack([...stack, value].slice(0, 20));
    setStackDraft('');
  };

  const visibleStatuses = EVIDENCE_STATUSES.filter((s) => statusCounts[s] > 0);

  return (
    <section className="pointer-events-auto flex h-full min-h-0 flex-col overflow-hidden rounded-r-2xl border-r border-line-1 bg-surface-100/95 shadow-xl backdrop-blur-md">
      <div className="shrink-0 px-3 pt-3">
        <div className="px-1 pb-2">
          <h1 className="text-lg font-semibold leading-tight tracking-tight text-heading">
            Live vulnerabilities, exploits and breaches
          </h1>
          <p className="mt-1 text-mini leading-snug text-muted">
            What attackers are using right now, who it hits, and how to lock down what you use.
          </p>
        </div>
        <div className="flex items-center justify-between gap-2 px-1">
          <span className="flex items-center gap-1.5 text-mini text-muted">
            <Radio size={11} className="text-emerald-500" aria-hidden />
            Live{generatedAt ? <span className="text-muted/70">· updated {relativeAgo(generatedAt)}</span> : null}
          </span>
          <div
            className="flex items-center gap-0.5 rounded-control border border-line-1 p-0.5"
            role="group"
            aria-label="Time window"
          >
            {(['24h', '7d', '30d'] as const).map((w) => (
              <button
                key={w}
                type="button"
                aria-pressed={window === w}
                onClick={() => onWindow(w)}
                className={`rounded px-1.5 py-0.5 font-mono text-micro transition-colors ${
                  window === w ? 'bg-surface-300 text-heading' : 'text-muted hover:text-heading'
                }`}
              >
                {w}
              </button>
            ))}
          </div>
        </div>

        {/* Headline count + honest status breakdown (GHM's Pulse panel). */}
        <div className="mt-2.5 rounded-xl border border-line-1 bg-surface-200/70 p-3">
          <div className="flex items-center justify-between">
            <Eyebrow>Sourced incidents</Eyebrow>
            <Eyebrow>{window} window</Eyebrow>
          </div>
          <div className="mt-1 flex items-end justify-between gap-2">
            <div>
              <div className="text-4xl font-semibold leading-none tracking-tight text-heading tabular-nums">
                {orgCount}
              </div>
              <p className="mt-1.5 text-micro text-muted">
                {incidents.length} sourced incidents · {cves.filter((c) => c.kev).length} known exploited
              </p>
            </div>
            <DayBars days={dayBars} />
          </div>
          <div className="mt-2.5 grid grid-cols-3 gap-px overflow-hidden rounded-lg border border-line-1 bg-line-1">
            {(['confirmed', 'reported', 'claimed'] as const).map((status) => (
              <button
                key={status}
                type="button"
                aria-pressed={statusFilter.has(status)}
                onClick={() => onToggleStatus(status)}
                title={STATUS_META[status].description}
                className={`bg-surface-100 px-2 py-2 text-left transition-opacity ${statusFilter.has(status) ? '' : 'opacity-40'}`}
              >
                <span className="flex items-center gap-1 text-micro text-muted">
                  <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[status]}`} />
                  {STATUS_META[status].label}
                </span>
                <span className="mt-1 block text-base font-semibold leading-none text-heading tabular-nums">
                  {statusCounts[status]}
                </span>
              </button>
            ))}
          </div>
          {visibleStatuses.some((s) => s === 'precautionary' || s === 'disputed') && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {visibleStatuses
                .filter((s) => s === 'precautionary' || s === 'disputed')
                .map((status) => (
                  <button
                    key={status}
                    type="button"
                    aria-pressed={statusFilter.has(status)}
                    onClick={() => onToggleStatus(status)}
                    className={`rounded-full border border-line-1 px-1.5 py-0.5 font-mono text-micro ${
                      statusFilter.has(status) ? 'text-heading' : 'text-muted opacity-50'
                    }`}
                  >
                    {STATUS_META[status].label} {statusCounts[status]}
                  </button>
                ))}
            </div>
          )}
          <p className="mt-2 text-micro leading-snug text-muted/70">
            Toggle statuses to filter the map and breach list. An absent result is never proof you&apos;re safe.
          </p>
        </div>

        {/* Omnibox */}
        <div className="relative mt-2.5">
          <Search
            size={13}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"
            aria-hidden
          />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder="CVE, product, company, victim…"
            aria-label="Search the situation room"
            className="w-full rounded-control border border-line-1 bg-surface py-2 pl-8 pr-3 text-mini text-body outline-none placeholder:text-muted/70 focus:border-rose-500/40"
          />
          <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-line-1 px-1 font-mono text-micro text-muted/60">
            ⌘K
          </span>
        </div>

        {/* Actions */}
        <div className="mt-2 flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={onCheck}
            className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
          >
            <CircleHelp size={11} /> Am I affected?
          </button>
          <button
            type="button"
            onClick={onBrief}
            className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
          >
            <Sparkles size={11} /> Daily brief
          </button>
          <Link
            to="/threatintel/cve-list"
            className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
          >
            All CVEs <ArrowUpRight size={11} />
          </Link>
        </div>

        {/* Stack picker — no upload, everything stays local. */}
        <div className="mt-2.5 rounded-lg border border-line-1 bg-surface-100 p-2">
          <div className="flex items-center justify-between">
            <Eyebrow>What do you run?</Eyebrow>
            <span className="font-mono text-micro text-muted/70">stored locally</span>
          </div>
          {stack.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {stack.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => onStack(stack.filter((s) => s !== item))}
                  className="rounded-full border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 font-mono text-micro text-rose-600 dark:text-rose-400"
                  title={`Remove ${item} from your stack`}
                >
                  {item} ×
                </button>
              ))}
            </div>
          )}
          <form
            className="mt-1.5 flex gap-1"
            onSubmit={(e) => {
              e.preventDefault();
              addStack();
            }}
          >
            <input
              value={stackDraft}
              onChange={(e) => setStackDraft(e.target.value)}
              placeholder="Add a vendor or product…"
              aria-label="Add a vendor or product to your stack"
              className="min-w-0 flex-1 rounded-control border border-line-1 bg-surface px-2 py-1 text-mini text-body outline-none focus:border-rose-500/40"
            />
            <button
              type="submit"
              className="rounded-control border border-line-1 px-2 text-mini text-muted hover:text-heading"
            >
              Add
            </button>
          </form>
        </div>
      </div>

      {/* Live lists */}
      <div className="sticky top-0 z-10 mt-2.5 flex shrink-0 gap-0.5 border-y border-line-1 bg-surface-100 px-2 py-1.5">
        {(
          [
            ['cves', 'CVEs', Bug],
            ['breaches', 'Breaches', ShieldAlert],
            ['malware', 'Malware', Package],
            ['outages', 'Outages', Activity],
          ] as const
        ).map(([id, label, Icon]) => (
          <button
            key={id}
            type="button"
            aria-pressed={tab === id}
            onClick={() => onTab(id)}
            className={`inline-flex items-center gap-1 rounded-control px-1.5 py-1 text-mini transition-colors ${
              tab === id ? 'bg-surface-300 text-heading' : 'text-muted hover:text-heading'
            }`}
          >
            <Icon size={11} aria-hidden />
            {label} <span className="font-mono text-micro text-muted/70">{tabCounts[id]}</span>
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto custom-scrollbar px-2 py-2" role="tabpanel">
        {tab === 'cves' &&
          (cveRows.length ? (
            <div className="space-y-3">
              <CveList
                heading="Exploited or in the news"
                rows={cveRows.filter((c) => c.kev || c.has_exploit || c.origin === 'vulntracker').slice(0, 20)}
                onSelect={onSelectCve}
              />
              <CveList
                heading="Advisories to review"
                rows={cveRows.filter((c) => !c.kev && !c.has_exploit && c.origin !== 'vulntracker').slice(0, 30)}
                onSelect={onSelectCve}
              />
            </div>
          ) : (
            <EmptyList label="No CVEs match this search or stack." />
          ))}

        {tab === 'breaches' &&
          (incidents.length ? (
            <ul className="space-y-1">
              {incidents.map((i) => (
                <li key={i.id}>
                  <button
                    type="button"
                    onClick={() => onSelectIncident(i)}
                    className="w-full rounded-lg border border-line-1 bg-surface px-2 py-1.5 text-left transition-colors hover:border-rose-500/40"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATUS_DOT[i.status]}`} />
                      <span className="font-mono text-micro uppercase tracking-wider text-muted">{i.type}</span>
                      {i.records != null && (
                        <span className="font-mono text-micro text-muted/70">{i.records.toLocaleString()} records</span>
                      )}
                      <span className="ml-auto font-mono text-micro text-muted/70">{relativeAgo(i.published)}</span>
                    </div>
                    <p className="mt-0.5 line-clamp-1 text-mini text-heading">{i.victim}</p>
                    <p className="line-clamp-2 text-micro text-muted">{i.description}</p>
                    <div className="mt-1 flex flex-wrap gap-1.5 font-mono text-micro">
                      <span className={STATUS_TONE_INLINE[i.status]}>{STATUS_META[i.status].label}</span>
                      {i.country && <span className="text-muted">{i.country}</span>}
                      {i.actor && <span className="text-amber-600 dark:text-amber-400">{i.actor}</span>}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          ) : eventRows.length ? (
            <ul className="space-y-1">
              {eventRows.map((e) => {
                const status = incidentStatus(e);
                return (
                  <li key={e.id}>
                    <button
                      type="button"
                      onClick={() => onSelectEvent(e)}
                      className="w-full rounded-lg border border-line-1 bg-surface px-2 py-1.5 text-left transition-colors hover:border-rose-500/40"
                    >
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className={`h-1.5 w-1.5 shrink-0 rounded-full ${status ? STATUS_DOT[status] : 'bg-slate-400'}`}
                        />
                        <span className="font-mono text-micro uppercase tracking-wider text-muted">
                          {e.kind.replace(/_/g, ' ')}
                        </span>
                        <span className="ml-auto font-mono text-micro text-muted/70">{relativeAgo(e.timestamp)}</span>
                      </div>
                      <p className="mt-0.5 line-clamp-1 text-mini text-heading">{e.title}</p>
                      <p className="line-clamp-1 text-micro text-muted">
                        {e.source}
                        {e.country ? ` · ${e.country}` : ''}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          ) : (
            <EmptyList label="No incidents in this window. That is a fact, not a guarantee." />
          ))}

        {tab === 'malware' &&
          (malwareRows.length ? (
            <FeedRowList rows={malwareRows} />
          ) : (
            <EmptyList label="Malware feeds did not answer — cross-check the source directly." />
          ))}
        {tab === 'outages' &&
          (outageRows.length ? (
            <FeedRowList rows={outageRows} />
          ) : (
            <EmptyList label="No maritime or connectivity rows in this window." />
          ))}
      </div>

      <div className="flex shrink-0 items-center justify-between border-t border-line-1 px-3 py-2 text-micro text-muted/70">
        <span>Every pin is sourced.</span>
        <Link to="/api/mcp" className="underline hover:text-heading">
          MCP
        </Link>
      </div>
    </section>
  );
}

/** One section of the CVE list — GHM splits advisories from confirmed exploitation. */
function CveList({
  heading,
  rows,
  onSelect,
}: {
  heading: string;
  rows: GhmCve[];
  onSelect: (id: string) => void;
}): JSX.Element | null {
  if (!rows.length) return null;
  return (
    <section>
      <Eyebrow className="mb-1.5 block px-1">{heading}</Eyebrow>
      <ul className="space-y-1">
        {rows.map((cve) => {
          const signal = cveSignal(cve);
          return (
            <li key={cve.id}>
              <button
                type="button"
                onClick={() => onSelect(cve.id)}
                className="w-full rounded-lg border border-line-1 bg-surface px-2 py-1.5 text-left transition-colors hover:border-rose-500/40"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className={`font-mono text-micro font-semibold ${SIGNAL_TONE[signal]}`}>
                    {SIGNAL_LABEL[signal]}
                  </span>
                  <span className="font-mono text-mini font-semibold text-heading">{cve.id}</span>
                  {cve.score != null && (
                    <span className={`rounded border px-1 font-mono text-micro ${severityTone(cve.severity)}`}>
                      {cve.score.toFixed(1)}
                    </span>
                  )}
                  <span className="ml-auto font-mono text-micro text-muted/70">{relativeAgo(cve.published)}</span>
                </div>
                <p className="mt-0.5 line-clamp-1 text-mini text-body">{productLabel(cve)}</p>
                <p className="line-clamp-2 text-micro text-muted">{cve.description}</p>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** Distinct organisations per rolling 24h over the last 14 days. */
function DayBars({ days }: { days: Array<{ date: string; count: number }> }): JSX.Element {
  const max = Math.max(1, ...days.map((d) => d.count));
  return (
    <div
      className="w-[min(45%,150px)] shrink-0"
      role="img"
      aria-label={`Organisations per 24-hour period over the last 14 days: ${days.map((d) => d.count).join(', ')}`}
    >
      <div className="flex h-11 items-end gap-[3px]">
        {days.map((d, index) => (
          <span
            key={d.date}
            title={`${d.date}: ${d.count} organisations`}
            className={`flex-1 rounded-[2px] ${index === days.length - 1 ? 'bg-heading' : 'bg-surface-300'}`}
            style={{ height: `${Math.max(3, (d.count / max) * 44)}px` }}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-micro text-muted/70">
        <span>14d ago</span>
        <span>last 24h</span>
      </div>
    </div>
  );
}

function EmptyList({ label }: { label: string }): JSX.Element {
  return <p className="py-8 text-center text-mini text-muted">{label}</p>;
}

/** Feed rows from MalwareBazaar / OpenSSF / UKMTO — link out to the source. */
function FeedRowList({ rows }: { rows: GhmFeedRow[] }): JSX.Element {
  return (
    <ul className="space-y-1">
      {rows.map((row) => (
        <li key={row.id} className="rounded-lg border border-line-1 bg-surface px-2 py-1.5">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-micro uppercase tracking-wider text-muted">{row.source}</span>
            <span className="ml-auto font-mono text-micro text-muted/70">
              {row.timestamp ? relativeAgo(row.timestamp) : ''}
            </span>
          </div>
          <p className="mt-0.5 line-clamp-1 text-mini text-heading">{row.title}</p>
          <p className="line-clamp-2 text-micro text-muted">{row.description}</p>
          {row.url && (
            <a
              href={sanitizeUrl(row.url) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-1 inline-flex items-center gap-1 font-mono text-micro text-muted hover:text-heading"
            >
              source <ExternalLink size={9} />
            </a>
          )}
        </li>
      ))}
    </ul>
  );
}

/** ─── Right detail dossier ─────────────────────────────────────────────── */

export function DetailPanel({
  event,
  cve,
  incident,
  onClose,
  onAnalyze,
}: {
  event: PulseEvent | null;
  cve: GhmCve | null;
  incident: GhmIncident | null;
  onClose: () => void;
  onAnalyze: () => void;
}): JSX.Element | null {
  if (!event && !cve && !incident) return null;
  const status = incident?.status ?? (event ? incidentStatus(event) : null);
  const id =
    cve?.id ??
    (cveFromText(incident?.description ?? '') ||
      cveFromText(event?.title ?? '') ||
      event?.id ||
      incident?.id ||
      'detail');
  return (
    <aside
      className="pointer-events-auto flex h-full w-full flex-col overflow-y-auto custom-scrollbar rounded-l-2xl border-l border-line-1 bg-surface-100/95 shadow-xl backdrop-blur-md"
      aria-label="Dossier"
    >
      <div className="flex items-center justify-between border-b border-line-1 px-3 py-2">
        <Eyebrow>Dossier</Eyebrow>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close dossier"
          className="rounded-control p-1 text-muted hover:text-heading"
        >
          <X size={14} />
        </button>
      </div>
      <div className="flex-1 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {incident ? (
            <>
              <ShieldAlert size={14} className="text-rose-500" aria-hidden />
              <h2 className="text-sm font-semibold leading-snug text-heading">{incident.victim}</h2>
              <span
                className={`rounded border px-1.5 py-0.5 font-mono text-micro ${STATUS_TONE_INLINE[incident.status]}`}
              >
                {STATUS_META[incident.status].label}
              </span>
            </>
          ) : cve ? (
            <>
              <Flame size={14} className="text-rose-500" aria-hidden />
              <h2 className="font-mono text-sm font-semibold text-heading">{cve.id}</h2>
              <span className={`rounded border px-1.5 py-0.5 font-mono text-micro ${severityTone(cve.severity)}`}>
                {cve.severity} {cve.score != null ? cve.score.toFixed(1) : ''}
              </span>
            </>
          ) : (
            <h2 className="text-sm font-semibold leading-snug text-heading">{event!.title}</h2>
          )}
        </div>

        {incident ? (
          <>
            <h3 className="mt-1 text-mini font-medium text-heading">{incident.title}</h3>
            <p className="mt-2 text-mini leading-relaxed text-body">{incident.description}</p>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <Fact label="Type" value={incident.type} />
              <Fact label="Reported" value={relativeAgo(incident.published) || '—'} />
              {incident.records != null && <Fact label="Records" value={incident.records.toLocaleString()} />}
              {incident.actor && <Fact label="Actor" value={incident.actor} />}
              {incident.country && <Fact label="Country" value={incident.country} />}
              {incident.place && <Fact label="Location" value={incident.place} />}
            </div>
            <p className="mt-3 text-micro leading-snug text-muted">
              {STATUS_META[incident.status].description}. If you use this organisation, check its own advisory and
              rotate anything exposed. An absent result is never proof you are unaffected.
            </p>
          </>
        ) : cve ? (
          <>
            <p className="mt-2 text-mini leading-relaxed text-body">{cve.description}</p>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <Fact label="Signal" value={SIGNAL_LABEL[cveSignal(cve)]} />
              <Fact label="Published" value={relativeAgo(cve.published) || '—'} />
              <Fact label="EPSS" value={epssPercent(cve.epss) || 'unknown'} />
              <Fact
                label="Corroboration"
                value={cve.listed_by_count ? `${cve.listed_by_count} sources` : 'single source'}
              />
              {cve.vendor && <Fact label="Vendor" value={cve.vendor} />}
              {cve.product && <Fact label="Product" value={cve.product} />}
            </div>
            <p className="mt-3 text-micro leading-snug text-muted">
              {cve.kev
                ? 'CISA KEV lists active exploitation. Treat patching as urgent, and check the vendor advisory for fixed versions.'
                : cve.has_exploit
                  ? 'Public exploit code exists. Severity alone is not the risk — check reachability in your environment.'
                  : 'No confirmed exploitation in the sources we checked. Absence of evidence is not evidence of safety.'}
            </p>
          </>
        ) : (
          <>
            <p className="mt-2 text-mini leading-relaxed text-body">{event!.description}</p>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <Fact label="Source" value={event!.source} />
              <Fact label="Severity" value={event!.severity} />
              {status && <Fact label="Evidence" value={STATUS_META[status].label} />}
              <Fact label="Reported" value={relativeAgo(event!.timestamp) || '—'} />
              {event!.country && <Fact label="Country" value={event!.country} />}
              {event!.magnitude != null && <Fact label="Magnitude" value={event!.magnitude.toFixed(1)} />}
            </div>
            {status && <p className="mt-3 text-micro text-muted">{STATUS_META[status].description}.</p>}
          </>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-2 text-mini">
          {incident && (
            <a
              href={sanitizeUrl(incident.url) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-muted hover:text-heading"
            >
              Original incident <ExternalLink size={10} />
            </a>
          )}
          {cve && (
            <a
              href={sanitizeUrl(`https://nvd.nist.gov/vuln/detail/${cve.id}`)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-muted hover:text-heading"
            >
              NVD <ExternalLink size={10} />
            </a>
          )}
          <Link
            to={`/threatintel/cve-list?q=${encodeURIComponent(id)}`}
            className="inline-flex items-center gap-1 text-muted hover:text-heading"
          >
            Platform record <ArrowUpRight size={10} />
          </Link>
          {event?.url && (
            <a
              href={sanitizeUrl(event.url) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-muted hover:text-heading"
            >
              Original source <ExternalLink size={10} />
            </a>
          )}
        </div>

        <button
          type="button"
          onClick={onAnalyze}
          className="mt-3 inline-flex items-center gap-1.5 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
        >
          <Sparkles size={11} /> AI analysis
        </button>

        {id && <AgentFixLinks cve={id} />}
      </div>
    </aside>
  );
}

function Fact({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="rounded-lg border border-line-1 bg-surface-200/60 px-2 py-1.5">
      <div className="font-mono text-micro uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-0.5 truncate text-mini text-body" title={value}>
        {value}
      </div>
    </div>
  );
}

/** ─── Bottom patch dock ────────────────────────────────────────────────── */

export function PatchDock({
  cves,
  patches,
  generatedAt,
  onSelectCve,
  open,
  onOpenChange,
}: {
  cves: GhmCve[];
  patches: GhmPatch[];
  generatedAt: string | null;
  onSelectCve: (id: string) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}): JSX.Element | null {
  if (!cves.length && !patches.length) return null;
  const showPatches = patches.length > 0;
  return (
    <>
      {!open && (
        <button
          type="button"
          onClick={() => onOpenChange(true)}
          className="pointer-events-auto absolute bottom-4 left-1/2 z-20 -translate-x-1/2 rounded-full border border-line-1 bg-surface-100/90 px-3 py-1.5 text-mini text-body backdrop-blur-md"
        >
          <ChevronUp size={11} className="mr-1 inline" aria-hidden /> Patch now
        </button>
      )}
      {open && (
        <section
          aria-label="Patch now"
          className="pointer-events-auto absolute bottom-4 left-1/2 z-20 w-[min(1100px,calc(100%-2rem))] -translate-x-1/2 rounded-2xl border border-line-1 bg-surface-100/95 p-2.5 shadow-xl backdrop-blur-md"
        >
          <div className="flex items-center gap-2 px-1">
            <Wrench size={12} className="text-rose-500" aria-hidden />
            <h2 className="font-mono text-micro uppercase tracking-wider text-heading">Patch now</h2>
            <p className="truncate text-micro text-muted">
              {showPatches
                ? 'Exploited software — who is affected and the exact fix'
                : 'The software attackers are using today'}
            </p>
            {generatedAt && (
              <span className="shrink-0 font-mono text-micro text-muted/70">{relativeAgo(generatedAt)}</span>
            )}
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              aria-label="Hide Patch now"
              className="ml-auto rounded-control p-1 text-muted hover:text-heading"
            >
              <ChevronDown size={12} />
            </button>
          </div>
          {showPatches ? (
            <ul className="mt-2 flex gap-2 overflow-x-auto custom-scrollbar">
              {patches.slice(0, 16).map((patch) => {
                const label = patch.ransomware ? 'Ransomware' : patch.exploited ? 'Exploited' : 'Patch';
                const tone = patch.ransomware || patch.exploited ? SIGNAL_TONE.ransomware : SIGNAL_TONE.news;
                const product = [patch.vendor, patch.product].filter(Boolean).join(' ') || patch.key;
                return (
                  <li key={patch.key} className="w-[300px] shrink-0">
                    <div className="flex h-full w-full flex-col rounded-xl border border-line-1 bg-surface px-2.5 py-2">
                      <div className="flex items-center gap-1.5">
                        <span className={`truncate text-mini font-medium ${tone}`}>{label}</span>
                        {patch.kevAdded && (
                          <span className="font-mono text-micro text-muted/70">KEV {patch.kevAdded.slice(5)}</span>
                        )}
                        {patch.epss != null && (
                          <span className="font-mono text-micro text-muted/70">
                            EPSS {(patch.epss * 100).toFixed(1)}%
                          </span>
                        )}
                        {patch.cvss != null && (
                          <span className="ml-auto font-mono text-micro text-muted/70">
                            CVSS {patch.cvss.toFixed(1)}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 line-clamp-1 text-mini font-semibold text-heading">{product}</div>
                      <div className="mt-0.5 line-clamp-2 text-micro text-body" title={patch.title}>
                        {patch.title}
                      </div>
                      {patch.who && (
                        <div className="mt-1 line-clamp-2 text-micro text-muted" title={patch.who}>
                          <span className="font-mono uppercase tracking-wider">who: </span>
                          {patch.who}
                        </div>
                      )}
                      {patch.fix && (
                        <div
                          className="mt-1 line-clamp-3 rounded border border-emerald-500/25 bg-emerald-500/5 px-1.5 py-1 text-micro text-emerald-700 dark:text-emerald-300"
                          title={patch.fix}
                        >
                          {patch.fix}
                        </div>
                      )}
                      <div className="mt-auto flex items-center gap-2 pt-1.5">
                        <span className="min-w-0 flex-1 truncate font-mono text-micro text-muted/70">
                          {patch.cves.slice(0, 2).join(' · ') || patch.key}
                        </span>
                        {patch.cves[0] && (
                          <button
                            type="button"
                            onClick={() => onSelectCve(patch.cves[0]!)}
                            className="shrink-0 font-mono text-micro text-sky-600 hover:underline dark:text-sky-400"
                          >
                            dossier
                          </button>
                        )}
                        <a
                          href={patch.url}
                          target="_blank"
                          rel="noreferrer noopener"
                          aria-label="Open upstream patch advisory"
                          className="shrink-0 text-muted hover:text-heading"
                        >
                          <ExternalLink size={10} />
                        </a>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : (
            <ul className="mt-2 flex gap-2 overflow-x-auto custom-scrollbar">
              {cves.map((cve) => {
                const signal = cveSignal(cve);
                return (
                  <li key={cve.id} className="w-[228px] shrink-0">
                    <button
                      type="button"
                      onClick={() => onSelectCve(cve.id)}
                      className="flex h-full w-full flex-col rounded-xl border border-line-1 bg-surface px-2.5 py-2 text-left hover:border-rose-500/40"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={`truncate text-mini font-medium ${SIGNAL_TONE[signal]}`}>
                          {SIGNAL_LABEL[signal]}
                        </span>
                        <span className="ml-auto font-mono text-micro text-muted/70">
                          {relativeAgo(cve.kev_added ?? cve.published)}
                        </span>
                      </div>
                      <div className="mt-1 line-clamp-1 text-mini font-semibold text-heading">{productLabel(cve)}</div>
                      <div className="mt-1 line-clamp-2 text-micro text-muted">{cve.description}</div>
                      <div className="mt-auto pt-1.5 font-mono text-micro text-muted/70">
                        {cve.id}
                        {cve.score != null ? ` · ${cve.score.toFixed(1)}` : ''}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      )}
    </>
  );
}

/** ─── Modals: Check / Brief / Agents ───────────────────────────────────── */

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }): JSX.Element {
  return (
    <div
      className="pointer-events-auto absolute inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/50 p-4 pt-[8vh]"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div className="w-full max-w-2xl rounded-2xl border border-line-1 bg-surface-100 p-4 shadow-2xl">
        <div className="flex items-center justify-between border-b border-line-1 pb-2">
          <h2 className="text-base font-semibold text-heading">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-control p-1 text-muted hover:text-heading"
          >
            <X size={15} />
          </button>
        </div>
        <div className="pt-3">{children}</div>
      </div>
    </div>
  );
}

export function CheckPanel({
  cves,
  events,
  stack,
  onStack,
  onSelectCve,
  onClose,
}: {
  cves: GhmCve[];
  events: PulseEvent[];
  stack: string[];
  onStack: (s: string[]) => void;
  onSelectCve: (id: string) => void;
  onClose: () => void;
}): JSX.Element {
  const [draft, setDraft] = useState('');
  const matches = cves
    .filter(
      (c) =>
        stack.length === 0 ||
        stack.some((s) =>
          `${c.vendor ?? ''} ${c.product ?? ''} ${c.description}`.toLowerCase().includes(s.toLowerCase())
        )
    )
    .slice(0, 20);
  const eventMatches = events
    .filter((e) => stack.some((s) => `${e.title} ${e.description}`.toLowerCase().includes(s.toLowerCase())))
    .slice(0, 10);
  return (
    <Modal title="Am I affected?" onClose={onClose}>
      <p className="text-mini leading-relaxed text-muted">
        Add the apps, products and companies you use. We show what attackers are exploiting in them and what to do about
        it. Nothing is uploaded — your stack stays in this browser.
      </p>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          const v = draft.trim();
          if (v && !stack.some((s) => s.toLowerCase() === v.toLowerCase())) onStack([...stack, v].slice(0, 20));
          setDraft('');
        }}
      >
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="e.g. Microsoft Exchange, Atlassian, nginx"
          aria-label="Add a product or company"
          className="min-w-0 flex-1 rounded-control border border-line-1 bg-surface px-2 py-1.5 text-mini outline-none focus:border-rose-500/40"
        />
        <button
          type="submit"
          className="rounded-control border border-line-1 px-3 text-mini text-body hover:border-rose-500/40"
        >
          Add
        </button>
      </form>
      {stack.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {stack.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => onStack(stack.filter((x) => x !== s))}
              className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-micro text-rose-600 dark:text-rose-400"
            >
              {s} ×
            </button>
          ))}
        </div>
      )}
      <div className="mt-4">
        <Eyebrow>
          {stack.length
            ? `${matches.length} CVE touches your stack`
            : `${matches.length} exploited CVEs in the live feed`}
        </Eyebrow>
        <ul className="mt-2 space-y-1">
          {matches.map((c) => {
            const signal = cveSignal(c);
            return (
              <li key={c.id}>
                <button
                  type="button"
                  onClick={() => {
                    onSelectCve(c.id);
                    onClose();
                  }}
                  className="flex w-full items-center gap-2 rounded-lg border border-line-1 bg-surface px-2 py-1.5 text-left hover:border-rose-500/40"
                >
                  <span className={`font-mono text-micro font-semibold ${SIGNAL_TONE[signal]}`}>
                    {SIGNAL_LABEL[signal]}
                  </span>
                  <span className="font-mono text-mini text-heading">{c.id}</span>
                  <span className="min-w-0 flex-1 truncate text-mini text-muted">{productLabel(c)}</span>
                  <ArrowUpRight size={11} className="text-muted" />
                </button>
              </li>
            );
          })}
        </ul>
      </div>
      {eventMatches.length > 0 && (
        <div className="mt-4">
          <Eyebrow>Breach &amp; incident matches</Eyebrow>
          <ul className="mt-2 space-y-1">
            {eventMatches.map((e) => (
              <li key={e.id} className="rounded-lg border border-line-1 bg-surface px-2 py-1.5 text-mini text-body">
                {e.title} <span className="font-mono text-micro text-muted">· {e.source}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="mt-4 text-micro text-muted/70">
        For a full email / domain breach search, use the{' '}
        <Link to="/dfir/breach" className="underline hover:text-heading" onClick={onClose}>
          breach checker
        </Link>
        . An empty result here never proves you are unaffected.
      </p>
    </Modal>
  );
}

export function BriefPanel({
  items,
  dayKey,
  onClose,
}: {
  items: Array<{ title: string; body?: string; source?: string }>;
  dayKey: string;
  onClose: () => void;
}): JSX.Element {
  const confirmed = items.filter((i) => /Confirmed/i.test(i.title)).length;
  const claimed = items.filter((i) => /Claimed/i.test(i.title)).length;
  const kev = items.filter((i) => /CVE-\d{4}-\d+/i.test(i.title)).length;
  return (
    <Modal title="Today's brief" onClose={onClose}>
      <p className="text-micro font-mono uppercase tracking-wider text-muted">Daily brief · {dayKey}</p>
      <h3 className="mt-1 text-lg font-semibold leading-snug text-heading">
        Everything that broke in the last 48 hours
      </h3>
      <p className="mt-1 text-mini text-muted">
        A live briefing built from the incident feed, confirmed-exploitation list and AI summary. Counts are live; every
        item links to its source.
      </p>

      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Fact label="Items" value={String(items.length)} />
        <Fact label="Confirmed" value={String(confirmed)} />
        <Fact label="Claims" value={String(claimed)} />
        <Fact label="CVEs" value={String(kev)} />
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <section>
          <Eyebrow className="mb-1.5 block">Critical · act now</Eyebrow>
          <ul className="space-y-1">
            {items
              .filter((i) => /Confirmed|CISA KEV/i.test(i.title))
              .slice(0, 6)
              .map((i, index) => (
                <li key={`${i.title}-${index}`} className="rounded-lg border border-line-1 bg-surface px-2 py-1.5">
                  <p className="line-clamp-2 text-mini text-heading">{i.title}</p>
                  <p className="mt-0.5 line-clamp-2 text-micro text-muted">{i.body}</p>
                  <p className="mt-1 text-micro font-mono text-rose-600 dark:text-rose-400">
                    What to do · verify the vendor advisory, patch and hunt for pre-patch compromise.
                  </p>
                </li>
              ))}
          </ul>
        </section>
        <section>
          <Eyebrow className="mb-1.5 block">Watch · claims &amp; reports</Eyebrow>
          <ul className="space-y-1">
            {items
              .filter((i) => !/Confirmed|CISA KEV/i.test(i.title))
              .slice(0, 6)
              .map((i, index) => (
                <li key={`${i.title}-${index}`} className="rounded-lg border border-line-1 bg-surface px-2 py-1.5">
                  <p className="line-clamp-2 text-mini text-heading">{i.title}</p>
                  <p className="mt-0.5 line-clamp-2 text-micro text-muted">{i.body}</p>
                  <p className="mt-1 text-micro font-mono text-amber-600 dark:text-amber-400">
                    What to do · treat as unconfirmed until the organisation or a regulator says so.
                  </p>
                </li>
              ))}
          </ul>
        </section>
      </div>

      <div className="mt-3 border-t border-line-1 pt-3">
        <Eyebrow className="mb-1.5 block">AI summary · on demand</Eyebrow>
        <AiSummaryCard surface="Global Hack Map" items={items} dayKey={dayKey} requireAdmin={false} autoFetch={false} />
      </div>
      <p className="mt-3 text-micro text-muted/70">
        Prefer per-event analysis? Click <Sparkles size={9} className="inline" /> AI analysis in any dossier.
      </p>
    </Modal>
  );
}

export function AgentsPanel({ onClose }: { onClose: () => void }): JSX.Element {
  return (
    <Modal title="For agents" onClose={onClose}>
      <p className="text-mini leading-relaxed text-muted">
        This situation room is readable by agents. The platform exposes a read-only MCP server, an{' '}
        <code className="font-mono text-mini text-body">llms.txt</code> and plain-text runbooks. Every dossier's
        one-click fix links only pre-fill a prompt — nothing runs until you send it.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Link
          to="/api/mcp"
          className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
        >
          MCP server <ExternalLink size={10} />
        </Link>
        <a
          href="/llms.txt"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
        >
          llms.txt <ExternalLink size={10} />
        </a>
        <Link
          to="/dfir/agent-suite"
          className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 text-mini text-body hover:border-rose-500/40"
        >
          Agent suite <ArrowUpRight size={10} />
        </Link>
      </div>
      <p className="mt-3 flex items-center gap-1.5 text-micro text-muted/70">
        <Users size={10} /> Open source concept: Global Hack Map (MIT).
      </p>
    </Modal>
  );
}

/** Mobile sheet fallback for the sidebar. */
export function MobileSidebarToggle({ open, onClick }: { open: boolean; onClick: () => void }): JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      className="pointer-events-auto absolute bottom-4 left-3 z-30 rounded-full border border-line-1 bg-surface-100/90 px-3 py-2 text-mini text-body backdrop-blur-md md:hidden"
    >
      {open ? <X size={12} className="inline" /> : <Globe2 size={12} className="inline" />}{' '}
      {open ? 'Close feed' : 'Open feed'}
    </button>
  );
}
