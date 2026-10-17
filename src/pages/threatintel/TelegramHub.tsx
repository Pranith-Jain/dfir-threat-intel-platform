import { lazy, Suspense, useEffect, useMemo, useRef, useState, FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  MessageSquare,
  Search,
  Loader2,
  Shield,
  FileText,
  Radio,
  Users,
  Settings,
  ExternalLink,
  AlertTriangle,
  Zap,
  Activity,
  BarChart3,
  Globe,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataState } from '../../components/DataState';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';

const TelegramFirehose = lazy(() => import('./TelegramFirehose'));
const TelegramLeaks = lazy(() => import('./TelegramLeaks'));
const TelegramLeakStats = lazy(() => import('./TelegramLeakStats'));
const TelegramChannelSearch = lazy(() => import('./TelegramChannelSearch'));
const TelegramDiscoveredChannels = lazy(() => import('./TelegramDiscoveredChannels'));
const TelegramLinkedActors = lazy(() => import('./TelegramLinkedActors'));
const TelegramSettings = lazy(() => import('./TelegramSettings'));

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface ChannelSearchResult {
  handle: string;
  name: string;
  description: string;
  subscribers: number | null;
  posts_per_day: number | null;
  category: string | null;
  tgstat_url: string;
  source: 'tgstat';
}

interface ChannelSearchResponse {
  query: string;
  generated_at: string;
  results: ChannelSearchResult[];
  warnings: string[];
}

interface LeakEntry {
  id: number;
  channel_handle: string;
  message_text: string | null;
  leak_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  discovered_at: string;
  domains_found: string;
}

interface LeakSearchResponse {
  entries: LeakEntry[];
  count: number;
}

interface StatsResponse {
  total_entries: number;
  last_24h: number;
  severity_distribution: Array<{ severity: string; n: number }>;
  top_channels: Array<{ channel_handle: string; n: number }>;
  top_domains: Array<{ domain: string; count: number }>;
}

interface HubKpis {
  totalLeakEntries: number | null;
  last24h: number | null;
  criticalCount: number | null;
  uniqueChannels: number | null;
  topDomains: string[];
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function formatNum(n: number | null): string {
  if (n === null) return '-';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function formatSubs(n: number | null): string {
  return formatNum(n);
}

function severityTone(s: string): string {
  switch (s) {
    case 'critical':
      return 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300';
    case 'high':
      return 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300';
    case 'medium':
      return 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300';
    default:
      return 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300';
  }
}

/* ------------------------------------------------------------------ */
/*  Hub cards                                                          */
/* ------------------------------------------------------------------ */

interface HubCard {
  path: string;
  icon: JSX.Element;
  title: string;
  blurb: string;
  badge?: 'live' | 'new' | 'beta';
  accent: string;
}

const HUB_CARDS: HubCard[] = [
  {
    path: '/threatintel/telegram?tab=firehose',
    icon: <Radio size={20} />,
    title: 'Telegram Monitor',
    blurb:
      '7-tab live workspace - firehose, leak feed, channel search, statistics, channel discovery, linked actors, settings.',
    badge: 'live',
    accent: 'border-sky-500/40 hover:border-sky-500/70 text-sky-700 dark:text-sky-300',
  },
  {
    path: '/threatintel/telegram?tab=iocs',
    icon: <Shield size={20} />,
    title: 'Telegram IOC Pipeline',
    blurb: 'Telegram-leaked hashes, IPs, domains, CVEs, URLs promoted to the cross-source consensus.',
    badge: 'new',
    accent: 'border-rose-500/40 hover:border-rose-500/70 text-rose-700 dark:text-rose-300',
  },
  {
    path: '/threatintel/telegram?tab=search',
    icon: <Search size={20} />,
    title: 'Channel Discovery',
    blurb: 'Keyword search across tgstat.com + curated catalog with linked-actor correlation.',
    accent: 'border-violet-500/40 hover:border-violet-500/70 text-violet-700 dark:text-violet-300',
  },
  {
    path: '/threatintel/telegram?tab=settings',
    icon: <Settings size={20} />,
    title: 'Channel Settings',
    blurb: 'Add or remove monitored channels, tweak per-source settings, manage the watchlist.',
    accent: 'border-emerald-500/40 hover:border-emerald-500/70 text-emerald-700 dark:text-emerald-300',
  },
];

/* ------------------------------------------------------------------ */
/*  Tab definitions                                                    */
/* ------------------------------------------------------------------ */

interface TabDef {
  id: string;
  label: string;
  icon: typeof Radio;
  component: React.LazyExoticComponent<() => JSX.Element>;
}

const TABS: TabDef[] = [
  {
    id: 'firehose',
    label: 'Firehose',
    icon: Radio,
    component: TelegramFirehose as React.LazyExoticComponent<() => JSX.Element>,
  },
  { id: 'leaks', label: 'Leak Feed', icon: AlertTriangle, component: TelegramLeaks },
  { id: 'search', label: 'Channel Search', icon: Search, component: TelegramChannelSearch },
  { id: 'stats', label: 'Statistics', icon: BarChart3, component: TelegramLeakStats },
  { id: 'channels', label: 'Discovery', icon: Globe, component: TelegramDiscoveredChannels },
  { id: 'actors', label: 'Linked Actors', icon: Users, component: TelegramLinkedActors },
  { id: 'iocs', label: 'IOC Pipeline', icon: Shield, component: TelegramLeaks },
  { id: 'settings', label: 'Settings', icon: Settings, component: TelegramSettings },
];

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export default function TelegramHub(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get('tab');
  const tabDef = TABS.find((t) => t.id === activeTab) ?? null;

  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);

  const [q, setQ] = useState('');
  const [submittedQ, setSubmittedQ] = useState('');
  const [channels, setChannels] = useState<ChannelSearchResult[]>([]);
  const [leaks, setLeaks] = useState<LeakEntry[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  /* Fetch hub KPIs (lightweight) once on mount */
  useEffect(() => {
    const ctrl = new AbortController();
    let cancel = false;
    async function run() {
      setStatsLoading(true);
      setStatsError(null);
      try {
        const res = await fetch('/api/v1/telegram-leaks/stats', {
          signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15000)]),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as StatsResponse;
        if (!cancel) setStats(data);
      } catch (e) {
        console.error('run failed:', errMessage(e));
        if (!cancel) setStatsError(errMessage(e, 'failed to load stats'));
      } finally {
        if (!cancel) setStatsLoading(false);
      }
    }
    void run();
    return () => {
      cancel = true;
      ctrl.abort();
    };
  }, []);

  /* Aggregate KPIs */
  const kpis: HubKpis = useMemo(() => {
    if (!stats) {
      return { totalLeakEntries: null, last24h: null, criticalCount: null, uniqueChannels: null, topDomains: [] };
    }
    const critical = stats.severity_distribution.find((d) => d.severity === 'critical')?.n ?? 0;
    return {
      totalLeakEntries: stats.total_entries,
      last24h: stats.last_24h,
      criticalCount: critical,
      uniqueChannels: stats.top_channels.length,
      topDomains: stats.top_domains.slice(0, 5).map((d) => d.domain),
    };
  }, [stats]);

  /* Unified search - runs both endpoints in parallel */
  const searchRef = useRef<AbortController | null>(null);
  async function runSearch(query: string) {
    searchRef.current?.abort();
    const ctrl = new AbortController();
    searchRef.current = ctrl;
    const signal = AbortSignal.any([ctrl.signal, AbortSignal.timeout(15000)]);
    setSearchLoading(true);
    setSearchError(null);
    setHasSearched(true);
    try {
      const emptyChannels: ChannelSearchResponse = { query: '', generated_at: '', results: [], warnings: [] };
      const emptyLeaks: LeakSearchResponse = { entries: [], count: 0 };
      const [ch, lk] = await Promise.all([
        fetch(`/api/v1/telegram-search?q=${encodeURIComponent(query)}`, { signal })
          .then((r) => (r.ok ? r.json() : Promise.resolve(emptyChannels)))
          .catch(() => emptyChannels),
        fetch(`/api/v1/telegram-leaks/search?q=${encodeURIComponent(query)}&limit=25`, { signal })
          .then((r) => (r.ok ? r.json() : Promise.resolve(emptyLeaks)))
          .catch(() => emptyLeaks),
      ]);
      setChannels(ch.results ?? []);
      setLeaks(lk.entries ?? []);
    } catch (e) {
      console.error('runSearch failed:', errMessage(e));
      setSearchError(errMessage(e, 'search failed'));
    } finally {
      setSearchLoading(false);
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = q.trim();
    if (!trimmed) return;
    setSubmittedQ(trimmed);
    void runSearch(trimmed);
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<MessageSquare size={28} />}
      title="Telegram Intelligence Hub"
      description="Unified Telegram CTI workspace - channel discovery, leak monitoring, IOC pipeline, and a free cross-source search across monitored channels and tgstat.com."
    >
      {/* Tab bar */}
      <div className="mb-6 flex flex-wrap gap-1.5 border-b border-line-1 pb-3">
        <button
          type="button"
          onClick={() => setSearchParams({}, { replace: true })}
          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors ${
            !tabDef ? 'bg-rose-600 text-white' : 'text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
          }`}
        >
          <MessageSquare size={13} />
          Hub
        </button>
        {TABS.map((t) => {
          const TIcon = t.icon;
          const isActive = tabDef?.id === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setSearchParams({ tab: t.id }, { replace: true })}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors ${
                isActive ? 'bg-rose-600 text-white' : 'text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
              }`}
            >
              <TIcon size={13} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Active tab content */}
      {tabDef ? (
        <Suspense
          fallback={
            <div className="flex items-center justify-center py-16">
              <Loader2 size={24} className="animate-spin text-muted" />
            </div>
          }
        >
          <tabDef.component />
        </Suspense>
      ) : (
        <>
          {/* Hero search */}
          <section className="mb-6 rounded-xl border border-line-1 bg-gradient-to-br from-slate-50 to-white dark:from-slate-900/50 dark:to-slate-900/20 p-5">
            <div className="flex items-center gap-2 mb-3">
              <Zap size={16} className="text-amber-500" />
              <h2 className="font-mono text-sm uppercase tracking-wider text-body">Cross-source Telegram search</h2>
            </div>
            <form onSubmit={onSubmit} className="flex gap-2">
              <div className="relative flex-1">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
                <input
                  type="search"
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search channels (e.g. conti leaks) or leak text (e.g. cve-2026-10520)"
                  className="w-full pl-9 pr-3 py-2.5 rounded border border-line-2 bg-surface-100 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-rose-500"
                  aria-label="Search Telegram channels and leak text"
                  maxLength={120}
                />
              </div>
              <button
                type="submit"
                disabled={searchLoading || !q.trim()}
                className="inline-flex items-center gap-2 rounded bg-rose-600 hover:bg-rose-700 dark:bg-rose-500 dark:hover:bg-rose-400 disabled:opacity-50 disabled:cursor-not-allowed text-on-fill font-mono text-sm font-semibold px-4 py-2.5 transition-colors"
              >
                {searchLoading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                Search
              </button>
            </form>
            <p className="text-mini font-mono text-muted mt-2">
              Hits <code>/api/v1/telegram-search</code> (tgstat-backed channel discovery) and{' '}
              <code>/api/v1/telegram-leaks/search</code> (D1 leak text) in parallel.
            </p>
          </section>

          {/* Search results */}
          {hasSearched && (
            <section className="mb-8">
              <h2 className="font-mono text-sm uppercase tracking-wider text-body mb-3">
                Results for <span className="text-rose-600 dark:text-rose-400">“{submittedQ}”</span>
              </h2>
              <DataState
                loading={searchLoading}
                error={searchError}
                empty={!searchLoading && channels.length === 0 && leaks.length === 0}
                emptyLabel="No matches across channels or leak text."
                rows={4}
                onRetry={() => void runSearch(submittedQ)}
              >
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Channel results */}
                  <div>
                    <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">
                      Channels ({channels.length})
                    </h3>
                    {channels.length === 0 ? (
                      <p className="text-xs text-muted italic">No matching channels on tgstat.</p>
                    ) : (
                      <ul className="space-y-2">
                        {channels.slice(0, 10).map((c) => (
                          <li key={c.handle} className="rounded border border-line-1 bg-surface-100/40 p-3">
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <a
                                href={sanitizeUrl(c.tgstat_url) ?? '#'}
                                target="_blank"
                                rel="noreferrer"
                                className="font-mono text-sm font-semibold text-rose-700 dark:text-rose-300 hover:underline flex items-center gap-1 transition-colors"
                              >
                                @{c.handle}
                                <ExternalLink size={11} />
                              </a>
                              <span className="text-micro font-mono text-muted">
                                {formatSubs(c.subscribers)} subs · {c.posts_per_day ?? '-'} posts/day
                              </span>
                            </div>
                            <p className="text-xs text-muted line-clamp-2">{c.description || c.name}</p>
                            {c.category && (
                              <span className="inline-block mt-1 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-line-2 text-muted">
                                {c.category}
                              </span>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {/* Leak results */}
                  <div>
                    <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">
                      Leak text matches ({leaks.length})
                    </h3>
                    {leaks.length === 0 ? (
                      <p className="text-xs text-muted italic">No matches in monitored leak text.</p>
                    ) : (
                      <ul className="space-y-2">
                        {leaks.slice(0, 10).map((l) => (
                          <li key={l.id} className="rounded border border-line-1 bg-surface-100/40 p-3">
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <Link
                                to={`/threatintel/telegram?tab=leaks&channel=${encodeURIComponent(l.channel_handle)}`}
                                className="font-mono text-sm font-semibold text-rose-700 dark:text-rose-300 hover:underline"
                              >
                                @{l.channel_handle}
                              </Link>
                              <span
                                className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${severityTone(
                                  l.severity
                                )}`}
                              >
                                {l.severity}
                              </span>
                            </div>
                            <p className="text-xs text-muted line-clamp-2">
                              {(l.message_text ?? '').slice(0, 220) || '-'}
                            </p>
                            <p className="text-micro font-mono text-muted mt-1">
                              {l.discovered_at} · {l.leak_type}
                            </p>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </DataState>
            </section>
          )}

          {/* KPI strip */}
          <section className="mb-8">
            <h2 className="font-mono text-sm uppercase tracking-wider text-body mb-3">At a glance</h2>
            <DataState loading={statsLoading} error={statsError} empty={false} rows={4}>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <KpiTile
                  icon={<FileText size={14} />}
                  label="Leak entries (total)"
                  value={formatNum(kpis.totalLeakEntries)}
                />
                <KpiTile icon={<Activity size={14} />} label="Discovered (24h)" value={formatNum(kpis.last24h)} />
                <KpiTile
                  icon={<AlertTriangle size={14} />}
                  label="Critical"
                  value={formatNum(kpis.criticalCount)}
                  tone="rose"
                />
                <KpiTile
                  icon={<Users size={14} />}
                  label="Top channels tracked"
                  value={formatNum(kpis.uniqueChannels)}
                />
              </div>
              {kpis.topDomains.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <span className="text-micro font-mono uppercase tracking-wider text-muted mr-1">Top domains:</span>
                  {kpis.topDomains.map((d) => (
                    <span
                      key={d}
                      className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 text-muted"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              )}
            </DataState>
          </section>

          {/* Hub cards */}
          <section>
            <h2 className="font-mono text-sm uppercase tracking-wider text-body mb-3">Telegram surfaces</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {HUB_CARDS.map((card) => (
                <Link
                  key={card.path}
                  to={card.path}
                  className={`group block rounded-xl border bg-surface-100 dark:bg-surface-200/40 p-4 transition-colors ${card.accent}`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="inline-flex items-center gap-2 font-mono text-sm font-semibold">
                      {card.icon}
                      {card.title}
                    </span>
                    {card.badge && (
                      <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-rose-600 dark:bg-rose-500 text-on-fill">
                        {card.badge}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted leading-relaxed">{card.blurb}</p>
                </Link>
              ))}
            </div>
          </section>

          {/* Source provenance footer */}
          <footer className="mt-8 pt-4 border-t border-line-1">
            <p className="text-mini font-mono text-muted">
              Sources: tgstat.com (HTML scrape, 12h cache) · telegram.me/s/ previews (hourly poll) · D1 leak store ·
              cross-source IOC consensus. All free-tier, no API keys.
            </p>
          </footer>
        </>
      )}
    </DataPageLayout>
  );
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

function KpiTile({
  icon,
  label,
  value,
  tone,
}: {
  icon: JSX.Element;
  label: string;
  value: string;
  tone?: 'rose';
}): JSX.Element {
  const accent =
    tone === 'rose'
      ? 'border-rose-500/40 bg-rose-500/5 text-rose-700 dark:text-rose-300'
      : 'border-line-1 bg-white dark:bg-surface-200/40 text-body';
  return (
    <div className={`rounded border p-3 ${accent}`}>
      <div className="flex items-center gap-1.5 text-micro font-mono uppercase tracking-wider opacity-80">
        {icon}
        {label}
      </div>
      <div className="mt-1 font-mono text-xl font-semibold">{value}</div>
    </div>
  );
}
