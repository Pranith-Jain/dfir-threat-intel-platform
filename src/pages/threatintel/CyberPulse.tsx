import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';
import {
  AlertTriangle,
  Bug,
  Building2,
  Calendar,
  ChevronDown,
  ExternalLink,
  Filter,
  Globe,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  Skull,
  TrendingUp,
  X,
} from 'lucide-react';
import { useDebounce } from '../../hooks/useDebounce';
import { turnstileHeaders } from '../../lib/turnstile';
import { relativeAgo } from '../../lib/relativeTime';

/**
 * CyberPulse - comprehensive breach/leak/intel incident tracker.
 *
 * Broader than ransom.live: covers ransomware, data leaks, credential leaks,
 * extortion, supply chain, zero-day, DDoS, hacktivism, and general breaches.
 * Data sourced from X/Twitter, Telegram, Reddit, Bluesky, and Mastodon firehose.
 */

const TYPE_ICONS: Record<string, typeof AlertTriangle> = {
  ransomware: Skull,
  data_leak: AlertTriangle,
  credential_leak: Bug,
  extortion: Shield,
  defacement: Globe,
  supply_chain: Building2,
  zero_day: AlertTriangle,
  breach: Shield,
  ddos: Globe,
  hacktivism: Skull,
  other: Shield,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-700 dark:text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-700 dark:text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/30',
  low: 'bg-brand-500/20 text-brand-700 dark:text-brand-400 border-brand-500/30',
  info: 'bg-slate-500/20 text-slate-700 dark:text-muted border-slate-500/30',
};

const TYPE_COLORS: Record<string, string> = {
  ransomware: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20',
  data_leak: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20',
  credential_leak: 'bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-500/20',
  extortion: 'bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20',
  defacement: 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border-cyan-500/20',
  supply_chain: 'bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 border-indigo-500/20',
  zero_day: 'bg-red-600/10 text-red-800 dark:text-red-300 border-red-600/20',
  breach: 'bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20',
  ddos: 'bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/20',
  hacktivism: 'bg-pink-500/10 text-pink-700 dark:text-pink-400 border-pink-500/20',
  other: 'bg-slate-500/10 text-slate-700 dark:text-muted border-slate-500/20',
};

const TYPE_LABELS: Record<string, string> = {
  ransomware: 'Ransomware',
  data_leak: 'Data Leak',
  credential_leak: 'Credential Leak',
  extortion: 'Extortion',
  defacement: 'Defacement',
  supply_chain: 'Supply Chain',
  zero_day: 'Zero-Day',
  breach: 'Breach',
  ddos: 'DDoS',
  hacktivism: 'Hacktivism',
  other: 'Other',
};

const PLATFORM_LABELS: Record<string, string> = {
  x: 'X/Twitter',
  telegram: 'Telegram',
  bluesky: 'Bluesky',
  mastodon: 'Mastodon',
  reddit: 'Reddit',
  manual: 'Manual',
  rss: 'RSS',
  other: 'Other',
};

interface Incident {
  id: string;
  incident_type: string;
  severity: string;
  victim_name: string | null;
  victim_domain: string | null;
  victim_sector: string | null;
  victim_country: string | null;
  threat_actor: string | null;
  title: string;
  description: string | null;
  records_count: number | null;
  data_volume: string | null;
  source_platform: string;
  source_url: string | null;
  source_handle: string | null;
  source_author: string | null;
  confidence: number;
  discovered_at: string;
  reported_at: string | null;
  tags: string;
  source_likes: number;
  source_retweets: number;
}

interface Stats {
  total: number;
  by_type: Array<{ incident_type: string; count: number }>;
  by_severity: Array<{ severity: string; count: number }>;
  by_platform: Array<{ source_platform: string; count: number }>;
  by_sector: Array<{ victim_sector: string; count: number }>;
  daily_trend: Array<{ day: string; count: number }>;
  top_actors: Array<{ threat_actor: string; count: number }>;
  top_victims: Array<{ victim_name: string; count: number }>;
  last_scan: string | null;
}

interface Trending {
  trending_actors: Array<{ name: string; this_week: number; last_week: number; delta: number }>;
  trending_victims: Array<{ name: string; this_week: number; last_week: number; delta: number }>;
}

function formatNumber(n: number | null): string {
  if (n === null) return '-';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export default function CyberPulse(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const postSummaries = usePostSummaries({
    surface: 'CyberPulse',
    items: incidents.slice(0, 100).map((inc) => ({
      id: inc.id,
      title: inc.title,
      body: `${inc.title}${inc.description ? `\n${inc.description}` : ''}`,
      source: inc.source_handle ?? inc.source_platform,
    })),
  });
  const [stats, setStats] = useState<Stats | null>(null);
  const [trending, setTrending] = useState<Trending | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState(searchParams.get('type') ?? '');
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('sev') ?? '');
  const [platformFilter, setPlatformFilter] = useState(searchParams.get('plat') ?? '');
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') ?? '');
  const debouncedSearch = useDebounce(searchQuery, 200);
  const [days, setDays] = useState(() => {
    // ?days=abc (shared/bookmarked URL) must not put NaN into API URLs.
    const d = Number(searchParams.get('days') ?? '7');
    return Number.isFinite(d) && d > 0 ? d : 7;
  });
  const [refreshKey, setRefreshKey] = useState(0);

  const pulseRef = useRef<AbortController | null>(null);

  const fetchIncidents = useCallback(async () => {
    pulseRef.current?.abort();
    const ctrl = new AbortController();
    pulseRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('limit', '100');
      params.set('days', String(days));
      if (typeFilter) params.set('type', typeFilter);
      if (severityFilter) params.set('severity', severityFilter);
      if (platformFilter) params.set('platform', platformFilter);
      if (debouncedSearch) params.set('q', debouncedSearch);

      const signal = AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]);
      const [incRes, statsRes, trendRes] = await Promise.all([
        fetch(`/api/v1/cyberpulse/incidents?${params}`, { signal }),
        fetch(`/api/v1/cyberpulse/stats?days=${days}`, { signal }),
        fetch('/api/v1/cyberpulse/trending', { signal }),
      ]);
      if (ctrl.signal.aborted) return;

      if (incRes.ok) {
        const d = await incRes.json();
        setIncidents(d.incidents);
        setTotal(d.total);
        setHasMore(d.has_more);
      }
      if (statsRes.ok) setStats(await statsRes.json());
      if (trendRes.ok) setTrending(await trendRes.json());
    } catch (e) {
      logCatch(e);
      if (ctrl.signal.aborted) return;
      setError(errMessage(e, 'Failed to load'));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
    // refreshKey is intentionally a dep to bust the callback identity so the
    // fetch effect re-fires on manual refresh — it isn't read inside the body.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days, typeFilter, severityFilter, platformFilter, debouncedSearch, refreshKey]);

  useEffect(() => {
    fetchIncidents();
    return () => {
      pulseRef.current?.abort();
    };
  }, [fetchIncidents]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (typeFilter) params.set('type', typeFilter);
    if (severityFilter) params.set('sev', severityFilter);
    if (platformFilter) params.set('plat', platformFilter);
    if (searchQuery) params.set('q', searchQuery);
    if (days !== 7) params.set('days', String(days));
    setSearchParams(params, { replace: true });
  }, [typeFilter, severityFilter, platformFilter, searchQuery, days, setSearchParams]);

  const clearFilters = () => {
    setTypeFilter('');
    setSeverityFilter('');
    setPlatformFilter('');
    setSearchQuery('');
    setDays(7);
  };

  const hasFilters = typeFilter || severityFilter || platformFilter || searchQuery || days !== 7;

  return (
    <DataPageLayout
      backTo="/threatintel"
      title="CyberPulse"
      description="Breach, leak & cybercrime incident tracker - sourced from X/Twitter, Telegram, Reddit, Bluesky & Mastodon firehose"
      icon={<AlertTriangle size={28} />}
    >
      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
          <StatCard label="Total" value={stats.total} color="text-slate-900 dark:text-white" />
          {stats.by_severity.map((s) => (
            <StatCard
              key={s.severity}
              label={s.severity}
              value={s.count}
              color={SEVERITY_COLORS[s.severity]?.split(' ')[1] ?? 'text-muted'}
            />
          ))}
        </div>
      )}

      {/* Filters bar */}
      <div className="flex flex-wrap items-center gap-2 mb-4 p-3 rounded-xl border border-line-1 bg-surface-100/50">
        <Filter className="w-4 h-4 text-muted" />
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search incidents..."
            className="pl-7 pr-2 py-1 text-sm rounded border border-line-2 bg-surface-100 text-heading w-48"
          />
        </div>
        <FilterSelect value={typeFilter} onChange={setTypeFilter} options={TYPE_LABELS} placeholder="Type" />
        <FilterSelect
          value={severityFilter}
          onChange={setSeverityFilter}
          options={{ critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }}
          placeholder="Severity"
        />
        <FilterSelect
          value={platformFilter}
          onChange={setPlatformFilter}
          options={PLATFORM_LABELS}
          placeholder="Platform"
        />
        <FilterSelect
          value={String(days)}
          onChange={(v) => setDays(Number(v))}
          options={{ '1': '1 day', '3': '3 days', '7': '7 days', '14': '14 days', '30': '30 days' }}
          placeholder="Period"
        />
        {hasFilters && (
          <button
            type="button"
            onClick={clearFilters}
            className="text-xs text-muted hover:text-heading dark:hover:text-white flex items-center gap-1 transition-colors"
          >
            <X className="w-3 h-3" /> Clear
          </button>
        )}
        <div className="ml-auto flex items-center gap-2">
          {stats?.last_scan && (
            <span
              className={`text-xs ${Date.now() - Date.parse(stats.last_scan) > 2 * 3600_000 ? 'text-amber-600 dark:text-amber-400' : 'text-muted'}`}
            >
              Last scan: {relativeAgo(stats.last_scan)}
            </span>
          )}
          <span className="text-xs text-muted">{total.toLocaleString()} incidents</span>
          <button
            type="button"
            onClick={async () => {
              if (scanning) return;
              setScanning(true);
              setScanResult(null);
              try {
                const res = await fetch('/api/v1/cyberpulse/scan', {
                  method: 'POST',
                  headers: await turnstileHeaders('cyberpulse-scan'),
                });
                const data = await res.json();
                if (data.ok) {
                  setScanResult(
                    `Scan complete - ${data.incidents_created} new, ${data.incidents_deduped} deduped in ${Math.round(data.duration_ms / 1000)}s`
                  );
                  setRefreshKey((k) => k + 1);
                } else {
                  setScanResult(data.error || 'Scan failed');
                }
              } catch (e) {
                setScanResult(errMessage(e, 'Scan failed'));
              } finally {
                setScanning(false);
              }
            }}
            disabled={scanning}
            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-blue-50 dark:bg-blue-900/30 text-brand-700 dark:text-brand-300 border border-blue-200 dark:border-blue-800 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors disabled:opacity-50"
          >
            {scanning ? <Loader2 className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
            {scanning ? 'Scanning…' : 'Scan now'}
          </button>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="p-1 rounded hover:bg-track dark:hover:bg-surface-300"
          >
            <RefreshCw className={`w-4 h-4 text-muted ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && <div className="text-center py-8 text-red-600 dark:text-red-400">{error}</div>}

      {scanResult && (
        <div
          className={`mb-4 px-4 py-2 rounded-xl text-sm ${scanResult.includes('complete') ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800' : 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800'}`}
        >
          {scanResult}
        </div>
      )}

      {/* Main content: incidents feed + sidebar */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Incidents feed */}
        <div className="flex-1 min-w-0 space-y-3">
          {incidents.length === 0 && !loading && (
            <div className="text-center py-12 text-muted">
              <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p>No incidents found. The ingestion pipeline runs hourly.</p>
              <p className="text-xs mt-2">Try broadening your filters or waiting for the next scan.</p>
            </div>
          )}
          <PostAnalysisButton
            title="CyberPulse Digest"
            description="AI-powered threat analysis of the current feed."
            source="cyberpulse"
          />
          <AiSummaryCard
            surface="CyberPulse"
            items={incidents.slice(0, 30).map((inc) => ({
              title: inc.title,
              body: `${inc.title}${inc.description ? `\n${inc.description}` : ''}`,
              source: inc.source_handle ?? inc.source_platform,
            }))}
            requireAdmin={false}
          />
          {incidents.map((inc) => (
            <IncidentCard key={inc.id} incident={inc} postSummary={postSummaries.get(inc.id)} />
          ))}
          {hasMore && (
            <div className="text-center py-4">
              <button
                type="button"
                disabled={loadingMore}
                onClick={() => {
                  if (loadingMore) return; // double-click guard — same-offset dupes
                  setLoadingMore(true);
                  const ctrl = new AbortController();
                  fetch(
                    `/api/v1/cyberpulse/incidents?limit=100&offset=${incidents.length}&days=${days}${typeFilter ? `&type=${typeFilter}` : ''}${severityFilter ? `&severity=${severityFilter}` : ''}${platformFilter ? `&platform=${platformFilter}` : ''}${debouncedSearch ? `&q=${debouncedSearch}` : ''}`,
                    { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) }
                  )
                    .then((r) => {
                      if (ctrl.signal.aborted) return;
                      return r.json();
                    })
                    .then((d) => {
                      if (ctrl.signal.aborted) return;
                      setIncidents((prev) => [...prev, ...d.incidents]);
                      setHasMore(d.has_more);
                    })
                    .catch(() => {
                      if (!ctrl.signal.aborted) setError('Failed to load more incidents');
                    })
                    .finally(() => setLoadingMore(false));
                }}
                className="text-sm text-brand-600 dark:text-brand-400 hover:text-brand-800 dark:hover:text-brand-300"
              >
                Load more...
              </button>
            </div>
          )}
        </div>

        {/* Sidebar: trending + type breakdown */}
        <div className="w-full lg:w-80 space-y-4">
          {/* Type breakdown */}
          {stats && stats.by_type.length > 0 && (
            <div className="surface-card p-4">
              <h3 className="text-sm font-semibold text-body mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4" /> By Type
              </h3>
              <div className="space-y-2">
                {stats.by_type.map((t) => (
                  <button
                    type="button"
                    key={t.incident_type}
                    onClick={() => setTypeFilter(typeFilter === t.incident_type ? '' : t.incident_type)}
                    className={`w-full flex items-center justify-between px-2 py-1.5 rounded text-xs transition-colors ${typeFilter === t.incident_type ? 'bg-brand-500/20 text-brand-600 dark:text-brand-400' : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-muted'}`}
                  >
                    <span className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-full ${TYPE_COLORS[t.incident_type]?.split(' ')[0] ?? 'bg-slate-500'}`}
                      />
                      {TYPE_LABELS[t.incident_type] ?? t.incident_type}
                    </span>
                    <span className="font-mono text-heading">{t.count}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Trending actors */}
          {trending && trending.trending_actors.length > 0 && (
            <div className="surface-card p-4">
              <h3 className="text-sm font-semibold text-body mb-3 flex items-center gap-2">
                <TrendingUp className="w-4 h-4" /> Trending Actors
              </h3>
              <div className="space-y-1.5">
                {trending.trending_actors.map((a) => (
                  <button
                    type="button"
                    key={a.name}
                    onClick={() => setTypeFilter('')}
                    className="w-full flex items-center justify-between px-2 py-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-200 text-body"
                  >
                    <span className="truncate">{a.name}</span>
                    <span className="flex items-center gap-1 font-mono">
                      <span className="text-heading">{a.this_week}</span>
                      <span className="text-green-600 dark:text-green-400">+{a.delta}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Top victims */}
          {stats && stats.top_victims.length > 0 && (
            <div className="surface-card p-4">
              <h3 className="text-sm font-semibold text-body mb-3 flex items-center gap-2">
                <Building2 className="w-4 h-4" /> Most Targeted
              </h3>
              <div className="space-y-1.5">
                {stats.top_victims.map((v) => (
                  <div key={v.victim_name} className="flex items-center justify-between px-2 py-1 text-xs text-body">
                    <span className="truncate">{v.victim_name}</span>
                    <span className="font-mono text-heading">{v.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Daily trend mini chart */}
          {stats && stats.daily_trend.length > 0 && (
            <div className="surface-card p-4">
              <h3 className="text-sm font-semibold text-body mb-3 flex items-center gap-2">
                <Calendar className="w-4 h-4" /> Daily Trend
              </h3>
              <div className="flex items-end gap-1 h-16">
                {stats.daily_trend.map((d) => {
                  const maxCount = Math.max(...stats.daily_trend.map((x) => x.count));
                  const barPx = maxCount > 0 ? Math.max((d.count / maxCount) * 48, 3) : 3;
                  return (
                    <div
                      key={d.day}
                      className="flex-1 flex flex-col items-center justify-end self-stretch"
                      title={`${d.day}: ${d.count}`}
                    >
                      <div className="w-full bg-brand-500/40 rounded-t" style={{ height: barPx }} />
                      <span className="text-micro text-muted font-mono leading-none mt-0.5">{d.day.slice(5)}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </DataPageLayout>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="surface-card p-3 text-center">
      <div className={`text-xl font-bold ${color}`}>{formatNumber(value)}</div>
      <div className="text-micro font-mono uppercase tracking-wider text-muted mt-0.5">{label}</div>
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  options: Record<string, string>;
  placeholder: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className={`flex items-center gap-1 px-2 py-1 text-xs rounded border ${value ? 'border-brand-500/50 text-brand-600 dark:text-brand-400 bg-brand-500/10' : 'border-slate-300 dark:border-line-1 text-slate-700 dark:text-muted'}`}
      >
        {value ? (options[value] ?? value) : placeholder}
        <ChevronDown className="w-3 h-3" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute z-20 mt-1 left-0 bg-surface-100 border border-line-1 rounded shadow-e3 max-h-48 overflow-auto min-w-[120px]">
            <button
              type="button"
              onClick={() => {
                onChange('');
                setOpen(false);
              }}
              className="block w-full text-left px-3 py-1.5 text-xs hover:bg-surface-300 dark:hover:bg-surface-300 text-muted"
            >
              All
            </button>
            {Object.entries(options).map(([k, v]) => (
              <button
                type="button"
                key={k}
                onClick={() => {
                  onChange(k);
                  setOpen(false);
                }}
                className={`block w-full text-left px-3 py-1.5 text-xs hover:bg-surface-300 dark:hover:bg-surface-300 ${value === k ? 'text-brand-600 dark:text-brand-400 font-semibold' : 'text-body'}`}
              >
                {v}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function IncidentCard({ incident: inc, postSummary }: { incident: Incident; postSummary?: string }) {
  const Icon = TYPE_ICONS[inc.incident_type] ?? Shield;
  const tags: string[] = (() => {
    try {
      return JSON.parse(inc.tags);
    } catch (_catchErr) {
      console.error('IncidentCard failed:', errMessage(_catchErr));
      return [];
    }
  })();

  return (
    <div className="surface-card p-4 hover:border-line-2 dark:hover:border-line-2 transition-colors">
      <PostSummary text={postSummary} />
      <div className="flex items-start gap-3">
        <div
          className={`mt-0.5 p-1.5 rounded ${TYPE_COLORS[inc.incident_type]?.split(' ').slice(0, 2).join(' ') ?? 'bg-slate-500/10 text-muted'}`}
        >
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span
              className={`px-1.5 py-0.5 text-micro font-semibold uppercase rounded border ${SEVERITY_COLORS[inc.severity] ?? 'bg-slate-500/20 text-muted border-slate-500/30'}`}
            >
              {inc.severity}
            </span>
            <span
              className={`px-1.5 py-0.5 text-micro font-medium uppercase rounded border ${TYPE_COLORS[inc.incident_type]?.split(' ').slice(0, 2).join(' ') ?? 'bg-slate-500/10 text-muted border-slate-500/20'}`}
            >
              {TYPE_LABELS[inc.incident_type] ?? inc.incident_type}
            </span>
            <span className="text-micro text-muted font-mono">
              {PLATFORM_LABELS[inc.source_platform] ?? inc.source_platform}
            </span>
          </div>

          <p className="text-sm text-heading leading-snug mb-1.5 line-clamp-2">{inc.title}</p>

          <div className="flex items-center gap-3 text-xs text-muted flex-wrap">
            {inc.victim_name && (
              <span className="flex items-center gap-1">
                <Building2 className="w-3 h-3" />
                {inc.victim_name}
              </span>
            )}
            {inc.threat_actor && (
              <span className="flex items-center gap-1 text-red-600 dark:text-red-400">
                <Skull className="w-3 h-3" />
                {inc.threat_actor}
              </span>
            )}
            {inc.victim_sector && <span className="text-muted">{inc.victim_sector}</span>}
            {inc.records_count && (
              <span className="font-mono text-body dark:text-muted">{formatNumber(inc.records_count)} records</span>
            )}
            {inc.data_volume && <span className="font-mono text-body dark:text-muted">{inc.data_volume}</span>}
          </div>

          <div className="flex items-center gap-2 mt-2 flex-wrap">
            {tags.slice(0, 5).map((tag) => (
              <span key={tag} className="px-1.5 py-0.5 text-micro rounded bg-surface-300 text-muted">
                {tag}
              </span>
            ))}
            <span className="text-micro text-muted ml-auto">{relativeAgo(inc.discovered_at)}</span>
            {inc.source_url && (
              <a
                href={inc.source_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-brand-600 dark:text-brand-400 hover:text-brand-800 dark:hover:text-brand-300 transition-colors"
              >
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
