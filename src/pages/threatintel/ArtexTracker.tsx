import { useEffect, useMemo, useState } from 'react';
import { Activity, Bot, Check, Copy, ExternalLink, Globe, Radar, Server, ShieldAlert, Skull, Tag } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { errMessage } from '../../lib/log';

/**
 * ARTEX Intel tracker mirror (artexintel.com).
 *
 * ARTEX (Autumn-27) is an intrusion set that operationalises AI tooling:
 * the infrastructure it abuses is dominated by LLM API endpoints
 * (api[.]anthropic[.]com, api[.]deepseek[.]com, api[.]x[.]ai are among the
 * most-seen domains), which is why this mirror lives in the AI Security
 * hub. The data files are a daily-synced verbatim copy of the upstream
 * tracker's own JSON (scripts/sync-artex.mjs); every entry keeps its
 * original sources, and all values stay defanged exactly as published.
 */

interface ArtexEvent {
  slug: string;
  title: string;
  url: string;
  cat: string;
  confidence: string;
  type: string;
  region: string;
  actor: string;
  icon: string;
  disclosed: string;
  summary: string;
  attributes: Record<string, string>;
  sources: Array<{ publisher: string; url: string }>;
  body: string[];
}

interface ArtexIndex {
  generated_at: string;
  upstream: {
    site: string;
    last_updated: string | null;
    exposure_feed: string | null;
    exposure_feed_updated: string | null;
  };
  sync_problems: string[];
  stats: {
    attack_events: number;
    tool_updates: number;
    events_total: number;
    first_public: string | null;
    last_public: string | null;
    days_tracked: number | null;
    iocs: number | null;
    exposed: number | null;
  };
  countries: Array<{ country: string; count: number }>;
  trend: Record<string, Array<[string, number]>> | null;
  keywords: Record<string, Array<[string, number]>> | null;
  events: ArtexEvent[];
  top_iocs: Record<string, Array<{ value: string; roles: string[]; sources: string[] }>>;
  samples: Array<{ hash: string; notes: string; status: string; sources: Array<{ publisher: string; url: string }> }>;
  traces: string[];
}

interface ArtexIoc {
  type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  infra: string;
  roles: string[];
  events: string[];
  status: string;
  tags: string[];
  defanged: string;
  type_label: string;
  sources: Array<{ publisher: string; url: string }>;
}

interface ExposureItem {
  value: string;
  first_seen: string;
  last_seen: string;
  active: boolean;
  verdict: string;
  country: string;
  country_en: string;
  carrier: string;
  infra: string;
  tags: string[];
  region: string;
  asn: number;
  code: string;
}

interface ExposureData {
  feed_url: string;
  feed_updated: string;
  items: ExposureItem[];
}

const TABS = ['overview', 'timeline', 'iocs', 'exposure'] as const;
type Tab = (typeof TABS)[number];

/** Upstream data-conf vocabulary, mapped to the tracker's own labels. */
const CONFIDENCE_LABELS: Record<string, string> = {
  ok: 'Confirmed',
  mid: 'Single-source',
  low: 'Unverified',
};

function confidenceLabel(v: string): string {
  return CONFIDENCE_LABELS[v] || (v ? v : 'Reported');
}

function StatTile({ label, value, icon }: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
      <div className="flex items-center gap-2 text-[11px] font-mono tracking-widest text-muted mb-1">
        {icon}
        {label}
      </div>
      <div className="text-2xl font-bold text-heading">{value}</div>
    </div>
  );
}

/** Compact SVG bar chart for a trend window (date, count) pairs. */
function TrendBars({ data }: { data: Array<[string, number]> }) {
  const max = Math.max(1, ...data.map((d) => d[1]));
  return (
    <div className="flex items-end gap-[3px] h-28">
      {data.map(([date, count]) => (
        <div key={date} className="flex-1 min-w-[4px] relative group">
          <div
            className="w-full rounded-t bg-sky-500/70 group-hover:bg-sky-400"
            style={{ height: `${Math.max(2, (count / max) * 100)}%` }}
          />
          <div className="absolute -top-7 left-1/2 -translate-x-1/2 hidden group-hover:block whitespace-nowrap z-10 rounded bg-surface-100 border border-line-1 px-1.5 py-0.5 text-[10px] font-mono text-muted">
            {date}: {count}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function ArtexTracker(): JSX.Element {
  const [tab, setTab] = useState<Tab>('overview');
  const [data, setData] = useState<ArtexIndex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [iocs, setIocs] = useState<ArtexIoc[] | null>(null);
  const [exposure, setExposure] = useState<ExposureData | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // IoC tab controls
  const [iocType, setIocType] = useState<string>('all');
  const [iocQuery, setIocQuery] = useState('');
  const [iocPage, setIocPage] = useState(0);
  // Exposure tab controls
  const [activeOnly, setActiveOnly] = useState(true);
  const [expPage, setExpPage] = useState(0);
  // Trend/keyword window
  const trendWindows = useMemo(() => Object.keys(data?.trend || {}), [data]);
  const kwWindows = useMemo(() => Object.keys(data?.keywords || {}), [data]);
  const [trendWindow, setTrendWindow] = useState<string>('d30');
  const [kwWindow, setKwWindow] = useState<string>('d30');
  const trendKey = trendWindows.includes(trendWindow) ? trendWindow : (trendWindows[0] ?? 'd30');
  const kwKey = kwWindows.includes(kwWindow) ? kwWindow : (kwWindows[0] ?? 'd30');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/data/artex/index.json', { signal: AbortSignal.timeout(15000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as ArtexIndex;
        if (!cancelled) setData(json);
      } catch (e) {
        if (!cancelled) setError(errMessage(e, 'Failed to load ARTEX tracker data'));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Deep tabs lazy-load their verbatim dataset the first time they open.
  useEffect(() => {
    if (tab === 'iocs' && !iocs && !error) {
      let cancelled = false;
      (async () => {
        try {
          const res = await fetch('/data/artex/iocs.json', { signal: AbortSignal.timeout(20000) });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const json = (await res.json()) as ArtexIoc[];
          if (!cancelled) setIocs(json);
        } catch (e) {
          if (!cancelled) setError(errMessage(e, 'Failed to load IoC dataset'));
        }
      })();
      return () => {
        cancelled = true;
      };
    }
    if (tab === 'exposure' && !exposure && !error) {
      let cancelled = false;
      (async () => {
        try {
          const res = await fetch('/data/artex/exposure.json', { signal: AbortSignal.timeout(20000) });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const json = (await res.json()) as ExposureData;
          if (!cancelled) setExposure(json);
        } catch (e) {
          if (!cancelled) setError(errMessage(e, 'Failed to load exposure dataset'));
        }
      })();
      return () => {
        cancelled = true;
      };
    }
    return undefined;
  }, [tab, iocs, exposure, error]);

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 1500);
  };

  const iocTypeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const ioc of iocs || []) {
      counts.set(ioc.type_label, (counts.get(ioc.type_label) || 0) + 1);
    }
    return [...counts.entries()].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count);
  }, [iocs]);

  const filteredIocs = useMemo(() => {
    const q = iocQuery.trim().toLowerCase();
    return (iocs || []).filter((ioc) => {
      if (iocType !== 'all' && ioc.type_label !== iocType) return false;
      if (!q) return true;
      return (
        ioc.defanged?.toLowerCase().includes(q) ||
        ioc.value?.toLowerCase().includes(q) ||
        (ioc.roles || []).some((r) => r.toLowerCase().includes(q))
      );
    });
  }, [iocs, iocType, iocQuery]);

  const filteredExposure = useMemo(() => {
    const items = exposure?.items || [];
    return activeOnly ? items.filter((it) => it.active) : items;
  }, [exposure, activeOnly]);

  const expCountries = useMemo(() => {
    const counts = new Map<string, number>();
    for (const it of exposure?.items || []) {
      const c = it.country_en || it.country || 'Unknown';
      counts.set(c, (counts.get(c) || 0) + 1);
    }
    return [...counts.entries()].map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count);
  }, [exposure]);

  const IOC_PAGE_SIZE = 50;
  const EXP_PAGE_SIZE = 50;

  const sortedEvents = useMemo(
    () => [...(data?.events || [])].sort((a, b) => (b.disclosed || '').localeCompare(a.disclosed || '')),
    [data]
  );

  return (
    <DataPageLayout
      backTo="/threatintel/ai-security"
      icon={<Radar size={28} />}
      title="ARTEX Intel Tracker"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-300 text-xs font-mono">
            AI-nexus intrusion set
          </span>
          <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted">
            Mirror of artexintel.com
          </span>
          {data?.upstream.last_updated && (
            <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted">
              Upstream updated {data.upstream.last_updated}
            </span>
          )}
        </span>
      }
      maxWidthClass="max-w-7xl"
      error={error}
      loading={!data && !error}
    >
      <AiSummaryCard
        surface="ARTEX AI-Nexus Tracker"
        items={sortedEvents.slice(0, 15).map((ev) => ({
          title: ev.title,
          body: `${ev.disclosed} · ${ev.cat} · ${ev.actor || ev.region || 'unknown actor'} · ${ev.confidence} · ${ev.summary}`,
          source: ev.url || ev.sources?.[0]?.url,
        }))}
        requireAdmin={false}
      />

      {/* Tab bar */}
      <div className="flex flex-wrap gap-1.5 mb-5">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => {
              setTab(t);
              setIocPage(0);
              setExpPage(0);
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono capitalize transition-colors ${
              tab === t
                ? 'bg-sky-500 text-on-fill font-bold'
                : 'bg-surface-100 border border-line-1 text-muted hover:text-heading'
            }`}
          >
            {t === 'iocs' ? 'IoCs' : t}
          </button>
        ))}
      </div>

      {data && tab === 'overview' && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            <StatTile label="ATTACK EVENTS" value={data.stats.attack_events} icon={<Skull size={12} />} />
            <StatTile label="TOOL UPDATES" value={data.stats.tool_updates} icon={<Bot size={12} />} />
            <StatTile label="DAYS TRACKED" value={data.stats.days_tracked ?? '-'} icon={<Activity size={12} />} />
            <StatTile label="IOCS" value={data.stats.iocs ?? '-'} icon={<Tag size={12} />} />
            <StatTile label="EXPOSED INSTANCES" value={data.stats.exposed ?? '-'} icon={<Server size={12} />} />
            <StatTile label="FIRST PUBLIC" value={data.stats.first_public || '-'} icon={<Globe size={12} />} />
          </div>

          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="font-mono text-[11px] tracking-widest text-sky-600 dark:text-sky-400">REPORT TREND</div>
              <div className="flex gap-1">
                {trendWindows.map((w) => (
                  <button
                    key={w}
                    onClick={() => setTrendWindow(w)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      trendKey === w ? 'bg-sky-500/20 text-sky-700 dark:text-sky-300' : 'text-muted hover:text-heading'
                    }`}
                  >
                    {w}
                  </button>
                ))}
              </div>
            </div>
            {data.trend?.[trendKey]?.length ? (
              <TrendBars data={data.trend[trendKey]} />
            ) : (
              <p className="text-xs text-muted">No trend window available.</p>
            )}
          </div>

          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="font-mono text-[11px] tracking-widest text-amber-600 dark:text-amber-400">
                TRENDING KEYWORDS
              </div>
              <div className="flex gap-1">
                {kwWindows.map((w) => (
                  <button
                    key={w}
                    onClick={() => setKwWindow(w)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      kwKey === w
                        ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300'
                        : 'text-muted hover:text-heading'
                    }`}
                  >
                    {w}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(data.keywords?.[kwKey] || []).slice(0, 24).map(([kw, count]) => (
                <span
                  key={kw}
                  className="px-2 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300 text-xs font-mono"
                >
                  {kw} <span className="opacity-60">{count}</span>
                </span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-muted mb-3">EXPOSURE BY COUNTRY (TOP 12)</div>
              <div className="space-y-1.5">
                {data.countries.slice(0, 12).map((c) => {
                  const max = data.countries[0]?.count || 1;
                  return (
                    <div key={c.country} className="flex items-center gap-2">
                      <span className="w-36 text-xs font-mono text-muted truncate">{c.country}</span>
                      <div className="flex-1 h-2.5 rounded bg-surface-300 overflow-hidden">
                        <div
                          className="h-full bg-rose-500/70"
                          style={{ width: `${Math.max(2, (c.count / max) * 100)}%` }}
                        />
                      </div>
                      <span className="w-10 text-right text-xs font-mono text-heading">{c.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-muted mb-3">NOTABLE SAMPLES</div>
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {data.samples.slice(0, 10).map((s) => (
                  <div key={s.hash} className="rounded-lg bg-surface-200 border border-line-1 p-2.5">
                    <button
                      onClick={() => copy(s.hash)}
                      className="font-mono text-[11px] text-heading break-all text-left hover:text-sky-500"
                      title="Copy hash"
                    >
                      {copied === s.hash ? <Check size={10} className="text-emerald-500" /> : null} {s.hash}
                    </button>
                    <div className="text-xs text-muted mt-1">{s.notes}</div>
                    <div className="text-[10px] font-mono text-muted mt-0.5">
                      {s.sources.map((src) => src.publisher).join(', ')}
                      {s.status ? ` - ${s.status}` : ''}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(['domain', 'ip'] as const).map((kind) => (
              <div key={kind} className="rounded-xl bg-surface-100 border border-line-1 p-4">
                <div className="font-mono text-[11px] tracking-widest text-muted mb-3 uppercase">
                  Top {kind === 'domain' ? 'domains' : 'IPs'} (defanged)
                </div>
                <div className="space-y-1">
                  {(data.top_iocs[kind] || []).map((ioc) => (
                    <div key={ioc.value} className="flex items-center gap-2">
                      <code className="flex-1 font-mono text-xs text-heading truncate">{ioc.value}</code>
                      <button
                        onClick={() => copy(ioc.value)}
                        className="p-1 rounded hover:bg-surface-300 dark:hover:bg-surface-200"
                        title="Copy defanged value"
                      >
                        {copied === ioc.value ? (
                          <Check size={12} className="text-emerald-500" />
                        ) : (
                          <Copy size={12} className="text-muted" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-3">SAMPLE TRACES (hunting)</div>
            <div className="flex flex-wrap gap-1.5">
              {data.traces.slice(0, 24).map((t) => (
                <span
                  key={t}
                  className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {data && tab === 'timeline' && (
        <div className="space-y-3">
          {sortedEvents.map((ev) => (
            <div key={ev.slug} className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <span className="text-xs font-mono text-muted">{ev.disclosed}</span>
                <span className="px-2 py-0.5 rounded bg-surface-300 border border-line-1 text-[10px] font-mono uppercase text-muted">
                  {ev.type}
                </span>
                {ev.cat === 'tool' && (
                  <span className="px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-700 dark:text-violet-300 text-[10px] font-mono">
                    tool
                  </span>
                )}
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                    ev.confidence === 'ok'
                      ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-300'
                      : 'bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300'
                  }`}
                  title={`Upstream confidence: ${ev.confidence}`}
                >
                  {confidenceLabel(ev.confidence)}
                </span>
                {ev.region && (
                  <span className="px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/20 text-sky-700 dark:text-sky-300 text-[10px] font-mono">
                    {ev.region}
                  </span>
                )}
                {ev.actor && (
                  <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-300 text-[10px] font-mono">
                    {ev.actor}
                  </span>
                )}
              </div>
              <a
                href={ev.url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-bold text-heading hover:text-sky-500 inline-flex items-center gap-1"
              >
                {ev.title} <ExternalLink size={12} />
              </a>
              {ev.summary && <p className="text-sm text-body mt-1.5 leading-relaxed">{ev.summary}</p>}
              {ev.sources.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {ev.sources.map((s) => (
                    <a
                      key={s.url}
                      href={s.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2 py-0.5 rounded bg-surface-300 border border-line-1 text-[10px] font-mono text-muted hover:text-sky-500"
                    >
                      {s.publisher} <ExternalLink size={9} className="inline" />
                    </a>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === 'iocs' && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2 items-center">
            <input
              value={iocQuery}
              onChange={(e) => {
                setIocQuery(e.target.value);
                setIocPage(0);
              }}
              placeholder="Search defanged values, roles..."
              className="flex-1 min-w-56 px-3 py-2 rounded-lg bg-surface-100 border border-line-1 text-sm font-mono text-heading placeholder:text-muted/60"
            />
            <select
              value={iocType}
              onChange={(e) => {
                setIocType(e.target.value);
                setIocPage(0);
              }}
              className="px-3 py-2 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-heading"
            >
              <option value="all">All types{iocs ? ` (${iocs.length})` : ''}</option>
              {iocTypeCounts.map((t) => (
                <option key={t.label} value={t.label}>
                  {t.label} ({t.count})
                </option>
              ))}
            </select>
          </div>

          {!iocs && !error && <p className="text-sm text-muted font-mono">Loading IoC dataset (1.2 MB)...</p>}
          {iocs && (
            <>
              <div className="text-xs font-mono text-muted">
                {filteredIocs.length} of {iocs.length} indicators
              </div>
              <div className="space-y-2">
                {filteredIocs.slice(iocPage * IOC_PAGE_SIZE, (iocPage + 1) * IOC_PAGE_SIZE).map((ioc, idx) => (
                  <div
                    key={`${ioc.type}-${ioc.value}-${idx}`}
                    className="rounded-lg bg-surface-100 border border-line-1 p-3"
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-surface-300 border border-line-1 text-muted">
                        {ioc.type_label}
                      </span>
                      <span className="text-[10px] font-mono text-muted">
                        {ioc.first_seen}
                        {ioc.last_seen && ioc.last_seen !== ioc.first_seen ? ` - ${ioc.last_seen}` : ''}
                      </span>
                      {ioc.status && <span className="text-[10px] font-mono text-muted">{ioc.status}</span>}
                      <button
                        onClick={() => copy(ioc.defanged)}
                        className="ml-auto p-1 rounded hover:bg-surface-300 dark:hover:bg-surface-200"
                        title="Copy defanged value"
                      >
                        {copied === ioc.defanged ? (
                          <Check size={12} className="text-emerald-500" />
                        ) : (
                          <Copy size={12} className="text-muted" />
                        )}
                      </button>
                    </div>
                    <div className="font-mono text-sm text-heading break-all mt-1.5">{ioc.defanged}</div>
                    {(ioc.roles || []).length > 0 && (
                      <div className="text-xs text-muted mt-1">{ioc.roles.join(' - ')}</div>
                    )}
                    {(ioc.sources || []).length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-1.5">
                        {ioc.sources.map((s) => (
                          <a
                            key={s.url}
                            href={s.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-2 py-0.5 rounded bg-surface-300 border border-line-1 text-[10px] font-mono text-muted hover:text-sky-500"
                          >
                            {s.publisher}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              {filteredIocs.length > IOC_PAGE_SIZE && (
                <div className="flex items-center justify-between">
                  <button
                    onClick={() => setIocPage((p) => Math.max(0, p - 1))}
                    disabled={iocPage === 0}
                    className="px-3 py-1.5 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted disabled:opacity-40"
                  >
                    Prev
                  </button>
                  <span className="text-xs font-mono text-muted">
                    page {iocPage + 1} / {Math.ceil(filteredIocs.length / IOC_PAGE_SIZE)}
                  </span>
                  <button
                    onClick={() => setIocPage((p) => p + 1)}
                    disabled={(iocPage + 1) * IOC_PAGE_SIZE >= filteredIocs.length}
                    className="px-3 py-1.5 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {tab === 'exposure' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <label className="inline-flex items-center gap-2 text-xs font-mono text-muted cursor-pointer">
              <input
                type="checkbox"
                checked={activeOnly}
                onChange={(e) => {
                  setActiveOnly(e.target.checked);
                  setExpPage(0);
                }}
                className="accent-sky-500"
              />
              Active only
            </label>
            {exposure && (
              <span className="text-xs font-mono text-muted">
                {exposure.items.length} snapshots - feed updated {exposure.feed_updated}
              </span>
            )}
          </div>

          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-3">EXPOSED CONSOLES BY COUNTRY</div>
            <div className="flex flex-wrap gap-1.5">
              {expCountries.slice(0, 18).map((c) => (
                <span
                  key={c.country}
                  className="px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-300 text-xs font-mono"
                >
                  {c.country} <span className="opacity-60">{c.count}</span>
                </span>
              ))}
            </div>
          </div>

          {!exposure && !error && <p className="text-sm text-muted font-mono">Loading exposure dataset...</p>}
          {exposure && (
            <>
              <div className="overflow-x-auto rounded-xl border border-line-1">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface-200/70 font-mono text-[10px] uppercase tracking-wider text-muted">
                    <tr>
                      <th className="px-3 py-2">Instance (defanged)</th>
                      <th className="px-3 py-2">Country</th>
                      <th className="px-3 py-2">Carrier</th>
                      <th className="px-3 py-2">Verdict</th>
                      <th className="px-3 py-2">First seen</th>
                      <th className="px-3 py-2">Last seen</th>
                      <th className="px-3 py-2">Status</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono text-muted">
                    {filteredExposure.slice(expPage * EXP_PAGE_SIZE, (expPage + 1) * EXP_PAGE_SIZE).map((it, idx) => (
                      <tr key={`${it.value}-${idx}`} className="border-t border-line-1 hover:bg-surface-100">
                        <td className="px-3 py-2 text-heading whitespace-nowrap">{it.value}</td>
                        <td className="px-3 py-2 whitespace-nowrap">{it.country_en || it.country}</td>
                        <td className="px-3 py-2 whitespace-nowrap">{it.carrier || '-'}</td>
                        <td className="px-3 py-2 whitespace-nowrap">{it.verdict}</td>
                        <td className="px-3 py-2 whitespace-nowrap">{it.first_seen}</td>
                        <td className="px-3 py-2 whitespace-nowrap">{it.last_seen}</td>
                        <td className="px-3 py-2">
                          {it.active ? (
                            <span className="px-1.5 py-0.5 rounded bg-rose-500 text-on-fill text-[10px] font-bold">
                              ACTIVE
                            </span>
                          ) : (
                            <span className="text-[10px] opacity-60">inactive</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {filteredExposure.length > EXP_PAGE_SIZE && (
                <div className="flex items-center justify-between">
                  <button
                    onClick={() => setExpPage((p) => Math.max(0, p - 1))}
                    disabled={expPage === 0}
                    className="px-3 py-1.5 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted disabled:opacity-40"
                  >
                    Prev
                  </button>
                  <span className="text-xs font-mono text-muted">
                    page {expPage + 1} / {Math.ceil(filteredExposure.length / EXP_PAGE_SIZE)}
                  </span>
                  <button
                    onClick={() => setExpPage((p) => p + 1)}
                    disabled={(expPage + 1) * EXP_PAGE_SIZE >= filteredExposure.length}
                    className="px-3 py-1.5 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}

          {data?.upstream.exposure_feed && (
            <p className="text-[11px] font-mono text-muted">
              Exposure snapshot sourced from the upstream feed: {data.upstream.exposure_feed} (updated{' '}
              {data.upstream.exposure_feed_updated}).
            </p>
          )}
        </div>
      )}

      <div className="mt-8 pt-4 border-t border-line-1 text-[11px] font-mono text-muted leading-relaxed">
        <p>
          Data mirrored from{' '}
          <a
            href={data?.upstream.site || 'https://artexintel.com/'}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-sky-500"
          >
            artexintel.com
          </a>{' '}
          (ARTEX Intel threat tracker; AGPL-licensed project). Entries keep their upstream confidence level and sources.
          All malicious addresses are defanged upstream and stay defanged here - do not de-fang or visit them. Synced{' '}
          {data?.generated_at ? new Date(data.generated_at).toISOString().slice(0, 16).replace('T', ' ') : ''} UTC via
          the daily sync workflow.
        </p>
        {data?.sync_problems && data.sync_problems.length > 0 && (
          <p className="mt-1 flex items-start gap-1">
            <ShieldAlert size={12} className="mt-0.5 shrink-0 text-amber-500" />
            <span>
              {data.sync_problems.length} sync step(s) reported problems; remaining data is from earlier steps.
            </span>
          </p>
        )}
      </div>
    </DataPageLayout>
  );
}
