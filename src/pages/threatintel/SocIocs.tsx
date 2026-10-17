import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Radar, Activity, ShieldAlert, Zap, Database, ExternalLink } from 'lucide-react';
import { fetchJson } from '../../lib/fetch-helpers';
import { SocShell, SocKpi, SocSection, SocPanel, type SocStatus } from '../../components/threatintel/soc/SocShell';
import { SocBar, SocDonut, type BarItem, type DonutSlice } from '../../components/threatintel/soc/SocCharts';
import { downloadCsv, dayKey, formatNumber } from '../../components/threatintel/soc/utils';
import { CHART_RANK, CHART_DAILY, CHART_IOC_KIND, CHART_CRIT } from '../../components/threatintel/soc/tone';
import { sourceWeight } from '../../lib/dfir/source-meta';
import { errMessage } from '../../lib/log';

/* ─── Data shape (matches /api/v1/live-iocs) ───────────────────────── */

type IocKind = 'ip' | 'url' | 'domain' | 'hash';

interface LiveIoc {
  value: string;
  kind: IocKind;
  source: string;
  reporter?: string;
  context?: string;
  reference_url?: string;
  observed_at?: string;
}

interface LiveSource {
  id: string;
  ok: boolean;
  count: number;
  newest_observation?: string;
  stale?: boolean;
}

interface LiveIocsResponse {
  generated_at: string;
  sources: LiveSource[];
  total: number;
  items: LiveIoc[];
  degraded?: boolean;
}

/* ─── Severity / criticality heuristic ─────────────────────────────── */

const EMPTY_ITEMS: LiveIoc[] = [];
const EMPTY_SOURCES: LiveSource[] = [];

/**
 * Per-IOC criticality score, 0-100. Higher = more actionable.
 *
 * Source reputation (which upstream flagged it) is the dominant signal -
 * C2/ThreatFox/URLhaus sources carry stronger attribution than bulk
 * blocklists. Kinds matter too: IP/URL are network-side and immediately
 * blockable, hash requires endpoint response, domain is in between.
 *
 * Bucket the score into one of three "criticality" tiers the UI surfaces
 * as a donut slice.
 */
function iocCriticality(ioc: LiveIoc): number {
  let s = 0;
  // Source weight (0-60) - canonical weights live in lib/dfir/source-meta.
  s += sourceWeight(ioc.source);
  // Kind weight (0-25)
  s += { ip: 25, url: 22, domain: 18, hash: 12 }[ioc.kind] ?? 10;
  // Context richness (0-15)
  if (ioc.context) s += 8;
  if (ioc.reporter && ioc.reporter !== '-') s += 4;
  if (ioc.reference_url) s += 3;
  return Math.min(100, s);
}

function criticalityBucket(score: number): 'critical' | 'sensitive' | 'informational' {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'sensitive';
  return 'informational';
}

const CRIT_COLOR: Record<string, string> = CHART_CRIT;
const KIND_COLOR: Record<string, string> = CHART_IOC_KIND;

const KIND_LABEL: Record<IocKind, string> = {
  ip: 'IP',
  url: 'URL',
  domain: 'Domain',
  hash: 'File hash',
};

const KIND_ORDER: IocKind[] = ['ip', 'url', 'domain', 'hash'];

export default function SocIocs(): JSX.Element {
  const [windowDays, setWindowDays] = useState<number>(7);
  const [data, setData] = useState<LiveIocsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [prevTotal, setPrevTotal] = useState<number | null>(null);
  const dataRef = useRef<LiveIocsResponse | null>(null);
  /** Map kind -> active set (null = all). Empty = no filter. */
  const [kindFilter, setKindFilter] = useState<Set<IocKind>>(new Set());

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    try {
      const r = (await fetchJson('/api/v1/live-iocs', { signal, cache: 'no-store' })) as LiveIocsResponse;
      setData(r);
    } catch (e) {
      console.error('SocIocs failed:', errMessage(e));
      if ((e as { name?: string }).name !== 'AbortError') {
        setError(errMessage(e, 'Failed to load.'));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // Capture previous total on each successful load for the delta chip.
  useEffect(() => {
    if (data && dataRef.current && dataRef.current !== data) {
      setPrevTotal(dataRef.current.total);
    }
    dataRef.current = data;
  }, [data]);

  useEffect(() => {
    const ctrl = new AbortController();
    void load(ctrl.signal);
    return () => ctrl.abort();
  }, [load]);

  const items = useMemo(() => data?.items ?? EMPTY_ITEMS, [data]);
  const sources = useMemo(() => data?.sources ?? EMPTY_SOURCES, [data]);

  /* ─── Windowing (time) + kind filter (UI) ────────────────────── */
  // For totals/KPIs, count uses the time window but ignores the kind filter
  // so a user can still see "X total / Y of those IPs".
  const inWindowScoped = useMemo(() => {
    const cutoff = Date.now() - windowDays * 86400_000;
    return items.filter((i) => {
      if (!i.observed_at) return true; // bulk-snapshot sources have no per-entry time
      return Date.parse(i.observed_at) >= cutoff;
    });
  }, [items, windowDays]);

  const inWindow = useMemo(() => {
    if (kindFilter.size === 0) return inWindowScoped;
    return inWindowScoped.filter((i) => kindFilter.has(i.kind));
  }, [inWindowScoped, kindFilter]);

  /* ─── Criticality buckets ─────────────────────────────────────── */
  const buckets = useMemo(() => {
    const out = { critical: 0, sensitive: 0, informational: 0 };
    for (const i of inWindowScoped) {
      out[criticalityBucket(iocCriticality(i))] += 1;
    }
    return out;
  }, [inWindowScoped]);

  /* ─── Status: derived from critical count ─────────────────────── */
  const status = useMemo<SocStatus>(() => {
    if (!data) return { label: 'Loading', severity: 'medium' };
    const c = buckets.critical;
    if (c > 500) return { label: 'Critical volume · investigate', severity: 'critical' };
    if (c > 100) return { label: 'Elevated critical flow', severity: 'high' };
    return { label: 'Active sensors', severity: 'info' };
  }, [data, buckets.critical]);

  const totalInWindow = inWindowScoped.length;
  const kindFilteredTotal = inWindow.length;

  const totalDelta = useMemo(() => {
    if (prevTotal == null || !data) return null;
    const diff = data.total - prevTotal;
    if (diff === 0) return { text: '· stable', direction: 'flat' as const };
    return {
      text: `${diff > 0 ? '+' : ''}${formatNumber(diff)} new`,
      direction: diff > 0 ? ('up' as const) : ('down' as const),
    };
  }, [prevTotal, data]);

  /* ─── Type distribution (donut) ───────────────────────────────── */
  const typeSlices: DonutSlice[] = useMemo(() => {
    const counts = new Map<IocKind, number>();
    for (const i of inWindowScoped) counts.set(i.kind, (counts.get(i.kind) ?? 0) + 1);
    return KIND_ORDER.filter((k) => (counts.get(k) ?? 0) > 0).map((k) => ({
      label: KIND_LABEL[k],
      value: counts.get(k) ?? 0,
      color: KIND_COLOR[k],
    }));
  }, [inWindowScoped]);

  /* ─── Source distribution (horizontal bars) ──────────────────── */
  const sourceBars: BarItem[] = useMemo(() => {
    return sources
      .filter((s) => s.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 12)
      .map((s, i) => ({
        label: s.id,
        value: s.count,
        hint: s.ok ? undefined : 'fetch failed',
        color: s.ok ? CHART_RANK[Math.min(i, CHART_RANK.length - 1)] : '#94a3b8',
      }));
  }, [sources]);

  /* ─── Criticality distribution (donut) ────────────────────────── */
  const critSlices: DonutSlice[] = useMemo(
    () =>
      [
        { label: 'CRITICAL', value: buckets.critical, color: CRIT_COLOR.critical },
        { label: 'SENSITIVE', value: buckets.sensitive, color: CRIT_COLOR.sensitive },
        { label: 'INFORMATIONAL', value: buckets.informational, color: CRIT_COLOR.informational },
      ].filter((s) => s.value > 0),
    [buckets]
  );

  /* ─── Daily observation timeline ──────────────────────────────── */
  const dailyCounts = useMemo(() => {
    const buckets = new Map<string, number>();
    for (const i of inWindowScoped) {
      const k = dayKey(i.observed_at);
      if (!k) continue;
      buckets.set(k, (buckets.get(k) ?? 0) + 1);
    }
    return Array.from(buckets.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([label, value]) => ({ label: label.slice(5), value }));
  }, [inWindowScoped]);

  const activeSources = sources.filter((s) => s.ok).length;

  /* ─── Top critical IOCs (sample) ──────────────────────────────── */
  const topCritical = useMemo(() => {
    return inWindowScoped
      .map((i) => ({ ioc: i, score: iocCriticality(i) }))
      .filter((x) => x.score >= 70)
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);
  }, [inWindowScoped]);

  /* ─── Export ──────────────────────────────────────────────────── */
  const onExport = useCallback(() => {
    if (!data) return;
    const rows: (string | number)[][] = [
      ['value', 'kind', 'source', 'reporter', 'context', 'observed_at', 'criticality'],
    ];
    for (const i of inWindowScoped) {
      rows.push([
        i.value,
        i.kind,
        i.source,
        i.reporter ?? '',
        (i.context ?? '').slice(0, 200),
        i.observed_at ?? '',
        criticalityBucket(iocCriticality(i)),
      ]);
    }
    downloadCsv(`soc-iocs-${windowDays}d-${new Date().toISOString().slice(0, 10)}.csv`, rows);
  }, [data, inWindowScoped, windowDays]);

  const toggleKind = (k: IocKind): void => {
    setKindFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  return (
    <SocShell
      title="Indicators of compromise"
      icon={<Radar size={28} />}
      status={status}
      generatedAt={data?.generated_at ?? null}
      loading={loading}
      error={error}
      onRefresh={() => void load()}
      windowDays={windowDays}
      onWindowChange={setWindowDays}
      onExport={onExport}
      description={
        <span>
          Live aggregation across {sources.length} upstream feeds - blocklists, threat intel, C2 trackers, and sandboxed
          malware samples. Criticality is a 0-100 score combining source reputation, kind, and context richness; filter
          by IOC kind to drill into a specific signal.
        </span>
      }
      meta={
        <span>
          {sources.length === 0 ? 'awaiting first fetch' : `${activeSources}/${sources.length} sources healthy`}
          {data?.degraded ? ' · degraded' : ''}
        </span>
      }
    >
      {/* ─── KPI row ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-6">
        <SocKpi
          label="Total captured IOCs"
          value={data ? formatNumber(data.total) : '-'}
          severity="info"
          sub={`${formatNumber(totalInWindow)} observed in last ${windowDays}d`}
          icon={<Database size={16} />}
          delta={totalDelta?.text}
          deltaDirection={totalDelta?.direction}
        />
        <SocKpi
          label="Critical"
          value={
            <span className="inline-flex items-baseline gap-2">
              {buckets.critical}
              <span className="text-2xl text-muted">
                ({totalInWindow ? Math.round((buckets.critical / totalInWindow) * 1000) / 10 : 0}%)
              </span>
            </span>
          }
          severity="critical"
          sub="score ≥ 70 · block & investigate"
          icon={<ShieldAlert size={16} />}
        />
        <SocKpi
          label="Sensitive"
          value={
            <span className="inline-flex items-baseline gap-2">
              {buckets.sensitive}
              <span className="text-2xl text-muted">
                ({totalInWindow ? Math.round((buckets.sensitive / totalInWindow) * 1000) / 10 : 0}%)
              </span>
            </span>
          }
          severity="medium"
          sub="score 40-69 · enrich & review"
          icon={<Zap size={16} />}
        />
        <SocKpi
          label="Active sources"
          value={`${activeSources}/${sources.length}`}
          severity="ok"
          sub="upstream feeds reporting"
          icon={<Activity size={16} />}
        />
      </div>

      {/* ─── Kind filter chips ────────────────────────────────────── */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-meta font-mono uppercase tracking-wider text-muted mr-1">kind</span>
        {KIND_ORDER.map((k) => {
          const on = kindFilter.has(k);
          return (
            <button
              key={k}
              type="button"
              onClick={() => toggleKind(k)}
              aria-pressed={on}
              className={`text-meta font-mono px-2.5 py-1 rounded border transition-colors ${
                on
                  ? 'border-rose-500 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                  : 'border-line-1 text-muted hover:border-rose-500/40'
              }`}
            >
              {KIND_LABEL[k]}
            </button>
          );
        })}
        {kindFilter.size > 0 && (
          <button
            type="button"
            onClick={() => setKindFilter(new Set())}
            className="text-meta font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 ml-1"
          >
            clear
          </button>
        )}
        {kindFilter.size > 0 && (
          <span className="text-meta font-mono text-muted ml-2">{formatNumber(kindFilteredTotal)} matching</span>
        )}
      </div>

      {/* ─── Charts row 1 ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4 mb-6">
        <SocPanel>
          <SocSection title="Distribution by type" />
          {typeSlices.length > 0 ? (
            <SocDonut slices={typeSlices} size={180} centerLabel={formatNumber(totalInWindow)} centerSub="in window" />
          ) : (
            <p className="text-meta font-mono text-muted italic">No IOCs in window.</p>
          )}
        </SocPanel>

        <SocPanel>
          <SocSection
            title="IOC volume by source"
            right={
              <Link
                to="/threatintel/catalog?cat=feeds"
                className="inline-flex items-center gap-1 text-meta font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                feeds <ExternalLink size={10} />
              </Link>
            }
          />
          <SocBar items={sourceBars} />
        </SocPanel>

        <SocPanel>
          <SocSection title="Criticality distribution" />
          {critSlices.length > 0 ? (
            <SocDonut
              slices={critSlices}
              size={180}
              centerLabel={
                <span>
                  {buckets.critical}
                  <br />
                  <span className="text-meta font-mono text-muted">critical</span>
                </span>
              }
            />
          ) : (
            <p className="text-meta font-mono text-muted italic">No IOCs in window.</p>
          )}
        </SocPanel>
      </div>

      {/* ─── Charts row 2: timeline + top critical ────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4">
        <SocPanel className="lg:col-span-2">
          <SocSection
            title="Observation timeline"
            right={
              dailyCounts.length > 0 ? (
                <span className="text-meta font-mono text-muted">
                  peak {Math.max(...dailyCounts.map((d) => d.value))} / day
                </span>
              ) : null
            }
          />
          <SocBar
            items={dailyCounts.slice(-30)}
            vertical
            height={180}
            defaultColor={CHART_DAILY}
            emptyText="No IOCs with per-entry timestamps in window."
          />
        </SocPanel>

        <SocPanel>
          <SocSection
            title="Top critical"
            right={
              <Link
                to="/threatintel/iocs/live"
                className="inline-flex items-center gap-1 text-meta font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                all <ExternalLink size={10} />
              </Link>
            }
          />
          <TopCriticalList rows={topCritical} />
        </SocPanel>
      </div>
    </SocShell>
  );
}

function TopCriticalList({ rows }: { rows: { ioc: LiveIoc; score: number }[] }): JSX.Element {
  if (rows.length === 0) {
    return <p className="text-meta font-mono text-muted italic">No critical IOCs in window.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {rows.map((r, i) => (
        <li key={`${r.ioc.value}-${i}`} className="text-meta font-mono">
          <div className="flex items-baseline gap-2 mb-0.5">
            <span className="text-rose-600 dark:text-rose-400 tabular-nums shrink-0">{r.score}</span>
            <span className="text-body truncate" title={r.ioc.value}>
              {r.ioc.value}
            </span>
            <span className="ml-auto text-muted text-mini uppercase tracking-wider shrink-0">{r.ioc.kind}</span>
          </div>
          <div className="text-mini text-muted truncate" title={r.ioc.context ?? ''}>
            {r.ioc.source}
            {r.ioc.context ? ` · ${r.ioc.context.slice(0, 60)}` : ''}
          </div>
        </li>
      ))}
    </ul>
  );
}
