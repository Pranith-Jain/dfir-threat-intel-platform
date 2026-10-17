import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AttackHeatmap } from '../../components/threatintel/AttackHeatmap';
import { BackLink } from '../../components/BackLink';
import { fetchJson } from '../../lib/fetch-helpers';
import { dedupRansomwareVictims } from '../../lib/dedup-ransomware';
import {
  Activity,
  BarChart3,
  Briefcase,
  Bug,
  Database,
  Flame,
  Globe2,
  Loader2,
  MessageSquare,
  Network,
  Radio,
  RefreshCw,
  Shield,
  Skull,
  TrendingUp,
  Users,
} from 'lucide-react';
import type {
  RansomwareVictim,
  RecentCve,
  PhishingUrl,
  ThreatMapResponse,
  MalwareSample,
  ReleakRow,
  C2Response,
  BreachDisclosure,
  PulseEntity,
  DeepDarkCtiResponse,
} from './metrics-types';
import { withinDays, dayKey, SEVERITY_COLORS } from './metrics-types';

/**
 * Threat Intel Metrics - quantitative read of what's flowing through the
 * platform RIGHT NOW. Everything is computed client-side from the same
 * four endpoints the other /threatintel pages use, so there's no new
 * worker code and no risk of stale aggregates: refresh → fresh chart.
 *
 * Fifteen panels answer the questions a CTI team actually asks:
 *   1. Who's most active in ransomware right now?              (HBar)
 *   2. What's the pace of ransomware claims this month?         (Area)
 *   3. How is CVE severity distributed in the current window?   (Stacked HBar)
 *   4. How often is CISA adding to KEV?                         (Sparkbars)
 *   5. Which brands are most-impersonated in active phishing?   (HBar)
 *   6. Which upstream feeds contribute the most IOCs right now? (HBar)
 *   7. Which sectors are ransomware groups targeting?           (HBar, heuristic)
 *   8. Which vendors are most-exploited on the KEV catalogue?   (HBar)
 *   9. Which malware families are spreading right now?          (HBar)
 *   10. Re-leak hotspots - groups doing the most cross-claims    (HBar)
 *   11. Where do malicious IPs originate?                        (HBar)
 *   12. Which C2 frameworks have the most live infra?            (HBar)
 *   13. Which fresh breach disclosures are largest?              (HBar)
 *   14. What are researchers cross-referencing right now?        (HBar)
 *   15. Where is dark-web CTI coverage concentrated?             (HBar)
 *
 * Headline counters carry a ▲/▼ delta vs the previous in-session refresh.
 *
 * Charts are hand-rolled SVG - no Recharts/D3 dependency. Each is small,
 * presentational, and accessible (title/aria on rects + percentage labels).
 */

/* ─── SVG chart primitives ──────────────────────────────────────────── */

interface HBarItem {
  label: string;
  value: number;
  /** Optional secondary text shown after value (e.g. "(KEV)"). */
  hint?: string;
}

function HBar({
  items,
  max,
  color,
  formatValue,
}: {
  items: HBarItem[];
  max?: number;
  color: string;
  formatValue?: (n: number) => string;
}) {
  if (items.length === 0) {
    return <p className="text-xs text-muted italic">No data in window.</p>;
  }
  const ceiling = max ?? Math.max(...items.map((i) => i.value), 1);
  const fmt = formatValue ?? ((n: number) => n.toLocaleString());
  return (
    <ul className="space-y-1.5">
      {items.map((it, idx) => {
        const pct = (it.value / ceiling) * 100;
        return (
          <li key={`${it.label}-${idx}`} className="text-mini font-mono">
            <div className="flex items-baseline justify-between mb-0.5">
              <span className="text-body truncate" title={String(it.label)}>
                {String(it.label)}
              </span>
              <span className="text-muted tabular-nums shrink-0">
                {fmt(it.value)}
                {it.hint && <span className="text-muted ml-1">{String(it.hint)}</span>}
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-surface-300 overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{ width: `${Math.max(2, pct)}%`, backgroundColor: color }}
                aria-label={`${it.label}: ${fmt(it.value)}`}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function StackedSeverityBar({ counts, total }: { counts: Record<RecentCve['severity'], number>; total: number }) {
  const order: RecentCve['severity'][] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'];
  const segments = order.map((sev) => ({ sev, n: counts[sev] ?? 0 })).filter((s) => s.n > 0);
  if (total === 0) {
    return <p className="text-xs text-muted italic">No CVEs in window.</p>;
  }
  return (
    <div>
      <div className="h-3 rounded overflow-hidden flex">
        {segments.map(({ sev, n }) => {
          const pct = (n / total) * 100;
          return (
            <div
              key={sev}
              style={{ width: `${pct}%`, backgroundColor: SEVERITY_COLORS[sev] }}
              title={`${sev}: ${n} (${pct.toFixed(0)}%)`}
            />
          );
        })}
      </div>
      <ul className="grid grid-cols-2 sm:grid-cols-3 gap-x-3 gap-y-1 mt-3 text-mini font-mono">
        {order.map((sev) => {
          const n = counts[sev] ?? 0;
          if (n === 0) return null;
          const pct = (n / total) * 100;
          return (
            <li key={sev} className="flex items-baseline gap-1.5">
              <span
                className="inline-block w-2 h-2 rounded shrink-0"
                style={{ backgroundColor: SEVERITY_COLORS[sev] }}
              />
              <span className="text-body">{sev}</span>
              <span className="ml-auto text-muted tabular-nums">
                {n} <span className="text-muted">({pct.toFixed(0)}%)</span>
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function Sparkbars({ buckets, color }: { buckets: { label: string; value: number }[]; color: string }) {
  if (buckets.length === 0) {
    return <p className="text-xs text-muted italic">No data.</p>;
  }
  const ceiling = Math.max(...buckets.map((b) => b.value), 1);
  const w = 360;
  const h = 80;
  const barW = w / buckets.length - 2;
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${w} ${h + 24}`} className="w-full">
        {buckets.map((b, i) => {
          const x = (i * w) / buckets.length;
          const barH = (b.value / ceiling) * h;
          return (
            <g key={`${b.label}-${i}`}>
              <rect
                x={x + 1}
                y={h - barH}
                width={barW}
                height={Math.max(1, barH)}
                fill={color}
                rx={1}
                aria-label={`${b.label}: ${b.value}`}
              >
                <title>
                  {String(b.label)}: {b.value}
                </title>
              </rect>
              {b.value > 0 && barH > 12 && (
                <text
                  x={x + 1 + barW / 2}
                  y={h - barH + 10}
                  textAnchor="middle"
                  fontSize="9"
                  fill="#fff"
                  fontFamily="ui-monospace,monospace"
                >
                  {b.value}
                </text>
              )}
              <text
                x={x + 1 + barW / 2}
                y={h + 14}
                textAnchor="middle"
                fontSize="9"
                fontFamily="ui-monospace,monospace"
                fill="currentColor"
                className="text-muted"
              >
                {String(b.label)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ─── Page ──────────────────────────────────────────────────────────── */

interface State {
  ransomware: RansomwareVictim[] | null;
  cves: RecentCve[] | null;
  phishing: PhishingUrl[] | null;
  threatMap: ThreatMapResponse | null;
  malware: MalwareSample[] | null;
  releaks: ReleakRow[] | null;
  c2: C2Response | null;
  breaches: BreachDisclosure[] | null;
  pulse: PulseEntity[] | null;
  ddc: DeepDarkCtiResponse | null;
  /** MyThreatIntel threat-group catalogue (group_id + profile). */
  mtiGroups: { group_id: string; description?: string }[] | null;
  refreshedAt: string | null;
  loading: boolean;
  error: string | null;
}

const INITIAL: State = {
  ransomware: null,
  cves: null,
  phishing: null,
  threatMap: null,
  malware: null,
  releaks: null,
  c2: null,
  breaches: null,
  pulse: null,
  ddc: null,
  mtiGroups: null,
  refreshedAt: null,
  loading: true,
  error: null,
};

/** Normalise a free-text severity (MyThreatIntel uses Title Case / N/D). */
function normSeverity(s: unknown): RecentCve['severity'] {
  const u = String(s ?? '')
    .trim()
    .toUpperCase();
  return u === 'CRITICAL' || u === 'HIGH' || u === 'MEDIUM' || u === 'LOW' || u === 'NONE'
    ? (u as RecentCve['severity'])
    : 'UNKNOWN';
}

interface MtiCveRow {
  cve?: string;
  published?: string;
  severity?: string;
  score?: string;
  description?: string;
}

// Window options (in days) for the panel-wide time-range toggle. KEV cadence
// has its own fixed 12-week scale and intentionally ignores this control.
const WINDOW_OPTIONS = [7, 30, 90] as const;
type WindowDays = (typeof WINDOW_OPTIONS)[number];

export default function Metrics(): JSX.Element {
  const [state, setState] = useState<State>(INITIAL);
  const [refreshKey, setRefreshKey] = useState(0);
  // Defaults to 7d so the page lands on a window that the backend pool
  // can actually fill (was 30d, but with the 60-record cap that meant
  // most days past day-2 showed as zero). Backend was raised to 500
  // records (≈14-16 days of typical leak-site activity) and the 30/90
  // toggles remain for deeper historical reads.
  const [windowDays, setWindowDays] = useState<WindowDays>(7);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    // 'no-store': this is a live metrics dashboard - always pull fresh from the
    // edge rather than risk the browser serving a stale HTTP-cached copy (a
    // past "0 ransomware claims" pinned-cache bug). The edge cache still makes
    // these cheap server-side.
    const opts = { signal: ctrl.signal, cache: 'no-store' } as const;
    setState((s) => ({ ...s, loading: true, error: null }));

    // Ransomware-recent is the heaviest feed - a multi-tracker fan-out with a
    // 15-min edge TTL. On a cache-miss the synchronous fan-out can transiently
    // return an empty 200 (cold colo, thin upstreams, no last-good yet) or time
    // out, which blanked ALL SIX ransomware panels to "No data". Retry once on
    // empty/failure so one transient doesn't zero the page; the retry often hits
    // a now-warm cache or a recovered upstream.
    const fetchRansomwareResilient = async (): Promise<{ victims: RansomwareVictim[] } | null> => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          const r = (await fetchJson(`/api/v1/ransomware-recent?days=${windowDays}`, opts)) as {
            victims?: RansomwareVictim[];
          };
          if (r.victims && r.victims.length > 0) return { victims: r.victims };
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* fall through to retry */
        }
        if (cancelled || attempt === 1) break;
        await new Promise((res) => setTimeout(res, 1500));
      }
      return null;
    };

    (async () => {
      try {
        const [rRes, cRes, pRes, tmRes, mRes, rlRes, c2Res, brRes, plRes, ddcRes, mtiCveRes, mtiGrpRes] =
          await Promise.allSettled([
            fetchRansomwareResilient(),
            fetchJson('/api/v1/cve-recent', opts),
            fetchJson('/api/v1/phishing-urls', opts),
            fetchJson('/api/v1/threat-map', opts),
            fetchJson('/api/v1/malware-samples', opts),
            fetchJson('/api/v1/victim-releaks', opts),
            fetchJson('/api/v1/c2-tracker', opts),
            fetchJson('/api/v1/breach-disclosures', opts),
            fetchJson('/api/v1/threat-pulse', opts),
            fetchJson('/api/v1/deepdarkcti', opts),
            fetchJson('/api/v1/mti?source=cve&limit=200', opts),
            fetchJson('/api/v1/mti?source=groups&limit=300', opts),
          ]);
        if (cancelled) return;

        // MyThreatIntel CVEs merged into the CVE pool (existing entries win
        // ties - they carry the KEV flag); enriches every CVE panel.
        const baseCves = cRes.status === 'fulfilled' ? ((cRes.value as { cves: RecentCve[] }).cves ?? []) : null;
        const mtiCveItems =
          mtiCveRes.status === 'fulfilled' ? ((mtiCveRes.value as { items?: MtiCveRow[] }).items ?? []) : [];
        const mergedCves: RecentCve[] | null = baseCves
          ? (() => {
              const seen = new Set(baseCves.map((c) => c.id.toUpperCase()));
              const extra: RecentCve[] = [];
              for (const m of mtiCveItems) {
                const id = m.cve?.trim().toUpperCase();
                if (!id || seen.has(id)) continue;
                seen.add(id);
                const score = m.score != null && m.score !== '' ? Number.parseFloat(m.score) : NaN;
                extra.push({
                  id,
                  published: m.published ?? '',
                  modified: m.published ?? '',
                  description: m.description,
                  severity: normSeverity(m.severity),
                  score: Number.isFinite(score) ? score : null,
                  kev: false,
                });
              }
              return [...baseCves, ...extra];
            })()
          : baseCves;
        const mtiGroups =
          mtiGrpRes.status === 'fulfilled'
            ? ((mtiGrpRes.value as { items?: { group_id?: string; description?: string }[] }).items ?? [])
                .filter((g): g is { group_id: string; description?: string } => Boolean(g.group_id))
                .map((g) => ({ group_id: g.group_id, description: g.description }))
            : null;
        setState({
          ransomware:
            rRes.status === 'fulfilled'
              ? ((rRes.value as { victims: RansomwareVictim[] } | null)?.victims ?? null)
              : null,
          cves: mergedCves,
          phishing: pRes.status === 'fulfilled' ? ((pRes.value as { urls: PhishingUrl[] }).urls ?? []) : null,
          threatMap: tmRes.status === 'fulfilled' ? (tmRes.value as ThreatMapResponse) : null,
          malware: mRes.status === 'fulfilled' ? ((mRes.value as { samples: MalwareSample[] }).samples ?? []) : null,
          releaks: rlRes.status === 'fulfilled' ? ((rlRes.value as { releaks: ReleakRow[] }).releaks ?? []) : null,
          c2: c2Res.status === 'fulfilled' ? (c2Res.value as C2Response) : null,
          breaches:
            brRes.status === 'fulfilled' ? ((brRes.value as { breaches: BreachDisclosure[] }).breaches ?? []) : null,
          pulse: plRes.status === 'fulfilled' ? ((plRes.value as { entities: PulseEntity[] }).entities ?? []) : null,
          ddc: ddcRes.status === 'fulfilled' ? (ddcRes.value as DeepDarkCtiResponse) : null,
          mtiGroups,
          refreshedAt: new Date().toISOString(),
          loading: false,
          error: null,
        });
      } catch (e) {
        logCatch(e);
        if (cancelled) return;
        const msg = errMessage(e);
        setState((s) => ({ ...s, loading: false, error: msg }));
      }
    })();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey, windowDays]);

  /* ─── Derived metrics ─── */

  /**
   * Set of UTC calendar-day keys covering the user-selected window. Every
   * ransomware-derived panel filters against this, so each panel's
   * row counts can sum to the StatBar headline count and to the
   * ransomware cadence chart bar sum. Was a rolling 168-hour
   * `withinDays(v.discovered, windowDays)` per-call check which counted
   * a partial day at the trailing edge - caused the "239 vs 231" surface
   * inconsistency users hit. windowDays still drives N: 7d = 7 UTC dates,
   * 30d = 30 UTC dates, 90d = 90 UTC dates.
   */
  const ransomwareWindowDayKeys = useMemo<Set<string>>(() => {
    const days = new Set<string>();
    const now = new Date();
    for (let i = 0; i < windowDays; i += 1) {
      days.add(new Date(now.getTime() - i * 86400_000).toISOString().slice(0, 10));
    }
    return days;
  }, [windowDays]);

  const inRansomwareWindow = (iso: string): boolean => {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return false;
    return ransomwareWindowDayKeys.has(new Date(t).toISOString().slice(0, 10));
  };

  /**
   * De-duplicate the ransomware feed before any panel aggregates it.
   *
   * The merged feed from /api/v1/ransomware-recent collapses same-day
   * (group, victim) duplicates at the worker, but the same victim can
   * still appear on multiple days when different upstream trackers
   * index it on different dates (Ransomlook vs cti.fyi vs ransomfeed
   * often disagree by 1-3 days). For metrics - "top groups", cadence,
   * headline read, sectors - we want each unique victim to count ONCE
   * per group, with the *earliest* discovery date winning. This was
   * the source of the "thegentlemen = 200+" surface where the real
   * distinct-victim count for the window was 51.
   */
  const dedupedRansomware = useMemo<RansomwareVictim[]>(
    () => dedupRansomwareVictims(state.ransomware ?? []) as RansomwareVictim[],
    [state.ransomware]
  );

  const topRansomwareGroups = useMemo<HBarItem[]>(() => {
    if (!dedupedRansomware.length) return [];
    const map = new Map<string, number>();
    for (const v of dedupedRansomware) {
      if (!inRansomwareWindow(v.discovered)) continue;
      map.set(v.group, (map.get(v.group) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dedupedRansomware, ransomwareWindowDayKeys]);

  // MyThreatIntel: which currently-active ransomware groups carry a
  // MyThreatIntel actor profile, ranked by their recent victim volume.
  // Joins the merged ransomware feed (already MTI-enriched) with the MTI
  // group catalogue so the bar = "active AND profiled".
  const mtiProfiledActiveGroups = useMemo<HBarItem[]>(() => {
    if (!dedupedRansomware.length || !state.mtiGroups || state.mtiGroups.length === 0) return [];
    const profiled = new Set(state.mtiGroups.map((g) => g.group_id.toLowerCase()));
    const map = new Map<string, number>();
    for (const v of dedupedRansomware) {
      if (!inRansomwareWindow(v.discovered)) continue;
      if (!profiled.has(v.group.toLowerCase())) continue;
      map.set(v.group, (map.get(v.group) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 12);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dedupedRansomware, state.mtiGroups, ransomwareWindowDayKeys]);

  // 11. NEW - country-origin of malicious IPs. data.threatMap.countries was
  // already being fetched but never visualised. Plain HBar; not gated by
  // windowDays because threat-map is a live snapshot, not historical.
  const topCountries = useMemo<HBarItem[]>(() => {
    if (!state.threatMap?.countries?.length) return [];
    return state.threatMap.countries
      .map((c) => ({ label: `${c.countryCode} · ${c.country}`, value: c.count }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.threatMap]);

  const ransomwareCadence = useMemo(() => {
    if (!dedupedRansomware.length) return [] as { label: string; value: number }[];
    const map = new Map<string, number>();
    const now = new Date();
    // Build 7 day buckets so empty days show as 0. Was 30 days; the page
    // now leads with a 7-day window and the headline read consumes the
    // same series, so the cadence chart matches.
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400_000);
      const key = d.toISOString().slice(0, 10);
      map.set(key, 0);
    }
    for (const v of dedupedRansomware) {
      const key = dayKey(v.discovered);
      if (map.has(key)) map.set(key, (map.get(key) ?? 0) + 1);
    }
    // Per-day axis labels - at 7 bars the labels fit without sparseness.
    return [...map.entries()].map(([k, v]) => ({
      label: k.slice(5),
      value: v,
    }));
  }, [dedupedRansomware]);

  /**
   * Headline read: an opinionated, automatically-computed interpretation
   * of the ransomware market posture right now. Replaces the temptation to
   * paste a static prose summary that goes stale the moment data refreshes.
   *
   * The values it computes are deliberately conservative: a 7-vs-7 day
   * trend with a 10% deadband to avoid calling noise as motion, a single
   * top-actor + share metric for concentration, and the count of distinct
   * groups active this week. The prose template wraps those numbers in
   * three sentences that always grammatically fit, regardless of which
   * values land.
   */
  const headlineRead = useMemo(() => {
    if (!dedupedRansomware.length) return null;
    const now = new Date();
    const day = 86400_000;

    // Calendar-day bucketing matching the ransomwareCadence sparkbar
    // computation above AND the hero sparkline on the portfolio root.
    // Was a rolling 168-hour window (`now - 7 * day`), which counted
    // a few extra claims at the trailing edge of the window that the
    // chart's calendar-day buckets excluded - visible to users as
    // "headline says 239 but the bars sum to 231". Now headline +
    // chart + hero all share the same 7-UTC-calendar-day definition
    // of "last 7 days", so the numbers line up across surfaces.
    const last7Days = new Set<string>();
    const prior7Days = new Set<string>();
    for (let i = 0; i < 7; i += 1) {
      last7Days.add(new Date(now.getTime() - i * day).toISOString().slice(0, 10));
    }
    for (let i = 7; i < 14; i += 1) {
      prior7Days.add(new Date(now.getTime() - i * day).toISOString().slice(0, 10));
    }

    let last7 = 0;
    let prior7 = 0;
    const last7Groups = new Set<string>();
    const last7GroupCounts = new Map<string, number>();
    for (const v of dedupedRansomware) {
      // dayKey via Date.parse round-trip so non-ISO timestamps from MTI
      // (which can arrive as "YYYY-MM-DD HH:MM:SS.fff") normalise to the
      // same UTC-date string the bucket sets above use.
      const t = Date.parse(v.discovered);
      if (Number.isNaN(t)) continue;
      const key = new Date(t).toISOString().slice(0, 10);
      if (last7Days.has(key)) {
        last7 += 1;
        last7Groups.add(v.group);
        last7GroupCounts.set(v.group, (last7GroupCounts.get(v.group) ?? 0) + 1);
      } else if (prior7Days.has(key)) {
        prior7 += 1;
      }
    }

    // Concentration is the top operator's share of the last 7 days (was
    // 30 days; the page now leads with a weekly read, so the denominator
    // matches the visible window).
    const ranked = [...last7GroupCounts.entries()].sort((a, b) => b[1] - a[1]);
    const top = ranked[0];
    const topShare = top && last7 > 0 ? (top[1] / last7) * 100 : 0;

    let trendLabel: 'accelerating' | 'cooling' | 'steady' = 'steady';
    let trendDelta = 0;
    if (prior7 > 0) {
      const change = ((last7 - prior7) / prior7) * 100;
      trendDelta = Math.round(change);
      if (change > 10) trendLabel = 'accelerating';
      else if (change < -10) trendLabel = 'cooling';
    } else if (last7 > 0) {
      trendLabel = 'accelerating';
      trendDelta = 100;
    }

    // Three sentences, each a separate piece of analysis. Concatenated
    // in the render so each can be styled or moved independently.
    const sentenceTrend =
      trendLabel === 'accelerating'
        ? `Ransomware leak-site posting is accelerating: ${last7} new claims in the last 7 days, up ${trendDelta}% from the prior 7 days (${prior7}).`
        : trendLabel === 'cooling'
          ? `Ransomware leak-site posting is cooling: ${last7} claims in the last 7 days, down ${Math.abs(trendDelta)}% from the prior 7 days (${prior7}).`
          : `Ransomware leak-site posting is steady: ${last7} claims in the last 7 days, within 10% of the prior 7 days (${prior7}).`;

    const sentenceConcentration = top
      ? `One operator, ${top[0]}, accounts for ${topShare.toFixed(0)}% of those ${last7} weekly claims; the rest split across ${ranked.length - 1} other groups.`
      : '';

    const sentenceReadout =
      topShare > 25
        ? `That level of concentration is unusual. When one group runs more than a quarter of all public claims, either an affiliate program is winning the moment or a single high-volume operator is in a "spray" phase. Either is worth a closer look at /threatintel/ransomware-activity.`
        : topShare > 15
          ? `That's near-typical concentration for a healthy multi-operator market: a leader carrying about a fifth, the long tail behind it. Worth watching the next 7-day window for whether the leader holds, gains, or gets displaced.`
          : `That's an unusually flat distribution. No one operator is dominating the moment, which historically precedes either consolidation or a quiet stretch. Either way, single-group fixation is the wrong lens for this week.`;

    return {
      last7,
      prior7,
      trendLabel,
      trendDelta,
      topGroup: top?.[0] ?? null,
      topShare,
      distinctGroupsLast7: last7Groups.size,
      sentences: [sentenceTrend, sentenceConcentration, sentenceReadout].filter(Boolean),
    };
  }, [dedupedRansomware]);

  const cveSeverityCounts = useMemo(() => {
    const counts: Record<RecentCve['severity'], number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      NONE: 0,
      UNKNOWN: 0,
    };
    if (!state.cves) return { counts, total: 0 };
    for (const c of state.cves) counts[c.severity] = (counts[c.severity] ?? 0) + 1;
    return { counts, total: state.cves.length };
  }, [state.cves]);

  const kevCadence = useMemo(() => {
    if (!state.cves) return [] as { label: string; value: number }[];
    // Last 12 weeks of KEV adds, by ISO week. Key MUST include the year:
    // late-December and early-January can both fall in ISO week 1 of
    // their respective years and a bare `W${week}` key collapses them
    // into one column. Use `YYYY-W##` for the map key but render the
    // short `W##` form in the chart label.
    const yearWeek = (d: Date) => `${d.getUTCFullYear()}-W${weekOfYear(d)}`;
    const labelOf = (d: Date) => `W${weekOfYear(d)}`;
    const map = new Map<string, { label: string; value: number }>();
    const now = new Date();
    for (let i = 11; i >= 0; i--) {
      const start = new Date(now.getTime() - i * 7 * 86400_000);
      map.set(yearWeek(start), { label: labelOf(start), value: 0 });
    }
    for (const c of state.cves) {
      if (!c.kev || !c.kev_added) continue;
      if (!withinDays(c.kev_added, 12 * 7)) continue;
      const d = new Date(c.kev_added);
      const k = yearWeek(d);
      const existing = map.get(k);
      if (existing) existing.value += 1;
    }
    return [...map.values()];
  }, [state.cves]);

  const topPhishingBrands = useMemo<HBarItem[]>(() => {
    if (!state.phishing) return [];
    const map = new Map<string, number>();
    for (const u of state.phishing) {
      const t = u.target?.trim();
      if (!t || t === 'Other' || t.toLowerCase() === 'unknown') continue;
      map.set(t, (map.get(t) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.phishing]);

  const iocSourceVolume = useMemo<HBarItem[]>(() => {
    if (!state.threatMap) return [];
    return Object.entries(state.threatMap.source_counts)
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }, [state.threatMap]);

  const targetedSectors = useMemo<HBarItem[]>(() => {
    if (!dedupedRansomware.length) return [];
    const map = new Map<string, number>();
    for (const v of dedupedRansomware) {
      if (!inRansomwareWindow(v.discovered)) continue;
      const s = v.sector || 'Unknown';
      if (s === 'Unknown') continue;
      map.set(s, (map.get(s) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dedupedRansomware, ransomwareWindowDayKeys]);

  const sectorClassifiedPct = useMemo(() => {
    if (!dedupedRansomware.length) return 0;
    const within = dedupedRansomware.filter((v) => inRansomwareWindow(v.discovered));
    if (!within.length) return 0;
    const known = within.filter((v) => v.sector && v.sector !== 'Unknown').length;
    return Math.round((known / within.length) * 100);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dedupedRansomware, ransomwareWindowDayKeys]);

  /** Top vendors on the KEV catalogue. Parsed from "[KEV] Vendor Product:" prefix in description. */
  const topKevVendors = useMemo<HBarItem[]>(() => {
    if (!state.cves) return [];
    const map = new Map<string, number>();
    for (const c of state.cves) {
      if (!c.kev) continue;
      const m = /^\[KEV\]\s+([^:]+):/.exec(c.description ?? '');
      if (!m) continue;
      // First token of "Vendor Product Subproduct" is usually the vendor.
      const vendor = m[1]!.split(/[\s/]+/)[0]!.trim();
      if (!vendor) continue;
      map.set(vendor, (map.get(vendor) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.cves]);

  /** Top malware families seen in the last 24h (MalwareBazaar signature field). */
  const topMalwareFamilies = useMemo<HBarItem[]>(() => {
    if (!state.malware) return [];
    const map = new Map<string, number>();
    for (const s of state.malware) {
      const family = (s.signature ?? '').trim();
      if (!family || family.toLowerCase() === 'n/a' || family.toLowerCase() === 'unknown') continue;
      map.set(family, (map.get(family) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.malware]);

  /** Groups making the most cross-claims (re-leak hotspots). */
  const releakGroups = useMemo<HBarItem[]>(() => {
    if (!state.releaks) return [];
    const map = new Map<string, number>();
    for (const r of state.releaks) {
      for (const c of r.claims) map.set(c.group, (map.get(c.group) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.releaks]);

  /** Top active C2 frameworks (Cobalt Strike, Sliver, …) across upstream feeds. */
  const topC2Frameworks = useMemo<HBarItem[]>(() => {
    if (!state.c2?.frameworks) return [];
    return Object.entries(state.c2.frameworks)
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.c2]);

  /* ─── Per-panel interpretations ──────────────────────────────────────
   *
   * Each of the six narrative panels gets a single computed sentence
   * underneath the chart that turns the values into a "what this means
   * right now" read. The text adapts on refresh as the underlying numbers
   * shift. Memoised so React doesn't recompute on unrelated state
   * changes. Returns '' to render no caption when the data is missing
   * or unilluminating (avoids the "(0 of 0)" trap).
   */

  const ransomwareGroupsRead = useMemo((): string => {
    if (topRansomwareGroups.length < 2) return '';
    const total = topRansomwareGroups.reduce((s, i) => s + i.value, 0);
    if (total === 0) return '';
    const lead = topRansomwareGroups[0]!;
    const second = topRansomwareGroups[1]!;
    const share = (lead.value / total) * 100;
    const gap = lead.value - second.value;
    const concentration =
      share > 25 ? 'high concentration' : share > 12 ? 'typical multi-operator spread' : 'unusually flat distribution';
    const leadShape = gap > second.value * 0.5 ? 'pulling away from' : 'roughly even with';
    return `${lead.label} runs ${share.toFixed(0)}% of tracked claims, ${leadShape} ${second.label}. That's ${concentration}.`;
  }, [topRansomwareGroups]);

  const ransomwareCadenceRead = useMemo((): string => {
    if (ransomwareCadence.length === 0) return '';
    const total = ransomwareCadence.reduce((s, b) => s + b.value, 0);
    if (total === 0) return 'No leak-site posts in the window. Either a quiet week or a feed outage.';
    const peak = Math.max(...ransomwareCadence.map((b) => b.value));
    const peakDayIdx = ransomwareCadence.findIndex((b) => b.value === peak);
    const peakDayLabel = ransomwareCadence[peakDayIdx]?.label || 'mid-window';
    const avg = total / ransomwareCadence.length;
    const peakRatio = peak / Math.max(avg, 1);
    const shape =
      peakRatio > 2.5
        ? 'one outsized day carrying the window'
        : peakRatio > 1.5
          ? 'a busier-than-average peak'
          : 'a roughly steady cadence';
    return `${total} total claims across the window, peak day ${peakDayLabel} at ${peak}. That reads as ${shape}.`;
  }, [ransomwareCadence]);

  const cveSeverityRead = useMemo((): string => {
    const t = cveSeverityCounts.total;
    if (t === 0) return '';
    const c = cveSeverityCounts.counts;
    const critHigh = (c.CRITICAL ?? 0) + (c.HIGH ?? 0);
    const critHighPct = (critHigh / t) * 100;
    const profile =
      critHighPct > 55 ? 'a top-heavy window' : critHighPct > 35 ? 'a typical mix' : 'a moderate-only window';
    return `${critHigh.toLocaleString()} of ${t.toLocaleString()} CVEs (${critHighPct.toFixed(0)}%) are CRITICAL or HIGH. ${profile} - prioritise the top ${critHigh > 0 ? critHigh : 0} for patch triage first.`;
  }, [cveSeverityCounts]);

  const kevCadenceRead = useMemo((): string => {
    if (kevCadence.length === 0) return '';
    const total = kevCadence.reduce((s, b) => s + b.value, 0);
    if (total === 0) return 'No KEV additions in the 12-week window. Unusual; verify the CISA feed is healthy.';
    const recentFour = kevCadence.slice(-4).reduce((s, b) => s + b.value, 0);
    const priorEight = kevCadence.slice(0, -4).reduce((s, b) => s + b.value, 0);
    const priorPerFour = priorEight / 2;
    const accel = priorPerFour > 0 ? ((recentFour - priorPerFour) / priorPerFour) * 100 : recentFour > 0 ? 100 : 0;
    const direction = accel > 20 ? 'up' : accel < -20 ? 'down' : 'steady';
    return `${total} new KEVs in 12 weeks, ${recentFour} in the most recent 4. Pace is ${direction}${
      direction !== 'steady' ? ` (${Math.abs(Math.round(accel))}% vs the prior 8-week average)` : ''
    }.`;
  }, [kevCadence]);

  const kevVendorsRead = useMemo((): string => {
    if (topKevVendors.length < 2) return '';
    const lead = topKevVendors[0]!;
    const others = topKevVendors.slice(1, 4);
    const otherLabels = others.map((o) => `${o.label} (${o.value})`).join(', ');
    return `${lead.label} carries ${lead.value} active-exploitation entries on KEV in the current window, ahead of ${otherLabels}. If any of these vendors are on your asset list, their KEV pages are the right next click.`;
  }, [topKevVendors]);

  const c2FrameworksRead = useMemo((): string => {
    if (topC2Frameworks.length === 0) return '';
    const total = topC2Frameworks.reduce((s, i) => s + i.value, 0);
    if (total === 0) return '';
    const lead = topC2Frameworks[0]!;
    const share = (lead.value / total) * 100;
    const second = topC2Frameworks[1];
    const tail = total - lead.value - (second?.value ?? 0);
    if (share > 80) {
      return `${lead.label} dominates at ${share.toFixed(0)}% of all dedicated-tracker hits${
        second ? `, with ${second.label} at ${((second.value / total) * 100).toFixed(0)}%` : ''
      }. Detection coverage on ${lead.label} is the only first-priority C2 investment by these numbers.`;
    }
    return `${lead.label} leads at ${share.toFixed(0)}%, ${second ? `${second.label} at ${((second.value / total) * 100).toFixed(0)}%` : 'with a long tail behind'}, others total ${tail}. Detection investment should follow the share, not the brand novelty.`;
  }, [topC2Frameworks]);

  /** Largest recent breach disclosures by account count (HIBP). */
  const largestBreaches = useMemo<HBarItem[]>(() => {
    if (!state.breaches) return [];
    return state.breaches
      .filter((b) => typeof b.pwn_count === 'number' && b.pwn_count > 0)
      .map((b) => ({ label: b.title || b.name, value: b.pwn_count as number }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.breaches]);

  /** Most cross-referenced entities in OSINT researcher chatter (threat-pulse). */
  const topPulseEntities = useMemo<HBarItem[]>(() => {
    if (!state.pulse) return [];
    return [...state.pulse]
      .sort((a, b) => b.source_count - a.source_count)
      .slice(0, 10)
      .map((e) => ({ label: e.label, value: e.source_count, hint: e.kind }));
  }, [state.pulse]);

  /** Dark-web / underground CTI resources by category (deepdarkcti corpus). */
  const ddcCategories = useMemo<HBarItem[]>(() => {
    if (!state.ddc?.categories) return [];
    return [...state.ddc.categories]
      .map((c) => ({ label: c.label, value: c.count }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [state.ddc]);

  /* ─── Summary header counts ─── */
  const summary = useMemo(() => {
    // Ransomware count uses calendar-day buckets (windowDays UTC dates,
    // today + N-1 prior) to match the ransomware cadence chart, the
    // headline read panel, and the hero sparkline on /. The old
    // `withinDays` filter used a rolling 168-hour window which counted
    // a partial day at the trailing edge that the chart's calendar
    // buckets excluded - that's the 239-vs-231 discrepancy users hit.
    //
    // We count DISTINCT (group, victim) pairs, not raw rows, so the
    // same victim reported by multiple upstream trackers across
    // different days doesn't double-count.
    let r = 0;
    if (dedupedRansomware.length) {
      const now = new Date();
      const windowDayKeys = new Set<string>();
      for (let i = 0; i < windowDays; i += 1) {
        windowDayKeys.add(new Date(now.getTime() - i * 86400_000).toISOString().slice(0, 10));
      }
      for (const v of dedupedRansomware) {
        const t = Date.parse(v.discovered);
        if (Number.isNaN(t)) continue;
        if (windowDayKeys.has(new Date(t).toISOString().slice(0, 10))) r += 1;
      }
    }
    const c = state.cves?.length ?? 0;
    const kevCount = state.cves?.filter((x) => x.kev).length ?? 0;
    const p = state.phishing?.length ?? 0;
    const ips = state.threatMap?.total_ips ?? 0;
    const c2 = state.c2?.count ?? 0;
    return { r, c, kevCount, p, ips, c2 };
  }, [state, windowDays, dedupedRansomware]);

  // Live deltas - change in each headline counter since the previous refresh.
  // Only meaningful within a fixed window, so it resets when windowDays flips
  // and stays null on first load (nothing to diff against yet).
  type Summary = typeof summary;
  const prevSummaryRef = useRef<Summary | null>(null);
  const [deltas, setDeltas] = useState<Summary | null>(null);

  useEffect(() => {
    // windowDays changed → previous baseline is no longer comparable.
    prevSummaryRef.current = null;
    setDeltas(null);
  }, [windowDays]);

  useEffect(() => {
    if (!state.refreshedAt) return; // not loaded yet
    const prev = prevSummaryRef.current;
    if (prev) {
      setDeltas({
        r: summary.r - prev.r,
        c: summary.c - prev.c,
        kevCount: summary.kevCount - prev.kevCount,
        p: summary.p - prev.p,
        ips: summary.ips - prev.ips,
        c2: summary.c2 - prev.c2,
      });
    }
    prevSummaryRef.current = summary;
    // Diff strictly per completed refresh (refreshedAt is the fetch-completion
    // stamp); summary is read fresh here but intentionally not a dep.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.refreshedAt]);

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/threatintel"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-rose-600 dark:hover:text-rose-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <BarChart3 size={28} className="text-rose-600 dark:text-rose-400" /> Threat Intel Metrics
        </h1>
        <p className="text-muted mb-6 max-w-3xl leading-relaxed">
          Quantitative snapshot computed live in the browser from ten upstream feeds. One headline read, six narrative
          panels with written interpretations, and ten more panels in the disclosure below. Headline counters show the
          ▲/▼ change since your last refresh.
        </p>
      </div>

      {/* Headline totals + window toggle + refresh */}
      <section className="surface-card p-4 mb-6 flex items-center justify-between gap-3 flex-wrap">
        <div className="grid grid-cols-2 sm:flex sm:flex-wrap gap-3 text-tool sm:text-meta font-mono w-full sm:w-auto">
          <Stat
            label={`ransomware claims · ${windowDays}d`}
            value={summary.r}
            loading={state.loading}
            delta={deltas?.r}
          />
          <Stat label="CVEs in window" value={summary.c} loading={state.loading} delta={deltas?.c} />
          <Stat
            label="on CISA KEV"
            value={summary.kevCount}
            loading={state.loading}
            accent="rose"
            delta={deltas?.kevCount}
          />
          <Stat label="active phishing URLs" value={summary.p} loading={state.loading} delta={deltas?.p} />
          <Stat label="malicious IPs · live" value={summary.ips} loading={state.loading} delta={deltas?.ips} />
          <Stat label="active C2 servers" value={summary.c2} loading={state.loading} delta={deltas?.c2} />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Window selector - gates ransomware-based panels (groups, cadence,
              sectors, sector-classified-pct) and the summary count. KEV
              cadence keeps its own 12-week scale; CVE list returns its own
              server-side window; threat-map is a live snapshot. */}
          <div
            role="group"
            aria-label="Time window"
            className="inline-flex rounded border border-line-1 overflow-hidden text-mini font-mono"
          >
            {WINDOW_OPTIONS.map((d) => {
              const active = d === windowDays;
              return (
                <button
                  key={d}
                  type="button"
                  onClick={() => setWindowDays(d)}
                  aria-pressed={active}
                  className={`px-2.5 py-1.5 transition-colors ${
                    active
                      ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                      : 'text-muted hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-surface-300'
                  }`}
                >
                  {d}d
                </button>
              );
            })}
          </div>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-line-1 hover:border-rose-500/40"
          >
            <RefreshCw size={12} /> refresh
          </button>
        </div>
      </section>

      {state.loading && (
        <div className="surface-card p-6 inline-flex items-center gap-2 font-mono text-sm text-muted">
          <Loader2 size={14} className="animate-spin" /> computing aggregates from upstream feeds…
        </div>
      )}

      {state.error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/5 p-4 font-mono text-sm text-rose-600 dark:text-rose-300 flex items-start justify-between gap-3">
          <span>Failed to load: {state.error}</span>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="shrink-0 text-xs font-mono px-3 py-1 rounded border border-rose-400/60 hover:bg-rose-500/10"
          >
            retry
          </button>
        </div>
      )}

      {/* Headline read - one chart, one written interpretation. Replaces the
          temptation to lead with a wall of fifteen neutral panels. The prose
          recomputes on refresh; the trend / concentration / takeaway lines
          adapt grammatically to whatever values the feed produces right now. */}
      {!state.loading && headlineRead && (
        <section className="rounded-xl border border-rose-500/30 bg-gradient-to-br from-rose-50/40 to-transparent dark:from-rose-900/20 dark:to-transparent p-5 sm:p-6 mb-6">
          <div className="flex items-baseline gap-3 mb-3">
            <Flame size={18} className="text-rose-600 dark:text-rose-400" />
            <h2 className="font-display font-bold text-lg text-heading">This week's read: ransomware posture</h2>
            <span className="text-mini font-mono uppercase tracking-[0.18em] text-muted">
              auto-computed · updates on refresh
            </span>
          </div>
          <div className="grid gap-5 lg:grid-cols-[1fr_1.4fr]">
            <div>
              <Sparkbars buckets={ransomwareCadence} color="#e11d48" />
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mt-3 text-mini font-mono">
                <div className="rounded border border-line-1 px-2 py-1.5">
                  <div className="text-muted">last 7d</div>
                  <div className="text-heading font-semibold text-sm">{String(headlineRead.last7)}</div>
                </div>
                <div className="rounded border border-line-1 px-2 py-1.5">
                  <div className="text-muted">prior 7d</div>
                  <div className="text-heading font-semibold text-sm">{String(headlineRead.prior7)}</div>
                </div>
                <div
                  className={`rounded border px-2 py-1.5 ${
                    headlineRead.trendLabel === 'accelerating'
                      ? 'border-rose-500/40 text-rose-600 dark:text-rose-300'
                      : headlineRead.trendLabel === 'cooling'
                        ? 'border-emerald-500/40 text-emerald-600 dark:text-emerald-300'
                        : 'border-line-1 text-body'
                  }`}
                >
                  <div className="opacity-70">trend</div>
                  <div className="font-semibold text-sm capitalize">{headlineRead.trendLabel}</div>
                </div>
              </div>
            </div>
            <div className="space-y-3">
              {headlineRead.sentences.map((s, i) => (
                <p key={i} className={`text-sm leading-relaxed ${i === 0 ? 'text-heading font-medium' : 'text-body'}`}>
                  {typeof s === 'string' ? s : String(s)}
                </p>
              ))}
              <p className="text-mini font-mono text-muted pt-1">
                Method: 7-vs-7-day delta with a 10% deadband; concentration is the top operator's share of the last 7
                days. Sources: ransomlook.io aggregated leak-site index merged with MyThreatIntel CTI events (deduped by
                victim).{' '}
                <Link to="/threatintel/catalog?cat=iocs" className="text-rose-600 dark:text-rose-400 hover:underline">
                  Drill into the underlying data →
                </Link>
              </p>
            </div>
          </div>
        </section>
      )}

      {/* Six narrative panels, each with a one-sentence written
          interpretation computed from the data. These are the panels
          that earn the first scroll - the ones an analyst would actually
          discuss in a meeting. The remaining ten panels (sectors, brands,
          IOC volume, malware families, re-leaks, IP origins, breaches,
          OSINT chatter, dark-web, MTI profiled) are equally accurate but
          less narrative; they sit inside the disclosure below for the
          analyst use case. */}
      {!state.loading && (
        <section className="mb-8">
          <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-4">
            Narrative panels · the six worth reading first
          </h2>
          <div className="grid gap-4 lg:grid-cols-2">
            {/* 1. Top ransomware groups */}
            <ChartCard
              icon={Skull}
              title="Most active ransomware groups"
              question={`Who's claiming the most victims in the last ${windowDays} days?`}
              footer={`Ransomlook + MyThreatIntel CTI events + ransomfeed.it + ransomwatch · ${dedupedRansomware.length.toLocaleString()} unique victims (deduped by group + victim, earliest discovery wins)`}
              href="/threatintel/iocs"
              interpretation={ransomwareGroupsRead}
            >
              <HBar items={topRansomwareGroups} color="#e11d48" />
            </ChartCard>

            {/* 2. Ransomware cadence */}
            <ChartCard
              icon={TrendingUp}
              title="Ransomware cadence · last 7 days"
              question="Is leak-site posting accelerating or cooling this week?"
              footer="Daily claim count · fixed 7-day axis · per-day labels"
              href="/threatintel/iocs"
              interpretation={ransomwareCadenceRead}
            >
              <Sparkbars buckets={ransomwareCadence} color="#e11d48" />
            </ChartCard>

            {/* 3. CVE severity distribution */}
            <ChartCard
              icon={BarChart3}
              title="CVE severity distribution"
              question="How serious are this window's CVEs?"
              footer={`${cveSeverityCounts.total} CVEs (NVD pubStartDate last 30d + CISA KEV last 30d merge)`}
              href="/threatintel/cve-list"
              interpretation={cveSeverityRead}
            >
              <StackedSeverityBar counts={cveSeverityCounts.counts} total={cveSeverityCounts.total} />
            </ChartCard>

            {/* 4. KEV cadence */}
            <ChartCard
              icon={Flame}
              title="CISA KEV cadence · last 12 weeks"
              question="How quickly is CISA flagging actively-exploited CVEs?"
              footer={`${summary.kevCount} entries on KEV in this window`}
              href="/threatintel/cve-list"
              interpretation={kevCadenceRead}
            >
              <Sparkbars buckets={kevCadence} color="#f59e0b" />
            </ChartCard>

            {/* 5. Top KEV vendors (promoted up from the analyst grid because
                vendor-share is concrete actionable signal for patch triage) */}
            <ChartCard
              icon={Shield}
              title="Most-exploited vendors on CISA KEV"
              question="Whose products are taking the most active-exploitation hits?"
              footer={`Parsed from KEV vulnerability descriptions in the current CVE window`}
              href="/threatintel/cve-list"
              interpretation={kevVendorsRead}
            >
              <HBar items={topKevVendors} color="#dc2626" />
            </ChartCard>

            {/* 6. Active C2 frameworks - promoted because the share split
                here is the operational basis for detection-coverage
                prioritisation (cf the c2-dominance research piece) */}
            <ChartCard
              icon={Radio}
              title="Active C2 frameworks · live"
              question="Which command-and-control frameworks have the most live infrastructure right now?"
              footer={`From c2-tracker · ${state.c2?.count?.toLocaleString() ?? 0} live C2 IPs across ${
                state.c2?.sources?.length ?? 0
              } feeds (C2IntelFeeds, ThreatFox)`}
              href="/threatintel/c2-tracker"
              interpretation={c2FrameworksRead}
            >
              <HBar items={topC2Frameworks} color="#14b8a6" />
            </ChartCard>
          </div>

          {/* 7. ATT&CK technique heatmap - full-width below the narrative
              grid because the horizontal column layout needs the space */}
          <AttackHeatmap mbClass="mt-6" />
        </section>
      )}

      {/* Analyst panels - the remaining 10. Accurate and well-sourced but
          less narrative than the six above. Default-collapsed because
          page load shouldn't pretend each of these matters equally to
          a first-time visitor; an analyst who knows what they want can
          expand to see the catalog. */}
      {!state.loading && (
        <details className="mb-2 group">
          <summary className="cursor-pointer text-xs font-bold uppercase tracking-[0.2em] text-muted hover:text-rose-600 dark:hover:text-rose-400 font-mono py-3">
            Analyst panels (10 more). Sectors, brands, IOC volume, malware families, re-leaks, IP origins, breaches,
            chatter, dark-web, MTI profiled
            <span className="ml-2 text-muted group-open:hidden">expand</span>
            <span className="ml-2 text-muted hidden group-open:inline">collapse</span>
          </summary>
          <p className="mt-2 text-meta font-mono text-muted max-w-2xl mb-4">
            All ten are computed live from the same upstream feeds the narrative panels above use. No interpretation
            captions; the chart speaks for itself once you know what you're looking at.
          </p>

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartCard
              icon={Activity}
              title="Most-impersonated brands"
              question="Whose customers are getting phished right now?"
              footer={`From PhishTank. ${state.phishing?.filter((u) => u.target).length ?? 0} URLs have brand attribution.`}
              href="/threatintel/iocs"
            >
              <HBar items={topPhishingBrands} color="#0ea5e9" />
            </ChartCard>

            <ChartCard
              icon={Globe2}
              title="IOC volume by upstream feed"
              question="Which feed is publishing the most malicious IPs right now?"
              footer={`Cross-feed view · ${summary.ips} total IPs across upstream sources`}
              href="/threatintel/threat-map"
            >
              <HBar items={iocSourceVolume} color="#8b5cf6" />
            </ChartCard>

            <ChartCard
              icon={Briefcase}
              title={`Targeted sectors · ${windowDays}d (heuristic)`}
              question="Which industries are ransomware groups hitting right now?"
              footer={`Classified ${sectorClassifiedPct}% of recent victims by keyword match on victim name + description. Best-effort; verify before action.`}
              href="/threatintel/iocs"
            >
              <HBar items={targetedSectors} color="#0891b2" />
            </ChartCard>

            <ChartCard
              icon={Bug}
              title="Most-active malware families · 24h"
              question="Which malware families are dropping on MalwareBazaar right now?"
              footer={`From MalwareBazaar recent samples · ${state.malware?.length ?? 0} samples in window`}
              href="/threatintel/iocs"
            >
              <HBar items={topMalwareFamilies} color="#a855f7" />
            </ChartCard>

            <ChartCard
              icon={Users}
              title="Re-leak hotspots: groups doing the most cross-claims"
              question="Which groups appear in cross-actor re-leaks the most? (affiliate-movement signal)"
              footer={`${state.releaks?.length ?? 0} re-leaks across top-8 active groups`}
              href="/threatintel/re-leaks"
            >
              <HBar items={releakGroups} color="#f43f5e" />
            </ChartCard>

            <ChartCard
              icon={Globe2}
              title="Malicious-IP origins · live"
              question="Where in the world are the malicious IPs originating?"
              footer={`Top 10 countries · ${state.threatMap?.countries?.length ?? 0} countries seen across upstream feeds`}
              href="/threatintel/threat-map"
            >
              <HBar items={topCountries} color="#3b82f6" />
            </ChartCard>

            <ChartCard
              icon={Database}
              title="Largest recent breach disclosures"
              question="Which freshly-disclosed breaches exposed the most accounts?"
              footer={`From HaveIBeenPwned · ${state.breaches?.length ?? 0} recent disclosures indexed`}
              href="/threatintel/iocs"
            >
              <HBar
                items={largestBreaches}
                color="#f59e0b"
                formatValue={(n) =>
                  n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 1_000 ? `${(n / 1_000).toFixed(0)}K` : `${n}`
                }
              />
            </ChartCard>

            <ChartCard
              icon={MessageSquare}
              title="OSINT chatter - most cross-referenced entities"
              question="Which CVEs, actors, techniques and malware are researchers talking about across the most feeds?"
              footer={`From threat-pulse · ${state.pulse?.length ?? 0} entities seen across Reddit / Mastodon / Telegram researcher feeds. Value = distinct feeds.`}
              href="/threatintel/feeds"
            >
              <HBar items={topPulseEntities} color="#6366f1" />
            </ChartCard>

            <ChartCard
              icon={Network}
              title="Dark-web CTI corpus by category"
              question="Where is the underground/dark-web CTI resource coverage concentrated?"
              footer={`From deepdarkcti · ${state.ddc?.total?.toLocaleString() ?? 0} resources across ${
                state.ddc?.categories?.length ?? 0
              } categories`}
              href="/threatintel/deepdarkcti"
            >
              <HBar items={ddcCategories} color="#a3a3a3" />
            </ChartCard>

            <ChartCard
              icon={Network}
              title="Profiled active groups · MyThreatIntel"
              question="Which currently-active ransomware groups have a MyThreatIntel actor profile?"
              footer={`Join of the merged ransomware feed with ${
                state.mtiGroups?.length?.toLocaleString() ?? 0
              } MyThreatIntel group profiles`}
              href="/threatintel/mythreatintel"
            >
              <HBar items={mtiProfiledActiveGroups} color="#0ea5e9" />
            </ChartCard>
          </div>
        </details>
      )}

      {/* Related-surfaces footer. Plain <a> caused full-page reloads -
          use <Link> so router state survives the navigation. */}
      <section className="mt-10 surface-card p-5">
        <h3 className="font-display font-semibold text-sm mb-3">Related surfaces</h3>
        <div className="grid sm:grid-cols-2 gap-2 text-meta font-mono">
          <Link
            to="/threatintel/iocs/cross"
            className="px-3 py-2 rounded border border-line-1 hover:border-rose-500/40 text-body"
          >
            Cross-source IOC correlation →
          </Link>
          <Link
            to="/threatintel/actors/hub"
            className="px-3 py-2 rounded border border-line-1 hover:border-rose-500/40 text-body"
          >
            Actor activity timeline + MITRE TTPs →
          </Link>
          <Link
            to="/threatintel/darkweb/leaks"
            className="px-3 py-2 rounded border border-line-1 hover:border-rose-500/40 text-body"
          >
            Victim re-leak detection →
          </Link>
          <Link
            to="/threatintel/catalog?cat=iocs"
            className="px-3 py-2 rounded border border-line-1 hover:border-rose-500/40 text-body"
          >
            Live IOC stream →
          </Link>
        </div>
      </section>

      {state.refreshedAt && (
        <p className="text-micro font-mono text-muted mt-6 text-right">
          recomputed {new Date(state.refreshedAt).toLocaleString()}
        </p>
      )}
    </div>
  );
}

/* ─── ISO week-of-year for KEV cadence x-axis ─── */
function weekOfYear(d: Date): number {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  return Math.ceil(((dt.getTime() - yearStart.getTime()) / 86400_000 + 1) / 7);
}

/* ─── Small helpers ─── */

function Stat({
  label,
  value,
  loading,
  accent,
  delta,
}: {
  label: string;
  value: number | string;
  loading?: boolean;
  accent?: 'rose';
  /** Change since the previous refresh; 0 / undefined hides the badge. */
  delta?: number;
}) {
  return (
    <div className="flex flex-col">
      <span className="inline-flex items-baseline gap-1.5">
        <span
          className={`tabular-nums text-base font-display font-semibold ${
            accent === 'rose' ? 'text-rose-600 dark:text-rose-400' : 'text-heading'
          }`}
        >
          {loading ? '-' : typeof value === 'number' ? value.toLocaleString() : value}
        </span>
        {!loading && typeof delta === 'number' && delta !== 0 && (
          <span
            className={`text-micro font-mono tabular-nums ${
              delta > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'
            }`}
            title={`${delta > 0 ? '+' : ''}${delta} since last refresh`}
          >
            {delta > 0 ? '▲' : '▼'}
            {delta > 0 ? '+' : ''}
            {delta.toLocaleString()}
          </span>
        )}
      </span>
      <span className="text-micro uppercase tracking-wider text-muted">{label}</span>
    </div>
  );
}

function ChartCard({
  icon: Icon,
  title,
  question,
  footer,
  href,
  children,
  interpretation,
}: {
  icon: typeof BarChart3;
  title: string;
  question: string;
  footer: string;
  href?: string;
  children: React.ReactNode;
  /** Optional one-sentence "what this means right now" prose under the
   *  chart. Promoted panels in the narrative section pass this; analyst
   *  panels in the collapsed grid leave it empty. */
  interpretation?: string;
}) {
  return (
    <div className="surface-card p-4">
      <div className="flex items-baseline justify-between gap-2 mb-1">
        <h3 className="font-display font-semibold text-sm inline-flex items-center gap-2">
          <Icon size={14} className="text-rose-600 dark:text-rose-400" /> {title}
        </h3>
        {href && (
          <Link to={href} className="text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline">
            details →
          </Link>
        )}
      </div>
      <p className="text-xs italic text-muted mb-3 leading-relaxed">{question}</p>
      <div className="mb-3">{children}</div>
      {interpretation && (
        <p className="text-meta text-body leading-relaxed mb-2 border-l-2 border-rose-500/40 pl-3">{interpretation}</p>
      )}
      <p className="text-micro font-mono text-muted">{footer}</p>
    </div>
  );
}
