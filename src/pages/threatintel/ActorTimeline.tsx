import { useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { relativeAgo as shortRel } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ExternalLink, RefreshCw, Skull } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { ActorTtpsPanel } from '../../components/threatintel/ActorTtpsPanel';
import { errMessage } from '../../lib/log';

interface MitreGroupRef {
  id: string;
  name: string;
  url: string;
}

interface ActorBucket {
  day: string;
  count: number;
}

interface ActorRow {
  slug: string;
  display_name: string;
  posts_in_window: number;
  all_time_count: number;
  buckets: ActorBucket[];
  description?: string;
  raas?: boolean;
  references: string[];
  mirrors_reachable: number;
  mirrors_total: number;
  mitre?: MitreGroupRef;
  /** Row rebuilt from the /api/recent feed because the per-group endpoint was down. */
  partial?: boolean;
}

interface AggregateTechnique {
  id: string;
  name: string;
  tactic: string;
  used_by_count: number;
  used_by_groups: string[];
  weighted_activity: number;
}

interface ActorTimelineResponse {
  generated_at: string;
  window_days: number;
  days: string[];
  groups: ActorRow[];
  aggregate_techniques: AggregateTechnique[];
  groups_with_ttp_data: number;
  warnings: Array<{ slug: string; reason: string }>;
}

function cellColor(count: number, max: number): string {
  if (count === 0) return 'bg-slate-100 dark:bg-surface-200';
  const intensity = Math.min(1, count / Math.max(1, max));
  if (intensity < 0.2) return 'bg-rose-200 dark:bg-rose-900/40';
  if (intensity < 0.4) return 'bg-rose-300 dark:bg-rose-800/60';
  if (intensity < 0.6) return 'bg-rose-400 dark:bg-rose-700/70';
  if (intensity < 0.8) return 'bg-rose-500 dark:bg-rose-600/80';
  return 'bg-rose-600 dark:bg-rose-500';
}

function shortDay(iso: string): string {
  const d = new Date(iso + 'T00:00:00Z');
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
}

export default function ActorTimeline(): JSX.Element {
  // Deep-link support: /threatintel/actors/hub?tab=timeline&actor=<slug>
  // (IOC pivots emit this) scrolls to and highlights that group's row.
  const [searchParams] = useSearchParams();
  const focusActor = searchParams.get('actor')?.trim().toLowerCase() ?? null;
  const highlightRef = useRef<HTMLLIElement | null>(null);

  useEffect(() => {
    if (focusActor && highlightRef.current) {
      highlightRef.current.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }, [focusActor]);

  const { data, loading, error, refetch } = useDataFetch<ActorTimelineResponse>({
    url: '/api/v1/actor-timeline',
    ttl: 120_000,
    staleWhileRevalidate: true,
  });

  // Per-row max for relative shading (a group with 10 posts/day shouldn't drown
  // out a group whose top day is 3 - the visual question is "is this group's
  // cadence accelerating or cooling," not "which group is biggest").
  const rowMaxes = useMemo(() => {
    if (!data) return new Map<string, number>();
    const m = new Map<string, number>();
    for (const g of data.groups) {
      let max = 0;
      for (const b of g.buckets) if (b.count > max) max = b.count;
      m.set(g.slug, max);
    }
    return m;
  }, [data]);

  const xAxisLabels = useMemo(() => {
    if (!data) return [] as Array<{ idx: number; label: string }>;
    const out: Array<{ idx: number; label: string }> = [];
    // Label every 5 days, plus the last column.
    for (let i = 0; i < data.days.length; i += 5) {
      out.push({ idx: i, label: shortDay(data.days[i]!) });
    }
    if (out[out.length - 1]?.idx !== data.days.length - 1) {
      out.push({ idx: data.days.length - 1, label: shortDay(data.days[data.days.length - 1]!) });
    }
    return out;
  }, [data]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Skull className="h-6 w-6" />}
      title="Ransomware actor activity timeline"
      description={
        <>
          Per-actor leak-site cadence across the last {data?.window_days ?? 30} days. Rows are the most-active groups
          this week; cells are daily post counts (relative shading per row so a slow week is still visible). MITRE
          ATT&CK Group profile linked where known, so you can pivot from "who's posting" to "what TTPs to hunt for."
        </>
      }
      loading={loading}
      error={error}
      empty={!error && (!data || data.groups.length === 0)}
      emptyMessage="Ransomlook returned no data this snapshot. Try refresh."
      onRetry={refetch}
      maxWidthClass="max-w-6xl"
      headerExtra={
        <section className="surface-card p-4 flex items-center justify-between gap-3 flex-wrap">
          {data && (
            <p className="text-mini font-mono text-muted">
              {data.groups.length} active groups · snapshot{' '}
              <span className="text-body">{shortRel(data.generated_at)}</span>
              {data.warnings.length > 0 && (
                <span className="text-amber-600 dark:text-amber-400 ml-2">
                  · {data.warnings.length} per-group fetch warnings
                </span>
              )}
            </p>
          )}
          <button
            type="button"
            onClick={() => refetch()}
            className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 disabled:opacity-50"
            aria-label="refresh"
          >
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
          </button>
        </section>
      }
    >
      <p className="text-xs text-muted font-mono mb-6">
        Joins Ransomlook per-group history with a curated MITRE Group lookup.
      </p>
      {data && (
        <>
          {/* overflow-x-auto wrapper: the heatmap has a fixed 200px label column + N day columns,
              which can't compress below ~640px without losing meaning. Let it scroll on mobile. */}
          <div className="overflow-x-auto -mx-4 sm:mx-0 px-4 sm:px-0">
            <div className="min-w-[640px]">
              {/* Day axis legend */}
              <div
                className="font-mono text-micro text-muted mb-1 grid"
                style={{ gridTemplateColumns: `200px repeat(${data.days.length}, minmax(0,1fr))` }}
              >
                <div></div>
                {data.days.map((day, i) => {
                  const tick = xAxisLabels.find((l) => l.idx === i);
                  return (
                    <div key={day} className="text-center">
                      {tick ? tick.label : ''}
                    </div>
                  );
                })}
              </div>

              <ul className="space-y-2">
                {data.groups.map((g) => {
                  const max = rowMaxes.get(g.slug) ?? 0;
                  const isFocus =
                    focusActor !== null && (g.slug === focusActor || g.display_name.toLowerCase() === focusActor);
                  return (
                    <li
                      key={g.slug}
                      ref={isFocus ? highlightRef : undefined}
                      className={`surface-card p-3 ${isFocus ? 'ring-2 ring-brand-500/60 dark:ring-brand-400/60' : ''}`}
                    >
                      <div
                        className="grid items-center gap-1"
                        style={{ gridTemplateColumns: `200px repeat(${g.buckets.length}, minmax(0,1fr))` }}
                      >
                        <div className="pr-3 min-w-0">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <div className="font-display font-semibold text-sm truncate min-w-0" title={g.display_name}>
                              {g.display_name}
                            </div>
                            <AccelerationBadge buckets={g.buckets} />
                          </div>
                          <div className="text-micro font-mono text-muted mt-0.5">
                            {g.posts_in_window} in {data.window_days}d ·{' '}
                            {g.partial ? 'recent-feed only' : `${g.all_time_count} all-time`}
                          </div>
                        </div>
                        {g.buckets.map((b) => (
                          <div
                            key={b.day}
                            className={`h-5 rounded ${cellColor(b.count, max)} hover:ring-2 hover:ring-rose-500/40 transition-shadow`}
                            title={`${b.day} · ${b.count} post${b.count === 1 ? '' : 's'}`}
                          />
                        ))}
                      </div>

                      {/* Per-group footer: MITRE link, raas tag, refs */}
                      <div className="mt-2 ml-[200px] pl-0 flex items-center gap-2 flex-wrap text-mini font-mono text-muted">
                        {g.mitre ? (
                          <a
                            href={sanitizeUrl(g.mitre.url)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:underline transition-colors"
                          >
                            MITRE {g.mitre.id} · {g.mitre.name} <ExternalLink size={9} />
                          </a>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded border border-line-2 text-muted">not in MITRE</span>
                        )}
                        {g.raas && (
                          <span className="px-1.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300">
                            RaaS
                          </span>
                        )}
                        {g.partial ? (
                          <span
                            className="px-1.5 py-0.5 rounded border border-line-2 text-muted"
                            title="ransomlook per-group endpoint was unreachable; this row is rebuilt from the recent-claims feed. Heatmap is accurate for the window; all-time count, mirrors and references are unavailable."
                          >
                            recent-feed only
                          </span>
                        ) : (
                          <span
                            className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded ${
                              g.mirrors_total > 0 && g.mirrors_reachable === 0
                                ? 'border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                                : 'bg-slate-100 dark:bg-surface-300'
                            }`}
                            title={`${g.mirrors_reachable} of ${g.mirrors_total} leak-site mirrors currently reachable${
                              g.mirrors_total > 0 && g.mirrors_reachable === 0 ? ' (site possibly down or seized)' : ''
                            }`}
                          >
                            mirrors:
                            <MirrorDots reachable={g.mirrors_reachable} total={g.mirrors_total} />
                            <span className="tabular-nums text-micro">
                              {g.mirrors_reachable}/{g.mirrors_total}
                            </span>
                          </span>
                        )}
                        {g.references.slice(0, 3).map((ref) => {
                          let host = ref;
                          try {
                            host = new URL(ref).hostname.replace(/^www\./, '');
                          } catch (_catchErr) {
                            console.error('handler failed:', errMessage(_catchErr));
                            /* ignore */
                          }
                          return (
                            <a
                              key={ref}
                              href={sanitizeUrl(ref) || undefined}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:underline hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1 transition-colors"
                              title={ref}
                            >
                              {host} <ExternalLink size={9} />
                            </a>
                          );
                        })}
                      </div>

                      {g.description && (
                        <p className="mt-2 ml-[200px] text-mini font-mono text-muted leading-relaxed">
                          {g.description}
                          {g.description.length >= 400 ? '…' : ''}
                        </p>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          <div className="mt-6">
            <ActorTtpsPanel />
          </div>

          <section className="mt-6 rounded-xl border border-line-1 bg-surface-200 p-4">
            <h3 className="font-display font-semibold text-sm mb-2">How to read this</h3>
            <ul className="text-meta font-mono text-muted space-y-1 list-disc list-inside">
              <li>
                Cell shading is relative to <em>each row's</em> peak, so a slow week for one group can still highlight
                its peak day.
              </li>
              <li>Empty cells = zero posts on that day. Hover any cell for exact count + date.</li>
              <li>
                "MITRE Gxxxx" pill links to ATT&CK Group profile (techniques, software, references). Newer groups may
                not be tracked yet.
              </li>
              <li>
                "RaaS" means the group operates as Ransomware-as-a-Service (recruits affiliates rather than executing
                intrusions directly).
              </li>
              <li>
                Aggregate TTPs panel: "X grp · Yp" means used by X active groups carrying Y total posts in the window.
              </li>
            </ul>
          </section>
        </>
      )}
    </DataPageLayout>
  );
}

/**
 * Acceleration badge - compares last-7-day post count vs the prior 7-day
 * window. A persistent +/-N signal next to the actor name flags groups
 * that are heating up or cooling off without forcing the analyst to
 * eyeball the heatmap.
 */
function AccelerationBadge({ buckets }: { buckets: ActorBucket[] }): JSX.Element | null {
  if (buckets.length < 14) return null;
  const last7 = buckets.slice(-7).reduce((a, b) => a + b.count, 0);
  const prior7 = buckets.slice(-14, -7).reduce((a, b) => a + b.count, 0);
  const delta = last7 - prior7;
  if (delta === 0 && last7 === 0) return null;
  const sign = delta > 0 ? '+' : '';
  const cls =
    delta > 0
      ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
      : delta < 0
        ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
        : 'border-slate-300 dark:border-line-1 text-slate-500';
  const arrow = delta > 0 ? '▲' : delta < 0 ? '▼' : '·';
  return (
    <span
      className={`inline-flex items-center gap-0.5 text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border ${cls}`}
      title={`7-day acceleration: ${last7} posts this week vs ${prior7} the prior week`}
    >
      <span aria-hidden="true">{arrow}</span>
      <span className="tabular-nums">
        {sign}
        {delta}
      </span>
      <span className="opacity-60">7d</span>
    </span>
  );
}

/**
 * Mirror-reachability dot strip. Filled dot = reachable, empty dot =
 * unreachable. Caps the display at 8 dots to keep the row compact; the
 * full N/M counts still show as text next to it. Red recoloration when
 * 0 reachable lives in the surrounding pill class.
 */
function MirrorDots({ reachable, total }: { reachable: number; total: number }): JSX.Element {
  const cap = Math.min(total, 8);
  const reachableCapped = Math.min(reachable, cap);
  const dots = Array.from({ length: cap }, (_, i) => ({ key: `dot-${i}`, on: i < reachableCapped }));
  return (
    <span className="inline-flex items-center gap-0.5" aria-hidden="true">
      {dots.map((d) => (
        <span
          key={d.key}
          className={`inline-block w-1.5 h-1.5 rounded-full ${
            d.on ? 'bg-emerald-500 dark:bg-emerald-400' : 'bg-slate-300 dark:bg-surface-300'
          }`}
        />
      ))}
    </span>
  );
}
