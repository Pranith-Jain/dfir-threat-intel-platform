import type { ReactNode } from 'react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowDown, ArrowUp, Minus, TrendingUp } from 'lucide-react';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { Badge, CyberViewPage, OutLink } from './shared-ui';
import { asArray, fmtDay, fmtNum } from './shared-utils';

/** Replication of CyberView's "Trends" page: one week of collected cyber
 * events (per day, and by category / sector / country / actor / product / tag)
 * plus a power-grid context panel. All figures come from trends.json. */

type DimKey = 'category' | 'sector' | 'country' | 'actor' | 'product' | 'tag';
type LinkKind = 'cat' | 'q';
type WeekWindow = { from: string; to: string; total: number };
type PrevWeek = WeekWindow & { complete: boolean };
type DimRow = { k: string; cur: number; prev: number };
type DailyPoint = { date: string; total: number };
type GridLargest = { id: string; name: string; peak_customers: number; peak_level: number | null; opened_at: string };
type GridCause = { cause: string; customers: number };
type GridRegion = { source: string; region: string; customer_hours: number; incidents: number; coverage: number } & {
  largest: GridLargest | null;
  causes: GridCause[];
};
type GridTrends = { window_days: number; from: string; to: string; regions: Record<string, GridRegion> };
type Grid = { updated_at: string; trends: GridTrends; anomalies: number; corroborated: number };
type TrendsData = { built_at: string; cur: WeekWindow; prev: PrevWeek; collection_started: string } & {
  dims: Record<DimKey, DimRow[]>;
  daily: DailyPoint[];
  grid: Grid;
};
type BarRowProps = { label: string; pinned: boolean; onToggle: () => void; className: string; children: ReactNode };

const CATEGORY_LABELS: Record<string, string> = {
  incident: 'Incidents',
  vuln: 'Patches and advisories',
  report: 'Threat reports',
  policy: 'Law and policy',
  enforcement: 'Law enforcement',
  outage: 'Outages',
  investment: 'Investment and vendors',
};
const DIMS: Array<{ key: DimKey; title: string; link: LinkKind }> = [
  { key: 'category', title: 'Event types', link: 'cat' },
  { key: 'sector', title: 'Sectors', link: 'q' },
  { key: 'country', title: 'Countries', link: 'q' },
  { key: 'actor', title: 'Actors', link: 'q' },
  { key: 'product', title: 'Products', link: 'q' },
  { key: 'tag', title: 'Themes', link: 'q' },
];
const UPSTREAM = 'https://xanderhutch.github.io/CyberView/';
const HEADERS = ['Name', 'This week', 'Week before (partial)', 'Change'];
const HEAD_CELL = 'font-mono text-mini font-semibold uppercase tracking-wide text-muted';
const DAILY_LABEL = 'Events per day, last 28 days';
const GRID_LABEL = 'Customer-hours without power by operator region, last 30 days';
const FOCUS = 'focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-text';
const UP_TONE = 'font-semibold text-emerald-600 dark:text-emerald-400';
const DOWN_TONE = 'font-semibold text-rose-600 dark:text-rose-400';

// Date-only strings are parsed as UTC so a viewer's timezone cannot shift a day.
const parseDay = (date: string): Date => new Date(`${date}T00:00:00Z`);
const DAY_OPTS: Intl.DateTimeFormatOptions = { timeZone: 'UTC', weekday: 'short', month: 'short', day: 'numeric' };
const dayLabelFmt = new Intl.DateTimeFormat('en-US', DAY_OPTS);
const longFmt = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'long', day: 'numeric' });
const fmtDayLabel = (date: string): string => dayLabelFmt.format(parseDay(date));
const fmtLong = (date: string): string => longFmt.format(parseDay(date));
const fmtPlusDays = (date: string, days: number): string =>
  new Date(parseDay(date).getTime() + days * 86_400_000).toISOString().slice(0, 10);
const fmtCoverage = (coverage: number): string => `${Math.round(coverage * 100)}%`;
const fmtBuilt = (iso: string): string => `${new Date(iso).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;

function ChangeCell({ cur, prev }: { cur: number; prev: number }): JSX.Element {
  const delta = cur - prev;
  const Icon = delta > 0 ? ArrowUp : delta < 0 ? ArrowDown : Minus;
  const tone = delta > 0 ? UP_TONE : delta < 0 ? DOWN_TONE : 'text-muted';
  return (
    <span className={`inline-flex items-center gap-0.5 font-mono text-meta ${tone}`}>
      <Icon size={12} aria-hidden="true" />
      {delta > 0 ? `+${delta}` : delta}
    </span>
  );
}

/** Shared focusable button shell for both the daily and the grid bars. */
// prettier-ignore
function BarRow({ label, pinned, onToggle, className, children }: BarRowProps): JSX.Element {
  return (
    <button type="button" aria-label={label} aria-pressed={pinned} onClick={onToggle} className={`group ${FOCUS} ${className}`}>
      {children}
    </button>
  );
}

// prettier-ignore
function DimTable({ title, rows, link }: { title: string; rows: DimRow[]; link: LinkKind }): JSX.Element | null {
  if (rows.length === 0) return null;
  return (
    <section className="surface-card rounded-xl border border-line-1 p-4 sm:p-5">
      <h3 className="text-sm font-bold text-heading">{title}</h3>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full min-w-[27rem] border-collapse text-left">
          <thead><tr className="border-b border-line-1">
            {HEADERS.map((h, i) => (
              <th key={h} scope="col" className={`${i === 0 ? 'py-2 pr-3' : i === 3 ? 'py-2 pl-3 text-right' : 'px-3 py-2 text-right'} ${HEAD_CELL}`}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {rows.map((row) => {
              const label = link === 'cat' ? (CATEGORY_LABELS[row.k] ?? row.k) : row.k;
              const href = `/threatintel/cyberview/archive?${link === 'cat' ? 'cat' : 'q'}=${encodeURIComponent(link === 'cat' ? row.k : label)}`;
              return (
                <tr key={row.k} className="border-b border-line-1 last:border-b-0">
                  <th scope="row" className="py-2 pr-3 text-xs font-normal text-body">
                    <Link to={href} className="text-accent-text hover:underline">{label}</Link>
                  </th>
                  <td className="px-3 py-2 text-right font-mono text-meta text-heading">{row.cur}</td>
                  <td className="px-3 py-2 text-right font-mono text-meta text-muted">{row.prev}</td>
                  <td className="py-2 pl-3 text-right"><ChangeCell cur={row.cur} prev={row.prev} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function regionDetail(region: GridRegion, windowDays: number): string {
  const causes = asArray(region.causes);
  const parts = [
    `${plural(region.incidents, 'incident')} opened`,
    `data for ${fmtCoverage(region.coverage)} of the ${windowDays} days`,
    ...(region.largest ? [`largest: ${region.largest.name}`] : []),
    causes.length > 0
      ? `causes as reported: ${causes.map((c) => `${c.cause} (${fmtNum(c.customers)})`).join(', ')}`
      : 'no causes reported',
  ];
  return parts.join(' · ');
}

export default function CyberViewTrends({ bare = false }: { bare?: boolean }): JSX.Element {
  const feed = useDataFetch<TrendsData>({ url: '/data/cyberview/data/trends.json', ttl: 600_000 });
  const [pinnedDay, setPinnedDay] = useState<number | null>(null);
  const [pinnedRegion, setPinnedRegion] = useState<number | null>(null);
  const data = feed.data;

  // regions is an object keyed by id in trends.json, so read its values safely.
  const regions = useMemo<GridRegion[]>(
    () => Object.values(data?.grid?.trends?.regions ?? {}).sort((a, b) => b.customer_hours - a.customer_hours),
    [data]
  );
  const topRegions = regions.slice(0, 20);
  const daily = data?.daily ?? [];
  const maxDay = Math.max(1, ...daily.map((d) => d.total));
  const pinnedPoint = pinnedDay !== null ? daily[pinnedDay] : undefined;
  const windowDays = data?.grid?.trends?.window_days ?? 30;
  const maxCH = Math.max(1, ...topRegions.map((r) => r.customer_hours));
  const shownCH = topRegions.reduce((sum, r) => sum + r.customer_hours, 0);
  const pinnedGrid = pinnedRegion !== null ? topRegions[pinnedRegion] : undefined;

  return (
    // prettier-ignore
    <CyberViewPage
      bare={bare} icon={<TrendingUp size={28} />} title="CyberView — Trends"
      description="Replication of CyberView's weekly trends: events per day, changes by type/sector/country/actor/product/tag and power-grid signals."
      loading={feed.loading} error={feed.error} onRetry={feed.refetch}>
      {feed.loading && !data && <p className="font-mono text-meta text-muted">Loading trends data…</p>}
      {feed.error && <p className="font-mono text-meta text-rose-500">error: {feed.error}</p>}
      {data && (
        <div className="space-y-5">
          <header className="surface-card rounded-xl border border-line-1 p-5">
            <h1 className="text-2xl font-bold text-heading">What is moving this week</h1>
            <p className="mt-2 text-sm text-body">{data.cur.total} events from {fmtDay(data.cur.from)} to {fmtDay(data.cur.to)}; {data.prev.total} in the week before.</p>
            <p className="mt-2 text-xs leading-relaxed text-muted">
              Collection began {fmtLong(data.collection_started)}; earlier events were backfilled and are incomplete,
              so the week before is undercounted. Until about {fmtLong(fmtPlusDays(data.collection_started, 14))},
              read this week&apos;s counts as a ranking, not the changes as real trends.
            </p>
          </header>

          <section className="surface-card rounded-xl border border-line-1 p-4 sm:p-5">
            <h2 className="text-base font-bold text-heading">How many events were recorded each day?</h2>
            <div role="group" aria-label={DAILY_LABEL} className="mt-4 flex h-44 gap-[3px] border-b border-line-1 pb-1">
              {daily.map((point, i) => {
                const barHeight = point.total === 0 ? 2 : Math.max(4, Math.round((point.total / maxDay) * 100));
                const showAxis = i % 7 === 6 || i === daily.length - 1;
                return (
                  <BarRow key={point.date} label={`${fmtDayLabel(point.date)}: ${plural(point.total, 'event')}`}
                    pinned={pinnedDay === i} onToggle={() => setPinnedDay(pinnedDay === i ? null : i)}
                    className="flex h-full min-w-0 flex-1 flex-col">
                    <span className="flex min-h-0 flex-1 items-end">
                      <span className={`block w-full rounded-t-sm transition-colors ${pinnedDay === i ? 'bg-brand-600' : 'bg-brand-500/70 group-hover:bg-brand-500'}`} style={{ height: `${barHeight}%` }} />
                    </span>
                    <span className={`mt-1.5 h-4 text-center font-mono text-mini ${showAxis ? 'text-muted' : 'text-transparent'}`} aria-hidden="true">
                      {showAxis ? fmtDay(point.date) : '·'}
                    </span>
                  </BarRow>
                );
              })}
            </div>
            <p className="mt-3 min-h-[1.1rem] font-mono text-meta text-muted" aria-live="polite">
              {pinnedPoint
                ? `${fmtDayLabel(pinnedPoint.date)} — ${plural(pinnedPoint.total, 'event')}`
                : "Tap a bar to see that day's count."}
            </p>
            <p className="mt-1 text-meta leading-relaxed text-muted">
              Last 28 days, unverified claims left out. A day&apos;s count can still grow as later sweeps find more.
            </p>
          </section>

          <section className="space-y-3">
            <h2 className="text-base font-bold text-heading">Changes by type, sector and source</h2>
            {DIMS.map((dim) => (
              <DimTable key={dim.key} title={dim.title} rows={data.dims[dim.key] ?? []} link={dim.link} />
            ))}
            <p className="text-meta leading-relaxed text-muted">
              Counts are events on file dated within each week; sectors, products and tags can overlap. Names come from
              sources and are not merged. Select a name to see its events in the archive.
            </p>
          </section>

          <section className="surface-card rounded-xl border border-line-1 p-4 sm:p-5">
            <h2 className="text-base font-bold text-heading">Power grid and internet outages</h2>
            <p className="mt-2 text-xs leading-relaxed text-muted">
              Where were the most customer-hours without power in the last 30 days? {fmtNum(shownCH)} customer-hours
              across {plural(topRegions.length, 'operator region')} in the last {windowDays} days. Some feeds were not
              read for the whole period, so their totals undercount; each row shows coverage, and no week-on-week change
              appears without 90% coverage in both weeks.
            </p>
            {(data.grid.anomalies > 0 || data.grid.corroborated > 0) && (
              <div className="mt-1 flex flex-wrap gap-1">
                {data.grid.anomalies > 0 && (
                  <Badge tone="high">{data.grid.anomalies} {data.grid.anomalies === 1 ? 'anomaly' : 'anomalies'}</Badge>
                )}
                {data.grid.corroborated > 0 && <Badge tone="good">{data.grid.corroborated} corroborated</Badge>}
              </div>
            )}
            {topRegions.length > 0 && (
              <div role="group" aria-label={GRID_LABEL} className="mt-4 space-y-0.5">
                {topRegions.map((region, i) => {
                  const width = Math.max(2, Math.round((region.customer_hours / maxCH) * 100));
                  return (
                    <BarRow key={`${region.source}|${region.region}`}
                      label={`${region.source}, ${region.region}: ${fmtNum(region.customer_hours)} customer-hours, ${regionDetail(region, windowDays).replace(/ · /g, ', ')}.`}
                      pinned={pinnedRegion === i} onToggle={() => setPinnedRegion(pinnedRegion === i ? null : i)}
                      className="grid w-full grid-cols-[minmax(0,9rem)_1fr_3.5rem] items-center gap-3 rounded-control px-2 py-1 text-left hover:bg-wash sm:grid-cols-[minmax(0,16rem)_1fr_4rem]">
                      <span className="truncate font-mono text-meta text-body">
                        {region.source}, {region.region}
                      </span>
                      <span className="block h-2.5 w-full overflow-hidden rounded bg-track">
                        <span className={`block h-full rounded transition-colors ${pinnedRegion === i ? 'bg-amber-500' : 'bg-amber-500/70 group-hover:bg-amber-500'}`} style={{ width: `${width}%` }} />
                      </span>
                      <span className="text-right font-mono text-meta text-heading">{fmtNum(region.customer_hours)}</span>
                    </BarRow>
                  );
                })}
              </div>
            )}
            <p className="mt-3 min-h-[1.1rem] font-mono text-meta text-muted" aria-live="polite">
              {pinnedGrid
                ? `${pinnedGrid.source}, ${pinnedGrid.region} — ${regionDetail(pinnedGrid, windowDays)}`
                : 'Tap a bar for the causes as the operators reported them.'}
            </p>
            <p className="mt-2 text-meta leading-relaxed text-muted">
              <strong className="font-semibold text-heading">Context, not cyber events.</strong> Outages are not attacks;
              causes are as the operator reports them. Customer-hours add up unplanned customers without power sampled
              every 15 minutes — a customer is a meter, not a person, and operators count them differently, so compare a
              region with itself over time. Load shedding and grid emergencies are levels, not customers, and are not in
              the bars.
            </p>
          </section>

          <footer className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-1 pt-3 font-mono text-mini text-muted">
            <span>Built {fmtBuilt(data.built_at)}</span>
            <OutLink href={UPSTREAM}>Original CyberView</OutLink>
            {data.grid.updated_at && <span className="ml-auto">Grid updated {fmtBuilt(data.grid.updated_at)}</span>}
          </footer>
        </div>
      )}
    </CyberViewPage>
  );
}
