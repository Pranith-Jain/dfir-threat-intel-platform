import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowDown, ArrowUp, ExternalLink, Minus, TrendingUp } from 'lucide-react';
import { DataPageLayout } from '../../../components/DataPageLayout';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { CyberViewNav } from './CyberViewNav';

/**
 * Replication of the CyberView "Trends" page. The upstream tool summarises one
 * week of collected cyber events (per day and by category / sector / country /
 * actor / product / tag) and adds a separate power-grid context panel. All
 * figures come from the mirrored trends.json — nothing here is invented.
 */

type DimKey = 'category' | 'sector' | 'country' | 'actor' | 'product' | 'tag';

interface WeekWindow {
  from: string;
  to: string;
  total: number;
}
interface PrevWeek extends WeekWindow {
  complete: boolean;
}
interface DimRow {
  k: string;
  cur: number;
  prev: number;
}
interface DailyPoint {
  date: string;
  total: number;
}
interface GridLargest {
  id: string;
  name: string;
  peak_customers: number;
  peak_level: number | null;
  opened_at: string;
}
interface GridCause {
  cause: string;
  customers: number;
}
interface GridRegion {
  source: string;
  region: string;
  name: string;
  incidents: number;
  customer_hours: number;
  coverage: number;
  largest: GridLargest | null;
  causes: GridCause[];
  week: unknown;
}
interface GridTrends {
  window_days: number;
  from: string;
  to: string;
  regions: Record<string, GridRegion>;
}
interface Grid {
  updated_at: string;
  trends: GridTrends;
  anomalies: number;
  corroborated: number;
}
interface TrendsData {
  built_at: string;
  cur: WeekWindow;
  prev: PrevWeek;
  collection_started: string;
  dims: Record<DimKey, DimRow[]>;
  daily: DailyPoint[];
  grid: Grid;
}

const CATEGORY_LABELS: Record<string, string> = {
  incident: 'Incidents',
  vuln: 'Patches and advisories',
  report: 'Threat reports',
  policy: 'Law and policy',
  enforcement: 'Law enforcement',
  outage: 'Outages',
  investment: 'Investment and vendors',
};

const DIMS: Array<{ key: DimKey; title: string; link: 'cat' | 'q' }> = [
  { key: 'category', title: 'Event types', link: 'cat' },
  { key: 'sector', title: 'Sectors', link: 'q' },
  { key: 'country', title: 'Countries', link: 'q' },
  { key: 'actor', title: 'Actors', link: 'q' },
  { key: 'product', title: 'Products', link: 'q' },
  { key: 'tag', title: 'Themes', link: 'q' },
];

const UPSTREAM = 'https://xanderhutch.github.io/CyberView/';

// Date-only strings are parsed as UTC so a viewer's timezone cannot shift a
// day into its neighbour.
const parseDay = (date: string): Date => new Date(`${date}T00:00:00Z`);
const dayLabelFmt = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC',
  weekday: 'short',
  month: 'short',
  day: 'numeric',
});
const shortFmt = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' });
const longFmt = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'long', day: 'numeric' });

const fmtDayLabel = (date: string): string => dayLabelFmt.format(parseDay(date));
const fmtShort = (date: string): string => shortFmt.format(parseDay(date));
const fmtLong = (date: string): string => longFmt.format(parseDay(date));
const fmtPlusDays = (date: string, days: number): string =>
  new Date(parseDay(date).getTime() + days * 86_400_000).toISOString().slice(0, 10);
const fmtCoverage = (coverage: number): string => `${Math.round(coverage * 100)}%`;
const fmtCount = (n: number): string => (n >= 10_000 ? `${Math.round(n / 1000)}K` : n.toLocaleString('en-US'));
const fmtBuilt = (iso: string): string => {
  const d = new Date(iso);
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
};

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;

function ChangeCell({ cur, prev }: { cur: number; prev: number }): JSX.Element {
  const delta = cur - prev;
  if (delta > 0) {
    return (
      <span className="inline-flex items-center gap-0.5 font-mono text-meta font-semibold text-emerald-600 dark:text-emerald-400">
        <ArrowUp size={12} aria-hidden="true" />+{delta}
      </span>
    );
  }
  if (delta < 0) {
    return (
      <span className="inline-flex items-center gap-0.5 font-mono text-meta font-semibold text-rose-600 dark:text-rose-400">
        <ArrowDown size={12} aria-hidden="true" />
        {delta}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-0.5 font-mono text-meta text-muted">
      <Minus size={12} aria-hidden="true" />0
    </span>
  );
}

function DimTable({ title, rows, link }: { title: string; rows: DimRow[]; link: 'cat' | 'q' }): JSX.Element | null {
  if (rows.length === 0) return null;
  return (
    <section className="surface-card rounded-xl border border-line-1 p-4 sm:p-5">
      <h3 className="text-sm font-bold text-heading">{title}</h3>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full min-w-[27rem] border-collapse text-left">
          <thead>
            <tr className="border-b border-line-1">
              <th
                scope="col"
                className="py-2 pr-3 font-mono text-mini font-semibold uppercase tracking-wide text-muted"
              >
                Name
              </th>
              <th
                scope="col"
                className="px-3 py-2 text-right font-mono text-mini font-semibold uppercase tracking-wide text-muted"
              >
                This week
              </th>
              <th
                scope="col"
                className="px-3 py-2 text-right font-mono text-mini font-semibold uppercase tracking-wide text-muted"
              >
                Week before (partial)
              </th>
              <th
                scope="col"
                className="py-2 pl-3 text-right font-mono text-mini font-semibold uppercase tracking-wide text-muted"
              >
                Change
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const label = link === 'cat' ? (CATEGORY_LABELS[row.k] ?? row.k) : row.k;
              const href =
                link === 'cat'
                  ? `/threatintel/cyberview/archive?cat=${encodeURIComponent(row.k)}`
                  : `/threatintel/cyberview/archive?q=${encodeURIComponent(label)}`;
              return (
                <tr key={row.k} className="border-b border-line-1 last:border-b-0">
                  <th scope="row" className="py-2 pr-3 text-xs font-normal text-body">
                    <Link to={href} className="text-accent-text hover:underline">
                      {label}
                    </Link>
                  </th>
                  <td className="px-3 py-2 text-right font-mono text-meta text-heading">{row.cur}</td>
                  <td className="px-3 py-2 text-right font-mono text-meta text-muted">{row.prev}</td>
                  <td className="py-2 pl-3 text-right">
                    <ChangeCell cur={row.cur} prev={row.prev} />
                  </td>
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
  const parts = [
    `${plural(region.incidents, 'incident')} opened`,
    `data for ${fmtCoverage(region.coverage)} of the ${windowDays} days`,
  ];
  if (region.largest) parts.push(`largest: ${region.largest.name}`);
  parts.push(
    region.causes.length > 0
      ? `causes as reported: ${region.causes.map((c) => `${c.cause} (${fmtCount(c.customers)})`).join(', ')}`
      : 'no causes reported'
  );
  return parts.join(' · ');
}

export default function CyberViewTrends({ bare = false }: { bare?: boolean }): JSX.Element {
  const feed = useDataFetch<TrendsData>({ url: '/data/cyberview/data/trends.json', ttl: 600_000 });
  const [pinnedDay, setPinnedDay] = useState<number | null>(null);
  const [pinnedRegion, setPinnedRegion] = useState<number | null>(null);

  const data = feed.data;

  const regions = useMemo<GridRegion[]>(() => {
    const all = Object.values(data?.grid?.trends?.regions ?? {});
    return all.sort((a, b) => b.customer_hours - a.customer_hours);
  }, [data]);
  const topRegions = regions.slice(0, 20);

  const daily = data?.daily ?? [];
  const maxDay = Math.max(1, ...daily.map((d) => d.total));
  const pinnedPoint = pinnedDay !== null ? daily[pinnedDay] : undefined;

  const windowDays = data?.grid?.trends?.window_days ?? 30;
  const maxCH = Math.max(1, ...topRegions.map((r) => r.customer_hours));
  const shownCH = topRegions.reduce((sum, r) => sum + r.customer_hours, 0);
  const pinnedGrid = pinnedRegion !== null ? topRegions[pinnedRegion] : undefined;

  const body = (
    <>
      <CyberViewNav />
      {feed.loading && !data && <p className="font-mono text-meta text-muted">Loading trends data…</p>}
      {feed.error && <p className="font-mono text-meta text-rose-500">error: {feed.error}</p>}
      {data && (
        <div className="space-y-5">
          <header className="surface-card rounded-xl border border-line-1 p-5">
            <h1 className="text-2xl font-bold text-heading">What is moving this week</h1>
            <p className="mt-2 text-sm text-body">
              {data.cur.total} events from {fmtShort(data.cur.from)} to {fmtShort(data.cur.to)}; {data.prev.total} in
              the week before.
            </p>
            <p className="mt-2 text-xs leading-relaxed text-muted">
              CyberView began collecting on {fmtLong(data.collection_started)}. Events before that were filled in
              afterwards and are incomplete, so the week before is undercounted. Until about{' '}
              {fmtLong(fmtPlusDays(data.collection_started, 14))}, read this week&apos;s counts as a ranking, not the
              changes as real trends.
            </p>
          </header>

          <section className="surface-card rounded-xl border border-line-1 p-4 sm:p-5">
            <h2 className="text-base font-bold text-heading">How many events were recorded each day?</h2>
            <div
              role="group"
              aria-label="Events per day, last 28 days"
              className="mt-4 flex h-44 items-stretch gap-[3px] border-b border-line-1 pb-1"
            >
              {daily.map((point, i) => {
                const barHeight = point.total === 0 ? 2 : Math.max(4, Math.round((point.total / maxDay) * 100));
                const showAxis = i % 7 === 6 || i === daily.length - 1;
                return (
                  <button
                    key={point.date}
                    type="button"
                    aria-label={`${fmtDayLabel(point.date)}: ${plural(point.total, 'event')}`}
                    aria-pressed={pinnedDay === i}
                    onClick={() => setPinnedDay(pinnedDay === i ? null : i)}
                    className="group flex h-full min-w-0 flex-1 flex-col focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-text"
                  >
                    <span className="flex min-h-0 flex-1 items-end">
                      <span
                        className={`block w-full rounded-t-sm transition-colors ${
                          pinnedDay === i ? 'bg-brand-600' : 'bg-brand-500/70 group-hover:bg-brand-500'
                        }`}
                        style={{ height: `${barHeight}%` }}
                      />
                    </span>
                    <span
                      className={`mt-1.5 h-4 text-center font-mono text-mini ${showAxis ? 'text-muted' : 'text-transparent'}`}
                      aria-hidden="true"
                    >
                      {showAxis ? fmtShort(point.date) : '·'}
                    </span>
                  </button>
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
              Counts are events on file whose date falls in each week; one event can carry several sectors, products or
              tags. Names come from the sources and are not merged across spellings. Select a name to see its events in
              the archive.
            </p>
          </section>

          <section className="surface-card rounded-xl border border-line-1 p-4 sm:p-5">
            <h2 className="text-base font-bold text-heading">Power grid and internet outages</h2>
            <p className="mt-2 text-xs leading-relaxed text-muted">
              Where were the most customer-hours without power in the last 30 days? {fmtCount(shownCH)} customer-hours
              across {plural(topRegions.length, 'operator region')} in the last {windowDays} days. Some operators&apos;
              feeds were not read for the whole period, so their totals undercount; each row says how much is covered,
              and no week-on-week change is shown without 90% coverage in both weeks.
            </p>
            {(data.grid.anomalies > 0 || data.grid.corroborated > 0) && (
              <p className="mt-1 font-mono text-mini text-muted">
                {data.grid.anomalies > 0 &&
                  `${data.grid.anomalies} ${data.grid.anomalies === 1 ? 'anomaly' : 'anomalies'} `}
                {data.grid.corroborated > 0 && `${data.grid.corroborated} corroborated`}
              </p>
            )}
            {topRegions.length > 0 && (
              <div
                role="group"
                aria-label="Customer-hours without power by operator region, last 30 days"
                className="mt-4 space-y-0.5"
              >
                {topRegions.map((region, i) => {
                  const width = Math.max(2, Math.round((region.customer_hours / maxCH) * 100));
                  return (
                    <button
                      key={`${region.source}|${region.region}`}
                      type="button"
                      aria-label={`${region.source}, ${region.region}: ${fmtCount(region.customer_hours)} customer-hours, ${regionDetail(region, windowDays).replace(/ · /g, ', ')}.`}
                      aria-pressed={pinnedRegion === i}
                      onClick={() => setPinnedRegion(pinnedRegion === i ? null : i)}
                      className={`group grid w-full grid-cols-[minmax(0,9rem)_1fr_3.5rem] items-center gap-3 rounded-control px-2 py-1 text-left hover:bg-wash focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-text sm:grid-cols-[minmax(0,16rem)_1fr_4rem] ${
                        pinnedRegion === i ? 'bg-wash' : ''
                      }`}
                    >
                      <span className="truncate font-mono text-meta text-body">
                        {region.source}, {region.region}
                      </span>
                      <span className="block h-2.5 w-full overflow-hidden rounded bg-track">
                        <span
                          className={`block h-full rounded transition-colors ${
                            pinnedRegion === i ? 'bg-amber-500' : 'bg-amber-500/70 group-hover:bg-amber-500'
                          }`}
                          style={{ width: `${width}%` }}
                        />
                      </span>
                      <span className="text-right font-mono text-meta text-heading">
                        {fmtCount(region.customer_hours)}
                      </span>
                    </button>
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
              <strong className="font-semibold text-heading">Context, not cyber events.</strong> Outages are not
              attacks, and a cause is shown as the operator reports it. Customer-hours add up unplanned customers
              without power sampled every 15 minutes; a customer is a meter, not a person, and operators count them
              differently, so compare a region with itself over time rather than with other regions. Load shedding and
              grid emergencies are levels, not customers, and are not in the bars.
            </p>
          </section>

          <footer className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-1 pt-3 font-mono text-mini text-muted">
            <span>Built {fmtBuilt(data.built_at)}</span>
            <a
              href={UPSTREAM}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-accent-text hover:underline"
            >
              Original CyberView <ExternalLink size={11} aria-hidden="true" />
            </a>
            {data.grid.updated_at && <span className="ml-auto">Grid updated {fmtBuilt(data.grid.updated_at)}</span>}
          </footer>
        </div>
      )}
    </>
  );

  return bare ? (
    body
  ) : (
    <DataPageLayout
      backTo="/threatintel"
      icon={<TrendingUp size={28} />}
      title="CyberView — Trends"
      description="Replication of CyberView's weekly trends: events per day, changes by type/sector/country/actor/product/tag and power-grid signals."
      onRetry={feed.refetch}
      loading={feed.loading}
      error={feed.error}
      maxWidthClass="max-w-6xl"
    >
      {body}
    </DataPageLayout>
  );
}
