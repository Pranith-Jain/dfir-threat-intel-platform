import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Flame, ExternalLink, RefreshCw, Search, TrendingUp, ShieldAlert, Activity } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { DataPageLayout } from '../../components/DataPageLayout';
import { relativeAgo } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';
import HexBrainLink from '../../components/HexBrainLink';
import { SEVERITY_TONE } from '../../components/severity';

/**
 * Trending CVEs.
 *
 * Intruder's cvemon feed ranks CVEs by social-media discussion rather than by
 * technical severity. That is a different question from every other tab on
 * this page, and the interesting part is where the two disagree:
 *
 *   - A CVE trending but not yet in CISA KEV has attention ahead of
 *     confirmation. That is the window where a write-up has value, and it is
 *     what `trending_before_kev` counts.
 *   - A CVE in KEV that nobody is talking about is an under-reported
 *     actively-exploited vulnerability, which is arguably worse.
 *
 * So this tab leads with both signals side by side rather than sorting purely
 * by hype.
 */

interface TrendingCve {
  id: string;
  rank: number;
  hypeScore: number;
  description: string;
  cveUrl: string;
  publishedAt: string;
  cvss?: number | null;
  severity?: string;
  kev: boolean;
  trending_before_kev: boolean;
  epss?: number;
  poc_count?: number;
  products?: string[];
  cwe?: string[];
  published?: string;
}

interface TrendsResponse {
  generated_at: string;
  stale: boolean;
  source: { id: string; url: string; ok: boolean; count: number };
  count: number;
  trending_before_kev?: number;
  cves: TrendingCve[];
}

type Filter = 'all' | 'before-kev' | 'kev' | 'poc';

/** Subset of /data/cve-intel/index.json used by the cves.io pulse panel. */
interface CvesIoPulse {
  generatedAt: string;
  trending: Array<{
    id: string;
    title: string;
    severity: string;
    cvss: number | null;
    kev: boolean;
    signals24h: number;
    recent: number;
    baseline: number;
    trend: number;
    isNew: boolean;
    url: string;
  }>;
}

function momentumLabel(trend: number): string {
  if (trend <= -2) return 'cooling fast';
  if (trend === -1) return 'cooling';
  if (trend === 1) return 'rising';
  if (trend >= 2) return 'surging';
  return 'steady';
}

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: 'all', label: 'All trending' },
  { id: 'before-kev', label: 'Trending, not yet KEV' },
  { id: 'kev', label: 'In KEV' },
  { id: 'poc', label: 'Public exploit exists' },
];

/** Hype score → bar width. The feed's own range is roughly 0-30. */
function hypeWidth(score: number): string {
  return `${Math.max(4, Math.min(100, (score / 30) * 100))}%`;
}

function toneFor(severity?: string): string {
  switch (severity) {
    case 'CRITICAL':
      return SEVERITY_TONE.critical;
    case 'HIGH':
      return SEVERITY_TONE.high;
    case 'MEDIUM':
      return SEVERITY_TONE.medium;
    case 'LOW':
      return SEVERITY_TONE.low;
    default:
      return 'border-slate-300 dark:border-line-1 text-muted';
  }
}

export default function CveTrends(): JSX.Element {
  const { data, loading, error } = useDataFetch<TrendsResponse>({
    url: '/api/v1/cve-trends?enrich=1&limit=40',
    ttl: 10 * 60_000,
  });
  // Same corpus, different question: cvemon counts discussion, cves.io counts
  // attention signals across news, forums and repos. Watching both is how you
  // see a CVE that is technically severe but nobody has picked up yet.
  const { data: cvesIo } = useDataFetch<CvesIoPulse>({
    url: '/data/cve-intel/pulse.json',
    ttl: 10 * 60_000,
  });
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');

  const rows = useMemo(() => {
    const all = data?.cves ?? [];
    const q = query.trim().toLowerCase();
    return all.filter((c) => {
      if (filter === 'before-kev' && !c.trending_before_kev) return false;
      if (filter === 'kev' && !c.kev) return false;
      if (filter === 'poc' && !c.poc_count) return false;
      if (!q) return true;
      return (
        c.id.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        (c.products ?? []).some((p) => p.toLowerCase().includes(q))
      );
    });
  }, [data, query, filter]);

  const beforeKev = (data?.cves ?? []).filter((c) => c.trending_before_kev).length;
  const kevCount = (data?.cves ?? []).filter((c) => c.kev).length;
  const pocCount = (data?.cves ?? []).filter((c) => c.poc_count).length;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Flame className="h-5 w-5 text-orange-500" />}
      title="Trending CVEs"
      description="What practitioners are reading about right now, ranked by social discussion volume (Intruder cvemon) — not by severity. The gap between the two is the signal. Updated every 30 minutes."
    >
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-[11px] text-muted">
            {data?.generated_at ? `Updated ${relativeAgo(data.generated_at)}` : 'Loading…'}
          </p>
          <a
            href="https://cvemon.intruder.io"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[11px] text-muted underline hover:text-accent"
          >
            source: cvemon.intruder.io
          </a>
        </div>

        {/* The disagreement between attention and severity is the headline. */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Trending" value={data?.count ?? 0} />
          <Stat
            label="Not yet in KEV"
            value={beforeKev}
            tone="text-amber-600 dark:text-amber-400"
            hint="Discussion ahead of confirmation"
          />
          <Stat label="In KEV" value={kevCount} tone="text-rose-600 dark:text-rose-400" />
          <Stat label="With public exploit" value={pocCount} tone="text-orange-600 dark:text-orange-400" />
        </div>

        {data?.stale && (
          <p className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
            Showing cached data — cvemon.intruder.io did not respond on the last fetch.
          </p>
        )}

        {/* cves.io pulse — RD Intelligence's own attention ranking for the
            same corpus. Distinct from cvemon above: signals across news,
            forums and repos rather than raw social posts. */}
        {cvesIo && cvesIo.trending.length > 0 && (
          <section className="surface-card rounded-lg border border-line-1 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="flex items-center gap-1.5 text-sm font-semibold text-heading">
                <Activity className="h-4 w-4 text-rose-500" />
                cves.io pulse
                <span className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 text-[10px] font-mono font-normal text-muted">
                  RD Intelligence
                </span>
              </h2>
              <Link
                to="/threatintel/cves/cves?tab=rdintel"
                className="text-[11px] text-muted underline hover:text-accent"
              >
                full CVE mirror
              </Link>
            </div>
            <p className="mt-1 text-[11px] text-muted">
              Attention, not severity: signals counted across news, forums and code hosts, ranked independently of CVSS.
              Momentum compares the last 6h with the previous 42h.
            </p>
            <ol className="mt-2 grid gap-1.5 sm:grid-cols-2">
              {cvesIo.trending.slice(0, 10).map((c, i) => (
                <li
                  key={c.id}
                  className="flex items-center gap-2 rounded border border-line-1 bg-surface-100 px-2 py-1.5"
                >
                  <span className="w-4 shrink-0 font-mono text-[10px] text-muted">{i + 1}</span>
                  <a
                    href={c.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="shrink-0 font-mono text-xs font-semibold text-rose-600 hover:underline dark:text-rose-400"
                  >
                    {c.id}
                  </a>
                  {c.severity !== 'UNKNOWN' && (
                    <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-mono ${toneFor(c.severity)}`}>
                      {c.severity.slice(0, 4)}
                    </span>
                  )}
                  {c.kev && (
                    <span className="shrink-0 font-mono text-[9px] font-semibold text-rose-600 dark:text-rose-400">
                      KEV
                    </span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-[11px] text-body" title={c.title}>
                    {c.title}
                  </span>
                  <span
                    className={`shrink-0 font-mono text-[10px] ${
                      c.trend > 0 ? 'text-orange-600 dark:text-orange-400' : 'text-muted'
                    }`}
                    title={`${c.signals24h} signals in 24h · ${c.recent} in 6h · ${c.baseline} in 42h before`}
                  >
                    {momentumLabel(c.trend)} · {c.signals24h}
                  </span>
                </li>
              ))}
            </ol>
            <p className="mt-2 text-[10px] text-muted">
              Snapshot {relativeAgo(cvesIo.generatedAt)} · source{' '}
              <a
                href="https://cves.io/"
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-accent"
              >
                cves.io
              </a>
            </p>
          </section>
        )}

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search CVE, product, vendor…"
              className="w-full rounded border border-line-1 bg-surface px-8 py-1.5 text-sm outline-none focus:border-accent"
            />
          </div>
          <div className="flex flex-wrap gap-1">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                  filter === f.id
                    ? 'bg-accent/15 text-accent border border-accent/40'
                    : 'border border-line-1 text-muted hover:text-ink'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <p className="rounded border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300">
            {error}
          </p>
        )}

        {loading && !data && (
          <div className="flex items-center gap-2 text-sm text-muted">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Loading trending CVEs…
          </div>
        )}

        {!loading && rows.length === 0 && !error && (
          <p className="py-8 text-center text-sm text-muted">No trending CVEs match this filter.</p>
        )}

        <div className="space-y-2">
          {rows.map((c) => (
            <article
              key={c.id}
              className="rounded border border-line-1 bg-surface p-3 transition-colors hover:border-accent/40"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-muted">#{c.rank}</span>
                    <Link
                      to={`/threatintel/cve-list?q=${encodeURIComponent(c.id)}`}
                      className="font-mono text-sm font-semibold text-accent hover:underline"
                    >
                      {c.id}
                    </Link>
                    {c.severity && (
                      <span
                        className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${toneFor(c.severity)}`}
                      >
                        {c.severity}
                        {c.cvss != null ? ` ${c.cvss}` : ''}
                      </span>
                    )}
                    {c.kev ? (
                      <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-rose-700 dark:text-rose-300">
                        CISA KEV
                      </span>
                    ) : (
                      <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300">
                        Not in KEV
                      </span>
                    )}
                    {!!c.poc_count && (
                      <span className="rounded border border-orange-500/40 bg-orange-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-orange-700 dark:text-orange-300">
                        {c.poc_count} PoC
                      </span>
                    )}
                  </div>

                  <p className="mt-1.5 line-clamp-3 text-sm text-ink-soft">{c.description}</p>

                  {(c.products?.length || c.cwe?.length) && (
                    <p className="mt-1.5 flex flex-wrap gap-1 text-[11px] text-muted">
                      {c.products?.slice(0, 4).map((p) => (
                        <span key={p} className="rounded bg-surface-2 px-1.5 py-0.5">
                          {p}
                        </span>
                      ))}
                      {c.cwe?.slice(0, 2).map((w) => (
                        <span key={w} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono">
                          {w}
                        </span>
                      ))}
                    </p>
                  )}
                </div>

                {/* Hype bar — the actual quantity this feed measures. */}
                <div className="w-full shrink-0 sm:w-32">
                  <div className="flex items-center justify-between text-[10px] text-muted">
                    <span className="flex items-center gap-1">
                      <TrendingUp className="h-3 w-3" />
                      hype
                    </span>
                    <span className="font-mono">{c.hypeScore}</span>
                  </div>
                  <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-amber-500 to-orange-500"
                      style={{ width: hypeWidth(c.hypeScore) }}
                    />
                  </div>
                  {c.epss != null && (
                    <p className="mt-1 text-right text-[10px] text-muted">EPSS {(c.epss * 100).toFixed(1)}%</p>
                  )}
                </div>
              </div>

              <div className="mt-2 flex items-center gap-3 text-[11px] text-muted">
                <a
                  href={sanitizeUrl(`https://nvd.nist.gov/vuln/detail/${c.id}`)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 hover:text-accent"
                >
                  NVD <ExternalLink className="h-3 w-3" />
                </a>
                <a
                  href={`https://rdintel.com/cve/${c.id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-rose-600 hover:underline dark:text-rose-400"
                  title={`Open ${c.id} on RD Intelligence`}
                >
                  RDIntel <ExternalLink className="h-3 w-3" />
                </a>
                <HexBrainLink
                  cve={c.id}
                  className="inline-flex items-center gap-1 text-[11px] text-orange-600 dark:text-orange-300 hover:underline"
                />
                {c.cveUrl && (
                  <a
                    href={sanitizeUrl(c.cveUrl)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 hover:text-accent"
                  >
                    cvemon <ExternalLink className="h-3 w-3" />
                  </a>
                )}
                {!c.kev && (
                  <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400">
                    <ShieldAlert className="h-3 w-3" />
                    discussion ahead of CISA confirmation
                  </span>
                )}
                {(c.published || c.publishedAt) && (
                  <span className="ml-auto">{relativeAgo(c.published || c.publishedAt)}</span>
                )}
              </div>
            </article>
          ))}
        </div>

        <p className="pt-2 text-center text-[11px] text-muted">
          Hype scores from{' '}
          <a
            href="https://cvemon.intruder.io"
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-accent"
          >
            cvemon.intruder.io
          </a>
          . Scores reflect social discussion volume, not risk — cross-check against KEV and EPSS.
        </p>
      </div>
    </DataPageLayout>
  );
}

function Stat({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: number;
  tone?: string;
  hint?: string;
}): JSX.Element {
  return (
    <div className="rounded border border-line-1 bg-surface p-3">
      <div className={`text-2xl font-semibold tabular-nums ${tone ?? 'text-ink'}`}>{value}</div>
      <div className="mt-0.5 text-[11px] text-muted">{label}</div>
      {hint && <div className="mt-0.5 text-[10px] text-muted/80">{hint}</div>}
    </div>
  );
}
