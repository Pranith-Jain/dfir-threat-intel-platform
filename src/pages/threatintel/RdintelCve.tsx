import { useMemo, useState } from 'react';
import {
  Activity,
  BarChart3,
  Bug,
  ExternalLink,
  Flame,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  TrendingUp,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { SEVERITY_TONE, normalizeSeverity } from '../../components/severity';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';

/**
 * RD Intelligence CVE intelligence mirror.
 *
 * Mirrors the two public surfaces of rdintel.com:
 *   - /cve        corpus stats, all-time top threats, recent CVE browser
 *   - cves.io     "attention" ranking (signals, momentum) for the same corpus
 *
 * Data is a static snapshot built by scripts/sync-cve-intel.mjs (GitHub
 * Actions, every 6h). Scores are upstream values: CVSS from NVD/MITRE, EPSS
 * from FIRST, KEV from CISA, threat_score from RD Intelligence. Nothing is
 * recomputed here, and every row links to the upstream record.
 */

interface CveRow {
  id: string;
  title: string;
  description: string;
  published: string | null;
  modified: string | null;
  severity: string;
  cvss: number | null;
  epss: number | null;
  threatScore: number | null;
  kev: boolean;
  poc: number;
  sigma: number;
  exploitStatus: string;
  cwes: string[];
  products: string[];
}

interface TopThreat {
  id: string;
  severity: string | null;
  kev: boolean;
  score: number | null;
  url: string;
}

interface TrendingCve {
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
  hourly: number[];
  url: string;
}

interface PreCve {
  id: string;
  tier: string;
  title: string;
  repo: string;
  detected: string;
  when: string;
  url: string;
}

interface CveIntelDataset {
  generatedAt: string;
  upstream: {
    stats: string;
    cves: string;
    pulse: string;
    statsUpdated: string | null;
    pulseAsOf: string | null;
  };
  stats: {
    total: number | null;
    critical: number | null;
    high: number | null;
    medium: number | null;
    low: number | null;
    unscored: number | null;
    recent24h: number | null;
    recent7d: number | null;
    recent30d: number | null;
    recent90d: number | null;
    kev: number | null;
    epssCovered: number | null;
    publicExploit: number | null;
    exploitDb: number | null;
    detectionRules: number | null;
    githubAdvisories: number | null;
    hackerone: number | null;
    kev7d: number | null;
    ransomware: number | null;
    highEpss: number | null;
    daily: Array<{ date: string; count: number }>;
  };
  recent: CveRow[];
  critical: CveRow[];
  topThreats: TopThreat[];
  trending: TrendingCve[];
  pulseSeries: Array<{ t: string; total: number }>;
  recentHours: number;
  preCve: PreCve[];
}

type SevFilter = 'all' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

const SEV_FILTERS: Array<{ id: SevFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'CRITICAL', label: 'Critical' },
  { id: 'HIGH', label: 'High' },
  { id: 'MEDIUM', label: 'Medium' },
  { id: 'LOW', label: 'Low' },
];

const PAGE_SIZE = 25;

function fmt(n: number | null | undefined): string {
  return n == null ? '-' : n.toLocaleString('en-US');
}

function pct(n: number | null | undefined): string {
  return n == null ? '-' : `${(n * 100).toFixed(1)}%`;
}

function sevPill(sev: string): string {
  return SEVERITY_TONE[normalizeSeverity(sev)];
}

function momentum(trend: number): { label: string; cls: string } {
  switch (trend) {
    case -2:
      return { label: 'cooling fast', cls: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300' };
    case -1:
      return { label: 'cooling', cls: 'border-sky-500/30 text-sky-600 dark:text-sky-400' };
    case 1:
      return { label: 'rising', cls: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300' };
    case 2:
      return { label: 'surging', cls: 'border-rose-500/50 bg-rose-500/15 text-rose-700 dark:text-rose-300' };
    default:
      return { label: 'steady', cls: 'border-line-2 text-muted' };
  }
}

function Stat({ label, value, tone, hint }: { label: string; value: string; tone?: string; hint?: string }) {
  return (
    <div className="surface-card rounded-xl border border-line-1 px-4 py-3" title={hint}>
      <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className={`text-xl font-semibold tabular-nums ${tone ?? 'text-heading'}`}>{value}</div>
    </div>
  );
}

/** 48h signal sparkline. Values are cves.io attention counters. */
function PulseSparkline({ series }: { series: Array<{ t: string; total: number }> }) {
  if (series.length < 2) return null;
  const width = 640;
  const height = 64;
  const max = Math.max(...series.map((p) => p.total), 1);
  const step = width / (series.length - 1);
  const points = series.map(
    (p, i) => `${(i * step).toFixed(1)},${(height - (p.total / max) * (height - 6) - 3).toFixed(1)}`
  );
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="h-16 w-full"
      role="img"
      aria-label={`cves.io attention signals over the last ${series.length} hours, peak ${max}`}
      preserveAspectRatio="none"
    >
      <polyline points={points.join(' ')} fill="none" stroke="currentColor" strokeWidth="2" className="text-rose-500" />
      <polyline
        points={`0,${height} ${points.join(' ')} ${width},${height}`}
        fill="currentColor"
        className="text-rose-500/10"
        stroke="none"
      />
    </svg>
  );
}

export default function RdintelCve({ bare = false }: { bare?: boolean }): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<CveIntelDataset>({
    url: '/data/cve-intel/index.json',
    ttl: 10 * 60_000,
  });

  const [query, setQuery] = useState('');
  const [sev, setSev] = useState<SevFilter>('all');
  const [kevOnly, setKevOnly] = useState(false);
  const [pocOnly, setPocOnly] = useState(false);
  const [visible, setVisible] = useState(PAGE_SIZE);

  const rows = useMemo(() => {
    const all = data?.recent ?? [];
    const q = query.trim().toLowerCase();
    return all.filter((c) => {
      if (sev !== 'all' && c.severity !== sev) return false;
      if (kevOnly && !c.kev) return false;
      if (pocOnly && c.poc === 0) return false;
      if (!q) return true;
      return (
        c.id.toLowerCase().includes(q) ||
        c.title.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.cwes.some((w) => w.toLowerCase().includes(q)) ||
        c.products.some((p) => p.toLowerCase().includes(q))
      );
    });
  }, [data, query, sev, kevOnly, pocOnly]);

  const shown = rows.slice(0, visible);
  const stats = data?.stats;
  const maxDaily = Math.max(...(stats?.daily ?? []).map((d) => d.count), 1);

  const body = data ? (
    <div className="space-y-8">
      <AiSummaryCard
        surface="RDIntel CVE Intelligence"
        items={data.recent.slice(0, 15).map((c) => ({
          title: `${c.id} — ${c.title}`,
          body: `${c.severity} · CVSS ${c.cvss ?? '-'} · EPSS ${pct(c.epss)} · threat score ${c.threatScore ?? '-'}${
            c.kev ? ' · CISA KEV' : ''
          }${c.poc > 0 ? ` · ${c.poc} PoC` : ''}`,
          source: `https://rdintel.com/cve/${c.id}`,
        }))}
        dayKey={data.generatedAt.slice(0, 10)}
        requireAdmin={false}
      />

      {/* Corpus stats */}
      <section aria-labelledby="rdi-stats">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 id="rdi-stats" className="flex items-center gap-2 text-lg font-bold text-heading">
            <BarChart3 size={18} /> Corpus
          </h2>
          <span className="text-[11px] text-muted">
            synced {relativeAgo(data.generatedAt)} · {fmt(stats?.total)} CVEs indexed
          </span>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <Stat label="Total CVEs" value={fmt(stats?.total)} />
          <Stat label="Last 24h" value={fmt(stats?.recent24h)} />
          <Stat label="Last 7 days" value={fmt(stats?.recent7d)} />
          <Stat label="Last 30 days" value={fmt(stats?.recent30d)} />
          <Stat
            label="Critical"
            value={fmt(stats?.critical)}
            tone="text-rose-600 dark:text-rose-400"
            hint="Corpus-wide CVSS critical count"
          />
          <Stat
            label="High"
            value={fmt(stats?.high)}
            tone="text-orange-600 dark:text-orange-400"
            hint="Corpus-wide CVSS high count"
          />
          <Stat
            label="Public exploit"
            value={fmt(stats?.publicExploit)}
            tone="text-rose-600 dark:text-rose-400"
            hint="CVEs with a public GitHub PoC repository"
          />
          <Stat label="Exploit-DB entries" value={fmt(stats?.exploitDb)} hint="CVEs with an Exploit-DB record" />
          <Stat label="Detection rules" value={fmt(stats?.detectionRules)} hint="CVEs with a Nuclei template" />
          <Stat label="High EPSS" value={fmt(stats?.highEpss)} hint="EPSS ≥ 0.1" />
          <Stat label="KEV total" value={fmt(stats?.kev)} tone="text-rose-600 dark:text-rose-400" />
          <Stat
            label="KEV added 7d"
            value={fmt(stats?.kev7d)}
            hint={`${fmt(stats?.ransomware)} KEV entries are linked to known ransomware use`}
          />
        </div>

        {/* 30-day publication volume */}
        {(stats?.daily?.length ?? 0) > 0 && (
          <div className="surface-card mt-3 rounded-xl border border-line-1 p-4">
            <div className="mb-2 flex items-center justify-between text-[11px] text-muted">
              <span className="uppercase tracking-wider">Daily CVE publications · last 30 days</span>
              <span>peak {fmt(maxDaily)}</span>
            </div>
            <div className="flex h-16 items-end gap-1">
              {stats?.daily.map((d) => (
                <div
                  key={d.date}
                  className="min-w-0 flex-1 rounded-t bg-brand-500/60 dark:bg-brand-400/60"
                  style={{ height: `${Math.max(3, (d.count / maxDaily) * 100)}%` }}
                  title={`${d.date}: ${d.count} CVEs`}
                />
              ))}
            </div>
            <div className="mt-2 flex justify-between text-[10px] text-muted">
              <span>{stats?.daily[0]?.date}</span>
              <span>{stats?.daily[stats.daily.length - 1]?.date}</span>
            </div>
          </div>
        )}
      </section>

      {/* Attention + all-time top threats */}
      <section className="grid gap-6 lg:grid-cols-2" aria-labelledby="rdi-attention">
        <div>
          <h2 id="rdi-attention" className="mb-1 flex items-center gap-2 text-lg font-bold text-heading">
            <Flame size={18} className="text-orange-500" /> Trending on cves.io
          </h2>
          <p className="mb-3 text-[11px] text-muted">
            Ranked by attention (mentions across news, forums, repos), not severity. Momentum compares the last{' '}
            {data.recentHours}h with the 42h before.
          </p>
          {data.pulseSeries.length > 1 && (
            <div className="surface-card mb-3 rounded-xl border border-line-1 p-3">
              <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wider text-muted">
                <span>signals per hour · last {data.pulseSeries.length}h</span>
                <span>{data.upstream.pulseAsOf?.slice(0, 16).replace('T', ' ') ?? ''} UTC</span>
              </div>
              <PulseSparkline series={data.pulseSeries} />
            </div>
          )}
          <ol className="space-y-2">
            {data.trending.slice(0, 10).map((c, i) => {
              const m = momentum(c.trend);
              return (
                <li key={c.id} className="surface-card rounded-lg border border-line-1 p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-mono text-[10px] text-muted">#{i + 1}</span>
                        <a
                          href={c.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-sm font-semibold text-rose-600 hover:underline dark:text-rose-400"
                        >
                          {c.id} <ExternalLink size={10} />
                        </a>
                        {c.severity !== 'UNKNOWN' && (
                          <span className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${sevPill(c.severity)}`}>
                            {c.severity}
                          </span>
                        )}
                        {c.kev && (
                          <span className="rounded border border-rose-500/40 px-1.5 py-0.5 text-[10px] font-mono text-rose-600 dark:text-rose-400">
                            KEV
                          </span>
                        )}
                        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${m.cls}`}>{m.label}</span>
                        {c.isNew && (
                          <span className="rounded border border-sky-500/40 px-1.5 py-0.5 text-[10px] font-mono text-sky-600 dark:text-sky-400">
                            new
                          </span>
                        )}
                      </div>
                      <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-body">{c.title}</p>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className="font-mono text-sm font-semibold tabular-nums text-heading">{c.signals24h}</div>
                      <div className="text-[10px] text-muted">signals</div>
                    </div>
                  </div>
                  <div className="mt-1.5 flex items-center gap-3 text-[10px] text-muted">
                    <span title="Signals in the last 6 hours">6h: {c.recent}</span>
                    <span title="Signals in the 42 hours before that">42h before: {c.baseline}</span>
                    {c.cvss != null && <span>CVSS {c.cvss}</span>}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>

        <div>
          <h2 className="mb-1 flex items-center gap-2 text-lg font-bold text-heading">
            <ShieldAlert size={18} className="text-rose-500" /> Top threats
          </h2>
          <p className="mb-3 text-[11px] text-muted">
            All-time highest RD Intelligence threat scores. Old CVEs stay here while they are still being exploited,
            which is the point of the band.
          </p>
          <ol className="surface-card divide-y divide-line-1 rounded-xl border border-line-1">
            {data.topThreats.map((t, i) => (
              <li key={t.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px] text-muted">{String(i + 1).padStart(2, '0')}</span>
                    <a
                      href={t.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-sm font-semibold text-heading hover:text-rose-600 dark:hover:text-rose-400"
                    >
                      {t.id} <ExternalLink size={10} />
                    </a>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-[10px]">
                    {t.severity && (
                      <span className={`rounded border px-1.5 py-0.5 font-mono ${sevPill(t.severity)}`}>
                        {t.severity}
                      </span>
                    )}
                    {t.kev && <span className="font-mono font-medium text-rose-600 dark:text-rose-400">KEV</span>}
                  </div>
                </div>
                <span className="font-mono text-sm font-bold tabular-nums text-rose-600 dark:text-rose-400">
                  {t.score ?? '-'}
                </span>
              </li>
            ))}
          </ol>

          {data.preCve.length > 0 && (
            <>
              <h3 className="mb-2 mt-6 flex items-center gap-2 text-sm font-bold text-heading">
                <Sparkles size={15} className="text-sky-500" /> Before the CVE
              </h3>
              <p className="mb-2 text-[11px] text-muted">
                Vulnerabilities found in the wild before an identifier was assigned (RDI records).
              </p>
              <ul className="space-y-1.5">
                {data.preCve.map((p) => (
                  <li key={p.id} className="rounded-lg border border-line-1 bg-surface-100 px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-muted">{p.id}</span>
                      <span className="rounded border border-sky-500/40 px-1 py-0.5 text-[10px] font-mono text-sky-600 dark:text-sky-400">
                        {p.tier}
                      </span>
                      <span className="ml-auto text-[10px] text-muted">{p.when}</span>
                    </div>
                    <a
                      href={p.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-0.5 flex items-center gap-1 text-xs font-semibold text-heading hover:underline"
                    >
                      {p.title} <ExternalLink size={10} />
                    </a>
                    <div className="font-mono text-[10px] text-muted">{p.repo}</div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </section>

      {/* Recent CVE browser */}
      <section aria-labelledby="rdi-browse">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="rdi-browse" className="flex items-center gap-2 text-lg font-bold text-heading">
              <Activity size={18} /> Recent CVEs
            </h2>
            <p className="mt-1 text-[11px] text-muted">
              {fmt(data.recent.length)} newest records in the snapshot, enriched with CVSS, EPSS, KEV and PoC counts.
              Full corpus search lives on rdintel.com.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <a
              href="https://rdintel.com/cve"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-muted underline hover:text-accent"
            >
              upstream search <ExternalLink size={10} />
            </a>
            <button
              type="button"
              onClick={() => void refetch()}
              className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 text-[11px] text-muted hover:text-heading"
            >
              <RefreshCw size={11} /> refresh
            </button>
          </div>
        </div>

        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="relative min-w-[220px] flex-1">
            <span className="sr-only">Search CVEs</span>
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setVisible(PAGE_SIZE);
              }}
              placeholder="CVE id, product, CWE, keyword…"
              className="w-full rounded-lg border border-line-1 bg-surface-100 py-2 pl-8 pr-3 text-sm text-body placeholder:text-muted focus:border-brand-500 focus:outline-none"
            />
          </label>
          <div className="flex flex-wrap gap-1">
            {SEV_FILTERS.map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => {
                  setSev(f.id);
                  setVisible(PAGE_SIZE);
                }}
                aria-pressed={sev === f.id}
                className={`rounded border px-2.5 py-1.5 text-xs font-mono ${
                  sev === f.id
                    ? 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                    : 'border-line-1 text-muted hover:text-heading'
                }`}
              >
                {f.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => {
                setKevOnly((v) => !v);
                setVisible(PAGE_SIZE);
              }}
              aria-pressed={kevOnly}
              className={`rounded border px-2.5 py-1.5 text-xs font-mono ${
                kevOnly
                  ? 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  : 'border-line-1 text-muted hover:text-heading'
              }`}
            >
              KEV only
            </button>
            <button
              type="button"
              onClick={() => {
                setPocOnly((v) => !v);
                setVisible(PAGE_SIZE);
              }}
              aria-pressed={pocOnly}
              className={`rounded border px-2.5 py-1.5 text-xs font-mono ${
                pocOnly
                  ? 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300'
                  : 'border-line-1 text-muted hover:text-heading'
              }`}
            >
              has PoC
            </button>
          </div>
        </div>

        <p className="mb-2 text-[11px] font-mono text-muted">
          {rows.length.toLocaleString()} match{rows.length === 1 ? '' : 'es'} · showing{' '}
          {Math.min(shown.length, rows.length).toLocaleString()}
        </p>

        <ul className="space-y-2">
          {shown.map((c) => (
            <li key={c.id} className="surface-card rounded-lg border border-line-1 p-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <a
                    href={`https://rdintel.com/cve/${c.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-sm font-semibold text-rose-600 hover:underline dark:text-rose-400"
                    title={`Open ${c.id} on RD Intelligence`}
                  >
                    {c.id} <ExternalLink size={10} />
                  </a>
                  <span className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${sevPill(c.severity)}`}>
                    {c.severity}
                    {c.cvss != null ? ` ${c.cvss.toFixed(1)}` : ''}
                  </span>
                  {c.kev && (
                    <span className="rounded border border-rose-500/40 px-1.5 py-0.5 text-[10px] font-mono text-rose-600 dark:text-rose-400">
                      KEV
                    </span>
                  )}
                  {c.poc > 0 && (
                    <span
                      className="rounded border border-orange-500/40 px-1.5 py-0.5 text-[10px] font-mono text-orange-600 dark:text-orange-400"
                      title="Public PoC repositories indexed upstream"
                    >
                      {c.poc} PoC
                    </span>
                  )}
                  {c.epss != null && (
                    <span
                      className="rounded border border-line-1 px-1.5 py-0.5 text-[10px] font-mono text-muted"
                      title="FIRST EPSS 30-day exploitation probability"
                    >
                      EPSS {pct(c.epss)}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-[10px] text-muted">
                  {c.threatScore != null && (
                    <span className="font-mono" title="RD Intelligence composite threat score">
                      score {c.threatScore}
                    </span>
                  )}
                  <span>{relativeAgo(c.published ?? c.modified ?? '')}</span>
                </div>
              </div>

              <p className="mt-1 text-sm font-semibold leading-snug text-heading">{c.title}</p>
              {c.description && <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-body">{c.description}</p>}

              <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted">
                {c.products.slice(0, 3).map((p) => (
                  <span key={p} className="font-mono">
                    {p}
                  </span>
                ))}
                {c.cwes.slice(0, 3).map((w) => (
                  <span key={w} className="font-mono">
                    {w}
                  </span>
                ))}
                <a
                  href={`https://hexbrainai.com/cve/${c.id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ml-auto inline-flex items-center gap-1 text-orange-600 hover:underline dark:text-orange-300"
                  title={`Open ${c.id} on HexBrain`}
                >
                  HexBrain <ExternalLink size={9} />
                </a>
              </div>
            </li>
          ))}
        </ul>

        {rows.length === 0 && (
          <p className="mt-4 flex items-center gap-2 text-sm text-muted">
            <Search size={14} /> No CVEs match those filters in the snapshot.
          </p>
        )}

        {visible < rows.length && (
          <div className="mt-4 flex justify-center">
            <button
              type="button"
              onClick={() => setVisible((v) => v + PAGE_SIZE)}
              className="rounded border border-line-1 px-4 py-2 text-xs font-mono text-muted hover:border-rose-500/40 hover:text-heading"
            >
              load {Math.min(PAGE_SIZE, rows.length - visible)} more
            </button>
          </div>
        )}
      </section>

      <section className="surface-card rounded-xl border border-line-1 p-4 text-[11px] leading-relaxed text-muted">
        <p className="mb-1 flex items-center gap-1.5 font-semibold text-heading">
          <TrendingUp size={13} /> Provenance
        </p>
        <p>
          Snapshot built {data.generatedAt.slice(0, 16).replace('T', ' ')} UTC from{' '}
          <a
            href={data.upstream.stats}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-accent"
          >
            rdintel.com/api/cve/stats
          </a>{' '}
          and{' '}
          <a
            href={data.upstream.cves}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-accent"
          >
            rdintel.com/api/cve
          </a>
          ; attention signals from{' '}
          <a
            href={data.upstream.pulse}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-accent"
          >
            cves.io
          </a>
          . Scores are upstream values (CVSS, FIRST EPSS, CISA KEV, RD Intelligence threat score). This mirror does not
          recompute them. Refresh cadence: 6 hours via GitHub Actions.
        </p>
      </section>
    </div>
  ) : null;

  if (bare) {
    if (loading && !data) {
      return <p className="py-10 text-center text-sm text-muted">Loading CVE intelligence…</p>;
    }
    if (error && !data) {
      return (
        <p className="py-10 text-center text-sm text-rose-600 dark:text-rose-400">
          CVE intelligence snapshot unavailable: {error}
        </p>
      );
    }
    return <>{body}</>;
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Bug size={28} />}
      title="CVE Intelligence"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
            Mirror of rdintel.com/cve
          </span>
          <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
            Attention data from cves.io
          </span>
          {data?.upstream.statsUpdated && (
            <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
              Upstream updated {data.upstream.statsUpdated.slice(0, 16).replace('T', ' ')} UTC
            </span>
          )}
        </span>
      }
      loading={loading && !data}
      error={error}
      onRetry={() => void refetch()}
    >
      {body}
    </DataPageLayout>
  );
}
