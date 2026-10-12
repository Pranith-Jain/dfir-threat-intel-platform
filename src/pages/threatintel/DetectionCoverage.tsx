import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataState } from '../../components/DataState';
import { DataPageLayout } from '../../components/DataPageLayout';
import { fetchJsonCached } from '../../lib/api-client';
import { memoryCache } from '../../infrastructure/cache/memory-cache';
import { Radar, RefreshCw, ExternalLink, ShieldAlert, Search } from 'lucide-react';

// ── types ────────────────────────────────────────────────────────────

interface CoverageRow {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
  epss: number | null;
  /** Change over the sampled history window. */
  epssDelta: number | null;
  /** Points per day; negative means falling. */
  epssTrend: number | null;
  epssHistoryPoints: number;
  cvss: number | null;
  severity: string | null;
  /** Rules citing this CVE id. Strong evidence. */
  explicit: number;
  /** Rules naming this CVE's product. Weaker. */
  inferred: number;
  inferredTotal: number;
  exploits: number;
  explicitSources: string[];
  inferredSources: string[];
  coveredBy: string[];
  covered: boolean;
  coveredAny: boolean;
}

interface PlatformCoverage {
  id: string;
  label: string;
  format: string;
  homepage: string;
  license: string;
  licenseUrl: string;
  attribution: string;
  accessUrl: string;
  rules: number;
  status: string;
  kevTotal: number;
  kevCovered: number;
  kevCoveredExplicit: number;
  kevCoveragePct: number | null;
}

interface BandCell {
  cvss: string;
  cvssLabel: string;
  total: number;
  covered: number;
  coveragePct: number | null;
  avgCvss: number | null;
}

interface BandRow {
  epss: string;
  epssLabel: string;
  cells: BandCell[];
}

interface TechniqueRow {
  id: string;
  total: number;
  byPlatform: Record<string, number>;
  coveredHere: number;
  coveredElsewhere: number;
}

interface TechniqueResponse {
  total: number;
  techniquesIndexed: number;
  filters: { platform: string | null; compareTo: string | null; gapsOnly: boolean };
  techniques: TechniqueRow[];
}

interface LibraryTechnique {
  id: string;
  rules: number;
}

interface LibraryRule {
  rid: string;
  source: string;
  title: string;
  url: string | null;
  level: string | null;
  techniques: string[];
  cves: string[];
  updated: string | null;
}

interface CoverageResponse {
  schemaVersion: string;
  generatedAt: string;
  indexAgeHours: number;
  scope: {
    kevTotal: number;
    kevEvaluated: number;
    coveredExplicit: number;
    coveredAny: number;
    gaps: number;
    coveragePct: number | null;
    coverageExplicitPct: number | null;
    withExploitAvailable: number;
    ransomwareLinked: number;
    gapsWithExploitAvailable: number;
    withEpssHistory: number;
    risingFast: number;
  };
  ruleCorpora: {
    detections: number;
    exploits: number;
    rules: number;
    detectionRules: number;
    detectionRulesCveTagged: number;
    detectionCveLinkRate: number;
    techniques: number;
    distinctCves: number;
    sources: Array<{
      id: string;
      label: string;
      kind: string;
      format: string;
      homepage: string;
      license: string;
      licenseUrl: string;
      attribution: string;
      accessUrl: string;
      ruleCount: number;
      scanned: number;
      status: string;
    }>;
  };
  perPlatform: PlatformCoverage[];
  bands: {
    cvssBands: Array<{ id: string; label: string; min: number; max: number }>;
    epssBands: Array<{ id: string; label: string; min: number | null; max: number | null }>;
    matrix: BandRow[];
  };
  rows: CoverageRow[];
  page: { limit: number; offset: number; total: number; hasMore: boolean };
  filters: {
    platform: string | null;
    days: number | null;
    ransomwareOnly: boolean;
    coveredOnly: boolean;
    gapOnly: boolean;
    tier: 'explicit' | 'any';
  };
}

interface LibraryResponse {
  total: number;
  techniques: LibraryTechnique[];
  rules: LibraryRule[];
}

type TabId = 'gaps' | 'platforms' | 'bands' | 'techniques' | 'library';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  {
    id: 'gaps',
    label: 'Coverage Gaps',
    desc: 'Known-exploited vulnerabilities with no published detection rule, in any tier.',
  },
  {
    id: 'platforms',
    label: 'By Platform',
    desc: 'Which SIEM or rule format actually has coverage, and how much of KEV it reaches.',
  },
  {
    id: 'techniques',
    label: 'Technique Gaps',
    desc: 'ATT&CK techniques your platform has nothing for, and another platform does. The rules worth porting.',
  },
  {
    id: 'bands',
    label: 'Severity × Exploitation',
    desc: 'Where vendor severity and measured exploitation likelihood disagree.',
  },
  {
    id: 'library',
    label: 'Rule Library',
    desc: 'Every indexed rule behind the coverage numbers, browsable by ATT&CK technique.',
  },
];

// ── shared bits ──────────────────────────────────────────────────────

function SeverityTag({ score, severity }: { score: number | null; severity: string | null }): JSX.Element {
  if (score === null) return <span className="text-muted font-mono text-xs">no CVSS</span>;
  const tone =
    (score ?? 0) >= 9
      ? 'text-rose-600 dark:text-rose-400'
      : (score ?? 0) >= 7
        ? 'text-amber-600 dark:text-amber-400'
        : (score ?? 0) >= 4
          ? 'text-yellow-700 dark:text-yellow-500'
          : 'text-muted';
  return (
    <span className={`font-mono text-xs font-semibold ${tone}`} title={severity ?? undefined}>
      {score.toFixed(1)}
    </span>
  );
}

function EpssTag({ epss, trend }: { epss: number | null; trend?: number | null }): JSX.Element {
  if (epss === null) return <span className="text-muted font-mono text-xs">—</span>;
  const pct = epss * 100;
  // Rising fast is the signal the history buys us: a modest score climbing
  // steadily outranks a higher one that has been flat for a month, because the
  // first one is still moving. Threshold is 0.1 percentage points per day.
  const rising = (trend ?? 0) > 0.001;
  const falling = (trend ?? 0) < -0.001;
  const tone =
    pct >= 10 || rising
      ? 'text-rose-600 dark:text-rose-400'
      : pct >= 1
        ? 'text-amber-600 dark:text-amber-400'
        : 'text-muted';
  return (
    <span className={`font-mono text-xs ${tone}`} title="EPSS: probability of exploitation in the next 30 days">
      {pct < 0.1 ? '<0.1' : pct.toFixed(1)}%{rising && <span aria-label="rising"> ▲</span>}
      {falling && (
        <span aria-label="falling" className="opacity-60">
          {' '}
          ▼
        </span>
      )}
    </span>
  );
}

/**
 * Coverage badge, showing both tiers.
 *
 * The two-tier display is the whole point: collapsing them produces a number
 * that reads as coverage but is mostly a statement about which vendors tag
 * their rules with CVE ids.
 */
function CoverageBadge({ row }: { row: CoverageRow }): JSX.Element {
  if (row.explicit > 0) {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs font-mono text-emerald-700 dark:text-emerald-400"
        title={`${row.explicit} rule(s) cite this CVE id`}
      >
        {row.explicit} cited
      </span>
    );
  }
  if (row.inferred > 0) {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs font-mono text-sky-700 dark:text-sky-400"
        title={`${row.inferred} rule(s) name this product (${row.inferredTotal} before truncation). Weaker evidence than citing the CVE.`}
      >
        {row.inferred} by product
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs font-mono ${
        row.exploits > 0 ? 'text-rose-600 dark:text-rose-400 font-semibold' : 'text-muted'
      }`}
      title={
        row.exploits > 0 ? 'No published detection at all, but public exploit code exists' : 'No published detection'
      }
    >
      <ShieldAlert size={12} aria-hidden />
      gap{row.exploits > 0 ? ` · ${row.exploits} exploit${row.exploits === 1 ? '' : 's'}` : ''}
    </span>
  );
}

// ── tabs ─────────────────────────────────────────────────────────────

function GapList({ data }: { data: CoverageResponse }): JSX.Element {
  const rows = data.rows;
  if (rows.length === 0) {
    return <p className="text-sm text-muted font-mono py-6">No entries match these filters.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line-2 text-left font-mono text-xs uppercase tracking-wider text-muted">
            <th className="py-2 pr-3">CVE</th>
            <th className="py-2 pr-3">Vendor / Product</th>
            <th className="py-2 pr-3 text-right">CVSS</th>
            <th className="py-2 pr-3 text-right">EPSS</th>
            <th className="py-2 pr-3">Detection</th>
            <th className="py-2 pr-3 text-right">Added</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.cveId} className="border-b border-line-1 hover:bg-surface-2">
              <td className="py-2 pr-3 whitespace-nowrap">
                <Link to={`/threatintel/cve/${r.cveId}`} className="font-mono text-accent hover:underline">
                  {r.cveId}
                </Link>
                {r.ransomware && (
                  <span
                    className="ml-2 text-[10px] font-mono uppercase text-rose-600 dark:text-rose-400"
                    title="CISA: known ransomware campaign use"
                  >
                    ransomware
                  </span>
                )}
              </td>
              <td className="py-2 pr-3 max-w-md">
                <div className="truncate font-mono text-xs text-muted">
                  {r.vendor} {r.product}
                </div>
                <div className="truncate text-xs" title={r.name}>
                  {r.name}
                </div>
              </td>
              <td className="py-2 pr-3 text-right">
                <SeverityTag score={r.cvss} severity={r.severity} />
              </td>
              <td className="py-2 pr-3 text-right">
                <EpssTag epss={r.epss} trend={r.epssTrend} />
              </td>
              <td className="py-2 pr-3">
                <CoverageBadge row={r} />
              </td>
              <td className="py-2 pr-3 text-right font-mono text-xs text-muted whitespace-nowrap">{r.dateAdded}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-xs font-mono text-muted">
        showing {rows.length} of {data.page.total} ·{' '}
        {data.page.hasMore ? <span>raise ?limit or page with ?offset to see more</span> : 'end of results'}
      </p>
    </div>
  );
}

function PlatformTable({ data }: { data: CoverageResponse }): JSX.Element {
  return (
    <div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line-2 text-left font-mono text-xs uppercase tracking-wider text-muted">
            <th className="py-2 pr-3">Platform</th>
            <th className="py-2 pr-3">Format</th>
            <th className="py-2 pr-3 text-right">Rules indexed</th>
            <th className="py-2 pr-3">KEV covered</th>
            <th className="py-2 pr-3 text-right">Coverage</th>
            <th className="py-2 pr-3" />
          </tr>
        </thead>
        <tbody>
          {data.perPlatform.map((p) => (
            <tr key={p.id} className="border-b border-line-1">
              <td className="py-2 pr-3 font-semibold">{p.label}</td>
              <td className="py-2 pr-3 text-xs text-muted">{p.format}</td>
              <td className="py-2 pr-3 text-right font-mono text-xs">{p.rules.toLocaleString()}</td>
              <td className="py-2 pr-3 font-mono text-xs">
                {p.kevCovered.toLocaleString()} / {p.kevTotal.toLocaleString()}
              </td>
              <td className="py-2 pr-3">
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-32 bg-surface-3 rounded-full overflow-hidden" aria-hidden>
                    <div className="h-full bg-accent" style={{ width: `${Math.min(p.kevCoveragePct ?? 0, 100)}%` }} />
                  </div>
                  <span className="font-mono text-xs">{p.kevCoveragePct === null ? '—' : `${p.kevCoveragePct}%`}</span>
                </div>
              </td>
              <td className="py-2 pr-3 text-right">
                <a
                  href={p.homepage}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 text-xs font-mono text-accent hover:underline"
                >
                  repo <ExternalLink size={11} aria-hidden />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="mt-6">
        <h3 className="text-sm font-semibold mb-2">Exploit corpora</h3>
        <p className="text-xs text-muted mb-3">
          Separate from detection coverage. A public exploit proves a bug is usable against you; it says nothing about
          whether anything alerts on it.
        </p>
        <table className="w-full text-sm">
          <tbody>
            {data.ruleCorpora.sources
              .filter((s) => s.kind === 'exploit')
              .map((s) => (
                <tr key={s.id} className="border-b border-line-1">
                  <td className="py-2 pr-3 font-semibold">{s.label}</td>
                  <td className="py-2 pr-3 text-xs text-muted">{s.format}</td>
                  <td className="py-2 pr-3 text-right font-mono text-xs">{s.ruleCount.toLocaleString()}</td>
                  <td className="py-2 pr-3 text-xs text-muted">
                    <a
                      href={s.homepage}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-accent hover:underline"
                    >
                      {s.license}
                    </a>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function BandMatrix({ data }: { data: CoverageResponse }): JSX.Element {
  const { matrix, cvssBands } = data.bands;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr>
            <th className="py-2 pr-3 text-left font-mono text-xs uppercase tracking-wider text-muted align-bottom">
              EPSS ↓ / CVSS →
            </th>
            {cvssBands.map((b) => (
              <th key={b.id} className="py-2 px-3 text-center font-mono text-xs uppercase tracking-wider text-muted">
                {b.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row) => (
            <tr key={row.epss}>
              <th scope="row" className="py-2 pr-3 text-left font-mono text-xs font-semibold whitespace-nowrap">
                {row.epssLabel}
              </th>
              {row.cells.map((cell) => {
                // Heat scales with the share of the cell that HAS a rule, so a
                // cell of 40 covered CVEs reads very differently from a cell of
                // 40 with no coverage at all.
                const cov = cell.coveragePct ?? 0;
                const bg =
                  cell.total === 0
                    ? 'bg-surface-1'
                    : cov >= 75
                      ? 'bg-emerald-500/12'
                      : cov >= 40
                        ? 'bg-sky-500/10'
                        : cov > 0
                          ? 'bg-amber-500/12'
                          : 'bg-rose-500/15';
                return (
                  <td key={cell.cvss} className={`p-0 ${bg}`}>
                    <div className="px-3 py-2 text-center">
                      {cell.total === 0 ? (
                        <span className="text-xs text-muted">—</span>
                      ) : (
                        <>
                          <div className="font-mono text-sm font-semibold">{cell.total}</div>
                          <div className="font-mono text-[11px] text-muted">{cov}% covered</div>
                          {cell.avgCvss !== null && (
                            <div className="font-mono text-[10px] text-muted opacity-70">avg {cell.avgCvss}</div>
                          )}
                        </>
                      )}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>

      <p className="mt-4 text-xs text-muted">
        Cells count KEV entries; the percentage is how many of them have a published rule at the selected tier. Cells
        worth reading closely are the ones where a low CVSS band meets a high EPSS band: vendors rated them low,
        measurement says they are getting exploited, and the coverage figure says whether you would have seen it.
      </p>
    </div>
  );
}

/**
 * ATT&CK technique coverage.
 *
 * The more general half of the question. A behavioural rule covers a class of
 * activity, so "T1566.001 is covered" generalises across every phishing CVE,
 * whereas a per-CVE join only ever answers about the one it names.
 */
function TechniqueCoverage({ platforms }: { platforms: PlatformCoverage[] }): JSX.Element {
  const [data, setData] = useState<TechniqueResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [platform, setPlatform] = useState('');
  const [compareTo, setCompareTo] = useState('');
  const [gapsOnly, setGapsOnly] = useState(true);

  const url = useCallback(() => {
    const params = new URLSearchParams({ limit: '250' });
    if (platform) params.set('platform', platform);
    if (compareTo) params.set('compareTo', compareTo);
    if (gapsOnly) params.set('gapsOnly', 'true');
    return `/api/v1/detection-coverage/techniques?${params.toString()}`;
  }, [platform, compareTo, gapsOnly]);

  useEffect(() => {
    setLoading(true);
    fetchJsonCached<TechniqueResponse>(url(), 300_000)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [url]);

  return (
    <div>
      <div className="surface-card p-4 mb-5 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-xs font-mono text-muted uppercase tracking-wider">My platform</span>
          <select
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
            className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          >
            <option value="">Any</option>
            {platforms.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-mono text-muted uppercase tracking-wider">Compare with</span>
          <select
            value={compareTo}
            onChange={(e) => setCompareTo(e.target.value)}
            className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          >
            <option value="">Any</option>
            {platforms
              .filter((p) => p.id !== platform)
              .map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={gapsOnly} onChange={(e) => setGapsOnly(e.target.checked)} />
          <span>Gaps only</span>
        </label>
      </div>

      {platform && compareTo && gapsOnly && (
        <p className="text-xs text-muted mb-4">
          Techniques with <strong>nothing</strong> published for {platform} but something published for {compareTo}.
          Each row is a rule you can read and port.
        </p>
      )}

      <DataState
        loading={loading}
        error={error}
        empty={!data || data.techniques.length === 0}
        emptyLabel="No techniques match this comparison"
        skeletonVariant="table"
        onRetry={() => setLoading(true)}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line-2 text-left font-mono text-xs uppercase tracking-wider text-muted">
                <th className="py-2 pr-3">Technique</th>
                <th className="py-2 pr-3 text-right">Rules here</th>
                {platform && <th className="py-2 pr-3 text-right">{platform}</th>}
                {compareTo && <th className="py-2 pr-3 text-right">{compareTo}</th>}
                <th className="py-2 pr-3">Across platforms</th>
              </tr>
            </thead>
            <tbody>
              {data?.techniques.map((t) => (
                <tr key={t.id} className="border-b border-line-1 hover:bg-surface-2">
                  <td className="py-2 pr-3 font-mono font-semibold">{t.id}</td>
                  <td className="py-2 pr-3 text-right font-mono text-xs">{t.coveredHere}</td>
                  {platform && (
                    <td className="py-2 pr-3 text-right font-mono text-xs">
                      {t.byPlatform[platform] ? (
                        t.byPlatform[platform]
                      ) : (
                        <span className="text-rose-600 dark:text-rose-400">0</span>
                      )}
                    </td>
                  )}
                  {compareTo && (
                    <td className="py-2 pr-3 text-right font-mono text-xs">
                      {t.byPlatform[compareTo] ? (
                        t.byPlatform[compareTo]
                      ) : (
                        <span className="text-rose-600 dark:text-rose-400">0</span>
                      )}
                    </td>
                  )}
                  <td className="py-2 pr-3">
                    <div className="flex gap-0.5 items-end h-4" aria-hidden>
                      {platforms.map((p) => {
                        const n = t.byPlatform[p.id] ?? 0;
                        const max = Math.max(1, ...Object.values(t.byPlatform));
                        return (
                          <div
                            key={p.id}
                            title={`${p.label}: ${n}`}
                            className={`w-2 rounded-sm ${n > 0 ? 'bg-accent' : 'bg-surface-3'}`}
                            style={{ height: `${n === 0 ? 2 : Math.max(15, (n / max) * 100)}%` }}
                          />
                        );
                      })}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </DataState>
    </div>
  );
}

function RuleLibrary(): JSX.Element {
  const [data, setData] = useState<LibraryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [technique, setTechnique] = useState<string>('');
  const [q, setQ] = useState('');

  const url = useCallback(() => {
    const params = new URLSearchParams({ limit: '200' });
    if (technique) params.set('technique', technique);
    if (q) params.set('q', q);
    return `/api/v1/detection-coverage/library?${params.toString()}`;
  }, [technique, q]);

  useEffect(() => {
    setLoading(true);
    fetchJsonCached<LibraryResponse>(url(), 300_000)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [url]);

  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-4">
        <div className="relative">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted" aria-hidden />
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter by title or rule path"
            aria-label="Filter rules"
            className="pl-7 pr-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          />
        </div>
        <select
          value={technique}
          onChange={(e) => setTechnique(e.target.value)}
          aria-label="Filter by ATT&CK technique"
          className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
        >
          <option value="">All techniques</option>
          {data?.techniques.map((t) => (
            <option key={t.id} value={t.id}>
              {t.id} ({t.rules})
            </option>
          ))}
        </select>
        {data && <span className="self-center text-xs font-mono text-muted">{data.total} rules</span>}
      </div>

      <DataState
        loading={loading}
        error={error}
        empty={!data || data.rules.length === 0}
        emptyLabel="No published rules match this filter"
        onRetry={() => setLoading(true)}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line-2 text-left font-mono text-xs uppercase tracking-wider text-muted">
                <th className="py-2 pr-3">Rule</th>
                <th className="py-2 pr-3">Source</th>
                <th className="py-2 pr-3">Techniques</th>
                <th className="py-2 pr-3">CVEs</th>
              </tr>
            </thead>
            <tbody>
              {data?.rules.map((r) => (
                <tr key={r.rid} className="border-b border-line-1">
                  <td className="py-2 pr-3 max-w-md">
                    {r.url ? (
                      <a href={r.url} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
                        {r.title}
                      </a>
                    ) : (
                      r.title
                    )}
                    <div className="font-mono text-[11px] text-muted truncate">
                      {r.rid.split(':').slice(1).join(':')}
                    </div>
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs text-muted">{r.source}</td>
                  <td className="py-2 pr-3 font-mono text-[11px]">
                    {r.techniques.length === 0 ? (
                      <span className="text-muted">—</span>
                    ) : (
                      r.techniques.slice(0, 4).join(' ')
                    )}
                  </td>
                  <td className="py-2 pr-3 font-mono text-[11px]">
                    {r.cves.slice(0, 3).map((c) => (
                      <Link key={c} to={`/threatintel/cve/${c}`} className="mr-1.5 text-accent hover:underline">
                        {c}
                      </Link>
                    ))}
                    {r.cves.length > 3 && <span className="text-muted">+{r.cves.length - 3}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </DataState>
    </div>
  );
}

// ── page ─────────────────────────────────────────────────────────────

export default function DetectionCoverage(): JSX.Element {
  const [tab, setTab] = useState<TabId>('gaps');
  const [data, setData] = useState<CoverageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [platform, setPlatform] = useState('');
  const [days, setDays] = useState('');
  const [ransomware, setRansomware] = useState(false);
  const [gapOnly, setGapOnly] = useState(true);
  const [tier, setTier] = useState<'any' | 'explicit'>('any');
  const [refreshKey, setRefreshKey] = useState(0);

  const url = useCallback(() => {
    const params = new URLSearchParams({ limit: '150' });
    if (platform) params.set('platform', platform);
    if (days) params.set('days', days);
    if (ransomware) params.set('ransomware', 'true');
    if (gapOnly) params.set('gaps', 'true');
    if (tier === 'explicit') params.set('tier', 'explicit');
    return `/api/v1/detection-coverage?${params.toString()}`;
  }, [platform, days, ransomware, gapOnly, tier]);

  useEffect(() => {
    setLoading(true);
    setError(null);
    if (refreshKey > 0) memoryCache.delete(url());
    fetchJsonCached<CoverageResponse>(url(), 60_000)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [url, refreshKey]);

  const active = TABS.find((t) => t.id === tab);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Radar size={28} />}
      title="Detection Coverage"
      description="Knowing a vulnerability is exploited is half the job. This joins the CISA KEV catalog and EPSS against published detection rules to answer the other half: does the platform you actually run have a rule for it?"
      maxWidthClass="max-w-6xl"
    >
      {/* Scope note. Deliberately above the data, not in a footer nobody reads. */}
      <div className="surface-card p-3 mb-5 border-l-2 border-amber-500">
        <p className="text-xs text-muted">
          <strong className="text-amber-600 dark:text-amber-400">Two tiers, because one number would mislead.</strong>{' '}
          Only <strong>{data?.ruleCorpora.detectionCveLinkRate ?? 4}%</strong> of published detection rules cite a CVE
          id at all ({data?.ruleCorpora.detectionRulesCveTagged ?? 0} of {data?.ruleCorpora.detectionRules ?? 0}). That
          is a fact about tagging conventions, not about detection, so this page separates rules that{' '}
          <em>cite the CVE</em> from rules that <em>name the product</em>. A Citrix rule is relevant coverage for a
          Citrix CVE but may target a different bug entirely. Private vendor content is not visible to any scan of
          public repos either.
        </p>
      </div>

      {/* Filters. Applies to the gaps/platforms/bands tabs. */}
      <div className="surface-card p-4 mb-5 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-xs font-mono text-muted uppercase tracking-wider">Platform</span>
          <select
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
            className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          >
            <option value="">Any platform</option>
            {data?.perPlatform.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs font-mono text-muted uppercase tracking-wider">Added within</span>
          <select
            value={days}
            onChange={(e) => setDays(e.target.value)}
            className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          >
            <option value="">All time</option>
            <option value="7">7 days</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
          </select>
        </label>

        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={ransomware} onChange={(e) => setRansomware(e.target.checked)} />
          <span>Ransomware-linked only</span>
        </label>

        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={gapOnly} onChange={(e) => setGapOnly(e.target.checked)} />
          <span>Gaps only</span>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs font-mono text-muted uppercase tracking-wider">Counts as covered</span>
          <select
            value={tier}
            onChange={(e) => setTier(e.target.value as 'any' | 'explicit')}
            className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          >
            <option value="any">CVE cited or product named</option>
            <option value="explicit">CVE cited only</option>
          </select>
        </label>

        <button
          type="button"
          onClick={() => setRefreshKey((k) => k + 1)}
          className="ml-auto inline-flex items-center gap-1.5 text-xs font-mono px-2.5 py-1.5 border border-line-2 rounded hover:bg-surface-2"
        >
          <RefreshCw size={13} aria-hidden />
          Refresh
        </button>
      </div>

      {/* Headline numbers. Only meaningful for the unfiltered scope. */}
      {data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
          <div className="surface-card p-3">
            <div className="text-xs font-mono text-muted uppercase tracking-wider">KEV entries</div>
            <div className="text-2xl font-mono font-semibold">{data.scope.kevEvaluated.toLocaleString()}</div>
          </div>
          <div className="surface-card p-3">
            <div className="text-xs font-mono text-muted uppercase tracking-wider">Has a published rule</div>
            <div className="text-2xl font-mono font-semibold text-emerald-700 dark:text-emerald-400">
              {data.scope.coveragePct === null ? '—' : `${data.scope.coveragePct}%`}
            </div>
            <div className="text-xs font-mono text-muted">
              {data.scope.coveredAny.toLocaleString()} covered · {data.scope.coveredExplicit.toLocaleString()} cite the
              CVE
            </div>
          </div>
          <div className="surface-card p-3">
            <div className="text-xs font-mono text-muted uppercase tracking-wider">Gaps</div>
            <div className="text-2xl font-mono font-semibold text-rose-600 dark:text-rose-400">
              {data.scope.gaps.toLocaleString()}
            </div>
          </div>
          <div className="surface-card p-3">
            <div className="text-xs font-mono text-muted uppercase tracking-wider">Gaps with public exploit</div>
            <div className="text-2xl font-mono font-semibold">
              {data.scope.gapsWithExploitAvailable.toLocaleString()}
            </div>
            <div className="text-xs font-mono text-muted">
              {data.scope.risingFast.toLocaleString()} with EPSS rising fast
            </div>
          </div>
        </div>
      )}

      <nav className="flex flex-wrap gap-1 border-b border-line-1 mb-4" aria-label="Detection coverage views">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`border-b-2 px-3 py-2 font-mono text-sm font-semibold transition-colors ${
              tab === t.id
                ? 'border-rose-600 text-rose-600 dark:border-rose-400 dark:text-rose-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>
      <p className="text-xs font-mono text-muted mb-4">{active?.desc}</p>

      <div role="tabpanel">
        {tab === 'library' ? (
          <RuleLibrary />
        ) : tab === 'techniques' ? (
          <TechniqueCoverage platforms={data?.perPlatform ?? []} />
        ) : (
          <DataState
            loading={loading}
            error={error}
            empty={!data || data.rows.length === 0}
            emptyLabel={gapOnly ? 'No gaps under these filters, which is rare for full KEV' : 'No entries match'}
            skeletonVariant="table"
            errorHint="Run: node scripts/build-detection-coverage.mjs to build the rule index."
            onRetry={() => setRefreshKey((k) => k + 1)}
          >
            {data && tab === 'gaps' && <GapList data={data} />}
            {data && tab === 'platforms' && <PlatformTable data={data} />}
            {data && tab === 'bands' && <BandMatrix data={data} />}
          </DataState>
        )}
      </div>

      {data && (
        <p className="mt-8 text-xs font-mono text-muted">
          rule index built {new Date(data.generatedAt).toISOString().slice(0, 10)} ({data.indexAgeHours}h ago) ·{' '}
          {data.ruleCorpora.detectionRules.toLocaleString()} detection rules across {data.ruleCorpora.detections}{' '}
          corpora ({data.ruleCorpora.techniques} ATT&CK techniques) · {data.ruleCorpora.exploits.toLocaleString()}{' '}
          exploit records · {data.ruleCorpora.sources.map((s) => `${s.label} (${s.license})`).join(' · ')}
        </p>
      )}
    </DataPageLayout>
  );
}
