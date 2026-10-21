import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Bug, AlertTriangle, Flame, ShieldCheck, ExternalLink } from 'lucide-react';
import { fetchJson } from '../../lib/fetch-helpers';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { SocShell, SocKpi, SocSection, SocPanel, type SocStatus } from '../../components/threatintel/soc/SocShell';
import { SocBar, SocDonut, type BarItem, type DonutSlice } from '../../components/threatintel/soc/SocCharts';
import { downloadCsv, dayKey, formatNumber } from '../../components/threatintel/soc/utils';
import { CHART_RANK, CHART_SEV, SEVERITY_PILL, type SocSeverity } from '../../components/threatintel/soc/tone';
import { errMessage } from '../../lib/log';

/* ─── Data shape (matches /api/v1/cve-recent) ──────────────────────── */

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';

interface RecentCve {
  id: string;
  published: string;
  modified: string;
  description?: string;
  severity: Severity;
  score: number | null;
  kev: boolean;
  kev_added?: string;
  kev_ransomware?: boolean;
  actors?: Array<{ slug: string; mitre_id?: string; mitre_url?: string; mitre_name?: string }>;
  origin: 'nvd' | 'kev' | 'mti' | 'cvefeed' | 'cvenotify' | 'tg' | 'dbugs' | 'threatwire';
}

interface CveRecentResponse {
  generated_at: string;
  sources: { id: string; ok: boolean; count: number; stale?: boolean }[];
  count: number;
  kev_count: number;
  cves: RecentCve[];
}

/* ─── Severity palette (canonical - mirrors tailwind.config severity tokens) ── */

const SEV_COLOR: Record<Severity, string | undefined> = {
  CRITICAL: CHART_SEV.CRITICAL,
  HIGH: CHART_SEV.HIGH,
  MEDIUM: CHART_SEV.MEDIUM,
  LOW: CHART_SEV.LOW,
  NONE: CHART_SEV.NONE,
  UNKNOWN: CHART_SEV.UNKNOWN,
};

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'];

const EMPTY_CVES: RecentCve[] = [];

/** Map NVD severity to the SOC pill token. NONE/UNKNOWN render as `info`. */
function cveSevToSoc(s: Severity): SocSeverity {
  if (s === 'NONE' || s === 'UNKNOWN') return 'info';
  return s.toLowerCase() as SocSeverity;
}

/* ─── Vendor extraction (best-effort from CVE description) ─────────── */

// Common stopwords / generic terms in the description's "X in Y" prefix.
const VENDOR_STOPWORDS = new Set([
  'the',
  'a',
  'an',
  'in',
  'on',
  'of',
  'to',
  'for',
  'with',
  'and',
  'or',
  'multiple',
  'various',
  'allows',
  'enables',
  'causes',
  'could',
  'may',
  'might',
  'use',
  'via',
  'when',
  'unspecified',
  'remote',
  'attacker',
  'authenticated',
  'unauthenticated',
  'user',
  'users',
  'admin',
]);

/**
 * Heuristic vendor extraction from CVE description. Tries the first N words
 * of the description looking for a capitalized noun phrase before "in" /
 * "before" / "allows". Falls back to "Other" if nothing usable is found.
 * CISA publishes structured vendor data but it's not on the NVD payload,
 * so the description is the only signal we have at the API tier.
 */
function extractVendorFromDescription(desc: string | undefined): string {
  if (!desc) return 'Unknown';
  // Common NVD template: "<Vendor> <Product> in <...> contains/allows ..."
  // Capture the leading noun phrase (2-3 capitalized words).
  const m = desc.match(
    /^([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+){0,2})(?:\s+(?:in|before|allows|contains|has|was|is|the|when|from))/
  );
  if (m) {
    const phrase = m[1]!.trim();
    if (phrase.length >= 3 && !VENDOR_STOPWORDS.has(phrase.toLowerCase())) return phrase;
  }
  // Fallback: take the first word if it looks like a vendor (starts with uppercase, >2 chars)
  const first = desc.split(/\s+/)[0];
  if (first && /^[A-Z][A-Za-z0-9]{2,}$/.test(first) && !VENDOR_STOPWORDS.has(first.toLowerCase())) {
    return first;
  }
  return 'Other';
}

export default function SocVulns(): JSX.Element {
  const [windowDays, setWindowDays] = useState<number>(30);
  const [data, setData] = useState<CveRecentResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [prevKev, setPrevKev] = useState<number | null>(null);
  const dataRef = useRef<CveRecentResponse | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    try {
      const r = (await fetchJson('/api/v1/cve-recent', { signal, cache: 'no-store' })) as CveRecentResponse;
      setData(r);
    } catch (e) {
      console.error('SocVulns failed:', errMessage(e));
      if ((e as { name?: string }).name !== 'AbortError') {
        setError(errMessage(e, 'Failed to load.'));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // Capture previous KEV count on each successful load for the delta chip.
  // Ref is updated *after* reading so we always see the prior value.
  useEffect(() => {
    if (data && dataRef.current && dataRef.current !== data) {
      setPrevKev(dataRef.current.kev_count);
    }
    dataRef.current = data;
  }, [data]);

  useEffect(() => {
    const ctrl = new AbortController();
    void load(ctrl.signal);
    return () => ctrl.abort();
  }, [load]);

  const cves = useMemo(() => data?.cves ?? EMPTY_CVES, [data]);

  /* ─── Windowing: filter CVEs to the last `windowDays` days ─────── */
  const inWindow = useMemo(() => {
    const cutoff = Date.now() - windowDays * 86400_000;
    return cves.filter((c) => Date.parse(c.published) >= cutoff);
  }, [cves, windowDays]);

  const counts = useMemo(() => {
    const out: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      NONE: 0,
      UNKNOWN: 0,
    };
    for (const c of inWindow) out[c.severity] += 1;
    return out;
  }, [inWindow]);

  const total = inWindow.length;
  const criticalPct = total ? Math.round((counts.CRITICAL / total) * 1000) / 10 : 0;
  const highPct = total ? Math.round((counts.HIGH / total) * 1000) / 10 : 0;
  const kevTotal = data?.kev_count ?? 0;

  const kevDelta = useMemo(() => {
    if (prevKev == null) return null;
    const diff = kevTotal - prevKev;
    if (diff === 0) return { text: '· stable', direction: 'flat' as const };
    return {
      text: `${diff > 0 ? '+' : ''}${diff} KEV`,
      direction: diff > 0 ? ('up' as const) : ('down' as const),
    };
  }, [prevKev, kevTotal]);

  /* ─── Status: severity-driven, derived from data ─────────────── */
  const status = useMemo<SocStatus>(() => {
    if (!data) return { label: 'Loading', severity: 'medium' };
    if (counts.CRITICAL > 20) return { label: 'Critical · patch now', severity: 'critical' };
    if (counts.CRITICAL > 5) return { label: 'High · elevated exposure', severity: 'high' };
    if (counts.HIGH > 10) return { label: 'Elevated high-severity flow', severity: 'high' };
    if (counts.HIGH > 0) return { label: 'Tracking high-severity CVEs', severity: 'medium' };
    return { label: 'Tracking exposures', severity: 'ok' };
  }, [data, counts.CRITICAL, counts.HIGH]);

  /* ─── Daily detection frequency ───────────────────────────────── */
  const dailyCounts = useMemo(() => {
    if (inWindow.length === 0) return [];
    const buckets = new Map<string, number>();
    for (const c of inWindow) {
      const k = dayKey(c.published);
      if (!k) continue;
      buckets.set(k, (buckets.get(k) ?? 0) + 1);
    }
    return Array.from(buckets.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([label, value]) => ({ label: label.slice(5), value }));
  }, [inWindow]);

  /* ─── Severity index (donut) ───────────────────────────────────── */
  const sevSlices: DonutSlice[] = useMemo(
    () => SEV_ORDER.filter((s) => counts[s] > 0).map((s) => ({ label: s, value: counts[s], color: SEV_COLOR[s] })),
    [counts]
  );

  /* ─── Top vendors ─────────────────────────────────────────────── */
  const topVendors: BarItem[] = useMemo(() => {
    if (inWindow.length === 0) return [];
    const counts = new Map<string, number>();
    for (const c of inWindow) {
      const v = extractVendorFromDescription(c.description);
      counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    const arr = Array.from(counts.entries())
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
    return arr.map((x, i) => ({
      label: x.label,
      value: x.value,
      hint: total ? `${Math.round((x.value / total) * 100)}%` : undefined,
      color: CHART_RANK[Math.min(i, CHART_RANK.length - 1)],
      href: `/threatintel/cve-list?vendor=${encodeURIComponent(x.label)}`,
    }));
  }, [inWindow, total]);

  /* ─── CVSS score distribution ─────────────────────────────────── */
  const cvssBins = useMemo(() => {
    if (inWindow.length === 0) return [];
    const bins = [
      { label: '0-3.9', min: 0, max: 3.99, n: 0 },
      { label: '4.0-6.9', min: 4.0, max: 6.99, n: 0 },
      { label: '7.0-8.9', min: 7.0, max: 8.99, n: 0 },
      { label: '9.0-10', min: 9.0, max: 10, n: 0 },
    ];
    for (const c of inWindow) {
      if (c.score == null) continue;
      const bin = bins.find((b) => c.score! >= b.min && c.score! <= b.max);
      if (bin) bin.n += 1;
    }
    return bins.map((b) => ({ label: b.label, value: b.n }));
  }, [inWindow]);

  /* ─── KEV-flagged CVEs (recent, high-value) ──────────────────── */
  const kevList = useMemo(() => inWindow.filter((c) => c.kev).slice(0, 10), [inWindow]);

  /* ─── Export ──────────────────────────────────────────────────── */
  const onExport = useCallback(() => {
    if (!data) return;
    const rows: (string | number)[][] = [['cve_id', 'published', 'severity', 'score', 'kev', 'vendor', 'description']];
    for (const c of inWindow) {
      rows.push([
        c.id,
        c.published,
        c.severity,
        c.score ?? '',
        c.kev ? 'yes' : 'no',
        extractVendorFromDescription(c.description),
        (c.description ?? '').replace(/\s+/g, ' ').slice(0, 240),
      ]);
    }
    downloadCsv(`soc-vulns-${windowDays}d-${new Date().toISOString().slice(0, 10)}.csv`, rows);
    // data is only used for the null guard; inWindow (derived from data) is the
    // real dep. Adding data would change identity every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inWindow, windowDays]);

  const navigate = useNavigate();
  const onItemClick = useCallback(
    (it: BarItem) => {
      if (it.href) navigate(it.href);
    },
    [navigate]
  );

  return (
    <SocShell
      title="Vulnerability monitoring"
      icon={<Bug size={28} />}
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
          NVD + CISA KEV + MyThreatIntel + cvefeed.io + CVE Telegram channels (@cvenotify · cvefeed · new_cves) merged
          for the chosen window. Critical and high counts derived from CVSS; KEV tracks the all-time known-exploited
          corpus. Drill into the vendor list or jump to the{' '}
          <Link to="/threatintel/cves/cves" className="text-rose-600 dark:text-rose-400 hover:underline">
            full CVE list
          </Link>
          .
        </span>
      }
      meta={
        <span>
          NVD · CISA KEV · MyThreatIntel · cvefeed.io · CVE Telegram channels
          {data?.sources && (
            <>
              {' '}
              · sources ok: {data.sources.filter((s) => s.ok).length}/{data.sources.length}
            </>
          )}
        </span>
      }
    >
      {/* ─── KPI row ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-6">
        <SocKpi
          label="Discovered CVEs"
          value={formatNumber(total)}
          severity="info"
          sub={`published in last ${windowDays} days`}
          icon={<Bug size={16} />}
        />
        <SocKpi
          label="Critical vectors"
          value={
            <span className="inline-flex items-baseline gap-2">
              {counts.CRITICAL}
              <span className="text-2xl text-muted">({criticalPct}%)</span>
            </span>
          }
          severity="critical"
          sub="CVSS ≥ 9.0"
          icon={<Flame size={16} />}
        />
        <SocKpi
          label="High severity"
          value={
            <span className="inline-flex items-baseline gap-2">
              {counts.HIGH}
              <span className="text-2xl text-muted">({highPct}%)</span>
            </span>
          }
          severity="high"
          sub="CVSS 7.0 – 8.9"
          icon={<AlertTriangle size={16} />}
        />
        <SocKpi
          label="CISA KEV"
          value={formatNumber(kevTotal)}
          severity="critical"
          sub="known-exploited · all-time"
          icon={<ShieldCheck size={16} />}
          delta={kevDelta?.text}
          deltaDirection={kevDelta?.direction}
        />
      </div>

      {/* ─── Charts row 1: line / donut / vendors ────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4 mb-6">
        <SocPanel>
          <SocSection
            title="Detection frequency"
            right={
              dailyCounts.length > 0 ? (
                <span className="text-meta font-mono text-muted">
                  peak {Math.max(...dailyCounts.map((d) => d.value))} / day
                </span>
              ) : null
            }
          />
          <SocBar items={dailyCounts.slice(-30)} vertical height={180} emptyText="No CVEs in window." />
        </SocPanel>

        <SocPanel>
          <SocSection title="Severity index" />
          {sevSlices.length > 0 ? (
            <SocDonut
              slices={sevSlices}
              size={180}
              thickness={26}
              centerLabel={formatNumber(total)}
              centerSub="cves in window"
            />
          ) : (
            <p className="text-meta font-mono text-muted italic">No CVEs in window.</p>
          )}
        </SocPanel>

        <SocPanel>
          <SocSection
            title="Top vendors"
            right={
              <Link
                to="/threatintel/cves/cves"
                className="inline-flex items-center gap-1 text-meta font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                all <ExternalLink size={10} />
              </Link>
            }
          />
          <SocBar items={topVendors} onItemClick={onItemClick} />
        </SocPanel>
      </div>

      {/* ─── Charts row 2: KEV list (wide, left) + CVSS dist ─────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4">
        <SocPanel className="lg:col-span-2">
          <SocSection
            title="KEV-flagged (recent)"
            right={
              <Link
                to="/threatintel/cves/cves?kev=1"
                className="inline-flex items-center gap-1 text-meta font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                feed <ExternalLink size={10} />
              </Link>
            }
          />
          <KevTable rows={kevList} />
        </SocPanel>

        <div className="space-y-3 sm:space-y-4">
          <SocPanel>
            <SocSection title="CVSS distribution" />
            <SocBar items={cvssBins} vertical height={180} />
          </SocPanel>

          <SocPanel>
            <SocSection title="Quick stats" />
            <dl className="space-y-2 text-meta font-mono">
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-muted">top vendor</dt>
                <dd className="text-body truncate">{topVendors[0]?.label ?? '-'}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-muted">critical + high</dt>
                <dd className="text-body">{formatNumber(counts.CRITICAL + counts.HIGH)}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-muted">KEV · all-time</dt>
                <dd className="text-body">{formatNumber(kevTotal)}</dd>
              </div>
            </dl>
          </SocPanel>
        </div>
      </div>
    </SocShell>
  );
}

function KevTable({ rows }: { rows: RecentCve[] }): JSX.Element {
  if (rows.length === 0) {
    return <p className="text-meta font-mono text-muted italic">No CISA KEV entries in window.</p>;
  }
  return (
    <div className="space-y-3">
      <PostAnalysisButton
        title="SOC Recent CVEs Digest"
        description="AI-powered threat analysis of the current feed."
        source="soc vulns"
      />
      <AiSummaryCard
        surface="SOC Recent CVEs"
        items={rows.slice(0, 30).map((r) => ({
          title: r.id,
          body: `${extractVendorFromDescription(r.description)}${r.kev ? '\nIn CISA KEV' : ''}${r.kev_ransomware ? ' (ransomware campaign use)' : ''}${(r.actors ?? []).length > 0 ? `\nActors: ${r.actors!.map((a) => a.slug).join(', ')}` : ''}`,
          source: r.origin,
        }))}
        requireAdmin={false}
      />
      <div className="overflow-x-auto -mx-4 sm:mx-0">
        <DataTable
          columns={
            [
              {
                key: 'cve',
                header: 'CVE',
                sortValue: (r: (typeof rows)[number]) => r.id,
                render: (r) => (
                  <Link
                    to={`/dfir/cve?id=${encodeURIComponent(r.id)}`}
                    className="text-rose-600 dark:text-rose-400 hover:underline"
                  >
                    {r.id}
                  </Link>
                ),
              },
              {
                key: 'cvss',
                header: 'CVSS',
                sortValue: (r: (typeof rows)[number]) => r.score ?? 0,
                render: (r) => <span className="tabular-nums text-body">{r.score?.toFixed(1) ?? '-'}</span>,
              },
              {
                key: 'sev',
                header: 'Sev',
                sortValue: (r: (typeof rows)[number]) => r.severity,
                render: (r) => (
                  <span
                    className={`inline-block px-1.5 py-0.5 rounded text-mini font-mono border ${SEVERITY_PILL[cveSevToSoc(r.severity)]}`}
                  >
                    {r.severity}
                  </span>
                ),
              },
              {
                key: 'vendor',
                header: 'Vendor',
                render: (r) => (
                  <span className="text-body truncate max-w-[200px]">
                    {extractVendorFromDescription(r.description)}
                  </span>
                ),
              },
              {
                key: 'kev',
                header: 'Added to KEV',
                align: 'right',
                sortValue: (r: (typeof rows)[number]) => r.kev_added ?? '',
                render: (r) => (
                  <span className="text-muted tabular-nums">{r.kev_added ? r.kev_added.slice(0, 10) : '-'}</span>
                ),
              },
            ] as DataTableColumn<(typeof rows)[number]>[]
          }
          rows={rows}
          rowKey={(r) => r.id}
          rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-surface-200/40'}
        />
      </div>
    </div>
  );
}
