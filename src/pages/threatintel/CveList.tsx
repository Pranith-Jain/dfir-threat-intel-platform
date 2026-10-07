import { useEffect, useMemo, useState } from 'react';
import { relativeAgo as shortRel } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link, useSearchParams } from 'react-router-dom';
import { AlertOctagon, ExternalLink, Flame, RefreshCw, Search, ShieldAlert, Sparkles } from 'lucide-react';
import { useLastVisit, isNewSince } from '../../hooks';
import { useDataFetch } from '../../hooks/useDataFetch';
import { SEVERITY_TONE } from '../../components/severity';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { DataPageLayout } from '../../components/DataPageLayout';

interface RecentCve {
  id: string;
  published: string;
  modified: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';
  score: number | null;
  reference?: string;
  kev: boolean;
  kev_added?: string;
  kev_due?: string;
  kev_ransomware?: boolean;
  actors?: Array<{ slug: string; mitre_id?: string; mitre_url?: string; mitre_name?: string }>;
  origin: 'nvd' | 'kev' | 'mti' | 'cvefeed' | 'cvenotify' | 'tg' | 'dbugs' | 'exploitgrid' | 'cvemon';
  /** Intruder cvemon trending rank (1 = most discussed). */
  hype_rank?: number;
  /** Intruder cvemon hype score. */
  hype_score?: number;
  /** cvemon detail page. */
  cvemon_url?: string;
  /** dbu.gs vendor (origin 'dbugs'). */
  vendor?: string;
  /** dbu.gs product (origin 'dbugs'). */
  product?: string;
  /** dbu.gs records a public exploit/PoC for this CVE. */
  has_exploit?: boolean;
  /** dbu.gs records an available fix or vendor advisory. */
  has_fix?: boolean;
  /** Telegram permalink when origin is 'mti'. */
  mti_permalink?: string;
  /** Telegram permalink when origin is 'cvenotify'. */
  cvenotify_permalink?: string;
  /** External link when origin is 'cvefeed' - cvefeed.io detail page or TG post. */
  cvefeed_url?: string;
  /** Telegram permalink when origin is 'tg'. */
  tg_permalink?: string;
  /** Channel handle when origin is 'tg' (e.g. 'new_cves'). */
  tg_channel?: string;
  /** FIRST EPSS exploitation probability (next 30 days), 0-1. */
  epss?: number;
  /** FIRST EPSS percentile, 0-1. */
  epss_percentile?: number;
}

interface CveResponse {
  generated_at: string;
  sources: { id: string; ok: boolean; count: number }[];
  count: number;
  kev_count: number;
  cves: RecentCve[];
}

// Source the four canonical severity tones from the shared Badge module so a
// future tweak ripples here. LOW intentionally uses slate (not emerald) - a
// low-severity CVE is still a CVE and green misreads as "safe".
const SEVERITY_PILL: Record<RecentCve['severity'], string> = {
  CRITICAL: SEVERITY_TONE.critical,
  HIGH: SEVERITY_TONE.high,
  MEDIUM: SEVERITY_TONE.medium,
  LOW: SEVERITY_TONE.low,
  NONE: 'border-slate-300 dark:border-line-1 text-slate-500',
  UNKNOWN: 'border-slate-300 dark:border-line-1 text-slate-500',
};

const ORIGIN_PILL: Record<RecentCve['origin'], { label: string; cls: string; tooltip: string }> = {
  nvd: {
    label: 'NVD',
    cls: 'border-slate-300 dark:border-line-1 text-muted',
    tooltip: 'Canonical NIST National Vulnerability Database entry',
  },
  kev: {
    label: 'KEV',
    cls: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    tooltip: 'CISA Known Exploited Vulnerabilities - actively exploited in the wild',
  },
  mti: {
    label: 'MTI',
    cls: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    tooltip: 'Gap-filled from mythreatintel Telegram channel - not yet in NVD',
  },
  cvefeed: {
    label: 'cvefeed.io',
    cls: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    tooltip: 'Gap-filled from cvefeed.io high-severity feed - not yet in NVD',
  },
  cvenotify: {
    label: 'cvenotify',
    cls: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    tooltip: 'Gap-filled from @cvenotify Telegram channel - not yet in NVD',
  },
  tg: {
    label: 'Telegram',
    cls: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    tooltip: 'Gap-filled from a CVE Telegram channel - not yet in NVD',
  },
  dbugs: {
    label: 'dbu.gs',
    cls: 'border-teal-500/40 bg-teal-500/10 text-teal-700 dark:text-teal-300',
    tooltip: 'Gap-filled from dbu.gs — carries vendor/product/CWE plus exploit- and fix-availability flags',
  },
  exploitgrid: {
    label: 'ExploitGrid',
    cls: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    tooltip: 'Gap-filled from ExploitGrid — a public proof-of-concept exists for this CVE',
  },
  cvemon: {
    label: 'Trending',
    cls: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
    tooltip: 'Gap-filled from Intruder cvemon — trending on social media by discussion volume',
  },
};

interface CveListProps {
  bare?: boolean;
}

export default function CveList({ bare }: CveListProps): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get('q') ?? '');
  const [severityFilter, setSeverityFilter] = useState<Set<RecentCve['severity']>>(
    () => new Set((searchParams.get('sev')?.split(',').filter(Boolean) ?? []) as RecentCve['severity'][])
  );
  const [kevOnly, setKevOnly] = useState(searchParams.get('kev') === '1');
  const [newOnly, setNewOnly] = useState(searchParams.get('new') === '1');
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [query, severityFilter, kevOnly, newOnly]);

  // Keep filter state in the URL so a curated view is shareable.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        if (query.trim()) out.set('q', query.trim());
        else out.delete('q');
        if (severityFilter.size > 0) out.set('sev', [...severityFilter].join(','));
        else out.delete('sev');
        if (kevOnly) out.set('kev', '1');
        else out.delete('kev');
        if (newOnly) out.set('new', '1');
        else out.delete('new');
        return out;
      },
      { replace: true }
    );
  }, [query, severityFilter, kevOnly, newOnly, setSearchParams]);
  const { previous: lastVisit, markVisited } = useLastVisit('cve-list');

  const { data, loading, error, refetch } = useDataFetch<CveResponse>({
    url: '/api/v1/cve-recent?limit=500',
    ttl: 120_000,
    staleWhileRevalidate: true,
  });

  // Mark the visit AFTER data lands so the "new since" diff uses the OLD
  // timestamp. Defer with setTimeout so the diff highlight has time to render.
  useEffect(() => {
    if (!data) return;
    const id = window.setTimeout(markVisited, 1500);
    return () => window.clearTimeout(id);
  }, [data, markVisited]);

  const newCount = useMemo(() => {
    if (!data || !lastVisit) return 0;
    return data.cves.filter((c) => isNewSince(c.published, lastVisit)).length;
  }, [data, lastVisit]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.cves.filter((c) => {
      if (kevOnly && !c.kev) return false;
      if (newOnly && !isNewSince(c.published, lastVisit)) return false;
      if (severityFilter.size > 0 && !severityFilter.has(c.severity)) return false;
      if (!q) return true;
      return c.id.toLowerCase().includes(q) || c.description.toLowerCase().includes(q);
    });
  }, [data, query, severityFilter, kevOnly, newOnly, lastVisit]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageItems = useMemo(() => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filtered, page]);
  const summaryItems = useMemo(
    () =>
      filtered.slice(0, 50).map((c) => ({
        title: c.id,
        body: c.description,
        source: c.origin,
      })),
    [filtered]
  );

  const toggleSeverity = (s: RecentCve['severity']) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const body = (
    <>
      {/* Cross-link to the complete 24h window. This list is a recent SAMPLE
          bounded by NVD paging; the digest is the complete window anchored on
          ctiwatch. One line, no extra fetch — the digest page carries the data. */}
      <div className="mb-4 rounded-lg border border-sky-500/30 bg-sky-500/10 p-3 text-xs text-sky-700 dark:text-sky-300 flex items-center justify-between gap-3 flex-wrap">
        <span>
          Looking for <strong>every CVE from the last 24 hours</strong>? The list below is a recent sample — the{' '}
          <Link to="/threatintel/cves/cves?tab=digest" className="font-semibold underline">
            24h Digest
          </Link>{' '}
          is the complete window.
        </span>
        <Link
          to="/threatintel/cves/cves?tab=digest"
          className="shrink-0 rounded border border-sky-500/40 px-2 py-1 font-mono text-mini hover:bg-sky-500/20"
        >
          Open digest →
        </Link>
      </div>
      {/* Top-level AI threat analysis for the filtered CVE set */}
      {filtered.length > 0 && (
        <div className="mb-6">
          <PostAnalysisButton
            title={`CVE Digest — ${filtered.length} CVEs${kevOnly ? ' (KEV only)' : ''}${newCount > 0 ? ` · ${newCount} new` : ''}`}
            description={filtered
              .slice(0, 20)
              .map((c) => `${c.id} (${c.severity}, score ${c.score ?? '?'}): ${c.description.slice(0, 150)}`)
              .join('\n')}
            source="nvd+kev+mti"
          />
        </div>
      )}

      <AiSummaryCard
        surface="Live CVE Updates"
        items={summaryItems}
        endpoint="/api/v1/unified-search/summarize"
        requireAdmin={false}
        autoFetch={false}
        extraBody={{ q: 'Recent CVE activity summary' }}
        className="mb-6"
      />

      <section className="surface-card p-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by CVE id or description text…"
              className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
              aria-label="Filter CVEs"
            />
          </div>
          <button
            type="button"
            onClick={() => setKevOnly((v) => !v)}
            className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border ${
              kevOnly
                ? 'border-rose-500/60 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                : 'border-line-1 hover:border-rose-500/40'
            }`}
            title="Toggle CISA KEV-only (actively exploited CVEs)"
          >
            <Flame size={12} /> KEV only{data ? ` · ${data.kev_count}` : ''}
          </button>
          {newCount > 0 && (
            <button
              type="button"
              onClick={() => setNewOnly((v) => !v)}
              className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border ${
                newOnly
                  ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                  : 'border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:border-emerald-500/60'
              }`}
              title={`${newCount} new since your last visit${lastVisit ? ` (${new Date(lastVisit).toLocaleString()})` : ''}`}
            >
              <Sparkles size={12} /> {newCount} new since last visit
            </button>
          )}
          <button
            type="button"
            onClick={() => refetch()}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-line-1 hover:border-rose-500/40"
          >
            <RefreshCw size={12} /> refresh
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 mt-3">
          <span className="text-mini font-mono text-muted mr-1">severity:</span>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'] as const).map((s) => {
            const active = severityFilter.has(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggleSeverity(s)}
                className={`text-mini font-mono px-2 py-1 rounded border ${
                  active ? SEVERITY_PILL[s] : 'border-slate-300 dark:border-line-1 text-slate-500'
                }`}
              >
                {s}
              </button>
            );
          })}
          {severityFilter.size > 0 && (
            <button
              type="button"
              onClick={() => setSeverityFilter(new Set())}
              className="text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline ml-2"
            >
              clear
            </button>
          )}
        </div>
      </section>

      {data && (
        <p className="text-mini font-mono text-muted mb-4">
          Showing page {page}/{totalPages} ({pageItems.length} of {filtered.length} filtered, {data.count} total) ·
          sources: {(data.sources ?? []).map((s) => `${s.id} ${s.ok ? `(${s.count})` : 'OFFLINE'}`).join(' · ')} ·
          snapshot <span className="text-body">{shortRel(data.generated_at)}</span>
        </p>
      )}

      <ul className="space-y-2">
        {pageItems.map((c) => {
          const isNew = isNewSince(c.published, lastVisit);
          return (
            <li
              key={c.id}
              className={`rounded-xl border p-4 ${
                isNew
                  ? 'border-emerald-500/50 bg-emerald-50/40 dark:bg-emerald-900/10 ring-1 ring-emerald-500/20'
                  : c.kev
                    ? 'border-rose-500/40 bg-rose-50/30 dark:bg-rose-900/10'
                    : 'border-line-1 bg-white dark:bg-surface-200'
              }`}
            >
              <div className="flex items-baseline justify-between gap-2 mb-2 flex-wrap">
                <Link
                  to={`/dfir/cve?id=${encodeURIComponent(c.id)}`}
                  className="font-display font-semibold text-base text-heading hover:text-rose-600 dark:hover:text-rose-400 font-mono inline-flex items-center gap-2"
                >
                  {c.id}
                  {isNew && (
                    <span
                      className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 inline-flex items-center gap-1"
                      title="new since your last visit"
                    >
                      <Sparkles size={9} /> new
                    </span>
                  )}
                </Link>
                <div className="flex items-center gap-2 text-mini font-mono flex-wrap">
                  {c.kev && (
                    <span
                      className="uppercase tracking-wider px-1.5 py-0.5 rounded border border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300 inline-flex items-center gap-1"
                      title={`Listed on CISA KEV ${c.kev_added ?? ''}${c.kev_due ? ` · federal due ${c.kev_due}` : ''}`}
                    >
                      <Flame size={9} /> KEV
                    </span>
                  )}
                  {c.kev_ransomware && (
                    <span
                      className="uppercase tracking-wider px-1.5 py-0.5 rounded border border-amber-500/60 bg-amber-500/15 text-amber-700 dark:text-amber-300 inline-flex items-center gap-1"
                      title="CISA flags this as used in known ransomware campaigns"
                    >
                      <AlertOctagon size={9} /> ransomware
                    </span>
                  )}
                  {c.actors && c.actors.length > 0 && (
                    <span className="inline-flex items-center gap-1 flex-wrap">
                      {c.actors.map((a) =>
                        a.mitre_url ? (
                          <a
                            key={a.slug}
                            href={a.mitre_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:underline lowercase tracking-normal transition-colors"
                            title={`MITRE ${a.mitre_id} · ${a.mitre_name}`}
                          >
                            {a.slug}
                            <span className="opacity-70"> · {a.mitre_id}</span>
                          </a>
                        ) : (
                          <span
                            key={a.slug}
                            className="px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 lowercase tracking-normal"
                            title="curated actor (not yet in MITRE)"
                          >
                            {a.slug}
                          </span>
                        )
                      )}
                    </span>
                  )}
                  <span
                    className={`uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEVERITY_PILL[c.severity]}`}
                  >
                    {c.severity}
                  </span>
                  {c.score !== null && <span className="text-muted">{c.score.toFixed(1)}</span>}
                  {c.epss !== undefined && (
                    <span
                      className="uppercase tracking-wider px-1.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                      title={`FIRST EPSS exploitation probability (next 30 days): ${(c.epss * 100).toFixed(1)}%${
                        c.epss_percentile !== undefined ? ` · percentile ${(c.epss_percentile * 100).toFixed(1)}` : ''
                      }`}
                    >
                      EPSS {(c.epss * 100).toFixed(0)}%
                    </span>
                  )}
                  <span
                    className={`uppercase tracking-wider px-1.5 py-0.5 rounded border ${ORIGIN_PILL[c.origin].cls}`}
                    title={
                      c.origin === 'tg' && c.tg_channel
                        ? `Gap-filled from @${c.tg_channel} Telegram channel - not yet in NVD`
                        : ORIGIN_PILL[c.origin].tooltip
                    }
                  >
                    {ORIGIN_PILL[c.origin].label}
                  </span>
                  <span
                    className="text-muted"
                    title={c.origin === 'kev' ? `Added to KEV ${c.kev_added}` : `Published ${c.published}`}
                  >
                    {shortRel(c.published)}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-2">
                <PostAnalysisButton title={c.id} description={c.description} source={c.origin} compact />
                {c.reference && (
                  <a
                    href={sanitizeUrl(c.reference) || undefined}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                  >
                    primary reference <ExternalLink size={9} />
                  </a>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      {totalPages > 1 && (
        <div className="mt-6 flex items-center justify-center gap-2">
          <button
            type="button"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="text-xs font-mono px-3 py-1.5 rounded border border-line-2 disabled:opacity-30 hover:border-rose-500/40"
          >
            ← prev
          </button>
          <span className="text-xs font-mono text-muted px-2">
            {page} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="text-xs font-mono px-3 py-1.5 rounded border border-line-2 disabled:opacity-30 hover:border-rose-500/40"
          >
            next →
          </button>
        </div>
      )}
    </>
  );
  if (bare) return body;
  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldAlert size={28} />}
      title="Live CVE updates"
      description={
        <>
          <p className="text-muted mb-2 max-w-3xl leading-relaxed">
            Up to <strong>1,500 CVEs newly published in the last 30 days</strong> (NVD) merged with{' '}
            <strong>CISA KEV</strong> additions, <strong>MyThreatIntel</strong> alerts,{' '}
            <strong>cvefeed.io high-severity</strong> RSS, and CVE Telegram channels (<strong>@cvenotify</strong>,{' '}
            <strong>cvefeed</strong>, <strong>new_cves</strong>) as gap-fillers. Every entry is enriched with{' '}
            <strong>FIRST EPSS</strong> exploitation probability where available. NVD reports ~5,500 CVEs per 30-day
            window - this is a triage view that prioritises high-signal records, not the full corpus. For exhaustive
            search use{' '}
            <a
              href="https://nvd.nist.gov/vuln/search"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              nvd.nist.gov/vuln/search
            </a>
            . Entries flagged KEV are known to be exploited in the wild, so prioritise those. Click a CVE id to drill
            into{' '}
            <Link to="/dfir/cve" className="text-rose-600 dark:text-rose-400 hover:underline">
              CVE Lookup
            </Link>{' '}
            (full NVD + EPSS + KEV record).
          </p>
          <p className="text-xs text-muted font-mono">
            Sources: <span className="text-body">NVD published-CVE feed</span> merged with the{' '}
            <span className="text-body">CISA KEV catalogue</span>, MyThreatIntel, cvefeed.io RSS, and{' '}
            <span className="text-body">CVE Telegram channels</span>. Scores:{' '}
            <span className="text-body">NVD CVSS</span> + <span className="text-body">FIRST EPSS</span>.
          </p>
        </>
      }
      loading={loading}
      error={error}
      empty={filtered.length === 0}
      emptyMessage="No CVEs match the current filter."
      onRetry={refetch}
      maxWidthClass="max-w-6xl"
    >
      {body}
    </DataPageLayout>
  );
}
