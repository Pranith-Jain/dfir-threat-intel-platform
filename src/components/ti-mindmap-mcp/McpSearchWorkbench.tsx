/**
 * Full-featured MCP search workbench.
 *
 * Used in two places:
 *   - inside the AI Report showcase as the cross-source panel
 *   - on /threatintel/mcp-search as the full page body
 *
 * State (query, mode, last result) is local to each instance; an
 * in-memory history of the last 10 queries is kept per page and
 * persisted in localStorage under "ti-mindmap:search-history" so the
 * user can re-run recent lookups without retyping.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { SeverityBadge } from '../SeverityBadge';
import { normalizeSeverity } from '../severity';
import { AlertTriangle, Calendar, ExternalLink, FileText, Filter, Loader2, Search, Shield, X } from 'lucide-react';
import {
  searchIoc,
  searchCve,
  listReports,
  listBriefings,
  getReportDetailsFlexible,
  getReportContent,
  idForReport,
  type TiReportSummary,
  type IocSearchResult,
  type CveSearchResult,
  type ListReportsResult,
  type BriefingSummary,
  type ReportDetailsResult,
} from '../../lib/ti-mindmap-mcp';
import { useMcp, McpError } from './McpContext';
import { errMessage } from '../../lib/log';

type Mode = 'ioc' | 'cve' | 'report' | 'briefing';
type Severity = 'critical' | 'high' | 'medium' | 'low';
type TimeRange = '' | '24h' | '7d' | '30d' | '90d';

const TIME_RANGE_LABELS: Record<TimeRange, string> = {
  '': 'all time',
  '24h': '24h',
  '7d': '7d',
  '30d': '30d',
  '90d': '90d',
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

const SEVERITY_PILL: Record<Severity, string> = {
  critical: 'border-rose-400 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300',
  high: 'border-orange-400 bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300',
  medium: 'border-amber-400 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300',
  low: 'border-slate-300 bg-slate-50 dark:bg-input-200/40 text-muted',
};

const HISTORY_KEY = 'ti-mindmap:search-history';
const HISTORY_MAX = 10;

function loadHistory(): string[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as unknown;
    if (Array.isArray(arr)) return arr.filter((x): x is string => typeof x === 'string').slice(0, HISTORY_MAX);
    return [];
  } catch {
    return [];
  }
}

function saveHistory(items: string[]): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_MAX)));
  } catch {
    /* ignore */
  }
}

interface SearchHit {
  ioc?: IocSearchResult;
  cve?: CveSearchResult;
  reports?: ListReportsResult;
  briefing?: BriefingSummary;
  briefings?: BriefingSummary[];
}

export function McpSearchWorkbench(props: {
  showKeyHint?: boolean;
  showHistory?: boolean;
  compact?: boolean;
}): JSX.Element {
  const { apiKey, status, statusMsg } = useMcp();
  const [mode, setMode] = useState<Mode>('report');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [hit, setHit] = useState<SearchHit | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [history, setHistory] = useState<string[]>([]);

  const [selectedReport, setSelectedReport] = useState<TiReportSummary | null>(null);
  const [reportDetail, setReportDetail] = useState<ReportDetailsResult | null>(null);
  const [reportSummary, setReportSummary] = useState<string | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);

  const [timeRange, setTimeRange] = useState<TimeRange>('');
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [detailsCache, setDetailsCache] = useState<Map<string, ReportDetailsResult>>(new Map());
  const [filterBusy, setFilterBusy] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    setHistory(loadHistory());
  }, []);

  // Auto-load latest reports on connect. `hit`/`busy`/`runLatestReports` are
  // intentionally excluded: the guard is a snapshot at connect time, and
  // including them would re-trigger the load after every search/state change.
  /* eslint-disable react-hooks/exhaustive-deps */
  useEffect(() => {
    if (status === 'connected' && apiKey && !hit && !busy) {
      void runLatestReports();
    }
  }, [status, apiKey]);
  /* eslint-enable react-hooks/exhaustive-deps */

  async function runLatestReports(): Promise<void> {
    if (!apiKey) return;
    setBusy(true);
    setErr(null);
    try {
      const [reportsRes, briefings] = await Promise.allSettled([
        listReports(apiKey, { limit: 15, timeRange: timeRange || undefined }),
        listBriefings(apiKey, 5),
      ]);
      const searchHit: SearchHit = {};
      if (reportsRes.status === 'fulfilled') searchHit.reports = reportsRes.value;
      if (briefings.status === 'fulfilled') {
        searchHit.briefings = briefings.value;
        searchHit.briefing = briefings.value[0];
      }
      setHit(searchHit);
    } catch (e) {
      setErr(e instanceof McpError ? e.message : errMessage(e));
    } finally {
      setBusy(false);
    }
  }

  function pushHistory(item: string): void {
    if (!item) return;
    setHistory((h) => {
      const next = [item, ...h.filter((x) => x !== item)].slice(0, HISTORY_MAX);
      saveHistory(next);
      return next;
    });
  }

  const run = useCallback(
    async (queryArg?: string) => {
      if (status !== 'connected' || !apiKey) return;
      const query = (queryArg ?? q).trim();
      if (mode !== 'briefing' && !query) return;
      setQ(query);
      setBusy(true);
      setErr(null);
      setHit(null);
      setSelectedReport(null);
      setReportDetail(null);
      setReportSummary(null);
      try {
        if (mode === 'ioc') {
          setHit({ ioc: await searchIoc(apiKey, query) });
        } else if (mode === 'cve') {
          setHit({ cve: await searchCve(apiKey, query.toUpperCase()) });
        } else if (mode === 'report') {
          setHit({
            reports: await listReports(apiKey, { search: query, limit: 20, timeRange: timeRange || undefined }),
          });
        } else {
          const list = await listBriefings(apiKey, 10);
          setHit({ briefings: list, briefing: list[0] });
        }
        pushHistory(`${mode}:${query}`);
      } catch (e) {
        setErr(e instanceof McpError ? e.message : errMessage(e));
      } finally {
        setBusy(false);
      }
    },
    [apiKey, status, q, mode, timeRange]
  );

  async function openReport(r: TiReportSummary): Promise<void> {
    if (!apiKey) return;
    const rid = idForReport(r);
    if (!rid) return;
    if (selectedReport === r) {
      setSelectedReport(null);
      setReportDetail(null);
      setReportSummary(null);
      return;
    }
    setSelectedReport(r);
    setReportDetail(null);
    setReportSummary(null);
    setDetailBusy(true);
    try {
      const [detail, summary] = await Promise.allSettled([
        getReportDetailsFlexible(apiKey, rid),
        getReportContent(apiKey, rid, 'summary'),
      ]);
      if (detail.status === 'fulfilled') setReportDetail(detail.value);
      if (summary.status === 'fulfilled' && typeof summary.value === 'string') setReportSummary(summary.value);
    } catch {
      /* partial failure is ok */
    }
    setDetailBusy(false);
  }

  // Fetch details for all visible reports when severity filter is active
  useEffect(() => {
    if (severityFilter.size === 0 || !hit?.reports?.reports || !apiKey) return;
    const reports = hit.reports.reports;
    const uncached = reports.filter((r) => {
      const rid = idForReport(r);
      return rid && !detailsCache.has(rid);
    });
    if (uncached.length === 0) return;

    const ctrl = new AbortController();
    abortRef.current?.abort();
    abortRef.current = ctrl;
    setFilterBusy(true);

    (async () => {
      const results = await Promise.allSettled(
        uncached.map(async (r) => {
          const rid = idForReport(r);
          if (!rid) return null;
          try {
            const d = await getReportDetailsFlexible(apiKey, rid);
            return { rid, detail: d };
          } catch {
            return null;
          }
        })
      );
      if (ctrl.signal.aborted) return;
      setDetailsCache((prev) => {
        const next = new Map(prev);
        for (const r of results) {
          if (r.status === 'fulfilled' && r.value) {
            next.set(r.value.rid, r.value.detail);
          }
        }
        return next;
      });
      setFilterBusy(false);
    })();

    return () => ctrl.abort();
  }, [severityFilter, hit, apiKey, detailsCache]);

  const placeholders: Record<Mode, string> = {
    ioc: '8.8.8.8 · evil.com · sha256:…',
    cve: 'CVE-2025-55182',
    report: 'ransomware · lazarus · apt29',
    briefing: '(no input needed - list latest briefings)',
  };
  const disabled = status !== 'connected' || busy || (mode !== 'briefing' && !q.trim());

  // Client-side severity filtering on report results
  const filteredReports = useMemo(() => {
    if (!hit?.reports?.reports) return undefined;
    if (severityFilter.size === 0) return hit.reports;
    const filtered = hit.reports.reports.filter((r) => {
      const rid = idForReport(r);
      if (!rid) return false;
      const detail = detailsCache.get(rid);
      if (!detail?.severity) return true; // keep reports without detail loaded
      return severityFilter.has(detail.severity.toLowerCase() as Severity);
    });
    return { ...hit.reports, reports: filtered };
  }, [hit?.reports, severityFilter, detailsCache]);

  const activeFilterCount = (timeRange ? 1 : 0) + severityFilter.size;
  const totalCount = hit?.reports?.reports?.length ?? 0;
  const filteredCount = filteredReports?.reports?.length ?? 0;
  const apiTotal = hit?.reports?.total;
  const hasFilters = activeFilterCount > 0;

  return (
    <div className={props.compact ? '' : 'surface-card'}>
      <div className={props.compact ? '' : 'p-4'}>
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <Search className="h-4 w-4 text-brand-600 dark:text-brand-400" />
          <h3 className="text-sm font-semibold text-heading">
            {props.compact ? 'Quick MCP search' : 'TI-Mindmap-Hub Search'}
          </h3>
          <span className="ml-auto text-micro font-mono uppercase text-muted">via MCP · 25 tools</span>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <div className="flex rounded border border-line-2 overflow-hidden text-xs font-mono">
            {(['report', 'ioc', 'cve', 'briefing'] as Mode[]).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                className={`px-2.5 py-1.5 ${mode === m ? 'bg-brand-50 dark:bg-brand-950/40 text-brand-700 dark:text-brand-300' : 'bg-white dark:bg-surface-200 text-body hover:bg-slate-50 dark:hover:bg-surface-300'}`}
              >
                {m}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            disabled={mode === 'briefing'}
            placeholder={placeholders[mode]}
            className="flex-1 min-w-[12rem] rounded border border-line-2 bg-surface-100 px-2.5 py-1.5 font-mono text-sm text-heading disabled:opacity-50"
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="submit"
            disabled={disabled}
            className="inline-flex items-center gap-1.5 rounded border border-brand-300 dark:border-brand-700 bg-brand-600 dark:bg-brand-500 px-3 py-1.5 text-sm font-medium text-on-fill hover:bg-brand-700 disabled:opacity-50 transition-colors"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
            search
          </button>
          {(hit || err) && (
            <button
              type="button"
              onClick={() => {
                setHit(null);
                setErr(null);
                setQ('');
                setSelectedReport(null);
                setReportDetail(null);
                setReportSummary(null);
              }}
              className="rounded border border-line-2 px-2 py-1.5 text-xs text-body"
              aria-label="Clear results"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </form>

        {/* Filter bar - only visible in report mode with results */}
        {mode === 'report' && hit?.reports && (
          <div className="mt-3 rounded-xl border border-line-1 bg-surface-200/50 p-3 space-y-2.5">
            {/* Row 1: Date range */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5">
                <Calendar className="h-3 w-3 text-muted" />
                <span className="text-micro font-mono uppercase tracking-wider text-muted">date</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {(['', '24h', '7d', '30d', '90d'] as TimeRange[]).map((tr) => (
                  <button
                    key={tr}
                    type="button"
                    onClick={() => {
                      setTimeRange(tr);
                      if (mode === 'report') {
                        setBusy(true);
                        listReports(apiKey!, { search: q || undefined, limit: 20, timeRange: tr || undefined })
                          .then((res) => setHit((prev) => (prev ? { ...prev, reports: res } : prev)))
                          .catch(() => {})
                          .finally(() => setBusy(false));
                      }
                    }}
                    className={`text-micro font-mono px-2 py-0.5 rounded-full border transition-colors ${
                      timeRange === tr
                        ? 'border-brand-400 bg-brand-50 dark:bg-brand-950/40 text-brand-700 dark:text-brand-300 font-medium'
                        : 'border-line-1 text-muted hover:border-brand-400/50 hover:text-brand-600 dark:hover:text-brand-400'
                    }`}
                  >
                    {TIME_RANGE_LABELS[tr]}
                  </button>
                ))}
              </div>
            </div>

            {/* Row 2: Severity */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5">
                <Shield className="h-3 w-3 text-muted" />
                <span className="text-micro font-mono uppercase tracking-wider text-muted">severity</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {SEVERITY_ORDER.map((sev) => {
                  const active = severityFilter.has(sev);
                  return (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => {
                        setSeverityFilter((prev) => {
                          const next = new Set(prev);
                          if (next.has(sev)) next.delete(sev);
                          else next.add(sev);
                          return next;
                        });
                      }}
                      className={`text-micro font-mono px-2 py-0.5 rounded-full border transition-colors ${
                        active ? SEVERITY_PILL[sev] + ' font-medium' : 'border-line-1 text-muted hover:border-slate-300'
                      }`}
                    >
                      {sev}
                    </button>
                  );
                })}
              </div>
              {filterBusy && (
                <span className="flex items-center gap-1 text-micro text-muted ml-1">
                  <Loader2 className="h-3 w-3 animate-spin" /> loading…
                </span>
              )}
            </div>

            {/* Row 3: Summary + clear */}
            <div className="flex items-center justify-between gap-2 pt-1 border-t border-line-1/60">
              <div className="flex items-center gap-1.5 text-micro font-mono text-muted">
                <Filter className="h-3 w-3" />
                <span>
                  {hasFilters ? (
                    <>
                      <span className="text-heading font-medium">{filteredCount}</span> of{' '}
                      <span className="text-heading">{totalCount}</span> reports
                      {typeof apiTotal === 'number' && apiTotal > totalCount && (
                        <span className="text-muted"> (of {apiTotal} total)</span>
                      )}
                    </>
                  ) : (
                    <>
                      <span className="text-heading font-medium">{totalCount}</span> reports
                      {typeof apiTotal === 'number' && apiTotal > totalCount && (
                        <span className="text-muted"> (of {apiTotal} total)</span>
                      )}
                    </>
                  )}
                </span>
                {hasFilters && (
                  <span className="text-muted">
                    · {activeFilterCount} filter{activeFilterCount === 1 ? '' : 's'} active
                  </span>
                )}
              </div>
              {hasFilters && (
                <button
                  type="button"
                  onClick={() => {
                    setTimeRange('');
                    setSeverityFilter(new Set());
                  }}
                  className="text-micro font-mono text-muted hover:text-rose-500 transition-colors"
                >
                  clear all
                </button>
              )}
            </div>
          </div>
        )}

        {status === 'unconfigured' && props.showKeyHint !== false && (
          <p className="mt-3 text-xs text-muted">
            Add your TI-Mindmap-Hub API key in the page header to enable search. Keys stay in your browser
            (localStorage).
          </p>
        )}
        {status === 'error' && (
          <div className="mt-3 flex flex-wrap items-start gap-2 rounded border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 px-2.5 py-1.5 text-xs text-rose-700 dark:text-rose-300">
            <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="font-mono font-semibold">MCP connection error</p>
              {statusMsg && (
                <p className="mt-0.5 font-mono text-mini text-rose-700/80 dark:text-rose-300/80 break-words">
                  {statusMsg}
                </p>
              )}
              <p className="mt-1 text-rose-700/80 dark:text-rose-300/80">
                Common causes: invalid or revoked key, or network/CORS issue. Open the MCP pill in the header to edit or
                re-probe the key.
              </p>
            </div>
          </div>
        )}

        {props.showHistory !== false && history.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="text-micro font-mono uppercase text-muted mr-1">recent:</span>
            {history.map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => {
                  const [m, ...rest] = h.split(':');
                  setMode((m as Mode) ?? 'ioc');
                  const text = rest.join(':');
                  setQ(text);
                  void run(text);
                }}
                className="rounded border border-line-2 bg-surface-200 px-2 py-0.5 text-micro font-mono text-body hover:border-brand-400"
                title={h}
              >
                {h}
              </button>
            ))}
            <button
              type="button"
              onClick={() => {
                setHistory([]);
                saveHistory([]);
              }}
              className="text-micro text-muted hover:text-rose-600 dark:hover:text-rose-400"
            >
              clear
            </button>
          </div>
        )}

        {err && (
          <div className="mt-3 rounded border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 p-2.5 text-xs text-rose-700 dark:text-rose-300">
            <AlertTriangle className="inline h-3.5 w-3.5 mr-1" /> {err}
          </div>
        )}

        {hit && (
          <div className="mt-3 space-y-3">
            {hit.ioc && <IocHitCard hit={hit.ioc} onSelectReport={openReport} selectedReport={selectedReport} />}
            {hit.cve && <CveHitCard hit={hit.cve} />}
            {filteredReports && (
              <ReportsHitCard
                hit={filteredReports}
                onSelectReport={openReport}
                selectedReport={selectedReport}
                reportDetail={reportDetail}
                reportSummary={reportSummary}
                detailBusy={detailBusy}
              />
            )}
            {hit.briefings && hit.briefings.length > 0 && !filteredReports && (
              <BriefingsHitCard briefings={hit.briefings} />
            )}
            {hit.briefing && hit.reports && (
              <div className="rounded border border-line-1 bg-surface-200 p-3">
                <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1">Latest Briefing</p>
                <BriefingInline hit={hit.briefing} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── IOC hit card ──────────────────────────────────────────────────

function IocHitCard({
  hit,
  onSelectReport,
  selectedReport,
}: {
  hit: IocSearchResult;
  onSelectReport: (r: TiReportSummary) => void;
  selectedReport: TiReportSummary | null;
}): JSX.Element {
  const reports = hit.reports ?? [];
  const total = hit.total_reports ?? reports.length;
  return (
    <div className="surface-card overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-4 py-2.5 bg-surface-200/30 border-b border-line-1">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-micro font-mono uppercase tracking-wider text-muted px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300">
            IOC
          </span>
          <span className="text-sm font-mono font-semibold text-heading truncate">{hit.ioc_value}</span>
          {hit.ioc_type && (
            <span className="shrink-0 rounded border border-line-2 px-1.5 py-0.5 text-micro font-mono text-muted">
              {hit.ioc_type}
            </span>
          )}
        </div>
        <span
          className={`shrink-0 text-micro font-mono px-1.5 py-0.5 rounded ${total > 0 ? 'bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300' : 'text-slate-500'}`}
        >
          {total} report{total === 1 ? '' : 's'}
        </span>
      </div>
      <div className="p-3">
        <div className="flex flex-wrap gap-3 text-micro font-mono text-muted mb-2">
          {hit.first_seen && <span>first seen: {hit.first_seen}</span>}
          {hit.last_seen && <span>last seen: {hit.last_seen}</span>}
        </div>
        {reports.length === 0 ? (
          <p className="text-xs text-muted text-center py-3">No reports mention this indicator.</p>
        ) : (
          <ul className="space-y-1.5">
            {reports.slice(0, 8).map((r) => (
              <ReportRow
                key={idForReport(r) || r.title || ''}
                r={r}
                selected={selectedReport === r}
                onSelect={() => onSelectReport(r)}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── CVE hit card ──────────────────────────────────────────────────

function CveHitCard({ hit }: { hit: CveSearchResult }): JSX.Element {
  return (
    <div className="surface-card overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-4 py-2.5 bg-surface-200/30 border-b border-line-1">
        <div className="flex items-center gap-2 min-w-0">
          <Shield className="h-4 w-4 text-orange-500 shrink-0" />
          <span className="text-sm font-mono font-semibold text-heading">{hit.cve_id}</span>
          {hit.severity && <SeverityBadge severity={normalizeSeverity(hit.severity)} />}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {typeof hit.cvss_score === 'number' && (
            <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-body">
              CVSS {hit.cvss_score.toFixed(1)}
            </span>
          )}
          {typeof hit.epss_score === 'number' && (
            <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-body">
              EPSS {(hit.epss_score * 100).toFixed(1)}%
            </span>
          )}
          {hit.exploited && (
            <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 font-medium">
              KEV
            </span>
          )}
        </div>
      </div>
      <div className="p-3 space-y-2">
        {hit.description && <p className="text-xs text-body leading-relaxed">{hit.description}</p>}
        {(hit.affected_products?.length ?? 0) > 0 && (
          <div>
            <p className="text-micro font-mono uppercase text-muted mb-1">affected</p>
            <div className="flex flex-wrap gap-1">
              {hit.affected_products!.slice(0, 6).map((p, i) => (
                <span
                  key={i}
                  className="rounded bg-orange-100 dark:bg-orange-950/30 px-1.5 py-0.5 text-micro font-mono text-orange-700 dark:text-orange-300"
                >
                  {p}
                </span>
              ))}
              {hit.affected_products!.length > 6 && (
                <span className="text-micro text-muted">+{hit.affected_products!.length - 6}</span>
              )}
            </div>
          </div>
        )}
        {(hit.references?.length ?? 0) > 0 && (
          <div>
            <p className="text-micro font-mono uppercase text-muted mb-1">references</p>
            <div className="flex flex-wrap gap-1.5">
              {hit.references!.slice(0, 4).map((ref, i) => (
                <a
                  key={i}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-0.5 text-micro font-mono text-brand-600 dark:text-brand-400 hover:underline truncate max-w-[18rem] transition-colors"
                >
                  <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                  {ref.replace(/^https?:\/\//, '').slice(0, 60)}
                </a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Reports hit card ──────────────────────────────────────────────

function ReportsHitCard({
  hit,
  onSelectReport,
  selectedReport,
  reportDetail,
  reportSummary,
  detailBusy,
}: {
  hit: ListReportsResult;
  onSelectReport: (r: TiReportSummary) => void;
  selectedReport: TiReportSummary | null;
  reportDetail: ReportDetailsResult | null;
  reportSummary: string | null;
  detailBusy: boolean;
}): JSX.Element {
  const reports = hit.reports ?? [];
  return (
    <div className="surface-card overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-4 py-2.5 bg-surface-200/30 border-b border-line-1">
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 text-brand-500" />
          <span className="text-xs font-semibold text-heading">Reports</span>
          <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-950/40 text-brand-700 dark:text-brand-300">
            {reports.length}
          </span>
        </div>
        {typeof hit.total === 'number' && hit.total !== reports.length && (
          <span className="text-micro font-mono text-muted">of {hit.total} total</span>
        )}
      </div>
      <div className="p-3">
        {reports.length === 0 ? (
          <p className="text-xs text-muted text-center py-4">No matching reports.</p>
        ) : (
          <ul className="space-y-1.5">
            {reports.slice(0, 10).map((r) => (
              <ReportRow
                key={idForReport(r) || r.title || ''}
                r={r}
                selected={selectedReport === r}
                onSelect={() => onSelectReport(r)}
              />
            ))}
          </ul>
        )}

        {/* Detail panel for selected report */}
        {selectedReport && (
          <ReportDetailPanel report={selectedReport} detail={reportDetail} summary={reportSummary} busy={detailBusy} />
        )}
      </div>
    </div>
  );
}

// ── Report detail panel (inline expansion) ────────────────────────

function ReportDetailPanel({
  report,
  detail,
  summary,
  busy,
}: {
  report: TiReportSummary;
  detail: ReportDetailsResult | null;
  summary: string | null;
  busy: boolean;
}): JSX.Element {
  const rid = idForReport(report);
  const sourceUrl = detail?.url || report.url || (rid ? `https://ti-mindmap-hub.com/report/${rid}` : null);

  return (
    <div className="mt-2 rounded border border-brand-200 dark:border-brand-800 bg-surface-100 p-3 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold text-heading line-clamp-2">{report.title || rid}</p>
          <div className="flex flex-wrap items-center gap-2 mt-1 text-micro font-mono text-muted">
            {report.source && <span>{report.source}</span>}
            {report.published_at && <span>· {report.published_at}</span>}
            {report.actor && <span className="text-rose-600 dark:text-rose-400">actor: {report.actor}</span>}
          </div>
        </div>
        {sourceUrl && (
          <a
            href={sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 inline-flex items-center gap-1 text-micro text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            <ExternalLink className="h-3 w-3" /> source
          </a>
        )}
      </div>

      {busy && (
        <div className="flex items-center gap-1.5 text-micro text-muted">
          <Loader2 className="h-3 w-3 animate-spin" /> Loading details…
        </div>
      )}

      {!busy && detail && (
        <>
          {detail.summary && <p className="text-mini text-muted leading-relaxed">{detail.summary}</p>}

          <DetailSection label="IOCs" items={detail.iocs?.map((i) => i.value)} color="rose" />
          <DetailSection label="TTPs" items={detail.ttps?.map((t) => t.name ?? t.id ?? '')} color="violet" />
          <DetailSection label="CVEs" items={detail.cves} color="orange" />
          <DetailSection label="Malware" items={detail.malware} color="emerald" />

          <div className="flex flex-wrap items-center gap-3 pt-1 text-micro font-mono text-muted">
            {detail.severity && <span>severity: {detail.severity}</span>}
            {typeof detail.cvss === 'number' && <span>CVSS {detail.cvss.toFixed(1)}</span>}
            {typeof detail.epss === 'number' && <span>EPSS {(detail.epss * 100).toFixed(1)}%</span>}
          </div>
        </>
      )}

      {!busy && !detail && summary && <p className="text-mini text-muted leading-relaxed line-clamp-6">{summary}</p>}
    </div>
  );
}

function DetailSection({
  label,
  items,
  color,
}: {
  label: string;
  items?: string[];
  color: string;
}): JSX.Element | null {
  if (!items || items.length === 0) return null;
  const colorCls: Record<string, string> = {
    rose: 'bg-rose-100 dark:bg-rose-950/30 text-rose-700 dark:text-rose-300',
    violet: 'bg-violet-100 dark:bg-violet-950/30 text-violet-700 dark:text-violet-300',
    orange: 'bg-orange-100 dark:bg-orange-950/30 text-orange-700 dark:text-orange-300',
    emerald: 'bg-emerald-100 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300',
  };
  return (
    <div>
      <p className="text-micro font-mono uppercase text-muted mb-0.5">
        {label} · {items.length}
      </p>
      <div className="flex flex-wrap gap-1">
        {items.slice(0, 12).map((item, i) => (
          <span key={i} className={`rounded px-1.5 py-0.5 text-micro font-mono ${colorCls[color] ?? ''}`}>
            {item}
          </span>
        ))}
        {items.length > 12 && <span className="text-micro text-muted">+{items.length - 12}</span>}
      </div>
    </div>
  );
}

// ── Briefings hit card ────────────────────────────────────────────

function BriefingsHitCard({ briefings }: { briefings: BriefingSummary[] }): JSX.Element {
  return (
    <div className="surface-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 bg-surface-200/30 border-b border-line-1">
        <span className="text-xs font-semibold text-heading">Briefings</span>
        <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-purple-100 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300">
          {briefings.length}
        </span>
      </div>
      <div className="p-3">
        <ul className="space-y-1.5">
          {briefings.map((b, i) => (
            <BriefingRow key={b.briefing_id || i} hit={b} />
          ))}
        </ul>
      </div>
    </div>
  );
}

function BriefingInline({ hit }: { hit: BriefingSummary }): JSX.Element {
  return (
    <div className="flex items-start gap-2">
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-heading">{hit.title ?? hit.briefing_id}</p>
        <p className="text-micro font-mono uppercase text-muted">
          {hit.type ?? 'briefing'} · {hit.date ?? '-'}
        </p>
        {hit.summary && <p className="mt-1 text-mini text-muted line-clamp-3">{hit.summary}</p>}
      </div>
    </div>
  );
}

function BriefingRow({ hit }: { hit: BriefingSummary }): JSX.Element {
  return (
    <li className="rounded border border-line-1 bg-surface-100 px-2.5 py-1.5">
      <p className="text-xs font-medium text-heading">{hit.title ?? hit.briefing_id}</p>
      <p className="text-micro font-mono uppercase text-muted">
        {hit.type ?? 'briefing'} · {hit.date ?? '-'}
      </p>
      {hit.summary && <p className="mt-1 text-mini text-muted line-clamp-2">{hit.summary}</p>}
    </li>
  );
}

// ── Report row (clickable) ────────────────────────────────────────

function ReportRow({
  r,
  selected,
  onSelect,
}: {
  r: TiReportSummary;
  selected: boolean;
  onSelect: () => void;
}): JSX.Element {
  const id = idForReport(r);
  const sourceUrl = r.url || (id ? `https://ti-mindmap-hub.com/report/${id}` : null);

  return (
    <li
      onClick={onSelect}
      className={`rounded border cursor-pointer px-2.5 py-1.5 transition-colors ${
        selected
          ? 'border-brand-400 dark:border-brand-600 bg-brand-50/60 dark:bg-brand-950/20'
          : 'border-line-1 hover:border-brand-400/50 hover:bg-white dark:hover:bg-surface-200'
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium text-heading line-clamp-2 flex-1 min-w-0">{r.title ?? id}</p>
        {sourceUrl && (
          <a
            href={sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="shrink-0 text-muted hover:text-brand-600 dark:hover:text-brand-400"
            title="Open on ti-mindmap-hub.com"
          >
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 mt-0.5 text-micro font-mono uppercase text-muted">
        {r.source && <span>{r.source}</span>}
        {r.published_at && <span>· {r.published_at}</span>}
        {r.actor && <span className="text-rose-600 dark:text-rose-400">actor: {r.actor}</span>}
        {r.cves && r.cves.length > 0 && (
          <span className="text-amber-600 dark:text-amber-400">
            cve: {r.cves.slice(0, 2).join(', ')}
            {r.cves.length > 2 ? '…' : ''}
          </span>
        )}
        {typeof r.ioc_count === 'number' && r.ioc_count > 0 && (
          <span className="text-cyan-600 dark:text-cyan-400">{r.ioc_count} IOCs</span>
        )}
        {typeof r.ttp_count === 'number' && r.ttp_count > 0 && (
          <span className="text-violet-600 dark:text-violet-400">{r.ttp_count} TTPs</span>
        )}
      </div>
      {r.summary && !selected && <p className="mt-1 text-mini text-muted line-clamp-2">{r.summary}</p>}
      {r.tags && r.tags.length > 0 && !selected && (
        <div className="mt-1 flex flex-wrap gap-1">
          {r.tags.slice(0, 4).map((tag) => (
            <span key={tag} className="rounded bg-surface-300 px-1 py-0.5 text-micro font-mono text-muted">
              {tag}
            </span>
          ))}
        </div>
      )}
    </li>
  );
}
