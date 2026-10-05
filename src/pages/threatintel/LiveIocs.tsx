import { useEffect, useMemo, useState } from 'react';
import { useApiData } from '../../hooks/useApiData';
import { IocChip } from '../../components/dfir/IocChip';
import { relativeAgo } from '../../lib/relativeTime';
const shortRel = (iso?: string) => relativeAgo(iso, 'no timestamp');
import { sanitizeUrl } from '../../lib/sanitize-url';
import { ExternalLink, Radio, RefreshCw, Search, Sparkles } from 'lucide-react';
import { useLastVisit, isNewSince } from '../../hooks';
import { DataState } from '../../components/DataState';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AdmiraltyBadge } from '../../components/dfir/AdmiraltyBadge';
import { gradeForLiveIoc } from '../../lib/dfir/admiralty-quick';
import { LiveFreshnessPill } from '../../components/LiveFreshnessPill';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';
import { sourceColor, sourcesSentence } from '../../lib/dfir/source-meta';

type IocKind = 'ip' | 'url' | 'domain' | 'hash';

interface LiveIoc {
  value: string;
  kind: IocKind;
  source: string;
  reporter?: string;
  context?: string;
  reference_url?: string;
  observed_at?: string;
  /** Extraction confidence, 0-1. Set by the ioc-normalize lib. */
  confidence?: number;
  /** Quick visual band: high / medium / low. */
  confidence_band?: 'high' | 'medium' | 'low';
}

interface LiveSource {
  id: string;
  ok: boolean;
  count: number;
  /**
   * Server sets this when the source returned >= the per-feed cap, i.e.
   * `count` is a truncation rather than the feed's real size. Without it a
   * 170k-line feed renders as a bare "300", indistinguishable from a small
   * feed — which reads as "not active" when it is the opposite.
   */
  capped?: boolean;
  /** ISO 8601 newest per-entry observation timestamp from this source. */
  newest_observation?: string;
}

interface LiveIocsResponse {
  generated_at: string;
  /**
   * Sources that contributed items to THIS snapshot. Drives the
   * count / freshness badge in the header. Silent-failure / empty
   * sources are NOT here - see `registered_sources` for the full roster.
   */
  sources: LiveSource[];
  /**
   * Every source the backend knows about, with the result of the latest
   * run attached. Includes silent-failure / empty sources. Used for the
   * "Sources: …" prose and the filter-pill row so the user sees the
   * full ~30-feed roster, not just the 10-12 that happened to have
   * items in the current snapshot. Field was added 2026-06 - older
   * responses omit it and we fall back to `sources`.
   */
  registered_sources?: LiveSource[];
  total: number;
  items: LiveIoc[];
}

type Freshness = 'fresh' | 'recent' | 'stale' | 'no-timestamp';

/** Bucket a per-source newest-observation timestamp into a freshness tier. */
function sourceFreshness(iso?: string): Freshness {
  if (!iso) return 'no-timestamp';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'no-timestamp';
  const ageH = (Date.now() - t) / 3600_000;
  if (ageH <= 6) return 'fresh';
  if (ageH <= 48) return 'recent';
  return 'stale';
}

const FRESHNESS_DOT: Record<Freshness, { cls: string; label: string }> = {
  fresh: { cls: 'bg-emerald-500', label: 'fresh (<6h)' },
  recent: { cls: 'bg-sky-500', label: 'recent (<48h)' },
  stale: { cls: 'bg-rose-500', label: 'stale (>48h)' },
  'no-timestamp': { cls: 'bg-slate-400', label: 'no per-entry timestamp' },
};

const KIND_PILL: Record<IocKind, string> = {
  ip: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  url: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  domain: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  hash: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
};

/** Confidence-band pill colors. Aligned with the ioc-normalize lib's
 *  `scoreConfidence` band thresholds: high ≥ 0.8, medium ≥ 0.5, low < 0.5. */
const CONFIDENCE_PILL: Record<'high' | 'medium' | 'low', string> = {
  high: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  medium: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  low: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
};

export default function LiveIocs(): JSX.Element {
  const { data, loading, error, refetch } = useApiData<LiveIocsResponse>('/api/v1/live-iocs', { ttl: 30_000 });
  const [query, setQuery] = useState('');
  const [kindFilter, setKindFilter] = useState<Set<IocKind>>(new Set());
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(new Set());
  const [newOnly, setNewOnly] = useState(false);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;
  const { previous: lastVisit, markVisited } = useLastVisit('live-iocs');

  const filtered = useMemo(() => {
    if (!data) return [] as LiveIoc[];
    const q = query.trim().toLowerCase();
    return data.items.filter((it) => {
      if (kindFilter.size > 0 && !kindFilter.has(it.kind)) return false;
      if (sourceFilter.size > 0 && !sourceFilter.has(it.source)) return false;
      if (newOnly && !isNewSince(it.observed_at, lastVisit)) return false;
      if (!q) return true;
      return (
        it.value.toLowerCase().includes(q) ||
        (it.context ?? '').toLowerCase().includes(q) ||
        (it.reporter ?? '').toLowerCase().includes(q)
      );
    });
  }, [data, query, kindFilter, sourceFilter, newOnly, lastVisit]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [query, kindFilter, sourceFilter, newOnly]);

  const newCount = useMemo(() => {
    if (!data || !lastVisit) return 0;
    return data.items.filter((it) => isNewSince(it.observed_at, lastVisit)).length;
  }, [data, lastVisit]);

  useEffect(() => {
    if (!data) return;
    const id = window.setTimeout(markVisited, 1500);
    return () => window.clearTimeout(id);
  }, [data, markVisited]);

  const kindCounts = useMemo(() => {
    const m: Record<IocKind, number> = { ip: 0, url: 0, domain: 0, hash: 0 };
    if (!data) return m;
    for (const it of data.items) m[it.kind] += 1;
    return m;
  }, [data]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  // Clamp the page when the result set shrinks (e.g. a refetch on page 3 that
  // now yields one page) — otherwise the list renders blank with "page 3/1".
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);
  const pageItems = useMemo(() => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filtered, page]);

  const postSummaries = usePostSummaries({
    surface: 'Live IOC Stream',
    items: pageItems.map((it) => ({
      id: String(`${it.source}:${it.value}`),
      title: it.value,
      body: `${it.kind} · ${it.source} · ${it.context ?? ''}`,
      source: it.source,
    })),
  });

  const toggleKind = (k: IocKind) =>
    setKindFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const toggleSource = (s: string) =>
    setSourceFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Radio size={28} />}
      title="Live IOC stream"
      description={
        'A chronological firehose of individual indicators, each carrying a reporter handle, source feed, and first-observed timestamp. /correlation answers "what\'s in 2+ feeds"; this page answers "what\'s freshly observed and by whom."'
      }
      maxWidthClass="max-w-5xl"
      headerExtra={
        <>
          <LiveFreshnessPill tone="live" ago={data ? shortRel(data.generated_at) : undefined} className="ml-1" />
          <p className="text-xs text-muted font-mono mt-2">
            Sources:{' '}
            {(() => {
              const list = (data?.registered_sources ?? data?.sources ?? []).filter((s) => s.count > 0);
              const labels = sourcesSentence(list);
              return (
                <>
                  {labels}
                  <span className="text-muted italic"> (active only)</span>
                </>
              );
            })()}
          </p>
          {data &&
            (() => {
              const list = data.registered_sources ?? data.sources;
              if (list.length === 0) return null;
              const healthy = list.filter((s) => s.ok && s.count > 0).length;
              const unreachable = list.filter((s) => s.ok === false);
              const unreachableIds = unreachable.map((s) => s.id).join(', ');
              // Feeds whose real size is unknown because the server truncated
              // them at the per-feed cap. Shown separately so "capped" is never
              // mistaken for "empty" — these are typically the LARGEST feeds.
              const capped = list.filter((s) => s.capped);
              const dotCls = (cls: string) => `inline-block w-1.5 h-1.5 rounded-full ${cls}`;
              return (
                <p
                  className="text-xs text-muted font-mono mb-2"
                  title={
                    unreachable.length > 0
                      ? `Unreachable this snapshot: ${unreachableIds}`
                      : 'All registered feeds reachable this snapshot'
                  }
                >
                  feed health:{' '}
                  <span className="inline-flex items-center gap-1">
                    <span className={dotCls('bg-emerald-500')} aria-label="healthy" />
                    {healthy} healthy
                  </span>
                  <span className="mx-1.5 opacity-50">·</span>
                  <span
                    className={`inline-flex items-center gap-1 ${
                      unreachable.length > 0 ? 'text-rose-700 dark:text-rose-400' : ''
                    }`}
                  >
                    <span className={dotCls('bg-rose-400 dark:bg-rose-500')} aria-label="unreachable" />
                    {unreachable.length} unreachable
                  </span>
                  {capped.length > 0 && (
                    <>
                      <span className="mx-1.5 opacity-50">·</span>
                      <span
                        className="inline-flex items-center gap-1"
                        title={`Truncated at the 300-per-feed cap, so the real feed is larger: ${capped.map((s) => s.id).join(', ')}`}
                      >
                        <span className={dotCls('bg-sky-400 dark:bg-sky-500')} aria-label="capped" />
                        {capped.length} at cap
                      </span>
                    </>
                  )}
                </p>
              );
            })()}
        </>
      }
    >
      <section className="surface-card p-4 mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by indicator, reporter, or context…"
              className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
              aria-label="Filter IOC stream"
            />
          </div>
          {newCount > 0 && (
            <button
              type="button"
              onClick={() => setNewOnly((v) => !v)}
              className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border ${
                newOnly
                  ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                  : 'border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:border-emerald-500/60'
              }`}
              title={`${newCount} indicator${newCount === 1 ? '' : 's'} observed after your previous visit${lastVisit ? ` (${new Date(lastVisit).toLocaleString()})` : ''}`}
            >
              <Sparkles size={12} /> {newCount} new
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
          <span className="text-mini font-mono text-muted mr-1">kinds:</span>
          {(['ip', 'url', 'domain', 'hash'] as const).map((k) => {
            const active = kindFilter.has(k);
            return (
              <button
                key={k}
                type="button"
                onClick={() => toggleKind(k)}
                className={`text-mini font-mono px-2 py-1 rounded border ${
                  active ? KIND_PILL[k] : 'border-slate-300 dark:border-line-1 text-slate-500'
                }`}
              >
                {k} <span className="opacity-70">· {kindCounts[k]}</span>
              </button>
            );
          })}
        </div>
        {data && (
          <div className="flex flex-wrap items-center gap-1.5 mt-2">
            <span className="text-mini font-mono text-muted mr-1">sources:</span>
            {(data.registered_sources ?? data.sources).map((s) => {
              const active = sourceFilter.has(s.id);
              const pillCls = sourceColor(s.id);
              const fresh = sourceFreshness(s.newest_observation);
              const dot = FRESHNESS_DOT[fresh];
              const newestRel = s.newest_observation ? shortRel(s.newest_observation) : null;
              // Inactive here means: registered but produced 0 items OR errored
              // in the current snapshot. Still clickable for filtering (so the
              // user can pick "all sources" or drill in) - the filter just
              // won’t match anything until the source has items again.
              const isEmpty = s.count === 0;
              const tooltip = isEmpty
                ? s.ok
                  ? newestRel
                    ? `${s.id}: 0 items in this snapshot · ${dot.label} · newest ${newestRel}`
                    : `${s.id}: 0 items in this snapshot (bulk feed) · ${dot.label}`
                  : `${s.id} unreachable in this snapshot`
                : newestRel
                  ? `${s.count} items from ${s.id} · ${dot.label} · newest ${newestRel}`
                  : `${s.count} items from ${s.id} · ${dot.label}`;
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => toggleSource(s.id)}
                  className={`text-mini font-mono px-2 py-1 rounded border inline-flex items-center gap-1.5 ${
                    active
                      ? pillCls
                      : s.ok === false
                        ? 'border-rose-300/70 dark:border-rose-700/40 text-rose-700/80 dark:text-rose-400/80'
                        : isEmpty
                          ? 'border-slate-300/60 dark:border-line-1/60 text-muted opacity-60'
                          : 'border-slate-300 dark:border-line-1 text-slate-500'
                  }`}
                  title={tooltip}
                >
                  {!isEmpty && s.ok && (
                    <span className={`inline-block w-1.5 h-1.5 rounded-full ${dot.cls}`} aria-label={dot.label} />
                  )}
                  {isEmpty && s.ok && (
                    <span
                      className="inline-block w-1.5 h-1.5 rounded-full bg-slate-300 dark:bg-surface-300"
                      aria-label="empty this snapshot"
                    />
                  )}
                  {s.ok === false && (
                    <span
                      className="inline-block w-1.5 h-1.5 rounded-full bg-rose-400 dark:bg-rose-500"
                      aria-label="unreachable"
                    />
                  )}
                  {s.id}{' '}
                  <span
                    className="opacity-70"
                    title={s.capped ? 'At or above the per-feed cap (300) — the real feed is larger' : undefined}
                  >
                    · {s.count}
                    {s.capped ? '+' : ''}
                  </span>
                </button>
              );
            })}
            {(sourceFilter.size > 0 || kindFilter.size > 0) && (
              <button
                type="button"
                onClick={() => {
                  setSourceFilter(new Set());
                  setKindFilter(new Set());
                }}
                className="text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline ml-2"
              >
                clear
              </button>
            )}
          </div>
        )}
        {data && (
          <>
            <div className="flex flex-wrap items-center gap-3 mt-2 text-micro font-mono text-muted">
              <span>freshness:</span>
              {(['fresh', 'recent', 'stale', 'no-timestamp'] as const).map((f) => (
                <span key={f} className="inline-flex items-center gap-1">
                  <span className={`inline-block w-1.5 h-1.5 rounded-full ${FRESHNESS_DOT[f].cls}`} />
                  {FRESHNESS_DOT[f].label}
                </span>
              ))}
            </div>
            <p className="text-mini font-mono text-muted mt-3">
              Showing page{' '}
              <span className="text-body">
                {page}/{totalPages}
              </span>{' '}
              · <span className="text-body">{pageItems.length}</span> of{' '}
              <span className="text-body">{filtered.length}</span> filtered · {data.total} total · snapshot{' '}
              <span className="text-body">{shortRel(data.generated_at)}</span>
            </p>
          </>
        )}
      </section>

      {filtered.length > 0 && (
        <>
          <PostAnalysisButton
            title="Live IOC Stream Digest"
            description="AI-powered threat analysis of the current feed."
            source="liveiocs"
          />
          <AiSummaryCard
            surface="Live IOC Stream"
            items={filtered.slice(0, 30).map((it) => ({
              title: it.value,
              body: `${it.kind} · ${it.source} · ${it.context ?? ''}`,
              source: it.source,
            }))}
            requireAdmin={false}
          />
        </>
      )}

      <DataState
        loading={loading}
        error={error}
        empty={filtered.length === 0}
        emptyLabel={
          query || kindFilter.size > 0 || sourceFilter.size > 0
            ? 'No indicators match the current filter.'
            : 'No indicators in the current snapshot. The hourly cron repopulates this - click refresh to re-pull.'
        }
        onRetry={() => refetch()}
        rows={8}
      >
        <ul className="space-y-2">
          {pageItems.map((it, i) => {
            const sourcePill = sourceColor(it.source);
            return (
              <li key={`${it.source}:${it.value}:${i}`} className="surface-card px-3 py-2.5 flex items-center gap-3">
                <span
                  className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${KIND_PILL[it.kind]} shrink-0`}
                >
                  {it.kind}
                </span>
                {it.confidence_band && (
                  <span
                    className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border shrink-0 ${CONFIDENCE_PILL[it.confidence_band]}`}
                    title={
                      it.confidence != null
                        ? `extraction confidence: ${(it.confidence * 100).toFixed(0)}%`
                        : 'extraction confidence'
                    }
                  >
                    conf {Math.round((it.confidence ?? 0) * 100)}%
                  </span>
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <IocChip value={it.value} size="sm" bare truncate={56} className="min-w-0" />
                    {it.reference_url && (
                      <a
                        href={sanitizeUrl(it.reference_url) || undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center justify-center min-h-[44px] min-w-[44px] sm:min-h-0 sm:min-w-0 text-muted hover:text-rose-500 transition-colors shrink-0"
                        aria-label="open source post"
                        title="open source post"
                      >
                        <ExternalLink size={11} />
                      </a>
                    )}
                  </div>
                  <div className="text-mini font-mono text-muted flex items-center gap-2 flex-wrap mt-0.5">
                    <span className={`px-1.5 py-0.5 rounded border ${sourcePill}`}>{it.source}</span>
                    <AdmiraltyBadge admiralty={gradeForLiveIoc(it.source, it.kind)} compact />
                    {it.reporter && <span className="text-muted">{it.reporter}</span>}
                    {it.context && (
                      <span className="text-muted italic truncate max-w-[40ch]" title={it.context}>
                        · {it.context}
                      </span>
                    )}
                  </div>
                  <PostSummary text={postSummaries.get(String(`${it.source}:${it.value}`))} />
                </div>
                <div
                  className="shrink-0 text-right text-mini font-mono text-muted"
                  title={it.observed_at ?? 'no timestamp'}
                >
                  {shortRel(it.observed_at)}
                </div>
              </li>
            );
          })}
        </ul>
      </DataState>

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
    </DataPageLayout>
  );
}
