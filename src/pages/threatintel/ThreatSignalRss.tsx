// src/pages/threatintel/ThreatSignalRss.tsx
//
// Aggregated live-RSS reader for security research feeds. Currently sources
// threatsignal.in (THREAT INTEL / DEFENSIVE SEC / OFFENSIVE TRADECRAFT /
// ADVANCED RESEARCH) and opensourcemalware.com (software-supply-chain
// malware). Designed to grow: add a new source by appending one entry to
// the SOURCES list in api/src/routes/threatsignal-rss.ts and the page picks
// it up automatically.
//
//   - Fetches /api/v1/rss/aggregate (Worker proxy that fans out across all
//     sources in parallel, caches each in KV for 15 min, and serves a
//     merged JSON shape).
//   - Renders posts as cards with title, source pill, category badge,
//     publish date, and an external-link affordance.
//   - Filters: search box, source pills (multi-select), category pills
//     (multi-select), and a "fresh this week" toggle.
//   - Surfaces the per-source cache state: "Last updated" per source
//     and a stale-snapshot banner per affected source.

import { useState, useEffect, useCallback, useMemo } from 'react';
import { Rss, ExternalLink, Search, RefreshCw, AlertTriangle, Clock, Tag, ChevronRight } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';
import { errMessage } from '../../lib/log';

const AGGREGATE_URL = '/api/v1/rss/aggregate';

type Accent = 'rose' | 'emerald' | 'amber' | 'cyan' | 'violet' | 'sky' | 'slate';

interface RssItem {
  id: string;
  title: string;
  link: string;
  description: string;
  pubDate: string;
  pubDateRaw: string;
  category: string | null;
  guid: string;
  author: string | null;
  sourceId: string;
  sourceName: string;
  sourceAuthor: string | null;
  sourceAccent: Accent;
}

interface RssFeed {
  source: { id: string; name: string; author: string | null; accent: Accent; displayLink: string };
  channel: { title: string; link: string; description: string; language: string | null; lastBuildDate: string | null };
  items: RssItem[];
  cachedAt: string;
  stale: boolean;
}

interface RssAggregate {
  assembledAt: string;
  sources: Array<{
    source: { id: string; name: string; author: string | null; accent: Accent; displayLink: string };
    cachedAt: string;
    stale: boolean;
    error: string | null;
    itemCount: number;
  }>;
  feeds: RssFeed[];
  items: RssItem[];
}

/* ── Styling helpers ────────────────────────────────────────────── */

const CATEGORY_STYLE: Record<string, { label: string; className: string }> = {
  'THREAT INTEL': { label: 'Threat Intel', className: 'bg-rose-500/15 text-rose-300 border-rose-500/30' },
  'DEFENSIVE SEC': { label: 'Defensive Sec', className: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' },
  'OFFENSIVE TRADECRAFT': { label: 'Offensive', className: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  'ADVANCED RESEARCH': { label: 'Research', className: 'bg-violet-500/15 text-violet-300 border-violet-500/30' },
};

function categoryStyle(cat: string | null): { label: string; className: string } {
  if (!cat)
    return {
      label: 'Uncategorised',
      className: 'bg-slate-500/15 text-body border-slate-500/30',
    };
  return (
    CATEGORY_STYLE[cat] ?? {
      label: cat.charAt(0) + cat.slice(1).toLowerCase(),
      className: 'bg-slate-500/15 text-body border-slate-500/30',
    }
  );
}

const ACCENT_PILL: Record<Accent, string> = {
  rose: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  amber: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  cyan: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  violet: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  sky: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  slate: 'bg-slate-500/15 text-body border-slate-500/30',
};

/* ── Helpers ─────────────────────────────────────────────────────── */

function relativeDate(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const diffMs = Date.now() - t;
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  return new Date(t).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function fullDate(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/* ── Page ────────────────────────────────────────────────────────── */

export default function ThreatSignalRss(): JSX.Element {
  const [agg, setAgg] = useState<RssAggregate | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [activeSources, setActiveSources] = useState<Set<string>>(new Set()); // empty = all
  const [activeCategories, setActiveCategories] = useState<Set<string>>(new Set()); // empty = all
  const [freshOnly, setFreshOnly] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(AGGREGATE_URL, { cache: 'no-cache' });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
        throw new Error(body.message || body.error || `HTTP ${res.status}`);
      }
      setAgg((await res.json()) as RssAggregate);
    } catch (e) {
      console.error('ThreatSignalRss failed:', errMessage(e));
      setError((e as Error).message || 'failed to fetch feed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Distinct categories across the current aggregate (so the filter bar
  // only shows what's actually present).
  const categories = useMemo(() => {
    if (!agg) return [] as string[];
    const seen = new Set<string>();
    for (const it of agg.items) if (it.category) seen.add(it.category);
    return [...seen].sort();
  }, [agg]);

  // Source summary stats.
  const sourceStats = useMemo(() => {
    if (!agg) return new Map<string, { count: number; latest: string | null }>();
    const m = new Map<string, { count: number; latest: string | null }>();
    for (const it of agg.items) {
      const s = m.get(it.sourceId) ?? { count: 0, latest: null };
      s.count += 1;
      if (!s.latest || it.pubDate > s.latest) s.latest = it.pubDate;
      m.set(it.sourceId, s);
    }
    return m;
  }, [agg]);

  const filtered = useMemo(() => {
    if (!agg) return [] as RssItem[];
    const q = query.trim().toLowerCase();
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    return agg.items.filter((it) => {
      if (activeSources.size > 0 && !activeSources.has(it.sourceId)) return false;
      if (activeCategories.size > 0 && (!it.category || !activeCategories.has(it.category))) return false;
      if (freshOnly) {
        const t = Date.parse(it.pubDate);
        if (!Number.isFinite(t) || t < sevenDaysAgo) return false;
      }
      if (q) {
        const hay = `${it.title} ${it.description}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [agg, query, activeSources, activeCategories, freshOnly]);

  const postSummaries = usePostSummaries({
    surface: 'Threat Research Feeds',
    items: filtered.map((it) => ({
      id: String(it.id),
      title: it.title,
      body: it.description ?? '',
      source: it.sourceName,
    })),
  });

  const totalCount = agg?.items.length ?? 0;
  const healthySources = agg?.sources.filter((s) => !s.error || s.itemCount > 0) ?? [];
  const staleSources = agg?.sources.filter((s) => s.stale) ?? [];

  const headerExtra = agg && (
    <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-muted">
      <span className="inline-flex items-center gap-1">
        <Clock size={11} />
        assembled {relativeDate(agg.assembledAt)}
      </span>
      <span className="text-muted">·</span>
      <span>
        {healthySources.length}/{agg.sources.length} source{agg.sources.length === 1 ? '' : 's'} healthy
      </span>
      <button
        type="button"
        onClick={() => void load()}
        disabled={loading}
        className="inline-flex items-center gap-1 px-2 py-1 rounded border border-line-2 hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-40"
        title="Refetch the aggregate (the Worker still respects its 15-min KV cache per source)"
      >
        <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
        refresh
      </button>
    </div>
  );

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<Rss size={28} className="text-rose-500" />}
      title="Threat Research Feeds"
      description={
        <span>
          High-signal research feeds - long-form threat analysis, campaign breakdowns, and offensive tradecraft.
          Sources:{' '}
          <a
            href="https://www.threatsignal.in/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            ThreatSignal
          </a>
          ,{' '}
          <a
            href="https://opensourcemalware.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            OpenSourceMalware
          </a>
          ,{' '}
          <a
            href="https://ctrlaltintel.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Ctrl-Alt-Intel
          </a>
          ,{' '}
          <a
            href="https://research.checkpoint.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Check Point Research
          </a>
          ,{' '}
          <a
            href="https://unit42.paloaltonetworks.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Unit 42
          </a>
          ,{' '}
          <a
            href="https://www.elastic.co/security-labs"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Elastic Security Labs
          </a>
          ,{' '}
          <a
            href="https://www.volexity.com/blog/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Volexity
          </a>
          . Fetched every 15 min via Cloudflare edge cache.
        </span>
      }
      headerExtra={headerExtra}
      loading={loading && !agg}
      error={error}
      onRetry={load}
      empty={!loading && !error && filtered.length === 0 && totalCount > 0}
      emptyMessage={
        query || activeSources.size > 0 || activeCategories.size > 0 || freshOnly
          ? 'No posts match the current filters.'
          : 'The feeds are currently empty.'
      }
    >
      {/* Per-source stale banner */}
      {staleSources.length > 0 && (
        <div className="mb-4 rounded-xl border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 px-3 py-2 text-xs text-amber-700 dark:text-amber-300 font-mono flex items-start gap-2">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
          <span>
            <strong>Stale snapshot{staleSources.length === 1 ? '' : 's'}.</strong>{' '}
            {staleSources.map((s) => s.source.name).join(', ')} upstream
            {staleSources.length === 1 ? ' is' : 's are'} currently unreachable; showing the last good snapshot
            {staleSources.length === 1 ? '' : 's'}.
          </span>
        </div>
      )}

      {/* Per-source error banner (no items at all) */}
      {agg?.sources
        .filter((s) => s.error && s.itemCount === 0)
        .map((s) => (
          <div
            key={s.source.id}
            className="mb-4 rounded-xl border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/40 px-3 py-2 text-xs text-rose-700 dark:text-rose-300 font-mono flex items-start gap-2"
          >
            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
            <span>
              <strong>{s.source.name} is unreachable.</strong> {s.error}
            </span>
          </div>
        ))}

      {/* Stats strip */}
      {agg && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
          <StatCard label="Posts" value={totalCount} />
          <StatCard label="Sources" value={agg.sources.length} accent="violet" />
          <StatCard
            label="This week"
            value={
              agg.items.filter((it) => {
                const t = Date.parse(it.pubDate);
                return Number.isFinite(t) && t > Date.now() - 7 * 24 * 60 * 60 * 1000;
              }).length
            }
            accent="emerald"
          />
          <StatCard
            label="Latest"
            value={agg.items[0] ? relativeDate(agg.items[0].pubDate) : '-'}
            accent="amber"
            small
          />
        </div>
      )}

      {/* Per-source cache status row (so the visitor can see at a glance
          which feeds are fresh and which are serving last-good). */}
      {agg && agg.sources.length > 1 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-4">
          {agg.sources.map((s) => {
            const stats = sourceStats.get(s.source.id);
            return (
              <a
                key={s.source.id}
                href={s.source.displayLink}
                target="_blank"
                rel="noopener noreferrer"
                className="group rounded-xl border border-line-1 bg-surface-100/40 p-3 flex flex-col gap-1 transition-colors hover:border-rose-500/50"
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-flex items-center px-1.5 py-0.5 text-micro font-mono rounded border ${ACCENT_PILL[s.source.accent]}`}
                  >
                    {s.source.name}
                  </span>
                  {s.stale && (
                    <span className="inline-flex items-center gap-0.5 text-micro font-mono text-amber-500">
                      <AlertTriangle size={9} /> stale
                    </span>
                  )}
                  <ExternalLink size={10} className="ml-auto text-muted group-hover:text-rose-500" />
                </div>
                <div className="flex items-center gap-3 text-micro font-mono text-muted">
                  <span>{stats?.count ?? 0} posts</span>
                  <span>·</span>
                  <span>cached {relativeDate(s.cachedAt)}</span>
                  {stats?.latest && (
                    <>
                      <span>·</span>
                      <span>latest {relativeDate(stats.latest)}</span>
                    </>
                  )}
                </div>
              </a>
            );
          })}
        </div>
      )}

      {/* Filters */}
      {agg && agg.items.length > 0 && (
        <div className="rounded-xl border border-line-1 bg-surface-100/50 dark:bg-surface-200/30 p-3 mb-4 flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="search posts…"
                className="pl-7 pr-2 py-1 text-xs rounded border border-line-2 bg-surface-100 w-48"
              />
            </div>
            <label className="ml-auto inline-flex items-center gap-1 px-2 py-1 text-mini rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300 cursor-pointer">
              <input type="checkbox" checked={freshOnly} onChange={(e) => setFreshOnly(e.target.checked)} />
              fresh this week
            </label>
            <span className="text-xs text-muted font-mono">
              showing {filtered.length} of {totalCount}
            </span>
          </div>

          {/* Source pills */}
          {agg.sources.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-micro font-mono uppercase text-muted">Sources:</span>
              {agg.sources.map((s) => {
                const active = activeSources.has(s.source.id);
                return (
                  <button
                    key={s.source.id}
                    type="button"
                    onClick={() => {
                      setActiveSources((prev) => {
                        const next = new Set(prev);
                        if (active) next.delete(s.source.id);
                        else next.add(s.source.id);
                        return next;
                      });
                    }}
                    className={`inline-flex items-center gap-1 px-2 py-1 text-mini rounded border transition-colors ${
                      active
                        ? ACCENT_PILL[s.source.accent]
                        : 'bg-transparent text-muted border-slate-300 dark:border-line-1 hover:border-slate-500'
                    }`}
                  >
                    {s.source.name}
                    {s.stale && <AlertTriangle size={9} className="text-amber-500" />}
                  </button>
                );
              })}
              {activeSources.size > 0 && (
                <button
                  type="button"
                  onClick={() => setActiveSources(new Set())}
                  className="text-micro font-mono text-muted hover:text-rose-500 underline"
                >
                  clear
                </button>
              )}
            </div>
          )}

          {/* Category pills (only show if any items have categories) */}
          {categories.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-micro font-mono uppercase text-muted">Categories:</span>
              {categories.map((cat) => {
                const meta = categoryStyle(cat);
                const active = activeCategories.has(cat);
                return (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => {
                      setActiveCategories((prev) => {
                        const next = new Set(prev);
                        if (active) next.delete(cat);
                        else next.add(cat);
                        return next;
                      });
                    }}
                    className={`inline-flex items-center gap-1 px-2 py-1 text-mini rounded border transition-colors ${
                      active
                        ? meta.className
                        : 'bg-transparent text-muted border-slate-300 dark:border-line-1 hover:border-slate-500'
                    }`}
                  >
                    <Tag size={10} />
                    {meta.label}
                  </button>
                );
              })}
              {activeCategories.size > 0 && (
                <button
                  type="button"
                  onClick={() => setActiveCategories(new Set())}
                  className="text-micro font-mono text-muted hover:text-rose-500 underline"
                >
                  clear
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* AI summary of the current research signal cut */}
      {filtered.length > 0 && (
        <AiSummaryCard
          surface="Threat Research Feeds"
          items={filtered.slice(0, 30).map((it) => ({
            title: it.title,
            body: it.description,
            source: it.sourceName,
          }))}
          requireAdmin={false}
        />
      )}

      {/* Posts grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {filtered.map((it) => (
          <PostCard key={it.id} item={it} summary={postSummaries.get(String(it.id))} />
        ))}
      </div>
    </DataPageLayout>
  );
}

/* ── Post card ───────────────────────────────────────────────────── */

function PostCard({ item, summary }: { item: RssItem; summary?: string }): JSX.Element {
  const cat = categoryStyle(item.category);
  return (
    <div className="group rounded-xl border border-line-1 bg-surface-100/60 dark:bg-surface-200/40 p-4 flex flex-col gap-2 transition-colors hover:border-rose-500/50 hover:bg-surface-100/80 dark:hover:bg-surface-200/60">
      <div className="flex items-start gap-2">
        <a
          href={sanitizeUrl(item.link)}
          target="_blank"
          rel="noopener noreferrer"
          className="flex-1 font-semibold text-heading text-sm leading-snug group-hover:text-rose-600 dark:group-hover:text-rose-400 inline-flex items-center gap-1 transition-colors"
        >
          {item.title}
          <ExternalLink size={12} className="text-muted group-hover:text-rose-500 shrink-0 mt-0.5" />
        </a>
        <PostAnalysisButton
          title={item.title}
          description={item.description}
          source={item.sourceName}
          link={item.link}
          compact
        />
      </div>

      {item.description && <p className="text-xs text-muted leading-relaxed line-clamp-3">{item.description}</p>}

      <PostSummary text={summary} />

      <div className="flex flex-wrap items-center gap-2 mt-auto pt-2">
        {/* Source pill */}
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border ${ACCENT_PILL[item.sourceAccent]}`}
        >
          {item.sourceName}
        </span>
        {/* Category pill (only if present) */}
        {item.category && (
          <span
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border ${cat.className}`}
          >
            <Tag size={9} />
            {cat.label}
          </span>
        )}
        <span className="inline-flex items-center gap-1 text-micro font-mono text-muted" title={fullDate(item.pubDate)}>
          <Clock size={9} />
          {relativeDate(item.pubDate)}
        </span>
        {item.author && <span className="text-micro font-mono text-muted">· {item.author}</span>}
        <span className="ml-auto inline-flex items-center gap-0.5 text-micro font-mono text-muted group-hover:text-rose-500">
          read <ChevronRight size={10} />
        </span>
      </div>
    </div>
  );
}

/* ── Stat card ───────────────────────────────────────────────────── */

interface StatCardProps {
  label: string;
  value: number | string;
  accent?: 'brand' | 'emerald' | 'violet' | 'amber';
  small?: boolean;
}
function StatCard({ label, value, accent = 'brand', small = false }: StatCardProps): JSX.Element {
  const color =
    accent === 'emerald'
      ? 'text-emerald-500 dark:text-emerald-400'
      : accent === 'amber'
        ? 'text-amber-500 dark:text-amber-400'
        : accent === 'violet'
          ? 'text-violet-500 dark:text-violet-400'
          : 'text-rose-500 dark:text-rose-400';
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/40 px-3 py-2">
      <div className="text-micro uppercase tracking-wide text-muted font-mono">{label}</div>
      <div className={`font-bold font-mono ${color} ${small ? 'text-sm' : 'text-2xl'}`}>{value}</div>
    </div>
  );
}
