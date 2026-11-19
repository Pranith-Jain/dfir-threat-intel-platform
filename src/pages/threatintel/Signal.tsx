import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Radio, ExternalLink, RefreshCw, Search } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { FeedAggregateCard } from '../../components/intel/FeedAggregateCard';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { XLivePanel } from '../../components/threatintel/XLivePanel';
import { sanitizeUrl } from '../../lib/sanitize-url';

/**
 * /threatintel/signal - the high-signal subset of /threatintel/writeups.
 *
 * The writeups endpoint aggregates ~30 RSS feeds across vendor labs,
 * independent researchers, and the Medium long-tail. That's the firehose.
 * This page asks for `?tier=signal`, which the server filters down to a
 * tight curated set (ThreatSignal, DFIR Report, SentinelLabs, Unit 42,
 * Check Point, Huntress, Eye, Exodus, OpenAnalysis, BushidoToken,
 * DoublePulsar). Low-volume sources, high-depth pieces - the kind of
 * source an analyst reads every time it ships.
 *
 * Same API contract as /writeups; tier filter is a server-side filter on
 * the already-cached firehose response so flipping between tiers doesn't
 * re-fetch upstream.
 */

interface Writeup {
  title: string;
  url: string;
  source: string;
  published?: string;
  description?: string;
  tags?: string[];
  author?: string;
  kind: 'medium' | 'devto' | 'hashnode' | 'rss' | 'jsonfeed' | 'manual';
}

interface SignalResponse {
  generated_at: string;
  sources: Array<{ kind: string; label: string; ok: boolean; count: number; error?: string }>;
  total: number;
  items: Writeup[];
}

function formatDate(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function shortRel(iso?: string): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const diff = Math.max(0, Date.now() - t) / 1000;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}d ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / (86400 * 7))}w ago`;
  return `${Math.floor(diff / (86400 * 30))}mo ago`;
}

export default function Signal(): JSX.Element {
  const [data, setData] = useState<SignalResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(new Set());
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/writeups?tier=signal', { signal: AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`upstream ${r.status}`);
        return r.json() as Promise<SignalResponse>;
      })
      .then((d) => {
        setData(d);
      })
      .catch((e: Error) => {
        if (e.name !== 'AbortError') setError(e.message);
      })
      .finally(() => {
        setLoading(false);
      });
    return () => ac.abort();
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!data) return [] as Writeup[];
    const q = query.trim().toLowerCase();
    return data.items.filter((it) => {
      if (sourceFilter.size > 0 && !sourceFilter.has(it.source)) return false;
      if (!q) return true;
      return (
        it.title.toLowerCase().includes(q) ||
        (it.description ?? '').toLowerCase().includes(q) ||
        it.source.toLowerCase().includes(q) ||
        (it.tags ?? []).some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [data, query, sourceFilter]);

  const sourceCounts = useMemo(() => {
    const m = new Map<string, number>();
    if (!data) return m;
    for (const it of data.items) m.set(it.source, (m.get(it.source) ?? 0) + 1);
    return m;
  }, [data]);

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
      icon={<Radio className="h-6 w-6" />}
      title="Research Signal"
      description={
        <>
          Curated set of vendor labs and independent research outlets. ThreatSignal Research, The DFIR Report,
          SentinelLabs, Unit 42, Check Point Research, Huntress, Eye Security, Exodus, OpenAnalysis, BushidoToken,
          DoublePulsar. Low-volume sources, longer-form pieces.
          <p className="text-meta text-muted font-mono mt-2">
            For the full ecosystem cut (including Medium tag feeds and the long tail), see{' '}
            <Link to="/threatintel/research-hub/writeups" className="text-rose-600 dark:text-rose-400 hover:underline">
              /threatintel/writeups
            </Link>
            .
          </p>
        </>
      }
      loading={loading}
      error={error}
      empty={filtered.length === 0}
      emptyMessage={
        query.trim() || sourceFilter.size > 0
          ? 'No items match the current filter.'
          : 'No items in the snapshot. Feed refreshes hourly - click refresh to re-pull.'
      }
      onRetry={() => setRefreshKey((k) => k + 1)}
      maxWidthClass="max-w-5xl"
    >
      {/* Aggregate STIX 2.1 intel card for the current curated cut. Pools
          titles + descriptions from the filtered set into one bundle so the
          page surfaces today's actors / malware / CVEs / IoCs at a glance. */}
      {filtered.length > 0 && (
        <>
          <PostAnalysisButton
            title="Research Signal Digest"
            description="AI-powered threat analysis of the current feed."
            source="signal"
          />
          <AiSummaryCard
            surface="Research Signal"
            items={filtered.slice(0, 30).map((it) => ({
              title: it.title,
              body: it.description ?? '',
              source: it.source,
            }))}
            requireAdmin={false}
          />
          <FeedAggregateCard
            sourceId="rss:signal"
            sourceName="Research Signal"
            title="Research Signal · today"
            items={filtered.map((it) => ({
              title: it.title,
              body: `${it.source} · ${it.description ?? ''}`,
            }))}
          />
        </>
      )}

      <section className="surface-card p-4 mb-4">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by title, source, tag, or summary…"
              className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
              aria-label="Filter research signal"
            />
          </div>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1"
          >
            <RefreshCw size={11} /> refresh
          </button>
        </div>
        {sourceCounts.size > 1 && (
          <div className="flex flex-wrap items-center gap-1.5 mt-3">
            <span className="text-mini font-mono uppercase tracking-[0.18em] text-muted mr-1">sources:</span>
            {Array.from(sourceCounts.entries())
              .sort((a, b) => b[1] - a[1])
              .map(([src, count]) => {
                const active = sourceFilter.has(src);
                return (
                  <button
                    key={src}
                    type="button"
                    onClick={() => toggleSource(src)}
                    className={`text-mini font-mono px-2 py-1 rounded border ${
                      active
                        ? 'border-rose-500/60 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                        : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/40'
                    }`}
                  >
                    {src} <span className="opacity-70">· {count}</span>
                  </button>
                );
              })}
            {(sourceFilter.size > 0 || query.trim()) && (
              <button
                type="button"
                onClick={() => {
                  setSourceFilter(new Set());
                  setQuery('');
                }}
                className="text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline ml-1"
              >
                clear
              </button>
            )}
          </div>
        )}
        {data && (
          <p className="text-mini font-mono text-muted mt-3">
            Showing <span className="text-body">{filtered.length}</span> of{' '}
            <span className="text-body">{data.total}</span> · {data.sources.length} sources · snapshot{' '}
            {new Date(data.generated_at).toLocaleString()}
          </p>
        )}
      </section>

      <ul className="space-y-3">
        {filtered.map((it) => (
          <li key={it.url} className="surface-card p-4">
            <a href={sanitizeUrl(it.url)} target="_blank" rel="noopener noreferrer" className="group block">
              <div className="flex items-baseline justify-between gap-3 mb-1.5">
                <span className="text-micro font-mono uppercase tracking-[0.18em] text-rose-600 dark:text-rose-400">
                  {it.source}
                </span>
                <span className="text-micro font-mono text-muted shrink-0" title={formatDate(it.published)}>
                  {shortRel(it.published)}
                </span>
              </div>
              <h2 className="font-display font-semibold text-base text-heading leading-snug group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors">
                {it.title}
                <ExternalLink size={12} className="inline-block ml-1 opacity-50" aria-hidden="true" />
              </h2>
              {it.description && (
                <p className="text-tool text-muted leading-relaxed mt-1.5 line-clamp-2">{it.description}</p>
              )}
            </a>
            {(it.tags?.length ?? 0) > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {it.tags!.slice(0, 6).map((t) => (
                  <span key={t} className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 text-muted">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>

      <div className="mt-8">
        <XLivePanel sinceHours={24} limit={10} title="X firehose · cybersec (last 24h)" />
      </div>
    </DataPageLayout>
  );
}
