import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { BookText, ExternalLink, RefreshCw, Search } from 'lucide-react';
import { FeedAggregateCard } from '../../components/intel/FeedAggregateCard';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { sanitizeUrl } from '../../lib/sanitize-url';

/**
 * /threatintel/writeups - live aggregation of long-form CTI writeups from
 * security-research blogs, vendor labs, and analyst Medium handles.
 *
 * Source list lives in api/src/lib/writeup-sources.ts and is pulled live
 * via /api/v1/writeups (RSS in, unified JSON out). Adding a new analyst
 * blog is one line: append to WRITEUP_SOURCES, redeploy, done.
 */

type WriteupKind = 'medium' | 'devto' | 'hashnode' | 'rss' | 'jsonfeed' | 'manual';

interface Writeup {
  title: string;
  url: string;
  source: string;
  published?: string;
  description?: string;
  tags?: string[];
  author?: string;
  kind: WriteupKind;
}

interface WriteupsResponse {
  generated_at: string;
  sources: Array<{ kind: string; label: string; ok: boolean; count: number; error?: string }>;
  total: number;
  items: Writeup[];
}

const KIND_PILL: Record<WriteupKind, string> = {
  medium: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  devto: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  hashnode: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  rss: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  jsonfeed: 'border-cyan-500/40 bg-cyan-500/10 text-sky-700 dark:text-sky-300',
  manual: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
};

const KIND_LABEL: Record<WriteupKind, string> = {
  medium: 'Medium',
  devto: 'dev.to',
  hashnode: 'Hashnode',
  rss: 'Vendor / Blog',
  jsonfeed: 'JSON Feed',
  manual: 'Featured',
};

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

export default function Writeups(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<WriteupsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState(searchParams.get('q') ?? '');
  const [kindFilter, setKindFilter] = useState<Set<WriteupKind>>(
    () => new Set((searchParams.get('kind')?.split(',').filter(Boolean) ?? []) as WriteupKind[])
  );
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(
    () => new Set(searchParams.get('src')?.split(',').filter(Boolean) ?? [])
  );
  const [refreshKey, setRefreshKey] = useState(0);

  // Keep filter state in the URL so a curated view is shareable.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        if (query.trim()) out.set('q', query.trim());
        else out.delete('q');
        if (kindFilter.size > 0) out.set('kind', [...kindFilter].join(','));
        else out.delete('kind');
        if (sourceFilter.size > 0) out.set('src', [...sourceFilter].join(','));
        else out.delete('src');
        return out;
      },
      { replace: true }
    );
  }, [query, kindFilter, sourceFilter, setSearchParams]);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/writeups', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`upstream ${r.status}`);
        return r.json() as Promise<WriteupsResponse>;
      })
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message ?? 'failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!data) return [] as Writeup[];
    const q = query.trim().toLowerCase();
    return data.items.filter((it) => {
      if (kindFilter.size > 0 && !kindFilter.has(it.kind)) return false;
      if (sourceFilter.size > 0 && !sourceFilter.has(it.source)) return false;
      if (!q) return true;
      return (
        it.title.toLowerCase().includes(q) ||
        (it.description ?? '').toLowerCase().includes(q) ||
        it.source.toLowerCase().includes(q) ||
        (it.author ?? '').toLowerCase().includes(q) ||
        (it.tags ?? []).some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [data, query, kindFilter, sourceFilter]);

  const kindCounts = useMemo(() => {
    const m: Record<WriteupKind, number> = { medium: 0, devto: 0, hashnode: 0, rss: 0, jsonfeed: 0, manual: 0 };
    if (!data) return m;
    for (const it of data.items) m[it.kind] += 1;
    return m;
  }, [data]);

  const sourceCounts = useMemo(() => {
    const m = new Map<string, number>();
    if (!data) return m;
    for (const it of data.items) m.set(it.source, (m.get(it.source) ?? 0) + 1);
    return m;
  }, [data]);

  const toggleKind = (k: WriteupKind) =>
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
      icon={<BookText className="h-6 w-6" />}
      title="Writeups feed"
      description={
        <>
          The broad ecosystem cut: vendor blogs, news outlets, Medium tag feeds, the long tail. For the curated
          analyst-must-read set, see{' '}
          <Link to="/threatintel/research-hub/signal" className="text-rose-600 dark:text-rose-400 hover:underline">
            /threatintel/research-hub/signal
          </Link>{' '}
          (no overlap between the two pages).
        </>
      }
      loading={loading}
      error={error}
      empty={filtered.length === 0}
      emptyMessage={
        query || kindFilter.size > 0 || sourceFilter.size > 0
          ? 'No writeups match the current filter.'
          : 'No writeups in the current snapshot.'
      }
      onRetry={() => setRefreshKey((k) => k + 1)}
      maxWidthClass="max-w-5xl"
    >
      <section className="surface-card p-4 mb-4">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by title, source, author, tag, or summary…"
              className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
              aria-label="Filter writeups"
            />
          </div>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-line-1 hover:border-rose-500/40"
          >
            <RefreshCw size={12} /> refresh
          </button>
        </div>
        {data && (
          <div className="flex flex-wrap items-center gap-1.5 mt-3">
            <span className="text-mini font-mono text-muted mr-1">platform:</span>
            {(['rss', 'medium', 'devto', 'hashnode', 'jsonfeed', 'manual'] as const).map((k) => {
              const count = kindCounts[k];
              if (count === 0) return null;
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
                  {KIND_LABEL[k]} <span className="opacity-70">· {count}</span>
                </button>
              );
            })}
          </div>
        )}
        {data && sourceCounts.size > 1 && (
          <div className="flex flex-wrap items-center gap-1.5 mt-2">
            <span className="text-mini font-mono text-muted mr-1">source:</span>
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
                        ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                        : 'border-slate-300 dark:border-line-1 text-slate-500'
                    }`}
                  >
                    {src} <span className="opacity-70">· {count}</span>
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
          <p className="text-mini font-mono text-muted mt-3">
            Showing <span className="text-body">{filtered.length}</span> of{' '}
            <span className="text-body">{data.total}</span> writeups across{' '}
            <span className="text-body">
              {data.sources.filter((s) => s.ok).length}/{data.sources.length}
            </span>{' '}
            sources.
          </p>
        )}
      </section>

      {/* Aggregate STIX 2.1 view of the firehose. Pools the top 40 visible
          titles + descriptions into one bundle so the page surfaces today's
          actors / malware / CVEs across the long tail without a per-item fan-out. */}
      {filtered.length > 0 && (
        <>
          <PostAnalysisButton
            title="CTI Writeups Digest"
            description="AI-powered threat analysis of the current feed."
            source="writeups"
          />
          <AiSummaryCard
            surface="CTI Writeups"
            items={filtered.slice(0, 40).map((it) => ({
              title: it.title,
              body: it.description ?? '',
              source: it.source,
            }))}
            requireAdmin={false}
          />
          <FeedAggregateCard
            sourceId="rss:writeups"
            sourceName="Writeups firehose"
            title="Writeups firehose · today"
            items={filtered.map((it) => ({
              title: it.title,
              body: `${it.source} · ${it.description ?? ''}`,
            }))}
          />
        </>
      )}

      <ul className="space-y-3">
        {filtered.map((it, i) => (
          <li key={`${it.url}-${i}`} className="surface-card p-4 hover:border-rose-500/40 transition-colors">
            <a href={sanitizeUrl(it.url)} target="_blank" rel="noopener noreferrer" className="group block">
              <div className="flex items-start justify-between gap-3 mb-1.5 flex-wrap">
                <h3 className="font-display font-semibold text-base text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400 flex-1 min-w-0">
                  {it.title}
                </h3>
                <ExternalLink size={12} className="text-muted shrink-0 mt-1" />
              </div>
              {it.description && (
                <p className="text-tool text-muted leading-relaxed mb-2 line-clamp-3">{it.description}</p>
              )}
              <div className="flex items-center gap-2 text-mini font-mono text-muted flex-wrap">
                <span className={`px-1.5 py-0.5 rounded border ${KIND_PILL[it.kind]}`}>{it.source}</span>
                {it.published && (
                  <span title={formatDate(it.published)}>{shortRel(it.published) || formatDate(it.published)}</span>
                )}
                {it.author && <span>by {it.author}</span>}
                {it.tags && it.tags.length > 0 && (
                  <span className="flex flex-wrap gap-1 ml-1">
                    {it.tags.slice(0, 4).map((t) => (
                      <span key={t} className="px-1 py-0.5 rounded bg-surface-300 text-muted">
                        {t}
                      </span>
                    ))}
                  </span>
                )}
              </div>
            </a>
          </li>
        ))}
      </ul>
    </DataPageLayout>
  );
}
