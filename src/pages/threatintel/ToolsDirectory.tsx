import { useEffect, useMemo, useState } from 'react';
import { Search, Wrench, ExternalLink, Github, Tag, RefreshCw } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface ToolEntry {
  slug: string;
  name: string;
  category: string;
  description: string;
  url: string;
  githubUrl?: string;
  language?: string;
  platforms?: string[];
  license?: string;
  isOpenSource: boolean;
  isOffensive: boolean;
  tags: string[];
}

interface ToolsPayload {
  count: number;
  tools: ToolEntry[];
}

interface StatsPayload {
  count: number;
  categories: string[];
}

export default function ToolsDirectory(): JSX.Element {
  const [data, setData] = useState<ToolsPayload | null>(null);
  const [stats, setStats] = useState<StatsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [offensiveFilter, setOffensiveFilter] = useState<boolean | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();

    setLoading(true);
    setError(null);

    const doFetch = async () => {
      try {
        const [resp, statsResp] = await Promise.all([
          fetch('/api/v1/tools', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) }),
          fetch('/api/v1/tools/stats', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) }),
        ]);
        if (cancelled) return;
        if (resp.ok) setData(await resp.json());
        else setError(`/tools returned HTTP ${resp.status}`);
        if (statsResp.ok) setStats(await statsResp.json());
      } catch (e) {
        console.error('ToolsDirectory failed:', errMessage(e));
        if (cancelled || (e instanceof DOMException && e.name === 'AbortError')) return;
        setError(errMessage(e, 'fetch failed'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    doFetch();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const allCategories = useMemo(() => {
    if (stats?.categories) return stats.categories;
    if (!data?.tools) return [];
    return [...new Set(data.tools.map((t) => t.category))].sort();
  }, [data, stats]);

  const filtered = useMemo(() => {
    if (!data?.tools) return [];
    const q = query.trim().toLowerCase();
    return data.tools.filter((t) => {
      if (selectedCategory && t.category !== selectedCategory) return false;
      if (offensiveFilter !== null && t.isOffensive !== offensiveFilter) return false;
      if (!q) return true;
      const hay = `${t.name} ${t.slug} ${t.description} ${t.tags.join(' ')} ${t.category}`.toLowerCase();
      return hay.includes(q);
    });
  }, [data, query, selectedCategory, offensiveFilter]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<Wrench className="h-6 w-6" />}
      title="Tools Directory"
      description="A curated directory of offensive and defensive security tools from the novasky.io reference. Browse by category, search by keyword, or filter by capability type."
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" /> refresh
          </button>
          {data && (
            <span className="rounded border border-line-2 px-2 py-1 text-muted font-mono">{data.count} tools</span>
          )}
        </div>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      empty={!loading && !data}
      emptyMessage="No tools data available."
      maxWidthClass="max-w-6xl"
    >
      {data && (
        <div className="animate-fade-in-up">
          {/* Stats bar */}
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Tools" value={stats?.count ?? data.count} />
            <Stat label="Categories" value={allCategories.length} />
            <Stat
              label="Filtered"
              value={query || selectedCategory || offensiveFilter !== null ? filtered.length : data.count}
            />
            <Stat label="Source" value="novasky.io" />
          </div>

          {/* Toolbar */}
          <section className="surface-card p-4 mb-4">
            <div className="flex flex-col gap-3">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={`Search ${data.count} tools…`}
                  className="w-full rounded-xl border border-line-2 bg-surface-100 py-2 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
                />
              </div>

              {/* Category pills */}
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => setSelectedCategory(null)}
                  className={`text-micro font-mono rounded-full border px-2.5 py-0.5 transition-colors ${
                    selectedCategory === null
                      ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                  }`}
                >
                  all
                </button>
                {allCategories.map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setSelectedCategory(cat === selectedCategory ? null : cat)}
                    className={`text-micro font-mono rounded-full border px-2.5 py-0.5 transition-colors ${
                      selectedCategory === cat
                        ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                        : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              {/* Offensive / defensive toggle */}
              <div className="flex gap-1.5">
                {(
                  [
                    { label: 'all', value: null },
                    { label: 'offensive', value: true },
                    { label: 'defensive', value: false },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.label}
                    type="button"
                    onClick={() => setOffensiveFilter(opt.value)}
                    className={`text-micro font-mono rounded-full border px-2.5 py-0.5 transition-colors ${
                      offensiveFilter === opt.value
                        ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                        : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </section>

          {/* Tool grid */}
          {filtered.length === 0 ? (
            <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
              <Search className="mx-auto mb-2 h-8 w-8 text-muted" />
              No tools match your filters
              {query && <> for &quot;{query}&quot;</>}.
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {filtered.map((tool) => (
                <ToolCard key={tool.slug} tool={tool} />
              ))}
            </div>
          )}
        </div>
      )}
    </DataPageLayout>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="surface-card px-3 py-2">
      <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
      <div className="text-lg font-semibold text-heading truncate">{value}</div>
    </div>
  );
}

function ToolCard({ tool }: { tool: ToolEntry }) {
  return (
    <a
      href={tool.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group block surface-card p-4 hover:border-rose-500/50 hover:shadow-e2 transition-all"
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <h3 className="font-display font-semibold text-base text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors leading-snug">
          {tool.name}
        </h3>
        <ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted group-hover:text-rose-500 transition-colors" />
      </div>

      <div className="flex flex-wrap items-center gap-1.5 mb-2">
        <span className="text-micro font-mono rounded-full border border-line-2 px-2 py-0.5 text-muted">
          {tool.category}
        </span>
        {tool.isOpenSource && (
          <span className="text-micro font-mono rounded-full border border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-0.5 text-emerald-700 dark:text-emerald-300">
            open source
          </span>
        )}
        {tool.isOffensive ? (
          <span className="text-micro font-mono rounded-full border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/40 px-2 py-0.5 text-rose-700 dark:text-rose-300">
            offensive
          </span>
        ) : (
          <span className="text-micro font-mono rounded-full border border-brand-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-950/40 px-2 py-0.5 text-brand-700 dark:text-brand-300">
            defensive
          </span>
        )}
      </div>

      <p className="text-xs text-muted leading-relaxed mb-3 line-clamp-2">{tool.description}</p>

      <div className="flex items-center justify-between gap-2">
        <div className="flex flex-wrap gap-1">
          {tool.tags.slice(0, 3).map((tag) => (
            <span key={tag} className="text-micro font-mono text-muted inline-flex items-center gap-0.5">
              <Tag className="h-2.5 w-2.5" />
              {tag}
            </span>
          ))}
          {tool.tags.length > 3 && <span className="text-micro font-mono text-muted">+{tool.tags.length - 3}</span>}
        </div>
        {tool.githubUrl && (
          <a
            href={tool.githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="shrink-0 text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
            title="GitHub repository"
          >
            <Github className="h-4 w-4" />
          </a>
        )}
      </div>
    </a>
  );
}
