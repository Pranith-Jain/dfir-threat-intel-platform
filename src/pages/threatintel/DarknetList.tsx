import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Activity, ExternalLink, Fingerprint, Globe, RefreshCw, Search, ShieldOff, Star, Zap } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface DarknetSite {
  slug: string;
  name: string;
  dwdId: string | null;
  category: string;
  status: 'up' | 'down' | 'unknown';
  upMirrors: number;
  totalMirrors: number;
  recommended: boolean;
  isOnion: boolean;
  url: string | null;
  onion: string | null;
  latencyMs?: number | null;
  httpCode?: string | null;
  pageSize?: string | null;
  fingerprint?: string | null;
}

interface DarknetCategory {
  id: string;
  title: string;
  description: string;
  siteCount: number;
  mirrorCount: number;
  upCount: number;
}

interface DarknetIndex {
  source: string;
  url: string;
  description: string;
  rebuiltAt: string;
  syncedAt: string;
  counts: {
    categories: number;
    sites: number;
    up: number;
    down: number;
    recommended: number;
    onion: number;
  };
  categories: DarknetCategory[];
  sites: DarknetSite[];
}

const CATEGORY_META: Record<string, { label: string; color: string; pill: string }> = {
  markets: {
    label: 'Markets',
    color: 'text-rose-600 dark:text-rose-400',
    pill: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  search: {
    label: 'Search',
    color: 'text-sky-600 dark:text-sky-400',
    pill: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  },
  forums: {
    label: 'Forums',
    color: 'text-violet-600 dark:text-violet-400',
    pill: 'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  },
  news: {
    label: 'News',
    color: 'text-amber-600 dark:text-amber-400',
    pill: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  },
  security: {
    label: 'Security',
    color: 'text-emerald-600 dark:text-emerald-400',
    pill: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
  communications: {
    label: 'Comms',
    color: 'text-cyan-600 dark:text-cyan-400',
    pill: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300',
  },
  crypto: {
    label: 'Crypto',
    color: 'text-orange-600 dark:text-orange-400',
    pill: 'border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  },
  tools: {
    label: 'Tools',
    color: 'text-indigo-600 dark:text-indigo-400',
    pill: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  },
  ai: {
    label: 'AI',
    color: 'text-fuchsia-600 dark:text-fuchsia-400',
    pill: 'border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
  },
};

function StatusBadge({ status }: { status: DarknetSite['status'] }) {
  if (status === 'up') {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> ONLINE
      </span>
    );
  }
  if (status === 'down') {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300">
        <span className="w-1.5 h-1.5 rounded-full bg-rose-500" /> DOWN
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> UNKNOWN
    </span>
  );
}

function SiteCard({ site }: { site: DarknetSite }) {
  const catMeta = CATEGORY_META[site.category] ?? {
    label: site.category,
    color: 'text-slate-500',
    pill: 'border-slate-300 dark:border-line-1 text-slate-500',
  };
  const safeUrl = sanitizeUrl(site.url);

  return (
    <div
      className={`rounded-xl border p-4 transition hover:shadow-e1 ${
        site.status === 'down'
          ? 'border-rose-200 dark:border-rose-800/40 bg-rose-50/30 dark:bg-rose-900/5'
          : 'border-line-1 bg-white dark:bg-surface-200/50'
      }`}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-base font-bold text-heading">{site.name}</h3>
            {site.recommended && (
              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-micro font-mono rounded border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300">
                <Star className="w-2.5 h-2.5" /> REC
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 text-mini text-muted mt-0.5">
            <span className={`font-mono ${catMeta.color}`}>{catMeta.label}</span>
            {site.dwdId && <span className="font-mono opacity-60">{site.dwdId}</span>}
          </div>
        </div>
        <StatusBadge status={site.status} />
      </div>

      {/* Onion URL — the primary value the user asked to surface */}
      {safeUrl ? (
        <a
          href={safeUrl}
          target="_blank"
          rel="noopener noreferrer nofollow"
          className="flex items-center gap-1 mt-1 mb-2 text-xs text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          title={site.url ?? undefined}
        >
          <ExternalLink className="w-3 h-3 shrink-0" />
          <span className="truncate font-mono">{site.onion ?? site.url}</span>
        </a>
      ) : site.onion ? (
        <div className="flex items-center gap-1 mt-1 mb-2 text-xs text-muted">
          <ShieldOff className="w-3 h-3 shrink-0" />
          <span className="truncate font-mono">{site.onion}</span>
        </div>
      ) : null}

      <div className="flex items-center gap-2 flex-wrap text-mini text-muted">
        <span className="flex items-center gap-1">
          <Activity className="w-2.5 h-2.5" />
          {site.upMirrors}/{site.totalMirrors} mirrors
        </span>
        <PostAnalysisButton
          title={`${site.name} — ${catMeta.label} onion site`}
          description={`${site.name} (${catMeta.label}): status ${site.status}, ${site.upMirrors}/${site.totalMirrors} mirrors up${site.latencyMs != null ? `, latency ${site.latencyMs}ms` : ''}${site.fingerprint ? `, fingerprint ${site.fingerprint}` : ''}. Onion URL: ${site.onion ?? site.url ?? 'n/a'}.`}
          source="darknetlist.is"
          compact
        />
        {site.latencyMs != null && (
          <span className="flex items-center gap-1">
            <Zap className="w-2.5 h-2.5" />
            {site.latencyMs}ms
          </span>
        )}
        {site.httpCode && site.httpCode !== 'n/a' && <span className="font-mono">HTTP {site.httpCode}</span>}
        {site.pageSize && <span>{site.pageSize}</span>}
        {site.fingerprint && (
          <span className="flex items-center gap-1 font-mono">
            <Fingerprint className="w-2.5 h-2.5" />
            {site.fingerprint}
          </span>
        )}
        {site.isOnion && (
          <span className="flex items-center gap-1 text-violet-600 dark:text-violet-400">
            <ShieldOff className="w-2.5 h-2.5" />
            .onion
          </span>
        )}
      </div>
    </div>
  );
}

export default function DarknetList(): JSX.Element {
  const [data, setData] = useState<DarknetIndex | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'up' | 'down'>('all');
  const [recommendedOnly, setRecommendedOnly] = useState(false);
  const [query, setQuery] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/darknet');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as DarknetIndex;
      const sitesRes = await fetch('/api/v1/threat-intel/darknet/sites?limit=500');
      if (sitesRes.ok) {
        const sitesJson = (await sitesRes.json()) as { sites: DarknetSite[] };
        json.sites = sitesJson.sites;
      }
      setData(json);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    if (!data) return [];
    const needle = query.toLowerCase().trim();
    return data.sites.filter((s) => {
      if (category !== 'all' && s.category !== category) return false;
      if (statusFilter !== 'all' && s.status !== statusFilter) return false;
      if (recommendedOnly && !s.recommended) return false;
      if (needle) {
        const hay = `${s.name} ${s.dwdId ?? ''} ${s.category} ${s.onion ?? ''} ${s.url ?? ''}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [data, category, statusFilter, recommendedOnly, query]);

  const categoryCounts = useMemo(() => {
    if (!data) return new Map<string, number>();
    const m = new Map<string, number>();
    for (const s of data.sites) m.set(s.category, (m.get(s.category) ?? 0) + 1);
    return m;
  }, [data]);

  return (
    <DataPageLayout
      backTo="/threatintel/darkweb"
      backLabel="Dark Web"
      icon={<Globe size={28} />}
      title="Darknet Directory"
      description={
        <>
          A live directory of Tor-accessible sites from{' '}
          <a
            href="https://darknetlist.is/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            darknetlist.is
          </a>
          . A scanner walks the list through a fresh SOCKS circuit every 30 minutes.
        </>
      }
      headerExtra={
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-meta font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      }
      loading={loading && !data}
      error={error}
      onRetry={load}
    >
      {data && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-5">
            {[
              { label: 'Sites', value: data.counts.sites, cls: 'text-slate-500' },
              { label: 'Online', value: data.counts.up, cls: 'text-emerald-600 dark:text-emerald-400' },
              { label: 'Down', value: data.counts.down, cls: 'text-rose-600 dark:text-rose-400' },
              { label: 'Recommended', value: data.counts.recommended, cls: 'text-amber-600 dark:text-amber-400' },
              { label: '.onion', value: data.counts.onion, cls: 'text-violet-600 dark:text-violet-400' },
              { label: 'Categories', value: data.counts.categories, cls: 'text-slate-500' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="surface-card/50 shadow-e1 p-2.5">
                <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">{label}</div>
                <div className={`text-lg font-bold ${cls}`}>{value}</div>
              </div>
            ))}
          </div>

          {/* Top-level AI threat analysis for the darknet site list */}
          {filtered.length > 0 && (
            <div className="mb-4">
              <PostAnalysisButton
                title={`Darknet Site Digest \u2014 ${filtered.length} sites${category !== 'all' ? ` (${category})` : ''}${statusFilter !== 'all' ? ` (${statusFilter})` : ''}${recommendedOnly ? ' (recommended)' : ''}`}
                description={filtered
                  .slice(0, 20)
                  .map(
                    (s) =>
                      `${s.name} (${CATEGORY_META[s.category]?.label ?? s.category}): status ${s.status}, ${s.upMirrors}/${s.totalMirrors} mirrors up${s.fingerprint ? `, fingerprint ${s.fingerprint}` : ''}. Onion: ${s.onion ?? 'n/a'}.`
                  )
                  .join('\n')}
                source="darknetlist.is"
              />
            </div>
          )}

          {/* Search + filters */}
          <div className="flex flex-col sm:flex-row gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                type="text"
                placeholder="Search site name, DWD ID, category, or .onion address…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
              />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'up' | 'down')}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
            >
              <option value="all">All status</option>
              <option value="up">Online only</option>
              <option value="down">Down only</option>
            </select>
            <button
              onClick={() => setRecommendedOnly((v) => !v)}
              className={`px-3 py-2 rounded-xl text-sm font-mono border flex items-center gap-1.5 transition ${
                recommendedOnly
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                  : 'border-line-1 text-slate-500 hover:border-amber-500/30'
              }`}
            >
              <Star className="w-3.5 h-3.5" />
              Recommended
            </button>
          </div>

          {/* Category pills */}
          <div className="flex flex-wrap items-center gap-1.5 mb-4">
            <span className="text-xs text-muted mr-1 font-mono">category:</span>
            <button
              onClick={() => setCategory('all')}
              className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                category === 'all'
                  ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                  : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/30'
              }`}
            >
              All <span className="opacity-60">{data.sites.length}</span>
            </button>
            {data.categories.map((cat) => {
              const meta = CATEGORY_META[cat.id];
              const active = category === cat.id;
              return (
                <button
                  key={cat.id}
                  onClick={() => setCategory(cat.id)}
                  className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                    active
                      ? (meta?.pill ?? 'border-rose-500/60 bg-rose-500/10 text-rose-600')
                      : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'
                  }`}
                >
                  {meta?.label ?? cat.title} <span className="opacity-60">{categoryCounts.get(cat.id) ?? 0}</span>
                </button>
              );
            })}
            {(category !== 'all' || statusFilter !== 'all' || recommendedOnly || query) && (
              <button
                onClick={() => {
                  setCategory('all');
                  setStatusFilter('all');
                  setRecommendedOnly(false);
                  setQuery('');
                }}
                className="text-xs text-rose-600 dark:text-rose-400 hover:underline ml-2"
              >
                clear
              </button>
            )}
          </div>

          {/* Results count + rebuilt time */}
          <div className="flex items-center justify-between mb-3 text-xs text-muted font-mono">
            <span>
              Showing {filtered.length} of {data.sites.length} sites
            </span>
            {data.rebuiltAt && (
              <span>
                rebuilt{' '}
                {new Date(data.rebuiltAt).toLocaleString(undefined, {
                  dateStyle: 'medium',
                  timeStyle: 'short',
                })}
              </span>
            )}
          </div>

          {/* Site grid */}
          {filtered.length === 0 ? (
            <div className="text-center py-12 text-muted font-mono text-sm">No sites match your filters</div>
          ) : (
            <>
              <AiSummaryCard
                surface="Darknetlist Directory"
                items={filtered.slice(0, 30).map((s) => ({
                  title: s.name,
                  body: `${CATEGORY_META[s.category]?.label ?? s.category} · ${s.status}${s.httpCode && s.httpCode !== 'n/a' ? ` · HTTP ${s.httpCode}` : ''}${s.recommended ? ' · recommended' : ''}`,
                  source: 'darknetlist.is',
                }))}
                requireAdmin={false}
              />
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filtered.map((site) => (
                  <SiteCard key={site.slug} site={site} />
                ))}
              </div>
            </>
          )}

          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
            Source: darknetlist.is · {data.counts.sites} sites across {data.counts.categories} categories · scanned
            every 30 min via fresh SOCKS circuit
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
