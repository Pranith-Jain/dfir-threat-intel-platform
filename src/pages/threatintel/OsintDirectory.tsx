import { useEffect, useMemo, useState } from 'react';
import { Search, ExternalLink, RefreshCw } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface OsintPortalEntry {
  slug: string;
  name: string;
  url: string;
  category: string;
  description: string;
  isFree: boolean;
  requiresRegistration: boolean;
  apiAvailable: boolean;
  tags: string[];
}

interface OsintResponse {
  count: number;
  portals: OsintPortalEntry[];
}

const CATEGORY_LABELS: Record<string, string> = {
  'threat-intel': 'Threat Intel',
  'paste-monitoring': 'Paste Monitoring',
  'dark-web': 'Dark Web',
  reputation: 'Reputation',
  hash: 'Hash',
  email: 'Email',
  breach: 'Breach',
  whois: 'WHOIS',
  dns: 'DNS',
  certificate: 'Certificate',
  forensics: 'Forensics',
};

const CATEGORY_BADGE_COLORS: Record<string, string> = {
  'threat-intel':
    'bg-rose-100 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-700',
  'paste-monitoring':
    'bg-amber-100 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700',
  'dark-web':
    'bg-purple-100 dark:bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-300 dark:border-purple-700',
  reputation: 'bg-cyan-100 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border-cyan-300 dark:border-cyan-700',
  hash: 'bg-orange-100 dark:bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-300 dark:border-orange-700',
  email: 'bg-blue-100 dark:bg-brand-500/10 text-brand-700 dark:text-brand-400 border-brand-300 dark:border-blue-700',
  breach: 'bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-400 border-red-300 dark:border-red-700',
  whois: 'bg-teal-100 dark:bg-teal-500/10 text-teal-700 dark:text-teal-400 border-teal-300 dark:border-teal-700',
  dns: 'bg-sky-100 dark:bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-300 dark:border-sky-700',
  certificate:
    'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-700',
  forensics:
    'bg-violet-100 dark:bg-violet-500/10 text-violet-700 dark:text-violet-400 border-violet-300 dark:border-violet-700',
};

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (_catchErr) {
    console.error('hostnameOf failed:', errMessage(_catchErr));
    return url;
  }
}

export default function OsintDirectory(): JSX.Element {
  const [data, setData] = useState<OsintResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [freeFilter, setFreeFilter] = useState<'all' | 'free' | 'paid'>('all');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();

    setLoading(true);
    setError(null);
    fetch('/api/v1/osint', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: OsintResponse) => {
        if (cancelled) return;
        setData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message ?? 'fetch failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const categories = useMemo(() => {
    if (!data?.portals) return [];
    const s = new Set(data.portals.map((p) => p.category));
    return Array.from(s).sort();
  }, [data]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.portals.filter((p) => {
      if (categoryFilter && p.category !== categoryFilter) return false;
      if (freeFilter === 'free' && !p.isFree) return false;
      if (freeFilter === 'paid' && p.isFree) return false;
      if (!q) return true;
      const hay = `${p.name} ${p.description} ${p.category} ${p.tags.join(' ')} ${hostnameOf(p.url)}`.toLowerCase();
      return hay.includes(q);
    });
  }, [data, query, categoryFilter, freeFilter]);

  const freeCount = data?.portals.filter((p) => p.isFree).length ?? 0;
  const paidCount = data ? data.count - freeCount : 0;

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<Search className="h-6 w-6" />}
      title="OSINT Portal Directory"
      description="Curated directory of OSINT portals and resources for threat intelligence, reputation checks, dark web monitoring, and forensic analysis. Sourced from the novasky.io CTI dashboard."
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
            <span className="rounded border border-line-2 px-2 py-1 text-muted font-mono">{data.count} portals</span>
          )}
        </div>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      empty={!loading && !data}
      emptyMessage="No portal data available."
      maxWidthClass="max-w-6xl"
    >
      {data && (
        <>
          <section className="surface-card p-4 mb-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={`Search ${data.count} portals\u2026`}
                  className="w-full rounded-xl border border-line-2 bg-surface-100 py-2 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
                />
              </div>
              <div className="flex gap-2">
                {(['all', 'free', 'paid'] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setFreeFilter(v)}
                    className={`text-mini font-mono rounded border px-2.5 py-1 transition-colors ${
                      freeFilter === v
                        ? 'border-rose-500/50 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400'
                        : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                    }`}
                  >
                    {v === 'all' ? 'all' : v}
                  </button>
                ))}
              </div>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => setCategoryFilter(null)}
                className={`text-micro font-mono rounded-full border px-2.5 py-0.5 transition-colors ${
                  categoryFilter === null
                    ? 'border-rose-500/50 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400'
                    : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                }`}
              >
                all
              </button>
              {categories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setCategoryFilter(cat === categoryFilter ? null : cat)}
                  className={`text-micro font-mono rounded-full border px-2.5 py-0.5 transition-colors ${
                    categoryFilter === cat
                      ? 'border-rose-500/50 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400'
                      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400'
                  }`}
                >
                  {CATEGORY_LABELS[cat] ?? cat}
                </button>
              ))}
            </div>
          </section>

          <div className="mb-4 grid grid-cols-3 gap-2 sm:grid-cols-3">
            <Stat label="Total" value={data.count} />
            <Stat label="Free" value={freeCount} />
            <Stat label="Paid" value={paidCount} />
          </div>

          {filtered.length === 0 ? (
            <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
              <Search className="mx-auto mb-2 h-8 w-8 text-muted" />
              No portals match{query ? ` "${query}"` : ''}
              {categoryFilter ? ` in ${CATEGORY_LABELS[categoryFilter] ?? categoryFilter}` : ''}
              {freeFilter !== 'all' ? ` (${freeFilter})` : ''}.
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {filtered.map((portal) => (
                <PortalCard key={portal.slug} portal={portal} />
              ))}
            </div>
          )}
        </>
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

function PortalCard({ portal }: { portal: OsintPortalEntry }) {
  const badgeColor =
    CATEGORY_BADGE_COLORS[portal.category] ??
    'bg-slate-100 dark:bg-slate-500/10 text-slate-700 dark:text-muted border-line-1';

  return (
    <div className="surface-card p-4 flex flex-col hover:border-line-2 dark:hover:border-line-1 transition-colors">
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-heading truncate">{portal.name}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${badgeColor}`}>
              {CATEGORY_LABELS[portal.category] ?? portal.category}
            </span>
          </div>
        </div>
        <a
          href={portal.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-muted hover:text-rose-600 dark:hover:text-rose-400 shrink-0 mt-0.5 transition-colors"
          title={`Open ${portal.name}`}
        >
          <ExternalLink className="h-4 w-4" />
        </a>
      </div>
      <p className="text-sm text-muted leading-relaxed mb-3 line-clamp-2">{portal.description}</p>
      <div className="flex flex-wrap items-center gap-1.5 mt-auto">
        <span
          className={`text-micro font-mono rounded-full border px-2 py-0.5 ${
            portal.isFree
              ? 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-700'
              : 'bg-amber-100 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700'
          }`}
        >
          {portal.isFree ? 'free' : 'paid'}
        </span>
        {portal.requiresRegistration && (
          <span className="text-micro font-mono rounded-full border border-line-2 bg-surface-200 px-2 py-0.5 text-muted">
            register
          </span>
        )}
        {portal.apiAvailable && (
          <span className="text-micro font-mono rounded-full border border-sky-300 dark:border-sky-700 bg-sky-50 dark:bg-sky-500/10 px-2 py-0.5 text-sky-700 dark:text-sky-400">
            API
          </span>
        )}
      </div>
      {portal.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {portal.tags.slice(0, 4).map((tag) => (
            <span
              key={tag}
              className="text-micro font-mono rounded-full border border-line-1 bg-surface-200 px-1.5 py-0.5 text-muted"
            >
              {tag}
            </span>
          ))}
          {portal.tags.length > 4 && <span className="text-micro font-mono text-muted">+{portal.tags.length - 4}</span>}
        </div>
      )}
    </div>
  );
}
