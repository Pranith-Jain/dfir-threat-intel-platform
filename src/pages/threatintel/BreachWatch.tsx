import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ExternalLink, Loader2, RefreshCw, ShieldAlert, Search, Filter } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { LiveFreshnessPill } from '../../components/LiveFreshnessPill';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { errMessage } from '../../lib/log';

type BwCategory = 'ransomware' | 'data_breach' | 'combo_list' | 'source_code' | 'credential_leak' | 'other';
type BwSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

interface BwBreachIndexEntry {
  slug: string;
  title: string;
  group: string;
  discovered: string;
  category: BwCategory;
  severity: BwSeverity;
  country: string | null;
  sizeBytes: number;
}

interface BwBreachBody extends BwBreachIndexEntry {
  description: string | null;
  source_url: string;
  groupAliases: string[];
  activity: string | null;
  references: string[];
}

interface BwGroupEntry {
  name: string;
  count: number;
  topCategory: BwCategory;
}

interface BwIndex {
  source: string;
  license: string;
  replicatedAt: string;
  lastSyncedAt: string | null;
  counts: { breaches: number; groups: number; categories: number };
  categories: Array<{ key: BwCategory; label: string; count: number }>;
}

const CATEGORY_LABELS: Record<string, string> = {
  ransomware: 'Ransomware',
  data_breach: 'Data Breach',
  combo_list: 'Combo List',
  source_code: 'Source Code',
  credential_leak: 'Credential Leak',
  other: 'Other',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-300 border-rose-300 dark:border-rose-700',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300 border-orange-300 dark:border-orange-700',
  medium: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300 border-amber-300 dark:border-amber-700',
  low: 'bg-sky-100 text-cyan-800 dark:bg-sky-900/40 dark:text-sky-300 border-sky-300 dark:border-sky-700',
  unknown: 'bg-slate-100 text-slate-600 dark:bg-surface-200 dark:text-muted border-slate-300 dark:border-slate-600',
};

function humanSize(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatDate(iso: string | null): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function shortRel(iso: string | null): string {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function freshnessTone(iso: string | null): 'live' | 'fresh' | 'recent' | 'stale' | 'cold' | 'unknown' {
  if (!iso) return 'unknown';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 3600000) return 'live';
  if (diff < 86400000) return 'fresh';
  if (diff < 604800000) return 'recent';
  if (diff < 2592000000) return 'stale';
  return 'cold';
}

const LIMIT = 200;
const DAYS_OPTIONS = [7, 14, 30, 90, 180, 365];

function BreachCard({
  entry,
  onSelect,
  selected,
}: {
  entry: BwBreachIndexEntry;
  onSelect: () => void;
  selected: boolean;
}): JSX.Element {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`w-full text-left rounded-xl border bg-surface-100 dark:bg-surface-200 shadow-e1 p-4 hover:border-rose-500/40 transition-colors [content-visibility:auto] [contain-intrinsic-size:auto_120px] ${
        selected ? 'border-rose-500/60 ring-1 ring-rose-500/30' : 'border-line-1'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h4 className="font-display font-semibold text-sm text-heading truncate">{entry.title}</h4>
          <div className="flex items-center gap-2 mt-1 text-mini font-mono text-muted flex-wrap">
            <span className="text-rose-600 dark:text-rose-400">{entry.group}</span>
            {entry.country && <span>{entry.country}</span>}
            <span>{entry.discovered ? new Date(entry.discovered).toLocaleDateString() : ''}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span
            className={`text-micro font-mono px-1.5 py-0.5 rounded border ${SEVERITY_COLORS[entry.severity] ?? ''}`}
          >
            {entry.severity}
          </span>
          <span className="text-micro font-mono text-muted">{humanSize(entry.sizeBytes)}</span>
        </div>
      </div>
      <div className="flex items-center justify-between mt-2">
        <span className="text-micro font-mono text-muted">{CATEGORY_LABELS[entry.category] ?? entry.category}</span>
        <PostAnalysisButton
          title={`${entry.title} — ${entry.group} breach`}
          description={`Ransomware group ${entry.group}${entry.country ? ` targeting ${entry.country}` : ''} claims ${entry.category === 'ransomware' ? 'ransomware' : 'data breach'} affecting ${entry.title}. Severity: ${entry.severity}. Discovered: ${entry.discovered ? new Date(entry.discovered).toLocaleDateString() : 'unknown'}. Data size: ${humanSize(entry.sizeBytes)}. Category: ${CATEGORY_LABELS[entry.category] ?? entry.category}.`}
          source={entry.group}
          compact
        />
      </div>
    </button>
  );
}

function BreachDetail({ slug, onClose }: { slug: string; onClose: () => void }): JSX.Element {
  const [body, setBody] = useState<BwBreachBody | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(`/api/v1/breach-watch/breaches/${encodeURIComponent(slug)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<BwBreachBody>;
      })
      .then((data) => {
        if (!cancelled) setBody(data);
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [slug]);

  return (
    <section className="surface-card p-5 animate-fade-in-up">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-display font-bold text-lg">Breach detail</h3>
        <button
          type="button"
          onClick={onClose}
          className="text-mini font-mono text-muted hover:text-body dark:hover:text-inverted transition-colors"
        >
          close
        </button>
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-muted text-sm font-mono">
          <Loader2 size={14} className="animate-spin" /> loading…
        </div>
      )}
      {error && <p className="font-mono text-sm text-rose-600">error: {error}</p>}

      {body && (
        <div className="space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-mini font-mono">
            <div>
              <span className="text-muted">Group:</span> {body.group}
            </div>
            <div>
              <span className="text-muted">Category:</span> {CATEGORY_LABELS[body.category] ?? body.category}
            </div>
            <div>
              <span className="text-muted">Severity:</span> {body.severity}
            </div>
            <div>
              <span className="text-muted">Discovered:</span> {formatDate(body.discovered)}
            </div>
            {body.country && (
              <div>
                <span className="text-muted">Country:</span> {body.country}
              </div>
            )}
            <div>
              <span className="text-muted">Size:</span> {humanSize(body.sizeBytes)}
            </div>
          </div>

          {body.description && <p className="text-body leading-relaxed">{body.description}</p>}

          {body.activity && (
            <div>
              <span className="text-muted font-mono text-mini">Activity:</span>
              <p className="text-body mt-0.5">{body.activity}</p>
            </div>
          )}

          {body.groupAliases.length > 0 && (
            <div>
              <span className="text-muted font-mono text-mini">Aliases:</span>
              <div className="flex flex-wrap gap-1 mt-0.5">
                {body.groupAliases.map((a, i) => (
                  <span key={i} className="text-micro px-2 py-0.5 bg-surface-300 rounded">
                    {a}
                  </span>
                ))}
              </div>
            </div>
          )}

          {body.source_url && (
            <a
              href={sanitizeUrl(body.source_url) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm font-mono text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              source <ExternalLink size={11} />
            </a>
          )}

          {body.references.length > 0 && (
            <div>
              <span className="text-muted font-mono text-mini">References:</span>
              <ul className="mt-0.5 space-y-0.5">
                {body.references.map((r, i) => (
                  <li key={i}>
                    <a
                      href={sanitizeUrl(r) || undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-rose-600 dark:text-rose-400 hover:underline break-all transition-colors"
                    >
                      {r} <ExternalLink size={9} className="inline" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <PostAnalysisButton
            title={body.title}
            description={body.description ?? undefined}
            source={body.group}
            link={body.source_url}
          />
        </div>
      )}
    </section>
  );
}

export default function BreachWatch(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [index, setIndex] = useState<BwIndex | null>(null);
  const [groups, setGroups] = useState<BwGroupEntry[]>([]);
  const [breaches, setBreaches] = useState<BwBreachIndexEntry[]>([]);
  const [totalBreaches, setTotalBreaches] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const mounted = useRef(false);

  const filterGroup = searchParams.get('group') ?? '';
  const filterCategory = searchParams.get('category') ?? '';
  const filterSeverity = searchParams.get('severity') ?? '';
  const filterCountry = searchParams.get('country') ?? '';
  const filterDays = searchParams.get('days') ?? '';
  const searchQuery = searchParams.get('q') ?? '';

  const setFilter = useCallback(
    (key: string, value: string) => {
      setSearchParams(
        (prev) => {
          const out = new URLSearchParams(prev);
          if (value) out.set(key, value);
          else out.delete(key);
          return out;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );

  const loadData = useCallback(
    async (isInitial = false) => {
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams();
        params.set('limit', String(LIMIT));
        if (searchQuery) params.set('q', searchQuery);
        if (filterGroup) params.set('group', filterGroup);
        if (filterCategory) params.set('category', filterCategory);
        if (filterSeverity) params.set('severity', filterSeverity);
        if (filterCountry) params.set('country', filterCountry);
        if (filterDays) params.set('days_back', filterDays);

        const [idxRes, groupsRes, breachesRes] = await Promise.all([
          fetch('/api/v1/breach-watch/'),
          fetch('/api/v1/breach-watch/groups?limit=200'),
          fetch(`/api/v1/breach-watch/breaches?${params}`),
        ]);
        if (!idxRes.ok) throw new Error(`index HTTP ${idxRes.status}`);
        if (!groupsRes.ok) throw new Error(`groups HTTP ${groupsRes.status}`);
        if (!breachesRes.ok) throw new Error(`breaches HTTP ${breachesRes.status}`);

        const idxData = (await idxRes.json()) as BwIndex;
        const groupsData = (await groupsRes.json()) as { groups: BwGroupEntry[] };
        const breachesData = (await breachesRes.json()) as { total: number; breaches: BwBreachIndexEntry[] };

        setIndex(idxData);
        setGroups(groupsData.groups);
        setBreaches(breachesData.breaches);
        setTotalBreaches(breachesData.total);
        setPage(0);
        if (!isInitial) setSelectedSlug(null);
      } catch (e: unknown) {
        setError(errMessage(e));
      } finally {
        setLoading(false);
      }
    },
    [searchQuery, filterGroup, filterCategory, filterSeverity, filterCountry, filterDays]
  );

  useEffect(() => {
    mounted.current = true;
    loadData(!mounted.current);
    return () => {
      mounted.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchQuery, filterGroup, filterCategory, filterSeverity, filterCountry, filterDays]);

  const uniqueCountries = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const b of breaches) {
      if (b.country && !seen.has(b.country)) {
        seen.add(b.country);
        out.push(b.country);
      }
    }
    return out.sort();
  }, [breaches]);

  const canLoadMore = breaches.length >= LIMIT && breaches.length < totalBreaches;
  const loadMore = useCallback(async () => {
    const next = page + 1;
    setLoadingMore(true);
    const params = new URLSearchParams();
    params.set('limit', String(LIMIT));
    params.set('offset', String(next * LIMIT));
    if (searchQuery) params.set('q', searchQuery);
    if (filterGroup) params.set('group', filterGroup);
    if (filterCategory) params.set('category', filterCategory);
    if (filterSeverity) params.set('severity', filterSeverity);
    if (filterCountry) params.set('country', filterCountry);
    if (filterDays) params.set('days_back', filterDays);

    try {
      const r = await fetch(`/api/v1/breach-watch/breaches?${params}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = (await r.json()) as { breaches: BwBreachIndexEntry[] };
      setBreaches((prev) => [...prev, ...data.breaches]);
      setPage(next);
    } catch (e: unknown) {
      console.error('loadMore failed:', errMessage(e));
    } finally {
      setLoadingMore(false);
    }
  }, [page, searchQuery, filterGroup, filterCategory, filterSeverity, filterCountry, filterDays]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      maxWidthClass="max-w-6xl"
      icon={<ShieldAlert size={28} />}
      title="Breach Watch"
      description={
        <>
          <span className="block">
            Aggregated breach and leak data from{' '}
            <a
              href="https://ransomware.live"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              ransomware.live
            </a>
            ,{' '}
            <a
              href="https://ransomlook.io"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              ransomlook.io
            </a>
            ,{' '}
            <a
              href="https://darkfield.orizon.one"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              Darkfield
            </a>
            ,{' '}
            <a
              href="https://recentbreaches.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              RecentBreaches
            </a>
            ,{' '}
            <a
              href="https://cti.fyi"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              CTI.FYI
            </a>
            , and{' '}
            <a
              href="https://xposedornot.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              XposedOrNot
            </a>
            .
          </span>
          <span className="block text-xs text-muted font-mono mt-2">
            Combined breach corpus - ransomware leaks, data breaches, credential dumps, and combo lists.
          </span>
        </>
      }
      headerExtra={
        <div className="flex items-center gap-3">
          {index && (
            <>
              <LiveFreshnessPill tone={freshnessTone(index.lastSyncedAt)} ago={shortRel(index.lastSyncedAt)} />
              <span className="text-mini font-mono text-muted">
                {index.counts.breaches.toLocaleString()} breaches · {index.counts.groups} groups
              </span>
            </>
          )}
          <button
            type="button"
            onClick={() => loadData(false)}
            disabled={loading}
            className="text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 disabled:opacity-40"
            aria-label="Refresh breach watch data"
          >
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
          </button>
        </div>
      }
    >
      {loading && !index && (
        <div className="surface-card p-4 inline-flex items-center gap-2 font-mono text-sm text-muted">
          <Loader2 size={14} className="animate-spin" /> loading breach watch data…
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/5 p-3 font-mono text-sm text-rose-600 dark:text-rose-300">
          Error: {error}
          <button type="button" onClick={() => loadData(false)} className="ml-3 underline hover:no-underline">
            retry
          </button>
        </div>
      )}

      {(!loading || index) && !error && (
        <>
          {/* Categories overview */}
          {index && index.categories.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-6">
              {index.categories.map((c) => (
                <button
                  key={c.key}
                  type="button"
                  onClick={() => setFilter('category', filterCategory === c.key ? '' : c.key)}
                  className={`text-micro font-mono px-2.5 py-1 rounded-full border transition-colors ${
                    filterCategory === c.key
                      ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/40'
                      : 'bg-white dark:bg-surface-200 text-slate-500 border-line-1 hover:border-rose-500/40'
                  }`}
                >
                  {c.label} ({c.count})
                </button>
              ))}
            </div>
          )}

          {/* Search + filters */}
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setFilter('q', e.target.value)}
                placeholder="Search breaches…"
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
              />
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <Filter size={13} className="text-muted" />
              <select
                value={filterGroup}
                onChange={(e) => setFilter('group', e.target.value)}
                className="text-mini font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 text-body"
              >
                <option value="">All groups</option>
                {groups.slice(0, 50).map((g) => (
                  <option key={g.name} value={g.name}>
                    {g.name} ({g.count})
                  </option>
                ))}
              </select>

              <select
                value={filterSeverity}
                onChange={(e) => setFilter('severity', e.target.value)}
                className="text-mini font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 text-body"
              >
                <option value="">All severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <select
                value={filterCountry}
                onChange={(e) => setFilter('country', e.target.value)}
                className="text-mini font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 text-body"
              >
                <option value="">All countries</option>
                {uniqueCountries.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>

              <select
                value={filterDays}
                onChange={(e) => setFilter('days', e.target.value)}
                className="text-mini font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 text-body"
              >
                <option value="">All time</option>
                {DAYS_OPTIONS.map((d) => (
                  <option key={d} value={String(d)}>
                    Last {d} days
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between mb-3">
            <p className="text-mini font-mono text-muted">
              {breaches.length} of {totalBreaches.toLocaleString()} breaches
              {loading && <Loader2 size={11} className="inline animate-spin ml-1" />}
            </p>
          </div>

          {/* Page-level AI summary across the visible breach entries.
              Public (requireAdmin={false}) so every visitor sees it. */}
          {breaches.length > 0 && (
            <AiSummaryCard
              surface="Breach Watch"
              items={breaches.slice(0, 30).map((b) => ({
                title: b.title,
                body: `${b.group} · ${b.category} · ${b.severity} · ${b.country ?? 'unknown'}`,
                source: b.group,
              }))}
              requireAdmin={false}
            />
          )}

          {/* Breach list */}
          {loading && index && (
            <div className="flex items-center gap-2 text-muted text-sm font-mono mb-3">
              <Loader2 size={14} className="animate-spin" /> re-filtering…
            </div>
          )}

          <div className="grid gap-2">
            {breaches.length === 0 && !loading && (
              <p className="text-sm font-mono text-muted italic py-4 text-center">
                No breaches match the current filters.
              </p>
            )}
            {breaches.map((b) => (
              <BreachCard
                key={b.slug}
                entry={b}
                selected={selectedSlug === b.slug}
                onSelect={() => setSelectedSlug(selectedSlug === b.slug ? null : b.slug)}
              />
            ))}
          </div>

          {canLoadMore && (
            <div className="mt-4 text-center">
              <button
                type="button"
                onClick={loadMore}
                disabled={loadingMore}
                className="text-mini font-mono px-4 py-2 rounded-xl border border-line-2 hover:border-rose-500/40 bg-surface-100 disabled:opacity-40 inline-flex items-center gap-2 transition-colors"
              >
                {loadingMore && <Loader2 size={12} className="animate-spin" />}
                Load more
              </button>
            </div>
          )}

          {/* Detail panel */}
          {selectedSlug && (
            <div className="mt-4">
              <BreachDetail slug={selectedSlug} onClose={() => setSelectedSlug(null)} />
            </div>
          )}

          {/* Groups section */}
          {groups.length > 0 && !filterGroup && (
            <section className="mt-10">
              <h2 className="font-display font-bold text-xl mb-3 inline-flex items-center gap-2">
                <ShieldAlert size={18} className="text-rose-600 dark:text-rose-400" /> Threat actor groups
              </h2>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {groups.slice(0, 60).map((g) => (
                  <button
                    key={g.name}
                    type="button"
                    onClick={() => setFilter('group', g.name)}
                    className="surface-card p-3 hover:border-rose-500/40 transition-colors text-left"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-display font-semibold text-sm text-heading truncate">{g.name}</span>
                      <span className="text-micro font-mono text-muted shrink-0 ml-2">{g.count}</span>
                    </div>
                    <span className="text-micro font-mono text-muted">
                      {CATEGORY_LABELS[g.topCategory] ?? g.topCategory}
                    </span>
                  </button>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </DataPageLayout>
  );
}
