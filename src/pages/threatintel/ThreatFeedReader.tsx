/**
 * ThreatFeed reader — an in-site port of the jozeta/ThreatFeed newsreader.
 *
 * Upstream is MIT. REA verified it is a pure client-side reader whose dataset
 * is data/snapshot.json + entities.json; we mirror that public metadata and
 * re-implement the information architecture (newspaper/list/compact layouts,
 * category + severity + source filters, local read/bookmark/watchlist state).
 * No upstream code, CSS, CORS proxies or article bodies are vendored.
 */
import { useCallback, useEffect, useMemo, useState, type JSX } from 'react';
import {
  Activity,
  ArrowUpRight,
  Bookmark,
  Check,
  Clock3,
  Database,
  ExternalLink,
  Filter,
  LayoutGrid,
  List,
  Newspaper,
  Rss,
  Search,
  Sparkles,
  Star,
  Users,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { relativeAgo } from '../../lib/relativeTime';

interface Article {
  id: string;
  title: string;
  url: string | null;
  sourceId: string;
  sourceName: string;
  description: string;
  author: string;
  feedCategory: string;
  publishedAt: string | null;
  fetchedAt: string | null;
  tags: string[];
  categories: string[];
  cves: string[];
  severity: string;
  severityScore: number | null;
}

interface FeedSource {
  id: string;
  name: string;
  url: string | null;
  category: string;
  tags: string[];
  enabled: boolean;
  status: string;
  httpStatus: number | null;
  latencyMs: number | null;
  articleCount: number | null;
  lastFetchedAt: string | null;
  lastSuccessAt: string | null;
  gatewayUsed: string;
}

interface ReaderData {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  repoUrl: string;
  license: string;
  note: string;
  counts: {
    articles: number;
    sources: number;
    categories: number;
    critical: number;
    withCves: number;
    sourcesHealthy: number;
    sourcesUnhealthy: number;
  };
  generatedFrom: string | null;
  trending: {
    vendors: string[];
    actors: Array<{ id: string; name: string }>;
    groups: Array<{ id: string; name: string }>;
  };
  sources: FeedSource[];
  articles: Article[];
}

type Layout = 'newspaper' | 'list' | 'compact';
type View = 'stream' | 'sources' | 'entities';

const SOURCE_STATUS: Record<string, string> = {
  healthy: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  http_error: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  network_error: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  invalid_xml: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
};

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

function useStoredSet(key: string): [Set<string>, (id: string) => void] {
  const [set, setSet] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem(key);
      const parsed = raw ? JSON.parse(raw) : [];
      return new Set(Array.isArray(parsed) ? parsed.filter((v) => typeof v === 'string') : []);
    } catch {
      return new Set();
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify([...set]));
    } catch {
      /* storage unavailable */
    }
  }, [key, set]);
  const toggle = useCallback((id: string) => {
    setSet((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  return [set, toggle];
}

function ArticleCard({
  article,
  layout,
  read,
  bookmarked,
  onRead,
  onBookmark,
}: {
  article: Article;
  layout: Layout;
  read: boolean;
  bookmarked: boolean;
  onRead: () => void;
  onBookmark: () => void;
}): JSX.Element {
  const severityClass = SEVERITY_STYLE[article.severity] ?? SEVERITY_STYLE.low;
  const open = () => {
    onRead();
    if (article.url) window.open(sanitizeUrl(article.url) ?? '_blank', '_blank', 'noopener,noreferrer');
  };
  if (layout === 'compact') {
    return (
      <li
        className={`flex items-center gap-2 rounded-lg border border-line-1 px-2.5 py-1.5 text-mini ${read ? 'opacity-55' : ''}`}
      >
        <button
          type="button"
          onClick={onRead}
          aria-label={read ? 'Mark unread' : 'Mark read'}
          className="shrink-0 text-muted hover:text-heading"
        >
          {read ? (
            <Check size={12} className="text-emerald-500" />
          ) : (
            <span className="block h-2.5 w-2.5 rounded-full border border-line-2" />
          )}
        </button>
        <span className="shrink-0 font-mono text-micro text-muted">{relativeAgo(article.publishedAt ?? '')}</span>
        <button type="button" onClick={open} className="min-w-0 flex-1 truncate text-left text-body hover:text-heading">
          {article.title}
        </button>
        <span className="shrink-0 font-mono text-micro text-muted">{article.sourceName.slice(0, 18)}</span>
        <button
          type="button"
          onClick={onBookmark}
          aria-label="Bookmark"
          className={`shrink-0 ${bookmarked ? 'text-amber-500' : 'text-muted hover:text-heading'}`}
        >
          <Bookmark size={12} fill={bookmarked ? 'currentColor' : 'none'} />
        </button>
      </li>
    );
  }
  return (
    <li className={`surface-card ${layout === 'newspaper' ? 'p-4' : 'p-3'} ${read ? 'opacity-65' : ''}`}>
      <div className="flex flex-wrap items-center gap-2 text-micro text-muted">
        <button
          type="button"
          onClick={onRead}
          aria-label={read ? 'Mark unread' : 'Mark read'}
          className="hover:text-heading"
        >
          {read ? (
            <Check size={12} className="text-emerald-500" />
          ) : (
            <span className="block h-2.5 w-2.5 rounded-full border border-line-2" />
          )}
        </button>
        <span className="font-semibold text-sky-700 dark:text-sky-300">{article.sourceName}</span>
        <span className="flex items-center gap-1">
          <Clock3 size={9} /> {relativeAgo(article.publishedAt ?? '')}
        </span>
        <span className={`rounded border px-1.5 py-0.5 font-mono uppercase ${severityClass}`}>{article.severity}</span>
        {article.cves.slice(0, 2).map((c) => (
          <span key={c} className="rounded border border-line-1 px-1.5 py-0.5 font-mono">
            {c}
          </span>
        ))}
        <button
          type="button"
          onClick={onBookmark}
          aria-label="Bookmark"
          className={`ml-auto ${bookmarked ? 'text-amber-500' : 'text-muted hover:text-heading'}`}
        >
          <Bookmark size={12} fill={bookmarked ? 'currentColor' : 'none'} />
        </button>
      </div>
      <button type="button" onClick={open} className="mt-2 block w-full text-left">
        <h3
          className={`${layout === 'newspaper' ? 'text-base' : 'text-sm'} font-semibold leading-snug text-heading hover:underline`}
        >
          {article.title}
        </h3>
        {article.description && (
          <p
            className={`mt-1 text-mini leading-relaxed text-muted ${layout === 'newspaper' ? 'line-clamp-3' : 'line-clamp-2'}`}
          >
            {article.description}
          </p>
        )}
      </button>
      <div className="mt-2 flex flex-wrap items-center gap-1">
        {article.tags.slice(0, 4).map((t) => (
          <span key={t} className="rounded-full border border-line-1 px-1.5 py-0.5 text-micro text-muted">
            {t}
          </span>
        ))}
        <PostAnalysisButton
          title={article.title}
          description={article.description}
          source={article.sourceName}
          link={article.url ?? undefined}
          compact
        />
        <a
          href={sanitizeUrl(article.url ?? '') ?? undefined}
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto inline-flex items-center gap-1 text-micro text-sky-600 hover:underline dark:text-sky-400"
        >
          read at source <ArrowUpRight size={10} />
        </a>
      </div>
    </li>
  );
}

export default function ThreatFeedReader(): JSX.Element {
  const { data, loading, error } = useDataFetch<ReaderData>({
    url: '/data/threatfeed-reader/index.json',
    ttl: 10 * 60_000,
  });
  const [view, setView] = useState<View>('stream');
  const [sourceCategory, setSourceCategory] = useState('all');
  const [sourceStatus, setSourceStatus] = useState('all');
  const [sourceQ, setSourceQ] = useState('');
  const [layout, setLayout] = useState<Layout>('newspaper');
  const [category, setCategory] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [source, setSource] = useState('all');
  const [q, setQ] = useState('');
  const [onlyUnread, setOnlyUnread] = useState(false);
  const [onlySaved, setOnlySaved] = useState(false);
  const [watchlist, toggleWatch] = useStoredSet('tf:watchlist');
  const [read, markRead] = useStoredSet('tf:read');
  const [saved, toggleSaved] = useStoredSet('tf:saved');

  const categories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of data?.articles ?? []) counts.set(a.feedCategory, (counts.get(a.feedCategory) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [data?.articles]);
  const sources = useMemo(
    () => [...new Set((data?.articles ?? []).map((a) => a.sourceName))].sort().slice(0, 60),
    [data?.articles]
  );

  const articles = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.articles ?? []).filter((a) => {
      if (category !== 'all' && a.feedCategory !== category) return false;
      if (severity !== 'all' && a.severity !== severity) return false;
      if (source !== 'all' && a.sourceName !== source) return false;
      if (onlyUnread && read.has(a.id)) return false;
      if (onlySaved && !saved.has(a.id)) return false;
      if (
        watchlist.size &&
        ![...watchlist].some((w) =>
          `${a.title} ${a.description} ${a.tags.join(' ')}`.toLowerCase().includes(w.toLowerCase())
        )
      )
        return false;
      if (
        needle &&
        !`${a.title} ${a.description} ${a.tags.join(' ')} ${a.cves.join(' ')}`.toLowerCase().includes(needle)
      )
        return false;
      return true;
    });
  }, [data?.articles, category, severity, source, q, onlyUnread, onlySaved, read, saved, watchlist]);

  const sourceCategories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of data?.sources ?? []) counts.set(s.category, (counts.get(s.category) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [data?.sources]);

  const visibleSources = useMemo(() => {
    const needle = sourceQ.trim().toLowerCase();
    return (data?.sources ?? []).filter((s) => {
      if (sourceCategory !== 'all' && s.category !== sourceCategory) return false;
      if (sourceStatus === 'healthy' && s.status !== 'healthy') return false;
      if (sourceStatus === 'unhealthy' && s.status === 'healthy') return false;
      if (needle && !`${s.name} ${s.id} ${s.tags.join(' ')}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data?.sources, sourceCategory, sourceStatus, sourceQ]);

  // AI is opt-in: the card only posts to /api/v1/ai-summary when the visitor
  // clicks Generate. A stable dayKey derived from the mirror's generatedAt
  // keeps the server cache warm for every visitor on the same snapshot.
  const summaryItems = useMemo(
    () =>
      articles.slice(0, 60).map((a) => ({
        title: a.title,
        body: a.description,
        source: a.sourceName,
      })),
    [articles]
  );

  const openSource = (name: string) => {
    setSource(name);
    setView('stream');
  };

  const addWatch = () => {
    const value = window.prompt('Add a watch phrase (product, actor, vendor)');
    if (value?.trim()) toggleWatch(value.trim());
  };

  return (
    <DataPageLayout
      backTo="/threatintel/threat-feed-catalog"
      backLabel="Feed catalog"
      icon={<Newspaper size={28} />}
      title="ThreatFeed Reader"
      description="A working in-site port of the MIT-licensed ThreatFeed newsreader — dispatches, live source health, trending entities, opt-in AI analysis and local read/bookmark state."
      maxWidthClass="max-w-7xl"
    >
      <PageMeta
        title="ThreatFeed Reader — security intelligence daily"
        description="Read, filter and bookmark the public ThreatFeed dispatch snapshot inside the platform, with source attribution and direct links."
        section="Threat Intel"
        canonicalPath="/threatintel/threatfeed-reader"
      />

      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-mini text-muted">
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.articles.toLocaleString()}</span> dispatches
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.sources}</span> sources
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.critical}</span> critical
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.withCves}</span> with CVEs
          </span>
          <span>
            {read.size} read · {saved.size} saved
          </span>
          <a
            href={sanitizeUrl(data.sourceUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            upstream reader <ExternalLink size={10} />
          </a>
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Reader views">
        {(
          [
            ['stream', Newspaper, 'Dispatches'],
            ['sources', Database, 'Sources'],
            ['entities', Users, 'Entities'],
          ] as const
        ).map(([id, Icon, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={view === id}
            onClick={() => setView(id)}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-mini ${
              view === id
                ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                : 'border-line-1 text-muted'
            }`}
          >
            <Icon size={12} /> {label}
          </button>
        ))}
        <a
          href="https://jozeta.github.io/ThreatFeed/#/sources"
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto inline-flex items-center gap-1 text-mini text-sky-600 hover:underline dark:text-sky-400"
        >
          upstream sources <ExternalLink size={10} />
        </a>
      </div>

      {view === 'sources' && (
        <section className="mb-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[220px] flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
              <input
                value={sourceQ}
                onChange={(e) => setSourceQ(e.target.value)}
                placeholder="Search sources, IDs, tags…"
                className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
              />
            </div>
            <select
              value={sourceCategory}
              onChange={(e) => setSourceCategory(e.target.value)}
              className="rounded-lg border border-line-1 bg-surface-100 px-2 py-1.5 text-mini text-fg"
              aria-label="Source category"
            >
              <option value="all">all categories</option>
              {sourceCategories.map(([name, count]) => (
                <option key={name} value={name}>
                  {name} ({count})
                </option>
              ))}
            </select>
            <select
              value={sourceStatus}
              onChange={(e) => setSourceStatus(e.target.value)}
              className="rounded-lg border border-line-1 bg-surface-100 px-2 py-1.5 text-mini text-fg"
              aria-label="Source status"
            >
              <option value="all">all statuses</option>
              <option value="healthy">healthy ({data?.counts.sourcesHealthy ?? 0})</option>
              <option value="unhealthy">unhealthy ({data?.counts.sourcesUnhealthy ?? 0})</option>
            </select>
            <span className="text-mini text-muted">
              {visibleSources.length} of {data?.sources.length ?? 0} sources
            </span>
          </div>
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {visibleSources.map((s) => (
              <div key={s.id} className="surface-card p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-heading">{s.name}</div>
                    <div className="truncate font-mono text-micro text-muted">
                      {s.category} · {s.id}
                    </div>
                  </div>
                  <span
                    className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-micro ${SOURCE_STATUS[s.status] ?? SOURCE_STATUS.http_error}`}
                  >
                    {s.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-micro text-muted">
                  <span>{s.articleCount ?? '—'} articles</span>
                  <span>{s.latencyMs != null ? `${s.latencyMs} ms` : '—'}</span>
                  {s.httpStatus != null && <span>HTTP {s.httpStatus}</span>}
                  <span className="flex items-center gap-1">
                    <Clock3 size={9} /> {relativeAgo(s.lastFetchedAt ?? '')}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => openSource(s.name)}
                    className="rounded border border-line-1 px-2 py-0.5 text-micro text-sky-700 hover:border-sky-400 dark:text-sky-300"
                  >
                    read dispatches
                  </button>
                  {s.url && (
                    <a
                      href={sanitizeUrl(s.url) ?? undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-micro text-muted hover:text-heading"
                    >
                      feed <ExternalLink size={9} />
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
          {visibleSources.length === 0 && (
            <p className="surface-card p-6 text-center text-mini text-muted">No sources match those filters.</p>
          )}
        </section>
      )}

      {view === 'entities' && (
        <section className="mb-4 grid gap-3 md:grid-cols-3">
          {(
            [
              ['Vendors', (data?.trending.vendors ?? []).map((v) => ({ id: v, name: v }))],
              ['Actors', data?.trending.actors ?? []],
              ['Groups', data?.trending.groups ?? []],
            ] as const
          ).map(([title, items]) => (
            <div key={title} className="surface-card p-3">
              <div className="mb-2 flex items-center gap-1.5 text-mini font-semibold uppercase tracking-wider text-muted">
                <Activity size={12} /> {title} ({items.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {items.slice(0, 40).map((item) => (
                  <button
                    key={item.id || item.name}
                    type="button"
                    onClick={() => toggleWatch(item.name)}
                    title={watchlist.has(item.name) ? 'Remove from watchlist' : 'Add to watchlist'}
                    className={`rounded-full border px-2 py-0.5 text-micro ${
                      watchlist.has(item.name)
                        ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                        : 'border-line-1 text-muted hover:text-heading'
                    }`}
                  >
                    {item.name}
                    {item.id && item.id !== item.name && <span className="ml-1 font-mono text-muted">{item.id}</span>}
                  </button>
                ))}
              </div>
              <p className="mt-2 text-micro text-muted">
                Click to add or remove a watch phrase for the dispatch stream.
              </p>
            </div>
          ))}
        </section>
      )}

      <div className={`mb-4 space-y-3 ${view === 'stream' ? '' : 'hidden'}`}>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search dispatches, tags, CVEs…"
              className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
            />
          </div>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-lg border border-line-1 bg-surface-100 px-2 py-1.5 text-mini text-fg"
            aria-label="Severity"
          >
            {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={source}
            onChange={(e) => setSource(e.target.value)}
            className="max-w-[190px] rounded-lg border border-line-1 bg-surface-100 px-2 py-1.5 text-mini text-fg"
            aria-label="Source"
          >
            <option value="all">all sources</option>
            {sources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => setOnlyUnread((v) => !v)}
            aria-pressed={onlyUnread}
            className={`rounded-lg border px-2.5 py-1.5 text-mini ${onlyUnread ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'}`}
          >
            Unread
          </button>
          <button
            type="button"
            onClick={() => setOnlySaved((v) => !v)}
            aria-pressed={onlySaved}
            className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-mini ${onlySaved ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300' : 'border-line-1 text-muted'}`}
          >
            <Bookmark size={11} /> Saved
          </button>
          <button
            type="button"
            onClick={addWatch}
            className="inline-flex items-center gap-1 rounded-lg border border-line-1 px-2.5 py-1.5 text-mini text-muted hover:text-fg"
          >
            <Star size={11} /> Watchlist {watchlist.size > 0 && `(${watchlist.size})`}
          </button>
          <div className="flex items-center gap-0.5 rounded-lg border border-line-1 p-0.5" aria-label="Layout">
            {(
              [
                ['newspaper', Newspaper],
                ['list', List],
                ['compact', LayoutGrid],
              ] as const
            ).map(([id, Icon]) => (
              <button
                key={id}
                type="button"
                onClick={() => setLayout(id)}
                aria-pressed={layout === id}
                title={id}
                className={`rounded p-1.5 ${layout === id ? 'bg-surface-300 text-heading' : 'text-muted hover:text-heading'}`}
              >
                <Icon size={13} />
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setCategory('all')}
            aria-pressed={category === 'all'}
            className={`rounded-full border px-2.5 py-1 text-mini font-mono ${category === 'all' ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'}`}
          >
            all
          </button>
          {categories.map(([name, count]) => (
            <button
              key={name}
              type="button"
              onClick={() => setCategory(name)}
              aria-pressed={category === name}
              className={`rounded-full border px-2.5 py-1 text-mini font-mono ${category === name ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'}`}
            >
              {name} ({count})
            </button>
          ))}
        </div>

        {watchlist.size > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-mini text-muted">
            <Filter size={11} />
            {[...watchlist].map((w) => (
              <button
                key={w}
                type="button"
                onClick={() => toggleWatch(w)}
                className="rounded-full border border-amber-500/40 px-2 py-0.5 text-micro text-amber-700 dark:text-amber-300"
              >
                {w} ×
              </button>
            ))}
          </div>
        )}
      </div>

      {view === 'stream' && data && summaryItems.length > 0 && (
        <AiSummaryCard
          surface="ThreatFeed Reader"
          items={summaryItems}
          dayKey={data.generatedAt?.slice(0, 10)}
          requireAdmin={false}
          autoFetch={false}
          className="mb-4"
        />
      )}

      {loading && !data && <p className="text-mini font-mono text-muted">loading dispatches…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      <div className={view === 'stream' ? '' : 'hidden'}>
        <div className="mb-2 text-mini text-muted">
          <span className="font-mono text-fg">{articles.length.toLocaleString()}</span> dispatches · chronological
          stream
        </div>
        <ul className={`grid gap-2 ${layout === 'newspaper' ? 'md:grid-cols-2' : ''}`}>
          {articles.slice(0, 300).map((a) => (
            <ArticleCard
              key={a.id}
              article={a}
              layout={layout}
              read={read.has(a.id)}
              bookmarked={saved.has(a.id)}
              onRead={() => markRead(a.id)}
              onBookmark={() => toggleSaved(a.id)}
            />
          ))}
        </ul>

        {data && articles.length === 0 && (
          <p className="surface-card p-6 text-center text-mini text-muted">No dispatches match those filters.</p>
        )}
        {articles.length > 300 && (
          <p className="mt-3 text-center text-mini text-muted">
            Showing the 300 newest of {articles.length.toLocaleString()} matches — narrow the filters to see older
            dispatches.
          </p>
        )}
      </div>

      <footer className="mt-6 border-t border-line-1 pt-3 text-micro text-muted">
        {data?.note} Reader UI re-implemented in this platform's design system; no upstream code or CSS vendored. AI
        summary and per-article analysis are opt-in and never fetched on page load.{' '}
        <Sparkles size={10} className="inline" /> <Rss size={10} className="inline" />
      </footer>
    </DataPageLayout>
  );
}
