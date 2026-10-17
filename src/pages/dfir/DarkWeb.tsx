import { errMessage, logCatch } from '../../lib/log';
import { Virtuoso } from 'react-virtuoso';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ExternalLink, RefreshCw, Plus, X, Eye, Bell, Search, Filter, Sparkles } from 'lucide-react';
import { useLastVisit, isNewSince, useFocusTrap } from '../../hooks';
import { fetchAggregatedFeed, formatRelativeTime } from '../../services/rssService';
import { rssFeeds } from '../../data/rssFeeds';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';
import type { FeedItem, DateWindow, MatchedItem } from './darkweb-helpers';
import {
  ALL_FEED_IDS,
  loadJson,
  saveJson,
  findWatchMatches,
  compileSearch,
  withinWindow,
  highlightInText,
  STORAGE_KEY_WATCH,
  STORAGE_KEY_SOURCES,
  MAX_ITEMS,
  MAX_PER_SOURCE,
  DARKWEB_FEEDS,
} from './darkweb-helpers';

// Use the same shape as before so we minimise downstream churn.

/**
 * DarkWeb is now the aggregated dark-web RSS feed view only - the three
 * per-source widgets (ransomware activity / cybersec Telegram firehose /
 * breach disclosures) live as their own dedicated /threatintel/* pages
 * and import their panel components from this file. See
 * RansomwareActivity.tsx, CybersecTelegram.tsx, BreachDisclosures.tsx.
 */
export default function DarkWeb(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [items, setItems] = useState<FeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [sourceCount, setSourceCount] = useState(0);
  const [watchlist, setWatchlist] = useState<string[]>([]);
  const [newTerm, setNewTerm] = useState('');
  // Search controls - persisted in URL as ?q=
  const [search, setSearch] = useState(searchParams.get('q') ?? '');
  const [activeSources, setActiveSources] = useState<Set<string>>(() => new Set(ALL_FEED_IDS));
  const [dateWindow, setDateWindow] = useState<DateWindow>('30d');
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);

  // Hydrate from localStorage
  useEffect(() => {
    setWatchlist(loadJson<string[]>(STORAGE_KEY_WATCH, []));
    const savedSources = loadJson<string[]>(STORAGE_KEY_SOURCES, ALL_FEED_IDS);
    setActiveSources(new Set(savedSources.length > 0 ? savedSources : ALL_FEED_IDS));
  }, []);

  // Sync search to URL as ?q=
  useEffect(() => {
    if (search) setSearchParams({ q: search }, { replace: true });
    else setSearchParams({}, { replace: true });
  }, [search, setSearchParams]);

  const fetchFeeds = useCallback(async () => {
    setLoading(true);
    setItems([]);
    setSourceCount(0);
    try {
      const data = await fetchAggregatedFeed(ALL_FEED_IDS, {
        limit: MAX_ITEMS,
        perSource: MAX_PER_SOURCE,
      });
      if (data) {
        setItems(data.items);
        setSourceCount(data.feeds_returned);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchFeeds();
  }, [fetchFeeds]);

  const addTerm = (raw: string) => {
    const term = raw.trim();
    if (!term) return;
    if (watchlist.some((w) => w.toLowerCase() === term.toLowerCase())) return;
    const next = [...watchlist, term];
    setWatchlist(next);
    saveJson(STORAGE_KEY_WATCH, next);
    setNewTerm('');
  };
  const removeTerm = (term: string) => {
    const next = watchlist.filter((w) => w !== term);
    setWatchlist(next);
    saveJson(STORAGE_KEY_WATCH, next);
  };
  const toggleSource = (id: string) => {
    setActiveSources((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      saveJson(STORAGE_KEY_SOURCES, Array.from(next));
      return next;
    });
  };
  const allSourcesOn = activeSources.size === ALL_FEED_IDS.length;
  const toggleAllSources = () => {
    const next = allSourcesOn ? new Set<string>() : new Set(ALL_FEED_IDS);
    setActiveSources(next);
    saveJson(STORAGE_KEY_SOURCES, Array.from(next));
  };

  const searchFn = useMemo(() => compileSearch(search), [search]);

  // Apply: source filter → date window → search → watchlist match annotation
  // Build url → feed-id index once per render. The aggregator returns each
  // item's `source_url`, so we look up the feed id directly instead of trying
  // to match on hostname (which would collapse all reddit subs together).
  const urlToFeedId = useMemo(() => {
    const map = new Map<string, string>();
    for (const f of DARKWEB_FEEDS) {
      const url = rssFeeds.find((r) => r.id === f.id)?.url;
      if (url) map.set(url, f.id);
    }
    return map;
  }, []);

  const matched = useMemo<MatchedItem[]>(() => {
    const filterBySource = !allSourcesOn;
    const out: MatchedItem[] = [];
    for (const it of items) {
      if (filterBySource) {
        const fid = urlToFeedId.get(it.source_url);
        if (fid && !activeSources.has(fid)) continue;
      }
      if (!withinWindow(it, dateWindow)) continue;
      if (searchFn && !searchFn(it)) continue;
      out.push({
        item: it,
        watchMatches: findWatchMatches(it, watchlist),
        searchMatch: !!searchFn,
      });
    }
    return out;
  }, [items, activeSources, allSourcesOn, dateWindow, searchFn, watchlist, urlToFeedId]);

  // Compile the highlight regex ONCE per [search, watchlist] change instead of
  // rebuilding it inside highlightInText for every one of up to MAX_ITEMS rows
  // on every keystroke. Tokens come only from the query + watchlist, never the
  // per-row text, so the regex is row-independent.
  const highlightRe = useMemo<RegExp | null>(() => {
    const tokens = [...search.toLowerCase().split(/\s+/).filter(Boolean), ...watchlist.map((t) => t.toLowerCase())];
    if (tokens.length === 0) return null;
    const escaped = tokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    try {
      return new RegExp(`(${escaped})`, 'gi');
    } catch (_catchErr) {
      logCatch(_catchErr);
      return null;
    }
  }, [search, watchlist]);

  const matchCount = matched.filter((m) => m.watchMatches.length > 0).length;
  const perTermCount = useMemo(() => {
    const map: Record<string, number> = {};
    for (const term of watchlist) map[term] = 0;
    for (const m of matched) for (const t of m.watchMatches) map[t]!++;
    return map;
  }, [matched, watchlist]);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Eye size={28} />}
      title="Dark Web Watch"
      description={
        <>
          Aggregated dark web, leak-site, breach, and security-research activity from
          {` ${DARKWEB_FEEDS.length} `}curated free sources. Use the search box for live filtering (regex like{' '}
          <code className="font-mono text-xs bg-surface-300 px-1 rounded">/lockbit|alphv/i</code> works), filter by
          source, narrow by date window, and add long-running keywords to your watchlist for highlighted matches across
          visits. Watchlist + source preferences are stored locally; nothing is uploaded.
        </>
      }
      headerExtra={
        <p className="text-xs text-muted font-mono">
          Per-source widgets -{' '}
          <Link to="/threatintel/ransomware-hub" className="text-brand-600 dark:text-brand-400 hover:underline">
            ransomware activity
          </Link>
          ,{' '}
          <Link to="/threatintel/telegram" className="text-brand-600 dark:text-brand-400 hover:underline">
            cybersec Telegram firehose
          </Link>
          ,{' '}
          <Link to="/threatintel/telegram" className="text-brand-600 dark:text-brand-400 hover:underline">
            breach disclosures
          </Link>
          ,{' '}
          <Link to="/threatintel/breach-hub" className="text-brand-600 dark:text-brand-400 hover:underline">
            breach / leak-forum tracker
          </Link>{' '}
          - live as their own pages.
        </p>
      }
    >
      <>
        {/* Search + filters */}
        <section className="mb-6 surface-card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Search size={14} className="text-brand-600 dark:text-brand-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Live search. Plain words = AND. /regex/i for regex."
              className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="text-xs font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                clear
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
            <Filter size={12} className="text-brand-600 dark:text-brand-400" />
            <span className="text-muted">Sources:</span>
            <button
              type="button"
              onClick={toggleAllSources}
              className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
            >
              {allSourcesOn ? 'clear all' : 'select all'}
            </button>
            {DARKWEB_FEEDS.map((f) => {
              const on = activeSources.has(f.id);
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => toggleSource(f.id)}
                  aria-pressed={on}
                  className={`px-2 py-0.5 rounded border transition-colors ${
                    on
                      ? 'border-brand-500/50 text-heading bg-brand-50 dark:bg-brand-900/20'
                      : 'border-line-1 text-slate-500'
                  }`}
                >
                  {f.label}
                </button>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="text-muted">Window:</span>
            {(['24h', '7d', '30d'] as DateWindow[]).map((w) => (
              <button
                key={w}
                type="button"
                onClick={() => setDateWindow(w)}
                aria-pressed={dateWindow === w}
                className={`px-2 py-0.5 rounded border transition-colors ${
                  dateWindow === w
                    ? 'border-brand-500/50 text-heading bg-brand-50 dark:bg-brand-900/20'
                    : 'border-line-1 text-slate-500'
                }`}
              >
                last {w}
              </button>
            ))}
            <span className="text-muted">(max 30 days)</span>
          </div>
        </section>

        {/* Watchlist control */}
        <section className="mb-6 surface-card p-5">
          <div className="flex items-center gap-2 mb-3">
            <Bell size={14} className="text-brand-600 dark:text-brand-400" />
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted">Watchlist</h2>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              addTerm(newTerm);
            }}
            className="flex gap-2 mb-3"
          >
            <input
              type="text"
              value={newTerm}
              onChange={(e) => setNewTerm(e.target.value)}
              placeholder="company name, domain, sector, threat actor…"
              className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
            <button
              type="submit"
              disabled={!newTerm.trim()}
              className="inline-flex items-center gap-1 px-3 py-2 bg-brand-600 dark:bg-brand-500 text-on-fill text-sm font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
            >
              <Plus size={14} /> Track
            </button>
          </form>
          {watchlist.length === 0 ? (
            <p className="text-xs font-mono text-muted">
              Empty. Add a keyword above to highlight matching posts in the feed below.
            </p>
          ) : (
            <ul className="flex flex-wrap gap-2">
              {watchlist.map((term) => (
                <li
                  key={term}
                  className="inline-flex items-center gap-2 text-xs font-mono px-2 py-1 rounded-full border border-brand-500/40 bg-brand-50 dark:bg-brand-900/20 text-brand-700 dark:text-brand-300"
                >
                  <span>{term}</span>
                  <span className="text-muted">{perTermCount[term] ?? 0}</span>
                  <button
                    type="button"
                    onClick={() => removeTerm(term)}
                    aria-label={`stop tracking ${term}`}
                    className="text-muted hover:text-rose-600 dark:hover:text-rose-400"
                  >
                    <X size={12} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Stats */}
        <header className="flex items-baseline justify-between mb-4 flex-wrap gap-2">
          <h2 className="font-display font-bold text-xl">Recent activity</h2>
          <div className="flex items-center gap-3 text-xs font-mono text-muted">
            <span>
              {sourceCount} of {DARKWEB_FEEDS.length} sources
            </span>
            <span aria-hidden="true">·</span>
            <span>
              {matched.length} of {items.length} items
            </span>
            {watchlist.length > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-brand-600 dark:text-brand-400">
                  {matchCount} watchlist match{matchCount === 1 ? '' : 'es'}
                </span>
              </>
            )}
            <span aria-hidden="true">·</span>
            <button
              type="button"
              onClick={() => void fetchFeeds()}
              disabled={loading}
              aria-label="refresh dark web feeds"
              className="inline-flex items-center gap-1 hover:text-brand-600 dark:hover:text-brand-400 disabled:opacity-50"
            >
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> refresh
            </button>
          </div>
        </header>

        {loading && items.length === 0 && <p className="font-mono text-sm text-muted">Fetching…</p>}

        {!loading && matched.length === 0 && items.length > 0 && (
          <p className="font-mono text-sm text-muted">
            No items match the current filters.{' '}
            <button
              type="button"
              onClick={() => {
                setSearch('');
                setActiveSources(new Set(ALL_FEED_IDS));
                setDateWindow('30d');
              }}
              className="text-brand-600 dark:text-brand-400 hover:underline"
            >
              reset filters
            </button>
          </p>
        )}

        <div aria-live="polite" aria-atomic="true" className="sr-only">
          {search ? `${matched.length} matching items` : ''}
        </div>

        {mounted && matched.length > 0 && (
          <Virtuoso
            style={{ height: '80vh' }}
            totalCount={matched.length}
            itemContent={(index) => {
              const { item: it, watchMatches } = matched[index]!;
              const hit = watchMatches.length > 0;
              return (
                <li
                  key={it.guid ?? it.link}
                  className={`rounded-xl border p-4 transition-colors mb-3 ${
                    hit
                      ? 'border-amber-400 bg-amber-50/50 dark:bg-amber-900/15 dark:border-amber-700'
                      : 'border-line-1 bg-white dark:bg-surface-200'
                  }`}
                >
                  <a
                    href={sanitizeUrl(it.link) || undefined}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`${it.title} (opens in new tab)`}
                    className="group block"
                  >
                    <div className="flex items-baseline justify-between gap-3">
                      <h3 className="font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
                        {highlightInText(it.title, highlightRe)}
                      </h3>
                      <ExternalLink size={12} className="text-muted shrink-0 mt-1" />
                    </div>
                    <div className="mt-1 flex items-center gap-3 text-xs font-mono text-muted">
                      {it.source && <span className="text-brand-600 dark:text-brand-400">{it.source}</span>}
                      {it.pubDate && <span>{formatRelativeTime(it.pubDate)}</span>}
                    </div>
                  </a>
                  {hit && (
                    <div className="mt-2 flex items-center gap-2 flex-wrap">
                      <Eye size={12} className="text-amber-700 dark:text-amber-400" />
                      {watchMatches.map((m) => (
                        <span
                          key={m}
                          className="text-micro font-mono px-1.5 py-0.5 rounded bg-amber-200/60 dark:bg-amber-700/30 text-amber-900 dark:text-amber-200"
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                  )}
                </li>
              );
            }}
            components={{
              List: ({ children, style }) => (
                <ul className="space-y-3" aria-label="Feed items" style={style}>
                  {children}
                </ul>
              ),
            }}
          />
        )}

        <footer className="mt-12 text-xs font-mono text-muted leading-relaxed">
          Sources: Dark Web Informer · Ransomware.live · DataBreaches.net · The DFIR Report · The Record · Curated
          Intelligence · Reddit (r/Malware, r/blueteamsec, r/threatintel, r/netsec) · BleepingComputer · Krebs · Malware
          Traffic Analysis · DoublePulsar · Sophos X-Ops. Closed-darknet content (private Telegram, paid leak sites,
          invite-only forums) is not in scope; see{' '}
          <a
            href="https://github.com/fastfire/deepdarkCTI"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            deepdarkCTI
          </a>{' '}
          for an index of those.
        </footer>
      </>
    </DataPageLayout>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Breach Disclosures panel - pulls Have I Been Pwned's public breach corpus
// ─────────────────────────────────────────────────────────────────────────

interface BreachDisclosure {
  name: string;
  title: string;
  domain?: string;
  breach_date?: string;
  added_date?: string;
  modified_date?: string;
  pwn_count?: number;
  description?: string;
  data_classes?: string[];
  verified: boolean;
  sensitive: boolean;
  logo_path?: string;
}

interface BreachDisclosuresResponse {
  generated_at: string;
  source: string;
  count: number;
  breaches: BreachDisclosure[];
}

function formatPwnCount(n?: number): string {
  if (!n || n <= 0) return '-';
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}k`;
  return String(n);
}

export function BreachDisclosuresPanel(): JSX.Element {
  const [data, setData] = useState<BreachDisclosuresResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      try {
        const res = await fetch('/api/v1/breach-disclosures', {
          signal: AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as BreachDisclosuresResponse;
        setData(json);
      } catch (e) {
        console.error('BreachDisclosuresPanel failed:', errMessage(e));
        if ((e as Error).name !== 'AbortError') setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    })();
    return () => ac.abort();
  }, []);

  const visible = data?.breaches.slice(0, expanded ? data.breaches.length : 8) ?? [];

  return (
    <section className="mb-6 surface-card p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-3 mb-3">
        <h2 className="font-display font-semibold text-lg inline-flex items-center gap-2">
          Recent breach disclosures
          <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300">
            HIBP corpus
          </span>
        </h2>
        <span className="text-mini font-mono text-muted">
          {loading ? 'loading…' : data ? `${data.count} disclosures` : ''}
        </span>
      </div>

      {error && (
        <p role="alert" className="text-sm font-mono text-rose-600 dark:text-rose-400">
          Could not load breach disclosures: {error}
        </p>
      )}

      {data && data.breaches.length === 0 && !error && (
        <p className="text-sm font-mono text-muted">
          No disclosures returned. The upstream HIBP API may be unavailable; the in-feed sources below still cover
          breach reporting.
        </p>
      )}

      {visible.length > 0 && (
        <ul className="grid gap-2 sm:grid-cols-2">
          {visible.map((b, i) => (
            <li key={`${b.name}-${b.added_date ?? i}`} className="rounded border border-line-1 bg-surface-200 p-2.5">
              <div className="flex flex-wrap items-baseline gap-2 mb-1">
                <a
                  href={b.domain ? `https://haveibeenpwned.com/PwnedWebsites#${b.name}` : '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-display font-semibold text-sm text-heading hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                >
                  {b.title}
                </a>
                {b.verified && (
                  <span className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                    verified
                  </span>
                )}
                {b.sensitive && (
                  <span className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300">
                    sensitive
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-baseline gap-3 text-mini font-mono text-muted mb-1">
                {b.domain && <span>{b.domain}</span>}
                {b.breach_date && <span>breached {b.breach_date}</span>}
                {b.added_date && <span>disclosed {b.added_date.slice(0, 10)}</span>}
                {typeof b.pwn_count === 'number' && b.pwn_count > 0 && (
                  <span className="text-body font-bold">{formatPwnCount(b.pwn_count)} accounts</span>
                )}
              </div>
              {b.data_classes && b.data_classes.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-1">
                  {b.data_classes.slice(0, 5).map((c) => (
                    <span key={c} className="text-micro font-mono px-1 py-0.5 rounded border border-line-2 text-muted">
                      {c}
                    </span>
                  ))}
                  {b.data_classes.length > 5 && (
                    <span className="text-micro font-mono text-muted">+{b.data_classes.length - 5}</span>
                  )}
                </div>
              )}
              {b.description && (
                <p className="text-mini font-mono text-muted leading-relaxed line-clamp-3">{b.description}</p>
              )}
            </li>
          ))}
        </ul>
      )}

      {data && data.breaches.length > 8 && (
        <div className="mt-3 flex items-center justify-between text-mini font-mono text-muted">
          <button onClick={() => setExpanded((v) => !v)} className="text-brand-600 dark:text-brand-400 hover:underline">
            {expanded ? 'Show fewer' : `Show all ${data.breaches.length}`}
          </button>
          <a
            href="https://haveibeenpwned.com/SpamEmail"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="full HIBP list (opens in new tab)"
            className="hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 transition-colors"
          >
            full HIBP list <ExternalLink size={10} />
          </a>
        </div>
      )}
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Recent Ransomware Activity panel - pulls Ransomlook.io's leak-site posts
// ─────────────────────────────────────────────────────────────────────────

type RansomwareOrigin =
  'ransomlook' | 'mti' | 'ransomfeed' | 'ransomwatch' | 'ransomwarelive' | 'andreafortuna' | 'ctifyi' | 'x';

interface RansomwareVictim {
  victim: string;
  group: string;
  discovered: string;
  description?: string;
  source_url: string;
  /** Clearnet URL for a screenshot of the .onion leak page (Ransomlook-rehosted). */
  screen_url?: string;
  /** Which of the trackers surfaced this victim. */
  origin?: RansomwareOrigin;
  /** ISO-3166 country (only set when upstream provided it; mythreatintel today). */
  country?: string;
  /** Sector classification (backend classifies from victim name + description). */
  sector?: string;
}

const ORIGIN_PILL: Record<RansomwareOrigin, { label: string; cls: string; tooltip: string }> = {
  ransomlook: {
    label: 'RL',
    cls: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    tooltip: 'Ransomlook - primary tracker with .onion screenshots',
  },
  mti: {
    label: 'MTI',
    cls: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    tooltip: 'mythreatintel Telegram channel - real-time Spanish CTI firehose',
  },
  ransomfeed: {
    label: 'RFI',
    cls: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    tooltip: 'ransomfeed.it - RSS of victim claims',
  },
  ransomwatch: {
    label: 'RW',
    cls: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    tooltip: 'ransomwatch slot - RansomLook deep leak-site feed (extended 7-day coverage)',
  },
  ransomwarelive: {
    label: 'RL!',
    cls: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    tooltip: 'ransomware.live - public victim dump with country + sector data',
  },
  andreafortuna: {
    label: 'AF',
    cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    tooltip: 'Andrea Fortuna CTI feeds - ransomware victim tracker',
  },
  ctifyi: {
    label: 'CTI',
    cls: 'border-teal-500/40 bg-teal-500/10 text-teal-700 dark:text-teal-300',
    tooltip: 'cti.fyi - leak-site post tracker with .onion screenshots',
  },
  x: {
    label: 'X',
    cls: 'border-slate-500/40 bg-slate-500/10 text-body',
    tooltip: 'X / FalconFeeds + @DailyDarkWeb - leak-site claims parsed from posts',
  },
};

interface RansomwareResponse {
  generated_at: string;
  source: string;
  count: number;
  groups: Array<{ group: string; count: number }>;
  victims: RansomwareVictim[];
}

export function RansomwareActivityPanel(): JSX.Element {
  const [searchParams] = useSearchParams();
  const [data, setData] = useState<RansomwareResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [groupFilter, setGroupFilter] = useState<string | 'all'>('all');
  // Honor a victim deep-link (e.g. from RansomwareMap: ?q=<victim>).
  const [victimQuery, setVictimQuery] = useState(searchParams.get('q') ?? '');
  const [expanded, setExpanded] = useState(false);
  const [lightbox, setLightbox] = useState<{ url: string; victim: string; group: string } | null>(null);
  const [newOnly, setNewOnly] = useState(false);
  const { previous: lastVisit, markVisited } = useLastVisit('ransomware-activity');
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const lightboxRef = useFocusTrap({ isActive: lightbox !== null, onEscape: () => setLightbox(null) });

  // Esc closes the lightbox.
  useEffect(() => {
    if (!lightbox) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setLightbox(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [lightbox]);

  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      try {
        setError(null);
        const res = await fetch('/api/v1/ransomware-recent', {
          signal: AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]),
          cache: 'no-cache',
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as RansomwareResponse;
        setData(json);
      } catch (e) {
        logCatch(e);
        if ((e as Error).name !== 'AbortError') setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    })();
    return () => ac.abort();
  }, [retryCount]);

  const filteredVictims = useMemo(() => {
    if (!data) return [];
    const q = victimQuery.trim().toLowerCase();
    return data.victims.filter((v) => {
      if (groupFilter !== 'all' && v.group !== groupFilter) return false;
      if (newOnly && !isNewSince(v.discovered, lastVisit)) return false;
      if (q && !v.victim.toLowerCase().includes(q) && !v.group.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [data, groupFilter, newOnly, lastVisit, victimQuery]);

  const newCount = useMemo(() => {
    if (!data || !lastVisit) return 0;
    return data.victims.filter((v) => isNewSince(v.discovered, lastVisit)).length;
  }, [data, lastVisit]);

  useEffect(() => {
    if (!data) return;
    const id = window.setTimeout(markVisited, 1500);
    return () => window.clearTimeout(id);
  }, [data, markVisited]);

  const visible = filteredVictims.slice(0, expanded ? filteredVictims.length : 12);

  const summaryItems = useMemo(
    () =>
      filteredVictims.slice(0, 50).map((v) => ({
        title: `${v.group} / ${v.victim}`,
        body: v.description ?? '',
        source: v.origin,
      })),
    [filteredVictims]
  );

  return (
    <section className="mb-6 surface-card p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-3 mb-3">
        <h2 className="font-display font-semibold text-lg inline-flex items-center gap-2">
          Recent ransomware activity
        </h2>
        <span className="text-mini font-mono text-muted" title={data?.source ?? ''}>
          {loading ? 'loading…' : data ? `${data.count} leak-site posts · multi-source merge` : ''}
        </span>
      </div>

      <AiSummaryCard
        surface="Ransomware Activity"
        items={summaryItems}
        endpoint="/api/v1/unified-search/summarize"
        requireAdmin={false}
        autoFetch={false}
        extraBody={{ q: 'Ransomware activity summary' }}
        className="mb-3"
      />

      <div className="mb-3">
        <input
          type="search"
          value={victimQuery}
          onChange={(e) => setVictimQuery(e.target.value)}
          placeholder="Filter by victim or group…"
          aria-label="Filter ransomware activity by victim or group"
          className="w-full sm:max-w-xs text-meta font-mono px-2.5 py-1.5 rounded border border-line-2 bg-surface-100 text-body focus:outline-none focus:border-brand-500/60"
        />
      </div>

      {error && (
        <p role="alert" className="text-sm font-mono text-rose-600 dark:text-rose-400 flex items-center gap-3">
          <span>Could not load ransomware feed: {error}</span>
          <button
            type="button"
            onClick={() => setRetryCount((n) => n + 1)}
            className="shrink-0 text-xs font-mono px-2 py-1 rounded border border-rose-400/60 hover:bg-rose-500/10"
          >
            retry
          </button>
        </p>
      )}

      {data && data.groups.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          <button
            onClick={() => setGroupFilter('all')}
            aria-pressed={groupFilter === 'all'}
            className={`text-mini font-mono px-2 py-1 rounded border transition-colors ${
              groupFilter === 'all'
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
            }`}
          >
            All <span className="opacity-60">· {data.count}</span>
          </button>
          {newCount > 0 && (
            <button
              onClick={() => setNewOnly((v) => !v)}
              aria-pressed={newOnly}
              className={`text-mini font-mono px-2 py-1 rounded border transition-colors inline-flex items-center gap-1 ${
                newOnly
                  ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                  : 'border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:border-emerald-500/60'
              }`}
              aria-label={`${newCount} new claims since your last visit`}
            >
              <Sparkles size={10} /> {newCount} new
            </button>
          )}
          {data.groups.map((g) => (
            <button
              key={g.group}
              onClick={() => setGroupFilter(g.group)}
              aria-pressed={groupFilter === g.group}
              className={`text-mini font-mono px-2 py-1 rounded border transition-colors ${
                groupFilter === g.group
                  ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                  : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
              }`}
            >
              {g.group} <span className="opacity-60">· {g.count}</span>
            </button>
          ))}
        </div>
      )}

      {visible.length > 0 && (
        <ul className="grid gap-2 sm:grid-cols-2">
          {visible.map((v, i) => (
            <li key={`${v.group}-${v.victim}-${i}`} className="rounded border border-line-1 bg-surface-200 p-2.5">
              <div className="flex gap-2.5">
                {v.screen_url && (
                  <button
                    type="button"
                    onClick={() => {
                      triggerRef.current = document.activeElement as HTMLButtonElement;
                      setLightbox({ url: v.screen_url!, victim: v.victim, group: v.group });
                    }}
                    className="shrink-0 group relative w-14 h-10 sm:w-20 sm:h-14 rounded overflow-hidden border border-line-2 bg-track hover:border-brand-500/60"
                    title="Click to view full leak-site screenshot"
                    aria-label={`View leak-site screenshot for ${v.victim}`}
                  >
                    <img
                      loading="lazy"
                      src={v.screen_url}
                      alt=""
                      decoding="async"
                      referrerPolicy="no-referrer"
                      className="w-full h-full object-cover object-left-top opacity-90 group-hover:opacity-100 transition-opacity"
                      onError={(e) => {
                        (e.currentTarget.parentElement as HTMLElement).style.display = 'none';
                      }}
                    />
                    <span className="absolute bottom-0.5 right-0.5 text-micro font-mono px-1 rounded bg-surface-100/70 text-slate-100 opacity-0 group-hover:opacity-100">
                      zoom
                    </span>
                  </button>
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2 mb-1">
                    <a
                      href={sanitizeUrl(v.source_url) || undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      aria-label={`${v.victim} (opens in new tab)`}
                      className="font-display font-semibold text-sm text-heading hover:text-brand-600 dark:hover:text-brand-400 break-words transition-colors"
                    >
                      {v.victim}
                    </a>
                    <span className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300">
                      {v.group}
                    </span>
                    {v.origin && ORIGIN_PILL[v.origin] && (
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border ${ORIGIN_PILL[v.origin].cls}`}
                        title={ORIGIN_PILL[v.origin].tooltip}
                      >
                        {ORIGIN_PILL[v.origin].label}
                      </span>
                    )}
                    {v.country && (
                      <span
                        className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border border-line-2 text-muted"
                        title={`Country attributed by upstream: ${v.country}`}
                      >
                        {v.country}
                      </span>
                    )}
                    {v.sector && (
                      <span
                        className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border border-indigo-500/30 bg-indigo-500/10 text-indigo-600 dark:text-indigo-300"
                        title={`Sector classification: ${v.sector}`}
                      >
                        {v.sector}
                      </span>
                    )}
                  </div>
                  <div className="text-mini font-mono text-muted mb-1">claimed {formatRelativeTime(v.discovered)}</div>
                  {v.description && (
                    <p className="text-mini font-mono text-muted leading-relaxed line-clamp-2">{v.description}</p>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}

      {filteredVictims.length > 12 && (
        <div className="mt-3 flex items-center justify-between text-mini font-mono text-muted">
          <button onClick={() => setExpanded((v) => !v)} className="text-brand-600 dark:text-brand-400 hover:underline">
            {expanded ? 'Show fewer' : `Show all ${filteredVictims.length}`}
          </button>
          <a
            href="https://www.ransomlook.io/recent"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="full Ransomlook feed (opens in new tab)"
            className="hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 transition-colors"
          >
            full Ransomlook feed <ExternalLink size={10} />
          </a>
        </div>
      )}

      {data && data.victims.some((v) => v.screen_url) && (
        <p className="mt-3 text-micro font-mono text-muted leading-relaxed">
          Thumbnails are PNG screenshots of the .onion leak post, captured by Ransomlook&apos;s Tor-equipped backend and
          rehosted on clearnet. Click to zoom - we never fetch the .onion site from your browser. Treat the content as
          untrusted (leak-site screenshots can include malicious links + actor branding).
        </p>
      )}

      {lightbox && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-100/80 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-label={`Leak-site screenshot for ${lightbox.victim}`}
          ref={lightboxRef as React.RefObject<HTMLDivElement>}
        >
          <button
            type="button"
            onClick={() => {
              setLightbox(null);
              setTimeout(() => triggerRef.current?.focus(), 0);
            }}
            className="absolute inset-0 cursor-zoom-out"
            aria-label="Close screenshot"
          />
          <div className="relative max-w-5xl max-h-[90vh] w-full flex flex-col gap-2">
            <div className="flex items-baseline justify-between gap-2 text-slate-100">
              <div className="font-display font-semibold inline-flex items-center gap-2">
                {lightbox.victim}
                <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-rose-400/40 bg-rose-500/10 text-rose-300">
                  {lightbox.group}
                </span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setLightbox(null);
                  setTimeout(() => triggerRef.current?.focus(), 0);
                }}
                id="lightbox-close"
                className="text-inverted hover:text-slate-100 inline-flex items-center gap-1 text-sm font-mono"
                aria-label="Close"
              >
                <X size={14} /> close (esc)
              </button>
            </div>
            <img
              loading="lazy"
              src={lightbox.url}
              alt={`Leak-site screenshot of ${lightbox.victim}`}
              className="w-full max-h-[80vh] object-contain rounded border border-slate-700 bg-surface-200"
              referrerPolicy="no-referrer"
            />
            <p className="text-micro font-mono text-muted text-center">
              Source: ransomlook.io · clearnet-rehosted PNG of the .onion leak page
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Telegram firehose panel - aggregated cybersec channel preview from
// /api/v1/telegram-feed. Server fetches telegram.me/s/<handle> for ~10 curated
// channels and we render the merged stream here. Watchlist matches use
// the same localStorage key as the main feed.
// ─────────────────────────────────────────────────────────────────────────

interface TelegramFeedItem {
  channel_handle: string;
  channel_name: string;
  channel_topic: 'malware' | 'ransomware' | 'hacktivism' | 'osint' | 'news' | 'leaks';
  channel_blurb: string;
  permalink: string;
  datetime: string;
  text: string;
  views?: string;
}

interface ChannelQuality {
  score: number;
  signals: {
    recent_pct: number;
    dupe_pct: number;
    median_text_len: number;
    posts_per_day: number;
  };
}

interface TelegramFeedResponse {
  generated_at: string;
  channels: {
    handle: string;
    name: string;
    topic: string;
    ok: boolean;
    count: number;
    quality?: ChannelQuality;
  }[];
  items: TelegramFeedItem[];
  warnings: string[];
}

function qualityPill(score?: number): { label: string; cls: string } {
  if (score === undefined)
    return {
      label: '-',
      cls: 'border-slate-300 dark:border-line-1 text-muted',
    };
  if (score >= 75)
    return { label: `${score}`, cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' };
  if (score >= 50) return { label: `${score}`, cls: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300' };
  if (score >= 25)
    return { label: `${score}`, cls: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300' };
  return { label: `${score}`, cls: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300' };
}

const TG_TOPIC_PILL: Record<TelegramFeedItem['channel_topic'], string> = {
  malware: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
  ransomware: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  hacktivism: 'border-pink-500/40 bg-pink-500/10 text-pink-700 dark:text-pink-300',
  osint: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  news: 'border-cyan-500/40 bg-cyan-500/10 text-sky-700 dark:text-sky-300',
  leaks: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
};

function highlightTelegramText(text: string, watchTerms: string[]): JSX.Element {
  if (watchTerms.length === 0) return <>{text}</>;
  // Build a single regex of all watch terms (escaped, case-insensitive).
  const escaped = watchTerms
    .filter(Boolean)
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .filter(Boolean);
  if (escaped.length === 0) return <>{text}</>;
  const re = new RegExp(`(${escaped.join('|')})`, 'gi');
  const parts = text.split(re);
  return (
    <>
      {parts.map((p, i) =>
        i % 2 === 1 ? (
          <mark key={`${p}-${i}`} className="bg-amber-300/40 dark:bg-amber-400/30 text-inherit rounded px-0.5">
            {p}
          </mark>
        ) : (
          <span key={`${p}-${i}`}>{p}</span>
        )
      )}
    </>
  );
}

export function TelegramFeedPanel(): JSX.Element {
  const [data, setData] = useState<TelegramFeedResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeChannel, setActiveChannel] = useState<string | 'all'>('all');
  const [expanded, setExpanded] = useState(false);
  const [watchlist, setWatchlist] = useState<string[]>(() => loadJson<string[]>(STORAGE_KEY_WATCH, []));
  const [newOnly, setNewOnly] = useState(false);
  const { previous: lastVisit, markVisited } = useLastVisit('telegram-feed');

  // Re-read watchlist when other components on the page mutate it.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY_WATCH) setWatchlist(loadJson<string[]>(STORAGE_KEY_WATCH, []));
    };
    window.addEventListener('storage', onStorage);
    // Also poll once after a short delay - same-tab writes don't fire `storage`.
    const t = setTimeout(() => setWatchlist(loadJson<string[]>(STORAGE_KEY_WATCH, [])), 1000);
    return () => {
      window.removeEventListener('storage', onStorage);
      clearTimeout(t);
    };
  }, []);

  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      // Cold-cache scrapes of telegram.me can exceed a single short timeout
      // (per-channel 12s × ~10 channels), so allow a generous window and retry
      // once — the backend populates its Cache API in waitUntil, so the second
      // attempt usually hits warm cache and returns instantly.
      const ATTEMPTS = 2;
      let lastErr: unknown = null;
      for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
        if (ac.signal.aborted) return;
        try {
          const res = await fetch('/api/v1/telegram-feed', {
            signal: AbortSignal.any([ac.signal, AbortSignal.timeout(30_000)]),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const json = (await res.json()) as TelegramFeedResponse;
          setData(json);
          setError(null);
          setLoading(false);
          return;
        } catch (e) {
          lastErr = e;
          if (ac.signal.aborted) return;
          const msg = errMessage(e);
          const retryable =
            (e as Error).name === 'TimeoutError' || /timed out|timeout|network|fetch failed|load failed/i.test(msg);
          if (attempt < ATTEMPTS - 1 && retryable) continue;
        }
      }
      if (!ac.signal.aborted) {
        if (lastErr) {
          logCatch(lastErr);
          if ((lastErr as Error).name !== 'AbortError') setError((lastErr as Error).message);
        }
        setLoading(false);
      }
    })();
    return () => ac.abort();
  }, []);

  const filteredItems = useMemo(() => {
    if (!data) return [];
    return data.items.filter((it) => {
      if (activeChannel !== 'all' && it.channel_handle !== activeChannel) return false;
      if (newOnly && !isNewSince(it.datetime, lastVisit)) return false;
      return true;
    });
  }, [data, activeChannel, newOnly, lastVisit]);

  const newCount = useMemo(() => {
    if (!data || !lastVisit) return 0;
    return data.items.filter((it) => isNewSince(it.datetime, lastVisit)).length;
  }, [data, lastVisit]);

  // Per-post AI summaries for the visible messages. Public surface (matches
  // the page-level AiSummaryCard) so every visitor gets the one-line take.
  const postSummaries = usePostSummaries({
    surface: 'Cybersec Telegram firehose',
    items: filteredItems.slice(0, 60).map((it) => ({
      id: it.permalink,
      title: it.channel_name,
      body: it.text,
      source: it.channel_name,
    })),
    requireAdmin: false,
  });

  useEffect(() => {
    if (!data) return;
    const id = window.setTimeout(markVisited, 1500);
    return () => window.clearTimeout(id);
  }, [data, markVisited]);

  const matchedItems = useMemo(() => {
    if (watchlist.length === 0) return filteredItems.map((it) => ({ it, matches: [] as string[] }));
    const lc = watchlist.map((w) => w.toLowerCase()).filter(Boolean);
    return filteredItems.map((it) => {
      const hay = it.text.toLowerCase();
      return { it, matches: lc.filter((w) => hay.includes(w)) };
    });
  }, [filteredItems, watchlist]);

  const visible = matchedItems.slice(0, expanded ? matchedItems.length : 10);
  const watchHits = matchedItems.filter((m) => m.matches.length > 0).length;

  return (
    <section className="mb-6 surface-card p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-3 mb-1">
        <h2 className="font-display font-semibold text-lg inline-flex items-center gap-2">
          Cybersec Telegram firehose
          <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300">
            t.me/s preview
          </span>
        </h2>
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-mini font-mono text-muted">
          {loading ? (
            <span>loading…</span>
          ) : data ? (
            <>
              <span>{data.items.length} posts</span>
              <span aria-hidden="true">·</span>
              <span>
                {data.channels.filter((c) => c.ok).length}/{data.channels.length} channels
              </span>
              <span aria-hidden="true">·</span>
              <span>cached 30 min</span>
            </>
          ) : null}
          {watchHits > 0 && (
            <>
              <span aria-hidden="true">·</span>
              <span className="text-amber-600 dark:text-amber-400">
                {watchHits} watchlist hit{watchHits === 1 ? '' : 's'}
              </span>
            </>
          )}
        </div>
      </div>

      <p className="text-meta font-mono text-muted mb-3 leading-relaxed">
        Latest messages from a curated set of public threat-intel and cybercrime-tracking Telegram channels -{' '}
        <Link to="/threatintel/telegram" className="text-brand-600 dark:text-brand-400 hover:underline">
          full catalogue
        </Link>
        . Server-side scrape of <code>telegram.me/s/&lt;handle&gt;</code>; no Telegram account required.
      </p>

      {error && (
        <p role="alert" className="text-sm font-mono text-rose-600 dark:text-rose-400">
          Could not load Telegram feed: {error}
        </p>
      )}

      {data && data.channels.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          <button
            onClick={() => setActiveChannel('all')}
            className={`text-mini font-mono px-2 py-1 rounded border transition-colors ${
              activeChannel === 'all'
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
            }`}
          >
            All <span className="opacity-60">· {data.items.length}</span>
          </button>
          {newCount > 0 && (
            <button
              onClick={() => setNewOnly((v) => !v)}
              className={`text-mini font-mono px-2 py-1 rounded border transition-colors inline-flex items-center gap-1 ${
                newOnly
                  ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                  : 'border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:border-emerald-500/60'
              }`}
              title={`${newCount} messages since your last visit${lastVisit ? ` (${new Date(lastVisit).toLocaleString()})` : ''}`}
            >
              <Sparkles size={10} /> {newCount} new
            </button>
          )}
          {[...data.channels]
            .sort((a, b) => {
              if (a.ok !== b.ok) return a.ok ? -1 : 1;
              return (b.quality?.score ?? 0) - (a.quality?.score ?? 0);
            })
            .map((ch) => {
              const qp = qualityPill(ch.quality?.score);
              const sig = ch.quality?.signals;
              const tip = ch.ok
                ? sig
                  ? `@${ch.handle} · quality ${ch.quality?.score}/100 · recent ${sig.recent_pct}% · dupes ${sig.dupe_pct}% · median ${sig.median_text_len} chars · ${sig.posts_per_day}/day`
                  : `@${ch.handle}`
                : `@${ch.handle} unreachable`;
              return (
                <button
                  key={ch.handle}
                  onClick={() => setActiveChannel(ch.handle)}
                  disabled={!ch.ok}
                  className={`text-mini font-mono px-2 py-1 rounded border transition-colors inline-flex items-center gap-1.5 ${
                    activeChannel === ch.handle
                      ? 'border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300'
                      : ch.ok
                        ? 'border-slate-300 dark:border-line-1 text-muted hover:border-sky-500/40'
                        : 'border-line-1 text-slate-400 cursor-not-allowed opacity-50'
                  }`}
                  title={tip}
                >
                  {ch.name} <span className="opacity-60">· {ch.count}</span>
                  {ch.ok && ch.quality && (
                    <span className={`text-micro px-1 rounded border ${qp.cls}`}>q{qp.label}</span>
                  )}
                </button>
              );
            })}
        </div>
      )}

      {data && data.warnings && data.warnings.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {data.warnings.map((w, i) => (
            <span
              key={i}
              className="text-micro font-mono px-1.5 py-0.5 rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300"
              title={w}
            >
              {w.replace('could not fetch telegram.me/s/', '! ')}
            </span>
          ))}
        </div>
      )}

      {visible.length > 0 && (
        <ul className="space-y-2">
          {visible.map(({ it, matches }) => {
            const hasMatch = matches.length > 0;
            return (
              <li
                key={it.permalink}
                className={`rounded border p-2.5 ${
                  hasMatch ? 'border-amber-500/40 bg-amber-500/5' : 'border-line-1 bg-slate-50 dark:bg-input-200'
                }`}
              >
                <div className="flex flex-wrap items-baseline gap-2 mb-1">
                  <a
                    href={sanitizeUrl(it.permalink) || undefined}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-display font-semibold text-sm text-heading hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 transition-colors"
                    title={it.channel_blurb}
                  >
                    {it.channel_name}
                    <ExternalLink size={10} className="opacity-50" />
                  </a>
                  <span
                    className={`text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border ${TG_TOPIC_PILL[it.channel_topic]}`}
                  >
                    {it.channel_topic}
                  </span>
                  <span className="text-micro font-mono text-muted">{formatRelativeTime(it.datetime)}</span>
                  {it.views && <span className="text-micro font-mono text-muted">{it.views} views</span>}
                  {hasMatch && (
                    <span className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/40 sm:ml-auto">
                      watch: {matches.join(', ')}
                    </span>
                  )}
                </div>
                <p className="text-meta font-mono text-body leading-relaxed whitespace-pre-wrap break-words">
                  {highlightTelegramText(it.text, watchlist)}
                </p>
                <PostSummary text={postSummaries.get(it.permalink)} />
              </li>
            );
          })}
        </ul>
      )}

      {data && filteredItems.length === 0 && !loading && !error && (
        <p className="text-sm font-mono text-muted">No messages from the selected channel.</p>
      )}

      {matchedItems.length > 10 && (
        <div className="mt-3 flex items-center justify-between text-mini font-mono text-muted">
          <button onClick={() => setExpanded((v) => !v)} className="text-brand-600 dark:text-brand-400 hover:underline">
            {expanded ? 'Show fewer' : `Show all ${matchedItems.length}`}
          </button>
          <Link
            to="/threatintel/telegram"
            className="hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1"
          >
            full Telegram catalogue <ExternalLink size={10} />
          </Link>
        </div>
      )}
    </section>
  );
}
