import { useState, useMemo, useEffect, useCallback, useRef } from 'react';
import {
  Rss,
  ExternalLink,
  ShieldAlert,
  Newspaper,
  Building2,
  Bug,
  Skull,
  FileSearch,
  AlertTriangle,
  RefreshCw,
  Clock,
  Search,
  Filter,
  X,
} from 'lucide-react';
import type { Actor, FeedItem } from '../types';
import { ACTORS } from '../data/actors';
import { cssVar } from '../lib';
import { AiSummaryCard } from '../../../components/intel/AiSummaryCard';
import { unwrapBingNewsLink } from '../../../services/rssService';
import { PostAnalysisButton } from '../../../components/threatintel/PostAnalysisButton';

interface Props {
  feed: FeedItem[];
  actors: Actor[];
  onOpen: (a: Actor) => void;
}

const CATEGORIES = [
  { key: 'all', label: 'All', icon: Rss },
  { key: 'vendor', label: 'Vendor', icon: ShieldAlert },
  { key: 'gov', label: 'Government', icon: Building2 },
  { key: 'news', label: 'News', icon: Newspaper },
  { key: 'cve', label: 'CVE', icon: Bug },
  { key: 'ransomware', label: 'Ransomware', icon: Skull },
  { key: 'research', label: 'Research', icon: FileSearch },
  { key: 'alert', label: 'Alert', icon: AlertTriangle },
] as const;

const CATEGORY_COLORS: Record<string, string> = {
  vendor: '#5b8def',
  gov: '#4ec9d4',
  news: cssVar('--text-secondary') || '#94a3b8',
  cve: '#e2b15c',
  ransomware: '#f56565',
  research: '#a78bfa',
  alert: '#ef4444',
};

const CATEGORY_ICONS: Record<string, typeof ShieldAlert> = {
  vendor: ShieldAlert,
  gov: Building2,
  news: Newspaper,
  cve: Bug,
  ransomware: Skull,
  research: FileSearch,
  alert: AlertTriangle,
};

const RSS_SOURCES = [
  // ── Vendor Research ──
  { url: 'https://research.checkpoint.com/feed/', name: 'Check Point Research', category: 'vendor' as const },
  { url: 'https://blog.checkpoint.com/feed/', name: 'Check Point Blog', category: 'vendor' as const },
  { url: 'https://www.crowdstrike.com/blog/feed/', name: 'CrowdStrike Blog', category: 'vendor' as const },
  { url: 'https://unit42.paloaltonetworks.com/feed/', name: 'Unit 42 (Palo Alto)', category: 'vendor' as const },
  { url: 'https://www.welivesecurity.com/feed/', name: 'WeLiveSecurity (ESET)', category: 'vendor' as const },
  { url: 'https://www.sentinelone.com/blog/feed/', name: 'SentinelOne Labs', category: 'vendor' as const },
  {
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    name: 'Microsoft Security Blog',
    category: 'vendor' as const,
  },
  { url: 'https://securelist.com/feed/', name: 'SecureList (Kaspersky)', category: 'vendor' as const },

  // ── News & Investigation ──
  // BleepingComputer 403s datacenter egress. Mirrored via Bing News — was a
  // Google News mirror, but news.google.com 503s Worker egress, and the URL
  // here must match the /api/v1/argus/rss allowlist in worker/argus-feed.ts or
  // the proxy rejects this source outright.
  {
    url: 'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
    name: 'BleepingComputer',
    category: 'news' as const,
  },
  { url: 'https://www.darkreading.com/feeds/rss.xml', name: 'Dark Reading', category: 'news' as const },
  { url: 'https://krebsonsecurity.com/feed/', name: 'Krebs on Security', category: 'news' as const },
  { url: 'https://feeds.feedburner.com/TheHackersNews', name: 'The Hacker News', category: 'news' as const },
  { url: 'https://therecord.media/feed', name: 'The Record', category: 'news' as const },
  { url: 'https://www.securityweek.com/feed/', name: 'SecurityWeek', category: 'news' as const },

  // ── Government / CERTs ──
  { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', name: 'CISA Advisories', category: 'gov' as const },
  { url: 'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml', name: 'NCSC UK', category: 'gov' as const },
];

function matchActors(text: string): string[] {
  const result: string[] = [];
  for (const actor of ACTORS) {
    const keywords = [
      actor.name.toLowerCase(),
      actor.apt?.toLowerCase() ?? '',
      ...actor.aka.map((a) => a.toLowerCase()),
    ];
    if (keywords.some((kw) => kw && text.includes(kw))) result.push(actor.id);
  }
  return result;
}

function parseRSS(xml: string, sourceName: string, sourceCategory: FeedItem['category']): FeedItem[] {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const items: FeedItem[] = [];

  // One malformed date must not throw (RangeError) and silently drop the
  // whole source — fall back to today for unparseable timestamps.
  const safeDate = (raw: string): string => {
    if (raw) {
      const ts = Date.parse(raw);
      if (Number.isFinite(ts)) return new Date(ts).toISOString().split('T')[0]!;
    }
    return new Date().toISOString().split('T')[0]!;
  };

  // RSS 2.0
  for (const item of doc.querySelectorAll('item')) {
    const title = item.querySelector('title')?.textContent?.trim() || '';
    // One of the sources is a Bing News mirror (the origin 403s datacenter
    // egress), so links arrive click-wrapped — resolve to the publisher.
    const link = unwrapBingNewsLink(item.querySelector('link')?.textContent?.trim() || '');
    const pubDate = item.querySelector('pubDate')?.textContent?.trim() || '';
    const description = item.querySelector('description')?.textContent?.trim() || '';
    if (!title || !link) continue;

    let category = sourceCategory;
    const text = (title + ' ' + description).toLowerCase();
    if (text.includes('cve-') || text.includes('vulnerability')) category = 'cve';
    else if (text.includes('ransomware') || text.includes('ransom')) category = 'ransomware';
    else if (text.includes('advisory') || text.includes('cisa') || text.includes('cert')) category = 'gov';

    const relatedActors = matchActors(text);
    items.push({
      id: `live-${sourceName.replace(/\s/g, '-').toLowerCase()}-${items.length}`,
      title,
      source: sourceName,
      url: link,
      published: safeDate(pubDate ?? ''),
      category,
      related_actors: relatedActors.length > 0 ? relatedActors : undefined,
    });
  }

  // Atom
  for (const entry of doc.querySelectorAll('entry')) {
    const title = entry.querySelector('title')?.textContent?.trim() || '';
    const link = entry.querySelector('link')?.getAttribute('href') || '';
    const updated = entry.querySelector('updated')?.textContent?.trim() || '';
    if (!title || !link) continue;

    const relatedActors = matchActors(title.toLowerCase());
    items.push({
      id: `live-${sourceName.replace(/\s/g, '-').toLowerCase()}-a-${items.length}`,
      title,
      source: sourceName,
      url: link,
      published: safeDate(updated ?? ''),
      category: sourceCategory,
      related_actors: relatedActors.length > 0 ? relatedActors : undefined,
    });
  }

  return items;
}

export function FeedView({ feed, actors }: Props) {
  const [catFilter, setCatFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string | null>(null);
  const [dateRange, setDateRange] = useState<'all' | '24h' | '7d' | '30d'>('all');
  const [sortBy, setSortBy] = useState<'date' | 'source'>('date');
  const [showFilters, setShowFilters] = useState(false);
  const [liveFeed, setLiveFeed] = useState<FeedItem[]>([]);
  const [liveStatus, setLiveStatus] = useState<'idle' | 'loading' | 'live' | 'error'>('idle');
  const [lastFetch, setLastFetch] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchLiveFeeds = useCallback(async () => {
    setLiveStatus('loading');
    try {
      const PROXY = '/api/v1/argus/rss?url=';
      const results: FeedItem[] = [];
      const fetches = RSS_SOURCES.map(async (source) => {
        try {
          const res = await fetch(`${PROXY}${encodeURIComponent(source.url)}`, { signal: AbortSignal.timeout(10000) });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return parseRSS(await res.text(), source.name, source.category);
        } catch {
          return [];
        }
      });
      const all = await Promise.allSettled(fetches);
      for (const r of all) {
        if (r.status === 'fulfilled') results.push(...r.value);
      }
      const seen = new Set<string>();
      const deduped = results.filter((item) => {
        const k = item.title.toLowerCase().trim();
        return seen.has(k) ? false : (seen.add(k), true);
      });
      deduped.sort((a, b) => b.published.localeCompare(a.published));
      setLiveFeed(deduped);
      setLiveStatus('live');
      setLastFetch(new Date());
    } catch {
      setLiveStatus('error');
    }
  }, []);

  useEffect(() => {
    fetchLiveFeeds();
    intervalRef.current = setInterval(fetchLiveFeeds, 5 * 60 * 1000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchLiveFeeds]);

  const allFeed = useMemo(() => {
    const seen = new Set<string>();
    return [...liveFeed, ...feed]
      .filter((item) => {
        const k = item.title.toLowerCase().trim();
        return seen.has(k) ? false : (seen.add(k), true);
      })
      .sort((a, b) => b.published.localeCompare(a.published));
  }, [liveFeed, feed]);

  const sources = useMemo(() => {
    const s = new Set<string>();
    allFeed.forEach((f) => s.add(f.source));
    return [...s].sort();
  }, [allFeed]);

  const filtered = useMemo(() => {
    let items = allFeed;
    if (catFilter !== 'all') items = items.filter((f) => f.category === catFilter);
    if (sourceFilter) items = items.filter((f) => f.source === sourceFilter);
    if (dateRange !== 'all') {
      const now = new Date();
      const cutoff = new Date();
      if (dateRange === '24h') cutoff.setDate(now.getDate() - 1);
      else if (dateRange === '7d') cutoff.setDate(now.getDate() - 7);
      else if (dateRange === '30d') cutoff.setDate(now.getDate() - 30);
      items = items.filter((f) => new Date(f.published) >= cutoff);
    }
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.source.toLowerCase().includes(q) ||
          f.related_actors?.some((id) => id.includes(q))
      );
    }
    if (sortBy === 'source') items = [...items].sort((a, b) => a.source.localeCompare(b.source));
    return items;
  }, [allFeed, catFilter, sourceFilter, dateRange, search, sortBy]);

  return (
    <div className="absolute inset-0 flex flex-col">
      <div className="shrink-0 border-b p-4" style={{ borderColor: 'var(--edge)' }}>
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Rss size={18} className="text-rose-600 dark:text-rose-400" />
              <h1 className="text-xl font-bold tracking-tight text-heading">Live Feed</h1>
              {liveStatus === 'live' && (
                <span className="flex items-center gap-1.5 text-micro font-mono text-emerald-500">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" /> LIVE
                </span>
              )}
              {liveStatus === 'loading' && (
                <span className="flex items-center gap-1.5 text-micro font-mono text-amber-500">
                  <RefreshCw size={10} className="animate-spin" /> Fetching…
                </span>
              )}
            </div>
            <div className="flex items-center gap-3">
              {lastFetch && (
                <span className="text-micro font-mono text-muted flex items-center gap-1">
                  <Clock size={10} /> {lastFetch.toLocaleTimeString()}
                </span>
              )}
              <button
                onClick={fetchLiveFeeds}
                disabled={liveStatus === 'loading'}
                className="flex items-center gap-1.5 px-2 py-1 rounded-md text-mini font-medium border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors disabled:opacity-50"
              >
                <RefreshCw size={11} className={liveStatus === 'loading' ? 'animate-spin' : ''} /> Refresh
              </button>
              <span className="text-mini font-mono text-muted">{filtered.length} items</span>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex gap-1">
              {CATEGORIES.map((c) => {
                const Icon = c.icon;
                return (
                  <button
                    key={c.key}
                    onClick={() => setCatFilter(c.key)}
                    data-active={catFilter === c.key}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-mini font-medium transition-colors border"
                    style={
                      catFilter === c.key
                        ? {
                            background: 'rgba(91,141,239,0.12)',
                            color: 'var(--accent-blue)',
                            borderColor: 'rgba(91,141,239,0.35)',
                          }
                        : { background: 'var(--ink-700)', color: 'var(--text-secondary)', borderColor: 'var(--edge)' }
                    }
                  >
                    <Icon size={11} />
                    {c.label}
                  </button>
                );
              })}
            </div>
            <div className="flex items-center gap-2 ml-auto">
              <div className="relative">
                <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search titles, CVEs, actors…"
                  className="w-56 h-7 pl-7 pr-2.5 rounded-md text-meta text-muted placeholder:text-muted dark:placeholder:text-muted focus:outline-none transition-colors"
                  style={{ background: 'var(--ink-700)', border: '1px solid var(--edge)' }}
                />
              </div>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center gap-1.5 px-2 py-1 rounded-md text-mini font-medium border transition-colors"
                style={{
                  borderColor: showFilters ? 'rgba(91,141,239,0.4)' : 'var(--edge)',
                  color: showFilters ? 'var(--accent-blue)' : 'var(--text-secondary)',
                  background: showFilters ? 'rgba(91,141,239,0.08)' : 'var(--ink-700)',
                }}
              >
                <Filter size={11} /> Filters
                {(sourceFilter || dateRange !== 'all') && <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />}
              </button>
            </div>
          </div>

          {showFilters && (
            <div
              className="mt-3 pt-3 border-t flex items-center gap-3 flex-wrap"
              style={{ borderColor: 'var(--edge)' }}
            >
              <div className="flex items-center gap-2">
                <span className="text-micro font-mono uppercase tracking-wider text-muted">Source</span>
                <select
                  value={sourceFilter ?? ''}
                  onChange={(e) => setSourceFilter(e.target.value || null)}
                  className="h-6 px-2 rounded text-mini text-muted border border-line-1 bg-surface-100 outline-none"
                >
                  <option value="">All sources</option>
                  {sources.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-micro font-mono uppercase tracking-wider text-muted">Date</span>
                {(['all', '24h', '7d', '30d'] as const).map((d) => (
                  <button
                    key={d}
                    onClick={() => setDateRange(d)}
                    className="px-2 py-0.5 rounded text-micro font-mono border transition-colors"
                    style={
                      dateRange === d
                        ? {
                            background: 'rgba(91,141,239,0.12)',
                            color: 'var(--accent-blue)',
                            borderColor: 'rgba(91,141,239,0.4)',
                          }
                        : { background: 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--edge)' }
                    }
                  >
                    {d === 'all' ? 'All' : d}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-micro font-mono uppercase tracking-wider text-muted">Sort</span>
                {(['date', 'source'] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSortBy(s)}
                    className="px-2 py-0.5 rounded text-micro font-mono border capitalize transition-colors"
                    style={
                      sortBy === s
                        ? {
                            background: 'rgba(91,141,239,0.12)',
                            color: 'var(--accent-blue)',
                            borderColor: 'rgba(91,141,239,0.4)',
                          }
                        : { background: 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--edge)' }
                    }
                  >
                    {s}
                  </button>
                ))}
              </div>
              {(sourceFilter || dateRange !== 'all') && (
                <button
                  onClick={() => {
                    setSourceFilter(null);
                    setDateRange('all');
                  }}
                  className="flex items-center gap-1 text-micro text-rose-500 hover:text-rose-600 transition-colors"
                >
                  <X size={10} /> Clear
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto">
          {/* AI summary of the visible feed cut. Public surface so every
              visitor gets the analyst take on the prioritised intel items. */}
          {filtered.length > 0 && (
            <AiSummaryCard
              surface="ARGUS Live Feed"
              items={filtered.slice(0, 30).map((f) => ({
                title: f.title,
                body: `${f.category} · ${f.source} · ${f.published}`,
                source: f.source,
              }))}
              requireAdmin={false}
              className="border-b"
            />
          )}
          <div className="divide-y divide-edge">
            {filtered.length === 0 && (
              <div className="py-12 text-center text-muted text-sm">
                {liveStatus === 'loading' ? (
                  <div className="flex items-center justify-center gap-2">
                    <RefreshCw size={14} className="animate-spin" /> Fetching live feeds…
                  </div>
                ) : (
                  'No items match your filter.'
                )}
              </div>
            )}
            {filtered.map((f) => {
              const color = CATEGORY_COLORS[f.category] ?? '#888';
              const Icon = CATEGORY_ICONS[f.category] ?? ShieldAlert;
              const related = f.related_actors?.map((id) => actors.find((a) => a.id === id)).filter(Boolean) as
                Actor[] | undefined;
              return (
                <article
                  key={f.id}
                  className="px-4 py-3.5 hover:bg-surface-200 dark:hover:bg-surface-300 transition-all duration-200"
                >
                  <div className="flex items-start gap-3">
                    <span
                      className="mt-0.5 h-6 w-6 rounded-md flex items-center justify-center shrink-0"
                      style={{ background: `${color}18`, color }}
                    >
                      <Icon size={12} />
                    </span>
                    <div className="flex-1 min-w-0">
                      <a
                        href={f.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1.5 group"
                      >
                        <span className="text-tool text-muted group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors leading-snug">
                          {f.title}
                        </span>
                        <ExternalLink
                          size={10}
                          className="text-muted opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                        />
                      </a>
                      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                        <span className="text-[10.5px] font-mono text-muted">{f.source}</span>
                        <span className="text-micro text-muted">·</span>
                        <span className="text-[10.5px] font-mono text-muted">{f.published}</span>
                        <span
                          className="text-micro px-1.5 py-0.5 rounded-full border font-mono"
                          style={{ borderColor: `${color}33`, color, background: `${color}0d` }}
                        >
                          {f.category}
                        </span>
                        <PostAnalysisButton
                          title={f.title}
                          description={`${f.category} from ${f.source} (${f.published})`}
                          source={f.source}
                          link={f.url}
                          compact
                        />
                      </div>
                    </div>
                  </div>
                  {related && related.length > 0 && (
                    <div className="flex gap-1.5 mt-2 ml-9">
                      {related.map((a) => (
                        <span
                          key={a.id}
                          className="text-micro px-1.5 py-0.5 rounded font-mono"
                          style={{
                            background: 'var(--ink-700)',
                            color: 'var(--text-tertiary)',
                            border: '1px solid var(--edge)',
                          }}
                        >
                          {a.name}
                        </span>
                      ))}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
