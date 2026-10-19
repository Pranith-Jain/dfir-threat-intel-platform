import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link } from 'react-router-dom';
import { DataPageLayout, useInsideDataPageLayout } from '../../components/DataPageLayout';
import {
  RefreshCw,
  ExternalLink,
  MessageSquare,
  Repeat,
  Heart,
  BarChart3,
  Search,
  Twitter,
  ShieldAlert,
  Radio,
} from 'lucide-react';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';
import { XClaimsPanel } from '../../components/threatintel/XClaimsPanel';

interface LiveTweet {
  id: string;
  url: string;
  text: string;
  author: { screen_name: string; name: string; avatar_url?: string };
  created_at: string;
  created_at_ms: number;
  replies: number;
  retweets: number;
  likes: number;
  views: number;
  media: Array<{ type: 'photo' | 'video' | 'gif'; url: string }>;
  tweetfeed_tags: string[];
  ioc_types: string[];
}

interface XLiveResponse {
  generated_at: string;
  source: string;
  since_hours: number;
  total_status_ids_seen: number;
  enriched_count: number;
  enrichment_failures?: number;
  stale?: boolean;
  items: LiveTweet[];
  /** Ransomware + breach claims extracted from the enriched tweet text. */
  claims?: {
    ransomware: Array<{ victim: string; group: string; discovered: string; source_url: string; country?: string }>;
    breach: Array<{ text: string; discovered: string; source_url: string; handle: string }>;
  };
}

function formatTimeAgo(iso: string | number): string {
  const t = typeof iso === 'number' ? iso : Date.parse(iso);
  if (!Number.isFinite(t) || t === 0) return '';
  const diff = Math.max(0, Date.now() - t);
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function compactNumber(n?: number): string {
  if (!n || n < 1) return '';
  if (n < 1000) return String(n);
  if (n < 1_000_000) {
    const v = n / 1000;
    if (v >= 999.5) return `${(n / 1_000_000).toFixed(1)}M`;
    return `${v.toFixed(n < 10_000 ? 1 : 0)}k`;
  }
  return `${(n / 1_000_000).toFixed(1)}M`;
}

const IOC_TYPE_COLOR: Record<string, string> = {
  url: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  domain: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  ip: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  sha256: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  md5: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  sha1: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
};

export default function XLive(): JSX.Element {
  const insideLayout = useInsideDataPageLayout();
  const [data, setData] = useState<XLiveResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [sinceHours, setSinceHours] = useState<number>(() => {
    try {
      return Number(localStorage.getItem('x-live.since-hours') ?? '24') || 24;
    } catch (_catchErr) {
      console.error('XLive failed:', errMessage(_catchErr));
      return 24;
    }
  });
  const [activeHandle, setActiveHandle] = useState<string | null>(null);
  const [category, setCategory] = useState<'all' | 'ioc'>('all');

  const load = (hours: number) => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch(`/api/v1/x-live?since_hours=${hours}&limit=30`, {
      signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
    })
      .then(async (r) => {
        const body = (await r.json()) as XLiveResponse | { error: string };
        if (cancelled) return;
        if (!r.ok || 'error' in body) {
          setError('error' in body ? body.error : `HTTP ${r.status}`);
        } else {
          setData(body);
        }
      })
      .catch((e) => !cancelled && (e as { name?: string }).name !== 'AbortError' && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  };

  useEffect(() => {
    try {
      localStorage.setItem('x-live.since-hours', String(sinceHours));
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* localStorage unavailable */
    }
    return load(sinceHours);
  }, [sinceHours]);

  const handleCounts = useMemo(() => {
    if (!data) return [] as Array<{ handle: string; count: number }>;
    const m = new Map<string, number>();
    for (const t of data.items) {
      const h = t.author.screen_name.toLowerCase();
      m.set(h, (m.get(h) ?? 0) + 1);
    }
    return [...m.entries()].map(([handle, count]) => ({ handle, count })).sort((a, b) => b.count - a.count);
  }, [data]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase();
    return data.items.filter((t) => {
      if (activeHandle && t.author.screen_name.toLowerCase() !== activeHandle) return false;
      // Category filter: IOC tweets carry ioc_types; 'ioc' shows only tweets
      // with extracted indicators. Ransomware/breach claims are surfaced via
      // the XClaimsPanel above the feed.
      if (category === 'ioc' && (!t.ioc_types || t.ioc_types.length === 0)) return false;
      if (!q) return true;
      return (
        t.text.toLowerCase().includes(q) ||
        t.author.screen_name.toLowerCase().includes(q) ||
        t.tweetfeed_tags.some((x) => x.toLowerCase().includes(q))
      );
    });
  }, [data, search, activeHandle, category]);

  const postSummaries = usePostSummaries({
    surface: 'X Live Cybersec',
    items: filtered.map((t) => ({
      id: t.id || `tweet-${t.created_at_ms}`,
      title: (t.text || '(no text)').slice(0, 120),
      body: t.text ?? '',
      source: t.author?.name ?? '',
    })),
  });

  const headerExtra = (
    <>
      <section className="flex flex-wrap items-center gap-2">
        <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
          live · free
        </span>
        <label className="inline-flex items-center gap-1 text-mini font-mono text-muted">
          window:
          <select
            value={sinceHours}
            onChange={(e) => setSinceHours(Number(e.target.value))}
            className="border border-line-2 bg-surface-100 px-1.5 py-0.5 text-mini font-mono rounded focus:outline-none focus:border-rose-500"
          >
            {[6, 12, 24, 48, 72, 168].map((h) => (
              <option key={h} value={h}>
                {h < 24 ? `${h}h` : `${h / 24}d`}
              </option>
            ))}
          </select>
        </label>
        {/* Category tabs: All / IOC tweets. Ransomware + Breach claims are
            surfaced via the XClaimsPanel above the feed (parsed from
            FalconFeeds/@DailyDarkWeb). */}
        <div className="flex items-center gap-1">
          {(
            [
              { id: 'all', label: 'All tweets', icon: Radio },
              { id: 'ioc', label: 'IOC only', icon: ShieldAlert },
            ] as const
          ).map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setCategory(c.id)}
              className={`inline-flex items-center gap-1 text-mini font-mono px-2 py-1 rounded border transition-colors ${
                category === c.id
                  ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                  : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
              }`}
            >
              <c.icon size={11} /> {c.label}
            </button>
          ))}
        </div>
        <div className="relative flex-1 min-w-[200px]">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="filter text, handle, or tag…"
            className="w-full pl-7 pr-2 py-1 rounded border border-line-2 bg-surface-200 text-xs font-mono focus:outline-none focus:border-rose-500"
          />
        </div>
        <button
          type="button"
          onClick={() => load(sinceHours)}
          disabled={loading}
          className="text-xs font-mono px-2 py-1 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 disabled:opacity-50"
        >
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
        </button>
      </section>

      {handleCounts.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-3">
          <button
            type="button"
            onClick={() => setActiveHandle(null)}
            className={`text-mini font-mono px-2 py-0.5 rounded border transition-colors ${
              activeHandle === null
                ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
            }`}
          >
            all · {data?.items.length ?? 0}
          </button>
          {handleCounts.map(({ handle, count }) => (
            <button
              key={handle}
              type="button"
              onClick={() => setActiveHandle(handle === activeHandle ? null : handle)}
              className={`text-mini font-mono px-2 py-0.5 rounded border transition-colors ${
                activeHandle === handle
                  ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                  : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
              }`}
            >
              @{handle} · {count}
            </button>
          ))}
        </div>
      )}
    </>
  );

  return (
    <DataPageLayout
      backTo="/threatintel"
      hideBack={insideLayout}
      icon={<Twitter size={28} />}
      title="X live (cybersec)"
      description={
        <>
          <span className="block text-sm font-mono max-w-3xl leading-relaxed">
            Live chronological X tweets from cybersec IOC-posting accounts + extracted ransomware/breach claims from
            FalconFeeds/@DailyDarkWeb. Tweets are assembled by joining{' '}
            <a
              href="https://github.com/0xDanielLopez/TweetFeed"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              TweetFeed
            </a>{' '}
            (chronological permalink stream from ~30 monitored accounts) with{' '}
            <a
              href="https://github.com/FxEmbed/FxEmbed"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
            >
              FxEmbed
            </a>{' '}
            (API v2 per-status enrichment for full text, author, media, engagement). This is the only free path that
            delivers <em>recent</em> X content - X gates anonymous timeline access, but per-tweet embed previews stay
            open because Discord/Slack/Telegram link cards depend on them.
          </span>
          <span className="block text-mini font-mono text-muted mt-2">
            <strong>Coverage caveat:</strong> only tweets that TweetFeed surfaces (researcher-posted IOCs). Prose-only
            researcher takes won&apos;t appear here. For non-IOC chatter use{' '}
            <Link to="/threatintel/social/firehose" className="text-rose-600 dark:text-rose-400 hover:underline">
              Bluesky+Mastodon firehose
            </Link>
            . For static profile reference, see{' '}
            <Link to="/threatintel/social/firehose" className="text-rose-600 dark:text-rose-400 hover:underline">
              X profile highlights
            </Link>
            .
          </span>
        </>
      }
      headerExtra={headerExtra}
      loading={loading && !data}
      error={error}
      onRetry={() => load(sinceHours)}
    >
      {/* Extracted ransomware + breach claims from FalconFeeds/@DailyDarkWeb.
          Parsed server-side by /api/v1/x-claims — the free-text posts are
          triaged into structured victim/group/country rows. */}
      <XClaimsPanel fallback={data?.claims} />

      {!loading && data && filtered.length === 0 && (
        <p className="text-xs font-mono text-muted rounded border border-dashed border-line-2 p-4 text-center">
          {data.stale ? 'Showing cached data (upstream enrichment temporarily unavailable). ' : ''}
          {data.items.length === 0
            ? data.total_status_ids_seen > 0
              ? `TweetFeed has ${data.total_status_ids_seen} status IDs but enrichment (fxtwitter) couldn't resolve them - upstream may be rate-limited or temporary unavailable.`
              : `No status IDs in the last ${sinceHours}h - TweetFeed may be quiet or upstream rate-limited.`
            : 'No tweets match the current filter.'}
        </p>
      )}

      {filtered.length > 0 && (
        <>
          <PostAnalysisButton
            title="X Live Cybersec Digest"
            description="AI-powered threat analysis of the current feed."
            source="xlive"
          />
          <AiSummaryCard
            surface="X Live Cybersec"
            items={filtered.slice(0, 30).map((t) => ({
              title: (t.text || '(no text)').slice(0, 120),
              body: t.text ?? '',
              source: t.author?.name ?? '',
            }))}
            requireAdmin={false}
          />
          <ul className="space-y-2">
            {filtered.map((t) => (
              <li key={t.id} className="surface-card p-3">
                <div className="flex items-start gap-3">
                  {t.author.avatar_url && (
                    <img
                      loading="lazy"
                      src={t.author.avatar_url}
                      alt={t.author.name}
                      className="w-9 h-9 rounded-full shrink-0"
                    />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-2 mb-1">
                      <span className="font-display font-semibold text-sm text-heading">{t.author.name}</span>
                      <button
                        type="button"
                        onClick={() => setActiveHandle(t.author.screen_name.toLowerCase())}
                        className="text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
                        title="filter to this handle"
                      >
                        @{t.author.screen_name}
                      </button>
                      {t.ioc_types.map((iocType) => (
                        <span
                          key={iocType}
                          className={`text-micro font-mono px-1 py-0.5 rounded border ${
                            IOC_TYPE_COLOR[iocType] ?? 'border-slate-300 dark:border-line-1 text-slate-500'
                          }`}
                        >
                          {iocType}
                        </span>
                      ))}
                      <a
                        href={sanitizeUrl(t.url) || undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-auto text-micro font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-0.5 transition-colors"
                        title={t.created_at}
                      >
                        {formatTimeAgo(t.created_at_ms || t.created_at)} <ExternalLink size={9} />
                      </a>
                    </div>
                    <p className="text-sm text-heading whitespace-pre-wrap break-words">{t.text}</p>
                    <PostSummary text={postSummaries.get(String(t.id))} />
                    {t.tweetfeed_tags.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {t.tweetfeed_tags.map((tag) => (
                          <button
                            key={tag}
                            type="button"
                            onClick={() => setSearch(tag)}
                            className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline"
                          >
                            {tag}
                          </button>
                        ))}
                      </div>
                    )}
                    {t.media.length > 0 && (
                      <div className="mt-2 grid grid-cols-2 gap-1.5">
                        {t.media.slice(0, 4).map((m, i) => (
                          <a
                            key={`${t.id}-m-${i}`}
                            href={sanitizeUrl(t.url) || undefined}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="block rounded overflow-hidden border border-line-1"
                          >
                            <img
                              src={m.url}
                              alt={m.type}
                              loading="lazy"
                              width={400}
                              height={128}
                              className="w-full h-32 object-cover"
                            />
                          </a>
                        ))}
                      </div>
                    )}
                    <div className="mt-2 flex items-center gap-3 text-micro font-mono text-muted">
                      <span className="inline-flex items-center gap-0.5">
                        <MessageSquare size={10} /> {compactNumber(t.replies) || '0'}
                      </span>
                      <span className="inline-flex items-center gap-0.5">
                        <Repeat size={10} /> {compactNumber(t.retweets) || '0'}
                      </span>
                      <span className="inline-flex items-center gap-0.5">
                        <Heart size={10} /> {compactNumber(t.likes) || '0'}
                      </span>
                      {t.views > 0 && (
                        <span className="inline-flex items-center gap-0.5">
                          <BarChart3 size={10} /> {compactNumber(t.views)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      {data && (
        <p className="mt-6 text-micro font-mono text-muted text-center">
          {data.stale && <span className="text-amber-500 dark:text-amber-400">stale · </span>}
          source: TweetFeed ({data.total_status_ids_seen} status IDs seen) × fxtwitter ({data.enriched_count} enriched
          {data.enrichment_failures != null && data.enrichment_failures > 0
            ? `, ${data.enrichment_failures} failed`
            : ''}
          ) · last {sinceHours}h · refreshed {formatTimeAgo(data.generated_at)}
        </p>
      )}
    </DataPageLayout>
  );
}
