import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Loader2, Twitter, Heart, Repeat, MessageSquare } from 'lucide-react';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface TweetItem {
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
  items: TweetItem[];
  generated_at: string;
  total_status_ids_seen: number;
  enriched_count: number;
}

function formatTimeAgo(ms: number | string): string {
  const t = typeof ms === 'number' ? ms : Date.parse(ms);
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

/**
 * Compact embeddable panel of recent cybersec X tweets - same data as
 * /threatintel/x-live (TweetFeed × fxtwitter hybrid). Drop into any page
 * that benefits from a fresh-from-X side panel.
 */
export function XLivePanel({
  sinceHours = 24,
  limit = 10,
  title = 'X firehose (cybersec)',
  className = '',
}: {
  sinceHours?: number;
  limit?: number;
  title?: string;
  className?: string;
}): JSX.Element {
  const [items, setItems] = useState<TweetItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    fetch(`/api/v1/x-live?since_hours=${sinceHours}&limit=${limit}`, {
      signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
    })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const body = (await r.json()) as XLiveResponse;
        if (!cancelled) setItems(body.items ?? []);
      })
      .catch((e) => !cancelled && (e as { name?: string }).name !== 'AbortError' && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [sinceHours, limit]);

  return (
    <section className={`surface-card p-4 ${className}`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-display font-semibold text-sm inline-flex items-center gap-1.5">
          <Twitter size={14} className="text-brand-600 dark:text-brand-400" /> {title}
        </h3>
        <Link
          to="/threatintel/social/firehose"
          className="text-mini font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-0.5"
        >
          all <ExternalLink size={9} />
        </Link>
      </div>
      <p className="text-micro font-mono text-muted mb-3">
        TweetFeed × fxtwitter - last {sinceHours}h of researcher-posted IOC tweets · click-through to x.com
      </p>
      {loading && (
        <p className="text-xs font-mono text-muted inline-flex items-center gap-1">
          <Loader2 size={11} className="animate-spin" /> loading…
        </p>
      )}
      {error && <p className="text-xs font-mono text-rose-500">load error: {error}</p>}
      {!loading && !error && items.length === 0 && (
        <p className="text-xs font-mono text-muted">No X activity in the last {sinceHours}h.</p>
      )}
      {items.length > 0 && (
        <ul className="space-y-2">
          {items.map((t) => (
            <li key={t.id} className="rounded-xl border border-line-1 bg-surface-200 p-2.5">
              <div className="flex items-start gap-2">
                {t.author.avatar_url && (
                  <img
                    loading="lazy"
                    src={t.author.avatar_url}
                    alt={t.author.name}
                    className="w-7 h-7 rounded-full shrink-0"
                  />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-1.5 mb-0.5 flex-wrap">
                    <span className="font-display font-semibold text-meta text-heading truncate">{t.author.name}</span>
                    <span className="text-micro font-mono text-muted">@{t.author.screen_name}</span>
                    <a
                      href={sanitizeUrl(t.url)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-auto text-micro font-mono text-muted hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-0.5 transition-colors"
                      title={t.created_at}
                    >
                      {formatTimeAgo(t.created_at_ms || t.created_at)} <ExternalLink size={9} />
                    </a>
                  </div>
                  <p className="text-meta text-heading whitespace-pre-wrap break-words line-clamp-4">{t.text}</p>
                  {t.tweetfeed_tags.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {t.tweetfeed_tags.slice(0, 4).map((tag) => (
                        <span key={tag} className="text-micro font-mono text-brand-600 dark:text-brand-400">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                  {(t.likes > 0 || t.retweets > 0 || t.replies > 0) && (
                    <div className="mt-1 flex items-center gap-2 text-micro font-mono text-muted">
                      {t.replies > 0 && (
                        <span className="inline-flex items-center gap-0.5">
                          <MessageSquare size={9} /> {compactNumber(t.replies)}
                        </span>
                      )}
                      {t.retweets > 0 && (
                        <span className="inline-flex items-center gap-0.5">
                          <Repeat size={9} /> {compactNumber(t.retweets)}
                        </span>
                      )}
                      {t.likes > 0 && (
                        <span className="inline-flex items-center gap-0.5">
                          <Heart size={9} /> {compactNumber(t.likes)}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
