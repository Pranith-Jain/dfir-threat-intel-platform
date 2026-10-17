import { useCallback, useEffect, useRef, useState } from 'react';
import { Sparkles, RefreshCw, Loader2 } from 'lucide-react';
import { adminAuthHeaders, readAdminToken } from '../../lib/admin-token';
import { ShareBar } from './ShareBar';
import { errMessage } from '../../lib/log';

/**
 * <AiSummaryCard> - AI-generated operational summary for a feed surface.
 *
 * Posts the visible items to /api/v1/ai-summary and renders the
 * analyst-grade summary. Cached per (surface, date) on the server so
 * repeated page loads are instant.
 *
 * Usage:
 *   <AiSummaryCard
 *     surface="CTI Writeups"
 *     items={writeups.map(w => ({ title: w.title, body: w.description ?? '', source: w.source }))}
 *   />
 */

export interface AiSummaryCardProps {
  /** Surface name shown in the card header + sent to the API. */
  surface: string;
  /** Items to summarize. title is required; body and source are optional. */
  items: Array<{ title: string; body?: string; source?: string }>;
  /** Override the day key (default: today's ISO date). */
  dayKey?: string;
  /** Extra CSS classes on the outer wrapper. */
  className?: string;
  /** API endpoint to POST to. Default: the admin-gated feed summary. */
  endpoint?: string;
  /** Require an admin token to render + fetch. Default true (feed surfaces). */
  requireAdmin?: boolean;
  /** Auto-fetch on mount. Default false; set true to pre-generate on load. */
  autoFetch?: boolean;
  /** Extra fields merged into the POST body (e.g. `{ q }` for the omnibox). */
  extraBody?: Record<string, unknown>;
}

interface SummaryResponse {
  summary: string;
  tweet: string;
  linkedin?: string;
  modelUsed: string;
  itemCount: number;
}

function ShareRow({
  tweet,
  summary,
  linkedin,
  surface,
}: {
  tweet: string;
  summary: string;
  linkedin?: string;
  surface: string;
}) {
  const pageUrl = typeof window !== 'undefined' ? window.location.href : '';
  const shareText = tweet || summary.split('\n')[0] || `AI threat summary: ${surface}`;
  return (
    <div className="mt-3 pt-3 border-t border-line-1 dark:border-white/8">
      <ShareBar shareText={shareText} linkedinText={linkedin} url={pageUrl} size="sm" label="Share:" xPrefix="🚨 " />
    </div>
  );
}

export function AiSummaryCard({
  surface,
  items,
  dayKey,
  className,
  endpoint = '/api/v1/ai-summary',
  requireAdmin = true,
  autoFetch = false,
  extraBody,
}: AiSummaryCardProps): JSX.Element | null {
  const [data, setData] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(true);

  const date = dayKey ?? new Date().toISOString().slice(0, 10);

  // The default endpoint (/api/v1/ai-summary) is admin-gated, so a public
  // visitor would only ever get a 401 - gate the UI on the token so the card
  // stays silent. The omnibox passes requireAdmin={false} to use its PUBLIC
  // same-origin endpoint, where the card renders for everyone.
  const allowed = requireAdmin ? readAdminToken() !== null : true;

  // Inflight request - cancelled on unmount + before a new fetch, so a
  // fast double-click on "Generate" or a hot-reload doesn't leave a
  // pending POST in flight that could race a later one. Also bounds the
  // request with a 35s timeout — the server allows the full provider
  // fallback chain (28s) plus a Workers-AI recovery pass, so a 20s abort
  // used to kill the request right before the fallback replied.
  const inflightRef = useRef<AbortController | null>(null);

  const fetchSummary = useCallback(async () => {
    if (items.length === 0) return;
    // Cancel any in-flight request before kicking off a new one.
    if (inflightRef.current) inflightRef.current.abort();
    const ctrl = new AbortController();
    inflightRef.current = ctrl;
    const timer = setTimeout(() => ctrl.abort(), 35_000);
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { ...(requireAdmin ? adminAuthHeaders() : {}), 'content-type': 'application/json' },
        body: JSON.stringify({
          surface,
          date,
          items: items.map((it) => ({
            title: it.title,
            body: it.body ?? '',
            source: it.source,
          })),
          ...extraBody,
        }),
        signal: ctrl.signal,
      });
      if (!res.ok) {
        if (res.status === 503) {
          setError('AI summary temporarily unavailable.');
          return;
        }
        const body = await res.json().catch(() => null);
        const detail = body?.message ?? body?.issues?.join('; ') ?? '';
        throw new Error(`HTTP ${res.status}${detail ? ': ' + detail : ''}`);
      }
      const json = (await res.json()) as SummaryResponse;
      if (ctrl.signal.aborted) return;
      setData(json);
    } catch (err) {
      if (ctrl.signal.aborted) return;
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setError(errMessage(err, 'Failed to load summary.'));
    } finally {
      clearTimeout(timer);
      if (inflightRef.current === ctrl) inflightRef.current = null;
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, [surface, date, items, endpoint, requireAdmin, extraBody]);

  // Abort any in-flight request on unmount so the POST is cancelled, not
  // silently abandoned (saves a worker roundtrip + closes a leak where a
  // late .then() could call setState on an unmounted component).
  useEffect(() => {
    return () => {
      inflightRef.current?.abort();
      inflightRef.current = null;
    };
  }, []);

  // Auto-fetch on mount when enabled + allowed + items are present. Opt-in
  // surfaces (autoFetch=false, e.g. the omnibox) fetch only on the button.
  useEffect(() => {
    if (autoFetch && allowed && items.length > 0 && !data && !loading && !error) {
      fetchSummary();
    }
  }, [autoFetch, allowed, items.length, data, loading, error, fetchSummary]);

  // Don't render when not allowed (admin-gated + no token) or with no items.
  if (!allowed || items.length === 0) return null;

  return (
    <div
      // Prominent card — visible above the feed list in both themes. Uses the
      // canonical `surface-card` treatment (8px radius, hairline border, e1
      // shadow, flat surface) so it reads as part of the design system rather
      // than a decorated one-off.
      className={`relative surface-card overflow-hidden ${className ?? ''}`}
    >
      {/* Header */}
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-surface-200 dark:hover:bg-wash transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center justify-center w-6 h-6 rounded-lg bg-brand-500/10 dark:bg-brand-400/15">
            <Sparkles size={14} className="text-brand-600 dark:text-brand-400" />
          </span>
          <span className="text-sm font-display font-bold text-heading">AI Summary - {surface}</span>
          {data && (
            <span className="text-micro font-mono text-muted ml-1">
              {data.itemCount} items · {data.modelUsed.split(':').pop()}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {!loading && !data && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                fetchSummary();
              }}
              className="text-mini font-mono text-brand-600 dark:text-brand-400 hover:underline"
            >
              Generate
            </button>
          )}
          <span className="text-micro text-muted">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {/* Body */}
      {expanded && (
        <div className="px-4 pb-4">
          {loading && (
            <div className="flex items-center gap-2 py-4 text-sm text-muted">
              <Loader2 size={14} className="animate-spin" />
              Generating AI summary…
            </div>
          )}

          {error && (
            <div className="flex items-center justify-between py-3">
              <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p>
              <button
                type="button"
                onClick={fetchSummary}
                className="flex items-center gap-1.5 text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
              >
                <RefreshCw size={12} /> Retry
              </button>
            </div>
          )}

          {data && (
            <div>
              <div className="prose prose-sm dark:prose-invert max-w-none text-body leading-relaxed whitespace-pre-wrap">
                {data.summary.split('\n').map((line, i) => {
                  const parts = line.split(/(\*\*[^*]+\*\*)/g);
                  return (
                    <p key={i} className={line.startsWith('- ') || line.startsWith('• ') ? 'ml-4' : ''}>
                      {parts.map((part, j) =>
                        part.startsWith('**') && part.endsWith('**') ? (
                          <strong key={j} className="text-heading">
                            {part.slice(2, -2)}
                          </strong>
                        ) : (
                          <span key={j}>{part}</span>
                        )
                      )}
                    </p>
                  );
                })}
              </div>
              <ShareRow tweet={data.tweet} summary={data.summary} linkedin={data.linkedin} surface={surface} />
            </div>
          )}

          {!loading && !error && !data && (
            <p className="text-sm text-muted py-2 italic">
              Click "Generate" to create an AI-powered summary of today's {surface.toLowerCase()}.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
