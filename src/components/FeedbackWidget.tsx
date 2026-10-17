import { useEffect, useRef, useState } from 'react';
import { errMessage } from '../lib/log';

type FeedbackRating = 'useful' | 'not_useful' | 'actioned' | 'accurate' | 'inaccurate' | 'no_value';
type FeedbackTarget = 'copilot' | 'briefing' | 'pir' | 'finding' | 'ioc' | 'assessment';

interface FeedbackWidgetProps {
  targetType: FeedbackTarget;
  targetId: string;
  /** Optional - prefilled sector context */
  sector?: string;
  /** Show compact thumbs-only mode */
  compact?: boolean;
  /** Called after feedback is recorded */
  onFeedback?: (rating: FeedbackRating) => void;
}

const RATING_LABELS: Record<FeedbackRating, string> = {
  useful: 'Useful',
  not_useful: 'Not useful',
  actioned: 'Actioned',
  accurate: 'Accurate',
  inaccurate: 'Inaccurate',
  no_value: 'No value',
};

export function FeedbackWidget({ targetType, targetId, sector, compact, onFeedback }: FeedbackWidgetProps) {
  const [submitted, setSubmitted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRating, setSelectedRating] = useState<FeedbackRating | null>(null);
  const [comment, setComment] = useState('');
  const savingRef = useRef(false);
  // Abort the in-flight POST on unmount so a fast nav away from the page
  // doesn't leave a pending request that races a later feedback submit.
  const inflightRef = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      inflightRef.current?.abort();
      inflightRef.current = null;
    },
    []
  );

  async function handleSubmit(rating: FeedbackRating) {
    if (savingRef.current) return;
    savingRef.current = true;
    setSaving(true);
    setError(null);
    const ctrl = new AbortController();
    inflightRef.current = ctrl;
    const timer = setTimeout(() => ctrl.abort(), 10_000);
    try {
      const res = await fetch('/api/v1/threat-intel/feedback', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          target_type: targetType,
          target_id: targetId,
          rating,
          comment: comment || undefined,
          sector,
        }),
        signal: ctrl.signal,
      });
      if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        let errMsg = 'Failed to submit';
        try {
          const parsed = JSON.parse(errBody);
          errMsg = parsed.error ?? errMsg;
        } catch {
          /* ignore */
        }
        throw new Error(errMsg);
      }
      setSubmitted(true);
      setSelectedRating(rating);
      onFeedback?.(rating);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      clearTimeout(timer);
      if (inflightRef.current === ctrl) inflightRef.current = null;
      if (!ctrl.signal.aborted) {
        setSaving(false);
        savingRef.current = false;
      }
    }
  }

  if (submitted) {
    return (
      <span className="inline-flex items-center gap-1.5 text-mini text-emerald-600 dark:text-emerald-400">
        <svg
          className="h-3.5 w-3.5"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
        Feedback recorded{selectedRating ? ` (${RATING_LABELS[selectedRating].toLowerCase()})` : ''}
      </span>
    );
  }

  if (compact) {
    return (
      <span className="inline-flex items-center gap-1">
        <button
          type="button"
          onClick={() => handleSubmit('useful')}
          disabled={saving}
          className="p-2 sm:p-1 rounded text-muted hover:text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-950/30 transition-colors disabled:opacity-50"
          title="Useful"
        >
          <svg
            className="h-3.5 w-3.5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M14 10h4.764a2 2 0 011.789 2.894l-3.5 7A2 2 0 0115.263 21h-4.017c-.163 0-.326-.02-.485-.06L7 20m7-10V5a2 2 0 00-2-2h-.095c-.5 0-.905.405-.905.905 0 .714-.211 1.412-.608 2.006L7 11v9m7-10h-2M7 20H5a2 2 0 01-2-2v-6a2 2 0 012-2h2.5"
            />
          </svg>
        </button>
        <button
          type="button"
          onClick={() => handleSubmit('not_useful')}
          disabled={saving}
          className="p-2 sm:p-1 rounded text-muted hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition-colors disabled:opacity-50"
          title="Not useful"
        >
          <svg
            className="h-3.5 w-3.5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M10 14H5.236a2 2 0 01-1.789-2.894l3.5-7A2 2 0 018.736 3h4.018a2 2 0 01.485.06l3.76.94m-7 10v5a2 2 0 002 2h.096c.5 0 .905-.405.905-.904 0-.715.211-1.413.608-2.008L17 13V4m-7 10h2m5-10h2a2 2 0 012 2v6a2 2 0 01-2 2h-2.5"
            />
          </svg>
        </button>
        {error && <span className="text-micro text-rose-500 ml-1">{error}</span>}
      </span>
    );
  }

  const ratings: FeedbackRating[] = ['useful', 'not_useful', 'actioned', 'accurate', 'inaccurate', 'no_value'];

  return (
    <div className="flex flex-col gap-2">
      <span className="text-mini font-medium text-muted">Was this intelligence useful?</span>
      <div className="flex flex-wrap gap-1.5">
        {ratings.map((r) => (
          <button
            key={r}
            type="button"
            onClick={() => handleSubmit(r)}
            disabled={saving}
            className={`px-2.5 py-1 text-mini rounded border transition-colors disabled:opacity-50 ${
              selectedRating === r
                ? 'border-brand-500 bg-brand-500/10 text-brand-700 dark:border-brand-400 dark:bg-brand-400/10 dark:text-brand-300'
                : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50 dark:border-white/10 dark:bg-transparent dark:text-slate-300 dark:hover:border-white/20 dark:hover:bg-white/5'
            }`}
          >
            {RATING_LABELS[r]}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="Optional comment…"
          className="flex-1 text-mini px-2 py-1 rounded border border-line-1 bg-surface-100 dark:border-white/10 dark:bg-transparent dark:text-inverted placeholder:text-muted focus:outline-none focus-visible:ring-1 focus-visible:ring-brand-500"
          maxLength={500}
        />
        {saving && <span className="text-micro text-muted animate-pulse">Saving…</span>}
      </div>
      {error && <p className="text-micro text-rose-500">{error}</p>}
    </div>
  );
}
