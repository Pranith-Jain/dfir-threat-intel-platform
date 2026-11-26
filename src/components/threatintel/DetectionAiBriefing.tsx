import { Sparkles } from 'lucide-react';
import { AiSummaryCard } from '../intel/AiSummaryCard';
import { PostAnalysisButton } from './PostAnalysisButton';

/**
 * Opt-in AI briefing for detection-reference pages.
 *
 * All surfaces here are click-triggered: nothing is fetched on page load,
 * so adding this component never spends an LLM call until an analyst asks.
 * The summary is cached per (surface, date) on the server, and `dayKey`
 * keeps that key stable when the page has its own snapshot date.
 */
export interface DetectionAiBriefingProps {
  /** Surface name shown on the summary card and used as the cache key. */
  surface: string;
  /** Short source tag sent to the threat-analysis endpoint. */
  source: string;
  /** Visible rows to summarize (capped at 50). */
  items: Array<{ title: string; body?: string; source?: string }>;
  /** Stable day key, usually the mirror's build/snapshot date. */
  dayKey?: string;
  /** Noun used in the helper line, e.g. "rules" or "techniques". */
  label?: string;
  className?: string;
}

export function DetectionAiBriefing({
  surface,
  source,
  items,
  dayKey,
  label = 'items',
  className = 'mb-4',
}: DetectionAiBriefingProps): JSX.Element | null {
  if (items.length === 0) return null;
  return (
    <div className={className}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-2 text-tool text-muted">
          <Sparkles size={13} className="text-accent-text" aria-hidden="true" />
          Opt-in AI briefing over the {items.length} {label} on this page.
        </p>
        <PostAnalysisButton
          title={`${surface} analysis`}
          description={`AI analysis of the current ${surface} data.`}
          source={source}
        />
      </div>
      <AiSummaryCard
        surface={surface}
        items={items.slice(0, 50)}
        dayKey={dayKey}
        requireAdmin={false}
        autoFetch={false}
      />
    </div>
  );
}
