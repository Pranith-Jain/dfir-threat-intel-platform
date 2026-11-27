import { ChevronDown } from 'lucide-react';

export interface FaqEntry {
  question: string;
  answer: string;
}

/**
 * Visible counterpart to FaqStructuredData. Google's FAQ rich-result guidance
 * requires the questions and answers in FAQPage JSON-LD to be visible on the
 * page; two hubs emitted the schema with no on-page Q&A at all.
 *
 * Questions are H2s: question-shaped headings match voice and LLM prompts
 * directly and give the page 2+ AEO question headings.
 */
export function FaqSection({ entries, className = '' }: { entries: FaqEntry[]; className?: string }) {
  if (!entries.length) return null;
  return (
    <details className={`group surface-card ${className}`.trim()}>
      <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
        <h2 className="font-display font-bold text-lg text-heading">Common questions</h2>
        <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
      </summary>
      <div className="px-4 sm:px-5 pb-4 sm:pb-5 space-y-4">
        {entries.map((f) => (
          <div key={f.question}>
            <h2 className="font-display text-sm font-semibold text-heading">{f.question}</h2>
            <p className="mt-1.5 text-sm text-muted leading-relaxed">{f.answer}</p>
          </div>
        ))}
      </div>
    </details>
  );
}
