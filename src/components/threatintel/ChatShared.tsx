import { useEffect, useState } from 'react';
import { Check, Loader2 } from 'lucide-react';
import { sanitizeAiHtml } from '../../lib/sanitize-html';

/** Shared agent-investigation step types + rendering used by VeraChat + Copilot. */

export interface AgentStep {
  stepNumber: number;
  name: string;
  status: 'running' | 'done' | 'error';
  result?: string;
  duration?: number;
}

const ACCENT_STEPS = ['bg-rose-600', 'bg-brand-500', 'bg-violet-500', 'bg-amber-500', 'bg-rose-500', 'bg-emerald-500'];

export function StepIndicator({ steps, currentStep }: { steps: AgentStep[]; currentStep: number }) {
  if (steps.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5 mb-3">
      {steps.map((s, i) => {
        const isActive = s.stepNumber === currentStep && s.status === 'running';
        const isDone = s.status === 'done';
        const isError = s.status === 'error';
        return (
          <div
            key={s.stepNumber}
            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-mini font-mono transition-all ${
              isDone
                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                : isError
                  ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300'
                  : isActive
                    ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300 ring-1 ring-rose-500/50'
                    : 'bg-slate-100 text-slate-400 dark:bg-surface-300 dark:text-slate-500'
            }`}
          >
            {isDone ? (
              <Check size={10} />
            ) : isActive ? (
              <Loader2 size={10} className="animate-spin" />
            ) : (
              <span className={`w-1.5 h-1.5 rounded-full ${ACCENT_STEPS[i % ACCENT_STEPS.length]}`} />
            )}
            {s.name}
          </div>
        );
      })}
    </div>
  );
}

/** Minimal markdown renderer (shared between VeraChat + Copilot). */
// eslint-disable-next-line react-refresh/only-export-components -- shared helper
export function renderMarkdown(safeMd: string): string {
  let html = safeMd;
  // Fenced code blocks - render before other markdown to protect content
  html = html.replace(/```(\w*)\s*\n([\s\S]*?)```/g, (_match, lang, code) => {
    const trimmed = (code as string).replace(/\n$/, '');
    const escaped = (trimmed as string).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const langAttr = lang ? ` data-language="${lang}"` : '';
    return `<pre class="overflow-x-auto rounded-xl bg-surface-300 p-3 my-2"${langAttr}><code class="text-xs font-mono leading-relaxed text-heading">${escaped}</code></pre>`;
  });
  html = html
    .replace(/### (.+)/g, '<h3 class="text-base font-semibold mt-4 mb-1.5">$1</h3>')
    .replace(/## (.+)/g, '<h2 class="text-lg font-bold mt-5 mb-2">$1</h2>')
    .replace(/# (.+)/g, '<h1 class="text-xl font-bold mt-5 mb-2">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(
      /`([^`]+)`/g,
      '<code class="px-1 py-0.5 rounded bg-slate-100 dark:bg-surface-300 text-xs font-mono">$1</code>'
    )
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-sm">$1</li>')
    .replace(/^\d+\.\s(.+)$/gm, '<li class="ml-4 list-decimal text-sm">$1</li>')
    .replace(/(<li.*<\/li>\n?)+/g, function (match) {
      if (match.includes('list-decimal')) return `<ol class="space-y-1 my-1.5">${match}</ol>`;
      return `<ul class="space-y-0.5 my-1.5">${match}</ul>`;
    });
  html = html
    .split(/\n\n+/)
    .map((block) => {
      const trimmed = block.trim();
      if (!trimmed) return '';
      if (
        trimmed.startsWith('<h') ||
        trimmed.startsWith('<ul') ||
        trimmed.startsWith('<ol') ||
        trimmed.startsWith('<li')
      )
        return trimmed;
      return `<p class="text-sm leading-relaxed mb-2">${trimmed}</p>`;
    })
    .join('\n');
  return html;
}

export function ChatNarrative({ markdown }: { markdown: string }) {
  const [html, setHtml] = useState('');
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const cleaned = markdown
        .replace(/\n*```(?:report-header|action-card|json|stix)\s*\n[\s\S]*?\n```\s*/g, '')
        .replace(/\n*:::handoff\s*[\s\S]*?:::/g, '')
        .replace(/\{\s*"severity"\s*:\s*"[^"]*"\s*,\s*"[^}]*"\s*\}/g, '')
        .trim();
      const { default: DOMPurify } = await import('isomorphic-dompurify');
      const safeMd = DOMPurify.sanitize(cleaned, { ALLOWED_TAGS: [] });
      const rendered = renderMarkdown(safeMd);
      const safe = await sanitizeAiHtml(rendered);
      if (!cancelled) setHtml(safe);
    })();
    return () => {
      cancelled = true;
    };
  }, [markdown]);
  return (
    <div
      className="text-heading [&_h2]:text-base [&_h2]:font-bold [&_h2]:mt-4 [&_h2]:mb-1.5 [&_h3]:text-sm [&_h3]:font-semibold [&_h3]:mt-3 [&_h3]:mb-1 [&_p]:text-sm [&_p]:leading-relaxed [&_p]:mb-2 [&_p]:text-body [&_p]:dark:text-inverted [&_ul]:space-y-0.5 [&_ul]:my-1 [&_ol]:space-y-1 [&_ol]:my-1 [&_li]:ml-4 [&_li]:pl-1 [&_li]:text-sm [&_li]:text-body [&_li]:dark:text-inverted [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:bg-surface-300 [&_code]:dark:bg-surface-200 [&_code]:text-xs [&_code]:font-mono [&_code]:text-rose-700 [&_code]:dark:text-rose-300"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
