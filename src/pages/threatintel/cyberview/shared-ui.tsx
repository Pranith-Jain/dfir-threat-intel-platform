import type { ReactNode } from 'react';
import { ExternalLink } from 'lucide-react';
import { DataPageLayout } from '../../../components/DataPageLayout';
import { sanitizeUrl } from '../../../lib/sanitize-url';
import { CyberViewNav } from './CyberViewNav';

/** One shell for all five replicated CyberView pages: shared nav + layout.
 * `bare` is used when a page is embedded as a tab in another surface. */
export function CyberViewPage({
  bare,
  icon,
  title,
  description,
  maxWidthClass = 'max-w-6xl',
  loading,
  error,
  onRetry,
  children,
}: {
  bare: boolean;
  icon: ReactNode;
  title: string;
  description: string;
  maxWidthClass?: string;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  children: ReactNode;
}): JSX.Element {
  const body = (
    <>
      <CyberViewNav />
      {children}
    </>
  );
  return bare ? (
    body
  ) : (
    <DataPageLayout
      backTo="/threatintel"
      icon={icon}
      title={title}
      description={description}
      loading={loading}
      error={error}
      onRetry={onRetry}
      maxWidthClass={maxWidthClass}
    >
      {body}
    </DataPageLayout>
  );
}

/** External link with scheme allow-listing and the standard new-tab attrs. */
export function OutLink({
  href,
  children,
  className = 'text-accent-text hover:underline',
}: {
  href: string;
  children: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <a href={sanitizeUrl(href) || '#'} target="_blank" rel="noopener noreferrer" className={className}>
      {children}
      <ExternalLink size={11} className="ml-1 inline align-baseline" aria-hidden="true" />
    </a>
  );
}

const TONES: Record<string, string> = {
  neutral: 'border-line-2 bg-wash text-muted',
  high: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  good: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  brand: 'border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300',
};

export function Badge({
  children,
  tone = 'neutral',
  className = '',
}: {
  children: ReactNode;
  tone?: keyof typeof TONES | string;
  className?: string;
}): JSX.Element {
  return (
    <span
      className={`inline-flex rounded border px-1.5 py-0.5 font-mono text-[11px] ${TONES[tone] ?? TONES.neutral} ${className}`}
    >
      {children}
    </span>
  );
}

export function Section({ title, hint, children }: { title: string; hint?: string; children: ReactNode }): JSX.Element {
  return (
    <section className="mt-6">
      <h2 className="text-lg font-semibold text-heading">{title}</h2>
      {hint && <p className="mt-1 text-sm text-muted">{hint}</p>}
      <div className="mt-3">{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }): JSX.Element {
  return <p className="rounded border border-dashed border-line-1 p-6 text-center text-sm text-muted">{children}</p>;
}

export function Pager({
  page,
  pages,
  onPage,
}: {
  page: number;
  pages: number;
  onPage: (next: number) => void;
}): JSX.Element | null {
  if (pages < 2) return null;
  return (
    <div className="mt-4 flex items-center justify-center gap-3 font-mono text-xs text-muted">
      <button
        type="button"
        onClick={() => onPage(Math.max(0, page - 1))}
        disabled={page === 0}
        className="rounded border border-line-1 px-2 py-1 hover:bg-wash disabled:opacity-40"
      >
        Prev
      </button>
      <span>
        {page + 1} / {pages}
      </span>
      <button
        type="button"
        onClick={() => onPage(Math.min(pages - 1, page + 1))}
        disabled={page >= pages - 1}
        className="rounded border border-line-1 px-2 py-1 hover:bg-wash disabled:opacity-40"
      >
        Next
      </button>
    </div>
  );
}
