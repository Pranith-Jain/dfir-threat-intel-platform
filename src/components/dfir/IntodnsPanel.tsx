import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { preloadRoute } from '../../lib/route-preloaders';
import { errMessage } from '../../lib/log';
import {
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Loader2,
} from 'lucide-react';

/**
 * IntoDNS.ai panel - surfaces a free, public DNS-and-email-security
 * grade for the queried domain. Calls our own /api/v1/intodns/snapshot
 * route (which wraps https://intodns.ai/api/scan/quick with KV caching),
 * not intodns.ai directly, so the UI never sees a CORS or rate-limit
 * issue and the response is cached 6h on our side.
 *
 * Why a panel like this exists alongside your own email_auth block:
 * your own parsers (SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT) report
 * *what's there*. IntoDNS reports a *grade* - an opinionated score
 * computed by the methodology at https://intodns.ai/methodology, with
 * weighted categories across DNS, email, and security headers. Showing
 * both gives the user a third-party corroboration.
 *
 * The LLM explanation (when GROQ_API_KEY is set server-side) is a
 * secondary, opt-in fetch - the user clicks "Explain with AI" and we
 * call /api/v1/intodns/explain. We don't auto-fetch on mount because
 * the LLM call is the expensive one and most users want the structured
 * grade first.
 */

interface IntodnsCategory {
  score: number;
  maxScore: number;
  percentage: number;
  status: 'pass' | 'warn' | 'fail' | 'unknown';
}

interface IntodnsIssue {
  id?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category?: string;
  title?: string;
  description?: string;
  fixable?: boolean;
}

interface IntodnsSnapshot {
  domain: string;
  timestamp: string;
  percentage: number;
  grade: string;
  gradeInfo?: { grade?: string; label?: string; description?: string };
  categories?: {
    dns?: IntodnsCategory;
    email?: IntodnsCategory;
    security?: IntodnsCategory;
  };
  issues?: IntodnsIssue[];
}

interface IntodnsApiResponse {
  domain?: string;
  timestamp?: string;
  score?: number;
  maxScore?: number;
  percentage?: number;
  grade?: string;
  gradeInfo?: { grade?: string; label?: string; description?: string };
  categories?: {
    dns?: IntodnsCategory;
    email?: IntodnsCategory;
    security?: IntodnsCategory;
    [k: string]: IntodnsCategory | undefined;
  };
  issues?: IntodnsIssue[];
}

interface IntodnsPanelProps {
  domain: string;
  /** Optional: override the panel title. */
  title?: string;
}

const CITATIONS = {
  liveReport: (d: string) => `https://intodns.ai/api/report/everything?domain=${encodeURIComponent(d)}`,
  methodology: 'https://intodns.ai/methodology',
  emailTest: (d: string) => `https://intodns.ai/email-test?domain=${encodeURIComponent(d)}`,
};

const CATEGORY_LABELS: Record<string, string> = {
  dns: 'DNS records',
  email: 'Email auth',
  security: 'Security headers',
};

const STATUS_STYLES: Record<string, string> = {
  pass: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
  warn: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
  fail: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
  unknown: 'bg-slate-500/15 text-muted border-slate-500/30',
};

const GRADE_TONE: Record<string, { bg: string; ring: string; text: string; icon: typeof ShieldCheck }> = {
  'A+': {
    bg: 'bg-emerald-500/10',
    ring: 'ring-emerald-500/40',
    text: 'text-emerald-700 dark:text-emerald-300',
    icon: ShieldCheck,
  },
  A: {
    bg: 'bg-emerald-500/10',
    ring: 'ring-emerald-500/40',
    text: 'text-emerald-700 dark:text-emerald-300',
    icon: ShieldCheck,
  },
  B: {
    bg: 'bg-emerald-500/10',
    ring: 'ring-emerald-500/40',
    text: 'text-emerald-700 dark:text-emerald-300',
    icon: ShieldCheck,
  },
  C: {
    bg: 'bg-amber-500/10',
    ring: 'ring-amber-500/40',
    text: 'text-amber-700 dark:text-amber-300',
    icon: ShieldAlert,
  },
  D: {
    bg: 'bg-orange-500/10',
    ring: 'ring-orange-500/40',
    text: 'text-orange-700 dark:text-orange-300',
    icon: ShieldAlert,
  },
  F: { bg: 'bg-rose-500/10', ring: 'ring-rose-500/40', text: 'text-rose-700 dark:text-rose-300', icon: ShieldX },
};

function toneForGrade(grade?: string) {
  const g = (grade ?? 'F').toUpperCase();
  return GRADE_TONE[g] ?? GRADE_TONE['F']!;
}

export function IntodnsPanel({ domain, title = 'IntoDNS.ai grade' }: IntodnsPanelProps): JSX.Element {
  const [snapshot, setSnapshot] = useState<IntodnsSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setSnapshot(null);

    fetch(`/api/v1/intodns/snapshot?domain=${encodeURIComponent(domain)}`)
      .then(async (res) => {
        if (cancelled) return;
        if (!res.ok) {
          // 429 → upstream rate-limited; 502 → upstream down; 400 → bad input
          const body = (await res.json().catch(() => ({}))) as { error?: string };
          setError(body.error ?? `intodns: ${res.status}`);
          return;
        }
        const data = (await res.json()) as IntodnsApiResponse;
        setSnapshot({
          domain: data.domain ?? domain,
          timestamp: data.timestamp ?? new Date().toISOString(),
          percentage: data.percentage ?? 0,
          grade: data.grade ?? 'F',
          gradeInfo: data.gradeInfo,
          categories: data.categories,
          issues: data.issues ?? [],
        });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(errMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [domain]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-100/40 px-3 py-2 text-mini font-mono text-muted">
        <Loader2 size={12} className="animate-spin" aria-hidden="true" />
        fetching intodns.ai grade…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-mini font-mono text-amber-700 dark:text-amber-300">
        intodns.ai unavailable: {error}
        <span className="ml-2 inline-block">
          <a
            href={CITATIONS.liveReport(domain)}
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-700 underline dark:text-amber-300"
          >
            view report directly <ExternalLink size={9} className="inline" />
          </a>
        </span>
      </div>
    );
  }

  if (!snapshot) return <></>;

  const tone = toneForGrade(snapshot.grade);
  const Icon = tone.icon;
  const issues = (snapshot.issues ?? []).slice(0, 5);
  const hasMoreIssues = (snapshot.issues?.length ?? 0) > issues.length;

  return (
    <section aria-label={title} className="surface-card p-4">
      <header className="flex flex-wrap items-center gap-3">
        <div
          className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl font-mono text-lg font-bold ring-2 ${tone.bg} ${tone.ring} ${tone.text}`}
          title={`Grade ${snapshot.grade} (${snapshot.percentage}%)`}
        >
          {snapshot.grade}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-mini font-mono uppercase tracking-[0.16em] text-muted">
            <Icon size={12} aria-hidden="true" />
            {title}
          </div>
          <div className="mt-0.5 text-sm font-semibold text-heading">
            {snapshot.gradeInfo?.label ?? `Grade ${snapshot.grade}`}
            <span className="ml-2 font-mono text-mini font-normal text-muted">{snapshot.percentage}%</span>
          </div>
          {snapshot.gradeInfo?.description && (
            <p className="mt-0.5 text-xs text-muted">{snapshot.gradeInfo.description}</p>
          )}
        </div>
        <a
          href={CITATIONS.liveReport(snapshot.domain)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex shrink-0 items-center gap-1 rounded border border-line-1 px-2.5 py-1 text-mini font-mono text-body hover:border-line-2 hover:bg-surface-200 dark:hover:border-slate-600 dark:hover:bg-surface-300/50 transition-colors"
        >
          view full <ExternalLink size={9} aria-hidden="true" />
        </a>
      </header>

      {/* Category rollup */}
      {snapshot.categories && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {Object.entries(snapshot.categories).map(([key, cat]) => {
            if (!cat) return null;
            const label = CATEGORY_LABELS[key] ?? key;
            return (
              <span
                key={key}
                className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-micro font-mono uppercase tracking-wider ${STATUS_STYLES[cat.status] ?? STATUS_STYLES['unknown']}`}
                title={`${label}: ${cat.percentage}% (${cat.score}/${cat.maxScore})`}
              >
                {label}
                <span className="tabular-nums">{cat.percentage}%</span>
              </span>
            );
          })}
        </div>
      )}

      {/* Issues - only show critical/high by default; expand for the rest */}
      {issues.length > 0 && (
        <div className="mt-3 border-t border-line-1 pt-3">
          <div className="text-mini font-mono uppercase tracking-[0.16em] text-muted">top issues</div>
          <ul className="mt-2 space-y-1.5 text-xs text-body">
            {issues.map((iss, i) => (
              <li key={iss.id ?? `iss-${i}`} className="flex items-start gap-2">
                <span
                  className={`mt-0.5 inline-block h-1.5 w-1.5 shrink-0 rounded-full ${
                    iss.severity === 'critical'
                      ? 'bg-rose-500'
                      : iss.severity === 'high'
                        ? 'bg-orange-500'
                        : iss.severity === 'medium'
                          ? 'bg-amber-500'
                          : 'bg-slate-400'
                  }`}
                  aria-hidden="true"
                />
                <span>
                  <span className="font-medium">{iss.title ?? iss.id ?? 'Issue'}</span>
                  {iss.category && <span className="ml-1.5 font-mono text-micro text-muted">{iss.category}</span>}
                </span>
              </li>
            ))}
          </ul>
          {hasMoreIssues && (
            <a
              href={CITATIONS.liveReport(snapshot.domain)}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-mini font-mono text-brand-600 hover:underline dark:text-brand-400 transition-colors"
            >
              {(snapshot.issues?.length ?? 0) - issues.length} more in full report <ExternalLink size={9} />
            </a>
          )}
        </div>
      )}

      <footer className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-line-1 pt-2">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-micro font-mono text-muted">
          <span className="flex items-center gap-1.5">
            <Sparkles size={9} aria-hidden="true" />
            powered by intodns.ai
          </span>
          <Link
            to={`/dfir/email-defense?eml=`}
            className="underline-offset-2 hover:underline dark:text-muted"
            title="Analyze a raw email for spam score, SPF/DKIM/DMARC alignment, and inbox-placement suggestions"
          >
            email test
          </Link>
          <Link
            to={`/dfir/sec-headers-live-live?domain=${encodeURIComponent(snapshot.domain)}`}
            onMouseEnter={() => preloadRoute('/dfir/sec-headers-live')}
            onFocus={() => preloadRoute('/dfir/sec-headers-live')}
            className="underline-offset-2 hover:underline dark:text-muted"
            title="Live third-party HTTP security-headers scan"
          >
            headers
          </Link>
          <a
            href={CITATIONS.methodology}
            target="_blank"
            rel="noopener noreferrer"
            className="underline-offset-2 hover:underline dark:text-muted transition-colors"
          >
            methodology
          </a>
        </div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="inline-flex items-center gap-1 text-mini font-mono text-muted hover:text-body dark:hover:text-inverted"
          aria-expanded={expanded}
        >
          {expanded ? 'less' : 'more'}
          {expanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
        </button>
      </footer>

      {expanded && (
        <p className="mt-2 text-micro text-muted">
          scan: {new Date(snapshot.timestamp).toUTCString()} · cache hit on follow-up queries for 6h ·{' '}
          <a
            href={CITATIONS.emailTest(snapshot.domain)}
            target="_blank"
            rel="noopener noreferrer"
            className="underline"
          >
            email-test
          </a>
        </p>
      )}
    </section>
  );
}
