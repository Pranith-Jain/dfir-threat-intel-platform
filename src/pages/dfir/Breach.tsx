import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useRef, useState, type FormEvent, type CSSProperties } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import {
  ShieldCheck,
  ShieldAlert,
  Key,
  Globe,
  Mail,
  Eye,
  EyeOff,
  ExternalLink,
  AlertTriangle,
  Users,
  BadgeCheck,
  MailCheck,
  MailX,
  Inbox,
} from 'lucide-react';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';
import { BreachDatabasesPanel } from '../../components/dfir/BreachDatabasesPanel';
import { SEVERITY_TONE, type Severity } from '../../components/severity';

// ─── types ────────────────────────────────────────────────────────────────────

type Mode = 'password' | 'email' | 'domain';

const SOURCE_LABELS: Record<string, string> = {
  xposedornot: 'XposedOrNot',
  leakcheck: 'LeakCheck',
  leakix: 'LeakIX',
  proxynova: 'ProxyNova',
  hudsonrock: 'Hudson Rock',
  projectdiscovery: 'ProjectDiscovery',
  breachvip: 'BreachVIP',
};

const SOURCE_COLORS: Record<string, string> = {
  xposedornot: 'bg-violet-500/10 text-violet-700 dark:text-violet-300 border-violet-500/30',
  leakcheck: 'bg-brand-500/10 text-brand-700 dark:text-brand-300 border-brand-500/30',
  leakix: 'bg-cyan-500/10 text-sky-700 dark:text-sky-300 border-cyan-500/30',
  proxynova: 'bg-orange-500/10 text-orange-700 dark:text-orange-300 border-orange-500/30',
  hudsonrock: 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/30',
  projectdiscovery: 'bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/30',
  breachvip: 'bg-teal-500/10 text-teal-700 dark:text-teal-300 border-teal-500/30',
};

const MODES: Array<{ id: Mode; label: string; icon: typeof Key }> = [
  { id: 'password', label: 'Password', icon: Key },
  { id: 'email', label: 'Email', icon: Mail },
  { id: 'domain', label: 'Domain', icon: Globe },
];

interface BreachEntry {
  name: string;
  domain?: string;
  breach_date?: string;
  description?: string;
  pwn_count?: number;
  data_classes?: string[];
  logo?: string;
  source?: string;
}

/**
 * Email-deliverability verdict. Sourced from two free, keyless public
 * APIs (throwaway.sslboard.com + rapid-email-verifier.fly.dev) merged
 * server-side. `status` is the headline verdict and `score` is a
 * heuristic 0-100 derived from the booleans (NOT a vendor-published
 * metric - see `deriveVerificationScore` in breach.ts for weights).
 */
interface EmailVerification {
  status: 'deliverable' | 'undeliverable' | 'risky' | 'unknown';
  score: number;
  isDisposable: boolean;
  hasMx: boolean;
  validTld: boolean;
  domainExists: boolean;
  syntaxValid: boolean;
  isRole: boolean;
  isAlias: boolean;
  sources: { throwaway: boolean; rapid: boolean };
}

interface BreachEmailResponse {
  email: string;
  found: boolean;
  sources_queried: string[];
  breach_count: number;
  breaches: BreachEntry[];
  /**
   * Free, keyless deliverability check (always populated; status
   * 'unknown' with sources empty when both free APIs were unreachable).
   */
  verification: EmailVerification;
}

interface BreachDomainResponse {
  domain: string;
  found: boolean;
  source: 'xposedornot' | 'leakcheck' | 'leakix' | 'hudsonrock' | 'projectdiscovery' | 'breachvip' | 'none';
  sources_queried: string[];
  breach_count: number;
  breaches: BreachEntry[];
}

// ─── helpers ──────────────────────────────────────────────────────────────────

async function sha1Upper(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const hashBuf = await crypto.subtle.digest('SHA-1', buf);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function humanizeCount(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return n.toLocaleString('en-US');
}

function getSeverity(count: number): { label: string; classes: string } {
  const severity: Severity = count >= 1000 ? 'critical' : count >= 100 ? 'high' : 'low';
  const label = severity === 'critical' ? 'Critical' : severity === 'high' ? 'High' : 'Low';
  return { label, classes: SEVERITY_TONE[severity] };
}

/**
 * Map a merged email-verification result to a UI verdict (label + classes).
 * The verdict is the headline signal a user needs ("can mail reach this
 * address?"); the raw booleans are surfaced as a small grid below for
 * analysts who want the precise source signals.
 */
function getVerificationVerdict(v: EmailVerification): {
  label: string;
  classes: string;
  Icon: typeof BadgeCheck;
  blurb: string;
} {
  if (v.isDisposable) {
    return {
      label: 'Disposable',
      classes: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300 border-rose-300 dark:border-rose-700',
      Icon: MailX,
      blurb: 'This is a throwaway / temporary-mail address. Breach records here are rarely actionable.',
    };
  }
  if (v.status === 'undeliverable') {
    const reason = !v.syntaxValid
      ? 'The address fails basic syntax checks'
      : !v.validTld
        ? 'The domain TLD is not recognized'
        : !v.domainExists
          ? 'The domain does not resolve in DNS'
          : !v.hasMx
            ? 'The domain has no mail-exchange records'
            : 'Mail to this address will not be accepted';
    return {
      label: 'Undeliverable',
      classes: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300 border-rose-300 dark:border-rose-700',
      Icon: MailX,
      blurb: `${reason}. Breach records may be stale or mis-typed.`,
    };
  }
  if (v.isRole) {
    return {
      label: 'Role address',
      classes: 'bg-sky-100 text-cyan-800 dark:bg-sky-500/10 dark:text-sky-300 border-cyan-300 dark:border-cyan-700',
      Icon: Inbox,
      blurb: 'This is a shared role address (info@, abuse@, postmaster@, …) - not tied to one person.',
    };
  }
  if (v.isAlias) {
    return {
      label: 'Alias',
      classes: 'bg-sky-100 text-cyan-800 dark:bg-sky-500/10 dark:text-sky-300 border-cyan-300 dark:border-cyan-700',
      Icon: Inbox,
      blurb: 'Plus-addressed or aliased (e.g. user+tag@). Pivot to the underlying mailbox before action.',
    };
  }
  if (v.status === 'risky') {
    return {
      label: 'Risky',
      classes:
        'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 border-amber-300 dark:border-amber-700',
      Icon: AlertTriangle,
      blurb: 'Deliverability is uncertain - treat breach records with caution.',
    };
  }
  if (v.status === 'deliverable') {
    return {
      label: 'Deliverable',
      classes:
        'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300 border-emerald-300 dark:border-emerald-700',
      Icon: MailCheck,
      blurb: 'Mail to this address is expected to be accepted by the recipient MX.',
    };
  }
  return {
    label: 'Unknown',
    classes: 'bg-slate-100 text-slate-700 dark:bg-surface-300 dark:text-slate-300 border-slate-300 dark:border-line-1',
    Icon: BadgeCheck,
    blurb: 'Neither free verifier (throwaway.sslboard.com, rapid-email-verifier.fly.dev) responded.',
  };
}

// ─── BreachCards: shared card renderer for email/domain results ───────────────

function BreachCards({ breaches }: { breaches: BreachEntry[] }): JSX.Element {
  return (
    <div className="space-y-4">
      {breaches.map((b, i) => (
        <div key={i} className="p-4 rounded-xl border border-line-1 bg-surface-200/50">
          <div className="flex items-start justify-between gap-3 mb-2">
            <div className="flex items-center gap-2 min-w-0">
              {b.logo && (
                <img
                  loading="lazy"
                  src={b.logo}
                  alt={b.name}
                  className="w-6 h-6 rounded object-contain shrink-0"
                  onError={(e) => {
                    (e.target as HTMLImageElement).style.display = 'none';
                  }}
                />
              )}
              <div className="min-w-0">
                <h4 className="font-semibold text-heading truncate">{b.name}</h4>
                {b.domain && <p className="text-xs text-muted truncate">{b.domain}</p>}
              </div>
            </div>
            <div className="flex flex-col items-end gap-1 shrink-0">
              <span
                className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SOURCE_COLORS[b.source ?? ''] || 'border-slate-300 dark:border-line-1 text-slate-500'}`}
              >
                {SOURCE_LABELS[b.source ?? ''] ?? b.source ?? 'unknown'}
              </span>
              {b.breach_date && <span className="text-xs font-mono text-muted">{b.breach_date}</span>}
              {b.pwn_count !== undefined && (
                <span className="text-xs font-mono text-muted">{humanizeCount(b.pwn_count)} records</span>
              )}
            </div>
          </div>
          {b.data_classes && b.data_classes.length > 0 && (
            <div className="flex flex-wrap gap-1 mb-2">
              {b.data_classes.slice(0, 8).map((d, j) => (
                <span key={j} className="text-xs px-2 py-0.5 bg-track text-body rounded">
                  {d}
                </span>
              ))}
            </div>
          )}
          {b.description && <p className="text-sm text-muted line-clamp-2">{b.description}</p>}
        </div>
      ))}
    </div>
  );
}

/**
 * Email-verification card. Renders the deliverability verdict with a
 * score bar and a small grid of raw signals (syntax / TLD / domain / MX /
 * role / alias / disposable). The card is intentionally a peer of the
 * breach summary, not a child - a deliverable address is independent
 * evidence that the breach dataset is current, not a derivative signal.
 *
 * Sourced from two free, keyless public APIs (throwaway.sslboard.com +
 * rapid-email-verifier.fly.dev). The "2/2 sources" badge in the header
 * tells the operator which APIs actually answered.
 */
function VerificationCard({ verification }: { verification: EmailVerification }): JSX.Element {
  const v = getVerificationVerdict(verification);
  const Icon = v.Icon;
  const sourceCount = (verification.sources.throwaway ? 1 : 0) + (verification.sources.rapid ? 1 : 0);
  return (
    <section className="surface-card p-5">
      <div className="flex items-start gap-4">
        <Icon size={22} className="shrink-0 mt-0.5 text-muted" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-display font-semibold text-base">Email deliverability</h3>
            <span
              className={`inline-flex items-center px-2 py-0.5 rounded text-micro font-bold uppercase tracking-wider border ${v.classes}`}
            >
              {v.label}
            </span>
            <span className="text-micro font-mono text-muted">verified by {sourceCount}/2 free sources</span>
            <a
              href="https://github.com/sslboard/throwaway"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-micro font-mono text-muted hover:text-body dark:hover:text-inverted transition-colors"
            >
              throwaway <ExternalLink size={9} />
            </a>
            <a
              href="https://github.com/umuterturk/email-verifier"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-micro font-mono text-muted hover:text-body dark:hover:text-inverted transition-colors"
            >
              rapid-verifier <ExternalLink size={9} />
            </a>
          </div>
          <p className="text-sm text-muted mt-1.5">{v.blurb}</p>

          <div className="mt-3 flex items-center gap-3">
            <div className="flex-1 h-1.5 rounded-full bg-surface-300 overflow-hidden">
              <div
                className={`h-full ${
                  verification.score >= 80
                    ? 'bg-emerald-500'
                    : verification.score >= 50
                      ? 'bg-amber-500'
                      : 'bg-rose-500'
                }`}
                style={{ width: `${Math.max(2, Math.min(100, verification.score))}%` }}
              />
            </div>
            <span className="text-xs font-mono text-muted shrink-0">score {verification.score}/100</span>
          </div>

          <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1.5 text-mini font-mono">
            <Signal label="syntax" value={verification.syntaxValid} />
            <Signal label="valid TLD" value={verification.validTld} />
            <Signal label="domain" value={verification.domainExists} />
            <Signal label="MX records" value={verification.hasMx} />
            <Signal label="disposable" value={verification.isDisposable} />
            <Signal label="role" value={verification.isRole} />
            <Signal label="alias" value={verification.isAlias} />
            <SourceSignal label="throwaway / rapid" t={verification.sources.throwaway} r={verification.sources.rapid} />
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * Two-dot source attribution: throwaway dot + rapid dot, each green
 * when the corresponding API answered. Visually compact alternative to
 * two separate `Signal` rows.
 */
function SourceSignal({ label, t, r }: { label: string; t: boolean; r: boolean }): JSX.Element {
  return (
    <div className="flex items-center gap-1.5">
      <span
        aria-hidden="true"
        className={`inline-block w-1.5 h-1.5 rounded-full ${t ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-surface-300'}`}
      />
      <span className="sr-only">{t ? 'present' : 'absent'} (text record)</span>
      <span
        aria-hidden="true"
        className={`inline-block w-1.5 h-1.5 rounded-full ${r ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-surface-300'}`}
      />
      <span className="sr-only">{r ? 'present' : 'absent'} (reverse record)</span>
      <span className="text-body">{label}</span>
    </div>
  );
}

function Signal({ label, value }: { label: string; value: boolean }): JSX.Element {
  return (
    <div className="flex items-center gap-1.5">
      <span
        aria-hidden="true"
        className={`inline-block w-1.5 h-1.5 rounded-full ${value ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-surface-300'}`}
      />
      <span className="sr-only">{value ? 'pass' : 'fail'}:</span>
      <span className={value ? 'text-body' : 'text-muted'}>{label}</span>
    </div>
  );
}

// ─── Password tab ─────────────────────────────────────────────────────────────

function PasswordTab(): JSX.Element {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ found: boolean; count?: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = password.length > 0 && !loading;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setLoading(true);
    setResult(null);
    setError(null);

    const pw = password;
    setPassword('');

    try {
      const hash = await sha1Upper(pw);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const r = await fetch(`/api/v1/breach/range?prefix=${prefix}`);
      if (!r.ok) throw new Error(`Upstream error: HTTP ${r.status}`);

      const text = await r.text();
      let found = false;
      let count = 0;
      for (const line of text.split('\n')) {
        const [lineSuffix, lineCount] = line.trim().split(':');
        if (lineSuffix && lineSuffix.toUpperCase() === suffix) {
          found = true;
          count = parseInt(lineCount ?? '0', 10);
          break;
        }
      }
      setResult({ found, count: found ? count : undefined });
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'check failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {/* Privacy notice */}
      <div className="mb-6 rounded-xl border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50 dark:bg-emerald-900/10 p-4">
        <div className="flex gap-3">
          <ShieldCheck size={18} className="text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
          <div className="text-sm text-emerald-800 dark:text-emerald-300">
            <strong className="font-semibold">Privacy-preserving:</strong> Your password is hashed in your browser using
            SHA-1. Only the first 5 characters of the hash (k-anonymity) are sent to our backend and then to{' '}
            <a
              href="https://haveibeenpwned.com/Passwords"
              target="_blank"
              rel="noopener noreferrer"
              className="underline"
            >
              HIBP
            </a>
            . Your password never leaves your device.
          </div>
        </div>
      </div>

      <form onSubmit={onSubmit} className="mb-8">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              // Deliberately NOT type="password". A masked password field on a
              // public page is what Google Safe Browsing classifies as a
              // deceptive "user login" - that got /dfir/breach flagged
              // ("Possible Phishing Detected on User Login"). This is a one-way
              // hash lookup, not a login: keep the masked UX via CSS
              // text-security and tell password managers to ignore the field so
              // browsers stop treating it as credential entry.
              type="text"
              inputMode="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Type or paste a password to check"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              data-1p-ignore
              data-lpignore="true"
              data-form-type="other"
              aria-label="Password to check against breach datasets"
              style={{ WebkitTextSecurity: showPassword ? 'none' : 'disc' } as CSSProperties}
              className="w-full px-4 py-3 pr-12 bg-surface-100 border border-line-1 rounded-xl font-mono text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-body dark:hover:text-inverted transition-colors"
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          <button
            type="submit"
            disabled={!canSubmit}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 whitespace-nowrap transition-colors"
          >
            Check
          </button>
        </div>
      </form>

      {loading && (
        <div className="flex items-center gap-2 text-muted">
          <div className="animate-spin w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full" />
          <span className="font-mono text-sm">Checking breach databases...</span>
        </div>
      )}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="animate-fade-in-up">
          {result.found && result.count !== undefined ? (
            <section className="rounded-xl border border-amber-200 dark:border-amber-900/40 bg-amber-50 dark:bg-amber-900/10 p-6">
              <div className="flex items-start gap-4">
                <AlertTriangle size={24} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <h2 className="font-display font-bold text-xl mb-1">
                    Seen in <span className="font-mono">{result.count.toLocaleString('en-US')}</span>{' '}
                    {result.count === 1 ? 'breach' : 'breaches'}
                  </h2>
                  <div className="mb-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider border ${getSeverity(result.count).classes}`}
                    >
                      {getSeverity(result.count).label} risk
                    </span>
                  </div>
                  <p className="text-sm text-amber-800 dark:text-amber-300 mb-3">
                    This password has been seen in known data breach datasets. Avoid using it for any accounts.
                  </p>
                  <a
                    href="https://haveibeenpwned.com/Passwords"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    Learn more at HIBP
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>
            </section>
          ) : (
            <section className="rounded-xl border border-emerald-200 dark:border-emerald-900/40 bg-emerald-50 dark:bg-emerald-900/10 p-6">
              <div className="flex items-start gap-4">
                <ShieldCheck size={24} className="text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <h2 className="font-display font-bold text-xl mb-1">Not seen in any known breach</h2>
                  <p className="text-sm text-emerald-800 dark:text-emerald-300 mb-3">
                    Good news, this password was not found in the HIBP database. This does not guarantee security;
                    always use unique, strong passwords with a password manager.
                  </p>
                  <a
                    href="https://haveibeenpwned.com/Passwords"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    haveibeenpwned.com/Passwords
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Email tab ────────────────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function EmailTab({ initialQuery = '' }: { initialQuery?: string }): JSX.Element {
  const [email, setEmail] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BreachEmailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const autoFetched = useRef(false);
  const [, setSearchParams] = useSearchParams();

  const isValid = EMAIL_RE.test(email.trim());

  const runLookup = async (q: string) => {
    if (!EMAIL_RE.test(q.trim()) || loading) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        out.set('tab', 'email');
        out.set('q', q.trim());
        return out;
      },
      { replace: true }
    );
    try {
      const r = await fetch(`/api/v1/breach/email?email=${encodeURIComponent(q.trim())}`);
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        let msg = `HTTP ${r.status}`;
        try {
          const parsed = JSON.parse(body) as { error?: string };
          msg = parsed.error ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* use default */
        }
        throw new Error(msg);
      }
      const ct = r.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setResult((await r.json()) as BreachEmailResponse);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'lookup failed'));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runLookup(email);
  };

  // Auto-run if the page was opened with ?tab=email&q=<addr>.
  useEffect(() => {
    if (autoFetched.current) return;
    if (initialQuery && EMAIL_RE.test(initialQuery)) {
      autoFetched.current = true;
      void runLookup(initialQuery);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      {/* Privacy notice - explicit about upstream forwarding */}
      <div className="mb-6 rounded-xl border border-amber-300 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-900/10 p-4">
        <div className="flex gap-3">
          <AlertTriangle size={18} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="text-sm text-amber-900 dark:text-amber-200">
            <p className="font-semibold mb-1">Your email is forwarded to third-party breach databases</p>
            <p className="text-tool">
              Queries are sent to{' '}
              <a href="https://xposedornot.com" target="_blank" rel="noopener noreferrer" className="underline">
                XposedOrNot
              </a>
              ,{' '}
              <a href="https://leakcheck.io" target="_blank" rel="noopener noreferrer" className="underline">
                LeakCheck
              </a>
              ,{' '}
              <a href="https://leakix.net" target="_blank" rel="noopener noreferrer" className="underline">
                LeakIX
              </a>
              ,{' '}
              <a href="https://proxynova.com" target="_blank" rel="noopener noreferrer" className="underline">
                ProxyNova
              </a>
              ,{' '}
              <a href="https://cavalier.hudsonrock.com" target="_blank" rel="noopener noreferrer" className="underline">
                Hudson Rock
              </a>
              ,{' '}
              <a href="https://projectdiscovery.io" target="_blank" rel="noopener noreferrer" className="underline">
                ProjectDiscovery
              </a>
              ,{' '}
              <a href="https://breach.vip" target="_blank" rel="noopener noreferrer" className="underline">
                BreachVIP
              </a>{' '}
              in parallel. Transit logs may record the request. The address is not stored in our app database.
              <strong> Don't query addresses you don't own.</strong>
            </p>
          </div>
        </div>
      </div>

      <form onSubmit={onSubmit} className="mb-8">
        <div className="flex gap-2">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="email@example.com"
            className="flex-1 px-4 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
          <button
            type="submit"
            disabled={!isValid || loading}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 whitespace-nowrap transition-colors"
          >
            Check
          </button>
        </div>
      </form>

      {loading && (
        <div className="flex items-center gap-2 text-muted">
          <div className="animate-spin w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full" />
          <span className="font-mono text-sm">Querying breach databases...</span>
        </div>
      )}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="animate-fade-in-up space-y-6">
          {/* Summary */}
          <section
            className={`rounded-xl border p-6 ${
              result.found
                ? 'border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/20'
                : 'border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/20'
            }`}
          >
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="font-display font-bold text-xl">{result.email}</h2>
                <p className="text-xs text-muted mt-1 font-mono">
                  sources: {result.sources_queried?.map((s) => SOURCE_LABELS[s] ?? s).join(', ') || 'none'}
                </p>
              </div>
              <div
                className={`px-4 py-2 rounded-xl text-center shrink-0 ${
                  result.found ? 'bg-rose-500 text-white' : 'bg-emerald-500 text-white'
                }`}
              >
                <span className="text-2xl font-bold">{result.breach_count}</span>
                <p className="text-xs">breach{result.breach_count !== 1 ? 'es' : ''}</p>
              </div>
            </div>

            {/* Per-source summary */}
            {result.sources_queried && result.sources_queried.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-line-1">
                {result.sources_queried.map((s) => {
                  const count = result.breaches.filter((b) => b.source === s).length;
                  return (
                    <span
                      key={s}
                      className={`text-mini font-mono px-2 py-1 rounded border ${SOURCE_COLORS[s] ?? 'border-slate-300 dark:border-line-1 text-slate-500'}`}
                    >
                      {SOURCE_LABELS[s] ?? s}: {count} hit{count !== 1 ? 's' : ''}
                    </span>
                  );
                })}
              </div>
            )}
          </section>

          {/* Breach cards */}
          {result.breaches.length > 0 && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                <ShieldAlert size={18} className="text-rose-500" />
                Found in {result.breaches.length} breach{result.breaches.length !== 1 ? 'es' : ''}
              </h3>
              <BreachCards breaches={result.breaches} />
            </section>
          )}

          {/* Not found */}
          {!result.found && (
            <div className="rounded-xl border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/20 p-6 text-center">
              <ShieldCheck size={32} className="mx-auto mb-3 text-emerald-500" />
              <p className="text-emerald-700 dark:text-emerald-400 font-semibold">No breaches found</p>
              <p className="text-sm text-emerald-600 dark:text-emerald-500 mt-1">
                {result.email} was not found in the databases we checked.
              </p>
            </div>
          )}

          {/* Hunter.io deliverability card (only when the server returned
              a verification result - `undefined` means no HUNTER_API_KEY
              is configured, `null` means the call failed). */}
          {result.verification && <VerificationCard verification={result.verification} />}

          {/* SOCMINT pivot CTA */}
          <Link
            to={`/dfir/socmint?q=${encodeURIComponent(result.email)}`}
            className="block rounded-xl border border-brand-500/30 bg-brand-500/5 p-5 hover:border-brand-500/60 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Users size={22} className="text-brand-600 dark:text-brand-400 shrink-0" />
              <div className="flex-1">
                <h3 className="font-display font-semibold text-base text-heading">
                  Pivot this email to SOCMINT sources →
                </h3>
                <p className="text-xs font-mono text-muted mt-0.5">
                  Look up <code>{result.email}</code> across XposedOrNot, IntelX, EmailRep, Hunter, Apollo, ZoomInfo,
                  RocketReach, Lusha, GitHub commit-author search, paste-site dorks, social profiles, Gravatar, and
                  more.
                </p>
              </div>
              <ExternalLink size={14} className="text-muted shrink-0" />
            </div>
          </Link>
        </div>
      )}
    </div>
  );
}

// ─── Domain tab ───────────────────────────────────────────────────────────────

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function DomainTab({ initialQuery = '' }: { initialQuery?: string }): JSX.Element {
  const [domain, setDomain] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BreachDomainResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const autoFetched = useRef(false);
  const [, setSearchParams] = useSearchParams();

  const isValid = DOMAIN_RE.test(domain.trim());

  const runLookup = async (q: string) => {
    if (!DOMAIN_RE.test(q.trim()) || loading) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        out.set('tab', 'domain');
        out.set('q', q.trim());
        return out;
      },
      { replace: true }
    );
    try {
      const r = await fetch(`/api/v1/breach/domain?domain=${encodeURIComponent(q.trim())}`);
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        let msg = `HTTP ${r.status}`;
        try {
          const parsed = JSON.parse(body) as { error?: string };
          msg = parsed.error ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* use default */
        }
        throw new Error(msg);
      }
      const ct = r.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setResult((await r.json()) as BreachDomainResponse);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'lookup failed'));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runLookup(domain);
  };

  // Auto-run if the page was opened with ?tab=domain&q=<domain>.
  useEffect(() => {
    if (autoFetched.current) return;
    if (initialQuery && DOMAIN_RE.test(initialQuery)) {
      autoFetched.current = true;
      void runLookup(initialQuery);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      {/* Notice - explicit about upstream forwarding + data quality */}
      <div className="mb-6 rounded-xl border border-amber-300 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-900/10 p-4">
        <div className="flex gap-3">
          <AlertTriangle size={18} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="text-sm text-amber-900 dark:text-amber-200">
            <p className="font-semibold mb-1">Domain forwarded to breach databases - results are noisy</p>
            <p className="text-tool">
              The domain is sent to{' '}
              <a href="https://xposedornot.com" target="_blank" rel="noopener noreferrer" className="underline">
                XposedOrNot
              </a>
              ,{' '}
              <a href="https://leakcheck.io" target="_blank" rel="noopener noreferrer" className="underline">
                LeakCheck
              </a>
              ,{' '}
              <a href="https://leakix.net" target="_blank" rel="noopener noreferrer" className="underline">
                LeakIX
              </a>
              , and{' '}
              <a href="https://cavalier.hudsonrock.com" target="_blank" rel="noopener noreferrer" className="underline">
                Hudson Rock
              </a>
              , and{' '}
              <a href="https://projectdiscovery.io" target="_blank" rel="noopener noreferrer" className="underline">
                ProjectDiscovery
              </a>
              , and{' '}
              <a href="https://breach.vip" target="_blank" rel="noopener noreferrer" className="underline">
                BreachVIP
              </a>{' '}
              in parallel. Treat any single hit as a starting point, not a verdict.{' '}
              <strong>Don't query domains you don't have authorization for.</strong>
            </p>
          </div>
        </div>
      </div>

      <form onSubmit={onSubmit} className="mb-8">
        <div className="flex gap-2">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="flex-1 px-4 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
          <button
            type="submit"
            disabled={!isValid || loading}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 whitespace-nowrap transition-colors"
          >
            Check
          </button>
        </div>
        {domain && !isValid && (
          <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">
            Enter a valid domain (e.g. example.com)
          </p>
        )}
      </form>

      {loading && (
        <div className="flex items-center gap-2 text-muted">
          <div className="animate-spin w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full" />
          <span className="font-mono text-sm">Querying breach databases...</span>
        </div>
      )}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="animate-fade-in-up space-y-6">
          {/* Summary */}
          <section
            className={`rounded-xl border p-6 ${
              result.found
                ? 'border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/20'
                : 'border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/20'
            }`}
          >
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="font-display font-bold text-xl">{result.domain}</h2>
                <p className="text-xs text-muted mt-1 font-mono">
                  sources: {result.sources_queried?.map((s) => SOURCE_LABELS[s] ?? s).join(', ') || 'none'}
                </p>
              </div>
              <div
                className={`px-4 py-2 rounded-xl text-center shrink-0 ${
                  result.found ? 'bg-rose-500 text-white' : 'bg-emerald-500 text-white'
                }`}
              >
                <span className="text-2xl font-bold">{result.breach_count}</span>
                <p className="text-xs">breach{result.breach_count !== 1 ? 'es' : ''}</p>
              </div>
            </div>

            {/* Per-source summary */}
            {result.sources_queried && result.sources_queried.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-line-1">
                {result.sources_queried.map((s) => {
                  const count = result.breaches.filter((b) => b.source === s).length;
                  return (
                    <span
                      key={s}
                      className={`text-mini font-mono px-2 py-1 rounded border ${SOURCE_COLORS[s] ?? 'border-slate-300 dark:border-line-1 text-slate-500'}`}
                    >
                      {SOURCE_LABELS[s] ?? s}: {count} hit{count !== 1 ? 's' : ''}
                    </span>
                  );
                })}
              </div>
            )}
          </section>

          {/* Breach cards */}
          {result.breaches.length > 0 && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                <ShieldAlert size={18} className="text-rose-500" />
                Found in {result.breaches.length} breach{result.breaches.length !== 1 ? 'es' : ''}
              </h3>
              <BreachCards breaches={result.breaches} />
            </section>
          )}

          {/* Not found */}
          {!result.found && (
            <div className="rounded-xl border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/20 p-6 text-center">
              <ShieldCheck size={32} className="mx-auto mb-3 text-emerald-500" />
              <p className="text-emerald-700 dark:text-emerald-400 font-semibold">No breaches found</p>
              <p className="text-sm text-emerald-600 dark:text-emerald-500 mt-1">
                {result.domain} was not found in the breach databases we checked.
              </p>
            </div>
          )}

          {/* SOCMINT pivot CTA */}
          <Link
            to={`/dfir/socmint?q=${encodeURIComponent(result.domain)}`}
            className="block rounded-xl border border-brand-500/30 bg-brand-500/5 p-5 hover:border-brand-500/60 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Users size={22} className="text-brand-600 dark:text-brand-400 shrink-0" />
              <div className="flex-1">
                <h3 className="font-display font-semibold text-base text-heading">
                  Pivot this domain to SOCMINT sources →
                </h3>
                <p className="text-xs font-mono text-muted mt-0.5">
                  Look up <code>{result.domain}</code> across Hunter, Apollo, ZoomInfo, RocketReach, GitHub
                  commit-author search, paste-site dorks, LinkedIn @domain dork, Shodan, Censys, crt.sh, and more.
                </p>
              </div>
              <ExternalLink size={14} className="text-muted shrink-0" />
            </div>
          </Link>
        </div>
      )}
    </div>
  );
}

// ─── Page shell ───────────────────────────────────────────────────────────────

function isMode(v: string | null): v is Mode {
  return v === 'password' || v === 'email' || v === 'domain';
}

export default function BreachPage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlMode = searchParams.get('tab');
  // Deep-link fallbacks: ?email=/?domain= (emitted by IOC pivots and legacy
  // /dfir/breach-check links) map onto tab+q so the lookup is pre-filled.
  const urlQuery = searchParams.get('q') ?? searchParams.get('email') ?? searchParams.get('domain') ?? '';
  const [mode, setModeState] = useState<Mode>(
    isMode(urlMode)
      ? urlMode
      : searchParams.get('domain') && !searchParams.get('tab')
        ? 'domain'
        : searchParams.get('email') && !searchParams.get('tab')
          ? 'email'
          : 'password'
  );

  // Sync mode → URL whenever the user changes tabs. Drops ?q= since
  // queries are scoped per tab and don't survive a tab switch.
  const setMode = (next: Mode) => {
    setModeState(next);
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        out.set('tab', next);
        out.delete('q');
        return out;
      },
      { replace: false }
    );
  };

  // React to URL changes from outside (back/forward, deep links).
  useEffect(() => {
    if (isMode(urlMode) && urlMode !== mode) setModeState(urlMode);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlMode]);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<ShieldAlert size={28} />}
      title="Breach Checker"
      description="Check if a password, email address, or domain has appeared in known data breaches."
      maxWidthClass="max-w-4xl"
    >
      {/* Tab pills */}
      <div className="flex flex-wrap gap-2 mb-8">
        {MODES.map((m) => {
          const Icon = m.icon;
          return (
            <button
              key={m.id}
              type="button"
              onClick={() => setMode(m.id)}
              className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-mono uppercase tracking-wider border transition-colors ${
                mode === m.id
                  ? 'bg-brand-500/15 dark:bg-brand-400/15 text-brand-700 dark:text-brand-300 border-brand-500/40'
                  : 'bg-white dark:bg-surface-200 text-muted border-line-1 hover:border-brand-500/40'
              }`}
            >
              <Icon size={12} />
              {m.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div className="animate-fade-in-up" key={mode}>
        {mode === 'password' && <PasswordTab />}
        {mode === 'email' && <EmailTab initialQuery={urlQuery} />}
        {mode === 'domain' && <DomainTab initialQuery={urlQuery} />}
      </div>

      <BreachDatabasesPanel initialQuery={mode === 'password' ? undefined : urlQuery} />

      <RelatedWikiArticles />
    </DataPageLayout>
  );
}
