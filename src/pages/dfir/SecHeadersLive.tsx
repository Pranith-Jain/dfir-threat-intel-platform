import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import {
  Globe,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  AlertTriangle,
} from 'lucide-react';
import { CopyButton } from '../../components/ui/CopyButton';

/**
 * Live Security Headers Scanner - third-party HSTS/CSP/etc. scan via
 * IntoDNS.ai. Complements the existing /dfir/sec-headers-live
 * (which is paste-your-headers, 100% client-side, no API). This tool
 * fetches a live URL and gets an opinionated grade + per-header status
 * + ready-to-paste server config.
 */

type HeaderStatus = 'pass' | 'missing' | 'present' | 'weak' | 'unknown';

interface IntodnsHeaderCurrent {
  name?: string;
  present?: boolean;
  value?: string | null;
  status?: HeaderStatus;
  recommendation?: string;
}

interface IntodnsSecHeadersResponse {
  domain?: string;
  scannedAt?: string;
  httpsAvailable?: boolean;
  headerFetchTimedOut?: boolean;
  current?: IntodnsHeaderCurrent[];
  missing?: string[];
  recommended?: Record<string, string | Record<string, string>>;
  outputs?: { nginx?: string; apache?: string; caddy?: string; cloudflare?: string; headers?: string; raw?: string };
  warnings?: string[];
}

const SEV_TONE: Record<HeaderStatus, { text: string; chip: string; Icon: typeof ShieldAlert }> = {
  pass: {
    text: 'text-emerald-700 dark:text-emerald-300',
    chip: 'border-emerald-500/30 bg-emerald-500/10',
    Icon: ShieldCheck,
  },
  present: { text: 'text-sky-700 dark:text-sky-300', chip: 'border-sky-500/30 bg-sky-500/10', Icon: ShieldCheck },
  weak: {
    text: 'text-amber-700 dark:text-amber-300',
    chip: 'border-amber-500/30 bg-amber-500/10',
    Icon: AlertTriangle,
  },
  missing: { text: 'text-rose-700 dark:text-rose-300', chip: 'border-rose-500/30 bg-rose-500/10', Icon: ShieldX },
  unknown: {
    text: 'text-muted',
    chip: 'border-slate-500/30 bg-slate-500/10',
    Icon: ShieldAlert,
  },
};

const CITATIONS = {
  apiDocs: 'https://intodns.ai/api-docs',
  methodology: 'https://intodns.ai/methodology',
  generate: 'https://intodns.ai/api/security-headers/generate',
};

export default function SecHeadersLive(): JSX.Element {
  const [searchParams] = useSearchParams();
  const initial = searchParams.get('domain') ?? '';
  const [domain, setDomain] = useState(initial);
  const [data, setData] = useState<IntodnsSecHeadersResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedOutput, setExpandedOutput] = useState<string | null>(null);

  useEffect(() => {
    if (!initial) return;
    void onSubmit({ preventDefault: () => {} } as FormEvent);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const valid = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(domain.trim());

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = domain.trim().toLowerCase();
    if (!valid) return;
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const res = await fetch(`/api/v1/intodns/sec-headers?domain=${encodeURIComponent(trimmed)}`);
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string; detail?: string };
        throw new Error(body.error ?? `${res.status}${body.detail ? `: ${body.detail}` : ''}`);
      }
      const json = (await res.json()) as IntodnsSecHeadersResponse;
      setData(json);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'scan failed'));
    } finally {
      setLoading(false);
    }
  };

  const passCount = (data?.current ?? []).filter((h) => h.status === 'pass').length;
  const total = (data?.current ?? []).length;
  const score = total > 0 ? Math.round((passCount / total) * 100) : 0;
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 50 ? 'D' : 'F';

  const gradeTone =
    grade === 'A' || grade === 'B'
      ? 'text-emerald-700 dark:text-emerald-300 ring-emerald-500/40 bg-emerald-500/10'
      : grade === 'C'
        ? 'text-amber-700 dark:text-amber-300 ring-amber-500/40 bg-amber-500/10'
        : 'text-rose-700 dark:text-rose-300 ring-rose-500/40 bg-rose-500/10';

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink to="/dfir" />
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Live Security Headers</h1>
        <p className="text-muted mb-8 max-w-3xl">
          Third-party HSTS, CSP, X-Frame-Options, and other security-header scan via{' '}
          <a
            href={CITATIONS.apiDocs}
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-0.5 transition-colors"
          >
            IntoDNS.ai <ExternalLink size={10} aria-hidden="true" />
          </a>
          . For paste-your-own-headers analysis, see{' '}
          <a
            href="/dfir/sec-headers-live"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            the offline analyzer
          </a>
          .
        </p>
      </div>

      <form onSubmit={onSubmit} className="mb-6 flex gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 px-4 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
        />
        <button
          type="submit"
          disabled={!valid || loading}
          className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
        >
          {loading ? (
            <Loader2 size={16} className="inline animate-spin" />
          ) : (
            <Globe size={16} className="inline mr-2" />
          )}
          {loading ? 'Scanning…' : 'Scan'}
        </button>
      </form>

      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400 mb-4">
          error: {error}
        </p>
      )}

      {data && (
        <div className="space-y-6">
          {/* Hero */}
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-4">
              <div
                className={`flex h-16 w-16 shrink-0 items-center justify-center rounded-xl font-mono text-2xl font-bold ring-2 ${gradeTone}`}
                title={`${passCount} of ${total} headers pass`}
              >
                {grade}
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-mini font-mono uppercase tracking-[0.16em] text-muted">{data.domain}</div>
                <div className="mt-0.5 text-lg font-semibold">
                  {passCount} of {total} headers pass
                </div>
                {data.scannedAt && (
                  <p className="mt-0.5 text-xs text-muted">
                    scanned {new Date(data.scannedAt).toUTCString()}
                    {data.headerFetchTimedOut && ' · upstream header fetch timed out'}
                  </p>
                )}
              </div>
            </div>
            {data.missing && data.missing.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5 border-t border-line-1 pt-3">
                <span className="text-mini font-mono uppercase tracking-[0.16em] text-muted">missing</span>
                {data.missing.map((m) => (
                  <span
                    key={m}
                    className="inline-block rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-micro font-mono text-rose-700 dark:text-rose-300"
                  >
                    {m}
                  </span>
                ))}
              </div>
            )}
          </section>

          {/* Per-header status */}
          <section className="surface-card p-5">
            <h2 className="font-display font-bold text-lg mb-3">Per-header status</h2>
            <ul className="space-y-2">
              {(data.current ?? []).map((h, i) => {
                const status = h.status ?? 'unknown';
                const t = SEV_TONE[status];
                const Icon = t.Icon;
                return (
                  <li key={`${h.name}-${i}`} className={`rounded border px-3 py-2 ${t.chip}`}>
                    <div className="flex items-start gap-2">
                      <Icon size={12} className={`mt-0.5 ${t.text}`} aria-hidden="true" />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <span className={`text-xs font-mono font-semibold ${t.text}`}>{h.name}</span>
                          <span className={`text-micro font-mono uppercase tracking-wider ${t.text}`}>{status}</span>
                        </div>
                        {h.value && (
                          <pre className="mt-1 text-micro font-mono text-body whitespace-pre-wrap break-all">
                            {h.value}
                          </pre>
                        )}
                        {h.recommendation && <p className="mt-1 text-micro text-muted">{h.recommendation}</p>}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          </section>

          {/* Ready-to-paste outputs */}
          {data.outputs && (
            <section className="surface-card p-5">
              <h2 className="font-display font-bold text-lg mb-3">Ready-to-paste config</h2>
              <p className="text-xs text-muted mb-3">
                Drop into your server config or generate a fresh policy via the{' '}
                <a
                  href={CITATIONS.generate}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-0.5 transition-colors"
                >
                  IntoDNS.ai generator <ExternalLink size={9} />
                </a>
                .
              </p>
              <div className="space-y-2">
                {(['nginx', 'apache', 'caddy', 'cloudflare', 'headers', 'raw'] as const).map((key) => {
                  const value = data.outputs?.[key];
                  if (!value) return null;
                  const isOpen = expandedOutput === key;
                  return (
                    <div key={key} className="rounded border border-line-1">
                      <button
                        type="button"
                        onClick={() => setExpandedOutput(isOpen ? null : key)}
                        className="w-full px-3 py-2 flex items-center justify-between text-mini font-mono uppercase tracking-wider text-muted hover:bg-surface-200 dark:hover:bg-surface-300/50"
                      >
                        {key}
                        {isOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                      </button>
                      {isOpen && (
                        <div className="border-t border-line-1 p-3 relative">
                          <pre className="text-micro font-mono text-heading whitespace-pre-wrap break-all">{value}</pre>
                          <CopyButton
                            text={value}
                            variant="ghost"
                            size="sm"
                            label="Copy header value"
                            className="absolute top-2 right-2 border border-line-1 bg-surface-100"
                          />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {data.warnings && data.warnings.length > 0 && (
            <section className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
              <h2 className="font-display font-bold text-sm text-amber-700 dark:text-amber-300 mb-2">Warnings</h2>
              <ul className="space-y-1 text-xs text-amber-700 dark:text-amber-300">
                {data.warnings.map((w, i) => (
                  <li key={i}>· {w}</li>
                ))}
              </ul>
            </section>
          )}

          <footer className="text-mini font-mono text-muted">
            methodology:{' '}
            <a href={CITATIONS.methodology} target="_blank" rel="noopener noreferrer" className="underline">
              intodns.ai/methodology
            </a>
          </footer>
        </div>
      )}
    </div>
  );
}
