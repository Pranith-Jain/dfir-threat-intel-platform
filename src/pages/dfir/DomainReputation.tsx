import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useRef, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link, useSearchParams } from 'react-router-dom';
import { Search, Loader2, ExternalLink, Globe, BookOpen } from 'lucide-react';
import { EXTERNAL_REP_TOOLS } from '../../lib/dfir/reputation';
import { BlacklistBadge } from '../../components/dfir/BlacklistBadge';

// ─── API Response Types ──────────────────────────────────────────────────────

interface BlacklistCheck {
  source: string;
  listed: boolean;
  details?: string;
}

interface IpResult {
  ip: string;
  checks: BlacklistCheck[];
}

interface DomainRepResponse {
  target: string;
  type: 'ip' | 'domain';
  score: number;
  domain?: BlacklistCheck[];
  ips?: IpResult[];
  error?: string;
  generated_at: string;
}

// ─── Score Helpers ───────────────────────────────────────────────────────────

function getScoreLabel(score: number): { label: string; classes: string } {
  if (score >= 90) {
    return {
      label: 'Clean',
      classes: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
    };
  }
  if (score >= 70) {
    return {
      label: 'Low Risk',
      classes: 'bg-cyan-500/15 text-sky-700 dark:text-sky-300 border-cyan-500/30',
    };
  }
  if (score >= 40) {
    return {
      label: 'Medium Risk',
      classes: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
    };
  }
  return {
    label: 'High Risk',
    classes: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
  };
}

function getScoreColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500';
  if (score >= 70) return 'bg-cyan-500';
  if (score >= 40) return 'bg-amber-500';
  return 'bg-rose-500';
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function DomainReputation(): JSX.Element {
  const [searchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('domain') ?? searchParams.get('q') ?? '');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<DomainRepResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const clean = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean);

  const run = useCallback(async () => {
    if (!clean) return;
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const signal = abortRef.current.signal;

    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const param = isIp ? `ip=${encodeURIComponent(clean)}` : `domain=${encodeURIComponent(clean)}`;
      const r = await fetch(`/api/v1/domain-rep?${param}`, { signal });
      if (!r.ok) {
        const body = (await r.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error ?? `HTTP ${r.status}`);
      }
      const data = (await r.json()) as DomainRepResponse;
      if (data.error) {
        setError(data.error);
      } else {
        setResults(data);
      }
    } catch (e) {
      logCatch(e);
      if (!signal.aborted) setError(errMessage(e, 'check failed'));
    } finally {
      if (!signal.aborted) setLoading(false);
    }
  }, [clean, isIp]);

  useEffect(() => {
    if (searchParams.get('domain') || searchParams.get('q')) run();
    return () => abortRef.current?.abort();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Compute aggregated stats from results
  const allChecks = results ? [...(results.domain ?? []), ...(results.ips ?? []).flatMap((r) => r.checks)] : [];
  const listedCount = allChecks.filter((c) => c.listed).length;
  const totalChecks = allChecks.length;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Globe size={28} className="text-brand-600 dark:text-brand-400" /> Domain & IP Reputation
        </h1>
        <p className="text-muted mb-8 max-w-2xl">
          Check a domain or IP against <strong>26+ DNSBL sources</strong> (Spamhaus, Barracuda, SORBS, URIBL, CBL,
          SURBL, and more) via server-side DNS resolution. Resolves A records and checks every resolved IP. No API key
          required.
        </p>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
        className="mb-6"
      >
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="example.com or 1.2.3.4"
              className="w-full pl-9 pr-3 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              aria-label="Domain or IP to check"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !clean}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            {loading ? (
              <Loader2 size={16} className="animate-spin inline mr-1" />
            ) : (
              <Search size={16} className="inline mr-1" />
            )}{' '}
            Check
          </button>
        </div>
      </form>

      {loading && (
        <div className="flex items-center gap-2 text-xs font-mono text-muted animate-pulse mb-4">
          <Loader2 size={12} className="animate-spin" />
          Checking reputation across 26+ sources...
        </div>
      )}
      {error && (
        <p role="alert" className="text-xs font-mono text-rose-600 dark:text-rose-400 mb-4">
          {error}
        </p>
      )}

      {results && !results.error && (
        <div className="space-y-6">
          {/* Score Summary */}
          <section className="surface-card p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-3 mb-3">
              <h2 className="font-display font-bold text-xl">{results.target}</h2>
              {(() => {
                const { label, classes } = getScoreLabel(results.score);
                return (
                  <span className={`text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded border ${classes}`}>
                    {label} · {results.score}/100
                  </span>
                );
              })()}
            </div>
            <div className="h-2 rounded bg-track overflow-hidden mb-3">
              <div
                className={`h-full transition-all ${getScoreColor(results.score)}`}
                style={{ width: `${Math.max(2, results.score)}%` }}
              />
            </div>
            <p className="text-sm font-mono text-muted">
              {listedCount > 0 ? (
                <>
                  <span className="text-rose-500 font-semibold">{listedCount}</span> of {totalChecks} sources flag this{' '}
                  {results.type}
                </>
              ) : (
                <>
                  <span className="text-emerald-500 font-semibold">Clean</span> - no blacklists flagged this{' '}
                  {results.type}
                </>
              )}
            </p>
          </section>

          {/* Domain Blacklists */}
          {results.domain && results.domain.length > 0 && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
                Domain blacklists ({results.domain.length})
              </h3>
              <div className="flex flex-wrap gap-2">
                {results.domain.map((bl) => (
                  <BlacklistBadge key={bl.source} bl={{ ...bl, name: bl.source, detail: bl.details }} />
                ))}
              </div>
            </section>
          )}

          {/* IP Blacklists */}
          {results.ips && results.ips.length > 0 && (
            <>
              {results.ips.map(({ ip, checks }) => {
                const ipListed = checks.filter((c) => c.listed).length;
                const ipScore = ipListed === 0 ? 100 : ipListed <= 2 ? 70 : ipListed <= 5 ? 40 : 10;
                const { label, classes } = getScoreLabel(ipScore);
                return (
                  <section key={ip} className="surface-card p-4">
                    <div className="flex items-baseline justify-between gap-2 mb-3">
                      <h3 className="font-display font-semibold text-base inline-flex items-center gap-2">
                        <Globe size={14} className="text-brand-600 dark:text-brand-400" aria-hidden="true" /> {ip}
                      </h3>
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${classes}`}
                      >
                        {label} · {ipScore}/100
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {checks.map((bl) => (
                        <BlacklistBadge key={bl.source} bl={{ ...bl, name: bl.source, detail: bl.details }} />
                      ))}
                    </div>
                  </section>
                );
              })}
            </>
          )}

          {/* Quick Links */}
          <div className="flex gap-2 flex-wrap">
            <Link
              to={`/dfir/email-rep?domain=${encodeURIComponent(clean)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> Email Reputation
            </Link>
            <Link
              to={`/dfir/url-risk?url=${encodeURIComponent(isIp ? `http://${clean}` : `https://${clean}`)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> URL Reputation
            </Link>
            <Link
              to={`/dfir/ioc-check?indicator=${encodeURIComponent(clean)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> IOC Checker
            </Link>
            {!isIp && (
              <Link
                to={`/threatintel/domain-monitor?domain=${encodeURIComponent(clean)}`}
                className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
              >
                <ExternalLink size={10} /> Domain Monitor
              </Link>
            )}
          </div>

          {/* External Tools */}
          <section className="surface-card p-4">
            <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
              <BookOpen size={12} aria-hidden="true" /> External reputation lookups
            </h3>
            <p className="text-mini font-mono text-muted mb-3">
              For a second opinion, cross-check against these free tools:
            </p>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {EXTERNAL_REP_TOOLS.map((t) => (
                <a
                  key={t.url}
                  href={sanitizeUrl(t.url) || undefined}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`${t.name} (opens in new tab)`}
                  className="rounded border border-line-1 bg-surface-200 p-2.5 hover:border-brand-500/40 transition-colors block"
                >
                  <div className="font-display font-semibold text-xs text-heading inline-flex items-center gap-1">
                    {t.name} <ExternalLink size={10} aria-hidden="true" />
                  </div>
                  <p className="text-micro font-mono text-muted mt-0.5">{t.description}</p>
                </a>
              ))}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
