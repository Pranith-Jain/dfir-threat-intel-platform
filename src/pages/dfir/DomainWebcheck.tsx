import { errMessage, logCatch } from '../../lib/log';
import { useState, useRef, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Globe, Shield, Lock, Server, ExternalLink, Loader2, Wifi } from 'lucide-react';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

interface SecurityCheck {
  header: string;
  present: boolean;
  value?: string;
  secure: boolean;
  recommendation: string;
}

interface TechFingerprint {
  category: string;
  name: string;
  confidence: number;
  evidence: string;
}

interface WebcheckResponse {
  domain: string;
  generated_at: string;
  http: {
    url: string;
    status: number;
    redirect_chain: string[];
    headers: Record<string, string>;
    response_time_ms: number;
    content_length: number;
    content_type: string;
  };
  tls: { protocol?: string; issuer?: string; self_signed?: boolean };
  security_headers: { score: number; grade: string; checks: SecurityCheck[] };
  technology: TechFingerprint[];
  ports: number[];
  shodan?: { ip?: string; org?: string; os?: string; vulns?: string[]; hostnames?: string[] };
}

const GRADE_CLS: Record<string, string> = {
  'A+': 'text-emerald-600 dark:text-emerald-400',
  A: 'text-emerald-600 dark:text-emerald-400',
  B: 'text-sky-600 dark:text-sky-400',
  C: 'text-amber-600 dark:text-amber-400',
  D: 'text-orange-600 dark:text-orange-400',
  F: 'text-rose-600 dark:text-rose-400',
};

export default function DomainWebcheck(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('domain') ?? '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WebcheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cdnResult, setCdnResult] = useState<{ is_cdn: boolean; provider: string | null; type: string | null } | null>(
    null
  );
  const cdnAbortRef = useRef<AbortController | null>(null);

  const valid = DOMAIN_RE.test(
    input
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
  );

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const domain = input
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');
    if (!DOMAIN_RE.test(domain)) return;
    setSearchParams({ domain }, { replace: true });
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await fetch(`/api/v1/domain/webcheck?domain=${encodeURIComponent(domain)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = (await r.json()) as WebcheckResponse;
      setResult(data);

      // CDN/WAF detection (metabigor cdn equivalent) - non-blocking
      cdnAbortRef.current?.abort();
      if (data.shodan?.ip) {
        const ac = new AbortController();
        cdnAbortRef.current = ac;
        fetch(`/api/v1/cdn-detect?ip=${encodeURIComponent(data.shodan.ip)}`, {
          signal: AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]),
        })
          .then((res) => (res.ok ? res.json() : null))
          .then((d) => setCdnResult(d))
          .catch(() => {});
      }
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'scan failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Globe size={28} className="text-brand-600 dark:text-brand-400" /> Domain Web Check
        </h1>
        <p className="text-muted mb-8 max-w-2xl">
          HTTP probe, TLS inspection, security headers audit, technology fingerprinting, open ports, and redirect chain
          analysis.
        </p>
      </div>

      <section className="surface-card p-4 mb-6">
        <form onSubmit={onSubmit} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com"
            className="flex-1 px-4 py-3 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="submit"
            disabled={!valid || loading}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            <Search size={16} className="inline mr-2" />
            Scan
          </button>
        </form>
        {input && !valid && (
          <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">Not a valid domain.</p>
        )}
      </section>

      {loading && (
        <p className="text-sm font-mono text-muted mb-4 inline-flex items-center gap-2">
          <Loader2 size={14} className="animate-spin" /> Scanning…
        </p>
      )}
      {error && (
        <p className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4 inline-flex items-center gap-2">
          error: {error}
        </p>
      )}

      {result && (
        <div className="space-y-6">
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="HTTP" value={String(result.http.status)} sub={`${result.http.response_time_ms}ms`} />
            <StatCard label="TLS" value={result.tls.protocol ?? 'N/A'} sub={result.tls.issuer ?? ''} />
            <StatCard
              label="Security"
              value={`${result.security_headers.score}/100`}
              valueClass={GRADE_CLS[result.security_headers.grade] ?? ''}
              sub={`Grade ${result.security_headers.grade}`}
            />
            <StatCard
              label="Ports"
              value={result.ports.length ? result.ports.join(', ') : '-'}
              sub={`${result.ports.length} open`}
            />
          </div>

          {/* Security Headers */}
          <section className="surface-card p-6">
            <h2 className="font-display font-bold text-xl mb-4 flex items-center gap-2">
              <Shield size={18} className="text-brand-600 dark:text-brand-400" /> Security Headers
            </h2>
            <div className="space-y-1.5">
              {result.security_headers.checks.map((ch) => (
                <div key={ch.header} className="flex items-center gap-2 text-sm font-mono">
                  <span className={ch.secure ? 'text-emerald-500' : ch.present ? 'text-amber-500' : 'text-rose-500'}>
                    {ch.secure ? 'secure' : ch.present ? 'partial' : 'missing'}
                  </span>
                  <span className="w-48 truncate text-body">{ch.header}</span>
                  <span className="text-muted text-xs flex-1 truncate">
                    {ch.present ? (ch.value?.slice(0, 60) ?? 'present') : 'MISSING'}
                  </span>
                  {!ch.secure && ch.recommendation && (
                    <span className="text-xs text-muted hidden md:block max-w-xs truncate">{ch.recommendation}</span>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Technology Stack */}
          {result.technology.length > 0 && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-4 flex items-center gap-2">
                <Server size={18} className="text-brand-600 dark:text-brand-400" /> Technology Stack
              </h2>
              <div className="flex flex-wrap gap-2">
                {result.technology.map((t, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded-xl text-xs font-mono bg-surface-300 border border-line-1"
                  >
                    <span className="text-muted">{t.category}:</span> {t.name}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Shodan */}
          {result.shodan && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-4 flex items-center gap-2">
                <Lock size={18} className="text-brand-600 dark:text-brand-400" /> Shodan Intelligence
              </h2>
              <div className="font-mono text-sm space-y-1">
                <div>
                  <span className="text-muted">IP:</span> {result.shodan.ip}
                </div>
                <div>
                  <span className="text-muted">Org:</span> {result.shodan.org}
                </div>
                <div>
                  <span className="text-muted">OS:</span> {result.shodan.os}
                </div>
                {result.shodan.vulns && result.shodan.vulns.length > 0 && (
                  <div>
                    <span className="text-muted">Vulns:</span> {result.shodan.vulns.join(', ')}
                  </div>
                )}
              </div>
            </section>
          )}

          {/* CDN/WAF Detection - metabigor cdn equivalent */}
          {cdnResult && cdnResult.is_cdn && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-2 flex items-center gap-2">
                <Wifi size={18} className="text-brand-600 dark:text-brand-400" /> CDN / WAF Detected
              </h2>
              <div className="font-mono text-sm space-y-1">
                <div>
                  <span className="text-muted">Provider:</span>{' '}
                  <span className="text-heading font-semibold">{cdnResult.provider}</span>
                </div>
                <div>
                  <span className="text-muted">Type:</span> {cdnResult.type}
                </div>
                <p className="text-xs text-muted mt-2">
                  This domain is fronted by a CDN/WAF - the origin server IP may differ from what Shodan shows.
                </p>
              </div>
            </section>
          )}

          {/* Redirect Chain */}
          {result.http.redirect_chain.length > 0 && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-4 flex items-center gap-2">
                <ExternalLink size={18} className="text-brand-600 dark:text-brand-400" /> Redirect Chain
              </h2>
              <div className="text-xs font-mono space-y-0.5">
                {result.http.redirect_chain.map((url, i) => (
                  <div key={i} className="text-muted">
                    {url}
                  </div>
                ))}
                <div className="text-heading font-semibold">{result.http.url}</div>
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  valueClass,
  sub,
}: {
  label: string;
  value: string;
  valueClass?: string;
  sub?: string;
}) {
  return (
    <div className="p-3 surface-card">
      <div className="text-xs font-mono text-muted">{label}</div>
      <div className={`text-lg font-bold font-mono mt-0.5 ${valueClass ?? 'text-heading'}`}>{value}</div>
      {sub && <div className="text-xs font-mono text-muted mt-0.5">{sub}</div>}
    </div>
  );
}
