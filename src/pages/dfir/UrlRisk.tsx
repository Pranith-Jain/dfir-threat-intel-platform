import { useState } from 'react';
import { api } from '../../lib/api-client';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Button } from '../../components/ui/Button';
import { Spinner } from '../../components/ui/Spinner';
import { Link2, Search, AlertTriangle } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface StaticAnalysis {
  hostname: string;
  port: number | null;
  scheme: string;
  url_length: number;
  long_url: boolean;
  has_at_symbol: boolean;
  suspicious_keywords: string[];
  punycode: boolean;
  shortener: boolean;
  shortener_name: string | null;
  ip_hostname: boolean;
  subdomain_count: number;
  many_subdomains: boolean;
  non_standard_port: boolean;
  flags: string[];
  static_score: number;
}

interface ProviderResult {
  source: string;
  status: string;
  score?: number;
  verdict?: string;
  tags?: string[];
  raw_summary?: Record<string, unknown>;
  error?: string;
  registrar?: string;
  created?: string;
  dnssec?: string;
}

interface UrlRiskResponse {
  url: string;
  hostname: string;
  ip_address: string | null;
  static: StaticAnalysis;
  risk: {
    risk_score: number;
    verdict: string;
    confidence: number;
    recommendation: string;
    evidence: string[];
    positive_findings: string[];
    informational_findings: string[];
    provider_status: Record<string, boolean>;
    score_breakdown: Record<string, number>;
    domain_age_days: number | null;
  };
  providers: Record<string, ProviderResult>;
}

const VERDICT_STYLE: Record<string, string> = {
  'Critical Risk': 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  'High Risk': 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  Suspicious: 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  'Low Risk': 'border-yellow-500/50 bg-yellow-500/10 text-yellow-700 dark:text-yellow-300',
  'No Strong Threat Evidence': 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

const PROVIDER_MAX: Record<string, number> = {
  virustotal: 35,
  google_safe_browsing: 30,
  urlscan: 30,
  abuseipdb: 20,
  whois: 20,
};

const PROVIDER_LABEL: Record<string, string> = {
  virustotal: 'VirusTotal',
  google_safe_browsing: 'Google Safe Browsing',
  urlscan: 'URLScan.io',
  abuseipdb: 'AbuseIPDB',
  whois: 'WHOIS / RDAP',
};

const SAMPLES: { label: string; url: string }[] = [
  { label: 'benign', url: 'https://example.com' },
  { label: 'fresh domain', url: 'https://login-secure-checkout-verify.7f3kx2.ltd/account/verify' },
  { label: 'shortener', url: 'http://bit.ly/3x9ZqrL' },
  { label: 'IP literal', url: 'https://185.220.101.45:8443/banking/login' },
];

export default function UrlRisk() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<UrlRiskResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.post<UrlRiskResponse>('/api/v1/url-risk/analyze', { url: trimmed });
      setResult(res);
    } catch (err) {
      const msg = errMessage(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const risk = result?.risk;
  const staticInfo = result?.static;

  const providerRows = Object.entries(PROVIDER_MAX)
    .map(([key, max]) => ({
      key,
      label: PROVIDER_LABEL[key] ?? key,
      max,
      score: risk?.score_breakdown[key] ?? 0,
      online: result?.providers[key]?.status === 'ok',
    }))
    .filter((r) => r.online || r.score > 0);

  const scoreColor = risk?.risk_score ?? 0;

  return (
    <DataPageLayout
      backTo="/dfir"
      backLabel="DFIR"
      icon={<Link2 />}
      title="URL Risk Analyzer"
      description={
        <span>
          Multi-source URL risk scoring - static heuristic signals plus correlated evidence from{' '}
          <span className="text-brand-600 dark:text-brand-400">VirusTotal</span>,{' '}
          <span className="text-brand-600 dark:text-brand-400">Google Safe Browsing</span>,{' '}
          <span className="text-brand-600 dark:text-brand-400">URLScan.io</span>,{' '}
          <span className="text-brand-600 dark:text-brand-400">AbuseIPDB</span> and WHOIS/RDAP age - ported from the{' '}
          <a
            href="https://github.com/Zep11/IntelX-Phishing-Intelligence-Framework"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            IntelX Phishing Intelligence Framework
          </a>{' '}
          (MIT).
        </span>
      }
    >
      <div className="space-y-6 max-w-3xl mx-auto">
        <section className="surface-card p-4">
          <form onSubmit={handleSubmit} className="flex gap-3">
            <div className="relative flex-1">
              <Link2 size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="https://example.com/login"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button
              type="submit"
              variant="primary-brand"
              size="sm"
              loading={loading}
              disabled={!url.trim() || loading}
              icon={<Search size={14} />}
            >
              {loading ? 'analyzing…' : 'analyze'}
            </Button>
          </form>
          <div className="flex flex-wrap gap-1.5 mt-3">
            <span className="text-micro font-mono text-muted self-center mr-1">samples:</span>
            {SAMPLES.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => setUrl(s.url)}
                className="text-mini font-mono px-2 py-0.5 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
              >
                {s.label}
              </button>
            ))}
          </div>
        </section>

        {loading && (
          <div className="flex items-center justify-center py-12 text-muted">
            <Spinner size="md" className="mr-3" />
            Correlating provider evidence…
          </div>
        )}

        {error && !loading && (
          <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 flex items-center gap-3">
            <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
            <p className="text-sm font-mono text-rose-700 dark:text-rose-300">{error}</p>
          </div>
        )}

        {result && risk && staticInfo && !loading && (
          <div className="space-y-4">
            <section className="surface-card p-4">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="relative w-20 h-20">
                    <svg viewBox="0 0 80 80" className="w-20 h-20 -rotate-90">
                      <circle
                        cx="40"
                        cy="40"
                        r="34"
                        fill="none"
                        strokeWidth="8"
                        className="stroke-slate-200 dark:stroke-slate-700"
                      />
                      <circle
                        cx="40"
                        cy="40"
                        r="34"
                        fill="none"
                        strokeWidth="8"
                        strokeLinecap="round"
                        strokeDasharray={2 * Math.PI * 34}
                        strokeDashoffset={2 * Math.PI * 34 * (1 - scoreColor / 100)}
                        className={
                          scoreColor >= 80
                            ? 'stroke-rose-500'
                            : scoreColor >= 60
                              ? 'stroke-orange-500'
                              : scoreColor >= 35
                                ? 'stroke-amber-500'
                                : scoreColor >= 15
                                  ? 'stroke-yellow-500'
                                  : 'stroke-emerald-500'
                        }
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-lg font-bold text-heading leading-none">{risk.risk_score}</span>
                      <span className="text-micro font-mono text-muted">/100</span>
                    </div>
                  </div>
                  <div>
                    <span
                      className={`inline-block text-micro font-mono uppercase tracking-wider px-2 py-1 rounded border mb-2 ${
                        VERDICT_STYLE[risk.verdict] ?? VERDICT_STYLE['No Strong Threat Evidence']
                      }`}
                    >
                      {risk.verdict}
                    </span>
                    <p className="text-sm text-heading font-mono break-all">{result.url}</p>
                    <p className="text-mini font-mono text-muted">
                      hostname {result.hostname}
                      {result.ip_address ? ` · resolved ${result.ip_address}` : ''}
                      {risk.confidence > 0 ? ` · confidence ${risk.confidence}%` : ''}
                    </p>
                  </div>
                </div>
              </div>
              <p className="mt-3 text-sm text-muted border-t border-line-1 pt-3">{risk.recommendation}</p>
            </section>

            <section className="surface-card p-4">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted mb-3">
                Provider Contribution
              </h2>
              <div className="space-y-2.5">
                {providerRows.map((p) => (
                  <div key={p.key} className="flex items-center gap-3">
                    <span className="w-40 text-sm font-medium text-heading flex-shrink-0">{p.label}</span>
                    <div className="flex-1 h-2 rounded-full bg-surface-300 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${p.score > 0 ? 'bg-rose-500/70' : 'bg-emerald-500/50'}`}
                        style={{ width: `${Math.min((p.score / p.max) * 100, 100)}%` }}
                      />
                    </div>
                    <span className="w-16 text-right text-micro font-mono text-muted flex-shrink-0">
                      {p.online ? `${p.score}/${p.max}` : 'offline'}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            <section className="surface-card p-4">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted mb-3">
                Static Signals ({staticInfo.static_score}/10)
              </h2>
              <div className="flex flex-wrap gap-1.5">
                {staticInfo.flags.length > 0 ? (
                  staticInfo.flags.map((f) => (
                    <span
                      key={f}
                      className="text-mini font-mono uppercase tracking-wider px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                    >
                      {f}
                    </span>
                  ))
                ) : (
                  <span className="text-mini font-mono uppercase tracking-wider px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                    no red flags
                  </span>
                )}
              </div>
              {staticInfo.suspicious_keywords.length > 0 && (
                <p className="text-mini font-mono text-muted mt-2">
                  keywords: {staticInfo.suspicious_keywords.join(', ')}
                </p>
              )}
            </section>

            {risk.evidence.length > 0 && (
              <section className="surface-card p-4">
                <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted mb-3">Evidence Chain</h2>
                <ul className="space-y-1.5">
                  {risk.evidence.map((line, i) => (
                    <li key={`${i}-${line}`} className="text-xs font-mono text-heading flex gap-2">
                      <span className="text-muted">›</span>
                      {line}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {(risk.positive_findings.length > 0 || risk.informational_findings.length > 0) && (
              <section className="surface-card p-4">
                <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted mb-3">Findings</h2>
                {risk.positive_findings.length > 0 && (
                  <ul className="space-y-1.5 mb-2">
                    {risk.positive_findings.map((line, i) => (
                      <li key={`p-${i}`} className="text-xs font-mono text-rose-700 dark:text-rose-300 flex gap-2">
                        <span className="text-rose-400">!</span>
                        {line}
                      </li>
                    ))}
                  </ul>
                )}
                {risk.informational_findings.length > 0 && (
                  <ul className="space-y-1.5">
                    {risk.informational_findings.map((line, i) => (
                      <li key={`i-${i}`} className="text-xs font-mono text-muted flex gap-2">
                        <span className="text-muted">i</span>
                        {line}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            )}

            {result.providers.whois && result.providers.whois.registrar && (
              <div className="text-center text-micro text-muted">
                WHOIS registrar: {result.providers.whois.registrar}
                {result.providers.whois.created ? ` · created ${result.providers.whois.created}` : ''}
                {result.providers.whois.dnssec ? ` · dnssec ${result.providers.whois.dnssec}` : ''}
              </div>
            )}
          </div>
        )}

        <div className="text-center pt-6 pb-2 text-xs text-muted border-t border-line-1">
          Correlated scoring weights carried over from the{' '}
          <a
            href="https://github.com/Zep11/IntelX-Phishing-Intelligence-Framework"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            IntelX Phishing Intelligence Framework
          </a>{' '}
          (MIT): VirusTotal 35 / Google Safe Browsing 30 / URLScan 30 / AbuseIPDB 20 / WHOIS 20, capped at 100.
        </div>
      </div>
    </DataPageLayout>
  );
}
