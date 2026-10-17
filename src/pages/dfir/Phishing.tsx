import { errMessage, logCatch } from '../../lib/log';
import { useState, useRef, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Textarea } from '../../components/ui/Input';
import {
  ScanText,
  Search,
  Crosshair,
  Fingerprint,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Eye,
  Globe,
  FileText,
  ExternalLink,
  Lock,
  Shield,
} from 'lucide-react';
import type { PhishingAnalysisResponse } from '../../lib/dfir/types';
import { VerdictChip } from '../../components/dfir/VerdictChip';
import { HeaderTable } from '../../components/dfir/HeaderTable';
import { AuthResultsChips } from '../../components/dfir/AuthResultsChips';
import { UrlList } from '../../components/dfir/UrlList';
import { recordHistory } from '../../lib/dfir/history';
import { RelatedActors } from '../../components/dfir/RelatedActors';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';
import { structuralFingerprint, submitFingerprint, type FingerprintResult } from '../../lib/dfir/phishing-fingerprint';
import { SEVERITY_TONE } from '../../components/severity';

export default function Phishing(): JSX.Element {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialInput = searchParams.get('q') ?? '';
  const [input, setInput] = useState(initialInput);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fpUrl, setFpUrl] = useState('');
  const [fpLoading, setFpLoading] = useState(false);
  const [fpResult, setFpResult] = useState<FingerprintResult | null>(null);
  const [fpHash, setFpHash] = useState<string | null>(null);
  const [fpError, setFpError] = useState<string | null>(null);
  const resultRef = useRef<HTMLHeadingElement>(null);
  const submitRef = useRef<AbortController | null>(null);

  // ─── URL Auto-Analysis state ─────────────────────────────────────────────
  interface FormField {
    type: string;
    name: string;
    placeholder: string;
  }
  interface AutoAnalysisReport {
    url: string;
    fetched: boolean;
    status?: number;
    title?: string;
    forms: FormField[];
    external_links: number;
    scripts: number;
    iframes: number;
    has_password_field: boolean;
    has_submit_button: boolean;
    suspicious_keywords: string[];
    risk_score: number;
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    ip?: string;
    error?: string;
  }
  const [aaUrl, setAaUrl] = useState('');
  const [aaLoading, setAaLoading] = useState(false);
  const [aaResult, setAaResult] = useState<AutoAnalysisReport | null>(null);
  const [aaError, setAaError] = useState<string | null>(null);

  const aaRef = useRef<AbortController | null>(null);
  const fpRef = useRef<AbortController | null>(null);

  const runAutoAnalyze = async () => {
    const u = aaUrl.trim();
    if (!u) return;
    aaRef.current?.abort();
    const ctrl = new AbortController();
    aaRef.current = ctrl;
    setAaLoading(true);
    setAaResult(null);
    setAaError(null);
    try {
      const r = await fetch(`/api/v1/phishing/auto-analyze?url=${encodeURIComponent(u)}`, {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) {
        setAaError(`${r.status}`);
        return;
      }
      setAaResult((await r.json()) as AutoAnalysisReport);
    } catch (e) {
      logCatch(e);
      if (ctrl.signal.aborted) return;
      setAaError(errMessage(e, 'analysis failed'));
    }
    if (!ctrl.signal.aborted) setAaLoading(false);
  };

  const runFingerprint = async () => {
    const url = fpUrl.trim();
    if (!url) return;
    fpRef.current?.abort();
    const ctrl = new AbortController();
    fpRef.current = ctrl;
    setFpLoading(true);
    setFpResult(null);
    setFpHash(null);
    setFpError(null);
    try {
      const r = await fetch('/api/v1/phishing/fetch-page', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(30_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) {
        const err = (await r.json().catch(() => null)) as { error?: string } | null;
        throw new Error(err?.error ?? `${r.status}`);
      }
      const { html } = (await r.json()) as { html: string };
      const hash = await structuralFingerprint(html);
      setFpHash(hash);
      const fp = await submitFingerprint(hash, url);
      setFpResult(fp);
    } catch (err) {
      logCatch(err);
      if (ctrl.signal.aborted) return;
      setFpError(errMessage(err, 'fingerprint failed'));
    } finally {
      if (!ctrl.signal.aborted) setFpLoading(false);
    }
  };

  const sendToExtractor = () => {
    if (!input.trim()) return;
    try {
      sessionStorage.setItem('ioc-extractor-pipe', input);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* sessionStorage unavailable - silent */
    }
    navigate('/dfir/extract?from=phishing');
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    submitRef.current?.abort();
    const ctrl = new AbortController();
    submitRef.current = ctrl;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const r = await fetch('/api/v1/phishing/analyze', {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: input,
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(30_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) {
        const body = (await r.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? `${r.status}`);
      }
      const r2 = (await r.json()) as PhishingAnalysisResponse;
      setResult(r2);
      const indicator = String(r2.headers['subject'] ?? r2.headers['from'] ?? 'email');
      recordHistory({ tool: 'phishing', indicator, verdict: r2.verdict, score: r2.score });
      setTimeout(() => resultRef.current?.focus(), 0);
    } catch (err) {
      logCatch(err);
      if (ctrl.signal.aborted) return;
      setError(errMessage(err, 'analysis failed'));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Phishing Email Analyzer</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Paste raw email source. We parse headers, check SPF/DKIM/DMARC results, extract URLs, and compute a risk
          score. URLs link straight into the IOC checker.
        </p>
      </div>

      <form onSubmit={onSubmit} className="mb-10">
        <label htmlFor="phishing-input" className="sr-only">
          Raw email source for phishing analysis
        </label>
        <Textarea
          id="phishing-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Paste raw email here (View Original / Show Source from your mail client)"
          rows={6}
          aria-label="Raw email source"
          className="sm:text-xs sm:rows-12"
          style={{ minHeight: '12rem' }}
        />
        <div className="mt-3 flex flex-col-reverse sm:flex-row sm:justify-end gap-2">
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="w-full sm:w-auto px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 inline-flex items-center justify-center gap-2 transition-colors"
          >
            <ScanText size={16} /> Analyze
          </button>
        </div>
      </form>

      {loading && (
        <p role="status" className="font-mono text-muted">
          Analyzing...
        </p>
      )}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="space-y-6">
          <section className="surface-card p-6">
            <div className="flex items-baseline justify-between mb-3 flex-wrap gap-2">
              <h2 ref={resultRef} tabIndex={-1} className="font-display font-bold text-2xl focus:outline-none">
                Risk verdict
              </h2>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={sendToExtractor}
                  className="inline-flex items-center gap-1.5 text-mini font-mono px-2 py-1 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20 transition-colors"
                  title="Send the raw email body to the IOC Extractor for full URL/IP/domain/hash extraction"
                >
                  <Search size={11} /> extract IOCs from raw →
                </button>
                <VerdictChip verdict={result.verdict} />
              </div>
            </div>
            <div className="font-mono text-sm text-muted">
              score: <span className="text-heading">{result.score}</span> / 100
            </div>
            {result.flags.length > 0 && (
              <ul className="mt-3 space-y-1 list-disc list-inside text-sm text-muted">
                {result.flags.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            )}
          </section>
          <AuthResultsChips auth={result.auth} />
          <HeaderTable headers={result.headers} />
          <UrlList urls={result.urls} />
          {result.urls.length > 0 && (
            <div className="flex gap-2">
              <Link
                to={`/dfir/url-risk?url=${encodeURIComponent(result.urls[0]!)}`}
                className="inline-flex items-center gap-1.5 text-mini font-mono px-3 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:bg-rose-500/20"
              >
                <Crosshair size={11} /> Check all URLs ({result.urls.length})
              </Link>
            </div>
          )}
          <RelatedActors
            hints={{
              tags: ['phishing', 'spear-phishing'],
              techniques: ['T1566.001', 'T1566.002'],
              free_text: result.urls,
            }}
          />
        </div>
      )}
      <section id="fingerprint" className="mt-12 surface-card p-5">
        <h2 className="text-lg font-display font-semibold mb-2 flex items-center gap-2">
          <Fingerprint size={16} className="text-brand-600 dark:text-brand-400" />
          Phishing Kit Fingerprint
        </h2>
        <p className="text-xs text-muted mb-4 max-w-xl">
          Paste a suspected phishing URL. The page content is fetched server-side, then a structural fingerprint
          (stripped of text/scripts/styles) is hashed in your browser. The hash and the submitted URL are sent to
          aggregate sightings; the URL is retained for up to 30 days and may be shown to others as a sample URL.
        </p>
        <div className="flex gap-2">
          <input
            type="url"
            value={fpUrl}
            onChange={(e) => setFpUrl(e.target.value)}
            placeholder="https://phishing-site.example.com/login"
            aria-label="Phishing URL to fingerprint"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
          <button
            type="button"
            onClick={() => void runFingerprint()}
            disabled={fpLoading || !fpUrl.trim()}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20 disabled:opacity-40"
          >
            {fpLoading && <Loader2 size={12} className="animate-spin" />}
            {fpLoading ? 'fingerprinting…' : 'fingerprint'}
          </button>
        </div>
        {fpError && (
          <p className="mt-3 text-xs font-mono text-rose-600 dark:text-rose-400 flex items-center gap-1.5">
            <AlertTriangle size={12} /> {fpError}
          </p>
        )}
        {fpResult && fpHash && (
          <div className="mt-3 space-y-2">
            <div className="flex items-center gap-2">
              {fpResult.match ? (
                <span className="inline-flex items-center gap-1 text-xs font-mono text-amber-700 dark:text-amber-300">
                  <AlertTriangle size={12} /> Known kit
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs font-mono text-emerald-700 dark:text-emerald-300">
                  <CheckCircle2 size={12} /> New fingerprint
                </span>
              )}
              {fpResult.count && (
                <span className="text-micro font-mono text-muted">
                  seen {fpResult.count} time{fpResult.count === 1 ? '' : 's'}
                </span>
              )}
            </div>
            {fpResult.first_seen && (
              <p className="text-mini font-mono text-muted">
                first seen: {new Date(fpResult.first_seen).toLocaleString()}
              </p>
            )}
            {fpResult.urls && fpResult.urls.length > 0 && (
              <div className="text-mini font-mono text-muted">
                <span className="text-muted">sample URLs:</span>
                <ul className="mt-1 space-y-0.5">
                  {fpResult.urls.map((u) => (
                    <li key={u} className="truncate max-w-lg" title={u}>
                      {u}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <p className="text-micro font-mono text-muted break-all" title={fpHash}>
              hash: {fpHash.slice(0, 16)}…{fpHash.slice(-8)}
            </p>
          </div>
        )}
      </section>

      {/* ─── URL Auto-Analysis ─────────────────────────────────────────────── */}
      <section id="auto-analyze" className="mt-12 surface-card p-5">
        <h2 className="text-lg font-display font-semibold mb-2 flex items-center gap-2">
          <Eye size={16} className="text-brand-600 dark:text-brand-400" />
          URL Auto-Analysis
        </h2>
        <p className="text-xs text-muted mb-4 max-w-xl">
          Enter a URL to fetch and scan for phishing indicators - form extraction, password fields, suspicious keywords,
          scripts/iframes, external links, DNS resolution, and auto risk score.
        </p>
        <div className="flex gap-2">
          <input
            type="url"
            value={aaUrl}
            onChange={(e) => setAaUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void runAutoAnalyze()}
            placeholder="https://example.com/login"
            aria-label="URL to auto-analyze"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
          <button
            type="button"
            onClick={() => void runAutoAnalyze()}
            disabled={aaLoading || !aaUrl.trim()}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20 disabled:opacity-40"
          >
            {aaLoading && <Loader2 size={12} className="animate-spin" />}
            {aaLoading ? 'analyzing…' : 'analyze'}
          </button>
        </div>
        {aaError && (
          <p className="mt-3 text-xs font-mono text-rose-600 dark:text-rose-400 flex items-center gap-1.5">
            <AlertTriangle size={12} /> {aaError}
          </p>
        )}
        {aaResult && (
          <div className="mt-4 space-y-4">
            {/* Risk header */}
            <div className={`rounded-xl border p-4 ${SEVERITY_TONE[aaResult.risk_level]}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="font-display font-bold flex items-center gap-2 text-sm">
                  <Shield size={14} />
                  {aaResult.risk_level.toUpperCase()}
                  <span className="text-xs font-mono opacity-70">({aaResult.risk_score}/100)</span>
                </span>
                <span
                  className={`text-micro font-mono px-2 py-0.5 rounded ${aaResult.fetched ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300'}`}
                >
                  {aaResult.fetched ? `HTTP ${aaResult.status}` : 'Unreachable'}
                </span>
              </div>
              <code className="text-mini font-mono text-muted break-all block">{aaResult.url}</code>
              {aaResult.title && <p className="text-xs mt-1.5 font-semibold">{aaResult.title}</p>}
              {aaResult.ip && (
                <p className="text-micro font-mono text-muted mt-1 flex items-center gap-1">
                  <Globe size={10} /> {aaResult.ip}
                </p>
              )}
            </div>

            {/* Key indicators */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="rounded-xl border border-line-1 bg-surface-200/50 p-3">
                <p className="text-micro font-mono text-muted flex items-center gap-1">
                  <Lock size={10} /> Password field
                </p>
                <p
                  className={`text-sm font-bold ${aaResult.has_password_field ? 'text-rose-500' : 'text-emerald-500'}`}
                >
                  {aaResult.has_password_field ? 'YES' : 'NO'}
                </p>
              </div>
              <div className="rounded-xl border border-line-1 bg-surface-200/50 p-3">
                <p className="text-micro font-mono text-muted flex items-center gap-1">
                  <FileText size={10} /> Fields
                </p>
                <p className="text-sm font-bold">{aaResult.forms.length}</p>
              </div>
              <div className="rounded-xl border border-line-1 bg-surface-200/50 p-3">
                <p className="text-micro font-mono text-muted flex items-center gap-1">
                  <ExternalLink size={10} /> Ext. links
                </p>
                <p className="text-sm font-bold">{aaResult.external_links}</p>
              </div>
              <div className="rounded-xl border border-line-1 bg-surface-200/50 p-3">
                <p className="text-micro font-mono text-muted flex items-center gap-1">
                  <FileText size={10} /> Scripts
                </p>
                <p className="text-sm font-bold">{aaResult.scripts}</p>
              </div>
            </div>

            {/* Suspicious keywords */}
            {aaResult.suspicious_keywords.length > 0 && (
              <div className="rounded-xl border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-900/10 p-3">
                <p className="text-micro font-bold uppercase tracking-[0.15em] text-amber-700 dark:text-amber-400 font-mono mb-1.5 flex items-center gap-1">
                  <AlertTriangle size={10} /> Keywords ({aaResult.suspicious_keywords.length})
                </p>
                <div className="flex flex-wrap gap-1">
                  {aaResult.suspicious_keywords.map((kw) => (
                    <span
                      key={kw}
                      className="text-micro font-mono px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-200"
                    >
                      {kw}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Form fields */}
            {aaResult.forms.length > 0 && (
              <div className="space-y-1">
                <p className="text-micro font-bold uppercase tracking-[0.15em] text-brand-600 dark:text-brand-400 font-mono">
                  Form Fields
                </p>
                {aaResult.forms.slice(0, 8).map((f, i) => (
                  <div key={i} className="flex gap-2 text-mini font-mono text-muted">
                    <span className="text-micro px-1.5 py-0.5 rounded bg-surface-300 uppercase">{f.type}</span>
                    <span className="text-brand-600 dark:text-brand-400">{f.name || '-'}</span>
                    <span className="text-muted">{f.placeholder || ''}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      <RelatedWikiArticles />
    </div>
  );
}
