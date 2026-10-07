import { logCatch } from '../../lib/log';
import { useState, useRef, useEffect, useCallback } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import {
  Bug,
  ExternalLink,
  Globe,
  Hash,
  Info,
  Loader2,
  Mail,
  Search,
  Shield,
  ShieldAlert,
  Zap,
  FileText,
  Sparkles,
} from 'lucide-react';
import { sanitizeAiHtml } from '../../lib/sanitize-html';
// Shared with VeraChat/Copilot — this file used to carry its own byte-for-byte
// copy of the same renderer (minus the fenced-code handling), which meant two
// subtly different renderers for identical input.
import { renderMarkdown } from '../../components/threatintel/ChatShared';

interface Source {
  name: string;
  items: number;
  data: unknown;
}

interface ConfidenceScore {
  level: string;
  score: number;
  admiralty?: { reliability: string; credibility: number; label: string };
  sources_contributing: number;
  contradictory_sources: number;
  reasoning: string;
}

interface CopilotResponse {
  query: string;
  query_type: string;
  narrative: string;
  sources: Source[];
  model_used: string;
  processed_at: string;
  _meta?: { total_sources: number; total_items: number };
  confidence?: ConfidenceScore;
}

const IOC_PATTERNS = {
  ip: /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/,
  domain: /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
  hash_md5: /^[a-fA-F0-9]{32}$/,
  hash_sha1: /^[a-fA-F0-9]{40}$/,
  hash_sha256: /^[a-fA-F0-9]{64}$/,
  hash_sha512: /^[a-fA-F0-9]{128}$/,
  url: /^https?:\/\//,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  cve: /^CVE-\d{4}-\d{4,}$/,
};

function detectIOCType(q: string): string {
  const trimmed = q.trim();
  if (IOC_PATTERNS.cve.test(trimmed)) return 'cve';
  if (IOC_PATTERNS.hash_sha256.test(trimmed)) return 'sha256';
  if (IOC_PATTERNS.hash_sha512.test(trimmed)) return 'sha512';
  if (IOC_PATTERNS.hash_sha1.test(trimmed)) return 'sha1';
  if (IOC_PATTERNS.hash_md5.test(trimmed)) return 'md5';
  if (IOC_PATTERNS.email.test(trimmed)) return 'email';
  if (IOC_PATTERNS.url.test(trimmed)) return 'url';
  if (IOC_PATTERNS.ip.test(trimmed)) return 'ip';
  if (IOC_PATTERNS.domain.test(trimmed)) return 'domain';
  return 'unknown';
}

const IOC_ICONS: Record<string, typeof Shield> = {
  ip: Globe,
  domain: Globe,
  md5: Hash,
  sha1: Hash,
  sha256: Hash,
  sha512: Hash,
  url: ExternalLink,
  email: Mail,
  cve: Bug,
  unknown: Search,
};

const IOC_COLORS: Record<string, string> = {
  ip: 'text-brand-600 dark:text-brand-400',
  domain: 'text-cyan-600 dark:text-cyan-400',
  md5: 'text-violet-600 dark:text-violet-400',
  sha1: 'text-violet-600 dark:text-violet-400',
  sha256: 'text-violet-600 dark:text-violet-400',
  sha512: 'text-violet-600 dark:text-violet-400',
  url: 'text-orange-600 dark:text-orange-400',
  email: 'text-pink-600 dark:text-pink-400',
  cve: 'text-amber-600 dark:text-amber-400',
  unknown: 'text-slate-500',
};

const QUERY_EXAMPLES = [
  { label: '8.8.8.8', type: 'IP address', query: '8.8.8.8' },
  { label: 'google.com', type: 'Domain', query: 'google.com' },
  { label: 'CVE-2024-1709', type: 'CVE', query: 'CVE-2024-1709' },
  { label: 'd41d8cd98f00b204e9800998ecf8427e', type: 'MD5 hash', query: 'd41d8cd98f00b204e9800998ecf8427e' },
];

const TYPE_BADGES: Record<string, { label: string; color: string }> = {
  cve: { label: 'CVE', color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' },
  ip: { label: 'IP', color: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300' },
  domain: { label: 'Domain', color: 'bg-sky-100 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300' },
  hash: { label: 'Hash', color: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300' },
  actor: { label: 'Actor', color: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300' },
  ransomware: {
    label: 'Ransomware',
    color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  },
  generic: {
    label: 'General',
    color: 'bg-slate-100 text-slate-700 dark:bg-surface-300 dark:text-slate-300',
  },
};

export default function DfirCopilot(): JSX.Element {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CopilotResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [narrativeHtml, setNarrativeHtml] = useState('');

  const iocType = detectIOCType(query);
  const Icon = IOC_ICONS[iocType] || Search;

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const md = result?.narrative;
    if (!md) {
      setNarrativeHtml('');
      return;
    }
    let cancelled = false;
    void (async () => {
      const { default: DOMPurify } = await import('isomorphic-dompurify');
      const safeMd = DOMPurify.sanitize(md, { ALLOWED_TAGS: [] });
      const safe = await sanitizeAiHtml(renderMarkdown(safeMd));
      if (!cancelled) setNarrativeHtml(safe);
    })();
    return () => {
      cancelled = true;
    };
  }, [result?.narrative]);

  const badge = result?.query_type ? TYPE_BADGES[result.query_type] : null;

  const investigate = useCallback(async (q: string) => {
    if (!q.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/copilot/investigate', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: q.trim() }),
      });
      if (!res.ok) {
        const body = await res.text();
        let msg = `HTTP ${res.status}`;
        try {
          msg = (JSON.parse(body) as { error?: string }).error ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* */
        }
        throw new Error(msg);
      }
      setResult(await res.json());
    } catch (e) {
      logCatch(e);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Zap size={28} />}
      title="DFIR Copilot"
      maxWidthClass="max-w-5xl"
      description="AI-powered IOC investigation. Paste any IP, domain, hash, URL, email, or CVE - get a multi-source verdict with confidence scoring and actionable recommendations."
    >
      {/* Search */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          investigate(query);
        }}
        className="surface-card p-4 mb-6"
      >
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Icon size={16} className={`absolute left-3 top-1/2 -translate-y-1/2 ${IOC_COLORS[iocType]}`} />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Paste an IOC - IP, domain, hash, URL, email, or CVE…"
              aria-label="Indicator of compromise to investigate"
              className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:focus:border-brand-400"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-4 py-2.5 rounded-xl border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:border-brand-500/70 disabled:opacity-50 transition-colors"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            Investigate
          </button>
        </div>
        {iocType !== 'unknown' && (
          <div className="mt-2 text-mini font-mono text-muted">
            Detected: <span className={IOC_COLORS[iocType]}>{iocType.toUpperCase()}</span>
          </div>
        )}
      </form>

      {/* Quick examples */}
      {!result && !loading && (
        <div className="mb-6">
          <div className="text-micro font-mono font-semibold uppercase tracking-wider text-muted mb-2">
            Quick examples
          </div>
          <div className="flex flex-wrap gap-2">
            {QUERY_EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                type="button"
                onClick={() => {
                  setQuery(ex.label);
                  investigate(ex.label);
                }}
                className="text-xs font-mono px-3 py-1.5 rounded-xl border border-line-1 text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
              >
                {ex.label} <span className="text-muted ml-1">({ex.type})</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 mb-6 flex items-center gap-3">
          <ShieldAlert size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
          <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}

      {loading && (
        <div role="status" aria-live="polite" className="py-16 text-center">
          <Loader2 size={32} className="mx-auto mb-4 animate-spin text-brand-500" aria-hidden="true" />
          <p className="font-mono text-sm text-muted">Gathering intelligence…</p>
          <p className="mt-1 font-mono text-xs text-muted">Querying threat data sources and generating narrative</p>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Header card */}
          <div className="surface-card p-5">
            <div className="flex items-start justify-between gap-4 mb-3">
              <div className="flex flex-wrap items-center gap-3">
                <h2 className="text-lg font-bold text-heading">{result.query}</h2>
                {badge && (
                  <span className={`rounded px-2 py-0.5 text-micro font-semibold uppercase ${badge.color}`}>
                    {badge.label}
                  </span>
                )}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs text-muted">
              <span>model: {result.model_used}</span>
              {result._meta && (
                <span>
                  {result._meta.total_sources} sources · {result._meta.total_items} data points
                </span>
              )}
              {result.confidence && (
                <span
                  className={`rounded px-1.5 py-0.5 ${
                    result.confidence.score >= 70
                      ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                      : result.confidence.score >= 40
                        ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                        : 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300'
                  }`}
                  title={result.confidence.reasoning}
                >
                  confidence: {result.confidence.score}/100 ({result.confidence.level})
                </span>
              )}
              <span>{new Date(result.processed_at).toLocaleString()}</span>
            </div>
            {result.sources.length > 0 && (
              <div className="mt-3 border-t border-line-1 pt-3">
                <div className="flex flex-wrap gap-1.5">
                  {result.sources.map((s, i) => (
                    <span
                      key={s.name}
                      className="inline-flex items-center gap-1 rounded border border-line-1 bg-surface-200 px-2 py-0.5 font-mono text-mini text-muted"
                    >
                      <span className="font-bold text-muted">{i + 1}.</span>
                      {s.name}
                      <span className="text-muted">({s.items})</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Narrative report */}
          <div className="overflow-hidden surface-card">
            <div className="flex items-center gap-2 border-b border-line-1 bg-surface-200/80 px-6 py-3 dark:bg-surface-200/40">
              <FileText size={15} className="text-brand-600 dark:text-brand-400" />
              <span className="text-sm font-semibold text-body">Investigation Report</span>
              {result._meta && (
                <span className="ml-auto font-mono text-mini text-muted">
                  {result._meta.total_items} data points across {result._meta.total_sources} sources
                </span>
              )}
            </div>
            <div
              className="px-6 py-5 text-heading [&_h2]:text-lg [&_h2]:font-bold [&_h2]:mt-6 [&_h2]:mb-2 [&_h2]:pb-1 [&_h2]:border-b [&_h2]:border-line-1 [&_h2]:dark:border-line-1 [&_h3]:text-base [&_h3]:font-semibold [&_h3]:mt-4 [&_h3]:mb-1.5 [&_p]:text-sm [&_p]:leading-relaxed [&_p]:mb-2 [&_p]:text-body [&_p]:dark:text-inverted [&_ul]:space-y-0.5 [&_ul]:my-1.5 [&_ol]:space-y-1 [&_ol]:my-1.5 [&_li]:ml-4 [&_li]:pl-1 [&_li]:text-sm [&_li]:text-body [&_li]:dark:text-inverted [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:bg-surface-300 [&_code]:dark:bg-surface-200 [&_code]:text-xs [&_code]:font-mono [&_code]:text-brand-700 [&_code]:dark:text-brand-300"
              dangerouslySetInnerHTML={{ __html: narrativeHtml }}
            />
          </div>

          {/* Source details */}
          {result.sources.length > 0 && (
            <details className="group">
              <summary className="flex cursor-pointer items-center gap-2 text-sm font-medium text-muted hover:text-body dark:hover:text-inverted">
                <Sparkles size={14} />
                Raw source data ({result.sources.length} sources)
              </summary>
              <div className="mt-3 space-y-3">
                {result.sources.map((s) => (
                  <details key={s.name} className="rounded-xl border border-line-1 bg-surface-200/30 p-3">
                    <summary className="cursor-pointer text-xs font-medium">
                      {s.name} ({s.items} items)
                    </summary>
                    <pre className="mt-2 max-h-48 overflow-auto overflow-x-auto rounded bg-surface-300 p-2 font-mono text-mini">
                      {JSON.stringify(s.data, null, 2)}
                    </pre>
                  </details>
                ))}
              </div>
            </details>
          )}

          {/* Metadata */}
          <div className="text-mini font-mono text-muted flex items-center gap-2">
            <Info size={12} />
            Investigated at {result.processed_at} · IOC type: {result.query_type} · Model: {result.model_used}
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}
