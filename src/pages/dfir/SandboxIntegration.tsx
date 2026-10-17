import { useState, useCallback } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { useNoindex } from '../../lib/use-noindex';
import { Upload, Loader2, AlertTriangle, Shield, ExternalLink, Globe, FileText, Activity } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface SandboxResult {
  source: string;
  status: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  score?: number;
  verdict?: string;
  summary?: string;
  link?: string;
  families?: string[];
  tags?: string[];
  behaviors?: Array<{ severity: string; category: string; description: string }>;
}

interface SandboxResponse {
  hash: string;
  results: SandboxResult[];
  consensus: { verdict: string; confidence: number; sources_agreeing: number };
}

const STATUS_BADGE: Record<string, string> = {
  malicious: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
  suspicious: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  clean: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
  unknown: 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted',
};

const SOURCE_ICONS: Record<string, typeof Shield> = {
  VirusTotal: Shield,
  MalwareBazaar: FileText,
  'ANY.RUN': Activity,
  Triage: Globe,
  'Hybrid Analysis': Activity,
  'Joe Sandbox': Shield,
};

export default function SandboxIntegration(): JSX.Element {
  useNoindex();
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SandboxResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = useCallback(async () => {
    if (!hash.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`/api/v1/sandbox/lookup?hash=${encodeURIComponent(hash.trim())}`);
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const p = JSON.parse(body) as { error?: string };
          msg = p.error ?? msg;
        } catch (_catchErr) {
          console.error('SandboxIntegration failed:', errMessage(_catchErr));
          /* ok */
        }
        throw new Error(msg);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setResult(await res.json());
    } catch (err) {
      console.error('SandboxIntegration failed:', errMessage(err));
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [hash]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      // Read file and compute hash client-side would be ideal,
      // but for now just show a message to use the hash directly.
      setError('Drop a hash string, not a file. Use the Malware Scanner to compute hashes first.');
    }
  }, []);

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Upload size={28} className="text-brand-600 dark:text-brand-400" /> Sandbox Integration
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Query multiple sandbox and malware analysis platforms with a single hash. Get consensus verdicts, behavioral
          analysis, and family attribution.
        </p>
      </div>

      {/* Supported Platforms */}
      <div className="flex flex-wrap gap-1.5 mb-6">
        {['VirusTotal', 'MalwareBazaar', 'ANY.RUN', 'Triage', 'Hybrid Analysis', 'Joe Sandbox', 'OTX'].map((s) => (
          <span key={s} className="px-2.5 py-1 rounded-xl text-xs font-mono border border-line-1 text-muted">
            {s}
          </span>
        ))}
      </div>

      {/* Input */}
      <div className="surface-card/40 shadow-e1 p-5 mb-6" onDrop={handleDrop} onDragOver={(e) => e.preventDefault()}>
        <h2 className="font-display font-bold text-sm mb-3">File Hash</h2>
        <input
          type="text"
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void handleLookup()}
          placeholder="MD5, SHA-1, or SHA-256…"
          className="w-full bg-surface-200 border border-line-1 rounded-xl px-4 py-2.5 text-sm font-mono text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
        />
        <button
          onClick={handleLookup}
          disabled={loading || !hash.trim()}
          className="mt-3 w-full px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}
          {loading ? 'Querying sandboxes…' : 'Lookup Hash'}
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 mb-6 flex items-center gap-3">
          <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
          <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-5 animate-fade-in-up">
          {/* Consensus */}
          <div
            className={`rounded-xl border p-5 ${
              result.consensus.verdict === 'malicious'
                ? 'border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30'
                : result.consensus.verdict === 'suspicious'
                  ? 'border-amber-300/70 dark:border-amber-800/60 bg-amber-50/60 dark:bg-amber-950/30'
                  : 'border-emerald-300/70 dark:border-emerald-800/60 bg-emerald-50/60 dark:bg-emerald-950/30'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <h2 className="font-display font-bold text-sm">Consensus Verdict</h2>
              <span className={`text-xs font-mono px-2 py-0.5 rounded ${STATUS_BADGE[result.consensus.verdict]}`}>
                {result.consensus.verdict}
              </span>
            </div>
            <div className="text-sm text-muted">
              {result.consensus.sources_agreeing} of {result.results.length} sources agree · Confidence:{' '}
              {result.consensus.confidence}%
            </div>
            <div className="text-micro font-mono text-muted mt-1 truncate">Hash: {result.hash}</div>
          </div>

          {/* Per-Source Results */}
          {result.results.map((r, i) => {
            const Icon = SOURCE_ICONS[r.source] ?? Shield;
            return (
              <div key={i} className="surface-card/40 shadow-e1 p-5">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Icon size={14} className="text-brand-600 dark:text-brand-400" />
                    <span className="font-display font-bold text-sm">{r.source}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-micro font-mono px-1.5 py-0.5 rounded ${STATUS_BADGE[r.status]}`}>
                      {r.status}
                    </span>
                    {r.score !== undefined && <span className="text-xs font-mono text-muted">{r.score}%</span>}
                    {r.link && (
                      <a
                        href={sanitizeUrl(r.link) || undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-muted hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                      >
                        <ExternalLink size={14} />
                      </a>
                    )}
                  </div>
                </div>
                {r.summary && <p className="text-xs text-muted mb-2">{r.summary}</p>}
                {r.families && r.families.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-2">
                    {r.families.map((f, j) => (
                      <span
                        key={j}
                        className="text-micro font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300"
                      >
                        {f}
                      </span>
                    ))}
                  </div>
                )}
                {r.tags && r.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {r.tags.map((t, j) => (
                      <span
                        key={j}
                        className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 text-muted"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
                {r.behaviors && r.behaviors.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {r.behaviors.map((b, j) => (
                      <div key={j} className="flex items-center gap-2 text-xs">
                        <span
                          className={`text-micro font-mono px-1.5 py-0.5 rounded ${b.severity === 'high' ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300' : b.severity === 'medium' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' : 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted'}`}
                        >
                          {b.severity}
                        </span>
                        <span className="text-muted">{b.category}:</span>
                        <span className="text-body">{b.description}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
