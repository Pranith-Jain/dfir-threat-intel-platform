import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback } from 'react';
import { BackLink } from '../../components/BackLink';
import { ShareBar } from '../../components/intel/ShareBar';
import {
  Bug,
  Loader2,
  AlertTriangle,
  Copy,
  Download,
  Check,
  Shield,
  Crosshair,
  FileSearch,
  ListChecks,
} from 'lucide-react';
import { downloadText } from '../../lib/download';
const CONFIDENCE_BADGE: Record<string, string> = {
  high: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
  medium: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  low: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
};

export default function MalbriefAi(): JSX.Element {
  const [indicators, setIndicators] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    classification?: string;
    confidence?: string;
    mitre?: Array<{ id: string; name: string }>;
    signatures?: string[];
    huntingPivots?: string[];
    summary?: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleAnalyze = useCallback(async () => {
    if (!indicators.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/ai-summary', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          surface: 'malbrief-ai',
          date: new Date().toISOString().slice(0, 10),
          items: [
            {
              title: 'Malware Behavior Analysis',
              body: `Analyze these malware behavioral indicators and return a structured analysis:\n\n${indicators.trim()}\n\nReturn JSON with fields: classification (string), confidence (high/medium/low), mitre (array of {id, name}), signatures (array of pseudo-YARA/sigma strings), huntingPivots (array of strings), summary (string).`,
            },
          ],
        }),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const p = JSON.parse(body) as { message?: string; error?: string };
          msg = p.message ?? p.error ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* */
        }
        throw new Error(msg);
      }
      const data = (await res.json()) as { summary?: string };
      const raw = data.summary ?? '';
      let parsed: typeof result = null;
      try {
        const jsonMatch = raw.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsed = JSON.parse(jsonMatch[0]) as typeof result;
        }
      } catch (_catchErr) {
        logCatch(_catchErr);
        /* */
      }
      setResult(parsed ?? { summary: raw });
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [indicators]);

  const copyResult = async () => {
    if (!result) return;
    const lines = ['# MALBRIEF-AI Malware Analysis', ''];
    if (result.classification)
      lines.push(`**Classification:** ${result.classification} (${result.confidence ?? 'N/A'})`);
    if (result.summary) lines.push(`\n## Analysis\n${result.summary}`);
    if (result.mitre?.length)
      lines.push(`\n## MITRE ATT&CK\n${result.mitre.map((m) => `- ${m.id}: ${m.name}`).join('\n')}`);
    if (result.signatures?.length)
      lines.push(`\n## Detection Signatures\n${result.signatures.map((s) => `- ${s}`).join('\n')}`);
    if (result.huntingPivots?.length)
      lines.push(`\n## Hunting Pivots\n${result.huntingPivots.map((p) => `- ${p}`).join('\n')}`);
    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* */
    }
  };

  const downloadReport = () => {
    if (!result) return;
    const lines = ['# MALBRIEF-AI Malware Behavior Briefing', `# Generated: ${new Date().toISOString()}`, ''];
    if (result.classification)
      lines.push(
        `## Classification\n\n**Malware:** ${result.classification}\n**Confidence:** ${result.confidence ?? 'N/A'}\n`
      );
    if (result.summary) lines.push(`## Analysis\n\n${result.summary}\n`);
    if (result.mitre?.length)
      lines.push(`## MITRE ATT&CK\n\n${result.mitre.map((m) => `- ${m.id} - ${m.name}`).join('\n')}\n`);
    if (result.signatures?.length)
      lines.push(`## Detection Signatures\n\n${result.signatures.map((s) => `- \`${s}\``).join('\n')}\n`);
    if (result.huntingPivots?.length)
      lines.push(`## Hunting Pivots\n\n${result.huntingPivots.map((p) => `- ${p}`).join('\n')}\n`);
    downloadText(lines.join('\n'), `malbrief-ai-${Date.now()}.md`, 'text/markdown');
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Bug size={28} className="text-brand-600 dark:text-brand-400" /> MALBRIEF-AI
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Submit behavioral indicators and get malware classification, MITRE ATT&CK mapping, detection signatures, and
          hunting pivot recommendations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="space-y-5">
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-baseline justify-between mb-2">
              <h2 className="font-display font-bold text-sm">Behavioral Indicators</h2>
              <span className="text-micro font-mono uppercase tracking-wider text-muted">required</span>
            </div>
            <textarea
              value={indicators}
              onChange={(e) => setIndicators(e.target.value)}
              rows={10}
              placeholder="Paste behavioral indicators, sandbox output, or malware analysis notes…"
              className="w-full rounded-xl border border-line-1 bg-surface-200 p-3 font-mono text-xs text-heading focus:outline-none focus:ring-2 focus:ring-brand-500/40"
            />
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading || !indicators.trim()}
            className="w-full px-6 py-3 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Analyzing…
              </>
            ) : (
              <>
                <Bug size={16} /> Analyze
              </>
            )}
          </button>
        </div>

        {/* Output Panel */}
        <div className="space-y-5">
          {error && (
            <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 flex items-start gap-3">
              <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-rose-700 dark:text-rose-300">Analysis failed</p>
                <p className="text-xs text-rose-600 dark:text-rose-400 mt-1 font-mono break-all">{error}</p>
              </div>
            </div>
          )}

          {loading && (
            <div className="surface-card/40 shadow-e1 p-10 text-center">
              <Loader2 size={32} className="text-brand-600 dark:text-brand-400 mx-auto mb-3 animate-spin" />
              <p className="text-sm text-body">Analyzing indicators…</p>
            </div>
          )}

          {result && !loading && (
            <>
              {result.classification && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h2 className="font-display font-bold text-sm flex items-center gap-2">
                      <Bug size={14} className="text-brand-600 dark:text-brand-400" /> Classification
                    </h2>
                    {result.confidence && (
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-xs font-mono ${CONFIDENCE_BADGE[result.confidence] ?? ''}`}
                      >
                        {result.confidence}
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-semibold text-heading">{result.classification}</p>
                </div>
              )}

              {result.mitre && result.mitre.length > 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                    <Shield size={14} className="text-amber-600 dark:text-amber-400" /> MITRE ATT&CK
                  </h2>
                  <div className="space-y-1.5">
                    {result.mitre.map((m, i) => (
                      <a
                        key={i}
                        href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-block mr-1.5 mb-1.5 px-2.5 py-1 rounded-xl border border-amber-300/50 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300 text-xs font-mono hover:border-amber-500/60 transition-colors"
                      >
                        {m.id}: {m.name}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {result.signatures && result.signatures.length > 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                    <FileSearch size={14} className="text-brand-600 dark:text-brand-400" /> Detection Signatures
                  </h2>
                  <div className="space-y-2">
                    {result.signatures.map((s, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <span className="text-brand-500 dark:text-brand-400 mt-0.5 text-xs">→</span>
                        <pre className="flex-1 bg-surface-200 rounded p-2 text-xs font-mono text-body overflow-x-auto border border-line-1 whitespace-pre-wrap">
                          {s}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {result.huntingPivots && result.huntingPivots.length > 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                    <Crosshair size={14} className="text-emerald-600 dark:text-emerald-400" /> Hunting Pivots
                  </h2>
                  <ul className="space-y-1.5 text-sm text-body">
                    {result.huntingPivots.map((p, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-emerald-500 dark:text-emerald-400 mt-0.5">+</span>
                        <span>{p}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {result.summary && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-2 flex items-center gap-2">
                    <ListChecks size={14} className="text-brand-600 dark:text-brand-400" /> Analysis Summary
                  </h2>
                  <p className="text-sm text-body leading-relaxed whitespace-pre-wrap">{result.summary}</p>
                  <div className="mt-3 pt-3 border-t border-line-1">
                    <ShareBar
                      shareText={
                        result.summary
                          .split('\n')
                          .find((l) => l.trim())
                          ?.slice(0, 200) ||
                        (result.classification
                          ? `MALBRIEF-AI: ${result.classification}`
                          : 'MALBRIEF-AI malware analysis')
                      }
                      title="MALBRIEF-AI malware analysis"
                      size="sm"
                      label="Share:"
                    />
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                <button
                  onClick={copyResult}
                  className="flex-1 px-4 py-2 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors flex items-center justify-center gap-2"
                >
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                  {copied ? 'Copied' : 'Copy Report'}
                </button>
                <button
                  onClick={downloadReport}
                  className="flex-1 px-4 py-2 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors flex items-center justify-center gap-2"
                >
                  <Download size={13} /> Download .md
                </button>
              </div>
            </>
          )}

          {!result && !loading && !error && (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <Bug size={32} className="text-inverted dark:text-muted mx-auto mb-3" />
              <p className="text-sm text-muted">
                Paste behavioral indicators and click <span className="font-semibold">Analyze</span>
              </p>
              <p className="text-xs text-muted mt-1">Output: classification, MITRE, signatures, hunting pivots</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
