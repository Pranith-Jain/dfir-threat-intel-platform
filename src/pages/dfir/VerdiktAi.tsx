import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback, useRef } from 'react';
import { BackLink } from '../../components/BackLink';
import { ShareBar } from '../../components/intel/ShareBar';
import {
  Shield,
  Loader2,
  AlertTriangle,
  Copy,
  Download,
  Check,
  Search,
  Globe,
  Fingerprint,
  Network,
  FileText,
  Terminal,
} from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';
import { downloadText } from '../../lib/download';
function detectIocType(value: string): 'ip' | 'domain' | 'url' | 'hash' | 'unknown' {
  const v = value.trim();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return 'ip';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[a-f0-9]{32}$/i.test(v) || /^[a-f0-9]{40}$/i.test(v) || /^[a-f0-9]{64}$/i.test(v)) return 'hash';
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i.test(v)) return 'domain';
  return 'unknown';
}

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'File Hash',
  unknown: 'Unknown',
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  ip: <Network size={14} />,
  domain: <Globe size={14} />,
  url: <Globe size={14} />,
  hash: <Fingerprint size={14} />,
  unknown: <Search size={14} />,
};

export default function VerdiktAi(): JSX.Element {
  const [iocValue, setIocValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    iocType?: string;
    iocValue?: string;
    iocDetails?: Record<string, unknown>;
    enrichmentSources?: Array<{ name: string; status: 'success' | 'rate_limited' | 'error'; data?: string }>;
    narrative?: string;
    mitreTechniques?: string[];
    detectionQueries?: Array<{ siem: string; query: string }>;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedNarrative, setCopiedNarrative] = useState(false);

  const iocType = detectIocType(iocValue);
  const isHash = iocType === 'hash';
  const isIpOrDomain = iocType === 'ip' || iocType === 'domain';

  const enrichRef = useRef<AbortController | null>(null);

  const handleEnrich = useCallback(async () => {
    if (!iocValue.trim()) return;
    enrichRef.current?.abort();
    const ctrl = new AbortController();
    enrichRef.current = ctrl;
    setLoading(true);
    setError(null);
    setResult(null);

    const iocTypeDetected = detectIocType(iocValue);
    const cleanValue = iocValue.trim();

    try {
      let enrichmentData: Record<string, unknown> = {};

      // Step 1: IOC check
      if (isIpOrDomain || isHash) {
        const iocRes = await fetch(`/api/v1/ioc/check?q=${encodeURIComponent(cleanValue)}`, {
          signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
        });
        if (ctrl.signal.aborted) return;
        if (iocRes.ok) {
          enrichmentData = (await iocRes.json()) as Record<string, unknown>;
        }
      }

      // Step 2: AI analysis
      const aiRes = await fetch('/api/v1/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          surface: 'verdikt-ai',
          date: new Date().toISOString().slice(0, 10),
          items: [
            {
              title: 'IOC Analysis Request',
              body: [
                `IOC: ${cleanValue}`,
                `Type: ${iocTypeDetected}`,
                `Enrichment: ${JSON.stringify(enrichmentData)}`,
                `Generate: analyst narrative, MITRE ATT&CK techniques, detection queries in KQL, SPL, and Sigma formats.`,
              ].join('\n'),
            },
          ],
        }),
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(60_000)]),
      });
      if (ctrl.signal.aborted) return;

      let narrative = '';
      let mitreTechniques: string[] = [];
      let detectionQueries: Array<{ siem: string; query: string }> = [];

      if (aiRes.ok) {
        const aiData = (await aiRes.json()) as { summary?: string };
        const raw = aiData.summary ?? '';
        try {
          const jsonMatch = raw.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]) as {
              narrative?: string;
              mitreTechniques?: string[];
              detectionQueries?: Array<{ siem: string; query: string }>;
            };
            narrative = parsed.narrative ?? raw;
            mitreTechniques = parsed.mitreTechniques ?? [];
            detectionQueries = parsed.detectionQueries ?? [];
          } else {
            narrative = raw;
          }
        } catch (_catchErr) {
          logCatch(_catchErr);
          narrative = raw;
        }
      }

      setResult({
        iocType: iocTypeDetected,
        iocValue: cleanValue,
        iocDetails: Object.keys(enrichmentData).length > 0 ? enrichmentData : undefined,
        enrichmentSources: enrichmentData?.sources as
          Array<{ name: string; status: 'success' | 'rate_limited' | 'error'; data?: string }> | undefined,
        narrative,
        mitreTechniques,
        detectionQueries,
      });
    } catch (err) {
      logCatch(err);
      if (ctrl.signal.aborted) return;
      setError(errMessage(err));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, [iocValue, isIpOrDomain, isHash]);

  const copyNarrative = async () => {
    if (!result?.narrative) return;
    try {
      await navigator.clipboard.writeText(result.narrative);
      setCopiedNarrative(true);
      setTimeout(() => setCopiedNarrative(false), 1500);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* */
    }
  };

  const downloadReport = () => {
    if (!result) return;
    const lines = [
      '# VERDIKT-AI IOC Analysis Report',
      `# Generated: ${new Date().toISOString()}`,
      '',
      `**IOC:** ${result.iocValue}`,
      `**Type:** ${result.iocType}`,
      '',
      '## Analyst Narrative',
      result.narrative ?? '',
    ];
    if (result.mitreTechniques?.length) {
      lines.push('', '## MITRE ATT&CK', ...result.mitreTechniques.map((t) => `- ${t}`));
    }
    if (result.detectionQueries?.length) {
      lines.push('', '## Detection Queries');
      for (const q of result.detectionQueries) {
        lines.push(`\n### ${q.siem}\n${q.query}`);
      }
    }
    downloadText(lines.join('\n'), `verdikt-ai-${Date.now()}.md`, 'text/markdown');
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
          <Shield size={28} className="text-brand-600 dark:text-brand-400" /> VERDIKT-AI
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Combine IOC enrichment with AI analysis. Submit an IP, domain, URL, or hash - get enrichment from multiple
          sources plus an AI-generated analyst narrative.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="space-y-5">
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-baseline justify-between mb-2">
              <h2 className="font-display font-bold text-sm">IOC Value</h2>
              <span className="text-micro font-mono uppercase tracking-wider text-muted">required</span>
            </div>
            <div className="relative">
              <input
                type="text"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                placeholder="Enter IP, domain, URL, or hash…"
                className="w-full rounded-xl border border-line-1 bg-surface-200 p-3 pr-20 text-sm text-heading focus:outline-none focus:ring-2 focus:ring-brand-500/40 font-mono"
              />
              {iocValue.trim() && (
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1 px-2 py-1 rounded text-micro font-mono bg-track text-body">
                  {TYPE_ICONS[iocType]}
                  {TYPE_LABELS[iocType]}
                </div>
              )}
            </div>
          </div>

          <button
            onClick={handleEnrich}
            disabled={loading || !iocValue.trim()}
            className="w-full px-6 py-3 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Enriching & Analyzing…
              </>
            ) : (
              <>
                <Search size={16} /> Enrich & Analyze
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
              <p className="text-sm text-body">Checking IOC sources…</p>
              <p className="text-xs text-muted mt-1">Generating analyst narrative</p>
            </div>
          )}

          {result && !loading && (
            <>
              {/* IOC Detail Card */}
              <div className="surface-card/40 shadow-e1 p-5">
                <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                  <Fingerprint size={14} className="text-brand-600 dark:text-brand-400" /> IOC Details
                </h2>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-body">
                    {result.iocType?.toUpperCase()}
                  </span>
                  <span className="text-sm font-mono text-heading">{result.iocValue}</span>
                </div>
                {result.iocDetails && (
                  <div className="grid grid-cols-2 gap-2 text-xs text-muted">
                    {Object.entries(result.iocDetails)
                      .slice(0, 6)
                      .map(([k, v]) => (
                        <div key={k}>
                          <span className="text-micro font-mono uppercase tracking-wider text-muted">{k}</span>
                          <div className="font-mono truncate">{String(v ?? '-')}</div>
                        </div>
                      ))}
                  </div>
                )}
              </div>

              {/* Enrichment Sources */}
              {result.enrichmentSources && result.enrichmentSources.length > 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                    <Network size={14} className="text-brand-600 dark:text-brand-400" /> Enrichment Sources
                  </h2>
                  <div className="grid grid-cols-2 gap-2">
                    {result.enrichmentSources.map((s, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between p-2 rounded-xl bg-surface-200 border border-line-1"
                      >
                        <span className="text-xs font-mono text-body">{s.name}</span>
                        <span
                          className={`text-micro font-mono px-1.5 py-0.5 rounded ${
                            s.status === 'success'
                              ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                              : s.status === 'rate_limited'
                                ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                                : 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300'
                          }`}
                        >
                          {s.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Narrative */}
              {result.narrative && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <div className="flex items-center justify-between mb-2">
                    <h2 className="font-display font-bold text-sm flex items-center gap-2">
                      <FileText size={14} className="text-brand-600 dark:text-brand-400" /> Analyst Narrative
                    </h2>
                    <button
                      onClick={copyNarrative}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      {copiedNarrative ? <Check size={13} /> : <Copy size={13} />}
                      {copiedNarrative ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <p className="text-sm text-body leading-relaxed whitespace-pre-wrap">{result.narrative}</p>
                  <div className="mt-3 pt-3 border-t border-line-1">
                    <ShareBar
                      shareText={
                        result.narrative
                          .split('\n')
                          .find((l) => l.trim())
                          ?.slice(0, 200) || `VERDIKT-AI analysis: ${result.iocValue}`
                      }
                      title={`VERDIKT-AI analysis: ${result.iocValue}`}
                      size="sm"
                      label="Share:"
                    />
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK */}
              {result.mitreTechniques && result.mitreTechniques.length > 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                    <Shield size={14} className="text-amber-600 dark:text-amber-400" /> MITRE ATT&CK
                  </h2>
                  <div className="flex flex-wrap gap-1.5">
                    {result.mitreTechniques.map((t, i) => (
                      <a
                        key={i}
                        href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2.5 py-1 rounded-xl border border-amber-300/50 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300 text-xs font-mono hover:border-amber-500/60 transition-colors"
                      >
                        {t}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Detection Queries */}
              {result.detectionQueries && result.detectionQueries.length > 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                    <Terminal size={14} className="text-brand-600 dark:text-brand-400" /> Detection Queries
                  </h2>
                  <div className="space-y-3">
                    {result.detectionQueries.map((q, i) => (
                      <div key={i}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300">
                            {q.siem}
                          </span>
                          <CopyButton value={q.query} />
                        </div>
                        <pre className="bg-surface-200 rounded-xl p-3 text-xs font-mono text-body border border-line-1 overflow-x-auto whitespace-pre-wrap">
                          {q.query}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <button
                onClick={downloadReport}
                className="w-full px-4 py-2.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors flex items-center justify-center gap-2"
              >
                <Download size={13} /> Download Report
              </button>
            </>
          )}

          {!result && !loading && !error && (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <Search size={32} className="text-inverted dark:text-muted mx-auto mb-3" />
              <p className="text-sm text-muted">
                Enter an IOC and click <span className="font-semibold">Enrich & Analyze</span>
              </p>
              <p className="text-xs text-muted mt-1">Output: enrichment + AI analyst narrative + detection queries</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
