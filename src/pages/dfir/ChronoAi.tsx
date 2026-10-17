import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback } from 'react';
import { BackLink } from '../../components/BackLink';
import { ShareBar } from '../../components/intel/ShareBar';
import {
  Clock,
  Loader2,
  AlertTriangle,
  Copy,
  Download,
  Check,
  Shield,
  Crosshair,
  Globe,
  FileCode,
  Terminal,
  Wifi,
  Users,
} from 'lucide-react';
import { downloadText } from '../../lib/download';
const KILL_CHAIN_PHASES = [
  {
    id: 'recon',
    label: 'Recon',
    color: 'bg-sky-500',
    textColor: 'text-sky-700 dark:text-sky-300',
    bgColor: 'bg-sky-50 dark:bg-sky-950/30',
    borderColor: 'border-sky-300/50 dark:border-sky-800/50',
  },
  {
    id: 'weaponization',
    label: 'Weaponization',
    color: 'bg-violet-500',
    textColor: 'text-violet-700 dark:text-violet-300',
    bgColor: 'bg-violet-50 dark:bg-violet-950/30',
    borderColor: 'border-violet-300/50 dark:border-violet-800/50',
  },
  {
    id: 'delivery',
    label: 'Delivery',
    color: 'bg-orange-500',
    textColor: 'text-orange-700 dark:text-orange-300',
    bgColor: 'bg-orange-50 dark:bg-orange-950/30',
    borderColor: 'border-orange-300/50 dark:border-orange-800/50',
  },
  {
    id: 'exploit',
    label: 'Exploit',
    color: 'bg-rose-500',
    textColor: 'text-rose-700 dark:text-rose-300',
    bgColor: 'bg-rose-50 dark:bg-rose-950/30',
    borderColor: 'border-rose-300/50 dark:border-rose-800/50',
  },
  {
    id: 'installation',
    label: 'Installation',
    color: 'bg-amber-500',
    textColor: 'text-amber-700 dark:text-amber-300',
    bgColor: 'bg-amber-50 dark:bg-amber-950/30',
    borderColor: 'border-amber-300/50 dark:border-amber-800/50',
  },
  {
    id: 'c2',
    label: 'C2',
    color: 'bg-rose-500',
    textColor: 'text-rose-700 dark:text-rose-300',
    bgColor: 'bg-rose-50 dark:bg-rose-950/30',
    borderColor: 'border-rose-300/50 dark:border-rose-800/50',
  },
  {
    id: 'actions',
    label: 'Actions',
    color: 'bg-purple-500',
    textColor: 'text-purple-700 dark:text-purple-300',
    bgColor: 'bg-purple-50 dark:bg-purple-950/30',
    borderColor: 'border-purple-300/50 dark:border-purple-800/50',
  },
];

const PHASE_ICONS: Record<string, React.ReactNode> = {
  recon: <Globe size={12} />,
  weaponization: <FileCode size={12} />,
  delivery: <Terminal size={12} />,
  exploit: <Crosshair size={12} />,
  installation: <Shield size={12} />,
  c2: <Wifi size={12} />,
  actions: <Users size={12} />,
};

export default function ChronoAi(): JSX.Element {
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    timeline: Array<{
      timestamp: string;
      source: string;
      event: string;
      phase: string;
      technique: string;
      isLateral: boolean;
      isPersistence: boolean;
    }>;
    summary: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleReconstruct = useCallback(async () => {
    if (!logs.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/ai-summary', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          surface: 'chrono-ai',
          date: new Date().toISOString().slice(0, 10),
          items: [
            {
              title: 'Timeline Reconstruction',
              body: `Reconstruct a kill chain timeline from these logs:\n\n${logs.trim()}\n\nReturn as JSON array with fields: timestamp, source, event, phase (one of: recon, weaponization, delivery, exploit, installation, c2, actions), technique (MITRE technique ID like TXXXX.XXX), isLateral (bool), isPersistence (bool). Also include a narrative summary.`,
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
        const jsonMatch = raw.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          const timeline = JSON.parse(jsonMatch[0]) as typeof result extends { timeline: infer T } ? T : never;
          const summary = raw.replace(jsonMatch[0], '').trim();
          parsed = { timeline, summary: summary || 'Timeline reconstructed.' };
        }
      } catch (_catchErr) {
        logCatch(_catchErr);
        /* */
      }
      setResult(parsed ?? { timeline: [], summary: raw });
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [logs]);

  const copyResult = async () => {
    if (!result) return;
    const text = [
      '# CHRONO-AI Timeline',
      '',
      result.summary,
      '',
      ...result.timeline.map((e) => `[${e.timestamp}] ${e.source} - ${e.event} (${e.phase}, ${e.technique})`),
    ].join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* */
    }
  };

  const downloadTimeline = () => {
    if (!result) return;
    const text = [
      '# CHRONO-AI Timeline Reconstruction',
      `# Generated: ${new Date().toISOString()}`,
      '',
      '## Summary',
      result.summary,
      '',
      '## Events',
      ...result.timeline.map(
        (e) =>
          `| ${e.timestamp} | ${e.source} | ${e.event} | ${e.phase} | ${e.technique} | ${e.isLateral ? 'Lateral' : ''} ${e.isPersistence ? 'Persistence' : ''} |`
      ),
    ].join('\n');
    downloadText(text, `chrono-ai-${Date.now()}.md`, 'text/markdown');
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
          <Clock size={28} className="text-brand-600 dark:text-brand-400" /> CHRONO-AI
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Reconstruct a kill chain timeline from log events. Paste mixed-format logs and get a structured, color-coded
          timeline mapped to the cyber kill chain phases.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="space-y-5">
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-baseline justify-between mb-2">
              <h2 className="font-display font-bold text-sm">Log Events</h2>
              <span className="text-micro font-mono uppercase tracking-wider text-muted">required</span>
            </div>
            <textarea
              value={logs}
              onChange={(e) => setLogs(e.target.value)}
              rows={14}
              placeholder="Paste log entries from any source…"
              className="w-full rounded-xl border border-line-1 bg-surface-200 p-3 font-mono text-xs text-heading focus:outline-none focus:ring-2 focus:ring-brand-500/40"
            />
          </div>

          <button
            onClick={handleReconstruct}
            disabled={loading || !logs.trim()}
            className="w-full px-6 py-3 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Reconstructing…
              </>
            ) : (
              <>
                <Clock size={16} /> Reconstruct Timeline
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
                <p className="text-sm font-semibold text-rose-700 dark:text-rose-300">Reconstruction failed</p>
                <p className="text-xs text-rose-600 dark:text-rose-400 mt-1 font-mono break-all">{error}</p>
              </div>
            </div>
          )}

          {loading && (
            <div className="surface-card/40 shadow-e1 p-10 text-center">
              <Loader2 size={32} className="text-brand-600 dark:text-brand-400 mx-auto mb-3 animate-spin" />
              <p className="text-sm text-body">Analyzing log events…</p>
              <p className="text-xs text-muted mt-1">Building timeline</p>
            </div>
          )}

          {result && !loading && (
            <>
              <div className="surface-card/40 shadow-e1 p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="font-display font-bold text-sm flex items-center gap-2">
                    <Clock size={14} className="text-brand-600 dark:text-brand-400" /> Timeline
                  </h2>
                  <div className="flex gap-1.5">
                    <button
                      onClick={copyResult}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                    </button>
                    <button
                      onClick={downloadTimeline}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      <Download size={13} /> .md
                    </button>
                  </div>
                </div>

                {/* Kill Chain Bars */}
                <div className="mb-5">
                  <div className="flex gap-1 mb-1">
                    {KILL_CHAIN_PHASES.map((p) => {
                      const count = result.timeline.filter((e) => e.phase === p.id).length;
                      const pct = result.timeline.length > 0 ? (count / result.timeline.length) * 100 : 0;
                      return (
                        <div key={p.id} className="flex-1">
                          <div className="flex items-center gap-1 mb-1">
                            <span className="text-micro text-muted">{PHASE_ICONS[p.id]}</span>
                            <span className="text-micro font-mono text-muted truncate">{p.label}</span>
                          </div>
                          <div className="h-2 rounded-full bg-track overflow-hidden">
                            <div
                              className={`h-full rounded-full ${p.color} transition-all duration-500`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-micro font-mono text-muted">{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Event Cards */}
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {result.timeline.map((event, i) => {
                    const phase = KILL_CHAIN_PHASES.find((p) => p.id === event.phase);
                    return (
                      <div
                        key={i}
                        className={`rounded-xl border ${phase?.borderColor ?? 'border-line-1'} ${phase?.bgColor ?? 'bg-slate-50/50 dark:bg-input-200/30'} p-3 flex items-start gap-3`}
                      >
                        <div
                          className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${phase?.color ?? 'bg-slate-400'}`}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 text-xs text-muted font-mono">
                            <span>{event.timestamp}</span>
                            <span className="text-inverted dark:text-muted">|</span>
                            <span>{event.source}</span>
                            {event.isLateral && (
                              <span className="px-1 py-0.5 rounded text-micro font-mono bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">
                                Lateral
                              </span>
                            )}
                            {event.isPersistence && (
                              <span className="px-1 py-0.5 rounded text-micro font-mono bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300">
                                Persistence
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-heading mt-0.5">{event.event}</p>
                          <div className="flex gap-1.5 mt-1">
                            {event.technique && (
                              <a
                                href={`https://attack.mitre.org/techniques/${event.technique.replace('.', '/')}/`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-micro font-mono px-1.5 py-0.5 rounded border border-amber-300/50 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300 hover:border-amber-500/60 transition-colors"
                              >
                                {event.technique}
                              </a>
                            )}
                            {phase && (
                              <span
                                className={`text-micro font-mono px-1.5 py-0.5 rounded ${phase.textColor} ${phase.bgColor} border ${phase.borderColor}`}
                              >
                                {phase.label}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {result.timeline.length === 0 && (
                  <p className="text-xs text-muted py-4 text-center">No timeline events parsed. Raw summary below.</p>
                )}
              </div>

              <div className="mt-3 pt-3 border-t border-line-1">
                <ShareBar
                  shareText={
                    result.summary
                      ?.split('\n')
                      .find((l) => l.trim())
                      ?.slice(0, 200) || 'CHRONO-AI timeline reconstruction'
                  }
                  title="CHRONO-AI timeline"
                  size="sm"
                  label="Share:"
                />
              </div>

              {result.summary && result.timeline.length === 0 && (
                <div className="surface-card/40 shadow-e1 p-5">
                  <h2 className="font-display font-bold text-sm mb-2">Narrative Summary</h2>
                  <p className="text-xs text-muted leading-relaxed whitespace-pre-wrap">{result.summary}</p>
                </div>
              )}
            </>
          )}

          {!result && !loading && !error && (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <Clock size={32} className="text-inverted dark:text-muted mx-auto mb-3" />
              <p className="text-sm text-muted">
                Paste log events and click <span className="font-semibold">Reconstruct</span>
              </p>
              <p className="text-xs text-muted mt-1">Output: kill chain timeline with color-coded phases</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
