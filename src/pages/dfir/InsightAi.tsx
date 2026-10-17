import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ShareBar } from '../../components/intel/ShareBar';
import {
  Sparkles,
  Loader2,
  AlertTriangle,
  Copy,
  Download,
  FileJson,
  FileText,
  Check,
  BookOpen,
  Search,
  Siren,
  Shield,
  BarChart3,
  Hash,
  Clock,
  Braces,
  Terminal,
} from 'lucide-react';
import { downloadText } from '../../lib/download';
type ModeId = 'full-runbook' | 'triage' | 'playbook' | 'fp-analysis' | 'queries' | 'attack' | 'artifacts' | 'timeline';

type SiemFormat = 'kql' | 'spl' | 'sigma' | 'xql';

const MODES: Array<{ id: ModeId; label: string; icon: React.ReactNode }> = [
  { id: 'full-runbook', label: 'Full Runbook', icon: <BookOpen size={14} /> },
  { id: 'triage', label: 'Triage', icon: <Siren size={14} /> },
  { id: 'playbook', label: 'Playbook', icon: <Shield size={14} /> },
  { id: 'fp-analysis', label: 'FP Analysis', icon: <BarChart3 size={14} /> },
  { id: 'queries', label: 'Queries', icon: <Search size={14} /> },
  { id: 'attack', label: 'ATT&CK', icon: <Braces size={14} /> },
  { id: 'artifacts', label: 'Artifacts', icon: <Hash size={14} /> },
  { id: 'timeline', label: 'Timeline', icon: <Clock size={14} /> },
];

const SIEM_FORMATS: Array<{ id: SiemFormat; label: string }> = [
  { id: 'kql', label: 'KQL' },
  { id: 'spl', label: 'SPL' },
  { id: 'sigma', label: 'Sigma' },
  { id: 'xql', label: 'XQL' },
];

const EXAMPLE_PROMPTS = [
  'Suspicious PowerShell encoded command execution on domain controller',
  'Multiple failed logins followed by successful authentication from foreign IP',
  'Outbound DNS queries to DGA-looking domains from workstation',
  'Mimikatz activity detected on Windows Server 2022',
  'Large data transfer to external cloud storage at 3 AM',
  'WMI persistence creation followed by beacon callout',
];

export default function InsightAi(): JSX.Element {
  const [alertText, setAlertText] = useState('');
  const [selectedModes, setSelectedModes] = useState<Set<ModeId>>(new Set(['full-runbook']));
  const [selectedSiems, setSelectedSiems] = useState<Set<SiemFormat>>(new Set(['kql', 'sigma']));
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ModeId | null>(null);
  const [copied, setCopied] = useState(false);

  const toggleMode = (m: ModeId) => {
    setSelectedModes((prev) => {
      const next = new Set(prev);
      if (next.has(m)) next.delete(m);
      else next.add(m);
      return next;
    });
  };

  const toggleSiem = (s: SiemFormat) => {
    setSelectedSiems((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const handleGenerate = useCallback(async () => {
    if (!alertText.trim() || selectedModes.size === 0) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/ai-summary', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          surface: 'insight-ai',
          date: new Date().toISOString().slice(0, 10),
          items: [
            {
              title: 'Alert Analysis Request',
              body: [
                `Alert: ${alertText.trim()}`,
                `Modes: ${[...selectedModes].join(', ')}`,
                `SIEM Formats: ${[...selectedSiems].join(', ')}`,
              ].join('\n'),
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
      setResult(data.summary ?? 'No summary returned.');
      const firstMode = [...selectedModes][0];
      setActiveTab(firstMode!);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [alertText, selectedModes, selectedSiems]);

  const copyResult = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* */
    }
  };

  const downloadAs = (fmt: 'md' | 'json' | 'yaml' | 'txt') => {
    if (!result) return;
    const ts = Date.now();
    switch (fmt) {
      case 'md':
        downloadText(result, `insight-ai-${ts}.md`, 'text/markdown');
        break;
      case 'json':
        downloadText(
          JSON.stringify({ result, generatedAt: new Date().toISOString(), modes: [...selectedModes] }, null, 2),
          `insight-ai-${ts}.json`,
          'application/json'
        );
        break;
      case 'yaml':
        downloadText(
          `# INSIGHT-AI Runbook\n# Generated: ${new Date().toISOString()}\n---\n${result}`,
          `insight-ai-${ts}.yaml`,
          'text/yaml'
        );
        break;
      case 'txt':
        downloadText(result, `insight-ai-${ts}.txt`, 'text/plain');
        break;
    }
  };

  return (
    <DataPageLayout
      backTo="/dfir"
      maxWidthClass="max-w-6xl"
      icon={<Sparkles size={28} />}
      title="INSIGHT-AI"
      description="AI-powered runbook generator. Paste an alert description and generate a structured investigation playbook with triage, queries, ATT&CK mapping, and more."
    >
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="space-y-5">
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-baseline justify-between mb-2">
              <h2 className="font-display font-bold text-sm">Alert / Log Content</h2>
              <span className="text-micro font-mono uppercase tracking-wider text-muted">required</span>
            </div>
            <textarea
              value={alertText}
              onChange={(e) => setAlertText(e.target.value)}
              rows={10}
              placeholder="Paste alert text, SIEM event, or investigation notes…"
              className="w-full rounded-xl border border-line-1 bg-surface-200 p-3 font-mono text-xs text-heading focus:outline-none focus:ring-2 focus:ring-brand-500/40"
            />
            <div className="mt-3 flex flex-wrap gap-2">
              {EXAMPLE_PROMPTS.slice(0, 3).map((ex) => (
                <button
                  key={ex}
                  type="button"
                  onClick={() => setAlertText(ex)}
                  className="px-2.5 py-1 rounded text-xs font-medium border border-line-1 text-body hover:border-brand-400 hover:text-brand-700 dark:hover:text-brand-300 transition-colors"
                >
                  {ex.slice(0, 40)}…
                </button>
              ))}
            </div>
          </div>

          <div className="surface-card/40 shadow-e1 p-5">
            <h2 className="font-display font-bold text-sm mb-3">Runbook Modes</h2>
            <div className="flex flex-wrap gap-1.5">
              {MODES.map((m) => (
                <button
                  key={m.id}
                  onClick={() => toggleMode(m.id)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-mono border transition-colors ${
                    selectedModes.has(m.id)
                      ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                      : 'border-line-1 text-muted hover:border-brand-500/30'
                  }`}
                >
                  {m.icon} {m.label}
                </button>
              ))}
            </div>
          </div>

          <div className="surface-card/40 shadow-e1 p-5">
            <h2 className="font-display font-bold text-sm mb-3">SIEM Formats</h2>
            <div className="flex flex-wrap gap-1.5">
              {SIEM_FORMATS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => toggleSiem(s.id)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-mono border transition-colors ${
                    selectedSiems.has(s.id)
                      ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                      : 'border-line-1 text-muted hover:border-brand-500/30'
                  }`}
                >
                  <Terminal size={12} /> {s.label}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={handleGenerate}
            disabled={loading || !alertText.trim() || selectedModes.size === 0}
            className="w-full px-6 py-3 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Generating…
              </>
            ) : (
              <>
                <Sparkles size={16} /> Generate Runbook
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
                <p className="text-sm font-semibold text-rose-700 dark:text-rose-300">Generation failed</p>
                <p className="text-xs text-rose-600 dark:text-rose-400 mt-1 font-mono break-all">{error}</p>
              </div>
            </div>
          )}

          {loading && (
            <div className="surface-card/40 shadow-e1 p-10 text-center">
              <Loader2 size={32} className="text-brand-600 dark:text-brand-400 mx-auto mb-3 animate-spin" />
              <p className="text-sm text-body">Generating runbook…</p>
              <p className="text-xs text-muted mt-1">This may take 15–30 seconds</p>
            </div>
          )}

          {result && !loading && (
            <>
              {selectedModes.size > 1 && (
                <div className="flex flex-wrap gap-1.5 surface-card/40 shadow-e1 p-2">
                  {[...selectedModes].map((m) => {
                    const mode = MODES.find((mm) => mm.id === m);
                    if (!mode) return null;
                    return (
                      <button
                        key={m}
                        onClick={() => setActiveTab(m)}
                        className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-colors ${
                          activeTab === m
                            ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                            : 'border-line-1 text-muted hover:border-brand-500/30'
                        }`}
                      >
                        {mode.icon} {mode.label}
                      </button>
                    );
                  })}
                </div>
              )}

              <div className="surface-card/40 shadow-e1 p-5">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="font-display font-bold text-sm flex items-center gap-2">
                    <BookOpen size={14} className="text-brand-600 dark:text-brand-400" />
                    {MODES.find((m) => m.id === activeTab)?.label ?? 'Runbook'}
                  </h2>
                  <div className="flex gap-1.5">
                    <button
                      onClick={copyResult}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                    <button
                      onClick={() => downloadAs('md')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      <Download size={13} /> .md
                    </button>
                    <button
                      onClick={() => downloadAs('json')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      <FileJson size={13} /> .json
                    </button>
                    <button
                      onClick={() => downloadAs('yaml')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      <FileText size={13} /> .yaml
                    </button>
                    <button
                      onClick={() => downloadAs('txt')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-1 text-xs font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      <FileText size={13} /> .txt
                    </button>
                  </div>
                </div>
                <div className="prose prose-sm dark:prose-invert max-w-none">
                  <pre className="bg-surface-200 rounded-xl p-4 overflow-x-auto text-xs text-body font-mono border border-line-1 whitespace-pre-wrap max-h-[600px] overflow-y-auto">
                    {result}
                  </pre>
                </div>
                <div className="mt-3 pt-3 border-t border-line-1">
                  <ShareBar
                    shareText={
                      result
                        .split('\n')
                        .find((l) => l.trim())
                        ?.slice(0, 200) || 'INSIGHT-AI runbook'
                    }
                    title="INSIGHT-AI runbook"
                    size="sm"
                    label="Share:"
                  />
                </div>
              </div>
            </>
          )}

          {!result && !loading && !error && (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <Sparkles size={32} className="text-inverted dark:text-muted mx-auto mb-3" />
              <p className="text-sm text-muted">
                Paste an alert and select modes, then click <span className="font-semibold">Generate</span>
              </p>
              <p className="text-xs text-muted mt-1">Output: structured investigation runbook</p>
            </div>
          )}
        </div>
      </div>
    </DataPageLayout>
  );
}
