import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback } from 'react';
import { BackLink } from '../../components/BackLink';
import { Crosshair, Loader2, AlertTriangle, Shield, Terminal, Search, Clock, Trash2 } from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';

type SiemFormat = 'kql' | 'spl' | 'sigma' | 'xql';
type DetectionTrack = 'detect' | 'hunt';

interface HistoryEntry {
  description: string;
  siem: SiemFormat;
  track: DetectionTrack;
  result: string;
  mitre: string[];
  confidence: string;
  timestamp: number;
}

const SIEM_CARDS: Array<{ id: SiemFormat; label: string; desc: string }> = [
  { id: 'kql', label: 'KQL', desc: 'Kusto Query Language - Azure Sentinel / Defender' },
  { id: 'spl', label: 'SPL', desc: 'Search Processing Language - Splunk' },
  { id: 'sigma', label: 'Sigma', desc: 'SIEM-agnostic generic rule format' },
  { id: 'xql', label: 'XQL', desc: 'eXtended Query Language - Cortex XSIAM' },
];

const EXAMPLE_PROMPTS = [
  'PowerShell encoded command execution via -EncodedCommand flag',
  'Mimikatz credential dumping from lsass process',
  'DNS tunneling with high entropy subdomain queries',
  'Suspicious scheduled task creation for persistence',
  'Large outbound data transfer to unknown external IP',
  'WMI lateral movement with process creation',
  'Registry run key modification for persistence',
  'Suspicious service installation from temp directory',
  'Pass-the-hash authentication attempt',
  'Suspicious rundll32 execution without DLL',
];

const CONFIDENCE_BADGE: Record<string, string> = {
  high: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
  medium: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  low: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
};

const HISTORY_KEY = 'querycraftHistory';

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch (_catchErr) {
    console.error('loadHistory failed:', errMessage(_catchErr));
    return [];
  }
}

function saveHistory(entries: HistoryEntry[]) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, 20)));
  } catch (_catchErr) {
    console.error('saveHistory failed:', errMessage(_catchErr));
    /* */
  }
}

export default function QuerycraftAi(): JSX.Element {
  const [description, setDescription] = useState('');
  const [siem, setSiem] = useState<SiemFormat>('kql');
  const [track, setTrack] = useState<DetectionTrack>('detect');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    query: string;
    description: string;
    mitre_techniques: string[];
    confidence: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);

  const handleGenerate = useCallback(async () => {
    if (!description.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/hunting-queries/generate', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat: description.trim(),
          platforms: [siem.toUpperCase()],
          track,
        }),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const p = JSON.parse(body) as { error?: string; message?: string };
          msg = p.error ?? p.message ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* */
        }
        throw new Error(msg);
      }
      const data = (await res.json()) as {
        threat?: string;
        queries?: Array<{ siem: string; query: string; description: string; confidence: string }>;
        mitre_techniques?: string[];
      };
      const q = data.queries?.[0];
      if (!q) throw new Error('No query returned');
      const r = {
        query: q.query,
        description: q.description,
        mitre_techniques: data.mitre_techniques ?? [],
        confidence: q.confidence ?? 'medium',
      };
      setResult(r);

      const entry: HistoryEntry = {
        description: description.trim(),
        siem,
        track,
        result: q.query,
        mitre: data.mitre_techniques ?? [],
        confidence: q.confidence ?? 'medium',
        timestamp: Date.now(),
      };
      const updated = [entry, ...history.filter((h) => h.description !== entry.description).slice(0, 19)];
      setHistory(updated);
      saveHistory(updated);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [description, siem, track, history]);

  const clearHistory = () => {
    setHistory([]);
    saveHistory([]);
  };

  const restoreFromHistory = (entry: HistoryEntry) => {
    setDescription(entry.description);
    setSiem(entry.siem);
    setTrack(entry.track);
    const fullResult = entry as HistoryEntry & { mitre?: string[] };
    setResult({
      query: fullResult.result,
      description: fullResult.description,
      mitre_techniques: fullResult.mitre ?? [],
      confidence: fullResult.confidence,
    });
    setError(null);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Crosshair size={28} className="text-brand-600 dark:text-brand-400" /> QUERYSECT-AI
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Build detection queries from natural language descriptions. Describe what to detect in plain English and get
          production-ready SIEM queries with MITRE ATT&CK mapping.
        </p>
      </div>

      {/* History */}
      {history.length > 0 && (
        <div className="surface-card/40 shadow-e1 p-4 mb-6">
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-display font-bold text-xs flex items-center gap-2">
              <Clock size={12} /> Recent Queries
            </h2>
            <button
              onClick={clearHistory}
              className="text-micro font-mono text-muted hover:text-rose-500 transition-colors inline-flex items-center gap-1"
            >
              <Trash2 size={11} /> clear
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {history.slice(0, 8).map((entry, i) => (
              <button
                key={i}
                onClick={() => restoreFromHistory(entry)}
                className="px-2 py-1 rounded text-micro font-mono border border-line-1 text-muted hover:border-brand-500/30 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
              >
                {entry.description.slice(0, 35)}…
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="surface-card/40 shadow-e1 p-5 mb-6">
        <h2 className="font-display font-bold text-sm mb-3">What to detect</h2>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Describe what you want to detect in plain language…"
          className="w-full h-24 bg-surface-200 border border-line-1 rounded-xl p-3 text-sm text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 dark:focus:border-brand-400 resize-y font-mono"
        />
        <div className="mt-2 flex flex-wrap gap-1">
          {EXAMPLE_PROMPTS.slice(0, 5).map((ex) => (
            <button
              key={ex}
              onClick={() => setDescription(ex)}
              className="text-mini px-2 py-1 rounded border border-line-1 text-muted hover:border-brand-500/30 transition-colors"
            >
              {ex.slice(0, 40)}…
            </button>
          ))}
        </div>

        {/* SIEM Selection */}
        <h3 className="font-display font-bold text-xs mt-4 mb-2">SIEM Format</h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {SIEM_CARDS.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                setSiem(s.id);
                setResult(null);
              }}
              className={`rounded-xl border p-3 text-left transition-colors ${
                siem === s.id
                  ? 'border-brand-500/60 bg-brand-500/10'
                  : 'border-line-1 hover:border-brand-500/30 bg-white dark:bg-surface-200/20'
              }`}
            >
              <div
                className={`text-xs font-mono font-semibold ${siem === s.id ? 'text-brand-600 dark:text-brand-400' : 'text-body'}`}
              >
                {s.label}
              </div>
              <div className="text-micro text-muted mt-0.5">{s.desc}</div>
            </button>
          ))}
        </div>

        {/* Detection Track Toggle */}
        <div className="flex gap-2 mt-4">
          <button
            onClick={() => setTrack('detect')}
            className={`flex-1 px-4 py-2 rounded-xl text-xs font-mono border transition-colors ${
              track === 'detect'
                ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                : 'border-line-1 text-muted hover:border-brand-500/30'
            }`}
          >
            <Shield size={12} className="inline mr-1" /> DETECT
          </button>
          <button
            onClick={() => setTrack('hunt')}
            className={`flex-1 px-4 py-2 rounded-xl text-xs font-mono border transition-colors ${
              track === 'hunt'
                ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                : 'border-line-1 text-muted hover:border-brand-500/30'
            }`}
          >
            <Search size={12} className="inline mr-1" /> HUNT
          </button>
        </div>

        <button
          onClick={handleGenerate}
          disabled={loading || !description.trim()}
          className="mt-4 w-full px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Crosshair size={14} />}
          {loading ? 'Generating…' : 'Generate Query'}
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
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-display font-bold text-sm flex items-center gap-2">
                <Terminal size={14} className="text-brand-600 dark:text-brand-400" /> Generated Query
              </h2>
              <div className="flex items-center gap-2">
                <span
                  className={`inline-block px-2 py-0.5 rounded text-xs font-mono ${CONFIDENCE_BADGE[result.confidence] ?? ''}`}
                >
                  {result.confidence}
                </span>
                <CopyButton value={result.query} />
              </div>
            </div>
            <pre className="bg-surface-200 rounded-xl p-4 overflow-x-auto text-xs text-body font-mono border border-line-1 whitespace-pre-wrap max-h-[400px] overflow-y-auto">
              {result.query}
            </pre>
            <p className="mt-3 text-xs text-muted leading-relaxed">{result.description}</p>
          </div>

          {result.mitre_techniques.length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                <Shield size={14} className="text-brand-600 dark:text-brand-400" /> MITRE ATT&CK
              </h2>
              <div className="flex flex-wrap gap-1.5">
                {result.mitre_techniques.map((t) => (
                  <a
                    key={t}
                    href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-micro font-mono px-2 py-0.5 rounded border border-amber-300/50 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300 hover:border-amber-500/60 transition-colors"
                  >
                    {t}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
