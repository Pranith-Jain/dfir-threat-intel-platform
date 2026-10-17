import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Bot } from 'lucide-react';
import {
  BookOpen,
  Loader2,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Clock,
  Shield,
  Link2,
  Bug,
  Mail,
  Database,
  User,
  LinkIcon,
  Crosshair,
  Wifi,
  KeyRound,
  Lock,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react';
import { SEVERITY_TONE, type Severity } from '../../components/severity';

interface PlaybookStep {
  id: string;
  title: string;
  description: string;
  tools: string[];
  estimated_time: string;
  critical: boolean;
}

interface Playbook {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  steps: PlaybookStep[];
  tools_used: string[];
  estimated_total_time: string;
}

interface PlaybookResponse {
  incident_type: string;
  playbook: Playbook;
  related_playbooks: Array<{ id: string; title: string; category: string }>;
}

const INCIDENT_TYPES: Array<{ id: string; label: string; icon: LucideIcon }> = [
  { id: 'ransomware', label: 'Ransomware', icon: Lock },
  { id: 'phishing', label: 'Phishing', icon: Mail },
  { id: 'data-breach', label: 'Data Breach', icon: Database },
  { id: 'bec', label: 'BEC / Fraud', icon: ShieldAlert },
  { id: 'insider-threat', label: 'Insider Threat', icon: User },
  { id: 'supply-chain', label: 'Supply Chain', icon: LinkIcon },
  { id: 'apt', label: 'APT Intrusion', icon: Crosshair },
  { id: 'malware', label: 'Malware Outbreak', icon: Bug },
  { id: 'ddos', label: 'DDoS Attack', icon: Wifi },
  { id: 'credential-theft', label: 'Credential Theft', icon: KeyRound },
];

export default function IrPlaybooks(): JSX.Element {
  const navigate = useNavigate();
  const [incidentType, setIncidentType] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PlaybookResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  const toggleStep = (id: string) => {
    setExpandedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleGenerate = useCallback(async () => {
    if (!incidentType) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/ir-playbooks/generate', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_type: incidentType, context: context.trim() || undefined }),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const p = JSON.parse(body) as { error?: string };
          msg = p.error ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* ok */
        }
        throw new Error(msg);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setResult(await res.json());
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [incidentType, context]);

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
          <BookOpen size={28} className="text-brand-600 dark:text-brand-400" /> IR Playbooks
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Step-by-step incident response workflows with integrated tool recommendations. Select an incident type to
          generate a tailored playbook.
        </p>
      </div>

      {/* Incident Type Selector */}
      <div className="surface-card/40 shadow-e1 p-5 mb-6">
        <h2 className="font-display font-bold text-sm mb-3">Incident Type</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
          {INCIDENT_TYPES.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                onClick={() => setIncidentType(t.id)}
                className={`p-3 rounded-xl border text-left transition-colors ${incidentType === t.id ? 'border-brand-500/60 bg-brand-500/5' : 'border-line-1 hover:border-brand-500/30'}`}
              >
                <Icon size={20} className="text-brand-600 dark:text-brand-400 mb-1" />
                <div className="text-xs font-medium">{t.label}</div>
              </button>
            );
          })}
        </div>

        <div className="mt-4">
          <label htmlFor="irplaybooks-context" className="text-xs text-muted mb-1 block">
            Additional Context (optional)
          </label>
          <textarea
            id="irplaybooks-context"
            value={context}
            onChange={(e) => setContext(e.target.value)}
            placeholder="Describe specific details about the incident…"
            className="w-full h-20 bg-surface-200 border border-line-1 rounded-xl p-3 text-sm text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 dark:focus:border-brand-400 resize-y"
          />
        </div>

        <button
          onClick={handleGenerate}
          disabled={loading || !incidentType}
          className="mt-4 w-full px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <BookOpen size={14} />}
          {loading ? 'Generating playbook…' : 'Generate IR Playbook'}
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
          {/* Playbook Header */}
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-center justify-between mb-2">
              <h2 className="font-display font-bold text-lg">{result.playbook.title}</h2>
              <span
                className={`text-micro font-mono px-1.5 py-0.5 rounded border ${SEVERITY_TONE[result.playbook.severity]}`}
              >
                {result.playbook.severity}
              </span>
            </div>
            <p className="text-sm text-muted mb-3">{result.playbook.description}</p>
            <div className="flex flex-wrap gap-3 text-xs text-muted">
              <span className="flex items-center gap-1">
                <Clock size={12} /> {result.playbook.estimated_total_time}
              </span>
              <span className="flex items-center gap-1">
                <Shield size={12} /> {result.playbook.steps.length} steps
              </span>
              <span className="flex items-center gap-1">
                <Link2 size={12} /> {result.playbook.tools_used.length} tools
              </span>
            </div>
            <div className="mt-3 flex gap-2">
              <button
                type="button"
                onClick={() => {
                  const steps = result.playbook.steps.map((s) => `${s.title}: ${s.description}`).join('\n');
                  const tools = result.playbook.tools_used.join(', ');
                  const query = `I generated an IR playbook for "${result.incident_type}". Investigate the threat and generate detection rules (YARA, Sigma, KQL) for the IOCs and TTPs.\n\nPlaybook: ${result.playbook.title}\nSeverity: ${result.playbook.severity}\nSteps:\n${steps}\nTools: ${tools}`;
                  navigate(`/copilot?q=${encodeURIComponent(query)}`);
                }}
                className="text-xs font-mono px-3 py-1.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:border-rose-500/50 inline-flex items-center gap-1.5"
              >
                <Bot size={11} /> Send to Agent
              </button>
            </div>
          </div>

          {/* Steps */}
          <div className="space-y-2">
            {result.playbook.steps.map((step, i) => {
              const isExpanded = expandedSteps.has(step.id);
              return (
                <div key={step.id} className="surface-card/40 shadow-e1 overflow-hidden">
                  <button
                    onClick={() => toggleStep(step.id)}
                    className="w-full flex items-center gap-3 p-4 text-left hover:bg-surface-200 dark:hover:bg-surface-200/20 transition-colors"
                  >
                    <div
                      className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white ${step.critical ? 'bg-rose-500' : 'bg-brand-600'}`}
                    >
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium">{step.title}</div>
                      <div className="text-micro font-mono text-muted">{step.estimated_time}</div>
                    </div>
                    {step.critical && (
                      <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300">
                        critical
                      </span>
                    )}
                    {isExpanded ? (
                      <ChevronDown size={14} className="text-muted" />
                    ) : (
                      <ChevronRight size={14} className="text-muted" />
                    )}
                  </button>
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-0 border-t border-line-1">
                      <p className="text-sm text-muted mt-3 mb-3">{step.description}</p>
                      {step.tools.length > 0 && (
                        <div>
                          <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1.5">
                            Recommended Tools
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {step.tools.map((tool, j) => (
                              <span
                                key={j}
                                className="text-micro font-mono px-2 py-0.5 rounded bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300"
                              >
                                {tool}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Tools Used Summary */}
          <div className="surface-card/40 shadow-e1 p-5">
            <h2 className="font-display font-bold text-sm mb-3">Tools Referenced</h2>
            <div className="flex flex-wrap gap-1.5">
              {result.playbook.tools_used.map((tool, i) => (
                <span key={i} className="text-xs font-mono px-2 py-1 rounded border border-line-1 text-muted">
                  {tool}
                </span>
              ))}
            </div>
          </div>

          {/* Related Playbooks */}
          {result.related_playbooks.length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <h2 className="font-display font-bold text-sm mb-3">Related Playbooks</h2>
              <div className="space-y-1.5">
                {result.related_playbooks.map((rp, i) => (
                  <button
                    key={i}
                    onClick={() => {
                      setIncidentType(rp.id);
                      setResult(null);
                    }}
                    className="w-full flex items-center justify-between p-3 rounded-xl border border-line-1 hover:border-brand-500/30 transition-colors text-left"
                  >
                    <div>
                      <div className="text-sm font-medium">{rp.title}</div>
                      <div className="text-micro font-mono text-muted">{rp.category}</div>
                    </div>
                    <ChevronRight size={14} className="text-muted" />
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
