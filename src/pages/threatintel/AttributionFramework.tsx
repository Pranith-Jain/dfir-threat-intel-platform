import { useState, useCallback } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { api } from '../../lib/api-client';
import { Scale, Loader2, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface AttributionAssessment {
  actor: string;
  confidence: number;
  level: string;
  evidence: Array<{ type: string; description: string; weight: number; source: string }>;
  methodology: string;
  caveats: string[];
}

const LEVEL_BADGE: Record<string, string> = {
  'almost-certain': 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
  probable: 'bg-blue-100 text-brand-800 dark:bg-blue-900/30 dark:text-brand-300',
  'reasonably-likely': 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  possible: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  doubtful: 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted',
  improbable: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
};

export default function AttributionFramework(): JSX.Element {
  const [indicators, setIndicators] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [assessment, setAssessment] = useState<AttributionAssessment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedEvidence, setExpandedEvidence] = useState(false);

  const handleAssess = useCallback(async () => {
    if (!indicators.trim()) return;
    setLoading(true);
    setError(null);
    setAssessment(null);
    try {
      const data = await api.post<AttributionAssessment>('/api/v1/threat-intel/predictive/attribution', {
        indicators: indicators
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        context: context.trim() || undefined,
      });
      setAssessment(data);
    } catch (err) {
      console.error('AttributionFramework failed:', errMessage(err));
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [indicators, context]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Scale size={28} />}
      title="Attribution Framework"
      description="Multi-signal attribution with confidence scoring."
    >
      <div className="surface-card-faint shadow-e1 p-5 mb-6">
        <h2 className="font-display font-bold text-sm mb-3">Indicators & Evidence</h2>
        <textarea
          value={indicators}
          onChange={(e) => setIndicators(e.target.value)}
          placeholder="Enter IOCs, one per line…"
          className="w-full h-28 bg-surface-200 border border-line-1 rounded-xl p-3 text-sm font-mono text-heading placeholder-slate-400 focus:outline-none focus:border-rose-500 dark:focus:border-rose-400 resize-y"
        />
        <div className="mt-3">
          <label htmlFor="attribution-context" className="text-xs text-muted mb-1 block">
            Context (optional)
          </label>
          <input
            id="attribution-context"
            type="text"
            value={context}
            onChange={(e) => setContext(e.target.value)}
            placeholder="e.g., targeting financial sector"
            className="w-full bg-surface-200 border border-line-1 rounded-xl px-3 py-2 text-sm text-heading placeholder-slate-400 focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
          />
        </div>
        <button
          type="button"
          onClick={() => void handleAssess()}
          disabled={loading || !indicators.trim()}
          className="mt-3 w-full px-5 py-2.5 bg-rose-600 hover:bg-rose-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Scale size={14} />}
          {loading ? 'Analyzing…' : 'Assess Attribution'}
        </button>
      </div>
      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 mb-6 flex items-center gap-3">
          <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
          <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}
      {assessment && (
        <div className="space-y-5 animate-fade-in-up">
          <div className="surface-card-faint shadow-e1 p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="font-display font-bold text-lg">{assessment.actor}</h2>
                <span className={`text-micro font-mono px-1.5 py-0.5 rounded ${LEVEL_BADGE[assessment.level] ?? ''}`}>
                  {assessment.level}
                </span>
              </div>
              <div className="text-right">
                <div className="text-3xl font-display font-bold text-rose-600 dark:text-rose-400">
                  {assessment.confidence}%
                </div>
                <div className="text-micro font-mono text-muted">confidence</div>
              </div>
            </div>
            <div className="w-full bg-track rounded-full h-2">
              <div className="bg-rose-500 h-2 rounded-full" style={{ width: `${assessment.confidence}%` }} />
            </div>
          </div>
          <div className="surface-card-faint shadow-e1 overflow-hidden">
            <button
              type="button"
              onClick={() => setExpandedEvidence(!expandedEvidence)}
              className="w-full flex items-center justify-between p-4 text-left hover:bg-surface-200 dark:hover:bg-surface-200/20 transition-colors"
            >
              <span className="font-display font-bold text-sm">Evidence ({assessment.evidence.length})</span>
              {expandedEvidence ? (
                <ChevronDown size={14} className="text-muted" />
              ) : (
                <ChevronRight size={14} className="text-muted" />
              )}
            </button>
            {expandedEvidence && (
              <div className="px-4 pb-4 space-y-2 border-t border-line-1">
                {assessment.evidence.map((e, i) => (
                  <div key={i} className="flex items-start gap-3 py-2 border-b border-line-1/50 last:border-0">
                    <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 shrink-0">
                      {e.type}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-body">{e.description}</div>
                      <div className="text-micro font-mono text-muted mt-0.5">
                        Weight: {e.weight} · Source: {e.source}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          {assessment.methodology && (
            <div className="surface-card-faint shadow-e1 p-5">
              <h3 className="font-display font-bold text-sm mb-2">Methodology</h3>
              <p className="text-xs text-muted leading-relaxed">{assessment.methodology}</p>
            </div>
          )}
          {assessment.caveats.length > 0 && (
            <div className="rounded-xl border border-amber-300/50 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 p-5">
              <h3 className="font-display font-bold text-sm mb-2 flex items-center gap-2 text-amber-700 dark:text-amber-300">
                <AlertTriangle size={14} /> Caveats
              </h3>
              <ul className="space-y-1">
                {assessment.caveats.map((c, i) => (
                  <li key={i} className="text-xs text-amber-600 dark:text-amber-400">
                    • {c}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </DataPageLayout>
  );
}
