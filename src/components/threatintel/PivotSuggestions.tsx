import { useState, useCallback, useEffect, useRef } from 'react';
import {
  Crosshair,
  Loader2,
  AlertTriangle,
  Search,
  Shield,
  Bug,
  Globe,
  Cpu,
  Target,
  BarChart3,
  FileText,
  ChevronRight,
  type LucideIcon,
} from 'lucide-react';
import { adminAuthHeaders } from '../../lib/admin-token';
import { errMessage } from '../../lib/log';

export interface PivotSuggestion {
  label: string;
  query: string;
  category: 'actor' | 'cve' | 'malware' | 'ioc' | 'campaign' | 'sector' | 'technique' | 'general';
  confidence: 'high' | 'medium' | 'low';
  rationale: string;
}

const CATEGORY_ICONS: Record<string, LucideIcon> = {
  actor: Shield,
  cve: Bug,
  malware: Cpu,
  ioc: Globe,
  campaign: Target,
  sector: BarChart3,
  technique: FileText,
  general: Search,
};

const CATEGORY_COLORS: Record<string, string> = {
  actor: 'text-rose-600 bg-rose-50 dark:text-rose-400 dark:bg-rose-950/20',
  cve: 'text-amber-600 bg-amber-50 dark:text-amber-400 dark:bg-amber-950/20',
  malware: 'text-violet-600 bg-violet-50 dark:text-violet-400 dark:bg-violet-950/20',
  ioc: 'text-brand-600 bg-blue-50 dark:text-brand-400 dark:bg-blue-950/20',
  campaign: 'text-emerald-600 bg-emerald-50 dark:text-emerald-400 dark:bg-emerald-950/20',
  sector: 'text-sky-600 bg-sky-50 dark:text-sky-400 dark:bg-sky-950/20',
  technique: 'text-indigo-600 bg-indigo-50 dark:text-indigo-400 dark:bg-indigo-950/20',
  general: 'text-slate-600 bg-slate-50 dark:text-muted dark:bg-input-200/20',
} as const;

const CONFIDENCE_LABELS = {
  high: { label: 'High', color: 'text-emerald-600 dark:text-emerald-400' },
  medium: { label: 'Med', color: 'text-amber-600 dark:text-amber-400' },
  low: { label: 'Low', color: 'text-muted' },
} as const;

interface PivotSuggestionsProps {
  query: string;
  queryType?: string;
  responseContent: string;
  responseSources?: Array<{ name: string; items: number }>;
  onSubmit: (q: string) => void;
  /** Pass true to trigger fetch on mount */
  autoFetch?: boolean;
}

export function PivotSuggestions({
  query,
  queryType,
  responseContent,
  responseSources,
  onSubmit,
  autoFetch = true,
}: PivotSuggestionsProps) {
  const [suggestions, setSuggestions] = useState<PivotSuggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fetchedRef = useRef(false);

  const fetchPivots = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/copilot/pivots', {
        method: 'POST',
        headers: { ...adminAuthHeaders(), 'content-type': 'application/json' },
        body: JSON.stringify({
          query,
          queryType: queryType ?? 'generic',
          responseContent: responseContent.slice(0, 5000),
          responseSources,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to load pivots' }));
        throw new Error(err.message ?? 'Failed to load pivots');
      }
      const data = (await res.json()) as { suggestions: PivotSuggestion[] };
      setSuggestions(data.suggestions ?? []);
    } catch (e) {
      setError(errMessage(e, 'Failed to load pivots'));
    } finally {
      setLoading(false);
    }
  }, [query, queryType, responseContent, responseSources]);

  useEffect(() => {
    if (autoFetch && !fetchedRef.current && responseContent.length > 20) {
      fetchedRef.current = true;
      void fetchPivots();
    }
  }, [autoFetch, fetchPivots, responseContent]);

  if (loading) {
    return (
      <div className="mt-3 flex items-center gap-2 border-t border-line-1 pt-3">
        <Loader2 size={12} className="animate-spin text-brand-500" />
        <span className="font-mono text-mini text-muted">Suggesting pivots…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-3 flex items-center gap-2 border-t border-line-1 pt-3">
        <AlertTriangle size={11} className="text-amber-500 shrink-0" />
        <span className="font-mono text-mini text-amber-600 dark:text-amber-400">{error}</span>
        <button
          onClick={fetchPivots}
          className="ml-auto font-mono text-mini text-brand-600 hover:text-brand-700 dark:text-brand-400 transition-colors"
        >
          retry
        </button>
      </div>
    );
  }

  if (suggestions.length === 0) return null;

  return (
    <div className="mt-3 border-t border-line-1 pt-2.5">
      <div className="mb-2 flex items-center gap-1.5">
        <Crosshair size={11} className="text-brand-500" />
        <span className="text-mini font-semibold uppercase tracking-wider text-muted">Investigation pivots</span>
      </div>
      <div className="space-y-1.5">
        {suggestions.map((s, i) => {
          const Icon = CATEGORY_ICONS[s.category] ?? Search;
          const conf = CONFIDENCE_LABELS[s.confidence] ?? { label: 'Med', color: 'text-amber-600 dark:text-amber-400' };
          return (
            <button
              key={i}
              onClick={() => onSubmit(s.query)}
              className="group flex w-full items-start gap-2 rounded-xl border border-line-1 bg-surface-200/50 px-2.5 py-2 text-left transition-all hover:border-brand-300 hover:bg-brand-50/50 dark:bg-surface-200/30 dark:hover:border-brand-400/30 dark:hover:bg-brand-900/10"
            >
              <span
                className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md ${CATEGORY_COLORS[s.category] ?? 'text-slate-600 bg-slate-50 dark:text-muted dark:bg-input-200/20'}`}
              >
                <Icon size={12} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-body">{s.label}</span>
                  <span className={`font-mono text-micro ${conf.color}`}>{conf.label}</span>
                </div>
                <p className="text-mini text-muted leading-tight">{s.rationale}</p>
              </div>
              <ChevronRight
                size={13}
                className="mt-1 shrink-0 text-inverted transition-all group-hover:text-brand-500 group-hover:translate-x-0.5"
              />
            </button>
          );
        })}
      </div>
    </div>
  );
}
