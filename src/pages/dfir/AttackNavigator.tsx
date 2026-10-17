import { useState, useMemo, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { DataState } from '../../components/DataState';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import { ExternalLink, Search, X, Shield } from 'lucide-react';
import { threatActors } from '../../data/dfir/threat-actors';
import { errMessage } from '../../lib/log';

type MatrixSource = 'attack' | 'a3m' | 'd3fend';

interface MitreTechniqueLite {
  id: string;
  name: string;
  description?: string;
  d3fend_id?: string;
  subtechniques?: Array<{ id: string; name: string }>;
}

interface MitreTactic {
  id: string;
  name: string;
  description?: string;
  short_name?: string;
  techniques: MitreTechniqueLite[];
}

type ColorMode = 'prevalence' | 'risk' | 'actor_pct';

interface TechniqueScore {
  raw_mean: number;
  adjusted: number;
  prevalence: number;
  count: number;
  n_actors: number;
  pct_actors: number;
  n_scored?: number;
}

const usedByActors = new Set<string>();
for (const a of threatActors) {
  for (const t of a.techniques) usedByActors.add(t);
}

function actorsByTechnique(id: string): typeof threatActors {
  return threatActors.filter((a) => a.techniques.includes(id));
}

const RISK_THRESHOLDS = [
  { min: 85, label: 'Critical', color: '#F44336', bg: 'bg-rose-500', text: 'text-rose-700 dark:text-rose-300' },
  { min: 70, label: 'High', color: '#FF9800', bg: 'bg-orange-500', text: 'text-orange-700 dark:text-orange-300' },
  { min: 50, label: 'Medium', color: '#FFC107', bg: 'bg-amber-500', text: 'text-amber-700 dark:text-amber-300' },
  { min: 0, label: 'Low', color: '#66BB6A', bg: 'bg-emerald-500', text: 'text-emerald-700 dark:text-emerald-300' },
];

const PCT_COLORS = [
  { min: 50, color: '#7f1d1d', label: '>50%' },
  { min: 25, color: '#b91c1c', label: '25-50%' },
  { min: 10, color: '#e8540c', label: '10-25%' },
  { min: 2, color: '#f5a623', label: '2-10%' },
  { min: 0, color: '#f9d976', label: '<2%' },
];

function getRiskColor(score: number): string {
  if (score >= 85) return RISK_THRESHOLDS[0]!.color;
  if (score >= 70) return RISK_THRESHOLDS[1]!.color;
  if (score >= 50) return RISK_THRESHOLDS[2]!.color;
  return RISK_THRESHOLDS[3]!.color;
}

function getPctColor(pct: number): string {
  if (pct >= 50) return PCT_COLORS[0]!.color;
  if (pct >= 25) return PCT_COLORS[1]!.color;
  if (pct >= 10) return PCT_COLORS[2]!.color;
  if (pct >= 2) return PCT_COLORS[3]!.color;
  if (pct > 0) return PCT_COLORS[4]!.color;
  return '#FFFFFF';
}

function getPrevalenceColor(prev: number): string {
  if (prev >= 1.5) return '#7f1d1d';
  if (prev >= 1.2) return '#b91c1c';
  if (prev >= 1.0) return '#e8540c';
  if (prev >= 0.5) return '#f5a623';
  return '#FFFFFF';
}

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace('#', '');
  return [parseInt(h.substring(0, 2), 16), parseInt(h.substring(2, 4), 16), parseInt(h.substring(4, 6), 16)];
}

function relativeLuminance(r: number, g: number, b: number): number {
  const srgb = [r, g, b].map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * srgb[0]! + 0.7152 * srgb[1]! + 0.0722 * srgb[2]!;
}

function fgFor(bgHex: string): string {
  if (bgHex === '#FFFFFF') return '#1c1917';
  const [r, g, b] = hexToRgb(bgHex);
  return relativeLuminance(r, g, b) > 0.55 ? '#1c1917' : '#ffffff';
}

function getColor(score: TechniqueScore | undefined, mode: ColorMode): string {
  if (!score) return '#FFFFFF';
  switch (mode) {
    case 'risk':
      return getRiskColor(score.raw_mean);
    case 'actor_pct':
      return getPctColor(score.pct_actors);
    case 'prevalence':
      return getPrevalenceColor(score.prevalence);
  }
}

function getLegendItems(mode: ColorMode): Array<{ label: string; color: string }> {
  switch (mode) {
    case 'risk':
      return RISK_THRESHOLDS.map((t) => ({
        label: `${t.label} (${t.min === 0 ? '0-49' : t.min === 50 ? '50-69' : t.min === 70 ? '70-84' : '85-100'})`,
        color: t.color,
      }));
    case 'actor_pct':
      return PCT_COLORS.map((t) => ({ label: t.label, color: t.color }));
    case 'prevalence':
      return [
        { label: 'Very High (1.5)', color: '#7f1d1d' },
        { label: 'High (1.2)', color: '#b91c1c' },
        { label: 'Moderate (1.0)', color: '#e8540c' },
        { label: 'Base (0.5)', color: '#f5a623' },
      ];
  }
}

const MODE_LABELS: Record<ColorMode, string> = {
  prevalence: 'Prevalence multiplier',
  risk: 'LLM Risk Score (ARiES)',
  actor_pct: '% of observed actors',
};

export default function AttackNavigator(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialSource = (searchParams.get('matrix') ?? 'attack') as MatrixSource;
  const [query, setQuery] = useState(searchParams.get('q') ?? '');
  const [selectedId, setSelectedId] = useState<string | null>(searchParams.get('id'));
  const [colorMode, setColorMode] = useState<ColorMode>('actor_pct');
  const [matrixSource, setMatrixSource] = useState<MatrixSource>(
    initialSource === 'a3m' || initialSource === 'd3fend' ? initialSource : 'attack'
  );
  const [mitreMatrix, setMitreMatrix] = useState<MitreTactic[]>([]);
  const [scores, setScores] = useState<Record<string, TechniqueScore>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    const endpoint =
      matrixSource === 'a3m'
        ? '/api/v1/a3m-matrix'
        : matrixSource === 'd3fend'
          ? '/api/v1/d3fend-matrix'
          : '/api/v1/attack-navigator';
    fetch(endpoint, { signal: ctrl.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: { matrix: MitreTactic[]; scores?: Record<string, TechniqueScore>; generated_at: string }) => {
        if (cancelled) return;
        setMitreMatrix(d.matrix);
        setScores(d.scores ?? {});
        setGeneratedAt(d.generated_at);
      })
      .catch((e) => {
        if (!cancelled && (e as { name?: string }).name !== 'AbortError') {
          setError(errMessage(e));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey, matrixSource]);

  useEffect(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (matrixSource !== 'attack') next.set('matrix', matrixSource);
        else next.delete('matrix');
        return next;
      },
      { replace: true }
    );
  }, [matrixSource, setSearchParams]);

  const openTechnique = useCallback(
    (id: string) => {
      setSelectedId(id);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('id', id);
        return next;
      });
    },
    [setSearchParams]
  );

  const closeDrawer = useCallback(() => {
    setSelectedId(null);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('id');
      return next;
    });
  }, [setSearchParams]);

  // Full focus trap for the detail drawer: moves focus into the dialog on
  // open, contains Tab/Shift+Tab within it, restores focus to the triggering
  // technique cell on close, and handles Escape. Replaces the old Escape-only
  // listener that left keyboard focus stranded in the background grid.
  const drawerRef = useFocusTrap({ isActive: !!selectedId, onEscape: closeDrawer });

  useEffect(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (query.trim()) next.set('q', query.trim());
        else next.delete('q');
        return next;
      },
      { replace: true }
    );
  }, [query, setSearchParams]);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    const set = new Set<string>();
    for (const tactic of mitreMatrix) {
      for (const t of tactic.techniques) {
        if (
          t.id.toLowerCase().includes(q) ||
          t.name.toLowerCase().includes(q) ||
          (t.description ?? '').toLowerCase().includes(q) ||
          (t.subtechniques ?? []).some((s) => s.id.toLowerCase().includes(q) || s.name.toLowerCase().includes(q))
        ) {
          set.add(t.id);
        }
      }
    }
    return set;
  }, [query, mitreMatrix]);

  const selectedScore = selectedId ? scores[selectedId] : undefined;
  const selectedActors = selectedId ? actorsByTechnique(selectedId) : [];

  const selectedTechnique = useMemo(() => {
    if (!selectedId) return null;
    for (const tactic of mitreMatrix) {
      for (const t of tactic.techniques) {
        if (t.id === selectedId) return t;
        if (t.subtechniques) {
          const sub = t.subtechniques.find((s) => s.id === selectedId);
          if (sub) return { ...sub, parent: t };
        }
      }
    }
    return null;
  }, [selectedId, mitreMatrix]);

  return (
    <div className="max-w-full px-4 sm:px-8 py-12 text-heading">
      <div className="max-w-[1600px] mx-auto">
        <BackLink
          to="/dfir"
          className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
        >
          back to DFIR
        </BackLink>

        <div className="animate-fade-in-up">
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-3xl sm:text-4xl font-display font-bold">
              {matrixSource === 'attack' && 'LLM ATT&CK Navigator'}
              {matrixSource === 'a3m' && 'A3M Matrix'}
              {matrixSource === 'd3fend' && 'D3FEND Matrix'}
            </h1>
            {!loading && !error && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 text-micro font-mono uppercase">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                live
              </span>
            )}
          </div>
          <p className="text-muted mb-2 max-w-4xl">
            {matrixSource === 'attack' &&
              'Interactive matrix mapping LLM-specific attack techniques to the MITRE ATT&CK framework. Color intensity reflects technique prevalence, risk scores, or actor adoption. Click any highlighted tile for full detail including ARiES scores, sub-techniques, and linked actors.'}
            {matrixSource === 'a3m' &&
              'A3M Matrix (Agentic AI Attack Matrix) - 167 techniques across 17 phases, covering reconnaissance to impact for tool-using agents, browser automation, RAG, memory, and SaaS integrations. Click any technique for full detail.'}
            {matrixSource === 'd3fend' &&
              'MITRE D3FEND - defensive countermeasure matrix. 250+ techniques across 7 tactics (Model, Harden, Detect, Isolate, Deceive, Evict, Restore) mapped to the artifacts they protect. Click any technique for full detail.'}
          </p>
          <div className="flex flex-wrap items-center gap-4 text-sm font-mono text-muted mb-3">
            <span>
              <span className="text-heading">{Object.keys(scores).length}</span> scored techniques
            </span>
            <span aria-hidden="true">&middot;</span>
            <span>
              <span className="text-heading">{mitreMatrix.length}</span> tactics
            </span>
            <span aria-hidden="true">&middot;</span>
            <span>
              <span className="text-heading">{mitreMatrix.reduce((sum, t) => sum + t.techniques.length, 0)}</span>{' '}
              techniques tracked
            </span>
            {generatedAt && (
              <>
                <span aria-hidden="true">&middot;</span>
                <span>
                  Updated: <span className="text-heading">{new Date(generatedAt).toLocaleString()}</span>
                </span>
              </>
            )}
          </div>
          <div className="flex items-center gap-2 mb-4">
            <Shield size={14} className="text-brand-500" />
            <span className="text-xs font-mono text-muted">
              {matrixSource === 'attack' && (
                <>
                  Based on{' '}
                  <a
                    href="https://red.anthropic.com/2026/attack-navigator/navigator"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    Anthropic LLM ATT&amp;CK research
                  </a>
                </>
              )}
              {matrixSource === 'a3m' && (
                <>
                  Source:{' '}
                  <a
                    href="https://www.cyberriskevaluator.com/A3M_Matrix_Agentic_AI_Attack_Matrix.html"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    A3M Matrix - Agentic AI Attack Matrix
                  </a>
                </>
              )}
              {matrixSource === 'd3fend' && (
                <>
                  Source:{' '}
                  <a
                    href="https://d3fend.mitre.org/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    MITRE D3FEND™
                  </a>
                </>
              )}
            </span>
          </div>
        </div>

        {/* Matrix source tabs */}
        <div className="flex flex-wrap items-center gap-1 mb-4 border-b border-line-1">
          {[
            { id: 'attack' as const, label: 'MITRE ATT&CK', sub: 'Enterprise · live' },
            { id: 'a3m' as const, label: 'A3M Matrix', sub: 'Agentic AI · live' },
            { id: 'd3fend' as const, label: 'D3FEND', sub: 'Defensive · live' },
          ].map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => {
                setMatrixSource(t.id);
                setSelectedId(null);
                setSearchParams(
                  (prev) => {
                    const next = new URLSearchParams(prev);
                    if (t.id !== 'attack') next.set('matrix', t.id);
                    else next.delete('matrix');
                    next.delete('id');
                    return next;
                  },
                  { replace: true }
                );
              }}
              className={`flex flex-col items-start gap-0.5 px-4 py-2.5 text-sm font-mono border-b-2 transition-colors ${
                matrixSource === t.id
                  ? 'border-brand-500 text-brand-600 dark:text-brand-400'
                  : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
              }`}
            >
              <span className="font-semibold">{t.label}</span>
              <span className="text-micro uppercase tracking-wider text-muted">{t.sub}</span>
            </button>
          ))}
        </div>

        {/* Toolbar */}
        <div className="flex flex-wrap items-center gap-2 mb-6 mt-6">
          <div className="relative flex-1 min-w-[260px] max-w-md">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search ID, name, or description..."
              className="w-full pl-9 pr-4 py-2.5 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              aria-label="Search techniques"
            />
          </div>
          {matrixSource === 'attack' && (
            <label className="flex items-center gap-2 text-xs font-mono text-muted">
              Color by:
              <select
                value={colorMode}
                onChange={(e) => setColorMode(e.target.value as ColorMode)}
                className="bg-surface-100 border border-line-1 rounded px-2 py-1.5 text-xs font-mono text-heading focus:outline-none focus:border-brand-500"
              >
                <option value="actor_pct">% of observed actors</option>
                <option value="risk">LLM Risk Score (ARiES)</option>
                <option value="prevalence">Prevalence multiplier</option>
              </select>
            </label>
          )}
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-3 mb-6 text-xs font-mono text-muted">
          {matrixSource === 'attack' ? (
            <>
              <span className="font-semibold uppercase tracking-wider text-micro text-muted">
                {MODE_LABELS[colorMode]}:
              </span>
              {getLegendItems(colorMode).map((item) => (
                <span key={item.label} className="inline-flex items-center gap-1.5">
                  <span
                    className="inline-block w-4 h-4 rounded border border-line-2"
                    style={{ backgroundColor: item.color }}
                  />
                  {item.label}
                </span>
              ))}
            </>
          ) : (
            <span className="inline-flex items-center gap-1.5">
              <span
                className="inline-block w-4 h-4 rounded border border-line-2"
                style={{ backgroundColor: matrixSource === 'a3m' ? '#8F00FF' : '#0ea5e9' }}
              />
              {matrixSource === 'a3m' ? 'A3M technique' : 'D3FEND technique'}
            </span>
          )}
          <span className="inline-flex items-center gap-1.5 ml-2">
            <span className="inline-block w-4 h-4 rounded border-2 border-slate-900 dark:border-line-1 bg-surface-100" />
            Observed (border)
          </span>
        </div>

        {matches && (
          <p className="text-xs font-mono text-cyan-600 dark:text-cyan-400 mb-4">{matches.size} techniques match</p>
        )}

        {/* Mobile hint */}
        <p className="sm:hidden text-mini font-mono text-muted mb-2 italic">
          Swipe horizontally to scan tactics &rarr;
        </p>

        {/* Matrix */}
        <DataState
          loading={loading}
          error={error}
          empty={!loading && !error && mitreMatrix.length === 0}
          emptyLabel="No MITRE ATT&CK data available"
          onRetry={() => setRefreshKey((k) => k + 1)}
        >
          <div className="overflow-x-auto pb-4 -mx-4 sm:mx-0 px-4 sm:px-0">
            <div className="flex gap-1 min-w-max bg-surface-300/50 p-1 rounded-xl">
              {mitreMatrix.map((tactic) => {
                const tacticCount = tactic.techniques.length;
                return (
                  <div key={tactic.id} className="w-[150px] flex-shrink-0 flex flex-col gap-[2px]">
                    {/* Tactic header */}
                    <div className="sticky top-0 z-10 bg-surface-200 border border-line-1 rounded px-2 py-2 text-center min-h-[52px] flex flex-col justify-center">
                      <a
                        href={`https://attack.mitre.org/tactics/${tactic.id}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                        title={tactic.description ?? tactic.name}
                      >
                        <div className="text-micro font-mono font-bold leading-tight text-heading">{tactic.name}</div>
                        <div className="text-micro font-mono text-muted mt-0.5">{tacticCount} techniques</div>
                      </a>
                    </div>

                    {/* Technique cells */}
                    {tactic.techniques.map((technique) => {
                      const score = scores[technique.id];
                      const isObserved = matrixSource !== 'attack' || !!score || usedByActors.has(technique.id);
                      const bg =
                        matrixSource === 'attack'
                          ? getColor(score, colorMode)
                          : matrixSource === 'a3m'
                            ? '#8F00FF'
                            : '#0ea5e9';
                      const fg = fgFor(bg);
                      const isMatch = matches ? matches.has(technique.id) : true;
                      const isDimmed = matches !== null && !isMatch;
                      const isSelected = selectedId === technique.id;
                      const actors = actorsByTechnique(technique.id);

                      return (
                        <button
                          key={technique.id}
                          type="button"
                          onClick={() => openTechnique(technique.id)}
                          className={[
                            'relative w-full text-left border px-1.5 py-1 min-h-[42px] transition-all text-[10.5px] leading-tight overflow-hidden word-break-break-word hyphens-auto rounded',
                            isSelected ? 'ring-2 ring-brand-500/60 dark:ring-brand-400/60' : '',
                            isDimmed ? 'opacity-25' : '',
                            isObserved
                              ? 'border-2 border-slate-900 dark:border-slate-100 cursor-pointer hover:brightness-95'
                              : 'border border-line-1 cursor-default',
                          ].join(' ')}
                          style={{ backgroundColor: bg, color: fg }}
                          title={technique.name}
                        >
                          <div className={`font-mono ${isObserved ? 'font-semibold' : 'font-medium'}`}>
                            {technique.id}
                          </div>
                          <div className={`mt-0.5 ${isObserved ? 'font-semibold' : 'font-medium'} line-clamp-2`}>
                            {technique.name}
                          </div>
                          {score && score.pct_actors > 0 && (
                            <div className="mt-0.5 font-mono text-micro opacity-80">
                              {score.pct_actors.toFixed(1)}% actors
                            </div>
                          )}
                          {actors.length > 0 && matrixSource === 'attack' && (
                            <div className="mt-0.5 font-mono text-micro opacity-80">
                              {actors.length === 1 ? actors[0]!.name : `${actors.length} actors`}
                            </div>
                          )}
                          {technique.subtechniques && technique.subtechniques.length > 0 && (
                            <div className="mt-0.5 font-mono text-micro opacity-60">
                              +{technique.subtechniques.length} sub
                            </div>
                          )}
                        </button>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Legend footer */}
          <div className="mt-8 flex flex-wrap gap-4 text-xs font-mono text-muted">
            <div className="flex items-center gap-2">
              <span className="inline-block w-4 h-4 rounded border-2 border-slate-900 dark:border-line-1 bg-surface-100" />
              Observed technique (clickable)
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block w-4 h-4 rounded border border-line-1 bg-surface-100" />
              Not observed
            </div>
          </div>
        </DataState>
      </div>

      {/* Detail drawer */}
      {selectedId && (
        <>
          <div
            className="fixed inset-0 z-40 bg-surface-100/40 dark:bg-input-200/60 backdrop-blur-sm"
            onClick={closeDrawer}
            aria-hidden="true"
          />
          <aside
            ref={drawerRef as React.RefObject<HTMLElement>}
            role="dialog"
            aria-modal="true"
            aria-labelledby="navigator-detail-title"
            className="fixed right-0 top-0 z-50 h-full w-full max-w-xl overflow-y-auto bg-surface-100 border-l border-line-1 shadow-2xl"
          >
            <div className="sticky top-0 z-10 flex items-center justify-between gap-4 px-6 py-4 bg-surface-100/95 border-b border-line-1 backdrop-blur">
              <div className="min-w-0">
                <span className="text-micro font-mono uppercase tracking-wider text-brand-600 dark:text-brand-400">
                  {selectedId}
                </span>
                <h2 id="navigator-detail-title" className="font-display font-bold text-lg text-heading truncate">
                  {selectedTechnique?.name ?? selectedId}
                </h2>
              </div>
              <button
                type="button"
                onClick={closeDrawer}
                aria-label="Close details"
                className="shrink-0 inline-flex items-center justify-center min-h-[44px] min-w-[44px] rounded text-muted hover:text-heading dark:hover:text-slate-100 hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
              >
                <X size={18} aria-hidden="true" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-6">
              {/* Activity stats */}
              {selectedScore && matrixSource === 'attack' && (
                <div className="bg-surface-200 rounded-xl p-4 border border-line-1">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-3">Activity</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted">Distinct actors:</span>
                      <span className="font-mono font-semibold">
                        {selectedScore.n_actors} ({selectedScore.pct_actors.toFixed(1)}% prevalence)
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted">Total observations:</span>
                      <span className="font-mono font-semibold">{selectedScore.count.toLocaleString()}</span>
                    </div>
                    <div className="border-t border-line-1 pt-2 mt-2">
                      <div className="text-micro font-mono uppercase text-muted mb-1">ARiES Risk Score</div>
                      <div className="flex justify-between">
                        <span className="text-muted">Raw mean:</span>
                        <span className="font-mono font-semibold">{selectedScore.raw_mean.toFixed(1)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted">Adjusted (mean x prevalence):</span>
                        <span className="font-mono font-semibold">{selectedScore.adjusted.toFixed(1)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted">Prevalence multiplier:</span>
                        <span className="font-mono font-semibold">{selectedScore.prevalence}x</span>
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted">Scored observations:</span>
                      <span className="font-mono font-semibold">{selectedScore.n_scored}</span>
                    </div>
                  </div>
                  <div className="mt-3">
                    <span
                      className="inline-block px-3 py-1 rounded font-mono text-sm font-bold"
                      style={{
                        backgroundColor: getRiskColor(selectedScore.raw_mean),
                        color: fgFor(getRiskColor(selectedScore.raw_mean)),
                      }}
                    >
                      {RISK_THRESHOLDS.find((t) => selectedScore.raw_mean >= t.min)?.label ?? 'Low'} Risk
                    </span>
                  </div>
                </div>
              )}

              {/* Linked actors */}
              {selectedActors.length > 0 && (
                <div>
                  <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">
                    Tracked actors using this technique ({selectedActors.length})
                  </h3>
                  <div className="space-y-1.5">
                    {selectedActors.map((a) => (
                      <div key={a.slug} className="px-3 py-2 rounded border border-line-1 bg-surface-200">
                        <div className="text-sm font-semibold text-heading">{a.name}</div>
                        {a.aliases.length > 0 && (
                          <div className="text-xs font-mono text-muted mt-0.5">
                            aka {a.aliases.slice(0, 4).join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sub-techniques */}
              {selectedTechnique &&
                'subtechniques' in selectedTechnique &&
                (selectedTechnique as { subtechniques?: Array<{ id: string; name: string }> }).subtechniques && (
                  <div>
                    <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">Sub-techniques</h3>
                    <div className="space-y-1">
                      {(selectedTechnique as { subtechniques: Array<{ id: string; name: string }> }).subtechniques.map(
                        (sub) => {
                          const subScore = scores[sub.id];
                          return (
                            <div
                              key={sub.id}
                              className="flex items-center gap-3 px-3 py-2 rounded border border-line-1 bg-surface-200"
                            >
                              <span className="text-xs font-mono text-brand-600 dark:text-brand-400 w-20 flex-shrink-0">
                                {sub.id}
                              </span>
                              <span className="text-sm text-heading flex-1">{sub.name}</span>
                              {subScore && (
                                <span
                                  className="text-xs font-mono px-2 py-0.5 rounded font-semibold"
                                  style={{
                                    backgroundColor: getRiskColor(subScore.raw_mean),
                                    color: fgFor(getRiskColor(subScore.raw_mean)),
                                  }}
                                >
                                  {subScore.raw_mean.toFixed(0)}
                                </span>
                              )}
                            </div>
                          );
                        }
                      )}
                    </div>
                  </div>
                )}

              {/* D3FEND definition (A3M doesn't have one; D3FEND does) */}
              {selectedTechnique &&
                matrixSource === 'd3fend' &&
                (selectedTechnique as MitreTechniqueLite & { d3fend_id?: string; definition?: string }).definition && (
                  <div>
                    <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">Definition</h3>
                    <p className="text-sm text-body leading-relaxed">
                      {(selectedTechnique as MitreTechniqueLite & { definition?: string }).definition}
                    </p>
                  </div>
                )}

              {/* External link */}
              <a
                href={
                  matrixSource === 'attack'
                    ? `https://attack.mitre.org/techniques/${selectedId}/`
                    : matrixSource === 'a3m'
                      ? 'https://www.cyberriskevaluator.com/A3M_Matrix_Agentic_AI_Attack_Matrix.html'
                      : `https://d3fend.mitre.org/technique/${(selectedTechnique as MitreTechniqueLite & { d3fend_id?: string })?.d3fend_id ?? selectedId}/`
                }
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded border border-line-1 bg-surface-200 text-body hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
              >
                {matrixSource === 'attack'
                  ? 'Open on attack.mitre.org'
                  : matrixSource === 'a3m'
                    ? 'Open A3M Matrix'
                    : 'Open on d3fend.mitre.org'}{' '}
                <ExternalLink size={12} />
              </a>
            </div>
          </aside>
        </>
      )}
    </div>
  );
}
