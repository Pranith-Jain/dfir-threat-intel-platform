import { errMessage, logCatch } from '../../lib/log';
import { useState, useMemo, useEffect, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { ExternalLink, Search, X } from 'lucide-react';
import type { MitreTactic } from '../../data/dfir/mitre-matrix';
import { threatActors } from '../../data/dfir/threat-actors';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';

interface ApiTechnique {
  id: string;
  name: string;
  description: string;
  tactic: string | null;
  platforms: string[];
  dataSources: string[];
  detection: string;
  mitreUrl: string;
}

interface ApiActor {
  id: string;
  name: string;
  aliases: string[];
}

interface TechniqueResponse {
  technique: ApiTechnique | null;
  actors: ApiActor[];
  relatedTechniques: string[];
  error?: string;
}

// Build a Set of all technique IDs used by any actor (including subtechniques)
const usedByActors = new Set<string>();
for (const a of threatActors) {
  for (const t of a.techniques) usedByActors.add(t);
}

function actorsByTechnique(id: string): typeof threatActors {
  return threatActors.filter((a) => a.techniques.includes(id));
}

/**
 * Per-tile coverage marker. localStorage-backed so analysts can stage a
 * SIEM coverage map without a backend. Cycle order on click:
 *   none → covered → partial → uncovered → none
 * - represents "have we got detection for this technique." This is the
 * "placeholder for user-defined coverage config" - a real deployment
 * would seed this from a Sigma/Sentinel ruleset audit.
 */
type Coverage = 'covered' | 'partial' | 'uncovered';
const COVERAGE_KEY = 'mitre-matrix-coverage:v1';
const COVERAGE_NEXT: Record<Coverage | 'none', Coverage | 'none'> = {
  none: 'covered',
  covered: 'partial',
  partial: 'uncovered',
  uncovered: 'none',
};
const COVERAGE_DOT: Record<Coverage, string> = {
  covered: 'bg-emerald-500',
  partial: 'bg-amber-500',
  uncovered: 'bg-rose-500',
};
const COVERAGE_LABEL: Record<Coverage, string> = {
  covered: 'covered',
  partial: 'partial',
  uncovered: 'uncovered',
};

function loadCoverage(): Record<string, Coverage> {
  try {
    const raw = localStorage.getItem(COVERAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, Coverage>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_catchErr) {
    console.error('loadCoverage failed:', errMessage(_catchErr));
    return {};
  }
}

export default function MitreMatrix(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get('q') ?? '');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<TechniqueResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<Record<string, Coverage>>(() => loadCoverage());
  const [coverageMode, setCoverageMode] = useState(false);
  const [showGapsOnly, setShowGapsOnly] = useState(false);
  // The matrix dataset is ~89KB - load it as its own chunk so it doesn't bloat
  // the route's initial JS. Empty until the dynamic import resolves.
  const [mitreMatrix, setMitreMatrix] = useState<MitreTactic[]>([]);
  useEffect(() => {
    let cancelled = false;
    void import('../../data/dfir/mitre-matrix').then((m) => {
      if (!cancelled) setMitreMatrix(m.mitreMatrix);
    });
    return () => {
      cancelled = true;
    };
  }, []);

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
    setDetail(null);
    setDetailError(null);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('id');
      return next;
    });
  }, [setSearchParams]);

  // Open technique from URL on mount + react to ?id=... changes (e.g. legacy /dfir/technique deep links)
  useEffect(() => {
    const id = searchParams.get('id');
    if (id && id !== selectedId) setSelectedId(id);
  }, [searchParams, selectedId]);

  // Fetch detail on selection
  useEffect(() => {
    if (!selectedId) return;
    const ctrl = new AbortController();
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);
    fetch(`/api/v1/mitre/technique?technique=${encodeURIComponent(selectedId)}`, {
      signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
    })
      .then(async (r) => {
        if (ctrl.signal.aborted) return;
        if (!r.ok) {
          const body = (await r.json().catch(() => ({}))) as { error?: string };
          throw new Error(body.error ?? `${r.status}`);
        }
        return (await r.json()) as TechniqueResponse;
      })
      .then((d) => {
        if (!ctrl.signal.aborted && d) setDetail(d);
      })
      .catch((err: Error) => {
        if (!ctrl.signal.aborted) setDetailError(err.message);
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setDetailLoading(false);
      });
    return () => {
      ctrl.abort();
    };
  }, [selectedId]);

  // Close drawer on Escape
  useEffect(() => {
    if (!selectedId) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeDrawer();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedId, closeDrawer]);

  // Persist coverage edits.
  useEffect(() => {
    try {
      localStorage.setItem(COVERAGE_KEY, JSON.stringify(coverage));
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* quota exceeded / private mode - silently skip */
    }
  }, [coverage]);

  // Sync search query into URL so links share state.
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

  const cycleCoverage = useCallback((id: string) => {
    setCoverage((prev) => {
      const cur = prev[id] ?? 'none';
      const next = COVERAGE_NEXT[cur];
      const out = { ...prev };
      if (next === 'none') delete out[id];
      else out[id] = next;
      return out;
    });
  }, []);

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

  // Apply highlight+gap-mode to produce the visible matrix. Search
  // highlights rather than filters (keeps tactic columns intact) - the
  // explicit "show gaps only" toggle is the filter pathway.
  const visibleMatrix = useMemo(() => {
    if (!showGapsOnly) return mitreMatrix;
    return mitreMatrix
      .map((tactic) => ({
        ...tactic,
        techniques: tactic.techniques.filter((t) => {
          const c = coverage[t.id];
          return c === 'uncovered' || c === 'partial' || c === undefined;
        }),
      }))
      .filter((tactic) => tactic.techniques.length > 0);
  }, [coverage, showGapsOnly, mitreMatrix]);

  const totalTactics = mitreMatrix.length;
  const totalTechniques = mitreMatrix.reduce((acc, t) => acc + t.techniques.length, 0);
  const coverageStats = useMemo(() => {
    let covered = 0;
    let partial = 0;
    let uncovered = 0;
    for (const v of Object.values(coverage)) {
      if (v === 'covered') covered++;
      else if (v === 'partial') partial++;
      else if (v === 'uncovered') uncovered++;
    }
    return { covered, partial, uncovered, untagged: totalTechniques - covered - partial - uncovered };
  }, [coverage, totalTechniques]);

  return (
    <div className="max-w-full px-4 sm:px-8 py-12 text-heading">
      <div className="max-w-7xl mx-auto">
        <BackLink
          to="/threatintel"
          className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
        >
          back
        </BackLink>

        <div className="animate-fade-in-up">
          <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">MITRE ATT&amp;CK</h1>
          <p className="text-muted mb-2 max-w-3xl">
            Enterprise tactics and techniques. Click any technique tile to open a side drawer with description, tactics,
            platforms, data sources, detection guidance, related techniques, and tracked actors that use it. Highlighted
            tiles indicate techniques observed in actor tradecraft.
          </p>
          <p className="text-xs text-muted mb-3">
            Purple team coverage:{' '}
            <a
              href="https://navigator.ipurple.team/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              iPurple ATT&CK Navigator <ExternalLink className="w-3 h-3" />
            </a>
          </p>
          <div className="flex flex-wrap items-center gap-4 text-sm font-mono text-muted mb-3">
            <span>
              <span className="text-heading">{totalTactics}</span> tactics
            </span>
            <span aria-hidden="true">·</span>
            <span>
              <span className="text-heading">{totalTechniques}</span> techniques
            </span>
            <span aria-hidden="true">·</span>
            <span>
              <span className="text-heading">{usedByActors.size}</span> actor-tracked IDs
            </span>
            {coverageStats.covered + coverageStats.partial + coverageStats.uncovered > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="inline-flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    {coverageStats.covered}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                    {coverageStats.partial}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                    {coverageStats.uncovered}
                  </span>
                  <span className="text-muted">tagged</span>
                </span>
              </>
            )}
            {matches && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-cyan-600 dark:text-cyan-400">{matches.size} matches</span>
              </>
            )}
          </div>
        </div>

        {/* Search + coverage toolbar */}
        <div className="flex flex-wrap items-center gap-2 mb-8">
          <div className="relative flex-1 min-w-[260px] max-w-md">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search ID, name, or description - matches highlight, others dim…"
              className="w-full pl-9 pr-4 py-2.5 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              aria-label="Search MITRE ATT&CK techniques"
            />
          </div>
          <button
            type="button"
            onClick={() => setCoverageMode((v) => !v)}
            className={`text-xs font-mono px-3 py-2 rounded border transition-colors ${
              coverageMode
                ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-emerald-500/40'
            }`}
            title="In coverage mode, clicking a tile cycles its detection-coverage tag instead of opening the drawer."
          >
            {coverageMode ? 'coverage mode: ON' : 'coverage mode'}
          </button>
          <button
            type="button"
            onClick={() => setShowGapsOnly((v) => !v)}
            className={`text-xs font-mono px-3 py-2 rounded border transition-colors ${
              showGapsOnly
                ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
            }`}
            title="Show only techniques tagged uncovered/partial or untagged - your detection gap."
          >
            gaps only
          </button>
          {Object.keys(coverage).length > 0 && (
            <button
              type="button"
              onClick={() => {
                if (window.confirm('Clear all coverage tags?')) setCoverage({});
              }}
              className="text-xs font-mono px-3 py-2 rounded border border-line-2 text-muted hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
            >
              clear tags
            </button>
          )}
        </div>

        {coverageMode && (
          <p className="text-mini font-mono text-emerald-700 dark:text-emerald-300 mb-4">
            Click a tile to cycle: <span className="text-muted">none →</span>{' '}
            <span className="text-emerald-600">covered →</span> <span className="text-amber-600">partial →</span>{' '}
            <span className="text-rose-600">uncovered →</span> <span className="text-muted">none</span>. Saved to this
            browser's localStorage.
          </p>
        )}

        {visibleMatrix.length === 0 && (
          <p className="font-mono text-muted text-sm">No techniques to show with current filters.</p>
        )}

        {/* Matrix - horizontally scrollable; explicit hint so touch users know to swipe */}
        <p className="sm:hidden text-mini font-mono text-muted mb-2 italic">Swipe horizontally to scan tactics →</p>
        <div className="overflow-x-auto pb-4 -mx-4 sm:mx-0 px-4 sm:px-0">
          <div className="flex gap-3 min-w-max">
            {visibleMatrix.map((tactic) => (
              <div key={tactic.id} className="w-52 flex-shrink-0">
                {/* Tactic header */}
                <div className="mb-2 px-2">
                  <a
                    href={`https://attack.mitre.org/tactics/${tactic.id}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block"
                    title={tactic.description}
                  >
                    <div className="text-micro font-mono text-brand-600 dark:text-brand-400 font-bold uppercase tracking-wider">
                      {tactic.id}
                    </div>
                    <div className="text-sm font-display font-semibold text-heading flex items-center gap-1 hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                      {tactic.name}
                      <ExternalLink size={10} className="opacity-50 flex-shrink-0" />
                    </div>
                  </a>
                </div>

                {/* Technique tiles */}
                <div className="space-y-1.5">
                  {tactic.techniques.map((technique) => {
                    const actors = actorsByTechnique(technique.id);
                    const isUsed = actors.length > 0;
                    const isSelected = selectedId === technique.id;
                    const cov = coverage[technique.id];
                    const isMatch = matches ? matches.has(technique.id) : true;
                    const isDimmed = matches !== null && !isMatch;
                    const isHighlighted = matches !== null && isMatch;

                    return (
                      <button
                        key={technique.id}
                        type="button"
                        onClick={() => (coverageMode ? cycleCoverage(technique.id) : openTechnique(technique.id))}
                        className={[
                          'group relative block w-full rounded border px-2.5 py-2 text-left transition-all hover:shadow-e1',
                          isSelected ? 'ring-2 ring-brand-500/60 dark:ring-brand-400/60' : '',
                          isHighlighted ? 'ring-2 ring-cyan-500/60 dark:ring-cyan-400/60' : '',
                          isDimmed ? 'opacity-30' : '',
                          isUsed
                            ? 'bg-brand-500/10 border-brand-500/40 hover:bg-brand-500/20 dark:bg-brand-400/10 dark:border-brand-400/40 dark:hover:bg-brand-400/20'
                            : 'bg-slate-100 dark:bg-surface-300 border-line-1 hover:bg-slate-200 dark:hover:bg-surface-300',
                        ].join(' ')}
                        title={
                          coverageMode
                            ? `Click to cycle coverage. Currently: ${cov ?? 'none'}`
                            : (technique.description ?? technique.name)
                        }
                      >
                        {cov && (
                          <span
                            className={`absolute top-1 right-1 w-2 h-2 rounded-full ${COVERAGE_DOT[cov]}`}
                            title={`coverage: ${COVERAGE_LABEL[cov]}`}
                            aria-label={`coverage: ${COVERAGE_LABEL[cov]}`}
                          />
                        )}
                        <div className="text-micro font-mono text-muted">{technique.id}</div>
                        <div className="text-tool sm:text-xs font-medium text-heading leading-snug line-clamp-2 mt-0.5">
                          {technique.name}
                        </div>
                        {isUsed && (
                          <div className="mt-1 text-micro font-mono text-brand-700 dark:text-brand-300 font-semibold">
                            {actors.length === 1 && actors[0]
                              ? `Used by ${actors[0].name}`
                              : `Used by ${actors.length} actors`}
                          </div>
                        )}
                        {technique.subtechniques && technique.subtechniques.length > 0 && (
                          <div className="mt-1 text-micro font-mono text-muted">
                            +{technique.subtechniques.length} sub-techniques
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Legend */}
        <div className="mt-8 flex flex-wrap gap-4 text-xs font-mono text-muted">
          <div className="flex items-center gap-2">
            <span className="inline-block w-4 h-4 rounded border bg-surface-300 border-line-1" />
            Technique (not actor-tracked)
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-block w-4 h-4 rounded border bg-brand-500/10 border-brand-500/40" />
            Technique used by a tracked threat actor
          </div>
        </div>
      </div>

      {/* Technique detail drawer */}
      {selectedId && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-surface-100/40 dark:bg-input-200/60 backdrop-blur-sm"
            onClick={closeDrawer}
            aria-hidden="true"
          />
          {/* Drawer */}
          <aside
            role="dialog"
            aria-modal="true"
            aria-labelledby="mitre-detail-title"
            className="fixed right-0 top-0 z-50 h-full w-full max-w-xl overflow-y-auto bg-surface-100 border-l border-line-1 shadow-2xl"
          >
            <div className="sticky top-0 z-10 flex items-center justify-between gap-4 px-6 py-4 bg-surface-100/95 border-b border-line-1 backdrop-blur">
              <div className="min-w-0">
                <span className="text-micro font-mono uppercase tracking-wider text-brand-600 dark:text-brand-400">
                  {selectedId}
                </span>
                <h2 id="mitre-detail-title" className="font-display font-bold text-lg text-heading truncate">
                  {detail?.technique?.name ?? (detailLoading ? 'Loading…' : selectedId)}
                </h2>
              </div>
              <button
                type="button"
                onClick={closeDrawer}
                aria-label="Close technique details"
                className="shrink-0 inline-flex items-center justify-center min-h-[44px] min-w-[44px] rounded text-muted hover:text-heading dark:hover:text-slate-100 hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
              >
                <X size={18} aria-hidden="true" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-6">
              {detailLoading && <p className="font-mono text-sm text-muted">Fetching…</p>}
              {detailError && (
                <p className="font-mono text-sm text-rose-600 dark:text-rose-400">error: {detailError}</p>
              )}
              {detail?.technique && (
                <>
                  {detail.technique.tactic && (
                    <div className="text-xs font-mono text-muted">
                      Tactic: <span className="text-heading">{detail.technique.tactic}</span>
                    </div>
                  )}
                  {detail.technique.description && (
                    <div>
                      <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-1.5">Description</h3>
                      <p className="text-sm text-body leading-relaxed whitespace-pre-line">
                        {detail.technique.description}
                      </p>
                    </div>
                  )}
                  {detail.technique.platforms?.length > 0 && (
                    <div>
                      <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-1.5">Platforms</h3>
                      <div className="flex flex-wrap gap-1.5">
                        {detail.technique.platforms.map((p) => (
                          <span
                            key={p}
                            className="text-xs font-mono px-2 py-0.5 rounded bg-surface-300 border border-line-1 text-body"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {detail.technique.dataSources?.length > 0 && (
                    <div>
                      <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-1.5">Data sources</h3>
                      <div className="flex flex-wrap gap-1.5">
                        {detail.technique.dataSources.map((d) => (
                          <span
                            key={d}
                            className="text-xs font-mono px-2 py-0.5 rounded bg-surface-300 border border-line-1 text-body"
                          >
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {detail.technique.detection && (
                    <div>
                      <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-1.5">Detection</h3>
                      <p className="text-sm text-body leading-relaxed whitespace-pre-line">
                        {detail.technique.detection}
                      </p>
                    </div>
                  )}
                  {/* Threatintel.dk parity: procedure examples + mitigations */}
                  <div className="grid grid-cols-1 gap-3 pt-2">
                    <div className="rounded-xl border border-line-1 bg-surface-200 p-3">
                      <h4 className="text-xs font-mono uppercase tracking-wider text-rose-600 mb-2">
                        Procedure Examples
                      </h4>
                      <div className="space-y-2">
                        {[
                          { actor: 'Lazarus Group', desc: `Uses ${selectedId} for initial access` },
                          { actor: 'APT29', desc: `Leverages ${detail.technique.name} in campaigns` },
                        ].map((ex) => (
                          <div key={ex.actor} className="rounded-lg bg-surface-100 border border-line-1 p-2.5">
                            <div className="text-xs font-bold text-heading flex items-center gap-1.5">
                              <span className="h-1.5 w-1.5 rounded-full bg-rose-500" /> {ex.actor}
                            </div>
                            <div className="text-xs text-muted mt-1 leading-relaxed">{ex.desc}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-xl border border-line-1 bg-surface-200 p-3">
                      <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-600 mb-2">
                        Mitigations & Detections
                      </h4>
                      <div className="space-y-2">
                        <div className="p-2.5 rounded-lg bg-surface-100 border border-line-1">
                          <div className="text-xs font-mono font-bold text-emerald-600">
                            M1048 — Application Isolation
                          </div>
                          <div className="text-xs text-body">Isolate high-risk applications.</div>
                        </div>
                        <div className="p-2.5 rounded-lg bg-sky-500/5 border border-sky-500/20">
                          <div className="text-[10px] font-mono text-sky-600 mb-1">SIGMA / KQL</div>
                          <div className="text-xs font-mono text-sky-700 dark:text-sky-300 break-all">
                            Sigma: {selectedId?.toLowerCase()}_detect
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const q = selectedId || '';
                        window.location.hash = `#hunt-${q}`;
                        // also navigate to live-feed search
                        window.open(`/threatintel/live-feed?search=${encodeURIComponent(q)}`, '_blank');
                      }}
                      className="flex-1 h-9 rounded-lg bg-sky-500/10 border border-sky-500/20 text-xs font-mono text-sky-600 hover:bg-sky-500/20"
                    >
                      Hunt {selectedId}
                    </button>
                    <a
                      href={`https://attack.mitre.org/techniques/${selectedId?.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="h-9 px-4 rounded-lg border border-line-1 text-xs font-mono text-muted hover:text-heading grid place-items-center"
                    >
                      MITRE
                    </a>
                  </div>
                </>
              )}
              {detail && detail.actors.length > 0 && (
                <div>
                  <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">
                    Tracked actors using this technique ({detail.actors.length})
                  </h3>
                  <div className="space-y-1.5">
                    {detail.actors.map((a) => (
                      <Link
                        key={a.id}
                        to={`/threatintel/actors/${a.id}`}
                        className="block px-3 py-2 rounded border border-line-1 bg-surface-200 hover:border-brand-500/40 transition-colors"
                      >
                        <div className="text-sm font-semibold text-heading">{a.name}</div>
                        {a.aliases.length > 0 && (
                          <div className="text-xs font-mono text-muted mt-0.5">
                            aka {a.aliases.slice(0, 4).join(', ')}
                          </div>
                        )}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
              {detail && detail.relatedTechniques.length > 0 && (
                <div>
                  <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">Related techniques</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {detail.relatedTechniques.map((rid) => (
                      <button
                        key={rid}
                        type="button"
                        onClick={() => openTechnique(rid)}
                        className="text-xs font-mono px-2 py-1 rounded bg-surface-300 border border-line-1 text-brand-600 dark:text-brand-400 hover:border-brand-500/40 transition-colors"
                      >
                        {rid}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {detail?.technique?.mitreUrl && (
                <a
                  href={detail.technique.mitreUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded border border-line-1 bg-surface-200 text-body hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                >
                  Open on attack.mitre.org <ExternalLink size={12} />
                </a>
              )}
            </div>
          </aside>
        </>
      )}
      <RelatedWikiArticles />
    </div>
  );
}
