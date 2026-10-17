import { useCallback, useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Activity, GitBranch, Loader2, Network, RefreshCw, Search } from 'lucide-react';

// ── Lazy-load the heavy ReactFlow canvas ────────────────────────────────
import { lazy, Suspense } from 'react';
import { errMessage } from '../../lib/log';
const EntityCanvas = lazy(() => import('./EntityGraphCanvas'));

// ── Types ───────────────────────────────────────────────────────────────

type EntityType = 'cve' | 'actor' | 'ioc' | 'sector' | 'technique';

interface EntityNode {
  id: string;
  type: EntityType;
  label: string;
  subtitle?: string;
  weight?: number;
}

interface EntityEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

interface GraphResponse {
  nodes: EntityNode[];
  edges: EntityEdge[];
  stats: { total_nodes: number; total_edges: number; by_type: Record<EntityType, number> };
  generated_at: string;
}

// ── Constants ───────────────────────────────────────────────────────────

const NODE_COLORS: Record<EntityType, string> = {
  cve: '#f59e0b',
  actor: '#ef4444',
  ioc: '#3b82f6',
  sector: '#10b981',
  technique: '#8b5cf6',
};

const NODE_LABELS: Record<EntityType, string> = {
  cve: 'CVEs',
  actor: 'Actors',
  ioc: 'IOC Families',
  sector: 'Sectors',
  technique: 'Techniques',
};

// ── Main component ──────────────────────────────────────────────────────

export default function EntityGraphPage(): JSX.Element {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<Set<EntityType>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');

  const fetchGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/entity-graph?limit=200');
      if (!res.ok) throw new Error(`Graph unavailable (${res.status})`);
      setGraph(await res.json());
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchGraph();
  }, [fetchGraph]);

  const toggleType = useCallback((t: EntityType) => {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  }, []);

  const filteredNodes = useMemo(() => {
    if (!graph) return [];
    return graph.nodes.filter((n) => {
      if (typeFilter.size > 0 && !typeFilter.has(n.type)) return false;
      if (searchQuery && !n.label.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      return true;
    });
  }, [graph, typeFilter, searchQuery]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);
  const filteredEdges = useMemo(
    () => (graph?.edges ?? []).filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)),
    [graph, filteredNodeIds]
  );

  const filteredGraph = useMemo(
    () => (graph ? { ...graph, nodes: filteredNodes, edges: filteredEdges } : null),
    [graph, filteredNodes, filteredEdges]
  );

  const stats = graph?.stats;

  return (
    <DataPageLayout
      title="Entity Graph"
      description="Interactive topology of threat-intel entities - CVEs, actors, IOCs, sectors, and techniques"
      icon={<Network size={20} />}
      accentClass="text-violet-500"
      backTo="/threatintel"
    >
      {/* ── Stats bar ───────────────────────────────────────────────── */}
      {stats && (
        <div className="flex flex-wrap gap-2 mb-4">
          {Object.entries(stats.by_type).map(([type, count]) => {
            const t = type as EntityType;
            const active = typeFilter.size === 0 || typeFilter.has(t);
            return (
              <button
                type="button"
                key={t}
                onClick={() => toggleType(t)}
                className={`flex items-center gap-1.5 rounded-xl px-2.5 py-1.5 text-xs font-mono transition-all ${
                  active
                    ? 'border-2 bg-white shadow-sm dark:bg-surface-200'
                    : 'border border-slate-200 bg-slate-50 opacity-50 dark:border-line-1 dark:bg-surface-100'
                }`}
                style={active ? { borderColor: NODE_COLORS[t] } : undefined}
              >
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: NODE_COLORS[t] }} />
                <span className="font-semibold">{count}</span>
                <span className="text-muted">{NODE_LABELS[t]}</span>
              </button>
            );
          })}
          <div className="ml-auto flex items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter nodes…"
                className="h-8 w-40 rounded-xl border border-line-1 bg-surface-100 pl-7 pr-2 text-xs dark:text-white"
              />
            </div>
            <button
              type="button"
              onClick={fetchGraph}
              className="flex items-center gap-1 rounded-xl p-1.5 text-muted hover:text-rose-600 transition-colors"
              aria-label="Refresh"
            >
              <RefreshCw size={13} />
            </button>
          </div>
        </div>
      )}

      {/* ── Canvas ──────────────────────────────────────────────────── */}
      {loading && (
        <div className="flex items-center justify-center py-24">
          <Loader2 size={28} className="animate-spin text-rose-500" />
          <span className="ml-3 font-mono text-sm text-muted">Building graph…</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-300 bg-rose-50/50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300">
          {error}
        </div>
      )}

      {!loading && !error && filteredGraph && (
        <div
          className="rounded-xl border border-line-1 bg-surface-100 overflow-hidden"
          style={{ height: 'calc(100vh - 280px)', minHeight: 500 }}
        >
          <Suspense
            fallback={
              <div className="flex items-center justify-center h-full">
                <Loader2 size={20} className="animate-spin text-muted" />
              </div>
            }
          >
            <EntityCanvas graphData={filteredGraph} />
          </Suspense>
        </div>
      )}

      {/* ── Legend ───────────────────────────────────────────────────── */}
      <div className="mt-4 flex flex-wrap items-center justify-center gap-4 text-mini font-mono text-muted">
        <span className="flex items-center gap-1.5">
          <GitBranch size={11} />
          {filteredEdges.length} edges
        </span>
        <span className="flex items-center gap-1.5">
          <Activity size={11} />
          {filteredNodes.length} nodes
        </span>
        {graph && <span>Generated {new Date(graph.generated_at).toLocaleTimeString()}</span>}
      </div>
    </DataPageLayout>
  );
}
