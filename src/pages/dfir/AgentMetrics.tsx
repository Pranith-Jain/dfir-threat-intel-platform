import { useEffect, useState, lazy, Suspense } from 'react';
import { adminAuthHeaders } from '../../lib/admin-token';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { errMessage } from '../../lib/log';

const RelationshipGraph = lazy(() => import('../../components/dfir/RelationshipGraph'));

interface KnowledgeGraphData {
  nodes: Array<{ id: string; label: string; type: string }>;
  edges: Array<{ source: string; target: string; relationship: string; confidence: 'high' | 'medium' | 'low' }>;
}

interface AgentMetricsData {
  totalInvestigations: number;
  successRate: number;
  avgQualityScore: number;
  avgStepsPerInvestigation: number;
  avgDurationMs: number;
  errorRate: number;
  topTools: Array<{ tool: string; count: number; avgDurationMs: number; successRate: number }>;
  topModels: Array<{ model: string; count: number; avgScore: number }>;
  recentErrors: Array<{ query: string; error: string; at: string }>;
  features: {
    parallelBurst: number;
    selfCorrection: number;
    avgScoreDelta: number;
    routingRefinements: number;
    avgFindings: number;
    avgCostUsd: number;
    convergenceIterations: number;
    avgSelfEvalScore: number;
    dataGapsCount: number;
  };
}

interface ProviderHealthData {
  healthy: boolean;
  lastRateLimit: number;
  consecutiveFailures: number;
  successes: number;
  failures: number;
  avgResponseMs: number;
}

interface MemoryEntry {
  query: string;
  queryType: string;
  actors: string[];
  cves: string[];
  mitre: string[];
  keyFindings: string[];
  qualityScore: number;
  completedAt: string;
}

function Stat({ label, value, suffix }: { label: string; value: string | number; suffix?: string }): JSX.Element {
  return (
    <div className="surface-card p-3">
      <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
      <div className="text-2xl font-bold text-heading">
        {value}
        {suffix ? <span className="text-sm font-normal text-muted">{suffix}</span> : null}
      </div>
    </div>
  );
}

export default function AgentMetrics(): JSX.Element {
  const [data, setData] = useState<AgentMetricsData | null>(null);
  const [providers, setProviders] = useState<Record<string, ProviderHealthData> | null>(null);
  const [memory, setMemory] = useState<MemoryEntry[] | null>(null);
  const [graph, setGraph] = useState<KnowledgeGraphData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const headers = adminAuthHeaders();
    const opts = { headers, credentials: 'same-origin' as const };
    Promise.all([
      fetch('/api/v1/agent/metrics', opts).then(async (r) => {
        if (r.status === 401 || r.status === 403) {
          throw new Error('Agent metrics require an admin session. Set your admin token in Settings.');
        }
        if (!r.ok) throw new Error(`Failed to load metrics (HTTP ${r.status}).`);
        return (await r.json()) as AgentMetricsData;
      }),
      fetch('/api/v1/agent/provider-health', opts)
        .then((r) => (r.ok ? (r.json() as Promise<Record<string, ProviderHealthData>>) : null))
        .catch(() => null),
      fetch('/api/v1/agent/memory?limit=15', opts)
        .then((r) => (r.ok ? (r.json() as Promise<{ investigations: MemoryEntry[] }>) : null))
        .catch(() => null),
      fetch('/api/v1/agent/knowledge-graph?limit=80', opts)
        .then((r) => (r.ok ? (r.json() as Promise<KnowledgeGraphData>) : null))
        .catch(() => null),
    ])
      .then(([metrics, prov, mem, kg]) => {
        if (cancelled) return;
        setData(metrics);
        setProviders(prov);
        setMemory(mem?.investigations ?? null);
        setGraph(kg);
      })
      .catch((e) => {
        if (!cancelled) setError(errMessage(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <div className="p-8 text-center font-mono text-sm text-muted">Loading metrics…</div>;
  if (error) return <div className="p-8 text-center font-mono text-sm text-rose-600">{error}</div>;
  if (!data || data.totalInvestigations === 0)
    return <div className="p-8 text-center font-mono text-sm text-muted">No investigations recorded yet.</div>;

  const f = data.features;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Investigations" value={data.totalInvestigations} />
        <Stat label="Success" value={data.successRate} suffix="%" />
        <Stat label="Avg Quality" value={data.avgQualityScore} suffix="/100" />
        <Stat label="Avg Steps" value={data.avgStepsPerInvestigation} />
        <Stat label="Avg Duration" value={(data.avgDurationMs / 1000).toFixed(1)} suffix="s" />
        <Stat label="Avg Cost" value={`$${f.avgCostUsd.toFixed(4)}`} />
      </div>

      <div>
        <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">Feature Telemetry</h3>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          <Stat label="Parallel Burst" value={f.parallelBurst} />
          <Stat label="Self-Correction" value={f.selfCorrection} />
          <Stat label="Avg Score Δ" value={f.avgScoreDelta > 0 ? `+${f.avgScoreDelta}` : f.avgScoreDelta} />
          <Stat label="Route Refinements" value={f.routingRefinements} />
          <Stat label="Avg Findings" value={f.avgFindings} />
          <Stat label="GAN Convergence" value={f.convergenceIterations ?? 0} />
          <Stat label="Avg Self-Eval" value={f.avgSelfEvalScore ? `${f.avgSelfEvalScore.toFixed(1)}/5` : '—'} />
          <Stat label="Data Gaps" value={f.dataGapsCount ?? 0} />
        </div>
      </div>

      {providers && (
        <div>
          <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">LLM Provider Health</h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {Object.entries(providers).map(([name, p]) => (
              <div key={name} className="surface-card p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold text-heading">{name}</span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-micro font-mono font-bold ${
                      p.healthy ? 'bg-emerald-500/10 text-emerald-600' : 'bg-rose-500/10 text-rose-600'
                    }`}
                  >
                    {p.healthy ? 'HEALTHY' : 'DEGRADED'}
                  </span>
                </div>
                <div className="mt-2 text-micro font-mono text-muted">
                  {p.avgResponseMs > 0 ? `${Math.round(p.avgResponseMs)}ms · ` : ''}
                  {p.successes}✓ / {p.failures}✗
                  {p.consecutiveFailures > 0 ? ` · ${p.consecutiveFailures} consec. fails` : ''}
                  {p.lastRateLimit > 0 ? ' · rate-limited' : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">Top Tools (latency / success)</h3>
        <div className="surface-card overflow-x-auto">
          <DataTable
            columns={
              [
                {
                  key: 'tool',
                  header: 'Tool',
                  sortValue: (t: (typeof data.topTools)[number]) => t.tool,
                  render: (t) => <span className="font-mono text-heading">{t.tool}</span>,
                },
                {
                  key: 'count',
                  header: 'Calls',
                  align: 'right',
                  sortValue: (t: (typeof data.topTools)[number]) => t.count,
                  render: (t) => <span className="tabular-nums">{t.count}</span>,
                },
                {
                  key: 'avgDurationMs',
                  header: 'Avg ms',
                  align: 'right',
                  sortValue: (t: (typeof data.topTools)[number]) => t.avgDurationMs,
                  render: (t) => <span className="tabular-nums">{t.avgDurationMs}</span>,
                },
                {
                  key: 'successRate',
                  header: 'Success',
                  align: 'right',
                  sortValue: (t: (typeof data.topTools)[number]) => t.successRate,
                  render: (t) => (
                    <span
                      className={`tabular-nums font-semibold ${t.successRate < 50 ? 'text-rose-600' : t.successRate < 80 ? 'text-amber-600' : 'text-emerald-600'}`}
                    >
                      {t.successRate}%
                    </span>
                  ),
                },
              ] as DataTableColumn<(typeof data.topTools)[number]>[]
            }
            rows={data.topTools}
            rowKey={(t) => t.tool}
          />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div>
          <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">Top Models</h3>
          <div className="surface-card divide-y divide-line-1">
            {data.topModels.map((m) => (
              <div key={m.model} className="flex items-center justify-between px-3 py-2 text-sm">
                <span className="font-mono text-heading">{m.model}</span>
                <span className="tabular-nums text-muted">
                  {m.count}× · avg {m.avgScore}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">Recent Errors</h3>
          <div className="surface-card divide-y divide-line-1">
            {data.recentErrors.length === 0 ? (
              <div className="px-3 py-2 text-sm text-muted">None.</div>
            ) : (
              data.recentErrors.map((e, i) => (
                <div key={i} className="px-3 py-2 text-sm">
                  <div className="font-mono text-heading truncate">{e.query}</div>
                  <div className="text-rose-600 text-xs truncate">{e.error}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {memory && memory.length > 0 && (
        <div>
          <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">Investigation Memory</h3>
          <div className="surface-card divide-y divide-line-1">
            {memory.map((m, i) => (
              <div key={i} className="px-3 py-2 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-heading truncate">{m.query}</span>
                  <span className="shrink-0 tabular-nums text-micro text-muted">{m.qualityScore}/100</span>
                </div>
                <div className="mt-0.5 flex flex-wrap gap-1 text-micro font-mono text-muted">
                  <span className="rounded bg-surface-300 px-1">{m.queryType}</span>
                  {m.actors.slice(0, 2).map((a) => (
                    <span key={a} className="rounded bg-rose-500/10 px-1 text-rose-600">
                      {a}
                    </span>
                  ))}
                  {m.cves.slice(0, 2).map((c) => (
                    <span key={c} className="rounded bg-amber-500/10 px-1 text-amber-600">
                      {c}
                    </span>
                  ))}
                  {m.mitre.slice(0, 3).map((t) => (
                    <span key={t} className="rounded bg-cyan-500/10 px-1 text-cyan-600">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {graph && graph.nodes.length > 0 && (
        <div>
          <h3 className="text-mini font-mono uppercase tracking-wider text-muted mb-2">
            Knowledge Graph ({graph.nodes.length} entities, {graph.edges.length} relationships)
          </h3>
          <Suspense fallback={<div className="h-[460px] animate-pulse rounded-xl bg-surface-300" />}>
            <RelationshipGraph graph={graph} />
          </Suspense>
        </div>
      )}
    </div>
  );
}
