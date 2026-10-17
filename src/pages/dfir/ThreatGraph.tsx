import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback, useEffect } from 'react';
import { BackLink } from '../../components/BackLink';
import { api } from '../../lib/api-client';
import { readAdminToken } from '../../lib/admin-token';
import { Network, Search, Loader2, Shield, GitBranch, Users, BarChart3, Circle, Link2, Database } from 'lucide-react';

interface GraphNode {
  id: string;
  type: string;
  value: string;
  properties: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  confidence: number;
}
interface GraphEdge {
  id: string;
  source_id: string;
  target_id: string;
  relationship: string;
  confidence: number;
}
interface GraphStats {
  nodes: number;
  edges: number;
  node_types: Array<{ type: string; count: number }>;
  relationship_types: Array<{ relationship: string; count: number }>;
  density: number;
}
interface Community {
  id: string;
  nodes: GraphNode[];
  centroid_type: string;
  labels: string[];
  confidence: number;
}

const TYPE_BADGE: Record<string, string> = {
  ip: 'bg-blue-100 text-brand-800 dark:bg-blue-900/30 dark:text-brand-300',
  domain: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
  hash: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
  url: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  actor: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
  malware: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  campaign: 'bg-pink-100 text-pink-800 dark:bg-pink-900/30 dark:text-pink-300',
  cve: 'bg-sky-100 text-cyan-800 dark:bg-sky-500/10 dark:text-sky-300',
};

const TABS = ['stats', 'lookup', 'communities'] as const;
const TAB_LABEL: Record<string, string> = { stats: 'Statistics', lookup: 'Node Lookup', communities: 'Communities' };

export default function ThreatGraph(): JSX.Element {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<'lookup' | 'stats' | 'communities'>('stats');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [communities, setCommunities] = useState<Community[]>([]);
  const [searchResult, setSearchResult] = useState<{
    found: boolean;
    node?: GraphNode;
    neighbors?: GraphNode[];
    edges?: GraphEdge[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ingesting, setIngesting] = useState(false);
  const [ingestResult, setIngestResult] = useState<string | null>(null);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setStats(await api.get<GraphStats>('/api/v1/graph/stats'));
    } catch (e) {
      console.error('ThreatGraph failed:', errMessage(e));
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);
  const fetchCommunities = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await api.get<{ communities?: Community[] }>('/api/v1/graph/communities?min_size=2');
      setCommunities(d.communities ?? []);
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);
  const searchNode = useCallback(async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setSearchResult(null);
    try {
      let type = 'domain';
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query)) type = 'ip';
      else if (/^[a-fA-F0-9]{32,64}$/.test(query)) type = 'hash';
      else if (/^https?:\/\//.test(query)) type = 'url';
      setSearchResult(await api.get(`/api/v1/graph/node/${type}/${encodeURIComponent(query)}?depth=2`));
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    if (searchType === 'stats') fetchStats();
    else if (searchType === 'communities') fetchCommunities();
  }, [searchType, fetchStats, fetchCommunities]);

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
          <Network size={28} className="text-brand-600 dark:text-brand-400" /> Threat Intelligence Graph
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Relationship-based threat analysis and community detection.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-3 mb-6">
        <div className="flex gap-1.5">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setSearchType(t)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-colors ${searchType === t ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400' : 'border-line-1 text-slate-500 hover:border-brand-500/30'}`}
            >
              {TAB_LABEL[t]}
            </button>
          ))}
        </div>
        {readAdminToken() && (
          <button
            onClick={async () => {
              setIngesting(true);
              setIngestResult(null);
              try {
                const r = await api.post<{ ok: boolean; total: { nodes_upserted: number; edges_created: number } }>(
                  '/api/v1/graph/ingest?source=ioc'
                );
                setIngestResult(`Ingested ${r.total.nodes_upserted} nodes, ${r.total.edges_created} edges`);
                fetchStats();
              } catch (e) {
                logCatch(e);
                setIngestResult(`Error: ${errMessage(e)}`);
              } finally {
                setIngesting(false);
              }
            }}
            disabled={ingesting}
            className="ml-auto px-3 py-1.5 rounded-xl text-xs font-mono border border-line-1 text-muted hover:border-brand-500/30 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            {ingesting ? <Loader2 size={12} className="animate-spin" /> : <Database size={12} />}
            {ingesting ? 'Ingesting…' : 'Ingest IOC Sources'}
          </button>
        )}
      </div>
      {ingestResult && (
        <div className="rounded-xl border border-emerald-300/70 dark:border-emerald-800/60 bg-emerald-50/60 dark:bg-emerald-950/30 p-3 mb-6 text-xs text-emerald-700 dark:text-emerald-300 font-mono flex items-center gap-2">
          <Database size={12} />
          {ingestResult}
        </div>
      )}
      {searchType === 'lookup' && (
        <div className="surface-card/40 shadow-e1 p-5 mb-6">
          <div className="flex gap-2">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && searchNode()}
              placeholder="Enter IP, domain, hash, or URL…"
              className="flex-1 bg-surface-200 border border-line-1 rounded-xl px-4 py-2.5 text-sm font-mono text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
            <button
              onClick={searchNode}
              disabled={loading || !query.trim()}
              className="px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center gap-2"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />} Search
            </button>
          </div>
        </div>
      )}
      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 mb-6 text-sm text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}
      {searchType === 'stats' && stats && (
        <div className="space-y-5 animate-fade-in-up">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard label="Nodes" value={stats.nodes} icon={<Circle size={16} />} />
            <StatCard label="Edges" value={stats.edges} icon={<Link2 size={16} />} />
            <StatCard
              label="Density"
              value={parseFloat(stats.density.toString()).toFixed(4)}
              icon={<BarChart3 size={16} />}
            />
            <StatCard
              label="Avg Conn"
              value={stats.nodes > 0 ? ((stats.edges * 2) / stats.nodes).toFixed(1) : '0'}
              icon={<GitBranch size={16} />}
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="surface-card/40 shadow-e1 p-5">
              <h3 className="font-display font-bold text-sm mb-3">Node Types</h3>
              <div className="space-y-2">
                {stats.node_types.map((nt) => (
                  <div key={nt.type} className="flex items-center justify-between">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded ${TYPE_BADGE[nt.type] ?? ''}`}>
                      {nt.type}
                    </span>
                    <span className="text-xs text-muted font-mono">{nt.count}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="surface-card/40 shadow-e1 p-5">
              <h3 className="font-display font-bold text-sm mb-3">Relationships</h3>
              <div className="space-y-2">
                {stats.relationship_types.map((rt) => (
                  <div key={rt.relationship} className="flex items-center justify-between">
                    <span className="text-xs text-body">{rt.relationship}</span>
                    <span className="text-xs text-muted font-mono">{rt.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
      {searchType === 'lookup' && searchResult && (
        <div className="space-y-5 animate-fade-in-up">
          {searchResult.found && searchResult.node ? (
            <div className="surface-card/40 shadow-e1 p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-display font-bold font-mono">{searchResult.node.value}</h2>
                  <span
                    className={`text-micro font-mono px-1.5 py-0.5 rounded ${TYPE_BADGE[searchResult.node.type] ?? ''}`}
                  >
                    {searchResult.node.type}
                  </span>
                </div>
                <div className="text-right text-xs text-muted font-mono">
                  <div>Confidence: {searchResult.node.confidence}%</div>
                </div>
              </div>
              {searchResult.neighbors && searchResult.neighbors.length > 0 && (
                <div>
                  <h3 className="font-display font-bold text-sm mb-2">Connected ({searchResult.neighbors.length})</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                    {searchResult.neighbors.slice(0, 10).map((n) => (
                      <div
                        key={n.id}
                        className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-200 px-3 py-2"
                      >
                        <span className={`text-micro font-mono px-1.5 py-0.5 rounded ${TYPE_BADGE[n.type] ?? ''}`}>
                          {n.type}
                        </span>
                        <span className="text-xs font-mono truncate">{n.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <Network size={32} className="text-inverted dark:text-muted mx-auto mb-3" />
              <p className="text-sm text-muted">Node not found</p>
            </div>
          )}
        </div>
      )}
      {searchType === 'communities' && (
        <div className="space-y-4 animate-fade-in-up">
          {communities.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
              <Users size={32} className="text-inverted dark:text-muted mx-auto mb-3" />
              <p className="text-sm text-muted">No communities detected</p>
            </div>
          ) : (
            communities.map((c) => (
              <div key={c.id} className="surface-card/40 shadow-e1 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Shield size={14} className="text-brand-600 dark:text-brand-400" />
                    <span className="font-display font-bold text-sm">Community {c.id}</span>
                  </div>
                  <span className={`text-micro font-mono px-1.5 py-0.5 rounded ${TYPE_BADGE[c.centroid_type] ?? ''}`}>
                    {c.centroid_type}
                  </span>
                </div>
                {c.labels.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-3">
                    {c.labels.map((l, i) => (
                      <span
                        key={i}
                        className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 text-muted"
                      >
                        {l}
                      </span>
                    ))}
                  </div>
                )}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-1.5">
                  {c.nodes.slice(0, 6).map((n) => (
                    <div
                      key={n.id}
                      className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-200 px-3 py-2"
                    >
                      <span className={`text-micro font-mono px-1.5 py-0.5 rounded ${TYPE_BADGE[n.type] ?? ''}`}>
                        {n.type}
                      </span>
                      <span className="text-xs font-mono truncate">{n.value}</span>
                    </div>
                  ))}
                  {c.nodes.length > 6 && (
                    <div className="flex items-center rounded-xl border border-dashed border-line-2 px-3 py-2 text-xs text-muted">
                      +{c.nodes.length - 6} more
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon }: { label: string; value: string | number; icon?: React.ReactNode }) {
  return (
    <div className="surface-card/40 shadow-e1 p-4">
      <div className="flex items-center gap-2 mb-1.5">
        {icon && <span className="text-brand-600 dark:text-brand-400">{icon}</span>}
        <span className="text-micro font-mono uppercase tracking-wider text-muted">{label}</span>
      </div>
      <div className="text-2xl font-display font-bold">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );
}
