import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback, useRef, useEffect, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  Search,
  Globe,
  Clock,
  Users,
  Server,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Network,
  Mail,
  Building2,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';

const API = '/api/v1';

interface WhoisSnapshot {
  id: number;
  domain: string;
  registrar?: string;
  registrant_name?: string;
  registrant_org?: string;
  registrant_email?: string;
  created_date?: string;
  expires_date?: string;
  updated_date?: string;
  nameservers: string[];
  status: string[];
  source: string;
  snapshot_at: string;
}

interface WhoisChange {
  id: number;
  domain: string;
  change_type: string;
  field_name: string;
  old_value?: string;
  new_value?: string;
  detected_at: string;
}

interface DomainPivot {
  domain: string;
  match_reason: string;
  match_value: string;
  first_seen: string;
  last_seen: string;
  snapshot_count: number;
  current_registrar?: string;
}

interface HistoryResult {
  domain: string;
  current: WhoisSnapshot | null;
  snapshots: WhoisSnapshot[];
  changes: WhoisChange[];
  summary: {
    total_snapshots: number;
    ownership_transfers: number;
    registrar_changes: number;
    nameserver_changes: number;
    first_seen: string;
    last_seen: string;
  };
}

interface PivotResult {
  target: string;
  pivot_type: string;
  related_domains: DomainPivot[];
  total_found: number;
  query_time_ms: number;
}

const CHANGE_ICONS: Record<string, typeof Users> = {
  registrant: Users,
  registrar: Building2,
  nameservers: Server,
  status: AlertTriangle,
};

const CHANGE_COLORS: Record<string, string> = {
  registrant: 'text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800/50',
  registrar:
    'text-brand-600 dark:text-brand-400 bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800/50',
  nameservers:
    'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/50',
  status:
    'text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-950/20 border-purple-200 dark:border-purple-800/50',
};

const PIVOT_ICONS: Record<string, typeof Mail> = {
  shared_registrant_email: Mail,
  shared_registrant_org: Building2,
  shared_nameserver: Server,
  shared_registrar: Globe,
};

export default function WhoisHistory(): JSX.Element {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<HistoryResult | null>(null);
  const [pivots, setPivots] = useState<PivotResult | null>(null);
  const [pivotLoading, setPivotLoading] = useState(false);
  const [expandedSnapshot, setExpandedSnapshot] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'timeline' | 'changes' | 'pivots'>('timeline');
  const ctrlRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      ctrlRef.current?.abort();
    };
  }, []);

  const fetchHistory = useCallback(async (domain: string) => {
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    setLoading(true);
    setError('');
    setHistory(null);
    setPivots(null);
    try {
      const res = await fetch(`${API}/domain/history?domain=${encodeURIComponent(domain)}`, { signal: ctrl.signal });
      if (!mountedRef.current || ctrl.signal.aborted) return;
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { message?: string };
        throw new Error(body.message || `HTTP ${res.status}`);
      }
      const data = (await res.json()) as HistoryResult;
      if (!mountedRef.current || ctrl.signal.aborted) return;
      setHistory(data);
      setActiveTab('timeline');
    } catch (e) {
      logCatch(e);
      if (e instanceof DOMException && e.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(errMessage(e, 'lookup failed'));
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  const fetchPivots = useCallback(async (domain: string, type: string = 'all') => {
    setPivotLoading(true);
    try {
      const res = await fetch(`${API}/domain/history/pivot?domain=${encodeURIComponent(domain)}&type=${type}`);
      if (!mountedRef.current) return;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as PivotResult;
      if (!mountedRef.current) return;
      setPivots(data);
      setActiveTab('pivots');
    } catch (e) {
      logCatch(e);
      if (e instanceof DOMException && e.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(errMessage(e, 'pivot failed'));
    } finally {
      if (mountedRef.current) setPivotLoading(false);
    }
  }, []);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) void fetchHistory(query.trim());
  };

  const formatDate = (d?: string) => {
    if (!d) return '-';
    try {
      return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch (_catchErr) {
      logCatch(_catchErr);
      return d;
    }
  };

  const formatDateTime = (d?: string) => {
    if (!d) return '-';
    try {
      return new Date(d).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch (_catchErr) {
      logCatch(_catchErr);
      return d;
    }
  };

  return (
    <div className="max-w-6xl">
      <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">WHOIS History Explorer</h1>
      <p className="text-muted mb-8">
        Track domain registration changes over time and discover related domains by shared registrant fingerprints.
        Inspired by etugen.io's WHOIS history capabilities.
      </p>

      <form onSubmit={onSubmit} className="flex gap-2 mb-8">
        <div className="relative flex-1">
          <Globe size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="example.com"
            aria-label="Domain name"
            className="w-full pl-10 pr-4 py-2.5 surface-card text-sm font-mono focus-visible:ring-2 focus-visible:ring-brand-500 focus:border-transparent"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !query.trim()}
          className="px-4 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-on-fill text-sm font-medium disabled:opacity-50 inline-flex items-center gap-2 transition-colors"
        >
          {loading ? <RefreshCw size={14} className="animate-spin" /> : <Search size={14} />}
          {loading ? 'Looking up…' : 'Search'}
        </button>
      </form>

      {error && (
        <div className="mb-6 p-3 rounded-xl bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/50 text-rose-700 dark:text-rose-300 text-sm font-mono">
          <AlertTriangle size={14} className="inline mr-2" />
          {error}
        </div>
      )}

      {history && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            {[
              { label: 'Snapshots', value: history.summary.total_snapshots, icon: Clock },
              { label: 'Ownership Transfers', value: history.summary.ownership_transfers, icon: Users },
              { label: 'Registrar Changes', value: history.summary.registrar_changes, icon: Building2 },
              { label: 'NS Changes', value: history.summary.nameserver_changes, icon: Server },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="p-3 surface-card">
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={14} className="text-muted" />
                  <span className="text-mini font-mono uppercase text-muted">{label}</span>
                </div>
                <span className="text-2xl font-mono font-bold">{value}</span>
              </div>
            ))}
          </div>

          {history.current && (
            <div className="mb-6 p-4 surface-card">
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Globe size={14} className="text-brand-600" /> Current Registration
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-muted">Registrar:</span>{' '}
                  <span className="font-mono">{history.current.registrar ?? '-'}</span>
                </div>
                <div>
                  <span className="text-muted">Created:</span>{' '}
                  <span className="font-mono">{formatDate(history.current.created_date)}</span>
                </div>
                <div>
                  <span className="text-muted">Expires:</span>{' '}
                  <span className="font-mono">{formatDate(history.current.expires_date)}</span>
                </div>
                <div>
                  <span className="text-muted">Updated:</span>{' '}
                  <span className="font-mono">{formatDate(history.current.updated_date)}</span>
                </div>
                {history.current.registrant_email && (
                  <div className="sm:col-span-2">
                    <span className="text-muted">Registrant:</span>{' '}
                    <span className="font-mono">{history.current.registrant_email}</span>
                  </div>
                )}
                {history.current.nameservers.length > 0 && (
                  <div className="sm:col-span-2">
                    <span className="text-muted">Nameservers:</span>{' '}
                    <span className="font-mono text-xs">{history.current.nameservers.join(', ')}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="flex gap-1 mb-4 border-b border-line-1">
            {(['timeline', 'changes', 'pivots'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => {
                  setActiveTab(tab);
                  if (tab === 'pivots' && !pivots && history) void fetchPivots(history.domain);
                }}
                className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${
                  activeTab === tab
                    ? 'border-brand-600 text-brand-600 dark:text-brand-400'
                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                {tab}{' '}
                {tab === 'changes' && history.changes.length > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 rounded-full text-micro bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400">
                    {history.changes.length}
                  </span>
                )}
              </button>
            ))}
          </div>

          {activeTab === 'timeline' && (
            <div className="space-y-3">
              {history.snapshots.length === 0 ? (
                <p className="text-sm text-muted text-center py-8">
                  No WHOIS history recorded yet. The first snapshot was just taken.
                </p>
              ) : (
                history.snapshots.map((snap, i) => (
                  <div key={snap.id} className="border border-line-1 rounded-xl bg-surface-100 overflow-hidden">
                    <button
                      onClick={() => setExpandedSnapshot(expandedSnapshot === snap.id ? null : snap.id)}
                      className="w-full flex items-center justify-between p-3 text-left hover:bg-surface-200 dark:hover:bg-surface-300/50"
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-2 h-2 rounded-full ${i === 0 ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-surface-300'}`}
                        />
                        <span className="text-sm font-mono">{formatDateTime(snap.snapshot_at)}</span>
                        <span className="text-xs px-2 py-0.5 rounded bg-surface-300 text-muted">{snap.source}</span>
                      </div>
                      {expandedSnapshot === snap.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>
                    {expandedSnapshot === snap.id && (
                      <div className="px-3 pb-3 pt-1 border-t border-line-1 text-sm space-y-1">
                        <div>
                          <span className="text-muted">Registrar:</span>{' '}
                          <span className="font-mono">{snap.registrar ?? '-'}</span>
                        </div>
                        <div>
                          <span className="text-muted">Created:</span>{' '}
                          <span className="font-mono">{formatDate(snap.created_date)}</span>
                        </div>
                        <div>
                          <span className="text-muted">Expires:</span>{' '}
                          <span className="font-mono">{formatDate(snap.expires_date)}</span>
                        </div>
                        {snap.registrant_email && (
                          <div>
                            <span className="text-muted">Registrant Email:</span>{' '}
                            <span className="font-mono">{snap.registrant_email}</span>
                          </div>
                        )}
                        {snap.registrant_org && (
                          <div>
                            <span className="text-muted">Registrant Org:</span>{' '}
                            <span className="font-mono">{snap.registrant_org}</span>
                          </div>
                        )}
                        {snap.nameservers.length > 0 && (
                          <div>
                            <span className="text-muted">Nameservers:</span>{' '}
                            <span className="font-mono text-xs">{snap.nameservers.join(', ')}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'changes' && (
            <div className="space-y-3">
              {history.changes.length === 0 ? (
                <p className="text-sm text-muted text-center py-8">No ownership or infrastructure changes detected.</p>
              ) : (
                history.changes.map((change) => {
                  const Icon = CHANGE_ICONS[change.change_type] ?? AlertTriangle;
                  const colorClass =
                    CHANGE_COLORS[change.change_type] ?? 'text-slate-600 bg-slate-50 dark:bg-surface-300 border-line-1';
                  return (
                    <div key={change.id} className={`p-3 rounded-xl border ${colorClass}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <Icon size={14} />
                        <span className="text-xs font-semibold uppercase">{change.change_type}</span>
                        <span className="text-xs text-muted ml-auto">{formatDateTime(change.detected_at)}</span>
                      </div>
                      <div className="text-sm grid grid-cols-1 sm:grid-cols-2 gap-1">
                        <div className="line-through text-muted font-mono text-xs break-all">
                          {change.old_value ?? '-'}
                        </div>
                        <div className="font-mono text-xs break-all">{change.new_value ?? '-'}</div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {activeTab === 'pivots' && (
            <div>
              {pivotLoading ? (
                <div className="text-center py-8">
                  <RefreshCw size={20} className="animate-spin mx-auto text-brand-600" />
                  <p className="text-sm text-muted mt-2">Searching for related domains…</p>
                </div>
              ) : pivots && pivots.related_domains.length > 0 ? (
                <>
                  <div className="mb-4 flex items-center justify-between">
                    <p className="text-sm text-muted">
                      Found <span className="font-bold text-brand-600">{pivots.total_found}</span> related domains
                      sharing registrant attributes with <span className="font-mono">{pivots.target}</span>
                    </p>
                    <span className="text-xs font-mono text-muted">{pivots.query_time_ms}ms</span>
                  </div>
                  <div className="space-y-2">
                    {pivots.related_domains.map((d) => {
                      const PivotIcon = PIVOT_ICONS[d.match_reason] ?? Network;
                      return (
                        <div key={`${d.domain}-${d.match_reason}`} className="p-3 surface-card">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <PivotIcon size={14} className="text-brand-600" />
                              <span className="font-mono text-sm font-medium">{d.domain}</span>
                            </div>
                            <a
                              href={`https://${d.domain}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-muted hover:text-brand-600 transition-colors"
                            >
                              <ExternalLink size={12} />
                            </a>
                          </div>
                          <div className="mt-1 flex flex-wrap gap-2 text-mini">
                            <span className="px-1.5 py-0.5 rounded bg-brand-50 dark:bg-brand-950/20 text-brand-700 dark:text-brand-300">
                              {d.match_reason.replace(/_/g, ' ')}
                            </span>
                            <span className="text-muted">{d.match_value}</span>
                            {d.current_registrar && <span className="text-muted">via {d.current_registrar}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              ) : pivots ? (
                <p className="text-sm text-muted text-center py-8">
                  No related domains found sharing registrant attributes.
                </p>
              ) : (
                <p className="text-sm text-muted text-center py-8">Click "Pivot" to find related domains.</p>
              )}
            </div>
          )}
        </>
      )}

      {!history && !loading && !error && (
        <div className="text-center py-16">
          <Globe size={48} className="mx-auto mb-4 text-inverted dark:text-muted" />
          <p className="text-muted">Enter a domain to explore its WHOIS registration history</p>
          <p className="text-xs text-muted mt-1">
            Track ownership changes, registrar transfers, and pivot across related domains
          </p>
          <p className="text-xs text-muted mt-3">
            Want to find all domains by an email? Try{' '}
            <Link to="/dfir/whoxy" className="text-brand-600 dark:text-brand-400 hover:underline">
              Whoxy Reverse WHOIS
            </Link>
          </p>
        </div>
      )}
    </div>
  );
}
