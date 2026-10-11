import { useState, type FormEvent } from 'react';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { Search, Globe, Server, Clock, AlertTriangle, CheckCircle, Loader2 } from 'lucide-react';

interface PassiveDnsRecord {
  query: string;
  resolved: string;
  rrtype: string;
  first_seen: string;
  last_seen: string;
  count: number;
  source: string;
}

interface PassiveDnsResult {
  query: string;
  query_type: string;
  records: PassiveDnsRecord[];
  unique_resolved: string[];
  migrations: Array<{
    indicator: string;
    from: string;
    to: string;
    detected_at: string;
    confidence: number;
  }>;
  fast_flux: {
    unique_ips: number;
    observation_window_hours: number;
    rotation_rate: number;
    is_fast_flux: boolean;
    severity: string;
  } | null;
  source_summary: Record<string, number>;
  total_observations: number;
  query_time_ms: number;
}

export default function PassiveDns(): JSX.Element {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<PassiveDnsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await fetch(`/api/v1/passive-dns?query=${encodeURIComponent(query.trim())}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error('PassiveDns failed:', err instanceof Error ? err.message : String(err));
      setError(err instanceof Error ? err.message : 'Failed to query passive DNS');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-6xl">

      <h1 className="font-display font-bold text-3xl mb-2">Passive DNS Lookup</h1>
      <p className="text-sm font-mono text-muted mb-6 max-w-2xl">
        Query historical DNS resolution data from multiple sources. Track infrastructure migrations, detect fast-flux,
        and pivot across related IPs and domains.
      </p>

      {/* Search Form */}
      <form onSubmit={handleSubmit} className="mb-8">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter domain or IP address..."
              aria-label="Domain or IP address for passive DNS lookup"
              className="w-full pl-10 pr-4 py-3 surface-card font-mono text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="px-6 py-3 rounded-xl bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-on-fill font-mono text-sm font-medium transition-colors"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : 'Query'}
          </button>
        </div>
      </form>

      {/* Error */}
      {error && (
        <div className="mb-6 p-4 rounded-xl bg-rose-50 dark:bg-rose-900/20 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 font-mono text-sm">
          <AlertTriangle size={16} className="inline mr-2" />
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 surface-card">
              <div className="text-2xl font-bold text-brand-600 dark:text-brand-400">
                {result.unique_resolved.length}
              </div>
              <div className="text-xs font-mono text-muted">Unique IPs</div>
            </div>
            <div className="p-4 surface-card">
              <div className="text-2xl font-bold text-brand-600 dark:text-brand-400">{result.total_observations}</div>
              <div className="text-xs font-mono text-muted">Total Records</div>
            </div>
            <div className="p-4 surface-card">
              <div className="text-2xl font-bold text-brand-600 dark:text-brand-400">
                {Object.keys(result.source_summary).length}
              </div>
              <div className="text-xs font-mono text-muted">Sources</div>
            </div>
            <div className="p-4 surface-card">
              <div className="text-2xl font-bold text-brand-600 dark:text-brand-400">{result.query_time_ms}ms</div>
              <div className="text-xs font-mono text-muted">Query Time</div>
            </div>
          </div>

          {/* Source Breakdown */}
          <div className="p-4 surface-card">
            <h2 className="font-display font-semibold mb-3 flex items-center gap-2">
              <Server size={16} /> Sources
            </h2>
            <div className="flex flex-wrap gap-3">
              {Object.entries(result.source_summary).map(([source, count]) => (
                <span
                  key={source}
                  className="px-3 py-1 rounded-full bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 text-xs font-mono"
                >
                  {source}: {count}
                </span>
              ))}
            </div>
          </div>

          {/* Migrations Detected */}
          {result.migrations.length > 0 && (
            <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20">
              <h2 className="font-display font-semibold mb-3 flex items-center gap-2 text-amber-700 dark:text-amber-300">
                <AlertTriangle size={16} /> Infrastructure Migrations Detected
              </h2>
              <div className="space-y-2">
                {result.migrations.map((m, i) => (
                  <div key={i} className="text-sm font-mono text-amber-800 dark:text-amber-200">
                    {m.from} → {m.to} (confidence: {(m.confidence * 100).toFixed(0)}%)
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Fast Flux */}
          {result.fast_flux && result.fast_flux.is_fast_flux && (
            <div className="p-4 rounded-xl border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-900/20">
              <h2 className="font-display font-semibold mb-3 flex items-center gap-2 text-rose-700 dark:text-rose-300">
                <AlertTriangle size={16} /> Fast-Flux Detection
              </h2>
              <div className="text-sm font-mono text-rose-800 dark:text-rose-200">
                {result.fast_flux.unique_ips} unique IPs in {result.fast_flux.observation_window_hours}h - rotation
                rate: {result.fast_flux.rotation_rate} IPs/day - severity: {result.fast_flux.severity}
              </div>
            </div>
          )}

          {/* Resolved IPs */}
          {result.unique_resolved.length > 0 && (
            <div className="p-4 surface-card">
              <h2 className="font-display font-semibold mb-3 flex items-center gap-2">
                <Globe size={16} /> Resolved IPs
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {result.unique_resolved
                  .filter((ip) => !ip.startsWith('['))
                  .map((ip) => (
                    <div key={ip} className="flex items-center gap-2 text-sm font-mono">
                      <CheckCircle size={14} className="text-emerald-500" />
                      <span>{ip}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Records Table */}
          {result.records.length > 0 && (
            <div className="p-4 surface-card">
              <h2 className="font-display font-semibold mb-3 flex items-center gap-2">
                <Clock size={16} /> Resolution History
              </h2>
              <div className="overflow-x-auto">
                <DataTable
                  rows={result.records.slice(0, 20)}
                  rowKey={(r, i) => `${r.source}-${r.resolved}-${i}`}
                  initialSort={{ key: 'first_seen', dir: 'desc' }}
                  columns={
                    [
                      {
                        key: 'source',
                        header: 'Source',
                        render: (r) => r.source,
                        sortValue: (r) => r.source,
                        className: 'font-mono',
                      },
                      {
                        key: 'resolved',
                        header: 'Resolved',
                        render: (r) => r.resolved,
                        sortValue: (r) => r.resolved,
                        className: 'font-mono',
                      },
                      {
                        key: 'rrtype',
                        header: 'Type',
                        render: (r) => r.rrtype,
                        sortValue: (r) => r.rrtype,
                        className: 'font-mono',
                      },
                      {
                        key: 'first_seen',
                        header: 'First Seen',
                        render: (r) => <span className="text-muted">{r.first_seen.slice(0, 10)}</span>,
                        sortValue: (r) => r.first_seen,
                        className: 'font-mono',
                      },
                    ] as DataTableColumn<PassiveDnsRecord>[]
                  }
                />
                {result.records.length > 20 && (
                  <div className="text-xs text-muted mt-2 font-mono">Showing 20 of {result.records.length} records</div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
