import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, useCallback } from 'react';
import { Search, Filter, Download, Database, ChevronDown, ChevronUp } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { DataState } from '../../components/DataState';
import { PageMeta } from '../../components/PageMeta';
import { downloadBlob } from '../../lib/download';

interface StixBundle {
  bundle_id: string;
  source_id: string;
  source_type: string;
  title: string;
  stix_published_at: string | null;
  api_created_at: string | null;
  ioc_count: number;
  actor_count: number;
  malware_count: number;
}

type FilterOp = 'eq' | 'neq' | 'gte' | 'lte' | 'cs' | 'like' | 'ilike';

interface FilterRow {
  column: string;
  op: FilterOp;
  value: string;
}

const COLUMNS = [
  { value: 'bundle_id', label: 'Bundle ID' },
  { value: 'source_type', label: 'Source Type' },
  { value: 'title', label: 'Title' },
  { value: 'threat_actors', label: 'Threat Actors' },
  { value: 'malware_names', label: 'Malware' },
  { value: 'sectors', label: 'Sectors' },
  { value: 'countries_target', label: 'Target Countries' },
  { value: 'vulnerabilities', label: 'CVEs' },
  { value: 'stix_published_at', label: 'Published' },
  { value: 'api_created_at', label: 'Ingested' },
  { value: 'ioc_count', label: 'IOC Count' },
  { value: 'actor_count', label: 'Actor Count' },
  { value: 'malware_count', label: 'Malware Count' },
];

export default function ThreatLandscapeStix(): JSX.Element {
  const [data, setData] = useState<StixBundle[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [select, setSelect] = useState(
    'bundle_id,source_type,title,threat_actors,malware_names,sectors,stix_published_at'
  );
  const [limit, setLimit] = useState('20');
  const [order, setOrder] = useState('stix_published_at.desc');
  const [filters, setFilters] = useState<FilterRow[]>([]);
  const [showFilters, setShowFilters] = useState(false);

  const buildQueryString = useCallback(() => {
    const params = new URLSearchParams();
    if (select) params.set('select', select);
    if (limit) params.set('limit', limit);
    if (order) params.set('order', order);
    for (const f of filters) {
      if (f.column && f.op && f.value) {
        params.set(f.column, `${f.op}.${f.value}`);
      }
    }
    return params.toString();
  }, [select, limit, order, filters]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const qs = buildQueryString();
      const res = await fetch(`/api/v1/stix_bundles${qs ? `?${qs}` : ''}`, {
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        throw new Error(err.error ?? `HTTP ${res.status}`);
      }
      const json = (await res.json()) as StixBundle[];
      setData(json);
    } catch (e) {
      logCatch(e);
      setError(errMessage(e, 'Unknown error'));
    } finally {
      setLoading(false);
    }
  }, [buildQueryString]);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  const addFilter = () => {
    setFilters([...filters, { column: 'source_type', op: 'eq', value: 'osint' }]);
  };

  const updateFilter = (i: number, field: keyof FilterRow, val: string) => {
    const next = [...filters];
    next[i] = { ...next[i]!, [field]: val };
    setFilters(next);
  };

  const removeFilter = (i: number) => {
    setFilters(filters.filter((_, idx) => idx !== i));
  };

  const exportAsJson = () => {
    if (!data?.length) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `stix-bundles-${Date.now()}.json`);
  };

  return (
    <>
      <PageMeta
        title="STIX Bundles - Threat Landscape"
        description="Query STIX 2.1 intelligence bundles with PostgREST-style filters"
        section="threatintel"
      />
      <DataPageLayout
        backTo="/threatintel"
        backLabel="Threat Intel"
        icon={<Database size={28} />}
        title="STIX Bundle Query"
        description="PostgREST-style query interface for STIX 2.1 intelligence bundles. Filter by threat actor, malware, sector, country, CVE, and more."
        headerExtra={
          <div className="flex gap-2">
            <button
              type="button"
              onClick={addFilter}
              className="text-xs flex items-center gap-1 px-2 py-1 rounded border border-line-2 hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
            >
              <Filter size={12} /> Add Filter
            </button>
            <button
              type="button"
              onClick={exportAsJson}
              disabled={!data?.length}
              className="text-xs flex items-center gap-1 px-2 py-1 rounded border border-line-2 hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-40 transition-colors"
            >
              <Download size={12} /> Export JSON
            </button>
          </div>
        }
      >
        {/* Controls */}
        <div className="mb-4 space-y-2">
          <div className="flex flex-wrap gap-2 items-center">
            <label className="text-xs font-medium">Select:</label>
            <input
              value={select}
              onChange={(e) => setSelect(e.target.value)}
              className="flex-1 min-w-[200px] text-xs px-2 py-1 rounded border border-line-2 bg-surface-100"
              placeholder="bundle_id,source_type,title"
            />
            <label className="text-xs font-medium">Order:</label>
            <input
              value={order}
              onChange={(e) => setOrder(e.target.value)}
              className="w-52 text-xs px-2 py-1 rounded border border-line-2 bg-surface-100"
              placeholder="stix_published_at.desc"
            />
            <label className="text-xs font-medium">Limit:</label>
            <input
              type="number"
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
              className="w-20 text-xs px-2 py-1 rounded border border-line-2 bg-surface-100"
            />
            <button
              type="button"
              onClick={fetchData}
              className="text-xs flex items-center gap-1 px-3 py-1.5 rounded bg-rose-600 text-on-fill hover:bg-rose-700 transition-colors"
            >
              <Search size={12} /> Query
            </button>
          </div>

          {/* Filter builder */}
          <div>
            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className="text-xs flex items-center gap-1 text-muted"
            >
              {showFilters ? <ChevronUp size={12} /> : <ChevronDown size={12} />} Filters ({filters.length})
            </button>
            {showFilters && (
              <div className="mt-1 space-y-1">
                {filters.map((f, i) => (
                  <div key={i} className="flex flex-wrap gap-1 items-center">
                    <select
                      value={f.column}
                      onChange={(e) => updateFilter(i, 'column', e.target.value)}
                      className="text-xs px-2 py-1 rounded border border-line-2 bg-surface-100"
                    >
                      {COLUMNS.map((c) => (
                        <option key={c.value} value={c.value}>
                          {c.label}
                        </option>
                      ))}
                    </select>
                    <select
                      value={f.op}
                      onChange={(e) => updateFilter(i, 'op', e.target.value as FilterOp)}
                      className="text-xs px-2 py-1 rounded border border-line-2 bg-surface-100"
                    >
                      <option value="eq">= (eq)</option>
                      <option value="neq">!= (neq)</option>
                      <option value="gte">&ge; (gte)</option>
                      <option value="lte">&le; (lte)</option>
                      <option value="cs">contains (cs)</option>
                      <option value="like">like</option>
                    </select>
                    <input
                      value={f.value}
                      onChange={(e) => updateFilter(i, 'value', e.target.value)}
                      className="text-xs px-2 py-1 rounded border border-line-2 bg-surface-100 min-w-[200px]"
                      placeholder="Value"
                    />
                    <button
                      type="button"
                      onClick={() => removeFilter(i)}
                      className="text-xs px-2 py-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                    >
                      &times;
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Results */}
        <DataState
          loading={loading}
          error={error}
          empty={data?.length === 0}
          onRetry={fetchData}
          emptyLabel="No bundles match these filters."
        >
          {data && (
            <div className="overflow-x-auto rounded-xl border border-line-1">
              <DataTable
                columns={
                  [
                    {
                      key: 'bundle_id',
                      header: 'Bundle ID',
                      sortValue: (row: (typeof data)[number]) => row.bundle_id,
                      render: (row) => (
                        <span className="font-mono text-micro text-muted max-w-[200px] truncate" title={row.bundle_id}>
                          {row.bundle_id}
                        </span>
                      ),
                    },
                    {
                      key: 'source_type',
                      header: 'Type',
                      sortValue: (row: (typeof data)[number]) => row.source_type,
                      render: (row) => (
                        <span
                          className={`px-1.5 py-0.5 rounded-full text-micro ${row.source_type === 'darknet' ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300' : 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300'}`}
                        >
                          {row.source_type}
                        </span>
                      ),
                    },
                    {
                      key: 'title',
                      header: 'Title',
                      sortValue: (row: (typeof data)[number]) => row.title,
                      render: (row) => (
                        <span className="max-w-[300px] truncate" title={row.title}>
                          {row.title}
                        </span>
                      ),
                    },
                    {
                      key: 'published',
                      header: 'Published',
                      sortValue: (row: (typeof data)[number]) => row.stix_published_at ?? '',
                      render: (row) => (
                        <span className="text-muted">
                          {row.stix_published_at ? new Date(row.stix_published_at).toLocaleDateString() : '-'}
                        </span>
                      ),
                    },
                    {
                      key: 'ioc_count',
                      header: 'IOCs',
                      align: 'right',
                      sortValue: (row: (typeof data)[number]) => row.ioc_count,
                      render: (row) => <span className="font-mono">{row.ioc_count}</span>,
                    },
                    {
                      key: 'actor_count',
                      header: 'Actors',
                      align: 'right',
                      sortValue: (row: (typeof data)[number]) => row.actor_count,
                      render: (row) => <span className="font-mono">{row.actor_count}</span>,
                    },
                    {
                      key: 'malware_count',
                      header: 'Malware',
                      align: 'right',
                      sortValue: (row: (typeof data)[number]) => row.malware_count,
                      render: (row) => <span className="font-mono">{row.malware_count}</span>,
                    },
                  ] as DataTableColumn<(typeof data)[number]>[]
                }
                rows={data}
                rowKey={(row) => row.bundle_id}
                rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-slate-800/50'}
              />
            </div>
          )}
          {data && (
            <p className="text-micro text-muted mt-2">
              {data.length} bundle{data.length !== 1 ? 's' : ''}
            </p>
          )}
        </DataState>
      </DataPageLayout>
    </>
  );
}
