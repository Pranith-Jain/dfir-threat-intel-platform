/**
 * LeakScope — breach and dark-forum leak thread index.
 *
 * `/threatintel/leakscope`
 *
 * Shows *what was exposed and by whom* across breach and dark forums. It
 * deliberately shows no link to any leak: the upstream index is metadata
 * only, and this surface keeps it that way.
 *
 * The search runs server-side. The index holds ~12k rows, and shipping it
 * to the browser would mean a multi-megabyte download before the first
 * character is typed — for a page whose whole job is to be typed into.
 */

import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Database,
  Eye,
  FileWarning,
  MessageSquare,
  Search,
  ShieldAlert,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Card } from '../../components/ui/Card';
import { StatCards } from '../../components/ui/StatCards';
import { useApiData } from '../../hooks/useApiData';

interface LeakScopeRow {
  tid: string;
  source: string;
  prefix: string | null;
  title: string;
  author: string;
  published_at: string | null;
  replies: number;
  views: number;
  pages: number;
  attachments: number;
  last_post_at: string | null;
  last_post_by: string;
  status: string;
}

interface LeakScopeResponse {
  generated_at: string;
  source: string;
  source_url: string;
  license: string;
  synced_at: string;
  counts: Record<string, number>;
  total: number;
  page: number;
  limit: number;
  pages: number;
  entries: LeakScopeRow[];
}

const SORTS = [
  { id: 'published_at', label: 'Newest' },
  { id: 'views', label: 'Most viewed' },
  { id: 'replies', label: 'Most replies' },
  { id: 'author', label: 'Author' },
  { id: 'title', label: 'Title' },
];

function fmtDate(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function LeakScope(): JSX.Element {
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const [source, setSource] = useState('');
  const [sort, setSort] = useState('published_at');
  const [page, setPage] = useState(1);

  // Debounce the query so a fast typist does not fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(query.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [query]);

  const url = useMemo(() => {
    const params = new URLSearchParams();
    if (search) params.set('q', search);
    if (source) params.set('source', source);
    params.set('sort', sort);
    params.set('page', String(page));
    params.set('limit', '50');
    return `/api/v1/threat-intel/leakscope?${params.toString()}`;
  }, [search, source, sort, page]);

  const { data, loading, error, refetch } = useApiData<LeakScopeResponse>(url, { ttl: 60_000 });

  const counts = data?.counts ?? {};
  const stats = [
    { label: 'Threads', value: counts.total ?? 0, icon: <Database size={16} /> },
    { label: 'Breach', value: counts.breach ?? 0, icon: <ShieldAlert size={16} /> },
    { label: 'Dark forum', value: counts.darkforum ?? 0, icon: <FileWarning size={16} /> },
    { label: 'Authors', value: counts.authors ?? 0, icon: <MessageSquare size={16} /> },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Database size={28} />}
      title="LeakScope"
      description="Breach and dark-forum leak threads — title, author, date and engagement. Metadata only: this index never links to leaked data."
      maxWidthClass="max-w-7xl"
    >
      <div className="space-y-5">
        <Card padding="md" radius="panel" tone="rose">
          <p className="mb-3 flex items-start gap-2 rounded border border-line-1 bg-surface-100 px-3 py-2 text-micro text-muted">
            <AlertTriangle size={13} className="mt-0.5 flex-shrink-0" />
            <span>
              Metadata only. Every row describes a leak that was announced; none of them links to the data itself, and
              no download URLs were collected.
            </span>
          </p>

          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[14rem] flex-1">
              <label
                htmlFor="leakscope-q"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Search title, author or prefix
              </label>
              <div className="relative">
                <Search
                  size={14}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                  aria-hidden="true"
                />
                <input
                  id="leakscope-q"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="e.g. employees, health, bank"
                  spellCheck={false}
                  className="w-full rounded border border-line-1 bg-surface-100 py-2 pl-9 pr-3 text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="leakscope-source"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Source
              </label>
              <select
                id="leakscope-source"
                value={source}
                onChange={(e) => {
                  setSource(e.target.value);
                  setPage(1);
                }}
                className="rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              >
                <option value="">All</option>
                <option value="breach">Breach</option>
                <option value="darkforum">Dark forum</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="leakscope-sort"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Sort
              </label>
              <select
                id="leakscope-sort"
                value={sort}
                onChange={(e) => {
                  setSort(e.target.value);
                  setPage(1);
                }}
                className="rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              >
                {SORTS.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </Card>

        {error && (
          <Card padding="md" radius="panel" tone="rose">
            <p role="alert" className="flex items-center gap-2 text-tool text-rose-600 dark:text-rose-400">
              <AlertTriangle size={15} /> {error}
            </p>
            <button
              type="button"
              onClick={refetch}
              className="mt-3 rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted hover:border-brand-500/40"
            >
              Retry
            </button>
          </Card>
        )}

        {!error && <StatCards cards={stats} />}

        {loading && (
          <div className="flex items-center justify-center py-12" role="status" aria-busy="true">
            <span className="font-mono text-meta text-muted">Loading the leak index…</span>
          </div>
        )}

        {data && !loading && (
          <>
            <Card padding="none" radius="panel" tone="rose">
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-line-1">
                      {['Published', 'Title', 'Author', 'Replies', 'Views', 'Last post'].map((h) => (
                        <th
                          key={h}
                          scope="col"
                          className="px-4 py-2.5 font-mono text-micro uppercase tracking-wider text-muted"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.entries.map((row) => (
                      <tr key={`${row.source}-${row.tid}`} className="border-b border-line-1 last:border-0">
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-micro text-muted">
                          {fmtDate(row.published_at)}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="block text-tool text-heading">{row.title || '(untitled)'}</span>
                          <span className="mt-0.5 flex flex-wrap gap-1.5">
                            <span
                              className={`rounded border px-1.5 py-0.5 font-mono text-micro ${
                                row.source === 'breach'
                                  ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                                  : 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                              }`}
                            >
                              {row.source}
                            </span>
                            {row.prefix && (
                              <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted">
                                {row.prefix}
                              </span>
                            )}
                            {row.attachments > 0 && (
                              <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-micro text-amber-700 dark:text-amber-300">
                                {row.attachments} attachments
                              </span>
                            )}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-micro text-muted">
                          {row.author || '—'}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-meta text-muted">{row.replies}</td>
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-meta text-muted">
                          <span className="inline-flex items-center gap-1">
                            <Eye size={11} /> {row.views}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-micro text-muted">
                          {row.last_post_by || '—'}
                          {row.last_post_at ? ` · ${fmtDate(row.last_post_at)}` : ''}
                        </td>
                      </tr>
                    ))}
                    {data.entries.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-10 text-center text-meta text-muted">
                          No threads match that search.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="font-mono text-micro text-muted">
                {data.total.toLocaleString()} matching threads · page {data.page} of {data.pages}
              </p>
              <div className="flex gap-1.5">
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={data.page <= 1}
                  className="inline-flex items-center gap-1 rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted disabled:opacity-40 hover:enabled:border-brand-500/40"
                >
                  <ChevronLeft size={13} /> Prev
                </button>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
                  disabled={data.page >= data.pages}
                  className="inline-flex items-center gap-1 rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted disabled:opacity-40 hover:enabled:border-brand-500/40"
                >
                  Next <ChevronRight size={13} />
                </button>
              </div>
            </div>

            <p className="font-mono text-micro text-muted">
              Synced {fmtDate(data.synced_at)} · source: {data.source} · {data.license}
            </p>
          </>
        )}
      </div>
    </DataPageLayout>
  );
}
