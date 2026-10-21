/**
 * Newly-registered domain monitor.
 *
 * `/threatintel/domain-monitor`
 *
 * Ported from DominiosINT: fetch the daily list of newly registered domains
 * and filter it by keyword.
 *
 * The watchlist is the part worth using daily. A watch is checked on every
 * sweep and its matches are recorded, so the page answers "has anyone
 * registered a domain containing *this word* recently" without anyone
 * having to remember to look.
 */

import { useCallback, useMemo, useState } from 'react';
import { AlertTriangle, Bell, CalendarClock, Globe, Plus, Search, Trash2 } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Card } from '../../components/ui/Card';
import { StatCards } from '../../components/ui/StatCards';
import { useApiData } from '../../hooks/useApiData';

interface SearchDay {
  date: string;
  domains: string[];
  total_domains: number;
}

interface SearchResponse {
  generated_at: string;
  keywords: string[];
  window: string[];
  days: SearchDay[];
  total: number;
  source: string;
}

interface Watch {
  id: string;
  keyword: string;
  normalized: string;
  note: string | null;
  enabled: boolean;
  created_at: string;
  last_checked_at: string | null;
  match_count: number;
}

interface WatchlistResponse {
  count: number;
  watches: Watch[];
}

function fmtDate(value: string | null | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function DomainRegistrationMonitor(): JSX.Element {
  const [keyword, setKeyword] = useState('');
  const [query, setQuery] = useState('');
  const [days, setDays] = useState(3);
  const [newWatch, setNewWatch] = useState('');
  const [note, setNote] = useState('');
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  const searchUrl = useMemo(() => {
    if (!query) return null;
    const params = new URLSearchParams({ q: query, days: String(days) });
    return `/api/v1/threat-intel/domain-monitor?${params.toString()}`;
  }, [query, days]);

  const { data, loading, error, refetch } = useApiData<SearchResponse>(searchUrl, { ttl: 120_000 });
  const {
    data: watchlist,
    loading: wlLoading,
    error: wlError,
    refetch: refetchWatchlist,
  } = useApiData<WatchlistResponse>('/api/v1/threat-intel/domain-monitor/watchlist', { ttl: 30_000 });

  const runSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setQuery(keyword.trim());
  };

  const addWatch = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const kw = newWatch.trim();
      if (!kw) return;
      setAdding(true);
      setAddError(null);
      try {
        const res = await fetch('/api/v1/threat-intel/domain-monitor/watchlist', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ keyword: kw, note: note.trim() || undefined }),
        });
        if (!res.ok) {
          const body = (await res.json().catch(() => null)) as { message?: string } | null;
          throw new Error(body?.message ?? `HTTP ${res.status}`);
        }
        setNewWatch('');
        setNote('');
        refetchWatchlist();
      } catch (err) {
        setAddError(err instanceof Error ? err.message : 'Could not add the watch.');
      } finally {
        setAdding(false);
      }
    },
    [newWatch, note, refetchWatchlist]
  );

  const removeWatch = useCallback(
    async (id: string) => {
      try {
        const res = await fetch(`/api/v1/threat-intel/domain-monitor/watchlist/${id}`, {
          method: 'DELETE',
        });
        if (res.ok) refetchWatchlist();
      } catch {
        /* the list re-renders on the next fetch either way */
      }
    },
    [refetchWatchlist]
  );

  const totalRegistered = useMemo(() => (data?.days ?? []).reduce((sum, d) => sum + d.total_domains, 0), [data]);

  const stats = [
    { label: 'Matches', value: data?.total ?? 0, icon: <Search size={16} /> },
    { label: 'Days scanned', value: data?.days.length ?? 0, icon: <CalendarClock size={16} /> },
    { label: 'Domains registered', value: totalRegistered, icon: <Globe size={16} /> },
    { label: 'Active watches', value: watchlist?.count ?? 0, icon: <Bell size={16} /> },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Globe size={28} />}
      title="Domain Registration Monitor"
      description="Newly registered domains, filtered by keyword — watch a word and be told when someone registers a domain containing it."
      maxWidthClass="max-w-6xl"
    >
      <div className="space-y-5">
        {/* ── Search ──────────────────────────────────────────────────── */}
        <Card padding="md" radius="panel" tone="rose">
          <form onSubmit={runSearch} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[14rem] flex-1">
              <label
                htmlFor="dm-keyword"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Keyword
              </label>
              <div className="relative">
                <Search
                  size={14}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                  aria-hidden="true"
                />
                <input
                  id="dm-keyword"
                  value={keyword}
                  onChange={(e) => setKeyword(e.target.value)}
                  placeholder="banco, salud, municipality name…"
                  spellCheck={false}
                  className="w-full rounded border border-line-1 bg-surface-100 py-2 pl-9 pr-3 text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                />
              </div>
            </div>
            <div>
              <label
                htmlFor="dm-days"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Look back
              </label>
              <select
                id="dm-days"
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                className="rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              >
                {[1, 3, 7, 14, 30].map((d) => (
                  <option key={d} value={d}>
                    {d} day{d === 1 ? '' : 's'}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 rounded bg-brand-600 px-4 py-2 font-mono text-meta text-on-fill transition-colors hover:bg-brand-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              <Search size={14} /> Scan
            </button>
          </form>
          <p className="mt-2 font-mono text-micro text-muted">
            Accents are stripped and the match is a substring, so &ldquo;banco&rdquo; also catches
            &ldquo;BANCO-SEGUR0&rdquo; and &ldquo;banco.com.mx&rdquo;. Keywords under three characters are ignored.
          </p>
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

        {data && !loading && <StatCards cards={stats} />}

        {loading && (
          <div className="flex items-center justify-center py-12" role="status" aria-busy="true">
            <span className="font-mono text-meta text-muted">Scanning the daily registration lists…</span>
          </div>
        )}

        {data && !loading && (
          <Card padding="none" radius="panel" tone="rose">
            {data.total === 0 ? (
              <p className="px-4 py-10 text-center text-meta text-muted">
                No domain containing {data.keywords.map((k) => `“${k}”`).join(' or ')} was registered in the last{' '}
                {data.window.length} day{data.window.length === 1 ? '' : 's'}.
              </p>
            ) : (
              <ul className="divide-y divide-line-1">
                {data.days
                  .filter((d) => d.domains.length > 0)
                  .map((day) => (
                    <li key={day.date} className="px-4 py-3">
                      <p className="mb-1.5 font-mono text-micro uppercase tracking-wider text-muted">
                        {day.date} · {day.domains.length} match
                        {day.domains.length === 1 ? '' : 'es'} of {day.total_domains.toLocaleString()} registered
                      </p>
                      <ul className="flex flex-wrap gap-1.5">
                        {day.domains.map((d) => (
                          <li
                            key={d}
                            className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-micro text-amber-700 dark:text-amber-300"
                          >
                            {d}
                          </li>
                        ))}
                      </ul>
                    </li>
                  ))}
              </ul>
            )}
          </Card>
        )}

        {/* ── Watchlist ───────────────────────────────────────────────── */}
        <Card padding="md" radius="panel" tone="rose">
          <CardHeaderRow />
          <form onSubmit={addWatch} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[12rem] flex-1">
              <label
                htmlFor="dm-watch"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Watch a keyword
              </label>
              <input
                id="dm-watch"
                value={newWatch}
                onChange={(e) => setNewWatch(e.target.value)}
                placeholder="banco"
                spellCheck={false}
                className="w-full rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              />
            </div>
            <div className="min-w-[12rem] flex-1">
              <label
                htmlFor="dm-note"
                className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
              >
                Note (optional)
              </label>
              <input
                id="dm-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="why this matters"
                className="w-full rounded border border-line-1 bg-surface-100 px-3 py-2 text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              />
            </div>
            <button
              type="submit"
              disabled={adding || !newWatch.trim()}
              className="inline-flex items-center gap-1.5 rounded bg-brand-600 px-4 py-2 font-mono text-meta text-on-fill transition-colors hover:bg-brand-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 disabled:opacity-50"
            >
              <Plus size={14} /> {adding ? 'Adding…' : 'Watch'}
            </button>
          </form>
          {addError && (
            <p role="alert" className="mt-2 flex items-center gap-1.5 text-meta text-rose-600 dark:text-rose-400">
              <AlertTriangle size={13} /> {addError}
            </p>
          )}

          {wlError && <p className="mt-3 font-mono text-micro text-rose-600 dark:text-rose-400">{wlError}</p>}

          {wlLoading && <p className="mt-3 font-mono text-micro text-muted">Loading the watchlist…</p>}

          {watchlist && watchlist.watches.length === 0 && (
            <p className="mt-3 text-meta text-muted">
              No watches yet. Add one and it will be checked on every daily sweep.
            </p>
          )}

          {watchlist && watchlist.watches.length > 0 && (
            <ul className="mt-4 space-y-2">
              {watchlist.watches.map((w) => (
                <li
                  key={w.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded border border-line-1 bg-surface-100 p-3"
                >
                  <div>
                    <span className="font-mono text-tool text-heading">{w.keyword}</span>
                    {w.note && <span className="ml-2 text-micro text-muted">{w.note}</span>}
                    <p className="font-mono text-micro text-muted">
                      {w.match_count} match{w.match_count === 1 ? '' : 'es'} · last checked {fmtDate(w.last_checked_at)}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void removeWatch(w.id)}
                    aria-label={`Remove the watch for ${w.keyword}`}
                    className="rounded border border-line-1 p-1.5 text-muted hover:border-rose-500/40 hover:text-rose-600"
                  >
                    <Trash2 size={13} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <p className="font-mono text-micro text-muted">
          Source: {data?.source ?? 'ccas10ca-prog/domain — daily newly-registered domain lists'}. A registration is a
          signal, not a verdict — brand-adjacent names are registered for many legitimate reasons.
        </p>
      </div>
    </DataPageLayout>
  );
}

/** Small header for the watchlist card. */
function CardHeaderRow(): JSX.Element {
  return (
    <div className="mb-4">
      <h2 className="font-display text-base font-semibold text-heading">Watchlist</h2>
      <p className="mt-1 text-meta text-muted">
        Each watch is checked on every daily sweep, and its matches are recorded so the same finding is not reported
        twice.
      </p>
    </div>
  );
}
