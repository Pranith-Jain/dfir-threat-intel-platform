import { useCallback, useEffect, useMemo, useState } from 'react';
import { getJson, postJson, postJsonWithBody } from './adminApi';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { Modal } from '../../components/ui/Modal';
import { errMessage } from '../../lib/log';

interface Slot {
  slotAt: string;
  candidateId: string;
  status: 'pending' | 'publishing' | 'published' | 'failed' | 'draft';
  publishedSlug?: string;
  error?: string;
}

const STATUS_COLORS: Record<string, string> = {
  published: 'bg-emerald-500 dark:bg-emerald-400',
  pending: 'bg-sky-500 dark:bg-sky-400',
  publishing: 'bg-amber-400 dark:bg-amber-500',
  draft: 'bg-slate-400 dark:bg-slate-500',
  failed: 'bg-rose-500 dark:bg-rose-400',
};

export default function ScheduleTab() {
  const [schedule, setSchedule] = useState<Slot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [publishing, setPublishing] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [rescheduleId, setRescheduleId] = useState<string | null>(null);
  const [rescheduleAt, setRescheduleAt] = useState('');

  // Calendar view state
  const [viewMode, setViewMode] = useState<'list' | 'calendar'>('list');
  const [calDate, setCalDate] = useState(() => new Date());
  const [selectedDay, setSelectedDay] = useState<string | null>(null);

  const calYear = calDate.getFullYear();
  const calMonth = calDate.getMonth();

  const slotsByDay = useMemo(() => {
    const map = new Map<string, Slot[]>();
    for (const s of schedule) {
      const d = new Date(s.slotAt);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
      const list = map.get(key) ?? [];
      list.push(s);
      map.set(key, list);
    }
    return map;
  }, [schedule]);

  const selectedDaySlots = selectedDay ? (slotsByDay.get(selectedDay) ?? []) : [];

  // Calendar grid: first day of month, number of days, offset
  const firstDow = new Date(calYear, calMonth, 1).getDay();
  const daysInMonth = new Date(calYear, calMonth + 1, 0).getDate();
  const prevMonthDays = new Date(calYear, calMonth, 0).getDate();

  const calCells = useMemo(() => {
    const cells: { day: number; isCurrent: boolean }[] = [];
    for (let p = firstDow - 1; p >= 0; p--) cells.push({ day: prevMonthDays - p, isCurrent: false });
    for (let d = 1; d <= daysInMonth; d++) cells.push({ day: d, isCurrent: true });
    const remaining = 7 - (cells.length % 7 || 7);
    for (let n = 1; n <= remaining; n++) cells.push({ day: n, isCurrent: false });
    return cells;
  }, [firstDow, daysInMonth, prevMonthDays]);

  // Backend's /admin/schedule handler already revalidates each published
  // slot against /posts/<slug> and downgrades stale rows to 'pending', so
  // the client just renders the response verbatim. The previous in-browser
  // post-exists fan-out used an unauthenticated raw fetch - that would
  // start mis-labelling rows the moment the blog endpoint got gated.
  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getJson<{ schedule: Slot[] }>('/schedule');
      setSchedule(d.schedule);
    } catch (e) {
      console.error('ScheduleTab failed:', errMessage(e));
      setError(errMessage(e, 'failed to load'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function publishNow(candidateId: string) {
    setPublishing(candidateId);
    setMsg(null);
    try {
      const r = await postJsonWithBody<{ ok?: boolean; slug?: string; error?: string }>(
        `/schedule/${encodeURIComponent(candidateId)}/publish-now`,
        {}
      );
      setMsg(r.ok ? `Published! /blog/${r.slug}` : `Error: ${r.error}`);
      await load();
    } catch (e) {
      console.error('publishNow failed:', errMessage(e));
      setMsg(`Error: ${errMessage(e)}`);
    } finally {
      setPublishing(null);
    }
  }

  async function removeSlot(candidateId: string) {
    setPublishing(candidateId);
    setMsg(null);
    try {
      await postJson(`/schedule/${encodeURIComponent(candidateId)}/remove`);
      setMsg('Removed');
      await load();
    } catch (e) {
      console.error('removeSlot failed:', errMessage(e));
      setMsg(`Error: ${errMessage(e)}`);
    } finally {
      setPublishing(null);
    }
  }

  function reschedule(candidateId: string) {
    setRescheduleAt('');
    setRescheduleId(candidateId);
  }

  async function confirmReschedule() {
    if (!rescheduleId || !rescheduleAt) return;
    const d = new Date(rescheduleAt);
    if (Number.isNaN(d.getTime())) {
      setMsg('Invalid date/time');
      return;
    }
    const candidateId = rescheduleId;
    setRescheduleId(null);
    setPublishing(candidateId);
    setMsg(null);
    try {
      const r = await postJsonWithBody<{ ok?: boolean; slotAt?: string; error?: string }>(
        `/schedule/${encodeURIComponent(candidateId)}/reschedule`,
        { slotAt: d.toISOString() }
      );
      setMsg(r.ok && r.slotAt ? `Rescheduled to ${new Date(r.slotAt).toLocaleString()}` : `Error: ${r.error}`);
      await load();
    } catch (e) {
      console.error('confirmReschedule failed:', errMessage(e));
      setMsg(`Error: ${errMessage(e)}`);
    } finally {
      setPublishing(null);
    }
  }

  if (loading) return <p className="text-muted">Loading…</p>;
  if (error)
    return (
      <div>
        <p className="text-rose-600 dark:text-rose-400 mb-2">Failed to load: {error}</p>
        <button onClick={() => void load()} className="px-3 py-1 border border-line-1 rounded text-sm">
          Retry
        </button>
      </div>
    );
  if (schedule.length === 0) return <p className="text-muted">No scheduled slots.</p>;

  return (
    <div>
      {msg && (
        <p className="mb-4 p-3 rounded text-sm font-mono bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
          {msg}
        </p>
      )}

      {/* View toggle */}
      <div className="flex items-center gap-2 mb-4">
        <button
          onClick={() => setViewMode('list')}
          className={`px-3 py-1 text-xs rounded border ${
            viewMode === 'list'
              ? 'bg-brand-500 text-white border-brand-500'
              : 'border-line-1 text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
          }`}
        >
          List
        </button>
        <button
          onClick={() => setViewMode('calendar')}
          className={`px-3 py-1 text-xs rounded border ${
            viewMode === 'calendar'
              ? 'bg-brand-500 text-white border-brand-500'
              : 'border-line-1 text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
          }`}
        >
          Calendar
        </button>
      </div>

      {viewMode === 'list' && (
        <div className="overflow-x-auto">
          <DataTable
            columns={
              [
                {
                  key: 'slotAt',
                  header: 'Slot time',
                  sortValue: (s: Slot) => s.slotAt,
                  render: (s) => (
                    <span className="text-body whitespace-nowrap">{new Date(s.slotAt).toLocaleString()}</span>
                  ),
                },
                {
                  key: 'candidateId',
                  header: 'Candidate ID',
                  sortValue: (s: Slot) => s.candidateId,
                  render: (s) => <span className="font-mono text-xs text-muted">{s.candidateId}</span>,
                },
                {
                  key: 'status',
                  header: 'Status',
                  sortValue: (s: Slot) => s.status,
                  render: (s) => <span className="text-body">{s.status}</span>,
                },
                {
                  key: 'actions',
                  header: 'Actions',
                  render: (s) => (
                    <div className="flex gap-2">
                      {s.status === 'pending' && (
                        <>
                          <button
                            onClick={() => publishNow(s.candidateId)}
                            disabled={publishing === s.candidateId}
                            className="px-2 py-1 border border-emerald-700 rounded text-xs hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50"
                          >
                            {publishing === s.candidateId ? 'Publishing…' : 'Publish now'}
                          </button>
                          <button
                            onClick={() => reschedule(s.candidateId)}
                            disabled={publishing === s.candidateId}
                            className="px-2 py-1 border border-sky-700 rounded text-xs hover:bg-sky-50 dark:hover:bg-sky-900/30 disabled:opacity-50"
                            title="Move this slot to a new date/time"
                          >
                            Reschedule
                          </button>
                          <button
                            onClick={() => removeSlot(s.candidateId)}
                            disabled={publishing === s.candidateId}
                            className="px-2 py-1 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
                          >
                            Remove
                          </button>
                        </>
                      )}
                    </div>
                  ),
                },
              ] as DataTableColumn<Slot>[]
            }
            rows={schedule}
            rowKey={(s, i) => `${s.candidateId}-${i}`}
          />
        </div>
      )}

      {viewMode === 'calendar' && (
        <div>
          {/* Calendar nav */}
          <div className="flex items-center justify-between mb-3">
            <button
              onClick={() => setCalDate(new Date(calYear, calMonth - 1, 1))}
              className="px-2 py-1 text-xs border border-line-1 rounded hover:bg-surface-300 dark:hover:bg-surface-300"
            >
              &larr; Prev
            </button>
            <h3 className="text-sm font-semibold text-heading">
              {calDate.toLocaleString('default', { month: 'long', year: 'numeric' })}
            </h3>
            <button
              onClick={() => setCalDate(new Date(calYear, calMonth + 1, 1))}
              className="px-2 py-1 text-xs border border-line-1 rounded hover:bg-surface-300 dark:hover:bg-surface-300"
            >
              Next &rarr;
            </button>
          </div>

          {/* Day-of-week header */}
          <div className="grid grid-cols-7 mb-1">
            {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d) => (
              <div key={d} className="text-center text-micro uppercase tracking-wider text-muted py-1">
                {d}
              </div>
            ))}
          </div>

          {/* Calendar grid */}
          <div className="grid grid-cols-7 gap-px bg-track dark:bg-line-1 rounded overflow-hidden">
            {calCells.map((cell, i) => {
              const key = cell.isCurrent
                ? `${calYear}-${String(calMonth + 1).padStart(2, '0')}-${String(cell.day).padStart(2, '0')}`
                : `other-${i}`;
              const daySlots = cell.isCurrent ? (slotsByDay.get(key) ?? []) : [];
              const isToday =
                cell.isCurrent &&
                calYear === new Date().getFullYear() &&
                calMonth === new Date().getMonth() &&
                cell.day === new Date().getDate();
              const isSelected = selectedDay === key;
              return (
                <button
                  key={key}
                  onClick={() => {
                    if (cell.isCurrent) {
                      setSelectedDay(selectedDay === key ? null : key);
                    }
                  }}
                  disabled={!cell.isCurrent}
                  className={`min-h-[60px] p-1 text-xs text-left bg-surface-100 ${
                    isSelected ? 'ring-2 ring-brand-500 z-10' : ''
                  } ${cell.isCurrent ? 'cursor-pointer hover:bg-slate-50 dark:hover:bg-surface-300' : 'opacity-40'}`}
                >
                  <span
                    className={`inline-block w-5 h-5 text-center leading-5 rounded-full text-micro ${
                      isToday ? 'bg-brand-500 text-white font-bold' : 'text-body'
                    }`}
                  >
                    {cell.day}
                  </span>
                  {daySlots.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-0.5">
                      {daySlots.map((sl) => (
                        <span
                          key={sl.candidateId}
                          className={`inline-block w-1.5 h-1.5 rounded-full ${STATUS_COLORS[sl.status] ?? 'bg-slate-300'}`}
                          title={`${sl.candidateId} (${sl.status})`}
                        />
                      ))}
                    </div>
                  )}
                </button>
              );
            })}
          </div>

          {/* Selected day detail */}
          {selectedDay && selectedDaySlots.length > 0 && (
            <div className="mt-4 space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
                {new Date(selectedDay + 'T00:00:00').toLocaleDateString('default', {
                  weekday: 'long',
                  month: 'long',
                  day: 'numeric',
                })}
              </h4>
              {selectedDaySlots.map((s) => (
                <div
                  key={s.candidateId}
                  className="flex items-center justify-between p-2 rounded border border-line-1 bg-surface-100"
                >
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${STATUS_COLORS[s.status] ?? 'bg-slate-300'}`} />
                    <span className="text-xs font-mono text-body">{s.candidateId}</span>
                    <span className="text-micro uppercase text-muted">{s.status}</span>
                    <span className="text-micro text-muted">{new Date(s.slotAt).toLocaleTimeString()}</span>
                  </div>
                  <div className="flex gap-1">
                    {s.status === 'pending' && (
                      <>
                        <button
                          onClick={() => publishNow(s.candidateId)}
                          disabled={publishing === s.candidateId}
                          className="px-2 py-0.5 text-micro border border-emerald-700 rounded hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50"
                        >
                          {publishing === s.candidateId ? '…' : 'Publish'}
                        </button>
                        <button
                          onClick={() => reschedule(s.candidateId)}
                          className="px-2 py-0.5 text-micro border border-sky-700 rounded hover:bg-sky-50 dark:hover:bg-sky-900/30"
                        >
                          Move
                        </button>
                      </>
                    )}
                    {s.status === 'published' && s.publishedSlug && (
                      <a
                        href={`/blog/${s.publishedSlug}`}
                        className="px-2 py-0.5 text-micro text-muted underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        View
                      </a>
                    )}
                    {s.status === 'draft' && <span className="text-micro text-muted">Awaiting approval</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <Modal open={rescheduleId !== null} onClose={() => setRescheduleId(null)} title="Reschedule slot">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void confirmReschedule();
          }}
          className="space-y-3"
        >
          <label className="block text-tool text-muted">
            New date &amp; time
            <input
              type="datetime-local"
              autoFocus
              value={rescheduleAt}
              onChange={(e) => setRescheduleAt(e.target.value)}
              className="mt-1 w-full px-3 py-2 rounded border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-brand-500"
            />
          </label>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setRescheduleId(null)}
              className="px-3 py-1.5 text-tool text-muted hover:text-body dark:hover:text-inverted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!rescheduleAt}
              className="px-3 py-1.5 rounded bg-brand-600 text-on-fill text-tool font-semibold hover:bg-brand-500 disabled:opacity-40 transition-colors"
            >
              Reschedule
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
