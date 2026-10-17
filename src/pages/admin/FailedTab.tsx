import { useCallback, useEffect, useState } from 'react';
import { getJson, postJson } from './adminApi';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { SearchFilter } from './SearchFilter';
import { errMessage } from '../../lib/log';

interface FailureRecord {
  slotId: string;
  candidateId: string;
  error: string;
  rawOutput?: string;
  failedAt: string;
  retries: number;
}

export default function FailedTab() {
  const [failures, setFailures] = useState<FailureRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getJson<{ failures: FailureRecord[] }>('/failures');
      setFailures(d.failures);
    } catch (e) {
      console.error('FailedTab failed:', errMessage(e));
      setError(errMessage(e, 'failed to load'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function clearOne(slotId: string) {
    setBusy(slotId);
    setActionMsg(null);
    try {
      await postJson(`/failures/${encodeURIComponent(slotId)}/clear`);
      setActionMsg(`Cleared ${slotId}`);
      await load();
    } catch (e) {
      console.error('clearOne failed:', errMessage(e));
      setActionMsg(`clear failed: ${errMessage(e)}`);
    } finally {
      setBusy(null);
    }
  }

  async function clearAll() {
    if (!window.confirm(`Clear all ${failures.length} failure records? This is irreversible.`)) return;
    setBusy('__all');
    setActionMsg(null);
    try {
      const r = await postJson<{ ok: boolean; cleared: number }>('/failures/clear-all');
      setActionMsg(`Cleared ${r.cleared} record(s)`);
      await load();
    } catch (e) {
      console.error('clearAll failed:', errMessage(e));
      setActionMsg(`clear-all failed: ${errMessage(e)}`);
    } finally {
      setBusy(null);
    }
  }

  if (loading) return <p className="text-muted">Loading…</p>;
  if (error)
    return (
      <div>
        <p className="text-rose-400 mb-2">Failed to load: {error}</p>
        <button onClick={() => void load()} className="px-3 py-1 border border-line-1 rounded text-sm">
          Retry
        </button>
      </div>
    );
  if (failures.length === 0)
    return (
      <div>
        {actionMsg && <p className="text-xs font-mono text-muted mb-2">{actionMsg}</p>}
        <p className="text-muted">No failures recorded.</p>
      </div>
    );

  return (
    <SearchFilter items={failures.map((f) => ({ slug: f.slotId, title: f.error }))} placeholder="Filter failures…">
      {(filtered) => {
        const filteredKeys = new Set(filtered.map((f) => f.slug));
        const shown = failures.filter((f) => filteredKeys.has(f.slotId));
        return (
          <div>
            <div className="flex items-center justify-between mb-3">
              {actionMsg ? (
                <p className="text-xs font-mono text-muted">{actionMsg}</p>
              ) : (
                <p className="text-xs font-mono text-muted">{failures.length} failure(s) recorded</p>
              )}
              <button
                type="button"
                onClick={() => void clearAll()}
                disabled={busy !== null}
                className="px-2.5 py-1 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
              >
                {busy === '__all' ? 'Clearing…' : 'Clear all'}
              </button>
            </div>
            <div className="overflow-x-auto">
              <DataTable
                columns={
                  [
                    {
                      key: 'slotId',
                      header: 'Slot ID',
                      sortValue: (f: (typeof shown)[number]) => f.slotId,
                      render: (f) => <span className="font-mono text-xs text-muted">{f.slotId}</span>,
                    },
                    {
                      key: 'candidateId',
                      header: 'Candidate ID',
                      sortValue: (f: (typeof shown)[number]) => f.candidateId,
                      render: (f) => <span className="font-mono text-xs text-muted">{f.candidateId}</span>,
                    },
                    {
                      key: 'error',
                      header: 'Error',
                      sortValue: (f: (typeof shown)[number]) => f.error,
                      render: (f) => (
                        <span className="text-rose-700 dark:text-rose-300 max-w-md break-words">{f.error}</span>
                      ),
                    },
                    {
                      key: 'failedAt',
                      header: 'Failed at',
                      sortValue: (f: (typeof shown)[number]) => f.failedAt,
                      render: (f) => (
                        <span className="text-muted text-xs whitespace-nowrap">
                          {new Date(f.failedAt).toLocaleString()}
                        </span>
                      ),
                    },
                    {
                      key: 'retries',
                      header: 'Retries',
                      align: 'right',
                      sortValue: (f: (typeof shown)[number]) => f.retries,
                      render: (f) => <span className="text-body tabular-nums">{f.retries}</span>,
                    },
                    {
                      key: 'actions',
                      header: 'Actions',
                      render: (f) => (
                        <button
                          onClick={() => clearOne(f.slotId)}
                          disabled={busy === f.slotId}
                          className="px-2 py-1 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
                        >
                          {busy === f.slotId ? '…' : 'Clear'}
                        </button>
                      ),
                    },
                  ] as DataTableColumn<(typeof shown)[number]>[]
                }
                rows={shown}
                rowKey={(f) => `${f.slotId}-${f.failedAt}`}
              />
            </div>
          </div>
        );
      }}
    </SearchFilter>
  );
}
