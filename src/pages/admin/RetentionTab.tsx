import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useState } from 'react';
import { postJsonWithBody } from './adminApi';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';

/**
 * Admin Retention tab - data retention sweep + Telegram cleanup.
 *
 * Two sections:
 *   1. Full retention sweep (13 tables, default 30 days)
 *   2. Telegram-only cleanup (7-day default)
 *
 * Endpoints:
 *   POST /api/v1/admin/retention/run           { days?, dry_run? }
 *   POST /api/v1/admin/retention/telegram-cleanup  { days? }
 */

interface TableSweep {
  table: string;
  deleted: number;
  dry_run: boolean;
}

interface RetentionResult {
  total_deleted: number;
  tables_swept: TableSweep[];
  cutoff: string;
  days: number;
  dry_run: boolean;
  ran_at: string;
}

interface TgCleanupResult {
  ok: boolean;
  max_age_days: number;
  deleted: number;
  count_before: number;
  count_after: number;
}

const DEFAULT_DAYS = 30;
const TG_DEFAULT_DAYS = 7;

export default function RetentionTab() {
  // ── Full sweep state ──
  const [days, setDays] = useState<number>(DEFAULT_DAYS);
  const [busy, setBusy] = useState<'dry' | 'run' | 'tg' | null>(null);
  const [result, setResult] = useState<RetentionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ── Telegram cleanup state ──
  const [tgDays, setTgDays] = useState<number>(TG_DEFAULT_DAYS);
  const [tgResult, setTgResult] = useState<TgCleanupResult | null>(null);
  const [tgError, setTgError] = useState<string | null>(null);

  const runSweep = useCallback(
    async (dryRun: boolean) => {
      setBusy(dryRun ? 'dry' : 'run');
      setError(null);
      try {
        const r = await postJsonWithBody<RetentionResult>('/retention/run', { days, dry_run: dryRun });
        setResult(r);
      } catch (e) {
        console.error('RetentionTab failed:', errMessage(e));
        setError(errMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [days]
  );

  const runTgCleanup = useCallback(async () => {
    setBusy('tg');
    setTgError(null);
    setTgResult(null);
    try {
      const r = await postJsonWithBody<TgCleanupResult>('/retention/telegram-cleanup', { days: tgDays });
      setTgResult(r);
    } catch (e) {
      logCatch(e);
      setTgError(errMessage(e));
    } finally {
      setBusy(null);
    }
  }, [tgDays]);

  const totalDeleted = result?.total_deleted ?? 0;
  const wasDry = result?.dry_run ?? false;
  const cutoff = result?.cutoff ? new Date(result.cutoff) : null;
  const ranAt = result?.ran_at ? new Date(result.ran_at) : null;

  return (
    <div className="space-y-6 max-w-3xl">
      {/* ── Telegram Leak Cleanup ─────────────────────────── */}
      <div className="rounded border border-line-1 p-4">
        <h2 className="text-lg font-semibold text-heading mb-1">Telegram leak cleanup</h2>
        <p className="text-sm text-muted mb-4">
          Deletes <code className="font-mono">telegram_leak_entries</code> older than the retention window. The weekly
          cron runs this automatically at 7 days; use this to force an immediate cleanup or adjust the window.
        </p>

        <div className="flex flex-wrap items-end gap-3 mb-4">
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Max age (days)</span>
            <input
              type="number"
              min={1}
              max={365}
              value={tgDays}
              onChange={(e) => setTgDays(Math.max(1, Math.min(365, Number(e.target.value) || TG_DEFAULT_DAYS)))}
              disabled={busy !== null}
              className="w-32 px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            />
          </label>
          <button
            onClick={() => void runTgCleanup()}
            disabled={busy !== null}
            className="px-4 py-1.5 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-200 rounded text-sm hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50"
          >
            {busy === 'tg' ? 'Cleaning…' : 'Clean up now'}
          </button>
        </div>

        {tgError && (
          <div className="mb-4 px-3 py-2 border border-rose-200 dark:border-rose-700 bg-rose-50 dark:bg-rose-900/20 rounded text-sm text-rose-700 dark:text-rose-200">
            {tgError}
          </div>
        )}

        {tgResult && (
          <div className="rounded border border-line-1 p-3 text-sm">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-emerald-700 dark:text-emerald-300 font-semibold">Done</span>
              <span className="text-body">
                Deleted <strong>{tgResult.deleted}</strong> row(s) older than {tgResult.max_age_days} days.
              </span>
            </div>
            <div className="text-xs font-mono text-muted">
              Before: {tgResult.count_before.toLocaleString()} → After: {tgResult.count_after.toLocaleString()}
            </div>
          </div>
        )}
      </div>

      {/* ── Full Retention Sweep ──────────────────────────── */}
      <div className="rounded border border-line-1 p-4">
        <h2 className="text-lg font-semibold text-heading mb-1">Full data retention sweep</h2>
        <p className="text-sm text-muted mb-4">
          Deletes rows older than the retention window across 13 data tables (briefings, IOC logs, report-extraction
          cache, etc.). The cron runs this hourly; use this to preview impact or override the window.
        </p>

        <div className="flex flex-wrap items-end gap-3 mb-4">
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Retention (days)</span>
            <input
              type="number"
              min={1}
              max={3650}
              value={days}
              onChange={(e) => setDays(Math.max(1, Math.min(3650, Number(e.target.value) || DEFAULT_DAYS)))}
              disabled={busy !== null}
              className="w-32 px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            />
          </label>
          <button
            onClick={() => runSweep(true)}
            disabled={busy !== null}
            className="px-4 py-1.5 border border-line-1 rounded text-sm text-heading hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
          >
            {busy === 'dry' ? 'Previewing…' : 'Dry-run preview'}
          </button>
          <button
            onClick={() => runSweep(false)}
            disabled={busy !== null}
            className="px-4 py-1.5 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-200 rounded text-sm hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50"
          >
            {busy === 'run' ? 'Sweeping…' : 'Run sweep now'}
          </button>
        </div>

        {error && (
          <div className="mb-4 px-3 py-2 border border-rose-200 dark:border-rose-700 bg-rose-50 dark:bg-rose-900/20 rounded text-sm text-rose-700 dark:text-rose-200">
            {error}
          </div>
        )}

        {result && (
          <div className="mt-4">
            <div className="text-sm text-body mb-3">
              {wasDry ? (
                <>
                  <span className="text-amber-700 dark:text-amber-300 font-semibold">Dry run</span> - {totalDeleted}{' '}
                  row(s) would be deleted (no DELETEs issued).
                </>
              ) : (
                <>
                  <span className="text-emerald-700 dark:text-emerald-300 font-semibold">Sweep complete</span> -{' '}
                  {totalDeleted} row(s) deleted.
                </>
              )}
              {cutoff && (
                <>
                  {' '}
                  Cutoff: <code className="font-mono text-muted">{cutoff.toISOString()}</code>.
                </>
              )}
              {ranAt && (
                <>
                  {' '}
                  Ran at: <code className="font-mono text-muted">{ranAt.toLocaleString()}</code>.
                </>
              )}
            </div>

            {result.tables_swept.length > 0 && (
              <div className="border border-line-1 rounded">
                <DataTable
                  columns={
                    [
                      {
                        key: 'table',
                        header: 'Table',
                        sortValue: (r: (typeof result.tables_swept)[number]) => r.table,
                        render: (r) => <span className="font-mono text-body">{r.table}</span>,
                      },
                      {
                        key: 'deleted',
                        header: wasDry ? 'Would delete' : 'Deleted',
                        align: 'right',
                        sortValue: (r: (typeof result.tables_swept)[number]) => r.deleted,
                        render: (r) => <span className="text-heading">{r.deleted}</span>,
                      },
                    ] as DataTableColumn<(typeof result.tables_swept)[number]>[]
                  }
                  rows={result.tables_swept}
                  rowKey={(r) => r.table}
                />
              </div>
            )}

            {result.tables_swept.length === 0 && (
              <p className="text-sm text-muted">No tables had rows past the cutoff - nothing to do.</p>
            )}
          </div>
        )}

        <p className="mt-4 text-xs text-muted">
          The sweep excludes <code>api_keys</code>, <code>telegram_watched_channels</code>, <code>ct_watch</code>, and{' '}
          <code>counters</code> - those are operator-state, not intel.
        </p>
      </div>
    </div>
  );
}
