import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useState } from 'react';
import { briefingsGet, briefingsPost } from './adminApi';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';

/**
 * Admin Briefings tab - manual control over the threat-briefing pipeline.
 *
 * The daily/weekly briefings are normally built by cron (30 0 * * * daily,
 * 45 0 * * 1 weekly) and self-healed hourly (0 * * * *). This tab lets an
 * operator drive every mutation by hand, which matters because:
 *   - the hourly heal shares its invocation with telegram scraping and can
 *     run out of the Free-plan subrequest budget before the briefing build,
 *     shipping a 0-finding / 0-IOC briefing (daily-2026-06-04/05). A manual
 *     build runs in REQUEST context with a full budget and rebuilds it rich.
 *   - a builder change (e.g. the CIRCL CVE-5.x parser fix) needs an immediate
 *     rebuild of already-stored rows without waiting for the next cron.
 *
 * Endpoints (all under /api/v1/briefings, admin-gated except list):
 *   POST /build?type=daily|weekly|landscape   → buildBriefingHandler
 *   POST /backfill?days=N&weeks=M&force=1      → backfillBriefingsHandler
 *   POST /sweep?max_age_days=N                 → sweepBriefingsHandler
 *   GET  /list?type=&limit=&offset=            → listBriefingsHandler
 */

interface BriefingStats {
  findings?: number;
  sections?: number;
  cves?: number;
  kevs?: number;
  iocs?: number;
  critical?: number;
  high?: number;
}

interface BuildResult {
  ok: boolean;
  slug: string;
  reason?: string;
  stats?: BriefingStats;
}

interface BackfillResult {
  ok: boolean;
  force: boolean;
  daily: string[];
  daily_skipped: string[];
  weekly: string[];
  weekly_skipped: string[];
  failures: Array<{ kind: 'daily' | 'weekly'; offset: number; error: string }>;
}

interface SweepResult {
  ok: boolean;
  max_age_days: number;
  deleted: string[];
  kept: number;
}

interface ListItem {
  slug: string;
  metadata: {
    type?: string;
    title?: string;
    date?: string;
    date_range?: string;
    stats?: BriefingStats;
  };
}

type BuildType = 'daily' | 'weekly' | 'landscape';

const num = (n: number | undefined): number => n ?? 0;
const isEmpty = (s: BriefingStats | undefined): boolean => num(s?.findings) === 0;

function StatPills({ stats }: { stats: BriefingStats | undefined }) {
  if (!stats) return <span className="text-muted">-</span>;
  const empty = isEmpty(stats);
  return (
    <span className={`font-mono text-xs ${empty ? 'text-rose-700 dark:text-rose-300' : 'text-body'}`}>
      {num(stats.findings)} findings · {num(stats.iocs)} IOCs · {num(stats.cves)} CVEs · {num(stats.kevs)} KEVs
      {empty && (
        <span className="ml-2 px-1.5 py-0.5 rounded bg-rose-50 dark:bg-rose-900/40 border border-rose-200 dark:border-rose-800">
          EMPTY
        </span>
      )}
    </span>
  );
}

export default function BriefingsTab() {
  // --- Build now ---
  const [building, setBuilding] = useState<string | null>(null);
  const [buildResult, setBuildResult] = useState<BuildResult | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);

  // --- Backfill ---
  const [days, setDays] = useState(1);
  const [weeks, setWeeks] = useState(0);
  const [force, setForce] = useState(true);
  const [backfilling, setBackfilling] = useState(false);
  const [backfillResult, setBackfillResult] = useState<BackfillResult | null>(null);
  const [backfillError, setBackfillError] = useState<string | null>(null);

  // --- Sweep ---
  const [maxAge, setMaxAge] = useState(30);
  const [sweeping, setSweeping] = useState(false);
  const [sweepResult, setSweepResult] = useState<SweepResult | null>(null);
  const [sweepError, setSweepError] = useState<string | null>(null);

  // --- Recent list + delete ---
  const [items, setItems] = useState<ListItem[]>([]);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [deletingSlug, setDeletingSlug] = useState<string | null>(null);
  const [pruning, setPruning] = useState(false);
  const [deleteMsg, setDeleteMsg] = useState<string | null>(null);

  const loadList = useCallback(async () => {
    setListLoading(true);
    setListError(null);
    try {
      const r = await briefingsGet<{ items: ListItem[] }>('/list?limit=30');
      setItems(r.items ?? []);
    } catch (e) {
      logCatch(e);
      setListError(errMessage(e));
    } finally {
      setListLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  const build = useCallback(
    async (type: BuildType, live = false) => {
      setBuilding(live ? 'daily-live' : type);
      setBuildError(null);
      setBuildResult(null);
      try {
        const r = await briefingsPost<BuildResult>(`/build?type=${type}${live ? '&live=1' : ''}`);
        setBuildResult(r);
        void loadList();
      } catch (e) {
        logCatch(e);
        setBuildError(errMessage(e));
      } finally {
        setBuilding(null);
      }
    },
    [loadList]
  );

  const runBackfill = useCallback(async () => {
    setBackfilling(true);
    setBackfillError(null);
    setBackfillResult(null);
    try {
      const qs = `days=${days}&weeks=${weeks}${force ? '&force=1' : ''}`;
      const r = await briefingsPost<BackfillResult>(`/backfill?${qs}`);
      setBackfillResult(r);
      void loadList();
    } catch (e) {
      logCatch(e);
      setBackfillError(errMessage(e));
    } finally {
      setBackfilling(false);
    }
  }, [days, weeks, force, loadList]);

  const runSweep = useCallback(async () => {
    setSweeping(true);
    setSweepError(null);
    setSweepResult(null);
    try {
      const r = await briefingsPost<SweepResult>(`/sweep?max_age_days=${maxAge}`);
      setSweepResult(r);
      void loadList();
    } catch (e) {
      logCatch(e);
      setSweepError(errMessage(e));
    } finally {
      setSweeping(false);
    }
  }, [maxAge, loadList]);

  const deleteOne = useCallback(
    async (slug: string) => {
      if (!window.confirm(`Delete briefing ${slug}? This cannot be undone.`)) return;
      setDeletingSlug(slug);
      setDeleteMsg(null);
      try {
        await briefingsPost<{ ok: boolean; deleted: boolean }>(`/delete?slug=${encodeURIComponent(slug)}`);
        setDeleteMsg(`Deleted ${slug}.`);
        void loadList();
      } catch (e) {
        logCatch(e);
        setDeleteMsg(`Delete failed: ${errMessage(e)}`);
      } finally {
        setDeletingSlug(null);
      }
    },
    [loadList]
  );

  const pruneEmpty = useCallback(async () => {
    if (!window.confirm('Delete ALL empty (0 findings / 0 IOCs) daily & weekly briefings?')) return;
    setPruning(true);
    setDeleteMsg(null);
    try {
      const r = await briefingsPost<{ ok: boolean; deleted: string[] }>('/prune-empty');
      setDeleteMsg(`Pruned ${r.deleted.length} empty briefing(s).`);
      void loadList();
    } catch (e) {
      logCatch(e);
      setDeleteMsg(`Prune failed: ${errMessage(e)}`);
    } finally {
      setPruning(false);
    }
  }, [loadList]);

  const anyEmpty = items.some((it) => isEmpty(it.metadata.stats));

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Build now */}
      <div className="rounded border border-line-1 p-4">
        <h2 className="text-lg font-semibold text-heading mb-1">Build now</h2>
        <p className="text-sm text-muted mb-4">
          Rebuilds the latest closed window for the chosen type and writes it (overwriting an empty row; a richer
          existing row is preserved). Runs in request context with a full subrequest budget - use this to recover a
          briefing the cron heal shipped empty, or to apply a builder change immediately. <code>daily</code> targets
          yesterday&apos;s UTC window.
        </p>
        <div className="flex flex-wrap items-center gap-2 mb-3">
          {(['daily', 'weekly', 'landscape'] as BuildType[]).map((t) => (
            <button
              key={t}
              onClick={() => build(t)}
              disabled={building !== null}
              className="px-4 py-1.5 border border-line-1 rounded text-sm text-heading hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50 capitalize"
            >
              {building === t ? `Building ${t}…` : `Build ${t}`}
            </button>
          ))}
          <button
            onClick={() => build('daily', true)}
            disabled={building !== null}
            title="Rebuild today's in-progress (live) daily - the only way to refresh daily-<today>"
            className="px-4 py-1.5 border border-emerald-200 dark:border-emerald-700 text-emerald-700 dark:text-emerald-200 rounded text-sm hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50"
          >
            {building === 'daily-live' ? 'Building today…' : 'Build today (live)'}
          </button>
        </div>
        {buildError && (
          <div className="px-3 py-2 border border-rose-200 dark:border-rose-700 bg-rose-50 dark:bg-rose-900/20 rounded text-sm text-rose-700 dark:text-rose-200">
            {buildError}
          </div>
        )}
        {buildResult && (
          <div className="px-3 py-2 border border-line-1 bg-surface-100 rounded text-sm">
            <span
              className={
                buildResult.ok
                  ? 'text-emerald-700 dark:text-emerald-300 font-semibold'
                  : 'text-amber-700 dark:text-amber-300 font-semibold'
              }
            >
              {buildResult.ok ? 'Built' : 'Done'}
            </span>{' '}
            <code className="font-mono text-body">{buildResult.slug}</code>
            {buildResult.reason && <span className="text-muted"> - {buildResult.reason}</span>}
            <div className="mt-1">
              <StatPills stats={buildResult.stats} />
            </div>
            {isEmpty(buildResult.stats) && (
              <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">
                Still empty in request context - the feeds themselves returned nothing for this window (check the
                briefing-build-sources log), not a cron-budget issue.
              </p>
            )}
          </div>
        )}
      </div>

      {/* Backfill */}
      <div className="rounded border border-line-1 p-4">
        <h2 className="text-lg font-semibold text-heading mb-1">Backfill</h2>
        <p className="text-sm text-muted mb-4">
          Rebuilds the past N daily + M weekly windows. With <strong>force</strong> on, existing rows are overwritten
          (use after a builder fix); off, existing rows are skipped. <code>days=1</code> targets only yesterday&apos;s
          daily.
        </p>
        <div className="flex flex-wrap items-end gap-3 mb-3">
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Daily (0–21)</span>
            <input
              type="number"
              min={0}
              max={21}
              value={days}
              onChange={(e) => setDays(Math.max(0, Math.min(21, Number(e.target.value) || 0)))}
              disabled={backfilling}
              className="w-24 px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            />
          </label>
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Weekly (0–4)</span>
            <input
              type="number"
              min={0}
              max={4}
              value={weeks}
              onChange={(e) => setWeeks(Math.max(0, Math.min(4, Number(e.target.value) || 0)))}
              disabled={backfilling}
              className="w-24 px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            />
          </label>
          <label className="flex items-center gap-2 pb-1.5 text-sm text-body">
            <input
              type="checkbox"
              checked={force}
              onChange={(e) => setForce(e.target.checked)}
              disabled={backfilling}
              className="accent-rose-500"
            />
            Force overwrite
          </label>
          <button
            onClick={runBackfill}
            disabled={backfilling || days + weeks === 0}
            className={`px-4 py-1.5 rounded text-sm disabled:opacity-50 ${
              force
                ? 'border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-200 hover:bg-rose-50 dark:hover:bg-rose-900/30'
                : 'border border-line-1 text-heading hover:bg-slate-100 dark:hover:bg-surface-300'
            } transition-colors`}
          >
            {backfilling ? 'Backfilling…' : 'Run backfill'}
          </button>
        </div>
        {backfillError && (
          <div className="px-3 py-2 border border-rose-200 dark:border-rose-700 bg-rose-50 dark:bg-rose-900/20 rounded text-sm text-rose-700 dark:text-rose-200">
            {backfillError}
          </div>
        )}
        {backfillResult && (
          <div className="px-3 py-2 border border-line-1 bg-surface-100 rounded text-sm text-body space-y-1">
            <div>
              <span className="text-emerald-700 dark:text-emerald-300">written:</span> daily{' '}
              {backfillResult.daily.length}, weekly {backfillResult.weekly.length} ·{' '}
              <span className="text-muted">skipped:</span> daily {backfillResult.daily_skipped.length}, weekly{' '}
              {backfillResult.weekly_skipped.length}
              {backfillResult.failures.length > 0 && (
                <span className="text-rose-700 dark:text-rose-300"> · failures: {backfillResult.failures.length}</span>
              )}
            </div>
            {backfillResult.daily.length > 0 && (
              <div className="font-mono text-xs text-muted break-all">{backfillResult.daily.join(', ')}</div>
            )}
          </div>
        )}
      </div>

      {/* Sweep */}
      <div className="rounded border border-line-1 p-4">
        <h2 className="text-lg font-semibold text-heading mb-1">Sweep old briefings</h2>
        <p className="text-sm text-muted mb-4">
          Deletes briefings older than the retention window (clamped to the policy ceiling). Also runs on the hourly
          cron - this is for a one-off prune.
        </p>
        <div className="flex flex-wrap items-end gap-3 mb-3">
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Max age (days)</span>
            <input
              type="number"
              min={1}
              max={3650}
              value={maxAge}
              onChange={(e) => setMaxAge(Math.max(1, Math.min(3650, Number(e.target.value) || 30)))}
              disabled={sweeping}
              className="w-28 px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            />
          </label>
          <button
            onClick={runSweep}
            disabled={sweeping}
            className="px-4 py-1.5 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-200 rounded text-sm hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50 transition-colors"
          >
            {sweeping ? 'Sweeping…' : 'Run sweep'}
          </button>
        </div>
        {sweepError && (
          <div className="px-3 py-2 border border-rose-200 dark:border-rose-700 bg-rose-50 dark:bg-rose-900/20 rounded text-sm text-rose-700 dark:text-rose-200">
            {sweepError}
          </div>
        )}
        {sweepResult && (
          <div className="px-3 py-2 border border-line-1 bg-surface-100 rounded text-sm text-body">
            <span className="text-emerald-700 dark:text-emerald-300 font-semibold">Swept</span> -{' '}
            {sweepResult.deleted.length} deleted, {sweepResult.kept} kept (max age {sweepResult.max_age_days}d).
          </div>
        )}
      </div>

      {/* Recent briefings */}
      <div className="rounded border border-line-1 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-heading">Recent briefings</h2>
          <div className="flex items-center gap-2">
            <button
              onClick={pruneEmpty}
              disabled={pruning || !anyEmpty}
              title={anyEmpty ? 'Delete all empty daily/weekly briefings' : 'No empty briefings to prune'}
              className="px-3 py-1 border border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-200 rounded text-sm hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-40 transition-colors"
            >
              {pruning ? 'Pruning…' : 'Delete all empty'}
            </button>
            <button
              onClick={() => void loadList()}
              disabled={listLoading}
              className="px-3 py-1 border border-line-1 rounded text-sm text-body hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
            >
              {listLoading ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>
        <p className="text-xs text-muted mb-3">
          Empty (0 findings / 0 IOCs) rows are flagged in red. The list is edge-cached ~5 min, so a just-built row may
          lag - the build/backfill result above shows fresh stats.
        </p>
        {deleteMsg && (
          <div className="mb-3 px-3 py-2 border border-line-1 bg-surface-100 rounded text-sm text-body">
            {deleteMsg}
          </div>
        )}
        {listError && (
          <div className="mb-3 px-3 py-2 border border-rose-200 dark:border-rose-700 bg-rose-50 dark:bg-rose-900/20 rounded text-sm text-rose-700 dark:text-rose-200">
            {listError}
          </div>
        )}
        <div className="border border-line-1 rounded overflow-hidden">
          <DataTable
            columns={
              [
                {
                  key: 'slug',
                  header: 'Slug',
                  sortValue: (it: (typeof items)[number]) => it.slug,
                  render: (it) => <span className="font-mono text-body">{it.slug}</span>,
                },
                {
                  key: 'type',
                  header: 'Type',
                  sortValue: (it: (typeof items)[number]) => it.metadata.type ?? '',
                  render: (it) => <span className="text-muted capitalize">{it.metadata.type ?? '-'}</span>,
                },
                { key: 'stats', header: 'Stats', render: (it) => <StatPills stats={it.metadata.stats} /> },
                {
                  key: 'action',
                  header: 'Action',
                  align: 'right',
                  render: (it) => (
                    <button
                      onClick={() => deleteOne(it.slug)}
                      disabled={deletingSlug !== null}
                      className="px-2 py-0.5 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 rounded text-xs hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-40"
                    >
                      {deletingSlug === it.slug ? 'Deleting…' : 'Delete'}
                    </button>
                  ),
                },
              ] as DataTableColumn<(typeof items)[number]>[]
            }
            rows={items}
            rowKey={(it) => it.slug}
            rowClassName={(it) => (isEmpty(it.metadata.stats) ? 'bg-rose-50 dark:bg-rose-950/20' : '')}
            empty={items.length === 0 && !listLoading ? 'No briefings.' : undefined}
          />
        </div>
      </div>
    </div>
  );
}
