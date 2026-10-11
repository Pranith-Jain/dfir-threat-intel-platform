/**
 * Daily rollup for cyberpulse_incidents.
 *
 * The `/api/v1/cyberpulse/stats` route used to re-derive every aggregate on
 * each request: five GROUP BYs over an append-only table whose grouping keys
 * (`DATE(discovered_at)`, `victim_name`, `threat_actor`, `victim_country`) are
 * unindexable by construction. Measured at ~105k rows_read/day — 65% of all
 * remaining D1 reads.
 *
 * Because the table is append-only, a day's aggregates never change once
 * written. So compute them once and store them; the route sums the stored days
 * in JS.
 *
 * Deliberately NOT KV: a KV cache would trade D1 reads for KV reads/writes, and
 * KV's free tier allows only 1,000 writes/day. This stays entirely in D1.
 *
 * If the rollup is empty or stale the caller falls back to the original live
 * queries, so this is a pure optimisation — it cannot make the route fail.
 */
import type { D1Database } from '@cloudflare/workers-types';

/** JSON `{value: count}` map. */
type Counts = Record<string, number>;

/**
 * One grouped row, shaped so `dim()` can read a dimension and the total off the
 * same object. Typed explicitly because `Counts` alone would make the numeric
 * `n` look like a string-keyed entry.
 */
interface GroupedRow {
  n: number;
  incident_type: string | null;
  severity: string | null;
  platform: string | null;
  sector: string | null;
  country: string | null;
  actor: string | null;
  victim: string | null;
}

export interface DailyRollupRow {
  bucket_date: string;
  total: number;
  incident_type: string;
  severity: string;
  platform: string;
  sector: string;
  country: string;
  actor: string;
  victim: string;
}

const ROLLUP_DDL = [
  `CREATE TABLE IF NOT EXISTS cyberpulse_daily_rollup (
     bucket_date TEXT PRIMARY KEY, total INTEGER NOT NULL,
     incident_type TEXT NOT NULL DEFAULT '{}', severity TEXT NOT NULL DEFAULT '{}',
     platform TEXT NOT NULL DEFAULT '{}', sector TEXT NOT NULL DEFAULT '{}',
     country TEXT NOT NULL DEFAULT '{}', actor TEXT NOT NULL DEFAULT '{}',
     victim TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_cpdr_bucket ON cyberpulse_daily_rollup(bucket_date)`,
];

let rollupTablePresent: Promise<boolean> | null = null;

export async function ensureDailyRollupTable(db: D1Database): Promise<void> {
  for (const stmt of ROLLUP_DDL) await db.prepare(stmt).run();
  // The table exists after this call, so the memoised probe is now stale.
  rollupTablePresent = null;
}

/**
 * Does the rollup table exist? Memoised per isolate.
 *
 * Deliberately probes `sqlite_master` rather than just trying the query and
 * catching. A missing-table error is thrown by D1 asynchronously and — under
 * the Workers test pool especially — surfaces as an uncaught exception even
 * when the caller awaits a `.catch()`. sqlite_master never errors, so the
 * existence check is safe on every code path, including before migration 0055
 * has been applied.
 *
 * The result is cached for the isolate's lifetime: the table is created by a
 * migration and by the cron, so it cannot appear and disappear within one
 * isolate's life. That also keeps this off the hot path — at most one
 * sqlite_master read per isolate rather than per request.
 */
export function rollupTableExists(db: D1Database): Promise<boolean> {
  if (!rollupTablePresent) {
    // try/catch rather than `.catch()` on the promise: under the Workers test
    // pool an empty-result `.first()` rejection is reported as an uncaught
    // exception even with a `.catch` attached, which fails unrelated tests.
    rollupTablePresent = (async () => {
      try {
        const r = await db
          .prepare(`SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name='cyberpulse_daily_rollup'`)
          .first<{ present: number }>();
        return !!r?.present;
      } catch {
        return false;
      }
    })();
  }
  return rollupTablePresent;
}

/** Test seam — clears the memoised existence probe. */
export function resetRollupTableProbe(): void {
  rollupTablePresent = null;
}

function parseMap(raw: unknown): Counts {
  if (typeof raw !== 'string' || !raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Counts) : {};
  } catch {
    return {};
  }
}

/** Sum several `{value: count}` maps into one. */
export function mergeMaps(maps: Counts[]): Counts {
  const out: Counts = {};
  for (const m of maps) for (const [k, v] of Object.entries(m)) out[k] = (out[k] ?? 0) + v;
  return out;
}

/**
 * Deterministic top-N: count descending, then key ascending.
 *
 * Matches the tiebreaker the live queries use (`ORDER BY count DESC,
 * victim_name ASC`) so the rollup and the fallback path produce identical
 * ordering for equal counts.
 */
export function topN(map: Counts, key: string, n: number): Array<Record<string, unknown>> {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([k, count]) => ({ [key]: k, count }));
}

/**
 * Recompute and store the rollup for every day that needs it.
 *
 * `days` is the window to keep fresh. Existing days are recomputed rather than
 * skipped: incidents can still be backfilled into a past day by a late scrape,
 * and a day that is more than ~2h old is treated as final to keep the cron
 * cheap. Today is always recomputed.
 */
export async function rebuildDailyRollup(db: D1Database, days = 30, now: Date = new Date()): Promise<number> {
  await ensureDailyRollupTable(db);
  // The table now exists; clear the memoised probe so later reads use it.
  resetRollupTableProbe();
  const cutoffDate = new Date(now.getTime() - days * 86_400_000);
  const cutoffIso = cutoffDate.toISOString().slice(0, 10);

  // One scan feeds every dimension, rather than one GROUP BY per dimension.
  // Mirrors the live route's filters exactly, including the NULL exclusions.
  const { results } = await db
    .prepare(
      `SELECT DATE(discovered_at) AS bucket_date,
              COUNT(*) AS n,
              incident_type, severity, source_platform, victim_sector,
              victim_country, threat_actor, victim_name
       FROM cyberpulse_incidents
       WHERE DATE(discovered_at) >= ?
       GROUP BY bucket_date, incident_type, severity, source_platform,
                victim_sector, victim_country, threat_actor, victim_name`
    )
    .bind(cutoffIso)
    .all<{
      bucket_date: string;
      n: number;
      incident_type: string | null;
      severity: string | null;
      source_platform: string | null;
      victim_sector: string | null;
      victim_country: string | null;
      threat_actor: string | null;
      victim_name: string | null;
    }>();

  const byDay = new Map<string, GroupedRow[]>();
  for (const r of results) {
    const d = r.bucket_date ?? '';
    if (!d) continue;
    const rowsForDay = byDay.get(d) ?? [];
    rowsForDay.push({
      n: r.n,
      incident_type: r.incident_type,
      severity: r.severity,
      platform: r.source_platform,
      sector: r.victim_sector,
      country: r.victim_country,
      actor: r.threat_actor,
      victim: r.victim_name,
    });
    byDay.set(d, rowsForDay);
  }

  const stamp = now.toISOString();
  const stmt = db.prepare(
    `INSERT OR REPLACE INTO cyberpulse_daily_rollup
       (bucket_date, total, incident_type, severity, platform, sector, country, actor, victim, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const batch: ReturnType<typeof stmt.bind>[] = [];
  for (const [date, dayRows] of byDay) {
    const dim = (key: keyof Omit<GroupedRow, 'n'>): Counts => {
      const out: Counts = {};
      for (const row of dayRows) {
        const v = row[key];
        // Mirrors the live route's `IS NOT NULL` filters exactly.
        if (v === null || v === undefined || v === '') continue;
        out[String(v)] = (out[String(v)] ?? 0) + row.n;
      }
      return out;
    };
    const total = dayRows.reduce((s, row) => s + row.n, 0);
    batch.push(
      stmt.bind(
        date,
        total,
        JSON.stringify(dim('incident_type')),
        JSON.stringify(dim('severity')),
        JSON.stringify(dim('platform')),
        JSON.stringify(dim('sector')),
        JSON.stringify(dim('country')),
        JSON.stringify(dim('actor')),
        JSON.stringify(dim('victim')),
        stamp
      )
    );
  }

  if (batch.length > 0) {
    // D1 caps a batch at 100 statements.
    for (let i = 0; i < batch.length; i += 100) await db.batch(batch.slice(i, i + 100));
  }
  return batch.length;
}

/** Merged rollup over a window, or null when the window has no rollup rows. */
export async function readDailyRollup(
  db: D1Database,
  cutoff: string,
  now: Date = new Date()
): Promise<{
  total: number;
  dims: {
    incident_type: Counts;
    severity: Counts;
    platform: Counts;
    sector: Counts;
    country: Counts;
    actor: Counts;
    victim: Counts;
  };
  daily: Array<{ day: string; count: number }>;
} | null> {
  const cutoffDate = cutoff.slice(0, 10);
  const today = now.toISOString().slice(0, 10);

  // Never touch the rollup table unless it is known to exist — see
  // rollupTableExists() for why this is not a try/catch.
  if (!(await rollupTableExists(db))) return null;

  const { results } = await db
    .prepare(
      `SELECT bucket_date, total, incident_type, severity, platform, sector, country, actor, victim
       FROM cyberpulse_daily_rollup
       WHERE bucket_date >= ? AND bucket_date <= ?
       ORDER BY bucket_date ASC`
    )
    .bind(cutoffDate, today)
    .all<DailyRollupRow>();

  const rows = results ?? [];
  if (rows.length === 0) return null;

  const dims: Record<string, Counts> = {};
  for (const key of ['incident_type', 'severity', 'platform', 'sector', 'country', 'actor', 'victim']) {
    dims[key] = mergeMaps(rows.map((r) => parseMap((r as unknown as Record<string, unknown>)[key])));
  }

  // Stable key set for the caller's type-safe access.
  const typed = {
    incident_type: dims.incident_type!,
    severity: dims.severity!,
    platform: dims.platform!,
    sector: dims.sector!,
    country: dims.country!,
    actor: dims.actor!,
    victim: dims.victim!,
  };

  return {
    total: rows.reduce((s, r) => s + (r.total ?? 0), 0),
    dims: typed,
    daily: rows.map((r) => ({ day: r.bucket_date, count: r.total ?? 0 })),
  };
}
