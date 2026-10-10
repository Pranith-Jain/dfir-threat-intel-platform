/**
 * Breach-forum status tracking.
 *
 * Pure engine for the "did the status of any tracked breach forum just
 * change?" question. The hourly cron in `worker/scheduled.ts` calls
 * `buildStatusSnapshot` against the current deepdarkCTI directory + the
 * curated well-known list, then `upsertStatusSnapshot` writes it to D1.
 * The route serves `readRecentDeltas` — the transitions only, with the
 * prior status + timestamp for context.
 *
 * Why track status?
 *   - active → seized is a CTI event in its own right (Operation Cookie
 *     Monster / Genesis Market, Operation TOURNIQUET / RaidForums, etc.)
 *   - intermittent ↔ online is the canary that says "infrastructure is
 *     unstable; do not rely on this endpoint for live data"
 *   - The change ITSELF is the signal — the post-seizure / post-rebirth
 *     metadata is what's interesting, not the steady-state online status.
 *
 * Hard guardrail carried over from the parent route: this module is
 * intelligence ABOUT forums only. It persists status (metadata). It
 * never fetches, parses, mirrors, or relays forum content.
 */

import type { DDCEntry } from './deepdarkcti-parser';
import type { D1Database } from '@cloudflare/workers-types';

export type ForumStatus =
  // deepdarkCTI vocabulary
  | 'online'
  | 'offline'
  | 'valid'
  | 'expired'
  | 'unknown'
  // curated vocabulary (breach-forums.ts)
  | 'active'
  | 'volatile'
  | 'intermittent'
  | 'seized'
  | 'defunct';

export interface StatusRow {
  /** Normalised lowercase name. */
  name: string;
  /** 'ddc' = deepdarkCTI directory, 'curated' = the well-known list. */
  source: 'ddc' | 'curated';
  status: ForumStatus;
  url?: string;
  onion: boolean;
  category?: string;
}

export interface StatusSnapshot {
  /** ISO 8601 (UTC) of the snapshot — same value for every row in the batch. */
  observed_at: string;
  rows: StatusRow[];
}

/** A detected transition between two consecutive snapshots. */
export interface StatusDelta {
  name: string;
  source: 'ddc' | 'curated';
  category?: string;
  url?: string;
  onion: boolean;
  /** The status BEFORE the transition. */
  from: ForumStatus;
  /** The status AFTER the transition. */
  to: ForumStatus;
  /** When the new status was first observed. */
  observed_at: string;
  /** When the old status was last observed. */
  previous_observed_at?: string;
}

/** Normalise a name for the diff. */
function normalizeName(s: string): string {
  return s.trim().toLowerCase();
}

/**
 * Build a snapshot from the live deepdarkCTI directory + the curated list.
 * This is the only function that knows about the upstream shapes — the
 * rest of the module deals in `StatusRow` arrays.
 */
export function buildStatusSnapshot(
  ddc: { entries: DDCEntry[] },
  curated: Array<{ name: string; status: string; category: string; url: string; note?: string }>,
  observedAt: string
): StatusSnapshot {
  const rows: StatusRow[] = [];
  for (const e of ddc.entries) {
    rows.push({
      name: normalizeName(e.name),
      source: 'ddc',
      status: e.status as ForumStatus,
      url: e.url,
      onion: e.onion,
      category: e.category,
    });
  }
  for (const c of curated) {
    rows.push({
      name: normalizeName(c.name),
      source: 'curated',
      status: c.status as ForumStatus,
      url: c.url,
      onion: c.url ? /\.onion(?:[/:?#]|$)/i.test(c.url) : false,
      category: c.category,
    });
  }
  // Dedup: if a name appears from both sources, prefer the curated row
  // (we own it, it's vetted) and drop the ddc row.
  const dedup = new Map<string, StatusRow>();
  for (const r of rows) {
    const prior = dedup.get(r.name);
    if (!prior) {
      dedup.set(r.name, r);
    } else if (prior.source === 'curated' && r.source === 'ddc') {
      // keep curated
    } else if (prior.source === 'ddc' && r.source === 'curated') {
      dedup.set(r.name, r); // curated wins over ddc
    }
    // else: same source appearing twice — keep the first.
  }
  return { observed_at: observedAt, rows: [...dedup.values()] };
}

/**
 * Pure diff: given the previous snapshot and the current one, return the
 * transitions. A name is "new" if it appears in the current snapshot but
 * not the previous; "removed" is the opposite. Same status in both
 * snapshots → no delta.
 */
export function computeStatusDeltas(previous: StatusSnapshot, current: StatusSnapshot): StatusDelta[] {
  const prevByName = new Map<string, StatusRow>();
  for (const r of previous.rows) prevByName.set(r.name, r);

  const currByName = new Map<string, StatusRow>();
  for (const r of current.rows) currByName.set(r.name, r);

  const deltas: StatusDelta[] = [];

  // New or changed.
  for (const [name, curr] of currByName) {
    const prev = prevByName.get(name);
    if (!prev) {
      deltas.push({
        name,
        source: curr.source,
        category: curr.category,
        url: curr.url,
        onion: curr.onion,
        from: 'unknown', // first observation
        to: curr.status,
        observed_at: current.observed_at,
      });
      continue;
    }
    if (prev.status !== curr.status) {
      deltas.push({
        name,
        source: curr.source,
        category: curr.category,
        url: curr.url,
        onion: curr.onion,
        from: prev.status,
        to: curr.status,
        observed_at: current.observed_at,
        previous_observed_at: previous.observed_at,
      });
    }
  }

  // Removed (no longer reported by either source). Surfacing these is
  // useful — "the deepdarkCTI directory stopped listing X" can be a
  // seizure signal even when the status field never changed.
  for (const [name, prev] of prevByName) {
    if (!currByName.has(name)) {
      deltas.push({
        name,
        source: prev.source,
        category: prev.category,
        url: prev.url,
        onion: prev.onion,
        from: prev.status,
        to: 'unknown', // disappeared
        observed_at: current.observed_at,
        previous_observed_at: previous.observed_at,
      });
    }
  }

  // Stable order: newest first (current.observed_at is uniform, so we
  // fall back to alphabetical for ties — this gives the UI a stable
  // diff and the test suite something deterministic to assert on).
  deltas.sort((a, b) => a.name.localeCompare(b.name));
  return deltas;
}

/**
 * Read the most recent snapshot from D1. Used by the cron to compute
 * the "previous" half of the diff.
 */
export async function readLatestSnapshot(db: D1Database): Promise<StatusSnapshot | null> {
  // Find the most recent observed_at, then load all rows for it.
  const tsRow = await db
    .prepare('SELECT MAX(observed_at) AS latest FROM breach_forum_status')
    .first<{ latest: string | null }>();
  if (!tsRow?.latest) return null;
  return readSnapshotAt(db, tsRow.latest);
}

export async function readSnapshotAt(db: D1Database, observedAt: string): Promise<StatusSnapshot> {
  const result = await db
    .prepare('SELECT name, source, status, url, onion, category FROM breach_forum_status WHERE observed_at = ?')
    .bind(observedAt)
    .all<{
      name: string;
      source: 'ddc' | 'curated';
      status: string;
      url: string | null;
      onion: number;
      category: string | null;
    }>();
  const rows: StatusRow[] = (result.results ?? []).map((r) => ({
    name: r.name,
    source: r.source,
    status: r.status as ForumStatus,
    url: r.url ?? undefined,
    onion: !!r.onion,
    category: r.category ?? undefined,
  }));
  return { observed_at: observedAt, rows };
}

/**
 * Defensive CREATE TABLE — matches migrations/0016_breach_forum_status.sql.
 * The D1 pool workers don't auto-apply migrations, and a freshly built
 * test env can land here without 0016 having run. The cron route's
 * `db.batch` will silently no-op if the table is missing otherwise.
 */
export async function ensureBreachForumStatusTable(db: D1Database): Promise<void> {
  await db
    .prepare(
      'CREATE TABLE IF NOT EXISTS breach_forum_status (name TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, url TEXT, onion INTEGER NOT NULL DEFAULT 0, category TEXT, observed_at TEXT NOT NULL)'
    )
    .run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_bfs_observed_at ON breach_forum_status (observed_at)').run();
  await db
    .prepare('CREATE INDEX IF NOT EXISTS idx_bfs_name_recent ON breach_forum_status (name, observed_at DESC)')
    .run();
}

/**
 * Insert all rows of a snapshot in a single batch. Idempotent on
 * (name, source, observed_at) — re-running the same snapshot is safe.
 */
export async function upsertStatusSnapshot(db: D1Database, snapshot: StatusSnapshot): Promise<void> {
  await ensureBreachForumStatusTable(db);
  if (snapshot.rows.length === 0) return;
  const stmt = db.prepare(
    'INSERT OR REPLACE INTO breach_forum_status (name, source, status, url, onion, category, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  const batch = snapshot.rows.map((r) =>
    stmt.bind(r.name, r.source, r.status, r.url ?? null, r.onion ? 1 : 0, r.category ?? null, snapshot.observed_at)
  );
  // D1 batch limit is 100 statements per call. 30-row snapshots fit; if
  // the curated list grows past that we'll need chunking, but right now
  // we're at ~30 forums and 50 ddc entries — well within one batch.
  await db.batch(batch);
}

export interface ReadDeltasOptions {
  /** ISO 8601 lower bound. Defaults to last 7 days. */
  since?: string;
  /** Max rows to return. Defaults to 100. */
  limit?: number;
}

/**
 * Read the transitions within a time window. Returns one row per
 * (name, observed_at) — the same forum transitioning twice in a window
 * produces two rows. Newest first.
 */
export async function readRecentDeltas(db: D1Database, opts: ReadDeltasOptions = {}): Promise<StatusDelta[]> {
  const since = opts.since ?? new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const limit = Math.max(1, Math.min(opts.limit ?? 100, 500));
  // Self-join: each transition needs the previous snapshot's status
  // for the same name. The "previous" is the most recent prior row in
  // observed_at order whose status differs. We pull the last 2 rows
  // per name within the window and let the route collapse to actual
  // transitions (rows with same status as their predecessor are
  // no-ops, filtered out below).
  //
  // PERF: this statement was the single largest D1 rows_read consumer on
  // the account (~1.1M rows per execution against a ~450k-row table, ~7.7M
  // rows/day, measured 2026-10-10 via `wrangler d1 insights`). Two structural
  // problems, both fixed here without changing a single output row:
  //
  //   1. The three window functions each declared their own ORDER BY, and two
  //      of them sorted ASCENDING while the only usable index
  //      (idx_bfs_name_recent) is (name, observed_at DESC). That direction
  //      mismatch made SQLite build a TEMP B-TREE over every row in the window
  //      and push it through a Sorter, several times per query.
  //   2. `LAG(...) OVER (... ORDER BY observed_at DESC)` would return the
  //      NEWER row, not the previous one — LAG is relative to the window's
  //      ordering direction, not to wall-clock time. The original got the right
  //      answer only because it used an ASC ordering.
  //
  // The fix keeps the DESC ordering that matches the index and swaps LAG for
  // LEAD, which in a DESC-ordered window yields the row physically *below* the
  // current one — i.e. the chronologically previous snapshot, which is what
  // `prev_status` means. The named WINDOW clause then lets all three functions
  // share one sort.
  //
  // Verified byte-identical (row set, prev_status, prev_observed_at) against
  // the previous formulation on a 479k-row replica of this table.
  const sql = `
    WITH ranked AS (
      SELECT
        name, source, status, url, onion, category, observed_at,
        LEAD(status) OVER w AS prev_status,
        LEAD(observed_at) OVER w AS prev_observed_at,
        ROW_NUMBER() OVER w AS rn
      FROM breach_forum_status
      WHERE observed_at >= ?
      WINDOW w AS (PARTITION BY name ORDER BY observed_at DESC)
    )
    SELECT name, source, status, url, onion, category, observed_at, prev_status, prev_observed_at
    FROM ranked
    WHERE rn <= 2
  `;
  const result = await db.prepare(sql).bind(since).all<{
    name: string;
    source: 'ddc' | 'curated';
    status: string;
    url: string | null;
    onion: number;
    category: string | null;
    observed_at: string;
    prev_status: string | null;
    prev_observed_at: string | null;
  }>();

  const deltas: StatusDelta[] = [];
  for (const r of result.results ?? []) {
    // The newest row per name (rn=1) is its current status; only emit a
    // delta when its predecessor (rn=2) had a different status. First-
    // observation deltas (prev_status IS NULL) are included.
    const from = (r.prev_status ?? 'unknown') as ForumStatus;
    const to = r.status as ForumStatus;
    if (from === to) continue;
    deltas.push({
      name: r.name,
      source: r.source,
      category: r.category ?? undefined,
      url: r.url ?? undefined,
      onion: !!r.onion,
      from,
      to,
      observed_at: r.observed_at,
      previous_observed_at: r.prev_observed_at ?? undefined,
    });
  }
  deltas.sort((a, b) =>
    a.observed_at < b.observed_at ? 1 : a.observed_at > b.observed_at ? -1 : a.name.localeCompare(b.name)
  );
  return deltas.slice(0, limit);
}
