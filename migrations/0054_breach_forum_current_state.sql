-- Cut breach_forum_status write amplification by ~99%.
--
-- PROBLEM
-- ------
-- `upsertStatusSnapshot` wrote ALL 1,494 forum rows on every snapshot, ~15
-- snapshots/day. Measured 2026-10-11 via `wrangler d1 insights --sort-by writes`:
--
--     INSERT OR REPLACE INTO breach_forum_status ...   115,375 rows_written
--                                                     x23,075 executions
--                                                     = exactly 5.0 rows each
--
-- The 5.0 is the tell: 1 table row + 4 index rows per forum. `breach_forum_status`
-- carried four indexes, so every snapshot cost 1,494 x 5 = 7,470 row writes to
-- record roughly TEN actual status changes. At ~15 snapshots/day that is
-- ~112k rows_written/day against a Workers Free allowance of 100,000/day — the
-- account breached the WRITE limit on its own, which (per the 2026-09-01 D1
-- free-tier enforcement change) fails every query account-wide, not just writes.
--
-- WHY NOT A DIFFERENT STORE
-- -------------------------
-- There is no free-tier Cloudflare store that gives more write capacity:
--   * Durable Objects SQLite is documented as "rows read and rows written
--     included limits ... match D1 pricing" — identical 100k/day.
--   * Workers KV Free allows 1,000 writes/DAY — 100x worse than D1.
--   * Analytics Engine is append-only (no upsert) and is shaped for aggregate
--     time-series, not "current state of 1,494 keyed rows".
-- So the fix is to write less, not to store it elsewhere.
--
-- THE FIX
-- -------
-- Separate CURRENT STATE from HISTORY. The table only ever needed two things:
--   (a) the previous state, to diff the next snapshot against, and
--   (b) a freshness/health signal for the route.
-- It never needed the full snapshot history — that history is what
-- `breach_forum_deltas` already stores, as transitions.
--
--   breach_forum_current   one row per forum, PK(name). Written ONLY when the
--                          forum is new or one of its fields actually changed.
--   breach_forum_snapshots one row per snapshot (observed_at, row_count).
--                          Replaces the row-count health signal without
--                          re-storing 1,494 rows.
--
-- `breach_forum_status` is deliberately LEFT IN PLACE, untouched and no longer
-- written. Rollback is therefore a code revert with no data migration, and the
-- legacy derivation in breach-forum-status.ts keeps working during rollout.
--
-- Cost after this change, per snapshot:
--   ~10 changed forums x 2 (table + 1 index) + 1 snapshot-log row  ~= 21 rows
-- versus 7,470 before. Two indexes, not four: the new table needs only
-- idx_bfc_observed_at (the PK covers name lookups), which avoids repeating
-- this exact mistake on the replacement table.
--
-- BACKFILL
-- --------
-- Seeds `breach_forum_current` from the newest snapshot already in
-- breach_forum_status, and writes the matching snapshot-log row, so the first
-- post-deploy snapshot diffs against real state instead of treating all 1,494
-- forums as brand new (which would be a one-off 1,494-row write — exactly the
-- spike this migration exists to avoid).
--
-- Reads 1,494 rows. Run it once, ideally right after 00:00 UTC.

CREATE TABLE IF NOT EXISTS breach_forum_current (
  name       TEXT PRIMARY KEY,
  source     TEXT NOT NULL,
  status     TEXT NOT NULL,
  url        TEXT,
  onion      INTEGER NOT NULL DEFAULT 0,
  category   TEXT,
  -- When THIS row last changed. Not "last seen": bumping it every snapshot for
  -- every forum would reintroduce the full-table write this table replaces.
  observed_at TEXT NOT NULL
);

-- Only the freshness/health query filters this table, and it filters by time.
-- The PRIMARY KEY already serves name lookups, so this is the single index
-- needed — deliberately NOT four.
CREATE INDEX IF NOT EXISTS idx_bfc_observed_at
  ON breach_forum_current(observed_at);

-- One row per snapshot: enough to answer "was there a snapshot in this window?"
-- without retaining (or re-writing) every forum row per snapshot.
CREATE TABLE IF NOT EXISTS breach_forum_snapshots (
  observed_at TEXT PRIMARY KEY,
  row_count   INTEGER NOT NULL
);

INSERT OR REPLACE INTO breach_forum_current
  (name, source, status, url, onion, category, observed_at)
SELECT name, source, status, url, onion, category, observed_at
FROM breach_forum_status
WHERE observed_at = (SELECT MAX(observed_at) FROM breach_forum_status);

INSERT OR IGNORE INTO breach_forum_snapshots (observed_at, row_count)
SELECT observed_at, COUNT(*)
FROM breach_forum_status
WHERE observed_at = (SELECT MAX(observed_at) FROM breach_forum_status)
GROUP BY observed_at;

-- Snapshot history older than the retention window is now two small tables.
-- breach_forum_status itself is left alone here: it is frozen (no new writes),
-- so sweeping it would be a large one-off DELETE that costs MORE rows_written
-- than leaving the dead rows in storage. Clear it separately, deliberately, if
-- the space is ever wanted:
--
--   DELETE FROM breach_forum_status WHERE observed_at < datetime('now','-30 days');
--
-- Adding indexes to breach_forum_deltas here is deliberate: the read path is
-- `WHERE observed_at >= ? ORDER BY observed_at DESC LIMIT ?`, which without this
-- degenerates into a scan+sort of the whole delta history.
CREATE INDEX IF NOT EXISTS idx_bfd_observed_at
  ON breach_forum_deltas(observed_at DESC);