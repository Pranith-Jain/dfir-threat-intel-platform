-- Persisted breach-forum status transitions.
--
-- Context: on 2026-10-10, `wrangler d1 insights` showed `readRecentDeltas`
-- (api/src/lib/breach-forum-status.ts) as the account's largest D1 rows_read
-- consumer — ~1.1M rows per execution against a 446,769-row snapshot table,
-- ~7.7M rows/day, which is what pushed the account past the 5M/day free-tier
-- read limit (error 7500) and blocked every D1 query until the 00:00 UTC
-- reset.
--
-- WHY THE EXPENSIVE QUERY EXISTS AT ALL
-- ------------------------------------
-- The route used to re-derive the transitions on read with a window-function
-- CTE (LAG + ROW_NUMBER over PARTITION BY name), which must touch every
-- snapshot row in the window before it can rank anything. That work is
-- redundant: the hourly cron ALREADY computes the exact transitions in memory
-- via `computeStatusDeltas(prev, snapshot)` (worker/scheduled.ts) and then
-- threw them away, keeping only `deltas.length` for its write-on-change gate.
--
-- This table is that discarded result, persisted. The read path becomes an
-- indexed range scan of the few hundred rows that are actually transitions
-- instead of ~1M rows of window machinery — roughly a 4-order-of-magnitude
-- reduction, and it removes the query that was single-handedly overrunning the
-- read budget.
--
-- The backfill below reproduces the read path's current semantics exactly
-- (including the rn<=2 "first observation" rows the route emits today), so the
-- route's output is unchanged at cutover rather than starting empty.
--
-- COST WARNING — READ THIS BEFORE RUNNING
-- ---------------------------------------
-- The backfill is itself one ~1M-row read. Run it ONCE, after the 00:00 UTC
-- reset, and do not run it in the same window as anything else heavy: it
-- costs roughly 20% of the daily 5M read budget.
--
--   npx wrangler d1 execute pranithjain-briefings --remote --file=migrations/0052_breach_forum_deltas.sql
--
-- The CREATE statements are safe and idempotent on their own. If you want to
-- stage the cutover, run only the two CREATE statements now and do the
-- INSERT..SELECT after the reset.

CREATE TABLE IF NOT EXISTS breach_forum_deltas (
  name                 TEXT NOT NULL,
  source               TEXT NOT NULL,
  status_from          TEXT NOT NULL,
  status_to            TEXT NOT NULL,
  url                  TEXT,
  onion                INTEGER NOT NULL DEFAULT 0,
  category             TEXT,
  observed_at          TEXT NOT NULL,
  previous_observed_at TEXT,
  -- One transition per forum per snapshot. Makes the cron's INSERT idempotent
  -- if it ever re-runs the same comparison, so a retry cannot double-count.
  PRIMARY KEY (name, observed_at)
);

-- The read path is `WHERE observed_at >= ? ORDER BY observed_at DESC LIMIT ?`.
-- Without this the ordering degenerates into a full scan + sort, which would
-- reintroduce exactly the cost this table exists to remove.
CREATE INDEX IF NOT EXISTS idx_bfd_observed_at
  ON breach_forum_deltas(observed_at DESC);

-- One-time backfill: replay the exact transition logic the read path used, so
-- the route serves the same deltas it served before the cutover.
--
-- Mirrors readRecentDeltas precisely:
--   * rn <= 2  — the route keeps the two newest snapshots per forum, which can
--     yield up to two deltas per forum (the rn=2 row with a NULL predecessor is
--     emitted as a first-observation delta). Preserved here so output matches.
--   * prev_status IS NULL OR prev_status <> status — the route's own
--     no-op filter for unchanged snapshots.
--   * ASC ordering for the LAGs, which is what "previous" means; DESC is only
--     correct for the ROW_NUMBER ranking.
INSERT OR REPLACE INTO breach_forum_deltas
  (name, source, status_from, status_to, url, onion, category, observed_at, previous_observed_at)
WITH ranked AS (
  SELECT
    name, source, status, url, onion, category, observed_at,
    LAG(status) OVER (PARTITION BY name ORDER BY observed_at) AS prev_status,
    LAG(observed_at) OVER (PARTITION BY name ORDER BY observed_at) AS prev_observed_at,
    ROW_NUMBER() OVER (PARTITION BY name ORDER BY observed_at DESC) AS rn
  FROM breach_forum_status
  WHERE observed_at >= datetime('now', '-30 days')
)
SELECT
  name, source, COALESCE(prev_status, 'unknown'), status, url, onion, category,
  observed_at, prev_observed_at
FROM ranked
WHERE rn <= 2 AND (prev_status IS NULL OR prev_status <> status);