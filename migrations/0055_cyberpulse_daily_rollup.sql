-- Materialised daily rollup for cyberpulse.
--
-- WHY
-- ---
-- `/api/v1/cyberpulse/stats` used to run five independent aggregates over
-- `cyberpulse_incidents`, each re-walking the table for its own GROUP BY.
-- Measured 2026-10-11 via `wrangler d1 insights --sort-by reads`:
--
--     SELECT DATE(discovered_at), COUNT(*) ... GROUP BY DATE(discovered_at)
--        64,020 rows_read, 12 runs, 5,335 rows per run
--     SELECT victim_name,      COUNT(*) ... GROUP BY victim_name
--        19,115 rows_read,  7 runs, 2,730 rows per run
--
-- ~105k rows/day — 65% of ALL remaining D1 reads after the breach-forum fix.
--
-- None of these GROUP BY keys are indexable: `DATE(discovered_at)` is a
-- function over the column, and `victim_name` / `threat_actor` /
-- `victim_country` are unbounded free text. An index cannot turn any of them
-- from a scan into a range lookup, so the answer is not "add an index".
--
-- The answer is to stop recomputing them per request. cyberpulse_incidents is
-- append-only (INSERT OR IGNORE, never UPDATE), so a day's aggregates are
-- immutable once the day is over. Computing them once per day and storing the
-- result turns "scan N rows per request" into "read ~30 rows for a 30-day
-- window".
--
-- NO KV INVOLVED
-- --------------
-- An earlier option was to cache the aggregate in KV behind the route. That was
-- rejected: it trades D1 reads for KV reads and writes, and KV's free tier is
-- only 1,000 writes/day. This keeps everything in D1.
--
-- SHAPE
-- -----
-- One row per calendar day, with each dimension's `{value: count}` map stored
-- as JSON. Storing per-day rather than per-window means the SAME row serves
-- every window size (7/30/90 days) — the route reads the days it needs and sums
-- the maps in JS. A per-window rollup would have to be recomputed whenever the
-- window changed.
--
-- Sizes are bounded in practice: victim/actor/country cardinality per day is
-- small (tens), and D1 allows rows far larger than this.

CREATE TABLE IF NOT EXISTS cyberpulse_daily_rollup (
  bucket_date   TEXT PRIMARY KEY,          -- YYYY-MM-DD (UTC)
  total         INTEGER NOT NULL,
  incident_type TEXT NOT NULL DEFAULT '{}', -- JSON {"ransomware": 12, ...}
  severity      TEXT NOT NULL DEFAULT '{}',
  platform      TEXT NOT NULL DEFAULT '{}',
  sector        TEXT NOT NULL DEFAULT '{}',
  country       TEXT NOT NULL DEFAULT '{}',
  actor         TEXT NOT NULL DEFAULT '{}',
  victim        TEXT NOT NULL DEFAULT '{}',
  updated_at    TEXT NOT NULL
);

-- The read path is "days in [cutoff, now]". Without this the table is tiny
-- enough today that a scan would be cheap, but it grows 1 row/day and the
-- route is on the hot path, so index the access pattern rather than the size.
CREATE INDEX IF NOT EXISTS idx_cpdr_bucket ON cyberpulse_daily_rollup(bucket_date);