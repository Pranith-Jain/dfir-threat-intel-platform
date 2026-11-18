-- Migration 0059: warm-slice store for Global Pulse feed warms.
--
-- WHY THIS TABLE EXISTS
-- ---------------------
-- The hourly queue consumer warms ~28 upstream feeds into `gp:warm:<key>`.
-- Each cycle wrote one KV key per feed plus the route's own L2 last-good copy,
-- and the free plan allows 1,000 KV WRITES per day. Measured 2026-11-18 over
-- the preceding 28 days:
--
--   KV_CACHE writes   27,630  (987/day average, peaks 1,450/day)
--   KV_CACHE reads    76,300  (2,725/day)
--   KV_CACHE deletes       0
--   KV_CACHE lists         0
--
-- Writes are the scarce resource (1k/day), and the account sat at 99% of the
-- quota with several days over it. Over-quota KV writes return 429s, so
-- warm slices silently stop refreshing and whole map layers go dark.
--
-- The warm slices are *cached data*, not cross-colo correctness state, so they
-- do not need KV's durability semantics. D1 has 100k rows written/day and
-- 5M rows read/day on the same free plan — 100x the write headroom — and the
-- 28 sequential `gp:warm` KV reads that the Global Pulse build did per request
-- collapse into ONE indexed query here.
--
-- Trade-off: D1 has a ~1 MB row limit, so bodies above 900k characters stay on
-- KV (see api/src/lib/warm-slices.ts). That is a safety valve, not the normal
-- path; typical feed payloads are 20-400 KB.
--
-- ROLLOUT
-- -------
-- The Worker falls back to KV whenever this table is missing, so deploying the
-- code before the migration is safe (and the reverse is too). Apply with:
--
--   npx wrangler d1 migrations apply pranithjain-briefings --remote
--
-- Legacy `gp:warm:*` KV keys keep their TTLs and serve as the read fallback
-- until they expire (<= 3h after cutover). No manual cleanup is needed.

CREATE TABLE IF NOT EXISTS warm_slices (
  -- Feed key without the legacy `gp:warm:` prefix (e.g. `reddit`, `cve`).
  key        TEXT PRIMARY KEY NOT NULL,
  -- Raw response body, stored verbatim so the write-on-change guard stays a
  -- byte comparison (re-serializing could reorder keys and force a write).
  body       TEXT NOT NULL,
  -- Epoch milliseconds — used for observability only.
  updated_at INTEGER NOT NULL,
  -- Epoch milliseconds. Reads filter `expires_at > now`, so a stale row is a
  -- miss without needing a delete job.
  expires_at INTEGER NOT NULL
);

-- The read path filters by expiry; this keeps the warm-slice query a covering
-- scan even if the table ever accumulates historical rows.
CREATE INDEX IF NOT EXISTS idx_warm_slices_expires ON warm_slices(expires_at);
