-- Query-cost indexes for the routes still doing full table scans (2026-10-10).
--
-- Follows the same discipline as 0048/0050/0051: additive, `IF NOT EXISTS`,
-- scoped to low-write tables, and verified with EXPLAIN QUERY PLAN against a
-- local replica of the real schema (SQLite 3.54) BEFORE being written here.
-- Never run DDL on a request path — apply this as a migration.
--
-- Apply with:
--   npx wrangler d1 execute pranithjain-briefings --remote --file=migrations/0053_d1_query_cost_indexes.sql
--   npx wrangler d1 execute pranithjain-briefings --remote --command "PRAGMA optimize"
--
-- Safe to run repeatedly and safe to run live: additive, no table rewrite.

-- ── graph_nodes: the /api/v1/live-iocs feed-scheduler compose ───────────────
--
-- `live-iocs.ts` reads this on EVERY compose of the flagship /threatintel
-- surface, and the predicate was:
--
--     WHERE json_extract(sources, '$[0]') LIKE 'feed:%'
--     ORDER BY last_seen DESC LIMIT ?
--
-- json_extract over an unindexed column is a guaranteed full scan, and
-- graph_nodes is an append-mostly table that the retention sweep only trims
-- once a day — so the scan grew all day. Verified baseline plan:
--
--     SCAN graph_nodes
--     USE TEMP B-TREE FOR ORDER BY
--
-- The index is on the 5-character prefix of the extracted value rather than
-- the whole thing, because the code now tests `substr(...,1,5) = 'feed:'`
-- instead of `LIKE 'feed:%'`. That rewrite is not cosmetic and the index is
-- useless without it: SQLite only applies its LIKE optimization to an
-- indexed column when `case_sensitive_like` is ON, and D1 does not guarantee
-- that pragma. Measured on SQLite 3.54 with the real schema:
--
--     expression index + `LIKE 'feed:%'`, pragma off -> SCAN   (index IGNORED)
--     expression index + `LIKE 'feed:%'`, pragma on  -> SEARCH, but still sorts
--     expression index + `substr(...)= 'feed:'`      -> SEARCH, no sort
--
-- So the equality form is the only variant that is index-served WITHOUT
-- depending on a pragma D1 controls, which is why the query was changed
-- alongside the schema. Semantics are identical: every writer builds feed
-- sources from the literal template `feed:${name}` (feed-scheduler.ts,
-- digitalside.ts), so the first source is always lowercase `feed:`.
--
-- `last_seen DESC` is the second column so the index also satisfies the
-- ORDER BY directly and the temp B-tree sort disappears — verified plan is
-- a single SEARCH with no sorter.
--
-- Write cost: graph_nodes ingests ~18 entities per graph run (daily 02:00),
-- so this adds well under 1% to the daily write budget.
CREATE INDEX IF NOT EXISTS idx_nodes_feed_last_seen
  ON graph_nodes(substr(json_extract(sources, '$[0]'), 1, 5), last_seen DESC);

-- ── Retention sweep keys ──────────────────────────────────────────────────
--
-- `retention.ts` runs 30+ `DELETE FROM t WHERE <col> < ?` once a day. D1 bills
-- a DELETE by the rows it READS, not the rows it removes — so a DELETE whose
-- filter column has no index is billed as a full table scan even when it
-- matches nothing. These four sweep columns have no index today, and the
-- tables they guard are the same unbounded-growth ones the policy was extended
-- to cover in 2026-10-07.
--
-- These are deliberately NOT covering indexes. A DELETE needs the rowid only,
-- and appending the payload columns here would inflate the write cost on
-- high-volume tables to save a table fetch on a once-a-day sweep — a bad
-- trade on a write budget that is also close to its ceiling.
CREATE INDEX IF NOT EXISTS idx_alert_feeds_created_at
  ON alert_feeds(created_at);
CREATE INDEX IF NOT EXISTS idx_passive_dns_created_at
  ON passive_dns_observations(created_at);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_first_seen
  ON graph_nodes(first_seen);
CREATE INDEX IF NOT EXISTS idx_graph_edges_first_seen
  ON graph_edges(first_seen);

-- ── telegram_leak_entries.discovered_at — ALREADY INDEXED (see note) ───────
--
-- No new index is added here. `discovered_at` already has one:
--
--     0010_leak_dedup.sql:7  idx_leak_entries_cleanup ON telegram_leak_entries(discovered_at)
--
-- so adding another would buy nothing on reads and cost one extra row write
-- per INSERT on the largest table in the schema — the wrong trade while the
-- daily write budget is also near its ceiling.
--
-- The `total_leaks` counter this section was originally written for
-- (`SELECT COUNT(*) FROM telegram_leak_entries` with no WHERE) is NOT fixable
-- by an index: counting every row is inherently O(n). It is handled by the
-- 300s KV cache in `api/src/lib/d1-cache.ts` instead.
--
-- SEPARATE FINDING, NOT ACTIONED HERE
-- -----------------------------------
-- `telegram_leak_entries.discovered_at` is indexed TWICE:
--     0009: idx_leak_entries_discovered  (discovered_at DESC)
--     0010: idx_leak_entries_cleanup     (discovered_at)
-- SQLite scans an index in either direction, so the DESC variant carries no
-- capability the ASC one lacks — one of the two is pure per-insert write cost.
-- Dropping the redundant one would REDUCE writes, but it should be a measured
-- decision against `rows_read` before/after rather than a drive-by in a
-- migration that is otherwise purely additive:
--
--     npx wrangler d1 execute pranithjain-briefings --remote \
--       --command "DROP INDEX IF EXISTS idx_leak_entries_discovered"