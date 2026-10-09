-- Index the "empty briefing" predicate used by pruneEmptyBriefingsHandler.
--
-- `briefings.ts` filters with:
--     WHERE type IN ('daily','weekly')
--       AND json_extract(stats_json,'$.findings') = 0
-- A JSON function on an unindexed column forces a full table scan of every
-- briefing row, and it appears twice in that handler (once to SELECT the
-- slugs, once to DELETE them). `idx_briefings_type` alone cannot serve the
-- json_extract half, so SQLite falls back to a scan.
--
-- SQLite supports indexes on expressions directly, which avoids adding a
-- column and a write-path change to every briefing insert. The expression must
-- match the query's verbatim or the planner will ignore it.
--
-- Deliberately NOT a partial index (`WHERE json_extract(...) = 0`): partial
-- index predicates must be satisfied by every row the query touches, and a
-- bare expression index is simpler and plans correctly for both the SELECT
-- and the DELETE.

CREATE INDEX IF NOT EXISTS idx_briefings_empty_findings
  ON briefings(json_extract(stats_json, '$.findings'));

-- The sweep at scheduled.ts reads `type IN ('daily','weekly')` alongside the
-- range ordering; a composite (type, range_end) index lets that resolve
-- without touching idx_briefings_type + idx_briefings_range_end separately.
CREATE INDEX IF NOT EXISTS idx_briefings_type_range
  ON briefings(type, range_end);