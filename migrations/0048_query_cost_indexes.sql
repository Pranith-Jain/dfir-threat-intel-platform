-- Query-cost indexes (2026-10-07 D1 row-read audit).
--
-- Context: the account exceeded the 5M rows/day free-tier read limit on
-- 2026-10-05, 10-06 and 10-07 (peak 12.4M on 09-23). Reads were hard-blocked
-- account-wide until the 00:00 UTC reset, because on the Free plan exceeding
-- the daily limit makes D1 refuse queries rather than billing overage.
--
-- These indexes are deliberately SCOPED TO SMALL TABLES. Every index adds a
-- row write per insert on the indexed columns, and the write side is also near
-- its limit (100k rows/day; Oct 5 hit 120k and Oct 6 hit 117k). Building an
-- index on a high-write, wide table such as cyberpulse_incidents would trade a
-- read problem for a write problem, so those are deferred until the Worker is
-- on the Paid plan (50M rows written/month included).
--
-- NOT applied by CI. wrangler deploy does not touch schema, so this file is
-- inert until someone runs:
--   npx wrangler d1 execute pranithjain-briefings --remote --file <this file>
-- Applying it on the Free plan writes only a few hundred rows (the tables
-- involved are all small), which fits inside the remaining daily write budget.

-- GET /api/v1/telegram-leaks/discovered-channels (the "Channels" tab of
-- /threatintel/telegram) appends `ORDER BY discovered_at DESC LIMIT 200` with
-- no WHERE clause, so SQLite scanned the whole table and sorted it. `reviewed`
-- was also unindexed despite being the only filter the route ever applies.
CREATE INDEX IF NOT EXISTS idx_tdc_reviewed_discovered
  ON telegram_discovered_channels(reviewed, discovered_at DESC);

-- GET /api/v1/telegram-leaks/watched-channels — a filter on the indexed
-- `active` followed by a sort on the unindexed `last_leak_found`, i.e. sort on
-- scan. Composite index lets SQLite satisfy both from the index.
CREATE INDEX IF NOT EXISTS idx_twc_active_last_leak
  ON telegram_watched_channels(active, last_leak_found DESC);

-- The iocs_ipv4 / iocs_sha256 / ... views select on (ioc_type, valid_until).
-- Having them adjacent lets the planner use idx_actionable_iocs_type for the
-- type restriction without an extra probe per row.
CREATE INDEX IF NOT EXISTS idx_actionable_iocs_type_valid
  ON actionable_iocs(ioc_type, valid_until);

-- Future-facing note (deliberately NOT created here):
--
-- The remaining large read offenders need schema work that cannot be indexed
-- away, and should be scheduled after the Paid-plan upgrade:
--
--   * telegram_leak_entries.message_text / domains_found — searched with
--     `LIKE '%term%'` (leading wildcard) and an OR across three columns, so no
--     B-tree index can ever be used. Needs FTS5, or a normalized
--     tle_domain(entry_id, domain) junction table.
--   * intel_bundles JSON-array filter columns (threat_actor_names,
--     malware_names, ...) — same leading-wildcard problem; needs junction
--     tables, which the codebase already anticipates in
--     api/src/lib/agent/investigation-memory.ts.
--   * saved_reports.report_json and investigation_memory.iocs/actors/cves —
--     blob LIKE scans, 11-20 of them per request.