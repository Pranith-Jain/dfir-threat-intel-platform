-- Migration 0058: newly-registered domain watchlist
--
-- A daily feed of newly registered domains is only useful if someone cares
-- about a specific word in it. "Show me every domain registered yesterday"
-- is a curiosity; "tell me when someone registers a domain containing
-- 'banco'" is an early-warning signal for typosquatting and brand abuse.
--
-- `domain_watchlist` holds the words. `domain_watch_matches` holds what
-- each watch found, so a watch that has fired 200 times does not fire 200
-- times again on every page load.
--
-- The matching itself is keyword-substring on the *normalized* domain (see
-- api/src/lib/domain-monitor.ts): accents stripped, lowercased, restricted
-- to alphanumerics, dots and dashes. That normalization is what makes
-- "banco" match "bancó-seguro.mx" and "BANCO.ORG" alike — which is the
-- whole point of a watchlist, and also why the normalized form is stored
-- alongside the raw keyword rather than replacing it.

CREATE TABLE IF NOT EXISTS domain_watchlist (
  id            TEXT PRIMARY KEY,
  -- The keyword as the analyst typed it.
  keyword       TEXT NOT NULL,
  -- The normalized form actually used for matching.
  normalized    TEXT NOT NULL,
  -- Optional free-text note explaining what the watch is for.
  note          TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL,
  last_checked_at TEXT,
  -- Total matches ever recorded for this watch.
  match_count   INTEGER NOT NULL DEFAULT 0
);

-- One keyword per watch — a duplicate watch would double every match.
CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_watchlist_normalized ON domain_watchlist(normalized);

-- The list is always read in bulk and sorted by recency.
CREATE INDEX IF NOT EXISTS idx_domain_watchlist_created ON domain_watchlist(created_at DESC);

CREATE TABLE IF NOT EXISTS domain_watch_matches (
  id          TEXT PRIMARY KEY,
  watch_id    TEXT NOT NULL,
  -- The registered domain that matched.
  domain      TEXT NOT NULL,
  -- The day the domain was registered (the feed's own date).
  registered_on TEXT NOT NULL,
  -- When this platform first saw it.
  detected_at TEXT NOT NULL,
  -- The keyword that matched, so one row can serve several watches.
  matched_keyword TEXT NOT NULL
);

-- The dedupe index: the same domain must not be recorded twice for the
-- same watch on the same day, or a re-scan of the same feed would inflate
-- the match count.
CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_watch_matches_unique
  ON domain_watch_matches(watch_id, domain, registered_on);

-- Backs "show me what this watch found, newest first".
CREATE INDEX IF NOT EXISTS idx_domain_watch_matches_watch
  ON domain_watch_matches(watch_id, detected_at DESC);
