-- Migration 0057: CVE first-seen observations and trending
--
-- The platform records a CVE's `published` date (from NVD and friends) but has
-- never recorded when IT first saw the record. Those are different numbers and
-- the gap between them is the only honest measure of detection latency: how
-- long between a bug being published and this platform being able to tell you
-- about it. Without a first-seen row there is nothing to compute, because
-- `published` alone cannot distinguish "we saw it late" from "we saw it fast".
--
-- Two tables, deliberately split:
--
--   cve_first_seen   one row per CVE, immutable once written. This is the
--                    latency anchor and must never be updated, or the metric
--                    drifts toward zero every time a record is re-indexed.
--
--   cve_observations per CVE per day. Counting mentions per day gives the
--                    velocity that "Hot" sorts on, and unlike an upvote count
--                    it is derived from feeds we already fetch rather than from
--                    activity we would have to solicit.
--
-- `mention_count` on the daily row is deliberately just the number of upstream
-- feeds that carried the CVE that day. That is a proxy for attention, not for
-- severity, and it is labelled as such everywhere it surfaces.

CREATE TABLE IF NOT EXISTS cve_first_seen (
  cve_id        TEXT PRIMARY KEY,
  published_at  TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  source        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_first_seen_date ON cve_first_seen(first_seen_at DESC);

CREATE TABLE IF NOT EXISTS cve_observations (
  cve_id        TEXT NOT NULL,
  observed_on   TEXT NOT NULL,
  mentions      INTEGER NOT NULL DEFAULT 0,
  sources       TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (cve_id, observed_on)
);

CREATE INDEX IF NOT EXISTS idx_cve_obs_date ON cve_observations(observed_on DESC);

-- Backs the "trending now" query, which always looks at a recent window.
CREATE INDEX IF NOT EXISTS idx_cve_obs_hot ON cve_observations(observed_on DESC, mentions DESC);