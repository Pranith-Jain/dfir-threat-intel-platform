-- Migration 0056: Feed alert delivery channels
--
-- 0035 gave feed_jobs a runner but nowhere to send what it found: the job
-- table had no channel, no filter, and no record of whether an alert was
-- delivered. The scheduler could fetch and count indicators and that was the
-- end of it, which makes the whole thing a curiosity rather than a pipeline.
--
-- This adds the outbound half. Delivery is a child table rather than columns
-- on feed_jobs so one job can fan out to a Slack channel, a webhook and an
-- email alias at once, and so adding a channel type does not need an ALTER.
--
-- `delivery_log` is kept separate from `feed_run_history` deliberately: a run
-- can succeed and a delivery still fail (the Slack webhook 404s), and
-- collapsing those into one status would make a broken channel look like a
-- broken feed.

CREATE TABLE IF NOT EXISTS feed_alert_channels (
  id                TEXT PRIMARY KEY,
  job_id            TEXT NOT NULL,
  name              TEXT NOT NULL,

  -- Channel type. `webhook` is the general case and covers Slack, Teams and
  -- Discord by pointing at the right URL with the right payload template.
  type              TEXT NOT NULL CHECK(type IN ('webhook', 'slack', 'discord', 'email')),

  -- Where it goes. For `email` this is a comma-separated alias list; for the
  -- webhook types it is the target URL.
  target            TEXT NOT NULL,

  enabled           INTEGER NOT NULL DEFAULT 1,

  -- Only alert when an indicator appears that matches all of these. Empty means
  -- "alert on any change", which is almost never what a noisy feed should do,
  -- so `min_new_items` below is the real guard.
  match_tags        TEXT NOT NULL DEFAULT '[]',

  -- Suppression. Without a threshold a 4,000-item feed run pages someone every
  -- cycle and the channel gets muted within a week, at which point the alerts
  -- are worse than useless: they train people to ignore the one that mattered.
  min_new_items     INTEGER NOT NULL DEFAULT 1,

  -- At most one alert per this many hours regardless of how often the job runs.
  cooldown_hours    INTEGER NOT NULL DEFAULT 6,

  last_delivered_at TEXT,
  last_status       TEXT CHECK(last_status IN ('ok', 'error', 'skipped')),
  last_error        TEXT,
  created_at        TEXT NOT NULL,

  FOREIGN KEY (job_id) REFERENCES feed_jobs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_channels_job ON feed_alert_channels(job_id);
CREATE INDEX IF NOT EXISTS idx_alert_channels_enabled ON feed_alert_channels(enabled) WHERE enabled = 1;

CREATE TABLE IF NOT EXISTS feed_delivery_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id    TEXT NOT NULL,
  job_id        TEXT NOT NULL,
  attempted_at  TEXT NOT NULL,
  status        TEXT NOT NULL CHECK(status IN ('ok', 'error', 'skipped')),
  item_count    INTEGER NOT NULL DEFAULT 0,
  error         TEXT,
  FOREIGN KEY (channel_id) REFERENCES feed_alert_channels(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_delivery_log_channel ON feed_delivery_log(channel_id, attempted_at DESC);