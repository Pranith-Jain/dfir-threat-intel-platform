import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';

/**
 * ThreatDataDO — Durable Object SQLite replacement for the D1 tables that
 * kept hitting the free-plan 5M-row/day hard block.
 *
 * Why a DO and not D1:
 *   D1's free tier enforces a HARD BLOCK at 5M rows_read/day — once exceeded,
 *   every D1 query account-wide fails until midnight UTC. That took briefings
 *   offline for 3 days (2026-10-08..10) because the cron couldn't write and
 *   the read routes couldn't read. DO SQLite has no such block: it has a
 *   5 GB storage limit and per-request CPU limits, neither of which these
 *   tables come close to.
 *
 * Tables owned here (mirrors of the D1 schemas, kept identical so the SQL
 * in the existing route handlers runs unchanged through the adapter):
 *   - briefings                (daily/weekly briefing JSON)
 *   - telegram_leak_entries    (leak monitor — largest table)
 *   - telegram_watched_channels
 *   - telegram_discovered_channels
 *   - cyberpulse_incidents     (breach/leak incident tracker)
 *   - cyberpulse_scan_log
 *   - breach_forum_status      (hourly snapshots)
 *   - breach_forum_deltas      (persisted transitions)
 *
 * The DO exposes a generic `sql()` RPC that takes raw SQL + params and
 * returns rows — the same contract D1's prepare/bind/all gives us. The
 * D1-compatible adapter (api/src/lib/do-database.ts) wraps a DO stub in
 * the D1Database interface so existing route code doesn't change.
 *
 * Single named instance ("threat-data"): all four tables are small-to-medium
 * and the access pattern is read-heavy with rare writes (cron). One instance
 * keeps the SQLite data in one place; the DO is single-threaded so concurrent
 * writes are serialized (which is what we want for consistency).
 */
export class ThreatDataDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      const sql = this.ctx.storage.sql;
      // ── briefings ──────────────────────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS briefings (
          slug        TEXT PRIMARY KEY,
          type        TEXT NOT NULL,
          title       TEXT NOT NULL,
          date        TEXT NOT NULL,
          date_range  TEXT NOT NULL,
          range_start TEXT NOT NULL,
          range_end   TEXT NOT NULL,
          stats_json  TEXT,
          sources_json TEXT,
          body        TEXT NOT NULL,
          created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_briefings_type ON briefings(type)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_briefings_range_end ON briefings(range_end)');

      // ── telegram leak entries ──────────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS telegram_leak_entries (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          channel_handle TEXT NOT NULL,
          message_link  TEXT,
          message_text  TEXT,
          leak_type   TEXT NOT NULL DEFAULT 'unknown',
          credential_count INTEGER DEFAULT 0,
          file_url    TEXT,
          file_name   TEXT,
          domains_found TEXT DEFAULT '[]',
          severity    TEXT DEFAULT 'medium',
          discovered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
          raw_content TEXT
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_tle_channel ON telegram_leak_entries(channel_handle)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_tle_discovered ON telegram_leak_entries(discovered_at DESC)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_tle_severity ON telegram_leak_entries(severity)');

      // ── telegram watched channels ──────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS telegram_watched_channels (
          handle      TEXT PRIMARY KEY,
          title       TEXT,
          category    TEXT NOT NULL DEFAULT 'auto-discovered',
          discovered_from TEXT,
          added_by    TEXT NOT NULL DEFAULT 'auto',
          added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
          last_scraped TEXT,
          last_leak_found TEXT,
          message_count INTEGER DEFAULT 0,
          leak_count  INTEGER DEFAULT 0,
          active      INTEGER DEFAULT 1,
          tags        TEXT DEFAULT '[]'
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_twc_active ON telegram_watched_channels(active)');

      // ── telegram discovered channels ───────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS telegram_discovered_channels (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          handle      TEXT NOT NULL,
          source_message TEXT,
          discovered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
          reviewed    INTEGER DEFAULT 0,
          added_to_watch INTEGER DEFAULT 0,
          UNIQUE(handle, source_message)
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_tdc_reviewed ON telegram_discovered_channels(reviewed, discovered_at DESC)');

      // ── cyberpulse incidents ───────────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS cyberpulse_incidents (
          id              TEXT PRIMARY KEY,
          incident_type   TEXT NOT NULL,
          severity        TEXT NOT NULL DEFAULT 'medium',
          victim_name     TEXT,
          victim_domain   TEXT,
          victim_sector   TEXT,
          victim_country  TEXT,
          threat_actor    TEXT,
          threat_actor_aliases TEXT DEFAULT '[]',
          title           TEXT NOT NULL,
          description     TEXT,
          data_types_leaked TEXT DEFAULT '[]',
          records_count   INTEGER,
          data_volume     TEXT,
          source_platform TEXT NOT NULL,
          source_url      TEXT,
          source_handle   TEXT,
          source_text     TEXT,
          source_author   TEXT,
          source_avatar   TEXT,
          confidence      REAL DEFAULT 0.5,
          classification_method TEXT DEFAULT 'keyword',
          discovered_at   TEXT NOT NULL,
          reported_at     TEXT,
          updated_at      TEXT NOT NULL,
          dedup_hash      TEXT,
          duplicate_of    TEXT,
          tags            TEXT DEFAULT '[]',
          mitre_techniques TEXT DEFAULT '[]',
          source_likes    INTEGER DEFAULT 0,
          source_retweets INTEGER DEFAULT 0,
          source_replies  INTEGER DEFAULT 0,
          source_views    INTEGER DEFAULT 0
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_discovered ON cyberpulse_incidents(discovered_at DESC)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_severity ON cyberpulse_incidents(severity)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_type ON cyberpulse_incidents(incident_type)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_platform ON cyberpulse_incidents(source_platform)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_actor ON cyberpulse_incidents(threat_actor)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_victim ON cyberpulse_incidents(victim_name)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_sector ON cyberpulse_incidents(victim_sector)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_dedup ON cyberpulse_incidents(dedup_hash)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_country ON cyberpulse_incidents(victim_country)');

      // ── cyberpulse scan log ────────────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS cyberpulse_scan_log (
          id              INTEGER PRIMARY KEY AUTOINCREMENT,
          source          TEXT NOT NULL,
          handle          TEXT,
          query           TEXT,
          scanned_at      TEXT NOT NULL,
          items_found     INTEGER DEFAULT 0,
          incidents_created INTEGER DEFAULT 0,
          incidents_deduped INTEGER DEFAULT 0,
          duration_ms     INTEGER,
          error           TEXT
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_cp_scan_time ON cyberpulse_scan_log(scanned_at DESC)');

      // ── breach forum status ────────────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS breach_forum_status (
          name        TEXT NOT NULL,
          source      TEXT NOT NULL,
          status      TEXT NOT NULL,
          url         TEXT,
          onion       INTEGER NOT NULL DEFAULT 0,
          category    TEXT,
          observed_at TEXT NOT NULL
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_bfs_observed ON breach_forum_status(observed_at DESC)');
      sql.exec('CREATE INDEX IF NOT EXISTS idx_bfs_name_recent ON breach_forum_status(name, observed_at DESC)');

      // ── breach forum deltas ────────────────────────────────────────────
      sql.exec(`
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
          PRIMARY KEY (name, observed_at)
        )
      `);
      sql.exec('CREATE INDEX IF NOT EXISTS idx_bfd_observed ON breach_forum_deltas(observed_at DESC)');

      // ── tg saved searches ──────────────────────────────────────────────
      sql.exec(`
        CREATE TABLE IF NOT EXISTS tg_saved_searches (
          id          TEXT PRIMARY KEY,
          name        TEXT NOT NULL,
          query       TEXT NOT NULL,
          mode        TEXT NOT NULL DEFAULT 'boolean',
          filters     TEXT DEFAULT '{}',
          sort_order  TEXT DEFAULT 'newest',
          date_range  TEXT DEFAULT '',
          created_at  TEXT NOT NULL,
          updated_at  TEXT NOT NULL,
          owner_hash  TEXT
        )
      `);
    });
  }

  /**
   * Generic SQL execution — the single RPC method the adapter calls.
   *
   * Mirrors D1's prepare/bind/all contract: takes raw SQL + positional
   * params, returns rows + meta. `mode` selects the D1-equivalent:
   *   'all'   → returns { results, success, meta }  (like .all())
   *   'first' → returns the first row or null        (like .first())
   *   'run'   → returns { success, meta }            (like .run())
   */
  sql(query: string, params: unknown[], mode: 'all' | 'first' | 'run' = 'all'): unknown {
    const sql = this.ctx.storage.sql;
    // DO SQLite's exec is synchronous. Spread params into the variadic
    // signature; empty arrays are fine.
    const cursor = sql.exec(query, ...(params as never[]));

    if (mode === 'first') {
      // `cursor.one()` THROWS on an empty result set ("Expected exactly one
      // result from SQL query, but got no results") rather than returning null.
      // D1's `.first()` contract is `null`.
      //
      // This is normalised HERE, inside the DO, and not in the client adapter:
      // an exception raised inside a Durable Object crosses the RPC boundary as
      // an unhandled rejection that the caller cannot reliably contain, so it
      // surfaces as an uncaught error regardless of any `.catch()` on the
      // client. Every `SELECT ... LIMIT 1` against an empty table would trip it.
      try {
        return cursor.one() as Record<string, unknown> | null;
      } catch {
        return null;
      }
    }

    // meta mirrors D1's D1Result.meta: `rows_read` / `rows_written`, NOT
    // `changes` / `last_row_id`.
    //
    // The cursor previously reported `changes`/`lastRowId`, which do not exist
    // on SqlStorageCursor at all (it exposes rowsRead/rowsWritten) — so those
    // values were `undefined` at runtime, and every route or log line reading
    // `meta.rows_read` — which this codebase uses to bill and attribute query
    // cost — silently got undefined instead of a number.
    const meta = { rows_read: cursor.rowsRead, rows_written: cursor.rowsWritten };

    if (mode === 'run') {
      return { success: true, meta };
    }

    const results = cursor.toArray();
    return {
      results,
      success: true,
      meta,
    };
  }

  /**
   * Batch execution — mirrors D1's db.batch(). Runs each statement in
   * sequence inside a single implicit transaction (DO SQLite serializes
   * all execs anyway).
   */
  batch(statements: Array<{ query: string; params: unknown[]; mode: 'all' | 'first' | 'run' }>): unknown[] {
    return statements.map((s) => this.sql(s.query, s.params, s.mode));
  }
}
