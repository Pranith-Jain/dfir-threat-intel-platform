import type { D1Database } from '@cloudflare/workers-types';
import { logError } from './logger';

/**
 * 30-day data retention sweep. Removes rows older than the configured
 * retention window from time-series and user-data tables.
 *
 * Scope (per the data-minimization policy):
 *   - User-generated data (feedback, annotations, intel bundles) — 30d
 *   - Time-series telemetry (IOCs, WHOIS, CT, telegram leaks, API usage) — 30d
 *   - Briefings (daily/weekly/landscape reports) — 30d
 *
 * Exempt tables (deleting these would break the system or are non-temporal):
 *   - api_keys (auth tokens — deletion locks users out)
 *   - api_key_usage rows newer than 30d remain (per policy)
 *   - telegram_watched_channels, ct_watch (user watchlists, not time-series)
 *   - counters (no timestamp column)
 *
 * The sweep is idempotent and dry-run-able. Returns per-table counts so
 * the operator can see what was removed.
 */

export interface RetentionPolicy {
  /** Tables to sweep. Each entry names the table + the timestamp column
   *  used to determine age. ISO-8601 text columns only. */
  table: string;
  /** Column to compare against `now() - days`. ISO-8601 text or unix int. */
  column: string;
  /** Format of the column value: 'iso' (text, strftime-format) or 'unix' (integer seconds). */
  format: 'iso' | 'unix';
}

export const DEFAULT_RETENTION_DAYS = 30;

/**
 * Table and column names cannot be bound as SQL parameters, so they are
 * interpolated into the statement text. Every current policy entry is a
 * hardcoded literal, but `runRetentionSweep` also accepts a caller-supplied
 * `opts.policy` — without a check, any future caller that forwards untrusted
 * input would be a straight SQL injection into a DELETE.
 *
 * D1 table and column names in this schema are all plain snake_case ASCII
 * identifiers, so anything outside that shape is rejected outright rather than
 * escaped. This runs before the sweep, so a bad policy entry cannot reach the
 * database.
 */
const IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function isSafeIdentifier(name: string): boolean {
  return typeof name === 'string' && name.length <= 64 && IDENTIFIER_RE.test(name);
}

/** Validate one policy entry. Returns an error message, or null when usable. */
function validatePolicyEntry(p: RetentionPolicy): string | null {
  if (!isSafeIdentifier(p.table)) return `unsafe table identifier: ${JSON.stringify(p.table)}`;
  if (!isSafeIdentifier(p.column)) return `unsafe column identifier: ${JSON.stringify(p.column)}`;
  if (p.format !== 'iso' && p.format !== 'unix') return `unknown format: ${JSON.stringify(p.format)}`;
  return null;
}

/**
 * Default policy. Excludes auth/control-plane tables. Add to this list
 * when a new time-series table ships so the sweep picks it up.
 */
export const RETENTION_POLICY: RetentionPolicy[] = [
  // Product data
  { table: 'briefings', column: 'created_at', format: 'iso' },
  { table: 'briefing_feedback', column: 'created_at', format: 'iso' },
  { table: 'briefing_annotations', column: 'created_at', format: 'iso' },
  { table: 'intel_bundles', column: 'updated_at', format: 'iso' },

  // IOC + WHOIS telemetry
  { table: 'ioc_lifecycle', column: 'last_seen', format: 'iso' },
  { table: 'whois_snapshots', column: 'first_seen', format: 'iso' },
  { table: 'whois_changes', column: 'first_seen', format: 'iso' },
  { table: 'domain_registrant_index', column: 'first_seen', format: 'iso' },
  { table: 'domain_nameserver_index', column: 'first_seen', format: 'iso' },

  // Telegram leak monitor
  { table: 'telegram_discovered_channels', column: 'discovered_at', format: 'iso' },
  { table: 'telegram_leak_entries', column: 'discovered_at', format: 'iso' },

  // Breach-forum status snapshots (hourly cron appends ~670 rows/hour;
  // without a sweep this table alone would pin the 500 MB free-tier cap).
  { table: 'breach_forum_status', column: 'observed_at', format: 'iso' },

  // CT monitor
  { table: 'ct_certs', column: 'first_seen', format: 'iso' },

  // API usage (last_request_at is ISO-8601 text per migration 0013)
  { table: 'api_key_usage', column: 'last_request_at', format: 'iso' },

  // CTI Collector (VHunt-inspired) — 30-day IOC, news, predictions, mutations
  { table: 'cti_iocs', column: 'last_seen', format: 'iso' },
  { table: 'cti_news', column: 'fetched_at', format: 'iso' },
  { table: 'cti_predictions', column: 'generated_at', format: 'iso' },
  { table: 'cti_mutation_variants', column: 'created_at', format: 'iso' },
  { table: 'cti_mutation_seeds', column: 'created_at', format: 'iso' },
  { table: 'cti_collection_jobs', column: 'started_at', format: 'iso' },

  // CyberPulse — scan_log was missing from retention (grew forever at
  // 4 rows/run × 72 runs/day). 7-day window keeps ops visibility without
  // unbounded growth; incidents keep the standard 30d.
  { table: 'cyberpulse_scan_log', column: 'scanned_at', format: 'iso' },
  { table: 'cyberpulse_incidents', column: 'discovered_at', format: 'iso' },

  // ── Previously unbounded (added 2026-10-07) ────────────────────────────
  //
  // These seven tables were never added to the policy, so they grew without
  // limit. That matters because unbounded growth turns every full scan into an
  // ever-larger rows_read charge: the threat graph alone is read by
  // `live-iocs.ts` via `json_extract(sources,...) LIKE 'feed:%' ORDER BY
  // last_seen DESC`, which is a full scan with no usable index.
  //
  // ORDER MATTERS: edges before nodes. graph_edges has no FOREIGN KEY to
  // graph_nodes, so nothing cascades — sweeping nodes first would leave the
  // edges pointing at them behind as orphans that no traversal can ever join
  // (threat-graph inner-joins the two), so the rows would occupy storage and
  // skew counts forever while returning nothing. Sweeping the child table first
  // keeps the pair consistent: anything past the cutoff loses its edges and its
  // nodes in the same pass.
  //
  // `graph_nodes` / `graph_edges` use `first_seen`, not `last_seen`, on purpose.
  // Sweeping on `last_seen` would keep any node that is ever re-observed
  // forever, which is unbounded by construction. `first_seen` bounds the table;
  // a genuinely still-active node re-ingests on the next graph run.
  { table: 'graph_edges', column: 'first_seen', format: 'iso' },
  { table: 'graph_nodes', column: 'first_seen', format: 'iso' },

  // Alert feed with no sweep at all; `ssvc-triage` and `estate` read it by
  // `dismissed` / `read` / `source_url`, none of which are indexed.
  { table: 'alert_feeds', column: 'created_at', format: 'iso' },

  // Telemetry tables with no sweep; `passive-dns` groups them by the
  // unindexed `source` column.
  { table: 'passive_dns_observations', column: 'created_at', format: 'iso' },

  // Grows one row per extracted IOC, unbounded. `valid_until` is the
  // semantically interesting column but is nullable and frequently NULL, so
  // sweeping on it would never remove anything; `created_at` is the insert
  // time and bounds the table.
  { table: 'actionable_iocs', column: 'created_at', format: 'iso' },

  // Synced article tables. Both already carry idx_*_published, so these
  // DELETEs are index-backed rather than scans.
  { table: 'articles', column: 'published_date', format: 'iso' },
  { table: 'supply_chain_incidents', column: 'published_date', format: 'iso' },
];

export interface RetentionResult {
  days: number;
  dry_run: boolean;
  cutoff_iso: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  tables: Array<{
    table: string;
    column: string;
    deleted: number;
    error?: string;
  }>;
  total_deleted: number;
  tables_swept: number;
}

function cutoffIso(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

function cutoffUnix(days: number): number {
  return Math.floor(Date.now() / 1000) - days * 86_400;
}

/**
 * Run the retention sweep. Safe to call from any cron or admin endpoint.
 * If `dry_run` is true, counts rows that *would* be deleted but issues
 * a SELECT instead of a DELETE so the operator can preview impact.
 */
export async function runRetentionSweep(
  db: D1Database,
  opts: { days?: number; dry_run?: boolean; policy?: RetentionPolicy[] } = {}
): Promise<RetentionResult> {
  const days = opts.days ?? DEFAULT_RETENTION_DAYS;
  const dryRun = opts.dry_run ?? false;
  const policy = opts.policy ?? RETENTION_POLICY;
  const startedAt = new Date();
  const cutoff = cutoffIso(days);

  const tables: RetentionResult['tables'] = [];
  let total = 0;

  for (const p of policy) {
    // Reject before interpolating `p.table` / `p.column` into the statement.
    // Counts as a swept table so the caller still sees the entry in its result.
    const invalid = validatePolicyEntry(p);
    if (invalid) {
      tables.push({ table: String(p.table), column: String(p.column), deleted: 0, error: invalid });
      logError(`retention skipped ${String(p.table)}`, new Error(invalid));
      continue;
    }
    try {
      if (dryRun) {
        const countRow = await db
          .prepare(`SELECT COUNT(*) AS n FROM ${p.table} WHERE ${p.column} < ?`)
          .bind(p.format === 'iso' ? cutoff : cutoffUnix(days))
          .first<{ n: number }>();
        tables.push({ table: p.table, column: p.column, deleted: countRow?.n ?? 0 });
        continue;
      }

      // No pre-COUNT on the live path: one DELETE round-trip, deleted count
      // from meta.changes. The old COUNT+DELETE doubled reads on large
      // tables (22 tables × full scan) with zero deletes most days.
      const res = await db
        .prepare(`DELETE FROM ${p.table} WHERE ${p.column} < ?`)
        .bind(p.format === 'iso' ? cutoff : cutoffUnix(days))
        .run();
      const deleted = res.meta?.changes ?? 0;
      tables.push({ table: p.table, column: p.column, deleted });
      total += deleted;
      // Log a single line per non-empty table for ops visibility
      if (deleted > 0) {
      }
    } catch (err) {
      tables.push({
        table: p.table,
        column: p.column,
        deleted: 0,
        error: err instanceof Error ? err.message : String(err),
      });
      logError(`retention ${p.table} failed`, err);
    }
  }

  return {
    days,
    dry_run: dryRun,
    cutoff_iso: cutoff,
    started_at: startedAt.toISOString(),
    finished_at: new Date().toISOString(),
    duration_ms: Date.now() - startedAt.getTime(),
    tables,
    total_deleted: total,
    tables_swept: tables.filter((t) => t.deleted > 0).length,
  };
}
