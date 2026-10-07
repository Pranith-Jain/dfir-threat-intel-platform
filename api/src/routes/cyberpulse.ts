/**
 * CyberPulse — API routes for breach/leak incident data.
 *
 * GET /api/v1/cyberpulse/incidents    — list incidents with filters
 * GET /api/v1/cyberpulse/stats        — aggregate statistics
 * GET /api/v1/cyberpulse/trending     — trending actors/victims
 * GET /api/v1/cyberpulse/scan-log     — ingestion health
 * GET /api/v1/cyberpulse/ingest       — trigger manual ingestion (admin only)
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, serviceUnavailable } from '../lib/api-error';
import { requireAdmin } from '../lib/admin-auth';
import { runCyberPulseIngestion } from './cyberpulse-ingest';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

// ─── GET /api/v1/cyberpulse/incidents ──────────────────────────────────────

export async function cyberpulseIncidentsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const env = c.env as unknown as Record<string, unknown>;
  const db = env.BRIEFINGS_DB as import('@cloudflare/workers-types').D1Database | undefined;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const url = new URL(c.req.url);
  const type = url.searchParams.get('type');
  const severity = url.searchParams.get('severity');
  const platform = url.searchParams.get('platform');
  const sector = url.searchParams.get('sector');
  const actor = url.searchParams.get('actor');
  const victim = url.searchParams.get('victim');
  const country = url.searchParams.get('country');
  const search = url.searchParams.get('q');
  const daysBack = Math.min(90, Math.max(1, Number(url.searchParams.get('days') ?? '7')));
  const limit = Math.min(MAX_LIMIT, Math.max(1, Number(url.searchParams.get('limit') ?? String(DEFAULT_LIMIT))));
  const offset = Math.max(0, Number(url.searchParams.get('offset') ?? '0'));

  const conditions: string[] = [];
  const binds: unknown[] = [];

  const cutoff = new Date(Date.now() - daysBack * 86_400_000).toISOString();
  conditions.push('discovered_at > ?');
  binds.push(cutoff);

  if (type) {
    conditions.push('incident_type = ?');
    binds.push(type);
  }
  if (severity) {
    conditions.push('severity = ?');
    binds.push(severity);
  }
  if (platform) {
    conditions.push('source_platform = ?');
    binds.push(platform);
  }
  if (sector) {
    conditions.push('victim_sector = ?');
    binds.push(sector);
  }
  if (actor) {
    conditions.push('LOWER(threat_actor) LIKE ?');
    binds.push(`%${actor.toLowerCase()}%`);
  }
  if (victim) {
    conditions.push('LOWER(victim_name) LIKE ?');
    binds.push(`%${victim.toLowerCase()}%`);
  }
  if (country) {
    conditions.push('victim_country = ?');
    binds.push(country.toUpperCase());
  }
  if (search) {
    conditions.push('(LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(victim_name) LIKE ?)');
    const needle = `%${search.toLowerCase()}%`;
    binds.push(needle, needle, needle);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await db
    .prepare(`SELECT COUNT(*) as total FROM cyberpulse_incidents ${where}`)
    .bind(...binds)
    .first<{ total: number }>();
  const total = countResult?.total ?? 0;

  const { results } = await db
    .prepare(
      `SELECT id, incident_type, severity, victim_name, victim_domain, victim_sector, victim_country, threat_actor, threat_actor_aliases, title, description, data_types_leaked, records_count, data_volume, source_platform, source_url, source_handle, source_text, source_author, source_avatar, confidence, classification_method, discovered_at, reported_at, updated_at, dedup_hash, duplicate_of, tags, mitre_techniques, source_likes, source_retweets, source_replies, source_views FROM cyberpulse_incidents ${where} ORDER BY discovered_at DESC LIMIT ? OFFSET ?`
    )
    .bind(...binds, limit, offset)
    .all();

  return c.json({
    total,
    limit,
    offset,
    has_more: offset + limit < total,
    incidents: results,
  });
}

// ─── GET /api/v1/cyberpulse/stats ──────────────────────────────────────────

/** Row shape of the combined low-cardinality rollup below. */
export type RollupRow = {
  incident_type: string | null;
  severity: string | null;
  source_platform: string | null;
  victim_sector: string | null;
  n: number;
};

/**
 * Dimensions folded into the tuple rollup.
 *
 * Every one of these is constrained at the schema level to a fixed enum, which
 * is what makes the fold safe: incident_type (CHECK), severity (CHECK, 4
 * values), source_platform (CHECK), victim_sector (CHECK, ~14 values). The
 * product bounds the result to a few thousand groups regardless of how many
 * incident rows fall in the window.
 *
 * victim_country is DELIBERATELY NOT HERE. It is plain `TEXT` with no CHECK
 * constraint, so its cardinality is whatever upstream feeds happen to emit.
 * Folding an unbounded dimension into the tuple means the group count is capped
 * only by the row count — in the degenerate case where tuples are mostly
 * distinct the "rollup" returns ~one row per incident, which is no cheaper than
 * the scan it replaced and adds a large result-set transfer on top. It gets its
 * own aggregate instead, so its cost stays independent of the other four.
 */
const ROLLUP_DIMS = ['incident_type', 'severity', 'source_platform', 'victim_sector'] as const;

/**
 * Derive per-dimension marginals from a tuple-grouped rollup.
 *
 * This handler previously issued NINE independent aggregates over the same
 * trailing window. Each one independently re-walked idx_cp_discovered AND
 * re-fetched the table row for its grouping column (that column is not in the
 * index), so every aggregate cost roughly rows-in-window x 2 in rows_read. With
 * a 36,170-row table and a 30-day default window that is ~650k rows_read for a
 * single request against a 5M/day free-tier budget — one dashboard refresh
 * could spend an eighth of the day's allowance.
 *
 * The four bounded dimensions collapse into ONE tuple GROUP BY. The exact
 * marginals are then recoverable in JS by summing `n` across groups that share
 * a key — the same numbers the original queries returned, from one scan instead
 * of five.
 *
 * NULL keys are skipped, preserving the original `victim_sector IS NOT NULL`
 * filter. Note the other three columns are NOT NULL at the schema level, so
 * skipping NULLs cannot drop a bucket that the old query would have returned.
 */
export function buildMarginals(rows: RollupRow[]): Record<(typeof ROLLUP_DIMS)[number], unknown[]> {
  const out = {} as Record<(typeof ROLLUP_DIMS)[number], unknown[]>;
  for (const dim of ROLLUP_DIMS) {
    const counts = new Map<string, number>();
    for (const row of rows) {
      const key = row[dim];
      if (key === null || key === undefined) continue;
      counts.set(key, (counts.get(key) ?? 0) + row.n);
    }
    // Deterministic ordering: count descending, then key ascending.
    //
    // The original SQL was `ORDER BY count DESC` with no tiebreaker, so equal
    // counts came back in whatever order the scan produced — which meant the
    // dashboard's "top N" lists could reshuffle between otherwise identical
    // requests. Sorting on the key as a secondary criterion makes the response
    // stable, which also makes it assertable in tests.
    out[dim] = [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([k, count]) => ({ [dim]: k, count }));
  }
  return out;
}

export async function cyberpulseStatsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const env = c.env as unknown as Record<string, unknown>;
  const db = env.BRIEFINGS_DB as import('@cloudflare/workers-types').D1Database | undefined;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const url = new URL(c.req.url);
  const daysBack = Math.min(90, Math.max(1, Number(url.searchParams.get('days') ?? '30')));
  const cutoff = new Date(Date.now() - daysBack * 86_400_000).toISOString();

  // 9 scans -> 5. The rollup replaces total / by_type / by_severity /
  // by_platform / by_sector (5 scans) with a single pass. by_country stays
  // separate (unconstrained cardinality — see ROLLUP_DIMS), as do top_actors,
  // top_victims and daily_trend, whose grouping keys are all unbounded.
  // victim_country is the explicit secondary sort key in the by_country query so
  // equal counts order stably, matching the tiebreaker buildMarginals applies
  // to the rollup dimensions.
  const [rollup, byCountry, dailyTrend, topActors, topVictims] = await Promise.all([
    db
      .prepare(
        `SELECT incident_type, severity, source_platform, victim_sector, COUNT(*) AS n
       FROM cyberpulse_incidents WHERE discovered_at > ?
       GROUP BY incident_type, severity, source_platform, victim_sector`
      )
      .bind(cutoff)
      .all<RollupRow>(),
    db
      .prepare(
        'SELECT victim_country, COUNT(*) as count FROM cyberpulse_incidents WHERE discovered_at > ? AND victim_country IS NOT NULL GROUP BY victim_country ORDER BY count DESC, victim_country ASC'
      )
      .bind(cutoff)
      .all(),
    db
      .prepare(
        `SELECT DATE(discovered_at) as day, COUNT(*) as count
      FROM cyberpulse_incidents WHERE discovered_at > ?
      GROUP BY DATE(discovered_at) ORDER BY day`
      )
      .bind(cutoff)
      .all(),
    db
      .prepare(
        `SELECT threat_actor, COUNT(*) as count
      FROM cyberpulse_incidents WHERE discovered_at > ? AND threat_actor IS NOT NULL
      GROUP BY threat_actor ORDER BY count DESC LIMIT 10`
      )
      .bind(cutoff)
      .all(),
    db
      .prepare(
        `SELECT victim_name, COUNT(*) as count
      FROM cyberpulse_incidents WHERE discovered_at > ? AND victim_name IS NOT NULL
      GROUP BY victim_name ORDER BY count DESC LIMIT 10`
      )
      .bind(cutoff)
      .all(),
  ]);

  const rollupRows = rollup.results;
  const total = rollupRows.reduce((sum, r) => sum + r.n, 0);
  const marginals = buildMarginals(rollupRows);

  // Get last scan timestamp for freshness indicator
  const lastScan = await db
    .prepare('SELECT scanned_at FROM cyberpulse_scan_log ORDER BY scanned_at DESC LIMIT 1')
    .first<{ scanned_at: string }>();

  return c.json({
    period_days: daysBack,
    total,
    by_type: marginals.incident_type,
    by_severity: marginals.severity,
    by_platform: marginals.source_platform,
    by_sector: marginals.victim_sector,
    by_country: byCountry.results,
    daily_trend: dailyTrend.results,
    top_actors: topActors.results,
    top_victims: topVictims.results,
    last_scan: lastScan?.scanned_at ?? null,
  });
}

// ─── GET /api/v1/cyberpulse/trending ───────────────────────────────────────

export async function cyberpulseTrendingHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const env = c.env as unknown as Record<string, unknown>;
  const db = env.BRIEFINGS_DB as import('@cloudflare/workers-types').D1Database | undefined;
  if (!db) return serviceUnavailable(c, 'database not configured');

  // Trending = actors/victims with the most incidents in the last 7 days
  // that weren't present (or had fewer) in the prior 7 days
  const weekAgo = new Date(Date.now() - 7 * 86_400_000).toISOString();
  const twoWeeksAgo = new Date(Date.now() - 14 * 86_400_000).toISOString();

  const [thisWeekActors, lastWeekActors, thisWeekVictims, lastWeekVictims] = await Promise.all([
    db
      .prepare(
        'SELECT threat_actor, COUNT(*) as count FROM cyberpulse_incidents WHERE discovered_at > ? AND threat_actor IS NOT NULL GROUP BY threat_actor'
      )
      .bind(weekAgo)
      .all(),
    db
      .prepare(
        'SELECT threat_actor, COUNT(*) as count FROM cyberpulse_incidents WHERE discovered_at > ? AND discovered_at <= ? AND threat_actor IS NOT NULL GROUP BY threat_actor'
      )
      .bind(twoWeeksAgo, weekAgo)
      .all(),
    db
      .prepare(
        'SELECT victim_name, COUNT(*) as count FROM cyberpulse_incidents WHERE discovered_at > ? AND victim_name IS NOT NULL GROUP BY victim_name'
      )
      .bind(weekAgo)
      .all(),
    db
      .prepare(
        'SELECT victim_name, COUNT(*) as count FROM cyberpulse_incidents WHERE discovered_at > ? AND discovered_at <= ? AND victim_name IS NOT NULL GROUP BY victim_name'
      )
      .bind(twoWeeksAgo, weekAgo)
      .all(),
  ]);

  const lastActorMap = new Map(
    (lastWeekActors.results as { threat_actor: string; count: number }[]).map((r) => [r.threat_actor, r.count])
  );
  const lastVictimMap = new Map(
    (lastWeekVictims.results as { victim_name: string; count: number }[]).map((r) => [r.victim_name, r.count])
  );

  const trendingActors = (thisWeekActors.results as { threat_actor: string; count: number }[])
    .map((r) => ({
      name: r.threat_actor,
      this_week: r.count,
      last_week: lastActorMap.get(r.threat_actor) ?? 0,
      delta: r.count - (lastActorMap.get(r.threat_actor) ?? 0),
    }))
    .filter((r) => r.delta > 0 || r.this_week >= 3)
    .sort((a, b) => b.delta - a.delta || b.this_week - a.this_week)
    .slice(0, 10);

  const trendingVictims = (thisWeekVictims.results as { victim_name: string; count: number }[])
    .map((r) => ({
      name: r.victim_name,
      this_week: r.count,
      last_week: lastVictimMap.get(r.victim_name) ?? 0,
      delta: r.count - (lastVictimMap.get(r.victim_name) ?? 0),
    }))
    .filter((r) => r.delta > 0)
    .sort((a, b) => b.delta - a.delta)
    .slice(0, 10);

  return c.json({ trending_actors: trendingActors, trending_victims: trendingVictims });
}

// ─── GET /api/v1/cyberpulse/scan-log ───────────────────────────────────────

export async function cyberpulseScanLogHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const env = c.env as unknown as Record<string, unknown>;
  const db = env.BRIEFINGS_DB as import('@cloudflare/workers-types').D1Database | undefined;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const limit = Math.min(100, Math.max(1, Number(new URL(c.req.url).searchParams.get('limit') ?? '20')));

  const { results } = await db
    .prepare(
      'SELECT id, source, handle, query, scanned_at, items_found, incidents_created, incidents_deduped, duration_ms, error FROM cyberpulse_scan_log ORDER BY scanned_at DESC LIMIT ?'
    )
    .bind(limit)
    .all();

  return c.json({ scans: results });
}

// ─── GET /api/v1/cyberpulse/ingest ─────────────────────────────────────────

export async function cyberpulseIngestHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const adminCheck = requireAdmin(c);
  if ('error' in adminCheck) return adminCheck.error;

  const db = (c.env as unknown as Record<string, unknown>).BRIEFINGS_DB as
    import('@cloudflare/workers-types').D1Database | undefined;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const start = Date.now();
  try {
    const results = await runCyberPulseIngestion(c.env, db);
    return c.json({
      ok: true,
      duration_ms: Date.now() - start,
      results,
    });
  } catch (e) {
    logError('cyberpulseIngestHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
}

// ─── POST /api/v1/cyberpulse/scan ──────────────────────────────────────────
// Public endpoint (no admin auth) with per-IP rate limiting.
// Allows users to trigger a scan from the UI without needing admin credentials.

const scanRateLimits = new Map<string, number>();
const SCAN_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes
/**
 * Upper bound on the cooldown map.
 *
 * This is a module-scope Map, so it is per-isolate and its lifetime is an
 * isolate's lifetime. Without a cap, every distinct source IP that reaches the
 * handler adds a permanent entry — an unauthenticated endpoint could be used to
 * grow isolate memory without bound. Entries older than the cooldown are dead
 * weight (the cooldown has expired), so a periodic sweep is lossless.
 */
const SCAN_LIMIT_SWEEP_MS = 60 * 1000;
const SCAN_LIMIT_MAX_ENTRIES = 10_000;
let lastScanSweep = 0;

function sweepScanCooldowns(now: number): void {
  if (now - lastScanSweep < SCAN_LIMIT_SWEEP_MS && scanRateLimits.size <= SCAN_LIMIT_MAX_ENTRIES) return;
  lastScanSweep = now;
  for (const [ip, ts] of scanRateLimits) {
    if (now - ts >= SCAN_COOLDOWN_MS) scanRateLimits.delete(ip);
  }
  // If a flood of fresh IPs still exceeds the cap, drop the oldest entries so
  // the map cannot outgrow its bound between sweeps.
  while (scanRateLimits.size > SCAN_LIMIT_MAX_ENTRIES) {
    const oldest = scanRateLimits.keys().next();
    if (oldest.done) break;
    scanRateLimits.delete(oldest.value);
  }
}

export async function cyberpulseScanHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
  const now = Date.now();
  sweepScanCooldowns(now);
  const lastScan = scanRateLimits.get(ip) ?? 0;

  if (now - lastScan < SCAN_COOLDOWN_MS) {
    const waitSeconds = Math.ceil((SCAN_COOLDOWN_MS - (now - lastScan)) / 1000);
    return c.json(
      { error: 'rate_limited', message: `Scan available in ${waitSeconds}s`, retry_after: waitSeconds },
      429
    );
  }

  const db = (c.env as unknown as Record<string, unknown>).BRIEFINGS_DB as
    import('@cloudflare/workers-types').D1Database | undefined;
  if (!db) return serviceUnavailable(c, 'database not configured');

  scanRateLimits.set(ip, now);

  const start = Date.now();
  try {
    const results = await runCyberPulseIngestion(c.env, db);
    const totalCreated = results.reduce((s, r) => s + r.incidents_created, 0);
    const totalDeduped = results.reduce((s, r) => s + r.incidents_deduped, 0);
    return c.json({
      ok: true,
      duration_ms: Date.now() - start,
      incidents_created: totalCreated,
      incidents_deduped: totalDeduped,
      sources: results.map((r) => ({
        source: r.source,
        items_scanned: r.items_scanned,
        created: r.incidents_created,
        deduped: r.incidents_deduped,
        errors: r.errors.length,
        duration_ms: r.duration_ms,
      })),
    });
  } catch (e) {
    logError('cyberpulseScanHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
}
