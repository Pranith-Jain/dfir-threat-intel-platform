/**
 * Breach-forum status deltas — the "did any tracked forum's status just
 * change?" route. Backs a "Recent Status Changes" section on the
 * BreachForums page so analysts see the active→seized / online→offline
 * transitions the cron has logged over the trailing window.
 *
 * Route: GET /api/v1/breach-forum-status/deltas?since=ISO&limit=N
 *   - `since` is an ISO 8601 timestamp; defaults to 7 days back
 *   - `limit` caps result size; defaults to 100, hard-max 500
 *
 * Cached at the edge for 10 minutes. Status changes are slow (a forum
 * doesn't flap hourly), so 10 min is fresh enough and cuts upstream
 * load by ~80% in steady state.
 *
 * Hard guardrail: this route serves the META — when a forum's status
 * changed, what it changed from/to, and when. It never serves forum
 * content.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, serviceUnavailable } from '../lib/api-error';
import { trackEvent, visitorCountry } from '../lib/analytics';
import { readRecentDeltas, type StatusDelta } from '../lib/breach-forum-status';
import { safeNullLog } from '../lib/safe-catch';

const CACHE_TTL_SECONDS = 600;
const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 100;
const DEFAULT_SINCE_DAYS = 7;
/**
 * Hard floor on the requested window.
 *
 * `since` is caller-controlled, and the deltas query is a window-function CTE
 * (two LAG() + one ROW_NUMBER() over PARTITION BY name) that must read every
 * row in the window before it can rank anything. Left unbounded, a single
 * `?since=1970-01-01T00:00:00Z` widens that to the entire snapshot table.
 *
 * 14 days, not the table's full 30-day retention window.
 *
 * The clamp bounds TWO scans, not one. The window query is now an indexed read
 * of the persisted deltas (migration 0052), but `total_rows` in the same
 * response still counts raw snapshot rows across the window, and that count is
 * proportional to the window: at 30 days it walks ~450k rows (~90k for the
 * 7-day default). Callers only ever pass the default or a slightly wider
 * window in practice, so a 14-day ceiling costs no real fidelity while cutting
 * the worst case by more than half.
 */
const MAX_SINCE_DAYS = 14;

function parseSince(s: string | undefined): string | null {
  if (!s) return null;
  // Accept any ISO 8601 the JS Date parser can handle. The route uses
  // the result as a D1 bind value, so anything Date.parse() doesn't
  // accept is rejected here (D1 would throw an opaque error otherwise).
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

function parseLimit(s: string | undefined): number {
  if (!s) return DEFAULT_LIMIT;
  const n = Number(s);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_LIMIT);
}

export interface BreachForumStatusResponse {
  generated_at: string;
  since: string;
  limit: number;
  deltas: StatusDelta[];
  /**
   * Number of snapshot rows within the response window (bounded health check).
   * Window-scoped rather than lifetime — see the COUNT(*) comment in the
   * handler for why the table-wide variant was removed.
   */
  total_rows: number;
}

export async function breachForumStatusHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const sinceParam = parseSince(c.req.query('since') ?? undefined);
  if (c.req.query('since') && sinceParam === null) {
    return badRequest(c, 'since must be a valid ISO 8601 timestamp');
  }
  const requestedSince = sinceParam ?? new Date(Date.now() - DEFAULT_SINCE_DAYS * 24 * 60 * 60 * 1000).toISOString();
  // Clamp the window: see MAX_SINCE_DAYS. String compare is safe because both
  // sides are `toISOString()` output, so lexicographic order == chronological.
  const sinceFloor = new Date(Date.now() - MAX_SINCE_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const since = requestedSince < sinceFloor ? sinceFloor : requestedSince;
  const limit = parseLimit(c.req.query('limit') ?? undefined);

  // Edge cache keyed by since + limit. The body is the same for the same
  // window — a small overlap with the previous response is acceptable
  // and cheaper than a precise nanosecond key.
  const cacheKey = new Request(
    `https://breach-forum-status.internal/v1?since=${encodeURIComponent(since)}&limit=${limit}`
  );
  try {
    const hit = await caches.default.match(cacheKey);
    if (hit) return new Response(hit.body, hit);
  } catch (_catchErr) {
    logError('breachForumStatusHandler failed', _catchErr);
    /* cache miss is fine */
  }

  const db = c.env.BRIEFINGS_DB;
  if (!db) {
    return serviceUnavailable(c, 'database not configured');
  }

  const [deltas, totalRow] = await Promise.all([
    readRecentDeltas(db, { since, limit }),
    safeNullLog(
      'd1-count-breach-forum',
      // Counts SNAPSHOTS in the window, from breach_forum_snapshots.
      //
      // This has been rewritten twice, each time because the previous form was
      // the account's largest read consumer:
      //
      //   v1 `SELECT COUNT(*) FROM breach_forum_status` — no WHERE, so a full
      //      scan of a table holding up to ~10^6 snapshot rows (~631k rows_read
      //      per execution) to populate one cosmetic field.
      //   v2 `... WHERE observed_at >= ?` — bounded by the window, but still
      //      counted FORUM ROWS, and the table holds all 1,494 forums x every
      //      snapshot in the window. At ~15 snapshots/day that is ~22k rows to
      //      read per call, still ~854k/day.
      //   v3 (now) count one row per snapshot instead. The snapshot count is
      //      the same health signal — arguably a better one, since it measures
      //      observation cadence rather than being multiplied by forum count —
      //      and reads ~15-160 rows instead of ~22,000.
      //
      // Falls back to the historical table if the snapshot log is not present
      // (pre-0054), so a partial rollout degrades instead of erroring.
      db
        .prepare(
          `SELECT
             (SELECT COUNT(*) FROM breach_forum_snapshots WHERE observed_at >= ?) AS n,
             (SELECT COUNT(*) FROM breach_forum_status WHERE observed_at >= ?) AS legacy_n`
        )
        .bind(since, since)
        .first<{ n: number; legacy_n: number }>()
        .then((r) => ({ n: r?.n || r?.legacy_n || 0 }))
    ),
  ]);

  const body: BreachForumStatusResponse = {
    generated_at: new Date().toISOString(),
    since,
    limit,
    deltas,
    total_rows: totalRow?.n ?? 0,
  };

  c.executionCtx.waitUntil(
    (async () => {
      try {
        await caches.default.put(
          cacheKey,
          new Response(JSON.stringify(body), {
            status: 200,
            headers: {
              'content-type': 'application/json',
              'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
            },
          })
        );
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* cache writes are non-fatal */
      }
      try {
        trackEvent(c.env, 'breach_forum_status_fetch', {
          indexes: [visitorCountry(c.req.raw)],
        });
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* telemetry is best-effort */
      }
    })()
  );

  return c.json(body, 200, { 'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}` });
}
