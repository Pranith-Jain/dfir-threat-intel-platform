import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { serviceUnavailable } from '../lib/api-error';
import type { D1Database } from '@cloudflare/workers-types';
import { fetchIocCorrelation } from './ioc-correlation';
import { fetchLiveIocs, type LiveIocsResponse, type LiveIoc, type LiveSource } from './live-iocs';
import { safeNullLog, kvBulkGetText } from '../lib/safe-catch';
import { scoreAllFeeds, type FeedContribution, type TifceHistoryRow, type TifceResult } from '../lib/tifce';
import { trackEvent, visitorCountry } from '../lib/analytics';

/**
 * TIFCE — TI Feed Content Evaluation route.
 *
 * Re-implements the four-pillar TIFCE framework
 * (https://zenodo.org/records/18208974) as a TypeScript pipeline on top of
 * the platform's existing IOC infrastructure. Reference impl is a Microsoft
 * Sentinel KQL workbook — see api/src/lib/tifce.ts for the full scoping
 * note on how the platform substitutes tenant telemetry for in-platform
 * signals.
 *
 * Pipeline:
 *   1. fetchIocCorrelation() — the 2+-feed cross-feed index
 *   2. fetchLiveIocs()       — per-feed items + per-source newest_observation
 *   3. D1 ioc_lifecycle      — peak_score > 0 rows = TP-proxy indicator set
 *   4. D1 tifce_scores       — trailing 7d history per feed (for Pillar 4
 *                              velocity)
 *   5. scoreAllFeeds()       — pure four-pillar + composite scoring
 *   6. Persist current build to tifce_scores so next build has history
 *
 * Cached at the edge for 1h — feed content moves slowly enough that
 * per-hour quality evaluation is the right cadence, and the per-feed
 * count tables are pulled in already-cached form by fetchIocCorrelation
 * (1h) and fetchLiveIocs (30m), so re-evaluating more often wouldn't
 * move the numbers.
 *
 * GET /api/v1/feed-quality
 */
export const FEED_QUALITY_CACHE_KEY = 'https://feed-quality-cache.internal/v1';
const CACHE_KEY = FEED_QUALITY_CACHE_KEY;
const CACHE_TTL_SECONDS = 60 * 60;
const HISTORY_WINDOW_DAYS = 7;
const MAX_FEEDS_IN_RESPONSE = 200;
/** Statements per D1 call. Bounds the atomicity blast radius, not a quota. */
const MAX_TIFCE_BATCH = 50;

export async function feedQualityHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(CACHE_KEY);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  const db = c.env.BRIEFINGS_DB;
  if (!db) {
    return serviceUnavailable(c, 'database not configured');
  }

  // Best-effort fan-in. fetchIocCorrelation and fetchLiveIocs each have
  // their own short-circuits on missing upstreams; a failure in either
  // degrades the relevant pillar (env-relevance / freshness) but does not
  // crash the whole route.
  const [correlation, live] = await Promise.all([
    safeNullLog('fetch-ioc-correlation', fetchIocCorrelation(c.env)),
    safeNullLog('fetch-live-iocs', fetchLiveIocs(c.executionCtx, c.env.KV_CACHE, c.env)),
  ]);

  if (!live) {
    return serviceUnavailable(c, 'live-IOC stream unavailable; cannot evaluate feed quality');
  }

  const tpSet = await loadTpIndicatorSet(db);
  const platformSet = await loadPlatformReportedSet(db);
  const detectionSet = await loadDetectionFiredSet(c.env);
  const history = await loadHistory(db);

  const feedContribs = toFeedContributions(live);
  // The cross-feed index is rebuilt inside scoreAllFeeds from inputs.feeds
  // so we don't need a second derivation here.

  const result = scoreAllFeeds({
    feeds: feedContribs,
    tpIndicatorSet: tpSet,
    platformReportedSet: platformSet,
    detectionFiredSet: detectionSet,
    history,
  });

  // Best-effort persist of the current build. Failures are logged but
  // don't break the response — the read path tolerates a missing row.
  const persist = persistCurrentBuild(db, result).catch((err) => {
    logError('tifce: failed to persist current build', err);
  });
  c.executionCtx.waitUntil(persist);

  // Track visit. Non-blocking.
  trackEvent(c.env, 'api_call', {
    blobs: ['/api/v1/feed-quality'],
    indexes: [visitorCountry(c.req.raw)],
  });

  const response = c.json(
    {
      ...result,
      _meta: {
        feeds_in_response: Math.min(result.feeds.length, MAX_FEEDS_IN_RESPONSE),
        correlation_ok: !!correlation,
        live_ok: !!live,
        tp_indicators_loaded: tpSet.size,
        platform_indicators_loaded: platformSet.size,
        detection_indicators_loaded: detectionSet.size,
        history_window_days: HISTORY_WINDOW_DAYS,
        cache_ttl_seconds: CACHE_TTL_SECONDS,
      },
    },
    200,
    { 'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}` }
  );
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}

// ────────────────────────────────────────────────────────────────────────
// D1 loaders
// ────────────────────────────────────────────────────────────────────────

/**
 * Create the tifce_scores table if it doesn't exist. Idempotent — the
 * primary route uses migration 0015_tifce_scores.sql, but this is a
 * belt-and-suspenders guard for local dev where the migration may not
 * have been applied yet. Same pattern as ioc-lifecycle.ts:73-98.
 */
async function ensureTifceScoresTable(db: D1Database): Promise<void> {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS tifce_scores (
         feed_id          TEXT    NOT NULL,
         generated_at     TEXT    NOT NULL,
         contributions    INTEGER NOT NULL DEFAULT 0,
         originality      REAL    NOT NULL DEFAULT 0,
         env_relevance    REAL    NOT NULL DEFAULT 0,
         signal_noise     REAL    NOT NULL DEFAULT 0,
         freshness        REAL    NOT NULL DEFAULT 0,
         composite        REAL    NOT NULL DEFAULT 0,
         unique_indicators   INTEGER NOT NULL DEFAULT 0,
         shared_indicators  INTEGER NOT NULL DEFAULT 0,
         tp_linked_indicators INTEGER NOT NULL DEFAULT 0,
         newest_observation TEXT,
         velocity_per_day   REAL    NOT NULL DEFAULT 0,
         PRIMARY KEY (feed_id, generated_at)
       )`
    )
    .run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_tifce_scores_generated_at ON tifce_scores (generated_at)').run();
  await db
    .prepare('CREATE INDEX IF NOT EXISTS idx_tifce_scores_feed_recent  ON tifce_scores (feed_id, generated_at DESC)')
    .run();
}

/**
 * Load the ioc_lifecycle TP-proxy set: every indicator that ever achieved
 * peak_score > 0. Cheap because the table is indexed on peak_score; a
 * bounded query stays well under the D1 read budget.
 */
async function loadTpIndicatorSet(db: D1Database): Promise<Set<string>> {
  try {
    const res = await db
      .prepare(
        `SELECT indicator FROM ioc_lifecycle
         WHERE peak_score > 0
         LIMIT 50000`
      )
      .all<{ indicator: string }>();
    const set = new Set<string>();
    for (const r of res.results ?? []) set.add(r.indicator);
    return set;
  } catch (err) {
    logError('tifce: ioc_lifecycle TP load failed', err);
    return new Set();
  }
}

/**
 * Load the platform-reported set: IOC indicators we have ourselves reported
 * on in a case-study briefing (api/src/case-study/). The briefings table
 * stores JSON in `body`; we walk it and pull anything that looks like a
 * domain, IP, URL, or hash. This is best-effort — the JSON walk is cheap
 * but lossy, and that's the right trade-off for a Pillar 2 proxy.
 */
async function loadPlatformReportedSet(db: D1Database): Promise<Set<string>> {
  try {
    const res = await db
      .prepare(
        `SELECT body FROM briefings
         WHERE body IS NOT NULL
         ORDER BY created_at DESC
         LIMIT 200`
      )
      .all<{ body: string }>();
    const set = new Set<string>();
    for (const r of res.results ?? []) {
      try {
        const parsed = JSON.parse(r.body) as { iocs?: unknown; sources?: unknown };
        const iocs = Array.isArray(parsed?.iocs) ? parsed.iocs : [];
        for (const i of iocs) {
          if (typeof i === 'string') set.add(i);
          else if (i && typeof i === 'object' && 'value' in i && typeof (i as { value: unknown }).value === 'string') {
            set.add((i as { value: string }).value);
          }
        }
      } catch (_catchErr) {
        logError('loadPlatformReportedSet failed', _catchErr);
        /* skip malformed body */
      }
    }
    return set;
  } catch (err) {
    logError('tifce: briefings platform-reported load failed', err);
    return new Set();
  }
}

/**
 * Load the detection-rules-fired set: IOCs the detection engine has fired
 * on in the last 24h. Stored in KV under detection-results:*; the engine
 * prunes older results, so a 24h window is the natural cutoff.
 */
async function loadDetectionFiredSet(env: Env): Promise<Set<string>> {
  const kv = env.KV_CACHE;
  if (!kv) return new Set();

  const cache = (caches as unknown as { default: Cache }).default;
  const CACHE_KEY = 'https://detection-results-cache.internal/v1';
  if (cache) {
    try {
      const hit = await cache.match(new Request(CACHE_KEY));
      if (hit) return new Set<string>((await hit.json()) as string[]);
    } catch (_catchErr) {
      logError('loadDetectionFiredSet failed', _catchErr);
      /* fall through */
    }
  }

  const set = new Set<string>();
  try {
    let cursor: string | undefined;
    let scanned = 0;
    const SCAN_CAP = 2000;
    do {
      const page: { keys: { name: string }[]; cursor?: string } = await kv.list({
        prefix: 'detection-results:',
        limit: 200,
        ...(cursor ? { cursor } : {}),
      });
      const pageKeys = page.keys ?? [];
      // Bulk-read this page's values — one subrequest per 100 keys instead of
      // one get per key (was up to 2000 gets per invocation). Keys past SCAN_CAP
      // are counted but not read, matching the old per-key cap check.
      const remaining = Math.max(0, SCAN_CAP - scanned);
      const keysToRead = pageKeys.slice(0, remaining).map((k) => k.name);
      scanned += pageKeys.length;
      const values = await kvBulkGetText(kv, keysToRead);
      const pageResults = keysToRead.map((name): string[] | null => {
        const raw = values.get(name) ?? null;
        if (!raw) return null;
        try {
          const parsed = JSON.parse(raw) as { iocs?: unknown; fired_at?: string };
          const firedAt = typeof parsed.fired_at === 'string' ? Date.parse(parsed.fired_at) : 0;
          if (firedAt && Date.now() - firedAt > 24 * 3_600_000) return null;
          if (Array.isArray(parsed.iocs)) {
            return parsed.iocs.filter((i): i is string => typeof i === 'string');
          }
          return null;
        } catch (_catchErr) {
          logError('handler failed', _catchErr);
          return null;
        }
      });
      for (const iocs of pageResults) {
        if (iocs) for (const i of iocs) set.add(i);
      }
      cursor = page.cursor;
      if (scanned > SCAN_CAP) break;
    } while (cursor);

    if (cache && set.size > 0) {
      void safeNullLog(
        'cache-put-tifce-detection',
        cache.put(
          new Request(CACHE_KEY),
          new Response(JSON.stringify([...set]), {
            headers: { 'cache-control': `max-age=${300}` },
          })
        )
      );
    }
    return set;
  } catch (err) {
    logError('tifce: detection-fired set load failed', err);
    return set;
  }
}

/**
 * Load per-feed TIFCE history for the trailing `HISTORY_WINDOW_DAYS`.
 * Returned as oldest → newest for each feed so the velocity calc can do
 * an OLS slope on a single forward pass.
 */
async function loadHistory(db: D1Database): Promise<Record<string, TifceHistoryRow[]>> {
  try {
    const cutoff = new Date(Date.now() - HISTORY_WINDOW_DAYS * 24 * 3_600_000).toISOString();
    const res = await db
      .prepare(
        `SELECT feed_id, generated_at, contributions
         FROM tifce_scores
         WHERE generated_at >= ?
         ORDER BY feed_id, generated_at ASC`
      )
      .bind(cutoff)
      .all<{ feed_id: string; generated_at: string; contributions: number }>();
    const out: Record<string, TifceHistoryRow[]> = {};
    for (const row of res.results ?? []) {
      const arr = out[row.feed_id] ?? [];
      arr.push({ generated_at: row.generated_at, contributions: row.contributions });
      out[row.feed_id] = arr;
    }
    return out;
  } catch (err) {
    logError('tifce: history load failed (table may not exist yet)', err);
    return {};
  }
}

/**
 * Persist one row per (feed, generated_at). The PRIMARY KEY (feed_id,
 * generated_at) is at minute granularity, so a same-minute second build
 * upserts in place instead of doubling. This is what gives Pillar 4 a
 * stable 7d window to regress against.
 *
 * Defensive: also runs the migration's CREATE TABLE on first access in
 * case the migration hasn't been applied yet (mirrors the pattern in
 * ioc-lifecycle.ts:73-98). The DDL is idempotent.
 */
async function persistCurrentBuild(db: D1Database, result: TifceResult): Promise<void> {
  await ensureTifceScoresTable(db);
  const nowIso = result.generated_at;
  // SQLite INSERT OR REPLACE is fine for our primary key shape and avoids
  // a SELECT-then-INSERT race; the table is small (~30 feeds × 1 row).
  const stmt = db.prepare(
    `INSERT OR REPLACE INTO tifce_scores (
       feed_id, generated_at, contributions, originality, env_relevance,
       signal_noise, freshness, composite, unique_indicators, shared_indicators,
       tp_linked_indicators, newest_observation, velocity_per_day
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const batch: D1PreparedStatement[] = [];
  for (const f of result.feeds) {
    batch.push(
      stmt.bind(
        f.feedId,
        nowIso,
        f.contributions,
        f.originality.score,
        f.envRelevance.score,
        f.signalNoise.score,
        f.freshness.score,
        f.composite,
        Number(f.originality.details.unique ?? 0),
        Number(f.originality.details.shared ?? 0),
        Number(f.signalNoise.details.tp_linked ?? 0),
        typeof f.freshness.details.newest_observation === 'string' ? f.freshness.details.newest_observation : null,
        Number(f.freshness.details.velocity_per_day ?? 0)
      )
    );
  }
  if (batch.length > 0) {
    // Chunked for atomicity, not budget: a batch is all-or-nothing, so one bad
    // statement would otherwise discard every row for the whole build. Today's
    // fan-out yields ~20 distinct sources, well inside one chunk; the chunking
    // is what keeps that true if the fan-out grows.
    for (let i = 0; i < batch.length; i += MAX_TIFCE_BATCH) {
      await db.batch(batch.slice(i, i + MAX_TIFCE_BATCH));
    }
  }
}

// ────────────────────────────────────────────────────────────────────────
// Shape adapters
// ────────────────────────────────────────────────────────────────────────

/** Convert a LiveIocsResponse into the per-feed TifceInputs shape. */
function toFeedContributions(live: LiveIocsResponse): FeedContribution[] {
  // Group items by source.
  const bySource = new Map<string, LiveIoc[]>();
  for (const it of live.items) {
    const arr = bySource.get(it.source) ?? [];
    arr.push(it);
    bySource.set(it.source, arr);
  }
  // Also include sources that returned 0 items (so the UI can show
  // "this feed contributed 0 IOCs" with a rationale rather than vanish
  // from the surface). The LiveIocsResponse drops those from `sources`
  // post-compose — we look up the registry by id and synthesize a stub.
  const knownSources = new Map<string, LiveSource>();
  for (const s of live.sources) knownSources.set(s.id, s);

  const out: FeedContribution[] = [];
  for (const [source, items] of bySource) {
    out.push({
      feedId: source,
      items,
      source: knownSources.get(source) ?? { id: source, ok: true, count: items.length },
    });
  }
  return out;
}
