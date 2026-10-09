/**
 * CTI Collector API routes
 *
 * /api/v1/cti/collect   — POST: trigger full IOC + news collection
 * /api/v1/cti/stats     — GET:  IOC statistics and breakdown
 * /api/v1/cti/iocs      — GET:  list collected IOCs (paginated, filtered)
 * /api/v1/cti/news      — GET:  recent news articles
 * /api/v1/cti/predictions — GET/POST: AI-generated attack predictions
 * /api/v1/cti/mutate    — POST: parse seed attack + generate mutation variants
 * /api/v1/cti/mutations — GET:  list mutations (seeds + top variants)
 * /api/v1/cti/decay     — POST: manually trigger decay scoring
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError, serviceUnavailable } from '../lib/api-error';
import { runFullCollection, getIocStats, applyDecayScoring, sweepStaleData } from '../lib/cti-collector';
import { generatePredictions, getRecentPredictions } from '../lib/cti-prediction';
import {
  parseSeedAttack,
  generateVariants,
  getSeeds,
  getVariantsForSeed,
  getTopVariants,
  getMutationStats,
} from '../lib/cti-mutation';

// ── Collection ─────────────────────────────────────────────────────────

export async function ctiCollectHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  const result = await runFullCollection(db, c.env.ABUSECH_AUTH_KEY);
  return c.json(result);
}

// ── Stats ──────────────────────────────────────────────────────────────

/**
 * `/api/v1/cti/stats` is the single largest D1 read amplifier on the platform.
 *
 * `getIocStats` runs ~8 unindexed aggregates on every call: four
 * `COUNT(*)`/`GROUP BY` passes over `cti_iocs` (4k+ rows) and four over
 * `cti_news`. Every one is a full scan, so one request costs ~15k rows read —
 * and the route was public with no `cache-control`, so every visitor (and
 * every prefetch) paid it. That alone accounted for the bulk of the 4.7M
 * rows/day against the 5M free-tier cap.
 *
 * Fix: edge-cache it. The numbers are aggregate counters that shift slowly;
 * nobody needs them fresher than a minute, and a hit now costs zero D1 reads.
 * `s-maxage` lets the Cloudflare cache hold it longer than the browser.
 */
const STATS_TTL_SECONDS = 60;

export async function ctiStatsHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  const stats = await getIocStats(db);
  return c.json(stats, 200, {
    'cache-control': `public, max-age=30, s-maxage=${STATS_TTL_SECONDS}`,
  });
}

// ── IOC listing ────────────────────────────────────────────────────────

export async function ctiIocsHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');

  const type = c.req.query('type') || '';
  const source = c.req.query('source') || '';
  const search = c.req.query('q') || '';
  const minDecay = Number(c.req.query('min_decay')) || 0;
  const limit = Math.min(Math.max(Number(c.req.query('limit')) || 100, 1), 500);
  const offset = Math.max(Number(c.req.query('offset')) || 0, 0);

  let where = 'WHERE 1=1';
  const params: string[] = [];

  if (type) {
    where += ' AND type = ?';
    params.push(type);
  }
  if (source) {
    where += ' AND source = ?';
    params.push(source);
  }
  if (search) {
    where += ' AND value LIKE ?';
    params.push(`%${search}%`);
  }
  if (minDecay > 0) {
    where += ' AND decay_score >= ?';
    params.push(String(minDecay));
  }

  const countResult = await db
    .prepare(`SELECT COUNT(*) as n FROM cti_iocs ${where}`)
    .bind(...params)
    .first();
  const rows = await db
    .prepare(
      `SELECT id, value, type, source, confidence, malware_family, threat_actor, tags, first_seen, last_seen, observation_count, decay_score
     FROM cti_iocs ${where} ORDER BY last_seen DESC LIMIT ? OFFSET ?`
    )
    .bind(...params, String(limit), String(offset))
    .all();

  return c.json({
    total: Number(countResult?.n || 0),
    limit,
    offset,
    iocs: rows.results.map((r) => ({
      ...r,
      tags: (() => {
        try {
          return JSON.parse(String(r.tags || '[]'));
        } catch {
          return [];
        }
      })(),
    })),
  });
}

// ── News listing ───────────────────────────────────────────────────────

export async function ctiNewsHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');

  const source = c.req.query('source') || '';
  const limit = Math.min(Math.max(Number(c.req.query('limit')) || 50, 1), 200);

  let where = 'WHERE 1=1';
  const params: string[] = [];
  if (source) {
    where += ' AND source = ?';
    params.push(source);
  }

  const rows = await db
    .prepare(
      `SELECT id, title, url, summary, source, published, tags, fetched_at FROM cti_news ${where} ORDER BY fetched_at DESC LIMIT ?`
    )
    .bind(...params, String(limit))
    .all();

  return c.json({
    total: rows.results.length,
    news: rows.results.map((r) => ({
      ...r,
      tags: (() => {
        try {
          return JSON.parse(String(r.tags || '[]'));
        } catch {
          return [];
        }
      })(),
    })),
  });
}

// ── Predictions ────────────────────────────────────────────────────────

export async function ctiPredictionsGetHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  const limit = Math.min(Math.max(Number(c.req.query('limit')) || 10, 1), 100);
  const predictions = await getRecentPredictions(db, limit);
  return c.json({ predictions });
}

export async function ctiPredictionsPostHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  const ai = c.env.AI;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  if (!ai) return serviceUnavailable(c, 'AI binding unavailable');

  const body = await c.req.json<{ count?: number; focus_sector?: string; focus_region?: string }>().catch(() => ({}));
  const result = await generatePredictions(db, ai, body, {
    groqKey: c.env.GROQ_API_KEY,
    googleKey: c.env.GOOGLE_AI_STUDIO_API_KEY,
  });
  return c.json(result);
}

// ── Mutation ───────────────────────────────────────────────────────────

export async function ctiMutateHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  const ai = c.env.AI;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  if (!ai) return serviceUnavailable(c, 'AI binding unavailable');

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return badRequest(c, 'invalid_json_body');
  }
  const input = String(body.input || '');
  if (!input) return badRequest(c, 'input is required');

  try {
    const keys = { groqKey: c.env.GROQ_API_KEY, googleKey: c.env.GOOGLE_AI_STUDIO_API_KEY };
    const seed = await parseSeedAttack(db, ai, input, String(body.seed_type || 'auto'), keys);
    const variants = await generateVariants(
      db,
      ai,
      seed,
      {
        count: typeof body.count === 'number' ? body.count : undefined,
        strategies: Array.isArray(body.strategies) ? body.strategies : undefined,
        target_sector: typeof body.target_sector === 'string' ? body.target_sector : undefined,
      },
      keys
    );

    return c.json({ seed, variants });
  } catch (e) {
    logError('ctiMutateHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'mutation failed');
  }
}

export async function ctiMutationsHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');

  const seedId = c.req.query('seed_id');
  if (seedId) {
    const variants = await getVariantsForSeed(db, seedId);
    return c.json({ seed_id: seedId, variants });
  }

  const seeds = await getSeeds(db);
  const topVariants = await getTopVariants(db, 10);
  const stats = await getMutationStats(db);
  return c.json({ seeds, top_variants: topVariants, stats });
}

// ── Decay scoring ──────────────────────────────────────────────────────

export async function ctiDecayHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  const result = await applyDecayScoring(db);
  return c.json(result);
}

// ── Stale data sweep ───────────────────────────────────────────────────

export async function ctiSweepHandler(c: Context<{ Bindings: Env }>) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database unavailable');
  const days = parseInt(c.req.query('days') || '30') || 30;
  const result = await sweepStaleData(db, days);
  return c.json({ days, ...result });
}
