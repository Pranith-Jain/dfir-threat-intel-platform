/**
 * Daily Briefs edge tools — REST surface for daily intelligence briefs.
 *
 * Endpoints (all under /api/v1/daily-briefs/):
 *   GET  /daily-briefs/                — slim index
 *   GET  /daily-briefs/:type           — list dates for brief type
 *   GET  /daily-briefs/:type/:date     — full brief body
 *   GET  /daily-briefs/stats           — cache + manifest stats
 *
 * Data source priority: KV (populated by cron) > ASSETS (static fallback).
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError, notFound } from '../lib/api-error';
import type { DbBriefBody } from '../lib/daily-briefs-manifest';

const KV_INDEX_KEY = 'db:index';
const KV_BODY_PREFIX = 'db:body';

// L1 per-colo Cache-API shadow for the index + bodies. The index flips only
// on the daily cron sync; bodies are immutable per (type,date). A 10-min
// shadow TTL collapses repeated reads to ~1 KV read per colo per window.
const DB_INDEX_SHADOW_TTL = 600;
const DB_BODY_SHADOW_TTL = 3600;
function dbIndexShadowReq(): Request {
  return new Request(`https://db-cache.internal/v1/${KV_INDEX_KEY}`);
}
function dbBodyShadowReq(type: string, date: string): Request {
  return new Request(`https://db-cache.internal/v1/${KV_BODY_PREFIX}:${type}:${date}`);
}

/**
 * Union two indexes rather than picking one.
 *
 * Exported for tests: the merge is the load-bearing logic here, and asserting
 * it through the HTTP route means fighting two module-level caches (the
 * manifest memo and the per-colo Cache-API shadow) that outlive a single test.
 *
 * KV and ASSETS hold different histories: the KV index accumulates every brief
 * the Worker-side sync has ever seen (long tail, but only as fresh as its last
 * successful run), while the committed static manifest is what the GitHub
 * Actions pipeline produces (authoritative, but only as fresh as its last
 * commit). Preferring whichever was merely non-empty meant a stale-but-populated
 * KV index shadowed a newer static manifest — the page listed September briefs
 * while the repository already carried the October ones, and nothing raised an
 * error, because each source looked healthy on its own.
 */
export function mergeIndexes(a: DbIndex | null, b: DbIndex | null): DbIndex | null {
  if (!a) return b;
  if (!b) return a;
  // Apply OLDEST first so the NEWEST source wins any key present in both.
  // Iterating `[a, b]` in argument order let the stale index overwrite the fresh
  // one for every shared (type, date) — the row then carried the older
  // `sizeBytes` while the envelope advertised the newer `generatedAt`.
  const ordered: [DbIndex, DbIndex] = a.generatedAt <= b.generatedAt ? [a, b] : [b, a];
  const briefs = new Map<string, { type: string; date: string; sizeBytes: number }>();
  for (const src of ordered) {
    for (const brief of src.briefs ?? []) briefs.set(`${brief.type}:${brief.date}`, brief);
  }
  // Newest first, with a type tiebreaker so equal dates keep a stable order
  // (the merged list is cached and diffed; a nondeterministic sort would make
  // two identical merges compare unequal).
  const merged = [...briefs.values()].sort((x, y) => y.date.localeCompare(x.date) || x.type.localeCompare(y.type));
  const counts: Record<string, number> = {};
  for (const brief of merged) counts[brief.type] = (counts[brief.type] ?? 0) + 1;
  return {
    source: ordered[1].source,
    license: a.license || b.license,
    generatedAt: ordered[1].generatedAt,
    counts: counts as DbIndex['counts'],
    briefs: merged,
  };
}

async function loadDbMod() {
  return await import('../lib/daily-briefs-manifest');
}

const VALID_TYPES = ['cyber', 'deepfake', 'disaster', 'maritime'] as const;

interface DbIndex {
  source: string;
  license: string;
  generatedAt: string;
  counts: { cyber: number; deepfake: number; disaster: number; maritime: number };
  briefs: { type: string; date: string; sizeBytes: number }[];
}

/**
 * The Cache API, or null when the runtime doesn't provide one.
 *
 * `caches` is undefined in some contexts (inside a Durable Object's global
 * scope, a bare router invoked outside a Worker, the Workers playground).
 * Dereferencing `caches.default` unguarded threw a TypeError BEFORE either data
 * source was read, so `/daily-briefs/` answered 500 even with a perfectly good
 * KV index and a valid ASSETS manifest in hand. The shadow is a pure
 * optimisation — losing it must cost latency, not availability.
 */
function cacheApi(): Cache | null {
  const c = (globalThis as { caches?: { default?: Cache } }).caches;
  return c?.default ?? null;
}

async function loadIndex(kv?: KVNamespace, assets?: Fetcher): Promise<DbIndex | null> {
  // L1: per-colo Cache-API shadow (free, no KV quota). The index only
  // changes on the daily cron, so a 10-min shadow is safe.
  const cache = cacheApi();
  if (cache && kv) {
    try {
      const hit = await cache.match(dbIndexShadowReq());
      if (hit) {
        const idx = (await hit.json()) as DbIndex;
        if (idx?.briefs && idx.briefs.length > 0) return idx;
      }
    } catch {
      /* fall through to KV */
    }
  }

  // Both sources are read before the shadow is written, so the shadow always
  // holds the union rather than whichever source happened to be warm.
  let fromKv: DbIndex | null = null;
  try {
    const raw = await kv?.get(KV_INDEX_KEY, 'json');
    if (raw && typeof raw === 'object' && 'briefs' in (raw as DbIndex)) {
      const idx = raw as DbIndex;
      if (idx.briefs && idx.briefs.length > 0) fromKv = idx;
    }
  } catch {
    /* fall through */
  }

  let fromAssets: DbIndex | null = null;
  if (assets) {
    try {
      const mod = await loadDbMod();
      const idx = (await mod.loadDbIndex(assets)) as unknown as DbIndex | null;
      fromAssets = idx && idx.briefs?.length ? idx : null;
    } catch {
      /* fall through */
    }
  }

  const idx = mergeIndexes(fromKv, fromAssets);
  if (!idx) return null;

  // Write-through so the next read in this colo skips KV and ASSETS.
  try {
    await cache?.put(
      dbIndexShadowReq(),
      new Response(JSON.stringify(idx), {
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${DB_INDEX_SHADOW_TTL}`,
        },
      })
    );
  } catch {
    /* best-effort shadow */
  }
  return idx;
}

async function loadBriefBody(
  kv?: KVNamespace,
  assets?: Fetcher,
  type?: string,
  date?: string
): Promise<DbBriefBody | null> {
  if (kv && type && date) {
    // L1: per-colo Cache-API shadow. Bodies are immutable per (type,date),
    // so a 1h shadow is safe and collapses repeated reads.
    const cache = cacheApi();
    const shadowReq = dbBodyShadowReq(type, date);
    try {
      const hit = await cache?.match(shadowReq);
      if (hit) return await hit.json();
    } catch {
      /* fall through to KV */
    }
    try {
      const raw = await kv.get(`${KV_BODY_PREFIX}:${type}:${date}`, 'json');
      if (raw) {
        try {
          await cache?.put(
            shadowReq,
            new Response(JSON.stringify(raw), {
              headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${DB_BODY_SHADOW_TTL}` },
            })
          );
        } catch {
          /* best-effort shadow */
        }
        return raw as DbBriefBody;
      }
    } catch {
      /* fall through */
    }
  }
  if (assets && type && date) {
    try {
      const mod = await loadDbMod();
      return await mod.getDbBrief(assets, type as Parameters<typeof mod.getDbBrief>[1], date);
    } catch {
      /* fall through */
    }
  }
  return null;
}

export const dailyBriefsRouter = new Hono<{ Bindings: Env }>();

// ─── Slim index ────────────────────────────────────────────────────────
dailyBriefsRouter.get('/daily-briefs/', async (c) => {
  try {
    const idx = await loadIndex(c.env.KV_CACHE, c.env.ASSETS);
    if (!idx) return internalError(c, 'db_index_failed: no data source available');
    return c.json({
      source: idx.source,
      license: idx.license,
      generatedAt: idx.generatedAt,
      counts: idx.counts,
      briefs: idx.briefs,
    });
  } catch (e) {
    logError('loadDbMod failed', e);
    return internalError(c, `db_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Stats ─────────────────────────────────────────────────────────────
// Registered BEFORE `/daily-briefs/:type`. Hono matches in registration order,
// so a literal segment declared after the parameterised one is unreachable —
// `GET /daily-briefs/stats` was being captured by `:type` and answered 400
// "invalid_type: stats" instead of the stats payload.
dailyBriefsRouter.get('/daily-briefs/stats', async (c) => {
  try {
    const idx = await loadIndex(c.env.KV_CACHE, c.env.ASSETS);
    if (!idx) return internalError(c, 'db_stats_failed: no data source available');
    return c.json({
      counts: idx.counts,
      source: idx.source,
      license: idx.license,
      generatedAt: idx.generatedAt,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `db_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── List dates for a brief type ───────────────────────────────────────
dailyBriefsRouter.get('/daily-briefs/:type', async (c) => {
  const type = c.req.param('type').toLowerCase();
  if (!VALID_TYPES.includes(type as (typeof VALID_TYPES)[number])) {
    return badRequest(c, `invalid_type: ${type} — must be cyber, deepfake, or disaster`);
  }
  try {
    const idx = await loadIndex(c.env.KV_CACHE, c.env.ASSETS);
    if (!idx) return internalError(c, 'db_list_failed: no data source available');
    const briefs = (idx.briefs ?? []).filter((b) => b.type === type);
    return c.json({ type, total: idx.counts[type as keyof typeof idx.counts], returned: briefs.length, briefs });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `db_list_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single brief body ─────────────────────────────────────────────────
dailyBriefsRouter.get('/daily-briefs/:type/:date', async (c) => {
  const type = c.req.param('type').toLowerCase();
  const date = c.req.param('date');
  if (!VALID_TYPES.includes(type as (typeof VALID_TYPES)[number])) {
    return badRequest(c, `invalid_type: ${type} — must be cyber, deepfake, or disaster`);
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return badRequest(c, `invalid_date: ${date} — must be YYYY-MM-DD`);
  }
  try {
    const body = await loadBriefBody(c.env.KV_CACHE, c.env.ASSETS, type, date);
    if (!body) return notFound(c, `brief_not_found: ${type}/${date}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `db_brief_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
