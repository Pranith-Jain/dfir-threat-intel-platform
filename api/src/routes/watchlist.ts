/**
 * Watchlist + Digests.
 *
 * Actor watchlist with CRUD + sector-filtered weekly digest generation.
 * Piggybacks on the existing Monday cron slot (45 0 * * 2) for digest
 * generation since we're at the 5-cron free-plan cap.
 *
 * Endpoints:
 *   GET  /api/v1/watchlist/actors            — list watched actors
 *   POST /api/v1/watchlist/actors            — add actor to watchlist
 *   DELETE /api/v1/watchlist/actors/:id      — remove actor from watchlist
 *   GET  /api/v1/watchlist/actors/:actor/activity — recent activity for a watched actor
 *   GET  /api/v1/watchlist/digests           — list generated digests
 *   POST /api/v1/watchlist/digest            — generate a digest now
 *   GET  /api/v1/watchlist/digest/:id        — get a specific digest
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { kvBulkGetText } from '../lib/safe-catch';
import { badRequest, internalError, notFound, serviceUnavailable } from '../lib/api-error';
import { callerOwnerId, ownerVisibilityFilter, ownerCheck } from '../lib/ownership';

// ── Helpers ────────────────────────────────────────────────────────────

function generateId(): string {
  return `wl_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
}

const ACTOR_EXAMPLES = ['LockBit', 'BlackCat', 'Lazarus', 'Scattered Spider', 'CL0P', 'APT29', 'Kimsuky', 'PLAY'];

// ── Actor Watchlist CRUD ───────────────────────────────────────────────

/**
 * GET /api/v1/watchlist/actors
 * Returns all active watched actors.
 */
export async function watchlistActorsListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');
  try {
    const vis = ownerVisibilityFilter(c);
    const rows = await db
      .prepare(
        `SELECT id, actor_name, description, target_sectors, target_regions, active, last_activity, created_at, updated_at
         FROM actor_watchlist
         WHERE active = 1 AND ${vis.clause}
         ORDER BY last_activity DESC, created_at DESC`
      )
      .bind(...vis.bindings)
      .all<{
        id: string;
        actor_name: string;
        description: string;
        target_sectors: string;
        target_regions: string;
        active: number;
        last_activity: string;
        created_at: string;
        updated_at: string;
      }>();

    const actors = (rows.results ?? []).map((r) => ({
      ...r,
      target_sectors: JSON.parse(r.target_sectors),
      target_regions: JSON.parse(r.target_regions),
    }));

    return c.json({ actors, suggestions: ACTOR_EXAMPLES });
  } catch (e) {
    logError('watchlistActorsListHandler failed', e);
    return internalError(c, e);
  }
}

/**
 * POST /api/v1/watchlist/actors
 * Body: { actor_name: string, description?: string, target_sectors?: string[], target_regions?: string[] }
 */
export async function watchlistActorsAddHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');
  try {
    const body = (await c.req.json()) as {
      actor_name?: string;
      description?: string;
      target_sectors?: string[];
      target_regions?: string[];
    };

    const name = body.actor_name?.trim();
    if (!name) return badRequest(c, 'actor_name is required');

    const id = generateId();
    await db
      .prepare(
        `INSERT INTO actor_watchlist (id, actor_name, description, target_sectors, target_regions, updated_at, owner_hash)
         VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?)`
      )
      .bind(
        id,
        name,
        body.description ?? '',
        JSON.stringify(body.target_sectors ?? []),
        JSON.stringify(body.target_regions ?? []),
        callerOwnerId(c)
      )
      .run();

    return c.json({ id, actor_name: name, ok: true }, 201);
  } catch (e) {
    logError('watchlistActorsAddHandler failed', e);
    return internalError(c, e);
  }
}

/**
 * DELETE /api/v1/watchlist/actors/:id
 */
export async function watchlistActorsDeleteHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');
  try {
    const id = c.req.param('id');
    if (!id) return badRequest(c, 'id required');
    const row = await db
      .prepare('SELECT owner_hash FROM actor_watchlist WHERE id = ?')
      .bind(id)
      .first<{ owner_hash: string | null }>();
    if (!row || ownerCheck(c, row.owner_hash) === 'hidden') return notFound(c, 'actor not found');
    await db.prepare('UPDATE actor_watchlist SET active = 0 WHERE id = ?').bind(id).run();
    return c.json({ ok: true });
  } catch (e) {
    logError('watchlistActorsDeleteHandler failed', e);
    return internalError(c, e);
  }
}

// ── Actor Activity ────────────────────────────────────────────────────

/**
 * GET /api/v1/watchlist/actors/:actor/activity
 * Returns recent news/victims for a specific actor.
 * Queries external feeds aggregated in KV.
 */
export async function watchlistActorActivityHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const actor = c.req.param('actor');
  if (!actor) return badRequest(c, 'actor required');

  const kv = c.env.KV_CACHE;
  if (!kv) return serviceUnavailable(c, 'KV cache not available');

  try {
    // Per-colo Cache-API shadows (free) — feeds change slowly, so a 5min
    // shadow collapses repeat activity views to ~1 KV read per colo.
    const cache = (caches as unknown as { default: Cache }).default;
    const shadowed = async <T>(kind: string): Promise<T | null> => {
      const req = new Request(`https://watchlist-activity-cache.internal/v1/${kind}/${encodeURIComponent(actor)}`);
      try {
        const hit = await cache.match(req);
        if (hit) return (await hit.json()) as T | null;
      } catch {
        /* fall through to KV */
      }
      const value = (await kv
        .get(`${kind === 'news' ? 'actor:news' : 'ransomware:actor'}:${actor}`, 'json')
        .catch(() => null)) as T | null;
      if (value && cache) {
        try {
          await cache.put(
            req,
            new Response(JSON.stringify(value), {
              headers: { 'content-type': 'application/json', 'cache-control': 'max-age=300' },
            })
          );
        } catch {
          /* best-effort */
        }
      }
      return value;
    };
    const [news, victims] = await Promise.all([shadowed<unknown>('news'), shadowed<unknown>('victims')]);

    return c.json({
      actor,
      news: news ?? [],
      victims: victims ?? [],
    });
  } catch (e) {
    logError('watchlistActorActivityHandler failed', e);
    return internalError(c, e);
  }
}

// ── Digest generation ──────────────────────────────────────────────────

interface DigestEntry {
  actor: string;
  sector: string;
  activity: string;
  victims: number;
  sources: string[];
}

interface DigestResult {
  id: string;
  period: 'weekly';
  iso_week: string;
  estate_sector: string;
  entries: DigestEntry[];
  generated_at: string;
  error?: string;
}

/**
 * POST /api/v1/watchlist/digest
 * Generate a digest now — sector-filtered, covers all watched actors.
 *
 * This is also called from the Monday cron slot for automated weekly generation.
 */
export async function watchlistDigestGenerateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const kv = c.env.KV_CACHE;
  if (!kv) return serviceUnavailable(c, 'KV cache not available');

  try {
    // Load estate sector
    const estateRow = await db
      .prepare('SELECT sector FROM estate_config WHERE id = ?')
      .bind('default')
      .first<{ sector: string }>();
    const estateSector = estateRow?.sector ?? '';

    // Load watched actors
    const rows = await db
      .prepare(`SELECT id, actor_name, target_sectors FROM actor_watchlist WHERE active = 1 ORDER BY created_at DESC`)
      .all<{ id: string; actor_name: string; target_sectors: string }>();

    const actors = rows.results ?? [];
    const entries: DigestEntry[] = [];

    // Sector-match first so only relevant actors' feeds are read…
    const matchedActors = actors.filter((row) => {
      const sectors = JSON.parse(row.target_sectors) as string[];
      return estateSector && sectors.length > 0
        ? sectors.some((s) => s.toLowerCase() === estateSector.toLowerCase())
        : sectors.length === 0; // wildcard match if no sectors specified
    });

    // …then ONE bulk KV read for every actor's news+victims slices. The old
    // loop issued 2 sequential KV gets PER ACTOR (2N subrequests); a batch
    // get is ONE subrequest per ≤100-key chunk regardless of key count.
    const feedKeys = matchedActors.flatMap((row) => [
      `actor:news:${row.actor_name}`,
      `ransomware:actor:${row.actor_name}`,
    ]);
    const feedRaw = await kvBulkGetText(kv, feedKeys);
    const parseFeed = <T>(key: string): T[] | null => {
      const raw = feedRaw.get(key);
      if (!raw) return null;
      try {
        return JSON.parse(raw) as T[];
      } catch {
        return null;
      }
    };

    for (const row of matchedActors) {
      const activity = parseFeed<{ title: string; url: string; date: string }>(`actor:news:${row.actor_name}`);

      const victims = parseFeed<{ victim: string; date: string; country: string }>(
        `ransomware:actor:${row.actor_name}`
      );

      entries.push({
        actor: row.actor_name,
        sector: estateSector || 'unknown',
        activity: (activity ?? [])
          .slice(0, 10)
          .map((a) => a.title)
          .join('; '),
        victims: (victims ?? []).length,
        sources: ['actor:news', 'ransomware:actor'],
      });
    }

    // Compute ISO week
    const now = new Date();
    const isoWeek = getIsoWeek(now);

    const digest: DigestResult = {
      id: generateId(),
      period: 'weekly',
      iso_week: isoWeek,
      estate_sector: estateSector,
      entries,
      generated_at: now.toISOString(),
    };

    // Store in KV
    await kv.put(`digest:weekly:${isoWeek}`, JSON.stringify(digest), { expirationTtl: 86400 * 14 });
    // Digests are NOT immutable across regeneration (same key is overwritten
    // when the week's digest is rebuilt) — evict the GET shadow so readers
    // see the fresh digest immediately.
    try {
      await (caches as unknown as { default: Cache }).default.delete(
        new Request(`https://watchlist-digest-cache.internal/v1/${encodeURIComponent(isoWeek)}`)
      );
    } catch {
      /* best-effort */
    }

    const indexRaw = await kv.get('digest:weekly:index').catch(() => null);
    const weeks: string[] = indexRaw ? JSON.parse(indexRaw) : [];
    if (!weeks.includes(isoWeek)) {
      weeks.unshift(isoWeek);
      await kv.put('digest:weekly:index', JSON.stringify(weeks.slice(0, 20))).catch(() => {});
    }

    return c.json({ digest, actor_count: entries.length });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e);
  }
}

/**
 * GET /api/v1/watchlist/digests — list recent digests.
 */
export async function watchlistDigestsListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const kv = c.env.KV_CACHE;
  if (!kv) return serviceUnavailable(c, 'KV cache not available');

  try {
    // L1: Cache API (per-colo, free)
    const l1Cached = await caches.default.match(new Request(c.req.url));
    if (l1Cached) return c.json(await l1Cached.json());

    // L2: KV bulk read (one subrequest per 100 keys, was N+1 per key)
    const indexRaw = await kv.get('digest:weekly:index');
    let weekKeys: string[];
    if (indexRaw) {
      const weeks: string[] = JSON.parse(indexRaw);
      weekKeys = weeks.slice(0, 20).map((w) => `digest:weekly:${w}`);
    } else {
      const listed = await kv.list<unknown>({ prefix: 'digest:weekly:', limit: 20 });
      weekKeys = listed.keys.map((k) => k.name).filter((n) => n !== 'digest:weekly:index');
    }
    const values = await kvBulkGetText(kv, weekKeys);
    const digests = weekKeys.map((key): DigestResult | null => {
      const raw = values.get(key) ?? null;
      if (!raw) return null;
      try {
        return JSON.parse(raw) as DigestResult;
      } catch {
        return null;
      }
    });

    const result = {
      digests: digests.filter(Boolean).sort((a, b) => b!.generated_at.localeCompare(a!.generated_at)),
    };

    // Shadow-write Cache API
    c.executionCtx.waitUntil(
      caches.default.put(
        new Request(c.req.url),
        new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, s-maxage=600' },
        })
      )
    );

    return c.json(result);
  } catch (e) {
    logError('watchlistDigestsListHandler failed', e);
    return internalError(c, e);
  }
}

/**
 * GET /api/v1/watchlist/digest/:id — fetch a specific digest.
 */
export async function watchlistDigestGetHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const id = c.req.param('id');
  if (!id) return badRequest(c, 'id required');

  const kv = c.env.KV_CACHE;
  if (!kv) return serviceUnavailable(c, 'KV cache not available');

  // Digests are immutable per ISO week — a per-colo Cache-API shadow (1h)
  // makes repeat views free. Validate the id shape before it reaches a key.
  if (!/^[a-z0-9-]{4,64}$/i.test(id)) return badRequest(c, 'invalid digest id');
  const cache = (caches as unknown as { default: Cache }).default;
  const shadowReq = new Request(`https://watchlist-digest-cache.internal/v1/${encodeURIComponent(id)}`);
  try {
    const hit = await cache.match(shadowReq);
    if (hit) return c.json((await hit.json()) as DigestResult);
  } catch {
    /* fall through to KV */
  }
  const val = (await kv.get(`digest:weekly:${id}`, 'json').catch(() => null)) as DigestResult | null;
  if (!val) return notFound(c, 'digest not found');
  try {
    await cache.put(
      shadowReq,
      new Response(JSON.stringify(val), {
        headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' },
      })
    );
  } catch {
    /* best-effort */
  }
  return c.json(val);
}

// ── Week helper ──────────────────────────────────────────────────────

function getIsoWeek(date: Date): string {
  // UTC getters throughout: the digest key must be timezone-stable. Mixing
  // local getters into a UTC construction shifted the week on non-UTC hosts.
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNum = Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNum).padStart(2, '0')}`;
}

// ── Cron hook ─────────────────────────────────────────────────────────

/**
 * Called from the Monday weekly briefing cron (scheduled.ts).
 * Generates the weekly watchlist digest if there are watched actors.
 */
export async function runWeeklyWatchlistDigest(db: D1Database, kv: KVNamespace): Promise<void> {
  try {
    const count = await db.prepare('SELECT COUNT(*) as c FROM actor_watchlist WHERE active = 1').first<{ c: number }>();
    if (!count || count.c === 0) {
      return;
    }

    // Generate the digest by calling the generation logic inline
    const now = new Date();
    const isoWeek = getIsoWeek(now);
    const estateRow = await db
      .prepare('SELECT sector FROM estate_config WHERE id = ?')
      .bind('default')
      .first<{ sector: string }>();
    const estateSector = estateRow?.sector ?? '';

    const rows = await db
      .prepare('SELECT id, actor_name, target_sectors FROM actor_watchlist WHERE active = 1')
      .all<{ id: string; actor_name: string; target_sectors: string }>();

    // Sector-match first, then ONE batched KV read for every matched actor's
    // news+victims slices (was 2 sequential gets per actor inside the loop).
    // Wildcard rule MUST mirror watchlistDigestGenerateHandler above: an actor
    // with no target_sectors matches ANY estate sector.
    const entries: DigestEntry[] = [];
    const matchedRows = (rows.results ?? []).filter((row) => {
      const sectors = JSON.parse(row.target_sectors) as string[];
      return estateSector && sectors.length > 0
        ? sectors.some((s) => s.toLowerCase() === estateSector.toLowerCase())
        : sectors.length === 0;
    });
    const feedKeys = matchedRows.flatMap((row) => [
      `actor:news:${row.actor_name}`,
      `ransomware:actor:${row.actor_name}`,
    ]);
    const feedRaw = await kvBulkGetText(kv, feedKeys);
    const parseFeed = <T>(key: string): T[] | null => {
      const raw = feedRaw.get(key);
      if (!raw) return null;
      try {
        return JSON.parse(raw) as T[];
      } catch {
        return null;
      }
    };

    for (const row of matchedRows) {
      const activity = parseFeed<{ title: string }>(`actor:news:${row.actor_name}`);
      const victims = parseFeed<unknown>(`ransomware:actor:${row.actor_name}`);

      entries.push({
        actor: row.actor_name,
        sector: estateSector || 'unknown',
        activity: (activity ?? [])
          .slice(0, 10)
          .map((a) => a.title)
          .join('; '),
        victims: (victims ?? []).length,
        sources: ['actor:news', 'ransomware:actor'],
      });
    }

    const digest: DigestResult = {
      id: generateId(),
      period: 'weekly',
      iso_week: isoWeek,
      estate_sector: estateSector,
      entries,
      generated_at: now.toISOString(),
    };

    await kv.put(`digest:weekly:${isoWeek}`, JSON.stringify(digest), { expirationTtl: 86400 * 14 });
    // Evict the GET shadow (digests regenerate under the same weekly key).
    try {
      await (caches as unknown as { default: Cache }).default.delete(
        new Request(`https://watchlist-digest-cache.internal/v1/${encodeURIComponent(isoWeek)}`)
      );
    } catch {
      /* best-effort */
    }

    const indexRaw = await kv.get('digest:weekly:index').catch(() => null);
    const weeks: string[] = indexRaw ? JSON.parse(indexRaw) : [];
    if (!weeks.includes(isoWeek)) {
      weeks.unshift(isoWeek);
      await kv.put('digest:weekly:index', JSON.stringify(weeks.slice(0, 20))).catch(() => {});
    }
  } catch (e) {
    logError('watchlist-digest: failed', e);
  }
}
