/**
 * Telegram Intelligence Search — boolean search, timeline, saved searches.
 *
 * Enhanced search API inspired by TraceOn.re:
 * - Boolean AND/OR/NOT with field qualifiers
 * - Timeline data (message volume by day)
 * - Saved searches (D1-backed)
 * - IOC extraction per message
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { callerOwnerId, ownerVisibilityFilter, ownerCheck } from '../lib/ownership';
import { badRequest, notFound, serviceUnavailable } from '../lib/api-error';
import { safeJsonBody } from '../lib/safe-body';
import { parseBooleanQuery } from '../lib/tg-boolean-search';
import { routeCacheGet, routeCachePut } from '../lib/route-cache';

function genId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}

// ─── Boolean Search ───

export async function tgBooleanSearchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const q = c.req.query('q') || '';
  const mode = c.req.query('mode') || 'boolean';
  const channel = c.req.query('channel');
  const severity = c.req.query('severity');
  const leakType = c.req.query('leak_type');
  const dateFrom = c.req.query('from');
  const dateTo = c.req.query('to');
  const sort = c.req.query('sort') || 'newest';
  // `|| 50` absorbs a non-numeric `limit` (Number('abc') is NaN, and Math.min(…, NaN)
  // is NaN) which would otherwise reach SQL as `LIMIT NaN` — a SQLite syntax error
  // and a 500.
  const limit = Math.min(Number(c.req.query('limit')) || 50, 200);
  const offset = Number(c.req.query('offset') ?? '0');

  const whereParts: string[] = [];
  const params: unknown[] = [];

  // Boolean search
  if (q.trim()) {
    if (mode === 'boolean') {
      const parsed = parseBooleanQuery(q);
      whereParts.push(`(${parsed.whereClause})`);
      params.push(...parsed.params);
      // Duplicate params for the 3-column LIKE in boolean parser
      // Actually the parser already outputs 3 params per term (message_text, channel_handle, domains_found)
    } else {
      // General mode: simple OR search
      const terms = q.trim().split(/\s+/);
      const orParts: string[] = [];
      for (const term of terms) {
        orParts.push('(message_text LIKE ? OR channel_handle LIKE ? OR domains_found LIKE ?)');
        params.push(`%${term}%`, `%${term}%`, `%${term}%`);
      }
      whereParts.push(`(${orParts.join(' OR ')})`);
    }
  }

  // Filters
  if (channel) {
    whereParts.push('channel_handle = ?');
    params.push(channel);
  }
  if (severity) {
    whereParts.push('severity = ?');
    params.push(severity);
  }
  if (leakType) {
    whereParts.push('leak_type = ?');
    params.push(leakType);
  }
  if (dateFrom) {
    whereParts.push('discovered_at >= ?');
    params.push(dateFrom);
  }
  if (dateTo) {
    whereParts.push('discovered_at <= ?');
    params.push(dateTo + 'T23:59:59Z');
  }

  const whereClause = whereParts.length > 0 ? `WHERE ${whereParts.join(' AND ')}` : '';
  const orderClause = sort === 'oldest' ? 'ASC' : 'DESC';

  // Count — Cache-API shadowed. The WHERE clause routinely contains
  // leading-wildcard LIKEs over message_text/domains_found (no B-tree index
  // can serve those; see migration 0048), so the COUNT scans the full
  // telegram_leak_entries table — the largest table in the schema. Leak data
  // arrives on an hourly cron, so 300 s of staleness is invisible. The key
  // is a digest of the exact WHERE + bind params so every distinct query
  // gets its own independent shadow.
  const querySig = await crypto.subtle
    .digest('SHA-256', new TextEncoder().encode(`${whereClause}|${JSON.stringify(params)}`))
    .then((buf) => Array.from(new Uint8Array(buf).subarray(0, 12), (b) => b.toString(16).padStart(2, '0')).join(''));
  const countCacheKey = `tg:search:count:v1:${querySig}`;

  let total: number | null = await routeCacheGet<number>(countCacheKey);
  if (total === null) {
    const countRow = await db
      .prepare(`SELECT COUNT(*) as total FROM telegram_leak_entries ${whereClause}`)
      .bind(...params)
      .first();
    total = (countRow?.total as number) ?? 0;
    routeCachePut(countCacheKey, total, 300).catch(() => {});
  }

  // Fetch
  const { results } = await db
    .prepare(
      `SELECT id, channel_handle, message_link, message_text, leak_type, credential_count, file_url, file_name, domains_found, severity, discovered_at, raw_content FROM telegram_leak_entries ${whereClause} ORDER BY discovered_at ${orderClause} LIMIT ? OFFSET ?`
    )
    .bind(...params, limit, offset)
    .all();

  return c.json({
    results,
    total,
    limit,
    offset,
    hasMore: offset + limit < total,
  });
}

// ─── Timeline Data ───

export async function tgTimelineHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const q = c.req.query('q') || '';
  const channel = c.req.query('channel');
  const days = Math.min(Number(c.req.query('days') ?? '30'), 365);

  const whereParts: string[] = [`discovered_at >= date('now', '-${days} days')`];
  const params: unknown[] = [];

  if (q.trim()) {
    const parsed = parseBooleanQuery(q);
    whereParts.push(`(${parsed.whereClause})`);
    params.push(...parsed.params);
  }
  if (channel) {
    whereParts.push('channel_handle = ?');
    params.push(channel);
  }

  const whereClause = `WHERE ${whereParts.join(' AND ')}`;

  // Timeline + top-channels are two full-table GROUP BY scans over
  // telegram_leak_entries. Leak data is ingested by an hourly cron, so a
  // 300 s Cache-API shadow collapses repeat loads to zero D1 reads.
  const timelineSig = await crypto.subtle
    .digest('SHA-256', new TextEncoder().encode(`${whereClause}|${JSON.stringify(params)}|${days}`))
    .then((buf) => Array.from(new Uint8Array(buf).subarray(0, 12), (b) => b.toString(16).padStart(2, '0')).join(''));
  const timelineCacheKey = `tg:timeline:v1:${timelineSig}`;

  const cachedTimeline = await routeCacheGet<{
    timeline: unknown[];
    topChannels: unknown[];
  }>(timelineCacheKey);
  if (cachedTimeline) {
    return c.json({ ...cachedTimeline, days });
  }

  const { results } = await db
    .prepare(
      `
    SELECT
      date(discovered_at) as day,
      COUNT(*) as count,
      SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
    FROM telegram_leak_entries
    ${whereClause}
    GROUP BY date(discovered_at)
    ORDER BY day ASC
  `
    )
    .bind(...params)
    .all();

  // Also get top channels for the period
  const { results: topChannels } = await db
    .prepare(
      `
    SELECT channel_handle, COUNT(*) as count
    FROM telegram_leak_entries
    ${whereClause}
    GROUP BY channel_handle
    ORDER BY count DESC
    LIMIT 10
  `
    )
    .bind(...params)
    .all();

  routeCachePut(timelineCacheKey, { timeline: results, topChannels }, 300).catch(() => {});

  return c.json({ timeline: results, topChannels, days });
}

// ─── Saved Searches CRUD ───

export async function tgSavedSearchesListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const vis = ownerVisibilityFilter(c);
  const { results } = await db
    .prepare(
      `SELECT id, name, query, mode, filters, sort_order, date_range, created_at, updated_at FROM tg_saved_searches WHERE ${vis.clause} ORDER BY updated_at DESC`
    )
    .bind(...vis.bindings)
    .all();

  return c.json({ searches: results });
}

export async function tgSavedSearchCreateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const body = await safeJsonBody<{
    name: string;
    query: string;
    mode?: string;
    filters?: Record<string, unknown>;
    sort_order?: string;
    date_range?: string;
  }>(c, { maxBytes: 4096 });
  if ('error' in body) return body.error;
  if (!body.value.name || !body.value.query) return badRequest(c, 'name and query required');

  const id = genId('tgs');
  const b = body.value;
  await db
    .prepare(
      `
    INSERT INTO tg_saved_searches (id, name, query, mode, filters, sort_order, date_range, created_at, updated_at, owner_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?)
  `
    )
    .bind(
      id,
      b.name,
      b.query,
      b.mode || 'boolean',
      JSON.stringify(b.filters || {}),
      b.sort_order || 'newest',
      b.date_range || '',
      callerOwnerId(c)
    )
    .run();

  const row = await db
    .prepare(
      'SELECT id, name, query, mode, filters, sort_order, date_range, created_at, updated_at FROM tg_saved_searches WHERE id = ?'
    )
    .bind(id)
    .first();
  return c.json(row, 201);
}

export async function tgSavedSearchDeleteHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const id = c.req.param('id');
  const row = await db
    .prepare('SELECT owner_hash FROM tg_saved_searches WHERE id = ?')
    .bind(id)
    .first<{ owner_hash: string | null }>();
  if (!row || ownerCheck(c, row.owner_hash) === 'hidden') return notFound(c, 'not found');
  await db.prepare('DELETE FROM tg_saved_searches WHERE id = ?').bind(id).run();
  return c.json({ success: true });
}
