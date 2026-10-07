/**
 * Threat Landscape-style STIX Bundles API.
 *
 * PostgREST-style endpoint for querying STIX 2.1 intelligence bundles.
 *
 * GET /api/v1/stix_bundles
 *   ?select=bundle_id,source_type,threat_actors,malware_names,api_created_at
 *   &source_type=eq.osint
 *   &threat_actors=cs.{APT29}
 *   &sectors=cs.{Healthcare}
 *   &stix_latest_at=gte.2026-01-01T00:00:00Z
 *   &order=api_created_at.desc
 *   &limit=10
 *   &offset=0
 *
 * Range header: Range: 0-9
 *
 * Returns JSON array of matching bundles with Content-Range header.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { badRequest, serviceUnavailable } from '../lib/api-error';
import { parsePostgrestQuery, resolveColumn, type PgFilter } from '../lib/postgrest-filter';

const STIX_BUNDLES_TABLE = 'intel_bundles';

/** Map from API column names to D1 column names. */
const COLUMN_MAP: Record<string, string> = {
  bundle_id: 'id',
  source_type: 'source_type',
  seq_id: 'id',
  title: 'title',
  summary: 'title',
  api_created_at: 'created_at',
  stix_created_at: 'created_at',
  stix_published_at: 'published_at',
  stix_latest_at: 'updated_at',
  threat_actors: 'threat_actor_names',
  malware_names: 'malware_names',
  campaigns: 'campaign_names',
  sectors: 'sector_names',
  countries_target: 'country_targets',
  countries_source: 'country_sources',
  vulnerabilities: 'vulnerability_ids',
  indicators_ipv4: 'indicator_ipv4',
  indicators_ipv6: 'indicator_ipv6',
  indicators_domain: 'indicator_domain',
  indicators_url: 'indicator_url',
  indicators_hash_sha256: 'indicator_sha256',
  victims: 'title',
  attack_patterns: 'title',
  identities: 'source_id',
  intrusion_sets: 'source_id',
  locations: 'country_targets',
};

const DEFAULT_SELECT = [
  'id AS bundle_id',
  'source_id',
  'item_ref',
  'source_type',
  'title',
  'published_at AS stix_published_at',
  'created_at AS api_created_at',
  'updated_at AS stix_latest_at',
  'ioc_count',
  'actor_count',
  'malware_count',
];

/** Build a SELECT expression for requested columns; null when any column is unknown. */
function buildSelectExpression(select?: string[]): string | null {
  if (!select?.length) return DEFAULT_SELECT.join(', ');
  const parts: string[] = [];
  for (const col of select) {
    const dbCol = resolveColumn(COLUMN_MAP, col);
    if (!dbCol) return null;
    parts.push(col === dbCol ? dbCol : `${dbCol} AS ${col}`);
  }
  return parts.join(', ');
}

/**
 * Build the WHERE clause + bindings once and reuse for both the data
 * query and the COUNT query — never string-slice the main SQL (fragile
 * if a value ever contains "WHERE").
 */
function buildBundleWhere(filters: PgFilter[]): { clause: string; bindings: unknown[] } {
  const whereClauses: string[] = [];
  const bindings: unknown[] = [];
  for (const f of filters) {
    // Handler pre-validates every column against COLUMN_MAP; the guard
    // below is defense-in-depth so an unvalidated path fails closed.
    const col = resolveColumn(COLUMN_MAP, f.column);
    if (!col) continue;
    switch (f.op) {
      case 'eq':
        whereClauses.push(`b.${col} = ?`);
        bindings.push(f.value);
        break;
      case 'neq':
        whereClauses.push(`b.${col} != ?`);
        bindings.push(f.value);
        break;
      case 'gt':
        whereClauses.push(`b.${col} > ?`);
        bindings.push(f.value);
        break;
      case 'gte':
        whereClauses.push(`b.${col} >= ?`);
        bindings.push(f.value);
        break;
      case 'lt':
        whereClauses.push(`b.${col} < ?`);
        bindings.push(f.value);
        break;
      case 'lte':
        whereClauses.push(`b.${col} <= ?`);
        bindings.push(f.value);
        break;
      case 'like':
        whereClauses.push(`b.${col} LIKE ?`);
        bindings.push(f.value);
        break;
      case 'ilike':
        whereClauses.push(`LOWER(b.${col}) LIKE LOWER(?)`);
        bindings.push(f.value);
        break;
      case 'is': {
        const v = f.value;
        if (v === null) whereClauses.push(`b.${col} IS NULL`);
        else if (String(v).toLowerCase() === 'not.null') whereClauses.push(`b.${col} IS NOT NULL`);
        else {
          whereClauses.push(`b.${col} = ?`);
          bindings.push(v);
        }
        break;
      }
      case 'in': {
        const arr = f.value as unknown[];
        if (arr.length === 0) {
          whereClauses.push('1 = 0');
          break;
        }
        whereClauses.push(`b.${col} IN (${arr.map(() => '?').join(',')})`);
        bindings.push(...arr);
        break;
      }
      case 'cs': {
        // Array contains: JSON array column (stored as TEXT, e.g. '["APT29"]')
        const arr = f.value as string[];
        if (arr.length === 0) break;
        const subClauses = arr.map(() => `b.${col} LIKE ? ESCAPE '\\'`);
        whereClauses.push(`(${subClauses.join(' AND ')})`);
        for (const v of arr) bindings.push(likeJsonArrayContains(v));
        break;
      }
      case 'cd': {
        // Contains any: JSON array column, match if ANY element matches
        const arr = f.value as string[];
        if (arr.length === 0) break;
        const subClauses = arr.map(() => `b.${col} LIKE ? ESCAPE '\\'`);
        whereClauses.push(`(${subClauses.join(' OR ')})`);
        for (const v of arr) bindings.push(likeJsonArrayContains(v));
        break;
      }
    }
  }
  return {
    clause: whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '',
    bindings,
  };
}

export async function stixBundlesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database_unavailable');

  const query = parsePostgrestQuery(
    new URLSearchParams(c.req.query() as Record<string, string>),
    c.req.header('Range')
  );
  const selectExpr = buildSelectExpression(query.select);
  if (!selectExpr) return badRequest(c, 'unknown column in select');
  // Reject unknown filter/order columns instead of interpolating them.
  for (const f of query.filters) {
    if (!resolveColumn(COLUMN_MAP, f.column)) return badRequest(c, `unknown column "${f.column}"`);
  }
  if (query.order && !resolveColumn(COLUMN_MAP, query.order.column)) {
    return badRequest(c, `unknown column "${query.order.column}"`);
  }

  const { clause: whereClause, bindings } = buildBundleWhere(query.filters);
  let sql = `SELECT ${selectExpr} FROM ${STIX_BUNDLES_TABLE} b`;
  if (whereClause) sql += ` ${whereClause}`;

  // Count query for Content-Range — reuses the same WHERE, no string slicing.
  const countRow = await db
    .prepare(`SELECT COUNT(*) as total FROM ${STIX_BUNDLES_TABLE}${whereClause ? ` ${whereClause}` : ''}`)
    .bind(...bindings)
    .first<{ total: number }>();
  const total = countRow?.total ?? 0;

  // ORDER
  if (query.order) {
    // Pre-validated above; the guard below is defense-in-depth.
    const col = resolveColumn(COLUMN_MAP, query.order.column) ?? 'created_at';
    sql += ` ORDER BY b.${col} ${query.order.dir === 'desc' ? 'DESC' : 'ASC'}`;
  } else {
    sql += ' ORDER BY b.created_at DESC';
  }

  // LIMIT / OFFSET — parsePostgrestQuery only yields finite ints.
  const limit = query.limit ?? 50;
  const offset = query.offset ?? 0;
  sql += ` LIMIT ${limit} OFFSET ${offset}`;

  const rows = await db
    .prepare(sql)
    .bind(...bindings)
    .all();
  const response = c.json(rows.results, 200, {
    'Content-Range': `${offset}-${offset + rows.results.length - 1}/${total}`,
    'Range-Unit': 'items',
  });
  return response;
}

/**
 * Build a LIKE pattern that matches `"value"` inside a stored JSON array, with
 * the pattern's own metacharacters neutralised.
 *
 * These predicates used to bind a pattern escaped only by escapeJsonString with NO
 * `ESCAPE` clause. That escaped only backslash and quote, so `%` and `_` in the
 * caller's value stayed live wildcards: `?threat_actors=cs.{%}` bound `%"%"%`
 * and matched effectively every row, silently turning "contains APT29" into
 * "match anything". The `cd` (OR) variant is worse — one wildcarded element
 * defeats the whole disjunction.
 *
 * The escape character must be declared in the predicate itself (hence
 * `LIKE ? ESCAPE '\'` above) or SQLite applies no escaping at all. This mirrors
 * briefing-builder/build.ts, which already does it correctly.
 *
 * Note the ordering: the escape char is added first so the backslashes this
 * function introduces are not themselves re-escaped.
 */
function likeJsonArrayContains(value: string): string {
  return `%"${value.replace(/[\\%_"]/g, '\\$&')}"%`;
}
