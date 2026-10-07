/**
 * PostgREST-style filter syntax parser and SQL WHERE-builder.
 *
 * Converts query-string filter parameters (eq, neq, gt, lt, cs, cd, in,
 * like, ilike, is, not, or) into parameterised D1 SQL WHERE clauses.
 *
 * Scalar filters:  `column=eq.value`
 * Array filters:   `column=cs.{val1,val2}`
 * Logical groups:  `or=(col1.cs.{X},col2.eq.Y)`
 *
 * Also handles:
 *   `select=col1,col2`  — column list
 *   `order=col.desc`    — ordering
 *   `limit=N`           — row limit
 *   `offset=N`          — row offset
 *   `Range: start-end`  — HTTP Range header
 */

export type PgScalarOp = 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'like' | 'ilike' | 'is' | 'in';
export type PgArrayOp = 'cs' | 'cd';
export type PgFilterOp = PgScalarOp | PgArrayOp;
export type PgLogicalOp = 'and' | 'or' | 'not';

export interface PgFilter {
  column: string;
  op: PgFilterOp;
  value: unknown;
}

export interface PgQuery {
  select?: string[];
  filters: PgFilter[];
  order?: { column: string; dir: 'asc' | 'desc' };
  limit?: number;
  offset?: number;
}

const SAFE_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * True when `name` is a bare SQL identifier (letters/digits/underscore,
 * not starting with a digit). A value passing this check cannot break out
 * of an identifier slot — defense-in-depth behind the per-table column
 * allowlists enforced at each call site via resolveColumn().
 */
export function isSafeSqlIdentifier(name: string): boolean {
  return SAFE_IDENTIFIER_RE.test(name);
}

/**
 * Parse a non-negative integer query param. Returns undefined for
 * missing/garbage/negative/oversized input so callers fall back to their
 * default instead of interpolating NaN into LIMIT/OFFSET (which 500s).
 */
export function parseFiniteInt(raw: string | null | undefined): number | undefined {
  if (raw == null || raw === '') return undefined;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 2147483647) return undefined;
  return n;
}

/**
 * Upper bound on a `Range:`-derived page size.
 *
 * The query-param `limit` path deliberately does not clamp (callers own their
 * own caps), but Range is an alternate route to the same LIMIT clause, so it
 * gets its own ceiling. 1000 comfortably covers the real UI page sizes while
 * keeping a single request from pulling an unbounded slice.
 */
const MAX_RANGE_ROWS = 1000;

/**
 * Resolve an API column name through a per-table allowlist map.
 * Returns the D1 column, or null when the name is unknown or the mapped
 * value is not a safe identifier — callers must reject (400) rather than
 * interpolate the raw value.
 */
export function resolveColumn(columnMap: Record<string, string>, col: string): string | null {
  const mapped = columnMap[col];
  if (!mapped || !isSafeSqlIdentifier(mapped)) return null;
  return mapped;
}

/** Parse a single `column=op.value` filter token. */
function parseFilterToken(key: string, raw: string): PgFilter {
  const dotIdx = raw.indexOf('.');
  if (dotIdx === -1) {
    return { column: key, op: 'eq', value: raw };
  }
  const op = raw.slice(0, dotIdx) as PgFilterOp;
  const valStr = raw.slice(dotIdx + 1);

  if (op === 'in') {
    const inner = valStr.startsWith('(') && valStr.endsWith(')') ? valStr.slice(1, -1) : valStr;
    return {
      column: key,
      op,
      value: inner
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    };
  }
  if (op === 'cs' || op === 'cd') {
    const inner = valStr.startsWith('{') && valStr.endsWith('}') ? valStr.slice(1, -1) : valStr;
    return {
      column: key,
      op,
      value: inner
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    };
  }
  if (op === 'is') {
    if (valStr.toLowerCase() === 'null') return { column: key, op, value: null };
    if (valStr.toLowerCase() === 'not.null') return { column: key, op: 'is', value: valStr };
    return { column: key, op, value: valStr };
  }
  if (op === 'like' || op === 'ilike') {
    return { column: key, op, value: valStr };
  }
  return { column: key, op, value: valStr };
}

/**
 * Parse PostgREST-style query parameters from a URLSearchParams or Headers.
 */
export function parsePostgrestQuery(params: URLSearchParams, rangeHeader?: string | null): PgQuery {
  const q: PgQuery = { filters: [] };

  // select
  const sel = params.get('select');
  if (sel && sel !== '*') q.select = sel.split(',').map((s) => s.trim());

  // order — direction is strictly asc/desc (case-insensitive); anything
  // else falls back to asc so the raw value can never reach SQL verbatim.
  const ord = params.get('order');
  if (ord) {
    const parts = ord.split('.');
    q.order = { column: parts[0] ?? '', dir: parts[1]?.toLowerCase() === 'desc' ? 'desc' : 'asc' };
  }

  // limit / offset — finite non-negative ints only; garbage → undefined
  // (callers apply their defaults).
  const limit = params.get('limit');
  if (limit) q.limit = parseFiniteInt(limit);
  const offset = params.get('offset');
  if (offset) q.offset = parseFiniteInt(offset);

  // Range header
  //
  // `start`/`end` go through parseFiniteInt for the same reason the limit/offset
  // query params do: the derived count is interpolated straight into
  // `LIMIT ${limit} OFFSET ${offset}` by stix-bundles.ts and
  // actionable-iocs.ts, and it is NOT guaranteed non-negative.
  //
  // `Range: 100-1` yields `end - start + 1 === -98`. SQLite reads a negative
  // LIMIT expression as "no upper bound", so that single header used to turn
  // `?limit` into a full-table dump — one request, the entire intel_bundles /
  // actionable_iocs table in the response body. Route it through
  // parseFiniteInt so a reversed or absurd range is discarded and the caller
  // falls back to its default.
  if (rangeHeader) {
    const m = rangeHeader.match(/^(\d+)-(\d+)$/);
    if (m) {
      const start = parseFiniteInt(m[1]!);
      const end = parseFiniteInt(m[2]!);
      if (start !== undefined && end !== undefined) {
        q.offset = q.offset ?? start;
        // Inclusive on both ends, and clamped to a sane maximum: a hostile
        // `Range: 0-2000000000` should not turn into a giant result set either.
        const span = Math.min(end - start + 1, MAX_RANGE_ROWS);
        q.limit = q.limit ?? (span > 0 ? span : undefined);
      }
    }
  }

  // Filter parameters (everything that isn't select/order/limit/offset)
  const reserved = new Set(['select', 'order', 'limit', 'offset']);
  for (const [key, val] of params) {
    if (reserved.has(key)) continue;
    if (key === 'or' || key === 'and') {
      // Logical group — parse the parenthesised group
      const inner = val.startsWith('(') && val.endsWith(')') ? val.slice(1, -1) : val;
      const parts = splitTopLevel(inner);
      for (const p of parts) {
        const [col, rest] = splitFilterToken(p);
        // Delegate to parseFilterToken rather than hand-rolling the filter.
        //
        // The hand-rolled version stored `value: rest` — the RAW "op.value"
        // string — where the scalar path stores a properly typed value (an
        // array for cs/cd/in). Consumers then cast to unknown[] and call
        // `.map()` on it, so `?or=(title.cs.{x})` threw
        // "arr.map is not a function" inside buildBundleWhere, which is not
        // wrapped in try/catch — an unauthenticated 500. The column is still
        // validated downstream by resolveColumn, and the value is still bound,
        // so this only fixes the shape, not the trust model.
        if (col && rest) q.filters.push(parseFilterToken(col, rest));
      }
    } else {
      q.filters.push(parseFilterToken(key, val));
    }
  }

  return q;
}

/** Split a top-level comma-separated list respecting nested parens/braces. */
function splitTopLevel(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '(' || ch === '{') depth++;
    else if (ch === ')' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) {
      parts.push(s.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(s.slice(start).trim());
  return parts.filter(Boolean);
}

/** Split "column.op.value" into column and the rest. */
function splitFilterToken(s: string): [string, string] | [null, null] {
  const dotIdx = s.indexOf('.');
  if (dotIdx === -1) return [null, null];
  return [s.slice(0, dotIdx), s.slice(dotIdx + 1)];
}

export interface SqlWhereClause {
  sql: string;
  bindings: unknown[];
}

/**
 * Build a parameterised SQL WHERE clause + bindings from parsed filters.
 *
 * Supports mapping column names to D1 columns. The `tableAlias` prefix is
 * prepended to column names (e.g. "b.").
 *
 * Array filters (cs, cd) use D1's JSON-EACH based contains matching since
 * the columns store JSON arrays as TEXT.
 */
export function buildWhereClause(
  filters: PgFilter[],
  tableAlias = 'b',
  columnMap: Record<string, string> = {}
): SqlWhereClause {
  const clauses: string[] = [];
  const bindings: unknown[] = [];
  // Strict allowlist: filters on unknown columns are dropped. Callers 400
  // first, so reaching here with one means an unvalidated path — fail
  // closed rather than interpolate.
  for (const f of filters) {
    const mapped = resolveColumn(columnMap, f.column);
    if (!mapped) continue;
    const col = `${tableAlias}.${mapped}`;
    switch (f.op) {
      case 'eq':
        clauses.push(`${col} = ?`);
        bindings.push(f.value);
        break;
      case 'neq':
        clauses.push(`${col} != ?`);
        bindings.push(f.value);
        break;
      case 'gt':
        clauses.push(`${col} > ?`);
        bindings.push(f.value);
        break;
      case 'gte':
        clauses.push(`${col} >= ?`);
        bindings.push(f.value);
        break;
      case 'lt':
        clauses.push(`${col} < ?`);
        bindings.push(f.value);
        break;
      case 'lte':
        clauses.push(`${col} <= ?`);
        bindings.push(f.value);
        break;
      case 'like':
        clauses.push(`${col} LIKE ?`);
        bindings.push(f.value);
        break;
      case 'ilike':
        clauses.push(`LOWER(${col}) LIKE LOWER(?)`);
        bindings.push(f.value);
        break;
      case 'is': {
        const v = f.value;
        if (v === null) clauses.push(`${col} IS NULL`);
        else if (String(v).toLowerCase() === 'not.null') clauses.push(`${col} IS NOT NULL`);
        else {
          clauses.push(`${col} = ?`);
          bindings.push(v);
        }
        break;
      }
      case 'in': {
        const arr = f.value as unknown[];
        if (arr.length === 0) {
          clauses.push('1 = 0');
          break;
        }
        clauses.push(`${col} IN (${arr.map(() => '?').join(',')})`);
        bindings.push(...arr);
        break;
      }
      case 'cs': {
        // Contains: value is present in JSON array column (stored as TEXT)
        const arr = f.value as string[];
        if (arr.length === 0) break;
        const subClauses = arr.map(() => `EXISTS (SELECT 1 FROM json_each(${col}) WHERE value = ?)`);
        clauses.push(`(${subClauses.join(' AND ')})`);
        bindings.push(...arr);
        break;
      }
      case 'cd': {
        // Contained by: all elements of column are in the provided set
        const arr = f.value as string[];
        if (arr.length === 0) break;
        const placeholders = arr.map(() => '?').join(',');
        clauses.push(`NOT EXISTS (SELECT 1 FROM json_each(${col}) j WHERE j.value NOT IN (${placeholders}))`);
        bindings.push(...arr);
        break;
      }
    }
  }

  return {
    sql: clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '',
    bindings,
  };
}

/**
 * Build a full SELECT query from parsed PostgREST parameters.
 * Returns { sql, bindings } ready for D1.
 */
export function buildSelectQuery(
  table: string,
  query: PgQuery,
  options?: {
    tableAlias?: string;
    columnMap?: Record<string, string>;
    defaultSelect?: string[];
  }
): { sql: string; bindings: unknown[] } {
  const alias = options?.tableAlias ?? 'b';
  const cols = options?.columnMap ?? {};
  // Strict allowlist: unknown select columns fall back to the default
  // select rather than interpolating raw input.
  const requested = query.select?.length
    ? query.select.map((c) => resolveColumn(cols, c)).filter((c): c is string => c !== null)
    : [];
  const selectCols = (requested.length > 0 ? requested : (options?.defaultSelect ?? ['*']))
    .map((c) => `${alias}.${c}`)
    .join(', ');

  let sql = `SELECT ${selectCols} FROM ${table} ${alias}`;

  const where = buildWhereClause(query.filters, alias, cols);
  if (where.sql) sql += ` ${where.sql}`;

  if (query.order) {
    const mapped = resolveColumn(cols, query.order.column);
    if (mapped) sql += ` ORDER BY ${alias}.${mapped} ${query.order.dir === 'desc' ? 'DESC' : 'ASC'}`;
  }

  if (Number.isInteger(query.limit) && (query.limit as number) >= 0) sql += ` LIMIT ${query.limit}`;
  if (Number.isInteger(query.offset) && (query.offset as number) >= 0) sql += ` OFFSET ${query.offset}`;

  return { sql, bindings: where.bindings };
}
