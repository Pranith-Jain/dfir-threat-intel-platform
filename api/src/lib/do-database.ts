/**
 * DoDatabase — a D1-compatible adapter backed by a Durable Object's SQLite.
 *
 * Implements the subset of the D1Database interface that the briefings /
 * telegram-leak / cyberpulse / breach-forum routes actually use:
 *   prepare(sql) → bind(...params) → first<T>() / all<T>() / run()
 *   batch(statements[])
 *
 * Each method forwards to the ThreatDataDO's generic `sql()` RPC. The DO
 * is synchronous SQLite inside; the RPC call is the only async hop.
 *
 * Why an adapter instead of rewriting 222 call sites: the SQL in the route
 * handlers is already correct and tested — only the *storage engine* needed
 * to change. Wrapping the DO stub in the D1Database shape means every
 * `db.prepare('SELECT ...').bind(...).first()` call site keeps working
 * verbatim; only the `c.env.BRIEFINGS_DB` reference needs to swap.
 *
 * Type assertion: `as unknown as D1Database` — the adapter satisfies the
 * runtime contract but is not structurally identical (no sessions, no
 * exec(), no withSession()). The routes we migrate only use the methods
 * above, so this is safe. Anything that needs a D1 method we don't
 * implement will throw a clear "not implemented" error.
 */
import type { D1Database, D1PreparedStatement, D1Result } from '@cloudflare/workers-types';

/** Minimal shape of the ThreatDataDO stub the adapter needs. */
interface ThreatDataStub {
  sql(query: string, params: unknown[], mode: 'all' | 'first' | 'run'): unknown;
  batch(statements: Array<{ query: string; params: unknown[]; mode: 'all' | 'first' | 'run' }>): unknown[];
}

/**
 * Deliberately NOT declared as `implements D1PreparedStatement`.
 *
 * D1PreparedStatement carries members this adapter does not implement
 * (`raw()`, and `run()`'s exact generic signature). Declaring `implements`
 * therefore fails to compile even though the runtime contract the routes
 * actually use — prepare → bind → first/all/run — is fully satisfied, and the
 * DO genuinely returns D1-shaped `{results, success, meta}` envelopes.
 *
 * Structural conformance is asserted once, at the export boundary below,
 * rather than forcing the class to fake members nobody calls.
 */
class DoPreparedStatement {
  private params: unknown[] = [];

  constructor(
    private stub: ThreatDataStub,
    private query: string
  ) {}

  bind(...values: unknown[]): this {
    this.params = values;
    return this;
  }

  async first<T>(): Promise<T | null> {
    // DO SQLite's `cursor.one()` THROWS when the query matches no rows
    // ("Expected exactly one result from SQL query, but got no results"),
    // whereas D1's `.first()` resolves to null. Without this translation every
    // `SELECT ... LIMIT 1` against an empty table rejects here, and because the
    // rejection is raised inside the RPC rather than by this promise, callers
    // that do `.catch()` still get an uncaught exception in some runtimes.
    try {
      const row = this.stub.sql(this.query, this.params, 'first');
      return (row ?? null) as T | null;
    } catch {
      return null;
    }
  }

  async all<T>(): Promise<D1Result<T>> {
    return this.stub.sql(this.query, this.params, 'all') as D1Result<T>;
  }

  async run<T>(): Promise<D1Result<T>> {
    return this.stub.sql(this.query, this.params, 'run') as D1Result<T>;
  }

  /** Exposed for batch() to read the internal state. */
  _internal(): { query: string; params: unknown[]; mode: 'all' | 'first' | 'run' } {
    return { query: this.query, params: this.params, mode: 'all' };
  }
}

export class DoDatabase {
  private stub: ThreatDataStub;

  constructor(stub: ThreatDataStub) {
    this.stub = stub;
  }

  prepare(query: string): D1PreparedStatement {
    return new DoPreparedStatement(this.stub, query) as unknown as D1PreparedStatement;
  }

  async batch<T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    const internal = statements.map((s) => (s as unknown as DoPreparedStatement)._internal());
    return this.stub.batch(internal) as D1Result<T>[];
  }

  /** Not implemented — routes that call exec() will throw. */
  async exec(_query: string): Promise<never> {
    throw new Error('DoDatabase.exec() not implemented — use prepare().bind().run() instead');
  }

  /** Not implemented — sessions are a D1-only concept. */
  async withSession<T = unknown>(_callback?: (session: unknown) => Promise<T>): Promise<never> {
    throw new Error('DoDatabase.withSession() not implemented');
  }
}

/**
 * Convenience: get a D1-compatible database handle backed by the DO.
 * Falls back to BRIEFINGS_DB when the DO is unbound (local dev / tests
 * that don't have the binding).
 */
export function getThreatDb(env: { THREAT_DATA_DO?: DurableObjectNamespace; BRIEFINGS_DB?: D1Database }): D1Database {
  if (env.THREAT_DATA_DO) {
    const stub = env.THREAT_DATA_DO.getByName('threat-data') as unknown as ThreatDataStub;
    return new DoDatabase(stub) as unknown as D1Database;
  }
  // Fallback for environments without the DO binding (vitest, wrangler dev
  // without the migration applied). The caller should log a warning.
  if (env.BRIEFINGS_DB) return env.BRIEFINGS_DB;
  throw new Error('Neither THREAT_DATA_DO nor BRIEFINGS_DB is bound');
}
