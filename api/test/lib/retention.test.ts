/**
 * Tests for the retention sweep's SQL identifier guard.
 *
 * `table` / `column` cannot be bound as D1 parameters, so they are interpolated
 * into the statement text. The default policy is all hardcoded literals, but
 * `runRetentionSweep` takes a caller-supplied `policy` — this suite pins that an
 * unsafe identifier is rejected BEFORE it reaches the database, rather than
 * relying on every future caller passing only literals (#306).
 */
import { describe, it, expect } from 'vitest';
import type { D1Database } from '@cloudflare/workers-types';
import { runRetentionSweep, RETENTION_POLICY, type RetentionPolicy } from '../../src/lib/retention';

/**
 * Minimal D1 stub: records every prepared statement so a test can assert that a
 * rejected identifier produced NO SQL at all (rather than SQL that D1 would
 * have refused later).
 */
function makeDb(): { db: D1Database; statements: string[] } {
  const statements: string[] = [];
  const db = {
    prepare(sql: string) {
      statements.push(sql);
      const chain = {
        bind: () => chain,
        first: async () => ({ n: 0 }),
        run: async () => ({ meta: { changes: 0 } }),
        all: async () => ({ results: [] }),
      };
      return chain;
    },
  } as unknown as D1Database;
  return { db, statements };
}

const policy = (over: Partial<RetentionPolicy> = {}): RetentionPolicy => ({
  table: 'briefings',
  column: 'created_at',
  format: 'iso',
  ...over,
});

describe('runRetentionSweep identifier guard', () => {
  it('accepts the shipped default policy in full', async () => {
    const { db } = makeDb();
    // Every default entry must pass the guard — otherwise the sweep silently
    // stops sweeping real tables.
    const result = await runRetentionSweep(db, { policy: RETENTION_POLICY });
    const rejected = result.tables.filter((t) => t.error?.startsWith('unsafe'));
    expect(rejected).toEqual([]);
    expect(result.tables).toHaveLength(RETENTION_POLICY.length);
  });

  it('accepts ordinary snake_case identifiers', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, { policy: [policy()] });
    expect(result.tables[0]?.error).toBeUndefined();
    expect(statements.some((s) => s.includes('FROM briefings'))).toBe(true);
  });

  it('rejects a table name carrying a SQL injection payload', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, {
      policy: [policy({ table: 'briefings; DROP TABLE users--' })],
    });
    expect(result.tables[0]?.error).toMatch(/unsafe table identifier/);
    expect(result.total_deleted).toBe(0);
    // The critical assertion: no statement was ever prepared.
    expect(statements).toEqual([]);
  });

  it('rejects a column name carrying a subquery payload', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, {
      policy: [policy({ column: 'created_at < 0) OR (SELECT 1' })],
    });
    expect(result.tables[0]?.error).toMatch(/unsafe column identifier/);
    expect(statements).toEqual([]);
  });

  it('rejects a quoted identifier that could break out of the statement', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, { policy: [policy({ table: '"briefings"' })] });
    expect(result.tables[0]?.error).toMatch(/unsafe table identifier/);
    expect(statements).toEqual([]);
  });

  it('rejects a whitespace/comment payload in the column', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, {
      policy: [policy({ column: 'created_at --' })],
    });
    expect(result.tables[0]?.error).toMatch(/unsafe column identifier/);
    expect(statements).toEqual([]);
  });

  it('rejects an over-long identifier', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, { policy: [policy({ table: 'a'.repeat(65) })] });
    expect(result.tables[0]?.error).toMatch(/unsafe table identifier/);
    expect(statements).toEqual([]);
  });

  it('rejects a non-identifier leading character', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, { policy: [policy({ table: '1briefings' })] });
    expect(result.tables[0]?.error).toMatch(/unsafe table identifier/);
    expect(statements).toEqual([]);
  });

  it('rejects an unknown column format instead of interpolating it', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, {
      policy: [policy({ format: 'bogus' as unknown as RetentionPolicy['format'] })],
    });
    expect(result.tables[0]?.error).toMatch(/unknown format/);
    expect(statements).toEqual([]);
  });

  it('keeps sweeping the valid entries in a mixed policy', async () => {
    const { db, statements } = makeDb();
    const result = await runRetentionSweep(db, {
      policy: [policy({ table: 'bad;table' }), policy({ table: 'cti_iocs' })],
    });
    expect(result.tables).toHaveLength(2);
    expect(result.tables[0]?.error).toMatch(/unsafe table identifier/);
    expect(result.tables[1]?.error).toBeUndefined();
    // Only the safe entry produced SQL.
    expect(statements).toHaveLength(1);
    expect(statements[0]).toContain('cti_iocs');
  });

  it('guards the DELETE path too, not just the dry-run COUNT', async () => {
    const { db, statements } = makeDb();
    await runRetentionSweep(db, {
      dry_run: false,
      policy: [policy({ table: 'x; DELETE FROM api_keys' })],
    });
    // A DELETE-capable statement must never be built from a rejected entry.
    expect(statements.some((s) => s.includes('DELETE'))).toBe(false);
  });

  it('does not count a rejected entry as a swept table', async () => {
    const { db } = makeDb();
    const result = await runRetentionSweep(db, { policy: [policy({ table: 'bad;name' })] });
    expect(result.tables_swept).toBe(0);
    expect(result.total_deleted).toBe(0);
  });
});
