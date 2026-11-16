import { describe, it, expect } from 'vitest';
import type { D1Database, D1PreparedStatement } from '@cloudflare/workers-types';
import { listBriefings } from '../../src/lib/briefing-builder/build';

/**
 * The website listing shows only the last 30 days; GitHub keeps every brief.
 * `listBriefings` implements that as an optional `recentDays` filter (the
 * public route passes 30, admin callers omit it), applied to both COUNT and
 * SELECT so pagination totals cannot disagree with the rows on the page.
 */

interface Query {
  sql: string;
  binds: unknown[];
}

function fakeD1(rows: Array<Record<string, unknown>>): { db: D1Database; queries: Query[] } {
  const queries: Query[] = [];
  const db = {
    prepare(sql: string): D1PreparedStatement {
      const q: Query = { sql, binds: [] };
      queries.push(q);
      const stmt = {
        bind(...params: unknown[]): D1PreparedStatement {
          q.binds = params;
          return stmt as unknown as D1PreparedStatement;
        },
        async first<T>(): Promise<T | null> {
          return { cnt: rows.length } as T;
        },
        async all<T>(): Promise<{ results: T[] }> {
          return { results: rows as T[] };
        },
      };
      return stmt as unknown as D1PreparedStatement;
    },
  } as unknown as D1Database;
  return { db, queries };
}

const row = (slug: string) => ({
  slug,
  type: 'daily',
  title: slug,
  date: slug.slice(-10),
  date_range: slug.slice(-10),
  range_end: slug.slice(-10),
  stats_json: '{}',
  sources_json: '[]',
});

describe('listBriefings recentDays window', () => {
  it('adds a date >= cutoff clause to both count and select when recentDays is set', async () => {
    const { db, queries } = fakeD1([row('daily-2026-11-15')]);
    const out = await listBriefings(db, { recentDays: 30, limit: 20 });

    expect(out.items).toHaveLength(1);
    expect(queries).toHaveLength(2);
    for (const q of queries) {
      expect(q.sql).toContain('date >= ?');
      const cutoff = q.binds.find((v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v));
      expect(cutoff).toBeDefined();
    }
    // Count query must use only the WHERE binds (no LIMIT/OFFSET).
    expect(queries[0]?.binds).toHaveLength(1);
    // Select query appends LIMIT and OFFSET after the cutoff.
    expect(queries[1]?.binds).toHaveLength(3);
  });

  it('does not filter by date when recentDays is omitted (admin sees all)', async () => {
    const { db, queries } = fakeD1([row('daily-2026-07-01'), row('daily-2026-11-15')]);
    const out = await listBriefings(db, { limit: 20 });

    expect(out.items).toHaveLength(2);
    expect(out.total).toBe(2);
    expect(queries.every((q) => !q.sql.includes('date >= ?'))).toBe(true);
  });

  it('combines the window with type and search filters without SQL injection', async () => {
    const { db, queries } = fakeD1([]);
    await listBriefings(db, { type: 'daily', q: "x' OR 1=1 --", recentDays: 30 });

    expect(queries[0]?.sql).toContain('type = ?');
    expect(queries[0]?.sql).toContain('date >= ?');
    expect(queries[0]?.sql).toContain("ESCAPE '\\'");
    // The quote in the search term is only a bound parameter, never SQL text.
    expect(queries[0]?.sql).not.toContain('1=1');
  });
});
