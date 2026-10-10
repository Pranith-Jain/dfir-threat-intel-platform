/**
 * Equivalence + cost tests for the `/api/v1/saved-reports/correlate` rewrite.
 *
 * The handler used to run one `report_json LIKE ?` statement PER IOC — up to
 * 20 full scans of saved_reports per request, each billed at the whole table
 * because `report_json` is an unindexable JSON blob. It now OR-s the
 * predicates into a single statement (one scan regardless of IOC count) and
 * buckets per-IOC in JS.
 *
 * `referenceCorrelate` below is the OLD implementation, kept verbatim as an
 * oracle. Every equivalence test asserts the new handler agrees with it on
 * real D1 rows, so this suite fails loudly if the rewrite ever changes
 * output rather than just getting cheaper.
 *
 * Run: npx vitest run api/test/routes/saved-reports-correlate.test.ts
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import { Hono } from 'hono';
import { correlateIocs } from '../../src/routes/saved-reports';
import type { Env } from '../../src/env';

const env = testEnv as unknown as Env;
const db = env.BRIEFINGS_DB!;

const app = new Hono<{ Bindings: Env }>();
app.post('/correlate', correlateIocs);

type Correlation = { count: number; reports: Array<{ id: string; title: string; created_at: string }> };
type Correlations = Record<string, Correlation>;

async function callCorrelate(iocs: string[]): Promise<{ correlations: Correlations; searched: number }> {
  const res = await app.request(
    '/correlate',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ iocs }),
    },
    env
  );
  expect(res.status).toBe(200);
  return res.json();
}

/** The pre-rewrite implementation, used as the behavioural oracle. */
async function referenceCorrelate(iocs: string[]): Promise<Correlations> {
  const correlations: Correlations = {};

  for (const ioc of iocs.slice(0, 20)) {
    const { results } = await db
      .prepare(
        `SELECT id, title, created_at, report_json FROM saved_reports
         WHERE report_json LIKE ? AND owner_hash IS NULL ORDER BY created_at DESC LIMIT 10`
      )
      .bind(`%${ioc}%`)
      .all();

    if (results.length > 1) {
      const matches = results.filter((r) => (r.report_json as string).includes(ioc));
      if (matches.length > 1) {
        correlations[ioc] = {
          count: matches.length,
          reports: matches.map((m) => ({
            id: m.id as string,
            title: m.title as string,
            created_at: m.created_at as string,
          })),
        };
      }
    }
  }
  return correlations;
}

/** Assert `ioc` produced a correlation and return it (non-null for TS). */
function corr(out: { correlations: Correlations }, ioc: string): Correlation {
  const c = out.correlations[ioc];
  expect(c, `expected a correlation for ${ioc}`).toBeDefined();
  return c as Correlation;
}

/** Assert `ioc` did NOT produce a correlation. */
function noCorr(out: { correlations: Correlations }, ioc: string): void {
  expect(out.correlations[ioc], `expected no correlation for ${ioc}`).toBeUndefined();
}

async function seed(): Promise<void> {
  await db.exec(`DROP TABLE IF EXISTS saved_reports`);
  // Single-line DDL: D1's exec() splits on newlines and chokes on a
  // multi-line CREATE (see test-helpers.ts, which concatenates for this reason).
  await db.exec(
    `CREATE TABLE saved_reports ( id TEXT PRIMARY KEY, title TEXT NOT NULL, source_url TEXT,` +
      ` report_json TEXT NOT NULL, owner_hash TEXT, created_at TEXT NOT NULL)`
  );
}

async function insert(
  id: string,
  title: string,
  iocs: string[],
  createdAt: string,
  owner: string | null = null
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO saved_reports (id, title, source_url, report_json, owner_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(id, title, 'https://example.test/' + id, JSON.stringify({ iocs }), owner, createdAt)
    .run();
}

describe('correlateIocs', () => {
  beforeEach(async () => {
    await seed();
  });

  it('rejects an empty iocs array', async () => {
    const res = await app.request(
      '/correlate',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ iocs: [] }) },
      env
    );
    expect(res.status).toBe(400);
  });

  it('reports an IOC present in multiple reports, newest first', async () => {
    await insert('r1', 'First', ['1.2.3.4'], '2026-10-01T00:00:00Z');
    await insert('r2', 'Second', ['1.2.3.4'], '2026-10-02T00:00:00Z');
    await insert('r3', 'Third', ['1.2.3.4'], '2026-10-03T00:00:00Z');

    const out = await callCorrelate(['1.2.3.4']);
    expect(corr(out, '1.2.3.4').count).toBe(3);
    expect(corr(out, '1.2.3.4').reports.map((r) => r.id)).toEqual(['r3', 'r2', 'r1']);
  });

  it('omits an IOC that appears in only one report (not a correlation)', async () => {
    await insert('r1', 'First', ['1.2.3.4'], '2026-10-01T00:00:00Z');
    await insert('r2', 'Second', ['9.9.9.9'], '2026-10-02T00:00:00Z');

    const out = await callCorrelate(['1.2.3.4']);
    noCorr(out, '1.2.3.4');
  });

  it("never surfaces another owner's report", async () => {
    await insert('mine', 'Mine', ['5.5.5.5'], '2026-10-01T00:00:00Z');
    await insert('theirs', 'Theirs', ['5.5.5.5'], '2026-10-02T00:00:00Z', 'owner-other');

    const out = await callCorrelate(['5.5.5.5']);
    // Only one visible match -> no correlation at all.
    noCorr(out, '5.5.5.5');
  });

  it('handles several IOCs across several reports', async () => {
    await insert('r1', 'A', ['1.1.1.1', '2.2.2.2'], '2026-10-01T00:00:00Z');
    await insert('r2', 'B', ['1.1.1.1', '3.3.3.3'], '2026-10-02T00:00:00Z');
    await insert('r3', 'C', ['2.2.2.2'], '2026-10-03T00:00:00Z');

    const out = await callCorrelate(['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4']);
    expect(corr(out, '1.1.1.1').count).toBe(2);
    expect(corr(out, '2.2.2.2').count).toBe(2);
    noCorr(out, '3.3.3.3');
    noCorr(out, '4.4.4.4');
    expect(out.searched).toBe(4);
  });

  it('caps each IOC at 10 reports', async () => {
    for (let i = 0; i < 15; i++) {
      await insert(
        `r${String(i).padStart(2, '0')}`,
        `R${i}`,
        ['7.7.7.7'],
        `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00Z`
      );
    }
    const out = await callCorrelate(['7.7.7.7']);
    expect(corr(out, '7.7.7.7').reports).toHaveLength(10);
    // Newest ten.
    expect(corr(out, '7.7.7.7').reports[0]!.id).toBe('r14');
  });

  // The equivalence assertions: same answer as the old per-IOC loop.
  it('matches the original per-IOC loop on a mixed dataset', async () => {
    await insert('r1', 'A', ['1.1.1.1', '2.2.2.2'], '2026-10-01T00:00:00Z');
    await insert('r2', 'B', ['1.1.1.1', '3.3.3.3'], '2026-10-02T00:00:00Z');
    await insert('r3', 'C', ['2.2.2.2', '4.4.4.4'], '2026-10-03T00:00:00Z');
    await insert('r4', 'D', ['4.4.4.4', '5.5.5.5'], '2026-10-04T00:00:00Z');
    await insert('r5', 'E', ['6.6.6.6'], '2026-10-05T00:00:00Z');

    const iocs = ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6'];
    const out = await callCorrelate(iocs);
    expect(out.correlations).toEqual(await referenceCorrelate(iocs));
  });

  it('matches the original loop when an IOC appears in many reports', async () => {
    for (let i = 0; i < 12; i++) {
      await insert(`x${i}`, `X${i}`, ['8.8.8.8'], `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00Z`);
    }
    const out = await callCorrelate(['8.8.8.8']);
    expect(out.correlations).toEqual(await referenceCorrelate(['8.8.8.8']));
  });

  it('matches the original loop when nothing matches', async () => {
    await insert('r1', 'A', ['1.1.1.1'], '2026-10-01T00:00:00Z');
    const out = await callCorrelate(['0.0.0.0']);
    expect(out.correlations).toEqual(await referenceCorrelate(['0.0.0.0']));
    expect(out.correlations).toEqual({});
  });

  it('ignores blank entries in the iocs list', async () => {
    await insert('r1', 'A', ['1.1.1.1'], '2026-10-01T00:00:00Z');
    await insert('r2', 'B', ['1.1.1.1'], '2026-10-02T00:00:00Z');
    const out = await callCorrelate(['', '   ', '1.1.1.1']);
    expect(corr(out, '1.1.1.1').count).toBe(2);
  });
});
