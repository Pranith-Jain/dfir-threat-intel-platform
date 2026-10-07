/**
 * Regression tests for GET /api/v1/cyberpulse/stats.
 *
 * This handler used to issue nine independent aggregates over the same
 * trailing window, each re-walking idx_cp_discovered and re-fetching the table
 * row for its grouping column — roughly rows-in-window x 2 rows_read apiece,
 * against a 5M rows/day free-tier budget. It now folds four bounded dimensions
 * into a single tuple GROUP BY and reconstructs the exact marginals in JS.
 *
 * These tests pin the part that is easy to get subtly wrong: the marginals
 * reconstructed in JS must be identical to what the original per-dimension SQL
 * returned, including the NULL-handling that the old `IS NOT NULL` filters
 * implied. A rollup that quietly dropped or double-counted a bucket would be
 * invisible in production and would corrupt the dashboard's numbers.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { env as testEnv, SELF } from 'cloudflare:test';

const db = testEnv.BRIEFINGS_DB as unknown as {
  prepare: (sql: string) => {
    bind: (...a: unknown[]) => { run: () => Promise<unknown> };
    run: () => Promise<unknown>;
  };
};

/**
 * Single-statement, single-line DDL applied via prepare().run().
 *
 * Deliberately not db.exec() with a multi-line blob: D1's exec() splits the
 * payload on statement boundaries and chokes on a CREATE TABLE whose column
 * list spans lines ("incomplete input"). test-helpers.ts uses the same
 * single-line convention for the api_keys table.
 */
const DDL: string[] = [
  `CREATE TABLE IF NOT EXISTS cyberpulse_incidents (id TEXT PRIMARY KEY, incident_type TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', victim_name TEXT, victim_sector TEXT, victim_country TEXT, threat_actor TEXT, source_platform TEXT NOT NULL, discovered_at TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS cyberpulse_scan_log (scanned_at TEXT NOT NULL)`,
];

interface StatsResponse {
  period_days: number;
  total: number;
  by_type: Array<{ incident_type: string; count: number }>;
  by_severity: Array<{ severity: string; count: number }>;
  by_platform: Array<{ source_platform: string; count: number }>;
  by_sector: Array<{ victim_sector: string; count: number }>;
  by_country: Array<{ victim_country: string; count: number }>;
  top_actors: Array<{ threat_actor: string; count: number }>;
  top_victims: Array<{ victim_name: string; count: number }>;
  daily_trend: Array<{ day: string; count: number }>;
  last_scan: string | null;
}

function daysAgoIso(days: number, hourOffset = 0): string {
  return new Date(Date.now() - days * 86_400_000 + hourOffset * 3_600_000).toISOString();
}

async function seed(
  rows: Array<{
    id: string;
    type: string;
    severity: string;
    sector: string | null;
    country: string | null;
    platform: string;
    actor?: string | null;
    victim?: string | null;
    daysAgo: number;
  }>
): Promise<void> {
  for (const r of rows) {
    await db
      .prepare(
        `INSERT INTO cyberpulse_incidents
           (id, incident_type, severity, victim_name, victim_sector, victim_country,
            threat_actor, source_platform, discovered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        r.id,
        r.type,
        r.severity,
        r.victim ?? null,
        r.sector,
        r.country,
        r.actor ?? null,
        r.platform,
        daysAgoIso(r.daysAgo)
      )
      .run();
  }
}

async function getStats(query = ''): Promise<StatsResponse> {
  const res = await SELF.fetch(`https://x/api/v1/cyberpulse/stats${query}`);
  expect(res.status).toBe(200);
  return (await res.json()) as StatsResponse;
}

beforeEach(async () => {
  for (const stmt of DDL) {
    await db.prepare(stmt).run();
  }
  await db.prepare('DELETE FROM cyberpulse_incidents').run();
  await db.prepare('DELETE FROM cyberpulse_scan_log').run();
});

describe('GET /api/v1/cyberpulse/stats — rollup marginals', () => {
  it('reconstructs exact per-dimension marginals from the tuple rollup', async () => {
    await seed([
      // Two rows share (ransomware, critical, telegram, Healthcare).
      {
        id: 'a',
        type: 'ransomware',
        severity: 'critical',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        daysAgo: 1,
      },
      {
        id: 'b',
        type: 'ransomware',
        severity: 'critical',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        daysAgo: 2,
      },
      {
        id: 'c',
        type: 'ransomware',
        severity: 'low',
        sector: 'Healthcare',
        country: 'DE',
        platform: 'telegram',
        daysAgo: 3,
      },
      {
        id: 'd',
        type: 'data_leak',
        severity: 'critical',
        sector: 'Finance',
        country: 'DE',
        platform: 'reddit',
        daysAgo: 1,
      },
      {
        id: 'e',
        type: 'data_leak',
        severity: 'medium',
        sector: 'Finance',
        country: 'FR',
        platform: 'reddit',
        daysAgo: 2,
      },
      // NULL sector — must be excluded from by_sector but still counted in total.
      { id: 'f', type: 'data_leak', severity: 'medium', sector: null, country: null, platform: 'reddit', daysAgo: 2 },
    ]);

    const s = await getStats();

    expect(s.total).toBe(6);

    // Marginal totals must each sum back to `total` for NOT NULL dimensions.
    expect(s.by_type).toEqual([
      { incident_type: 'data_leak', count: 3 },
      { incident_type: 'ransomware', count: 3 },
    ]);
    expect(s.by_severity).toEqual([
      { severity: 'critical', count: 3 },
      { severity: 'medium', count: 2 },
      { severity: 'low', count: 1 },
    ]);
    expect(s.by_platform).toEqual([
      { source_platform: 'reddit', count: 3 },
      { source_platform: 'telegram', count: 3 },
    ]);

    // victim_sector IS NULL for row f: excluded here, per the original
    // `AND victim_sector IS NOT NULL`, but still inside `total`.
    // Ordered descending by count, like every other bucket list.
    expect(s.by_sector).toEqual([
      { victim_sector: 'Healthcare', count: 3 },
      { victim_sector: 'Finance', count: 2 },
    ]);
    const sectorSum = s.by_sector.reduce((a, b) => a + b.count, 0);
    expect(sectorSum).toBe(5);

    // victim_country has its own aggregate (it is unconstrained, so folding it
    // into the tuple would let the group count run away with the row count).
    // DE and US both total 2, so this also pins the tiebreaker: equal counts
    // fall back to ascending key, which is what makes the response stable.
    expect(s.by_country).toEqual([
      { victim_country: 'DE', count: 2 },
      { victim_country: 'US', count: 2 },
      { victim_country: 'FR', count: 1 },
    ]);
  });

  it('does not double-count rows that differ only in an ungrouped column', async () => {
    // a and b are identical across every rollup dimension but differ in
    // victim_name. A naive reconstruction that summed per-group counts once per
    // distinct row would double this bucket.
    await seed([
      {
        id: 'a',
        type: 'ransomware',
        severity: 'critical',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        victim: 'Alpha',
        daysAgo: 1,
      },
      {
        id: 'b',
        type: 'ransomware',
        severity: 'critical',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        victim: 'Beta',
        daysAgo: 1,
      },
    ]);

    const s = await getStats();
    expect(s.total).toBe(2);
    expect(s.by_type).toEqual([{ incident_type: 'ransomware', count: 2 }]);
    expect(s.by_severity).toEqual([{ severity: 'critical', count: 2 }]);
    expect(s.by_sector).toEqual([{ victim_sector: 'Healthcare', count: 2 }]);
  });

  it('orders every bucket list descending by count', async () => {
    await seed([
      {
        id: 'a',
        type: 'ransomware',
        severity: 'low',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        daysAgo: 1,
      },
      {
        id: 'b',
        type: 'ransomware',
        severity: 'low',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        daysAgo: 1,
      },
      {
        id: 'c',
        type: 'data_leak',
        severity: 'critical',
        sector: 'Finance',
        country: 'DE',
        platform: 'reddit',
        daysAgo: 1,
      },
    ]);

    const s = await getStats();
    for (const list of [s.by_type, s.by_severity, s.by_platform, s.by_sector, s.by_country]) {
      const counts = list.map((r) => r.count);
      expect(counts).toEqual([...counts].sort((x, y) => y - x));
    }
    expect(s.by_type[0]!.incident_type).toBe('ransomware');
  });

  it('excludes rows outside the requested window from the rollup', async () => {
    await seed([
      {
        id: 'in',
        type: 'ransomware',
        severity: 'critical',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        daysAgo: 2,
      },
      {
        id: 'out',
        type: 'ransomware',
        severity: 'critical',
        sector: 'Healthcare',
        country: 'US',
        platform: 'telegram',
        daysAgo: 40,
      },
    ]);

    const s = await getStats('?days=30');
    expect(s.period_days).toBe(30);
    expect(s.total).toBe(1);
    expect(s.by_type).toEqual([{ incident_type: 'ransomware', count: 1 }]);
  });

  it('reports zeros for an empty window rather than erroring', async () => {
    const s = await getStats();
    expect(s.total).toBe(0);
    expect(s.by_type).toEqual([]);
    expect(s.by_sector).toEqual([]);
    expect(s.by_country).toEqual([]);
    expect(s.last_scan).toBeNull();
  });
});
