/**
 * Equivalence tests for the cyberpulse daily rollup.
 *
 * The rollup is only worth having if it returns the SAME numbers as the live
 * GROUP BY queries it replaces. A dashboard that quietly disagrees with its
 * own data is worse than one that is slow, so these tests build a fixture,
 * compute both ways, and compare.
 *
 * Cost context: the live path re-walked cyberpulse_incidents on every request
 * with grouping keys (`DATE(discovered_at)`, `victim_name`, `threat_actor`)
 * that no index can serve — ~105k rows_read/day, 65% of all remaining D1 reads.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import type { D1Database } from '@cloudflare/workers-types';
import { rebuildDailyRollup, readDailyRollup, topN, mergeMaps, ensureDailyRollupTable } from '../../src/lib/cyberpulse-rollup';

const db = testEnv.BRIEFINGS_DB as unknown as D1Database;

interface Incident {
  at: string;
  type?: string;
  sev?: string;
  platform?: string;
  sector?: string | null;
  country?: string | null;
  actor?: string | null;
  victim?: string | null;
}

beforeAll(async () => {
  await db.exec('DROP TABLE IF EXISTS cyberpulse_incidents');
  // Single-line DDL: D1's exec() splits on newlines and fails on multi-line
  // CREATE (same constraint as test-helpers.ts).
  await db.exec(
    `CREATE TABLE cyberpulse_incidents ( id TEXT PRIMARY KEY, discovered_at TEXT NOT NULL, incident_type TEXT, severity TEXT, source_platform TEXT, victim_sector TEXT, victim_country TEXT, threat_actor TEXT, victim_name TEXT)`
  );
  await ensureDailyRollupTable(db);

  // Two "yesterday" days plus a distant day outside any 2-day window, so the
  // windowing logic is actually exercised.
  const rows: Incident[] = [];
  const day = (offset: number): string => new Date(Date.now() - offset * 86_400_000).toISOString().slice(0, 10);

  for (let i = 0; i < 5; i++) {
    rows.push({ at: `${day(1)}T0${i}:00:00Z`, type: 'ransomware', sev: 'critical', platform: 'telegram', sector: 'finance', country: 'RU', actor: 'APT28', victim: 'Acme' });
  }
  for (let i = 0; i < 3; i++) {
    rows.push({ at: `${day(1)}T1${i}:00:00Z`, type: 'exploit', sev: 'high', platform: 'reddit', sector: 'health', country: 'US', actor: null, victim: 'Beta' });
  }
  for (let i = 0; i < 2; i++) {
    rows.push({ at: `${day(2)}T0${i}:00:00Z`, type: 'ransomware', sev: 'critical', platform: 'telegram', sector: null, country: null, actor: 'APT28', victim: 'Acme' });
  }
  // Outside the window — must never be counted.
  rows.push({ at: '2000-01-01T00:00:00Z', type: 'old', sev: 'low', platform: 'x', sector: 'retail', country: 'CN', actor: 'OldActor', victim: 'OldVictim' });

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]!;
    await db
      .prepare(
        `INSERT INTO cyberpulse_incidents (id, discovered_at, incident_type, severity, source_platform,
           victim_sector, victim_country, threat_actor, victim_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(`i${i}`, r.at, r.type ?? null, r.sev ?? null, r.platform ?? null, r.sector ?? null, r.country ?? null, r.actor ?? null, r.victim ?? null)
      .run();
  }
});

describe('cyberpulse daily rollup', () => {
  it('materialises one row per day inside the window', async () => {
    const days = await rebuildDailyRollup(db, 30);
    expect(days).toBe(2); // yesterday and the day before; the 2000 row is excluded
  });

  it('produces the same total as a live COUNT over the window', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const live = await db
      .prepare('SELECT COUNT(*) AS n FROM cyberpulse_incidents WHERE discovered_at > ?')
      .bind(cutoff)
      .first<{ n: number }>();
    const roll = await readDailyRollup(db, cutoff);
    expect(roll!.total).toBe(live!.n);
    expect(roll!.total).toBe(10);
  });

  it('matches the live daily_trend series', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const live = await db
      .prepare(
        `SELECT DATE(discovered_at) as day, COUNT(*) as count FROM cyberpulse_incidents
         WHERE discovered_at > ? GROUP BY DATE(discovered_at) ORDER BY day`
      )
      .bind(cutoff)
      .all<{ day: string; count: number }>();
    const roll = await readDailyRollup(db, cutoff);
    expect(roll!.daily).toEqual(live.results);
  });

  it('matches the live dimension marginals', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    for (const [dim, rollKey] of [
      ['incident_type', 'incident_type'],
      ['severity', 'severity'],
      ['source_platform', 'platform'],
      ['victim_sector', 'sector'],
    ] as const) {
      const live = await db
        .prepare(
          `SELECT ${dim} AS k, COUNT(*) AS count FROM cyberpulse_incidents
           WHERE discovered_at > ? AND ${dim} IS NOT NULL GROUP BY ${dim}`
        )
        .bind(cutoff)
        .all<{ k: string; count: number }>();
      const expected = Object.fromEntries(live.results.map((r) => [r.k, r.count]));
      const roll = await readDailyRollup(db, cutoff);
      expect(roll!.dims[rollKey], `dim ${dim}`).toEqual(expected);
    }
  });

  it('matches the live top victims, capped at 10', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const live = await db
      .prepare(
        `SELECT victim_name, COUNT(*) as count FROM cyberpulse_incidents
         WHERE discovered_at > ? AND victim_name IS NOT NULL GROUP BY victim_name
         ORDER BY count DESC, victim_name ASC LIMIT 10`
      )
      .bind(cutoff)
      .all<{ victim_name: string; count: number }>();
    const roll = await readDailyRollup(db, cutoff);
    expect(topN(roll!.dims.victim, 'victim_name', 10)).toEqual(live.results);
  });

  it('matches the live top actors, capped at 10', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const live = await db
      .prepare(
        `SELECT threat_actor, COUNT(*) as count FROM cyberpulse_incidents
         WHERE discovered_at > ? AND threat_actor IS NOT NULL GROUP BY threat_actor
         ORDER BY count DESC, threat_actor ASC LIMIT 10`
      )
      .bind(cutoff)
      .all<{ threat_actor: string; count: number }>();
    const roll = await readDailyRollup(db, cutoff);
    expect(topN(roll!.dims.actor, 'threat_actor', 10)).toEqual(live.results);
  });

  it('excludes NULLs exactly like the live IS NOT NULL filters', async () => {
    const roll = await readDailyRollup(db, new Date(Date.now() - 30 * 86_400_000).toISOString());
    expect(Object.keys(roll!.dims.sector)).not.toContain('null');
    expect(roll!.dims.sector['finance']).toBe(5);
  });

  it('honours the window — a 1-day window excludes the older day', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 86_400_000).toISOString();
    const roll = await readDailyRollup(db, cutoff);
    expect(roll!.daily).toHaveLength(1);
    expect(roll!.total).toBe(8);
  });

  // The route falls back to live queries on null, so this must return null
  // (not throw) when the rollup has nothing. A FUTURE cutoff matches no
  // bucket_date, which is the "rollup not built yet" case.
  it('returns null when no rollup rows cover the window (route falls back)', async () => {
    const future = await readDailyRollup(db, new Date(Date.now() + 400 * 86_400_000).toISOString());
    expect(future).toBeNull();
  });

  it('is idempotent — rebuilding twice does not double-count', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const first = (await readDailyRollup(db, cutoff))!.total;
    await rebuildDailyRollup(db, 30);
    const second = (await readDailyRollup(db, cutoff))!.total;
    expect(second).toBe(first);
  });

  it('picks up new incidents on rebuild', async () => {
    await rebuildDailyRollup(db, 30);
    const cutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const before = (await readDailyRollup(db, cutoff))!.total;
    await db
      .prepare(
        `INSERT INTO cyberpulse_incidents (id, discovered_at, incident_type, severity, source_platform,
           victim_sector, victim_country, threat_actor, victim_name)
         VALUES ('fresh', ?, 'ransomware', 'critical', 'telegram', 'finance', 'US', 'APT29', 'Zeta')`
      )
      .bind(new Date().toISOString())
      .run();
    await rebuildDailyRollup(db, 30);
    expect((await readDailyRollup(db, cutoff))!.total).toBe(before + 1);
  });
});

describe('rollup helpers', () => {
  it('mergeMaps sums across days', () => {
    expect(mergeMaps([{ a: 1 }, { a: 2, b: 5 }])).toEqual({ a: 3, b: 5 });
  });

  it('topN sorts by count desc then key asc', () => {
    expect(topN({ b: 2, a: 2, c: 5 }, 'k', 10)).toEqual([
      { k: 'c', count: 5 },
      { k: 'a', count: 2 },
      { k: 'b', count: 2 },
    ]);
  });

  it('topN honours the cap', () => {
    expect(topN({ a: 1, b: 2, c: 3 }, 'k', 2)).toHaveLength(2);
  });
});