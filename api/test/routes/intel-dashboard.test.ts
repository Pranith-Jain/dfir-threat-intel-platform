/**
 * The intel-dashboard handler used to run three `COUNT(*)` statements over
 * `telegram_leak_entries` — the largest table in the schema — one of them with
 * no WHERE clause at all. D1 bills rows READ, so each request paid the full
 * table size to produce five integers, and on the Free plan the daily read
 * ceiling is a hard account-wide block rather than a billable overage.
 *
 * The counts are now KV-cached (api/src/lib/d1-cache.ts). These tests assert
 * the cache actually short-circuits D1 — a cache that is written but never
 * read back would be pure added cost, and a correct-value assertion alone
 * would not catch that.
 *
 * Run: npx vitest run api/test/routes/intel-dashboard.test.ts
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import { Hono } from 'hono';
import { intelDashboardHandler } from '../../src/routes/intel-dashboard';
import { invalidateD1Cache } from '../../src/lib/d1-cache';
import type { Env } from '../../src/env';

const env = testEnv as unknown as Env;
const db = env.BRIEFINGS_DB!;
const KEY = 'd1cache:v1:intel-dashboard:leak-stats:all';

const app = new Hono<{ Bindings: Env }>();
app.get('/intel-dashboard', intelDashboardHandler);

async function callDashboard(): Promise<Record<string, unknown>> {
  const res = await app.request('/intel-dashboard', {}, env);
  expect(res.status).toBe(200);
  return res.json();
}

beforeAll(async () => {
  await db.exec(`DROP TABLE IF EXISTS telegram_leak_entries`);
  await db.exec(
    `CREATE TABLE telegram_leak_entries ( id INTEGER PRIMARY KEY AUTOINCREMENT, channel_handle TEXT NOT NULL,` +
      ` message_text TEXT, leak_type TEXT, severity TEXT DEFAULT 'medium', discovered_at TEXT NOT NULL,` +
      ` domains_found TEXT DEFAULT '[]')`
  );
  await db.exec(`DROP TABLE IF EXISTS telegram_watched_channels`);
  await db.exec(
    `CREATE TABLE telegram_watched_channels ( id INTEGER PRIMARY KEY, handle TEXT, active INTEGER DEFAULT 0)`
  );
  await db.exec(`DROP TABLE IF EXISTS telegram_discovered_channels`);
  await db.exec(
    `CREATE TABLE telegram_discovered_channels ( id INTEGER PRIMARY KEY, handle TEXT, reviewed INTEGER DEFAULT 0)`
  );
});

beforeEach(async () => {
  await invalidateD1Cache(env, KEY);
  await db.exec(`DELETE FROM telegram_leak_entries`);
  await db.exec(`DELETE FROM telegram_watched_channels`);
  await db.exec(`DELETE FROM telegram_discovered_channels`);
});

async function addLeak(severity: string, discoveredAt: string): Promise<void> {
  await db
    .prepare(
      `INSERT INTO telegram_leak_entries (channel_handle, message_text, leak_type, severity, discovered_at, domains_found)
       VALUES ('chan', 'txt', 'creds', ?, ?, '[]')`
    )
    .bind(severity, discoveredAt)
    .run();
}

/**
 * An ISO-8601 timestamp `daysAgo` days before now, in the format the handler
 * compares against (`datetime('now', '-7 days')`, i.e. UTC to the second).
 *
 * The window assertions used to use hard-coded calendar dates ("inside 7d" was
 * literally 2026-10-05/07). That silently expired: the handler compares against
 * the *current* SQLite clock, so once 2026-10-07 fell outside the 7-day window
 * the suite started failing with `expected 0 to be 2` and would keep failing
 * forever — a time bomb that looked like a handler regression. Relative
 * fixtures keep "inside the window" true whenever the suite runs.
 */
function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 19).replace('T', ' ');
}

describe('intelDashboardHandler', () => {
  it('returns zeroed counters on an empty schema', async () => {
    const body = await callDashboard();
    const m = body.telegram_monitor as Record<string, number>;
    expect(m.total_leaks).toBe(0);
    expect(m.leaks_24h).toBe(0);
    expect(body.leaks_7d).toBe(0);
  });

  /**
   * NOTE ON TIMESTAMP COMPARISON — a pre-existing bug this test pins down
   * rather than hides.
   *
   * `discovered_at` is stored ISO-with-T/Z (the schema default is
   * `strftime('%Y-%m-%dT%H:%M:%SZ','now')`) but the query compares it to
   * `datetime('now', ...)`, which SQLite renders space-separated
   * ('2026-10-09 18:18:25'). That comparison is LEXICOGRAPHIC, and at index 10
   * the stored 'T' (0x54) always beats the cutoff's ' ' (0x20) — so on any
   * pair that shares a calendar date, the row counts as "newer" than the
   * cutoff regardless of the actual time of day.
   *
   * Net effect: `leaks_24h` OVERCOUNTS, by including up to a further 24h of
   * rows from yesterday that predate the current time-of-day.
   *
   * This is a correctness bug, not a performance one, so it is deliberately
   * NOT fixed here — fixing it silently changes a published number and
   * deserves its own change. The fixtures below use timestamps that are whole
   * days apart, where the lexicographic and chronological orderings agree, so
   * this suite measures the cache behaviour without depending on the bug.
   */
  it('counts total and the 7-day window', async () => {
    await addLeak('high', daysAgo(2)); // within 7d
    await addLeak('low', daysAgo(4)); // within 7d
    await addLeak('low', daysAgo(30)); // outside both windows

    const body = await callDashboard();
    const m = body.telegram_monitor as Record<string, number>;
    expect(m.total_leaks).toBe(3);
    expect(body.leaks_7d).toBe(2);
  });

  it('counts watched and unreviewed channels', async () => {
    await db.prepare(`INSERT INTO telegram_watched_channels (handle, active) VALUES ('a', 1)`).run();
    await db.prepare(`INSERT INTO telegram_watched_channels (handle, active) VALUES ('b', 0)`).run();
    await db.prepare(`INSERT INTO telegram_discovered_channels (handle, reviewed) VALUES ('c', 0)`).run();
    await db.prepare(`INSERT INTO telegram_discovered_channels (handle, reviewed) VALUES ('d', 1)`).run();

    const m = (await callDashboard()).telegram_monitor as Record<string, number>;
    expect(m.watched_channels).toBe(1);
    expect(m.unreviewed_channels).toBe(1);
  });

  // The core saving: the second request must be served without touching D1.
  it('serves a repeat request from cache without re-querying D1', async () => {
    await addLeak('high', daysAgo(1));
    await callDashboard();

    expect((await db.prepare(`SELECT COUNT(*) as n FROM telegram_leak_entries`).first<{ n: number }>())!.n).toBe(1);

    // Prove the cache path: delete the underlying rows entirely. A cached read
    // still reports 1; an uncached read would report 0.
    await db.exec(`DELETE FROM telegram_leak_entries`);
    const m = (await callDashboard()).telegram_monitor as Record<string, number>;
    expect(m.total_leaks).toBe(1);
  });

  it('reflects new rows after the cache is invalidated', async () => {
    await addLeak('high', daysAgo(1));
    expect(((await callDashboard()).telegram_monitor as Record<string, number>).total_leaks).toBe(1);

    await invalidateD1Cache(env, KEY);
    await addLeak('low', daysAgo(2));
    expect(((await callDashboard()).telegram_monitor as Record<string, number>).total_leaks).toBe(2);
  });
});
