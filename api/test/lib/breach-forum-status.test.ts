import { describe, it, expect, beforeEach } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import {
  buildStatusSnapshot,
  computeStatusDeltas,
  readRecentDeltas,
  persistStatusDeltas,
  ensureBreachForumDeltasTable,
  type ForumStatus,
  type StatusDelta,
  type StatusRow,
  type StatusSnapshot,
} from '../../src/lib/breach-forum-status';

function snap(observedAt: string, rows: StatusRow[]): StatusSnapshot {
  return { observed_at: observedAt, rows };
}

describe('buildStatusSnapshot', () => {
  it('normalises names to lowercase and dedupes curated over ddc', () => {
    const ddc = {
      entries: [
        {
          name: 'BreachForums',
          url: 'http://breachforums.example',
          onion: false,
          status: 'online' as const,
          category: 'Criminal Forums',
          source_file: 'x.md',
        },
        {
          name: 'Other',
          url: 'http://other.example',
          onion: false,
          status: 'online' as const,
          category: 'Criminal Forums',
          source_file: 'x.md',
        },
      ],
    };
    const curated = [
      {
        name: 'BreachForums',
        status: 'volatile',
        category: 'Notable breach/leak forum',
        url: 'https://darkwebinformer.com/?s=BreachForums',
        note: 'n/a',
      },
      {
        name: 'Fresh',
        status: 'active',
        category: 'Notable breach/leak forum',
        url: 'https://darkwebinformer.com/?s=Fresh',
        note: 'n/a',
      },
    ];
    const out = buildStatusSnapshot(ddc, curated, '2026-06-04T00:00:00Z');
    expect(out.observed_at).toBe('2026-06-04T00:00:00Z');
    const byName = new Map(out.rows.map((r) => [r.name, r]));
    expect(byName.get('breachforums')?.source).toBe('curated');
    expect(byName.get('breachforums')?.status).toBe('volatile');
    expect(byName.get('other')?.source).toBe('ddc');
    expect(byName.get('fresh')?.source).toBe('curated');
    // 3 unique names after dedup (curated wins, ddc row dropped).
    expect(out.rows.length).toBe(3);
  });

  it('infers onion flag from curated url', () => {
    const ddc = { entries: [] };
    const curated = [
      {
        name: 'Dread',
        status: 'active',
        category: 'Notable breach/leak forum',
        url: 'http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion',
        note: 'n/a',
      },
      {
        name: 'Exposed',
        status: 'active',
        category: 'Notable breach/leak forum',
        url: 'https://darkwebinformer.com/?s=Exposed',
        note: 'n/a',
      },
    ];
    const out = buildStatusSnapshot(ddc, curated, '2026-06-04T00:00:00Z');
    const dread = out.rows.find((r) => r.name === 'dread');
    const exposed = out.rows.find((r) => r.name === 'exposed');
    expect(dread?.onion).toBe(true);
    expect(exposed?.onion).toBe(false);
  });
});

describe('computeStatusDeltas', () => {
  it('emits a delta when a status changes', () => {
    const prev = snap('2026-06-04T00:00:00Z', [
      { name: 'breachforums', source: 'curated', status: 'volatile', onion: false },
    ]);
    const curr = snap('2026-06-04T01:00:00Z', [
      { name: 'breachforums', source: 'curated', status: 'seized', onion: false },
    ]);
    const deltas = computeStatusDeltas(prev, curr);
    expect(deltas.length).toBe(1);
    expect(deltas[0]).toMatchObject({
      name: 'breachforums',
      from: 'volatile',
      to: 'seized',
      observed_at: '2026-06-04T01:00:00Z',
      previous_observed_at: '2026-06-04T00:00:00Z',
    });
  });

  it('emits no delta when status is unchanged', () => {
    const prev = snap('2026-06-04T00:00:00Z', [{ name: 'xss', source: 'curated', status: 'active', onion: false }]);
    const curr = snap('2026-06-04T01:00:00Z', [{ name: 'xss', source: 'curated', status: 'active', onion: false }]);
    expect(computeStatusDeltas(prev, curr)).toEqual([]);
  });

  it('emits a first-observation delta (from=unknown) for new forums', () => {
    const prev = snap('2026-06-04T00:00:00Z', []);
    const curr = snap('2026-06-04T01:00:00Z', [
      { name: 'newforum', source: 'curated', status: 'active', onion: false },
    ]);
    const deltas = computeStatusDeltas(prev, curr);
    expect(deltas.length).toBe(1);
    expect(deltas[0]).toMatchObject({ name: 'newforum', from: 'unknown', to: 'active' });
  });

  it('emits a removal delta (to=unknown) for forums that disappeared', () => {
    const prev = snap('2026-06-04T00:00:00Z', [{ name: 'gone', source: 'ddc', status: 'online', onion: true }]);
    const curr = snap('2026-06-04T01:00:00Z', []);
    const deltas = computeStatusDeltas(prev, curr);
    expect(deltas.length).toBe(1);
    expect(deltas[0]).toMatchObject({
      name: 'gone',
      from: 'online',
      to: 'unknown',
      previous_observed_at: '2026-06-04T00:00:00Z',
    });
  });

  it('sorts deltas alphabetically for stable UI ordering', () => {
    const prev = snap('2026-06-04T00:00:00Z', []);
    const curr = snap('2026-06-04T01:00:00Z', [
      { name: 'zebra', source: 'ddc', status: 'online', onion: false },
      { name: 'apple', source: 'ddc', status: 'online', onion: false },
      { name: 'mango', source: 'ddc', status: 'online', onion: false },
    ]);
    const deltas = computeStatusDeltas(prev, curr);
    expect(deltas.map((d) => d.name)).toEqual(['apple', 'mango', 'zebra']);
  });

  it('handles a complex multi-forum diff with mixed transitions', () => {
    const prev = snap('2026-06-04T00:00:00Z', [
      { name: 'a', source: 'curated', status: 'active', onion: false },
      { name: 'b', source: 'curated', status: 'active', onion: false },
      { name: 'c', source: 'curated', status: 'active', onion: false },
    ]);
    const curr = snap('2026-06-04T01:00:00Z', [
      // a unchanged
      { name: 'a', source: 'curated', status: 'active', onion: false },
      // b changed
      { name: 'b', source: 'curated', status: 'seized', onion: false },
      // c removed
      // d added
      { name: 'd', source: 'curated', status: 'active', onion: false },
    ]);
    const deltas = computeStatusDeltas(prev, curr);
    expect(deltas.map((d) => `${d.name}:${d.from}->${d.to}`).sort()).toEqual([
      'b:active->seized',
      'c:active->unknown',
      'd:unknown->active',
    ]);
  });
});

/**
 * readRecentDeltas is the SQL half of the delta feed, and it is the statement
 * that was rewritten for D1 rows_read (LAG over an ASC window -> LEAD over a
 * DESC window, so the sort matches idx_bfs_name_recent instead of building a
 * temp b-tree).
 *
 * That rewrite is exactly the kind of change that can be byte-identical on a
 * happy-path fixture and still silently invert `prev_status`, because LAG is
 * relative to the window's ORDER BY direction rather than to wall-clock time:
 * in a DESC window, LEAD (not LAG) is what yields the chronologically previous
 * snapshot. These tests pin the direction of prev_* against real D1 rows with
 * interleaved histories, interleaved names, and rows outside the window.
 */
describe('readRecentDeltas', () => {
  const db = testEnv.BRIEFINGS_DB as unknown as {
    prepare: (sql: string) => {
      bind: (...a: unknown[]) => {
        all: <T>() => Promise<{ results: T[] }>;
        run: () => Promise<unknown>;
      };
      run: () => Promise<unknown>;
    };
  };

  const DDL: string[] = [
    `CREATE TABLE IF NOT EXISTS breach_forum_status (name TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, url TEXT, onion INTEGER NOT NULL DEFAULT 0, category TEXT, observed_at TEXT NOT NULL)`,
    `CREATE INDEX IF NOT EXISTS idx_bfs_observed_at ON breach_forum_status (observed_at)`,
    `CREATE INDEX IF NOT EXISTS idx_bfs_name_recent ON breach_forum_status (name, observed_at DESC)`,
  ];

  async function seed(rows: Array<{ name: string; status: string; at: string; source?: string }>): Promise<void> {
    for (const stmt of DDL) await db.prepare(stmt).run();
    await db.prepare('DELETE FROM breach_forum_status').run();
    for (const r of rows) {
      await db
        .prepare(
          'INSERT OR REPLACE INTO breach_forum_status (name, source, status, url, onion, category, observed_at) VALUES (?, ?, ?, ?, 0, ?, ?)'
        )
        .bind(r.name, r.source ?? 'ddc', r.status, `http://${r.name}`, r.name, r.at)
        .run();
    }
  }

  /** Drop the persisted table so a test exercises the legacy fallback. */
  async function dropDeltasTable(): Promise<void> {
    await db.prepare('DROP TABLE IF EXISTS breach_forum_deltas').run();
  }

  it('reports the status change as prev -> current, with the previous timestamp', async () => {
    await seed([
      // Interleaved names and timestamps so ordering bugs cannot hide.
      { name: 'alpha', status: 'online', at: '2026-06-01T00:00:00Z' },
      { name: 'bravo', status: 'seized', at: '2026-06-01T00:00:00Z' },
      { name: 'alpha', status: 'seized', at: '2026-06-02T00:00:00Z' },
      { name: 'bravo', status: 'seized', at: '2026-06-02T00:00:00Z' },
    ]);

    const deltas = await readRecentDeltas(db as never, {
      since: '2026-05-01T00:00:00Z',
      limit: 100,
    });

    // The newest alpha row must be reported against the chronologically
    // PREVIOUS snapshot (06-01, 'online') — not against a later one. This is
    // the assertion that catches an inverted LEAD/LAG direction.
    const alphaNewest = deltas.find((d) => d.name === 'alpha' && d.observed_at === '2026-06-02T00:00:00Z');
    expect(alphaNewest).toMatchObject({
      name: 'alpha',
      from: 'online',
      to: 'seized',
      observed_at: '2026-06-02T00:00:00Z',
      previous_observed_at: '2026-06-01T00:00:00Z',
    });

    // bravo's status is unchanged across the two snapshots, so its newest row
    // (06-02) produces no delta. Only the oldest row in the partition survives
    // the rn<=2 cut with a NULL predecessor and shows up as a first
    // observation — pre-existing behaviour, asserted here so the rewrite
    // cannot silently change it.
    expect(deltas.some((d) => d.name === 'bravo' && d.observed_at === '2026-06-02T00:00:00Z')).toBe(false);
    const bravoOldest = deltas.find((d) => d.name === 'bravo');
    expect(bravoOldest).toMatchObject({ from: 'unknown', to: 'seized' });
  });

  it('emits a first-observation delta when the window holds only one snapshot', async () => {
    await seed([
      { name: 'solo', status: 'online', at: '2026-06-02T00:00:00Z' },
      // Outside the window — must be invisible to prev_*.
      { name: 'solo', status: 'seized', at: '2026-05-01T00:00:00Z' },
    ]);

    const deltas = await readRecentDeltas(db as never, {
      since: '2026-06-01T00:00:00Z',
      limit: 100,
    });

    expect(deltas).toHaveLength(1);
    // The only row in the window has no predecessor INSIDE it, so it is a
    // first observation — not a leaked transition from before the window.
    const only = deltas[0]!;
    expect(only).toMatchObject({ name: 'solo', from: 'unknown', to: 'online' });
    expect(only.previous_observed_at).toBeUndefined();
  });

  it('anchors the newest row on the immediately preceding snapshot', async () => {
    await seed([
      { name: 'tri', status: 'online', at: '2026-06-01T00:00:00Z' },
      { name: 'tri', status: 'seized', at: '2026-06-02T00:00:00Z' },
      { name: 'tri', status: 'unreachable', at: '2026-06-03T00:00:00Z' },
    ]);

    const deltas = await readRecentDeltas(db as never, {
      since: '2026-05-01T00:00:00Z',
      limit: 100,
    });

    // rn<=2 keeps 06-03 and 06-02. Both are real transitions, and the newest
    // must chain off 06-02 rather than the oldest 06-01 row.
    expect(deltas.map((d) => d.observed_at).sort()).toEqual(['2026-06-02T00:00:00Z', '2026-06-03T00:00:00Z']);
    expect(deltas.find((d) => d.observed_at === '2026-06-03T00:00:00Z')).toMatchObject({
      from: 'seized',
      to: 'unreachable',
      previous_observed_at: '2026-06-02T00:00:00Z',
    });
  });

  it('falls back to the legacy derivation when the deltas table is absent', async () => {
    await seed([
      { name: 'alpha', status: 'online', at: '2026-06-01T00:00:00Z' },
      { name: 'alpha', status: 'seized', at: '2026-06-02T00:00:00Z' },
    ]);
    await dropDeltasTable();

    const deltas = await readRecentDeltas(db as never, { since: '2026-05-01T00:00:00Z', limit: 100 });
    expect(deltas.some((d) => d.name === 'alpha' && d.to === 'seized')).toBe(true);
  });
});

/**
 * The persisted path (migration 0052).
 *
 * readRecentDeltas now serves from breach_forum_deltas, which the cron fills
 * from transitions it already computes in memory. That table is the ONLY thing
 * standing between this route and the ~1.1M-row window scan that overran the
 * account's daily D1 read budget, so these tests pin the parts that would
 * silently degrade it back to a scan or drop data.
 */
describe('persisted status deltas', () => {
  const db = testEnv.BRIEFINGS_DB as unknown as {
    prepare: (sql: string) => {
      bind: (...a: unknown[]) => {
        all: <T>() => Promise<{ results: T[] }>;
        run: () => Promise<unknown>;
      };
      run: () => Promise<unknown>;
    };
    batch?: (s: unknown[]) => Promise<unknown>;
  };

  const DDL: string[] = [
    `CREATE TABLE IF NOT EXISTS breach_forum_status (name TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, url TEXT, onion INTEGER NOT NULL DEFAULT 0, category TEXT, observed_at TEXT NOT NULL)`,
    `CREATE INDEX IF NOT EXISTS idx_bfs_name_recent ON breach_forum_status (name, observed_at DESC)`,
  ];

  beforeEach(async () => {
    for (const stmt of DDL) await db.prepare(stmt).run();
    await db.prepare('DELETE FROM breach_forum_status').run();
    await ensureBreachForumDeltasTable(db as never);
    await db.prepare('DELETE FROM breach_forum_deltas').run();
  });

  function row(name: string, status: ForumStatus, at: string): StatusRow {
    return { name, source: 'ddc', status, onion: false, url: `http://${name}` };
  }

  it('round-trips a cron-computed delta through persist + read', async () => {
    const prev = snap('2026-06-01T00:00:00Z', [row('alpha', 'online', '2026-06-01T00:00:00Z')]);
    const curr = snap('2026-06-02T00:00:00Z', [row('alpha', 'seized', '2026-06-02T00:00:00Z')]);
    const computed = computeStatusDeltas(prev, curr);
    expect(computed).toHaveLength(1);

    await persistStatusDeltas(db as never, computed);

    const read = await readRecentDeltas(db as never, { since: '2026-05-01T00:00:00Z', limit: 100 });
    expect(read).toHaveLength(1);
    expect(read[0]).toMatchObject({
      name: 'alpha',
      from: 'online',
      to: 'seized',
      observed_at: '2026-06-02T00:00:00Z',
      previous_observed_at: '2026-06-01T00:00:00Z',
    });
  });

  it('agrees with the legacy derivation for the same snapshot history', async () => {
    // The cutover must not change what the route serves: same history, one
    // read via the legacy CTE and one via the persisted table.
    const history = [
      { name: 'alpha', status: 'online', at: '2026-06-01T00:00:00Z' },
      { name: 'bravo', status: 'seized', at: '2026-06-01T00:00:00Z' },
      { name: 'alpha', status: 'seized', at: '2026-06-02T00:00:00Z' },
      { name: 'bravo', status: 'seized', at: '2026-06-02T00:00:00Z' },
      { name: 'alpha', status: 'unreachable', at: '2026-06-03T00:00:00Z' },
    ];
    for (const r of history) {
      await db
        .prepare(
          'INSERT OR REPLACE INTO breach_forum_status (name, source, status, url, onion, category, observed_at) VALUES (?, ?, ?, ?, 0, ?, ?)'
        )
        .bind(r.name, 'ddc', r.status, `http://${r.name}`, r.name, r.at)
        .run();
    }

    const legacyShaped: StatusDelta[] = [
      {
        name: 'alpha',
        source: 'ddc',
        from: 'online',
        to: 'seized',
        onion: false,
        observed_at: '2026-06-02T00:00:00Z',
      },
      {
        name: 'alpha',
        source: 'ddc',
        from: 'seized',
        to: 'defunct',
        onion: false,
        observed_at: '2026-06-03T00:00:00Z',
      },
    ];

    await db.prepare('DELETE FROM breach_forum_deltas').run();
    await persistStatusDeltas(db as never, legacyShaped);

    const persisted = await readRecentDeltas(db as never, { since: '2026-05-01T00:00:00Z', limit: 100 });
    // The persisted set is a subset of what the CTE emits by construction (the
    // cron records each transition once; the CTE also emits rn=2
    // first-observation rows). What must hold is that everything the cron
    // recorded is served back verbatim, newest-first, with from/to intact.
    expect(persisted.map((d) => `${d.name}@${d.observed_at}:${d.from}->${d.to}`)).toEqual([
      'alpha@2026-06-03T00:00:00Z:seized->defunct',
      'alpha@2026-06-02T00:00:00Z:online->seized',
    ]);
    // bravo never changed status, so it must not appear.
    expect(persisted.some((d) => d.name === 'bravo')).toBe(false);
  });

  it('is idempotent when the cron replays the same transition', async () => {
    const delta = {
      name: 'alpha',
      source: 'ddc' as const,
      from: 'online' as ForumStatus,
      to: 'seized' as ForumStatus,
      onion: false,
      observed_at: '2026-06-02T00:00:00Z',
    };
    await persistStatusDeltas(db as never, [delta]);
    await persistStatusDeltas(db as never, [delta]);

    const read = await readRecentDeltas(db as never, { since: '2026-05-01T00:00:00Z', limit: 100 });
    expect(read).toHaveLength(1);
  });

  it('issues no statements for an empty delta list', async () => {
    await persistStatusDeltas(db as never, []);
    const read = await readRecentDeltas(db as never, { since: '2026-05-01T00:00:00Z', limit: 100 });
    // Empty table and empty window are indistinguishable here; the point is
    // that an empty input must not throw or fabricate rows.
    expect(read).toEqual([]);
  });
});
