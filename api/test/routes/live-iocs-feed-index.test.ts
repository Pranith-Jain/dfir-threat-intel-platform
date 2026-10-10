/**
 * Regression tests for the `/api/v1/live-iocs` feed-scheduler graph query.
 *
 * The query used to be:
 *     WHERE json_extract(sources, '$[0]') LIKE 'feed:%'
 *     ORDER BY last_seen DESC LIMIT ?
 *
 * which is a JSON function over an unindexed column — a guaranteed full scan
 * of graph_nodes on every compose of the flagship /threatintel surface, plus a
 * temp B-tree sort because `last_seen` had no index.
 *
 * It is now an equality on a 5-char prefix, which an expression index can
 * serve. Two properties must hold and are asserted here against real D1:
 *
 *   1. EQUIVALENCE — the new predicate selects exactly the rows the old one
 *      did. A perf rewrite that silently drops or adds IOCs would be far worse
 *      than the scan it replaced.
 *   2. THE INDEX IS ACTUALLY USED — not merely created. This is the
 *      non-obvious part: SQLite only applies its LIKE optimization to an
 *      indexed column when `case_sensitive_like` is ON, and D1 does not
 *      guarantee that pragma, so the LIKE form would have left the plan a
 *      full SCAN even with the index present.
 *
 * Run: npx vitest run api/test/routes/live-iocs-feed-index.test.ts
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import type { Env } from '../../src/env';

const env = testEnv as unknown as Env;
const db = env.BRIEFINGS_DB!;

const OLD_PREDICATE = `json_extract(sources, '$[0]') LIKE 'feed:%'`;
const NEW_PREDICATE = `substr(json_extract(sources, '$[0]'), 1, 5) = 'feed:'`;

/** Mirrors api/src/routes/threat-graph.ts ensureGraphTables. */
const DDL = [
  `CREATE TABLE IF NOT EXISTS graph_nodes ( id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, properties TEXT DEFAULT '{}', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, confidence INTEGER DEFAULT 50, sources TEXT DEFAULT '[]')`,
  `CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(type)`,
  `CREATE INDEX IF NOT EXISTS idx_nodes_value ON graph_nodes(value)`,
  // migration 0053
  `CREATE INDEX IF NOT EXISTS idx_nodes_feed_last_seen ON graph_nodes(substr(json_extract(sources, '$[0]'), 1, 5), last_seen DESC)`,
];

async function insertNode(id: string, sources: string, lastSeen: string, type = 'ip'): Promise<void> {
  await db
    .prepare(
      `INSERT OR REPLACE INTO graph_nodes (id, type, value, properties, first_seen, last_seen, confidence, sources)
       VALUES (?, ?, ?, '{}', ?, ?, 50, ?)`
    )
    .bind(id, type, `val-${id}`, '2026-09-01T00:00:00Z', lastSeen, sources)
    .run();
}

beforeAll(async () => {
  await db.exec(`DROP TABLE IF EXISTS graph_nodes`);
  for (const stmt of DDL) await db.exec(stmt);

  // Feed-scheduler nodes: first source is `feed:<name>` (feed-scheduler.ts:548).
  for (let i = 0; i < 10; i++) {
    await insertNode(
      `feed-${i}`,
      JSON.stringify([`feed:blocklist-${i}`]),
      `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00Z`
    );
  }
  // Feed source present but NOT first — the old `$[0]` semantics must skip these.
  for (let i = 0; i < 5; i++) {
    await insertNode(`second-${i}`, JSON.stringify([`apt:apt${i}`, `feed:otx-${i}`]), '2026-10-20T00:00:00Z');
  }
  // Non-feed nodes, deliberately carrying the newest timestamps so that a
  // broken predicate cannot pass by accident.
  for (let i = 0; i < 5; i++) {
    await insertNode(
      `apt-${i}`,
      JSON.stringify([`apt:apt${i}`]),
      `2026-10-${String(25 + i).padStart(2, '0')}T00:00:00Z`
    );
  }
  // Edge cases: empty array and a bare null element.
  await insertNode('empty-array', '[]', '2026-10-28T00:00:00Z');
  await insertNode('null-elem', '[null]', '2026-10-29T00:00:00Z');
});

describe('live-iocs feed query', () => {
  it('new predicate selects exactly the same rows as the old LIKE', async () => {
    const oldRows = await db
      .prepare(`SELECT id FROM graph_nodes WHERE ${OLD_PREDICATE} ORDER BY last_seen DESC`)
      .all<{ id: string }>();
    const newRows = await db
      .prepare(`SELECT id FROM graph_nodes WHERE ${NEW_PREDICATE} ORDER BY last_seen DESC`)
      .all<{ id: string }>();

    expect(newRows.results.map((r) => r.id).sort()).toEqual(oldRows.results.map((r) => r.id).sort());
    // Sanity: the fixture really does contain feed nodes.
    expect(oldRows.results.length).toBe(10);
  });

  it('only matches when the FIRST source is a feed source', async () => {
    const rows = await db
      .prepare(`SELECT id FROM graph_nodes WHERE ${NEW_PREDICATE} ORDER BY id`)
      .all<{ id: string }>();
    // 'second-N' have feed: as sources[1], which the $[0] rule excludes.
    expect(rows.results.every((r) => r.id.startsWith('feed-'))).toBe(true);
    expect(rows.results).toHaveLength(10);
  });

  it('excludes empty and null-element sources without erroring', async () => {
    const rows = await db
      .prepare(`SELECT id FROM graph_nodes WHERE id IN ('empty-array','null-elem') AND ${NEW_PREDICATE}`)
      .all<{ id: string }>();
    expect(rows.results).toHaveLength(0);
  });

  it('orders newest-first and honours LIMIT', async () => {
    const rows = await db
      .prepare(`SELECT value, last_seen FROM graph_nodes WHERE ${NEW_PREDICATE} ORDER BY last_seen DESC LIMIT ?`)
      .bind(3)
      .all<{ value: string; last_seen: string }>();
    expect(rows.results).toHaveLength(3);
    const dates = rows.results.map((r) => r.last_seen);
    expect([...dates].sort().reverse()).toEqual(dates);
  });

  // The load-bearing assertion: with the index present, the new predicate must
  // plan as an index SEARCH. If someone reverts to LIKE, this flips to SCAN and
  // fails here rather than silently reintroducing the full-table scan.
  it('uses idx_nodes_feed_last_seen instead of scanning', async () => {
    const plan = await db
      .prepare(
        `EXPLAIN QUERY PLAN SELECT value, type, sources, last_seen, properties FROM graph_nodes WHERE ${NEW_PREDICATE} ORDER BY last_seen DESC LIMIT ?`
      )
      .bind(50)
      .all<{ detail: string }>();
    const text = plan.results.map((r) => r.detail).join(' | ');

    expect(text).toContain('idx_nodes_feed_last_seen');
    expect(text).toMatch(/SEARCH/i);
    // The temp B-tree sorter is what made the old query expensive on top of
    // the scan; the composite index supplies the ordering directly.
    expect(text).not.toMatch(/TEMP B-TREE/i);
    expect(text).not.toMatch(/^SCAN|SCAN graph_nodes/i);
  });

  it('confirms the old LIKE form still plans as scan + sorter (why the rewrite was needed)', async () => {
    const plan = await db
      .prepare(
        `EXPLAIN QUERY PLAN SELECT value FROM graph_nodes WHERE ${OLD_PREDICATE} ORDER BY last_seen DESC LIMIT ?`
      )
      .bind(50)
      .all<{ detail: string }>();
    const text = plan.results.map((r) => r.detail).join(' | ');

    // Verified against the real D1 SQLite build: even with
    // idx_nodes_feed_last_seen present, the LIKE form is NOT index-served,
    // because SQLite only applies the LIKE optimization to an indexed column
    // when `case_sensitive_like` is ON and D1 leaves it at its default.
    //
    // This is the canary: if a future SQLite or D1 changes that default and
    // the LIKE form becomes index-served, this assertion fails and the
    // comment above can be retired along with the reason for the rewrite.
    expect(text).toMatch(/SCAN graph_nodes/i);
    expect(text).toMatch(/TEMP B-TREE/i);
  });
});
