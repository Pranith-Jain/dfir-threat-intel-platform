/**
 * Unit tests for the cyberpulse stats rollup reconstruction.
 *
 * `buildMarginals` is the one piece of non-trivial logic in the
 * /api/v1/cyberpulse/stats rewrite: it turns a tuple-grouped rollup back into
 * the per-dimension buckets the dashboard renders. Getting it subtly wrong is
 * invisible in review and silently corrupts the numbers on screen, so it is
 * tested directly as a pure function.
 *
 * Deliberately a direct module import rather than going through SELF.fetch:
 * this exercises the arithmetic without booting the whole Worker, which keeps
 * the test fast and independent of unrelated route wiring.
 *
 * The companion integration test (cyberpulse-stats.test.ts) covers the HTTP
 * surface — window filtering, response shape and the empty-window case.
 */

import { describe, it, expect } from 'vitest';
import { buildMarginals, type RollupRow } from '../../src/routes/cyberpulse';

function row(partial: Partial<RollupRow> & { n: number }): RollupRow {
  return {
    incident_type: null,
    severity: null,
    source_platform: null,
    victim_sector: null,
    ...partial,
  };
}

/**
 * buildMarginals returns `Record<dim, unknown[]>` because each bucket is an
 * object keyed by its own dimension name. These helpers narrow once so the
 * assertions below stay readable instead of casting at every call site.
 */
type Bucket = Record<string, string | number>;
const countsOf = (list: unknown[]): unknown[] => (list as Bucket[]).map((b) => b.count);
const valuesOf = (list: unknown[], key: string): unknown[] => (list as Bucket[]).map((b) => b[key]);

describe('buildMarginals', () => {
  it('sums a dimension across every tuple that shares its key', () => {
    // (ransomware, critical, telegram, Healthcare) appears twice with different
    // country values — country is NOT in the rollup, so both rows must still
    // contribute to by_type/by_severity/by_platform/by_sector.
    const m = buildMarginals([
      row({
        incident_type: 'ransomware',
        severity: 'critical',
        source_platform: 'telegram',
        victim_sector: 'Healthcare',
        n: 5,
      }),
      row({
        incident_type: 'ransomware',
        severity: 'critical',
        source_platform: 'telegram',
        victim_sector: 'Healthcare',
        n: 3,
      }),
    ]);

    expect(m.incident_type).toEqual([{ incident_type: 'ransomware', count: 8 }]);
    expect(m.severity).toEqual([{ severity: 'critical', count: 8 }]);
    expect(m.source_platform).toEqual([{ source_platform: 'telegram', count: 8 }]);
    expect(m.victim_sector).toEqual([{ victim_sector: 'Healthcare', count: 8 }]);
  });

  it('drops NULL keys, preserving the original IS NOT NULL semantics', () => {
    const m = buildMarginals([
      row({
        incident_type: 'data_leak',
        severity: 'medium',
        source_platform: 'reddit',
        victim_sector: 'Finance',
        n: 2,
      }),
      row({ incident_type: 'data_leak', severity: 'medium', source_platform: 'reddit', victim_sector: null, n: 4 }),
    ]);

    expect(m.victim_sector).toEqual([{ victim_sector: 'Finance', count: 2 }]);
    // The dropped row is still counted on the dimensions that were populated.
    expect(m.incident_type).toEqual([{ incident_type: 'data_leak', count: 6 }]);
  });

  it('does not merge distinct keys that merely share a count', () => {
    const m = buildMarginals([row({ incident_type: 'ransomware', n: 3 }), row({ incident_type: 'data_leak', n: 3 })]);
    // Same count, so the tiebreaker (ascending key) decides: data_leak first.
    expect(m.incident_type).toEqual([
      { incident_type: 'data_leak', count: 3 },
      { incident_type: 'ransomware', count: 3 },
    ]);
  });

  it('returns each bucket list ordered by descending count, then by key', () => {
    const m = buildMarginals([
      row({ incident_type: 'a', severity: 'low', n: 1 }),
      row({ incident_type: 'b', severity: 'high', n: 9 }),
      row({ incident_type: 'c', severity: 'medium', n: 5 }),
      row({ incident_type: 'd', severity: 'critical', n: 7 }),
    ]);

    expect(countsOf(m.incident_type)).toEqual([9, 5, 7, 1].sort((x, y) => y - x));
    expect(valuesOf(m.severity, 'severity')).toEqual(['high', 'critical', 'medium', 'low']);
  });

  it('breaks count ties by ascending key so output is deterministic', () => {
    // SQL's bare `ORDER BY count DESC` left ties in scan order, which made the
    // dashboard's top-N lists able to reshuffle between identical requests.
    const m = buildMarginals([
      row({ incident_type: 'zebra', n: 4 }),
      row({ incident_type: 'alpha', n: 4 }),
      row({ incident_type: 'mango', n: 4 }),
      row({ incident_type: 'beta', n: 1 }),
    ]);

    expect(m.incident_type).toEqual([
      { incident_type: 'alpha', count: 4 },
      { incident_type: 'mango', count: 4 },
      { incident_type: 'zebra', count: 4 },
      { incident_type: 'beta', count: 1 },
    ]);
  });

  it('keys each output object by its own dimension name', () => {
    // The reducer builds objects with a computed key, so a copy/paste slip here
    // would silently emit every bucket under the wrong column name.
    const m = buildMarginals([
      row({ incident_type: 'x', severity: 'y', source_platform: 'z', victim_sector: 'w', n: 1 }),
    ]);
    expect(Object.keys(m.incident_type[0] as object)).toEqual(['incident_type', 'count']);
    expect(Object.keys(m.severity[0] as object)).toEqual(['severity', 'count']);
    expect(Object.keys(m.source_platform[0] as object)).toEqual(['source_platform', 'count']);
    expect(Object.keys(m.victim_sector[0] as object)).toEqual(['victim_sector', 'count']);
  });

  it('emits numeric counts', () => {
    const m = buildMarginals([row({ incident_type: 'x', n: 4 })]);
    expect(typeof (m.incident_type[0] as { count: unknown }).count).toBe('number');
  });

  it('handles an empty rollup without throwing', () => {
    const m = buildMarginals([]);
    expect(m.incident_type).toEqual([]);
    expect(m.severity).toEqual([]);
    expect(m.source_platform).toEqual([]);
    expect(m.victim_sector).toEqual([]);
  });
});
