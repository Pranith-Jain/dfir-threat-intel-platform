/**
 * Security regression tests for the PostgREST-style filter layer.
 *
 * The `Range` header is a second, less-hardened route to the same
 * `LIMIT ${limit} OFFSET ${offset}` clause that the `limit`/`offset` query
 * params feed. It used to compute the page size as `end - start + 1` with no
 * non-negative check, so a single header — `Range: 100-1` — produced
 * `LIMIT -98`, which SQLite reads as "no upper bound". One request then dumped
 * the entire intel_bundles / actionable_iocs table.
 *
 * These tests pin the guard so it cannot be quietly removed.
 */

import { describe, it, expect } from 'vitest';
import { parsePostgrestQuery, parseFiniteInt, resolveColumn } from '../../src/lib/postgrest-filter';

describe('parsePostgrestQuery — Range header hardening', () => {
  it('rejects a reversed range instead of emitting a negative LIMIT', () => {
    // The exploit: end < start makes end - start + 1 negative.
    const q = parsePostgrestQuery(new URLSearchParams(), '100-1');
    expect(q.limit).toBeUndefined();
  });

  it('rejects a same-instant zero-width range that yields a non-positive span', () => {
    // end - start + 1 === 0 here; must not be bound as LIMIT 0 or leak a negative.
    const q = parsePostgrestQuery(new URLSearchParams(), '5-4');
    expect(q.limit === undefined || (q.limit as number) > 0).toBe(true);
  });

  it('computes an inclusive page size for a normal range', () => {
    const q = parsePostgrestQuery(new URLSearchParams(), '0-49');
    expect(q.limit).toBe(50);
    expect(q.offset).toBe(0);
  });

  it('clamps an absurd range span to a bounded page size', () => {
    // `Range: 0-2000000000` must not become a giant single-request result set.
    const q = parsePostgrestQuery(new URLSearchParams(), '0-2000000000');
    expect(q.limit).toBe(1000);
  });

  it('leaves an explicit ?limit= authoritative over the Range header', () => {
    const q = parsePostgrestQuery(new URLSearchParams('limit=5'), '0-999');
    expect(q.limit).toBe(5);
  });

  it('ignores a malformed Range header entirely', () => {
    for (const bad of ['', 'abc', '10', '10-', '-10', '10-20-30', '10 - 20']) {
      const q = parsePostgrestQuery(new URLSearchParams(), bad);
      expect(q.limit).toBeUndefined();
      expect(q.offset).toBeUndefined();
    }
  });

  it('never produces a negative limit or offset from any Range input', () => {
    // Property-style sweep across reversed / huge / zero-width ranges.
    for (const range of ['100-1', '9-0', '0-0', '1000-2', '50-10', '2-2']) {
      const q = parsePostgrestQuery(new URLSearchParams(), range);
      if (q.limit !== undefined) expect(q.limit as number).toBeGreaterThan(0);
      if (q.offset !== undefined) expect(q.offset as number).toBeGreaterThanOrEqual(0);
    }
  });
});

describe('parsePostgrestQuery — logical group value shape', () => {
  it('gives cs/cd filters inside or=/and= an array value, not a raw string', () => {
    // The hand-rolled or=/and= path stored `value: "cs.{x}"`. Consumers cast to
    // unknown[] and call .map(), so `?or=(title.cs.{x})` threw
    // "arr.map is not a function" inside buildBundleWhere (not wrapped in
    // try/catch) — an unauthenticated 500.
    const q = parsePostgrestQuery(new URLSearchParams('or=(title.cs.{APT29,LockBit})'));
    expect(q.filters).toHaveLength(1);
    const f = q.filters[0]!;
    expect(f.op).toBe('cs');
    expect(Array.isArray(f.value)).toBe(true);
    expect(f.value).toEqual(['APT29', 'LockBit']);
  });

  it('splits multiple or= clauses into one filter each', () => {
    const q = parsePostgrestQuery(new URLSearchParams('or=(title.cs.{a},severity.eq.critical)'));
    expect(q.filters.map((f) => f.op).sort()).toEqual(['cs', 'eq']);
  });
});

describe('parseFiniteInt', () => {
  it('accepts non-negative integers only', () => {
    expect(parseFiniteInt('0')).toBe(0);
    expect(parseFiniteInt('50')).toBe(50);
    expect(parseFiniteInt('-1')).toBeUndefined();
    expect(parseFiniteInt('1.5')).toBeUndefined();
    expect(parseFiniteInt('abc')).toBeUndefined();
    expect(parseFiniteInt('')).toBeUndefined();
    expect(parseFiniteInt(null)).toBeUndefined();
    expect(parseFiniteInt('1e999')).toBeUndefined(); // Infinity is not an integer
  });
});

describe('resolveColumn — identifier allowlist', () => {
  const map = { title: 'title', created_at: 'created_at' };

  it('resolves a known column', () => {
    expect(resolveColumn(map, 'title')).toBe('title');
  });

  it('rejects unknown columns', () => {
    expect(resolveColumn(map, 'nope')).toBeNull();
    expect(resolveColumn(map, '')).toBeNull();
    expect(resolveColumn(map, 'title; DROP TABLE x')).toBeNull();
  });

  it('rejects prototype keys that would otherwise resolve to a native', () => {
    // columnMap['constructor'] is the Object constructor; stringifying it fails
    // the identifier regex, so it must not be interpolated.
    expect(resolveColumn(map, 'constructor')).toBeNull();
    expect(resolveColumn(map, 'toString')).toBeNull();
    expect(resolveColumn(map, '__proto__')).toBeNull();
  });
});
