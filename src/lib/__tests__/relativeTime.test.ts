import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { relativeAgo, relativeAgoSeeded, shortRel } from '../relativeTime';

/**
 * `lib/relativeTime.ts` is the shared formatter behind a dozen feed/table rows.
 * It had no tests while nine near-identical private copies of it grew across
 * pages — the copies existed precisely because nothing stopped anyone from
 * writing another one, and each copy drifted (floor vs round, 'now' vs 'just
 * now', date-after-30-days). These pin the contract the pages now rely on.
 */

// Every helper reads the wall clock, so the tests own it: without this the
// assertions silently become "122d ago" the day after they are written — the
// exact time-bomb shape that broke api/test/routes/intel-dashboard.test.ts.
const NOW = Date.parse('2026-06-15T12:00:00Z');
beforeAll(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterAll(() => {
  vi.useRealTimers();
});

const ago = (ms: number) => new Date(NOW - ms).toISOString();

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

describe('relativeAgo', () => {
  it('labels the sub-minute window "just now"', () => {
    expect(relativeAgo(ago(0))).toBe('just now');
    expect(relativeAgo(ago(59_000))).toBe('just now');
  });

  it('floors each unit and appends "ago"', () => {
    expect(relativeAgo(ago(MIN))).toBe('1m ago');
    expect(relativeAgo(ago(90_000))).toBe('1m ago'); // 1.5 min floors, never rounds up
    expect(relativeAgo(ago(59 * MIN))).toBe('59m ago');
    expect(relativeAgo(ago(HOUR))).toBe('1h ago');
    expect(relativeAgo(ago(23 * HOUR))).toBe('23h ago');
    expect(relativeAgo(ago(DAY))).toBe('1d ago');
    expect(relativeAgo(ago(400 * DAY))).toBe('400d ago');
  });

  it('clamps future timestamps to "just now" instead of a negative age', () => {
    // Feed clocks drift; a timestamp 10 minutes in the future must not render
    // as "-10m ago".
    expect(relativeAgo(ago(-10 * MIN))).toBe('just now');
  });

  it('returns the empty label for missing or unparseable input', () => {
    expect(relativeAgo(undefined)).toBe('');
    expect(relativeAgo('')).toBe('');
    expect(relativeAgo('not a date')).toBe('');
    expect(relativeAgo('not a date', 'no timestamp')).toBe('no timestamp');
    expect(relativeAgo(undefined, 'no timestamp')).toBe('no timestamp');
  });

  it('accepts RFC-822 dates, which RSS feeds emit', () => {
    const rfc822 = new Date(NOW - 2 * HOUR).toUTCString();
    expect(relativeAgo(rfc822)).toBe('2h ago');
  });
});

describe('relativeAgoSeeded', () => {
  it('labels the feed builder zero-date sentinel instead of ageing it', () => {
    // The regression this guards: "1970-01-01" formatting honestly would print
    // "20y ago" on every row whose loader had no timestamp.
    expect(relativeAgoSeeded('1970-01-01T00:00:00Z')).toBe('seed');
    expect(relativeAgoSeeded('1970-01-01')).toBe('seed');
  });

  it('labels missing input with the missing label and bad input with the invalid one', () => {
    expect(relativeAgoSeeded(undefined)).toBe('seed');
    expect(relativeAgoSeeded('nonsense')).toBe('unknown');
  });

  it('honours custom labels, for pages that spell them differently', () => {
    expect(relativeAgoSeeded(undefined, { missing: '—' })).toBe('—');
    expect(relativeAgoSeeded('nonsense', { invalid: 'bad date' })).toBe('bad date');
  });

  it('ages every real timestamp exactly like relativeAgo', () => {
    expect(relativeAgoSeeded(ago(5 * MIN))).toBe('5m ago');
    expect(relativeAgoSeeded(ago(3 * DAY))).toBe('3d ago');
  });
});

describe('shortRel', () => {
  it('uses the space-constrained labels, distinct from relativeAgo', () => {
    expect(shortRel(ago(10_000))).toBe('now');
    expect(shortRel(ago(5 * MIN))).toBe('5m ago');
    expect(shortRel(ago(2 * HOUR))).toBe('2h ago');
    expect(shortRel(ago(3 * DAY))).toBe('3d ago');
    expect(shortRel(undefined)).toBe('');
    expect(shortRel('not a date')).toBe('');
  });
});
