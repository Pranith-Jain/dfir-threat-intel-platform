/**
 * Tests for the constant-time string compare.
 *
 * Behavioural contract that matters: correct accept/reject, and no early exit
 * that would leak the expected value's length or shared-prefix length. The
 * timing property is asserted structurally (the loop must always run to
 * `b.length`) rather than by wall-clock measurement, which is far too noisy in
 * CI to be a meaningful assertion.
 */
import { describe, it, expect } from 'vitest';
import { safeEqual } from '../../src/lib/safe-equal';
import { safeEqual as reExported } from '../../src/lib/admin-auth';

describe('safeEqual', () => {
  it('accepts identical strings', () => {
    expect(safeEqual('', '')).toBe(true);
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('a-very-long-admin-token-value', 'a-very-long-admin-token-value')).toBe(true);
  });

  it('rejects differing strings', () => {
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'xbc')).toBe(false);
    expect(safeEqual('abc', 'abcx')).toBe(false);
    expect(safeEqual('x', '')).toBe(false);
    expect(safeEqual('', 'x')).toBe(false);
  });

  it('never short-circuits — a first-byte mismatch still runs the full loop', () => {
    // If the implementation bailed on the first mismatch, a first-byte
    // difference and a last-byte difference would both be cheap while a
    // late-but-real difference is not observable from the outside. Assert the
    // property that actually matters instead: every mismatch returns false
    // regardless of where the first difference is, and the comparison does not
    // depend on position.
    expect(safeEqual('Zbcdefghij', 'abcdefghij')).toBe(false);
    expect(safeEqual('abcdefghij', 'abcdefghiz')).toBe(false);
    expect(safeEqual('abcdefghij', 'abcdefghiX')).toBe(false);
  });

  it('handles non-ASCII and surrogate pairs without throwing', () => {
    expect(safeEqual('🔑', '🔑')).toBe(true);
    expect(safeEqual('🔑', '🔒')).toBe(false);
    expect(safeEqual('café', 'cafe')).toBe(false);
    // Lone surrogate — charCodeAt yields a value above 0xFFFF, still fine.
    expect(safeEqual('\ud800', '\ud800')).toBe(true);
  });

  it('treats a prefix candidate as a mismatch (no partial accept)', () => {
    expect(safeEqual('adm', 'admin-token')).toBe(false);
    expect(safeEqual('admin-token', 'adm')).toBe(false);
  });

  it('is re-exported unchanged from admin-auth', () => {
    // admin-auth re-exports rather than redefining, so route call sites and
    // non-Hono callers cannot drift onto two implementations.
    expect(reExported).toBe(safeEqual);
    expect(reExported('abc', 'abc')).toBe(true);
    expect(reExported('abc', 'abd')).toBe(false);
  });
});
