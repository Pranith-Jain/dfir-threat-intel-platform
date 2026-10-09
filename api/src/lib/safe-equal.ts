/**
 * Constant-time string comparison for secrets and capability tokens.
 *
 * Lives in its own leaf module (no Hono / Env imports) so non-Hono callers —
 * notably Durable Objects under worker/ — can use it without dragging the
 * request framework into their module graph. `admin-auth.ts` re-exports it, so
 * existing `import { safeEqual } from '../lib/admin-auth'` sites are unchanged.
 *
 * WHAT THIS IS FOR: comparing an attacker-supplied candidate against a secret
 * the server holds (admin tokens, internal HMAC tokens, cron lease tokens).
 * `===` bails out on the first differing byte, so response latency correlates
 * with the shared prefix length and lets an attacker recover the secret one
 * byte at a time.
 *
 * WHAT THIS IS NOT FOR: values that are not secrets. Comparing a public crypto
 * token *symbol* (`USDT`), a status enum, or a table name needs no
 * constant-time treatment — `===` is correct and clearer there.
 */

/**
 * Fold the length difference into the accumulator and always iterate over the
 * expected value's (`b`) length, so a wrong-length candidate does not
 * short-circuit and leak the secret's length via response timing.
 * Out-of-range `a.charCodeAt(i)` is NaN, and `NaN | 0 === 0`, so a shorter
 * candidate still runs the full loop.
 */
export function safeEqual(a: string, b: string): boolean {
  let mismatch = a.length ^ b.length;
  for (let i = 0; i < b.length; i += 1) {
    mismatch |= (a.charCodeAt(i) | 0) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
