/**
 * Shared logging helpers for frontend catch blocks.
 *
 * Replaces the 293-instance `console.error('handler failed:', e instanceof
 * Error ? e.message : String(e))` boilerplate with a one-liner that's
 * consistent, shorter, and centralises any future log-format changes.
 */

/**
 * Coerce an unknown caught value to a human-readable message string.
 *
 * Mirrors the inline `e instanceof Error ? e.message : String(e)` pattern
 * that was duplicated across every catch block.
 *
 * `fallback` replaces the `String(err)` branch for the sites that used a fixed
 * label for the non-Error case — `e instanceof Error ? e.message : 'no data'`
 * was the second most common shape while deleting the inline ternary.
 */
export function errMessage(err: unknown, fallback?: string): string {
  return err instanceof Error ? err.message : (fallback ?? String(err));
}

/**
 * Log a caught error in a fetch/handler catch block. Kept deliberately
 * non-throwing — every call site is a best-effort log that must not
 * divert the degradation path.
 *
 *   } catch (e) {
 *     logCatch(e);
 *   }
 *
 * Pass an optional context label to disambiguate which handler failed:
 *   logCatch(e, 'telegram-feed');
 */
export function logCatch(err: unknown, context?: string): void {
  const msg = errMessage(err);
  if (context) {
    console.error(`handler failed [${context}]:`, msg);
  } else {
    console.error('handler failed:', msg);
  }
}
