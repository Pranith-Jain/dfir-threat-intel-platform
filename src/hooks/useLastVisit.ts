import { useEffect, useState, useCallback } from 'react';

/**
 * Per-page "last visit" tracker, backed by localStorage.
 *
 * Pattern: a page calls useLastVisit('cve-list') on mount → gets back the
 * timestamp of the previous visit (ISO 8601) plus a `markVisited()` fn
 * the page calls AFTER it has computed diffs (so the "new since" highlight
 * uses the OLD timestamp, then we bump it to now for next time).
 *
 * Cross-tab `storage` events keep multiple tabs in sync. If localStorage
 * is unavailable (SSR / private mode), returns null and a no-op so callers
 * can still render without crashing.
 */

const STORAGE_PREFIX = 'dfir.lastvisit.';

export interface LastVisit {
  /** ISO 8601 of the previous visit. Null on first-ever visit. */
  previous: string | null;
  /** Call AFTER computing diffs to advance the marker to now. */
  markVisited: () => void;
}

export function useLastVisit(pageKey: string): LastVisit {
  const storageKey = `${STORAGE_PREFIX}${pageKey}`;
  const [previous, setPrevious] = useState<string | null>(() => {
    if (typeof window === 'undefined') return null;
    try {
      return window.localStorage.getItem(storageKey);
    } catch {
      return null;
    }
  });

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === storageKey) setPrevious(e.newValue);
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [storageKey]);

  const markVisited = useCallback(() => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(storageKey, new Date().toISOString());
    } catch {
      /* ignore quota / private-mode */
    }
  }, [storageKey]);

  return { previous, markVisited };
}

/**
 * Check whether an ISO timestamp is "new since" the previous visit. First-
 * ever visit returns false for everything (no false-positive flood).
 */
export function isNewSince(iso: string | undefined, previous: string | null): boolean {
  if (!previous || !iso) return false;
  const t = Date.parse(iso);
  const p = Date.parse(previous);
  if (Number.isNaN(t) || Number.isNaN(p)) return iso > previous;
  return t > p;
}
