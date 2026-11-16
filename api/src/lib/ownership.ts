import type { Context } from 'hono';
import type { Env } from './env';
import { requireAdmin } from './admin-auth';

type OwnerCtx = Context<{ Bindings: Env }>;

/**
 * Per-caller ownership for shared playground stores (saved reports,
 * workspaces, copilot/vera sessions, watchlists, …).
 *
 * Model (backward compatible):
 *   - Keyed callers (API key → c.user.keyId) stamp new rows with their key
 *     id and can only see/mutate their own rows plus legacy unowned rows.
 *   - Keyless same-origin callers (the public SPA) have no identity: they
 *     keep today's behavior exactly (shared pool of owner_hash IS NULL rows).
 *   - ADMIN_TOKEN (or admin session cookie) bypasses ownership everywhere,
 *     so the operator retains full visibility.
 *
 * Hidden rows 404 (never 403) so ids can't be probed for existence —
 * this matters for INTEGER-id tables (ioc_watchlist) where ids are
 * enumerable.
 *
 * NOTE: Copilot/Vera chat sessions no longer use this module. They use
 * `lib/visitor.ts`, which gives keyless browsers a per-visitor identity and
 * hides legacy `owner_hash IS NULL` rows instead of sharing them.
 */

export function callerOwnerId(c: OwnerCtx): string | null {
  const user = (c as OwnerCtx & { user?: { keyId?: string } }).user;
  return user?.keyId ?? null;
}

export function isOperator(c: OwnerCtx): boolean {
  return !('error' in requireAdmin(c));
}

/**
 * SQL fragment + binding restricting a listing to visible rows.
 * Returns { clause, bindings } where clause is e.g.
 * `owner_hash IS NULL OR owner_hash = ?` (or `1 = 1` for the operator).
 */
export function ownerVisibilityFilter(c: OwnerCtx, column = 'owner_hash'): { clause: string; bindings: unknown[] } {
  if (isOperator(c)) return { clause: '1 = 1', bindings: [] };
  const owner = callerOwnerId(c);
  if (!owner) return { clause: `${column} IS NULL`, bindings: [] };
  return { clause: `(${column} IS NULL OR ${column} = ?)`, bindings: [owner] };
}

/**
 * Row-level check for get/update/delete. Pass the row's owner_hash (null
 * when the column is absent/NULL). Returns null when visible, or the string
 * 'hidden' when the caller must get a 404. Operator bypasses; legacy NULL
 * rows stay shared.
 */
export function ownerCheck(c: OwnerCtx, rowOwner: string | null | undefined): 'visible' | 'hidden' {
  if (rowOwner == null) return 'visible';
  if (isOperator(c)) return 'visible';
  return callerOwnerId(c) === rowOwner ? 'visible' : 'hidden';
}
