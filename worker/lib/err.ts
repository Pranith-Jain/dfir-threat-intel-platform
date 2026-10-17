/**
 * Re-export of the shared caught-error stringifier for Worker code.
 *
 * `worker/` and `api/src/` are separate deployment surfaces with separate
 * logging conventions, but the `e instanceof Error ? e.message : String(e)`
 * ternary is not a convention — it is the same expression 161 times across 39
 * worker modules, and it belongs in one place exactly like it does in the SPA.
 *
 * Re-exported rather than redefined (same reasoning as
 * `api/src/lib/admin-auth.ts` → `api/src/lib/safe-equal.ts`): one
 * implementation, so the two can never drift, with a stable import path that
 * doesn't reach into the SPA tree from Worker code.
 */
export { errMessage } from '../../src/lib/log';
