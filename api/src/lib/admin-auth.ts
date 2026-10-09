import type { Context, MiddlewareHandler } from 'hono';
import type { Env } from '../env';
import { validateInternalToken, ALLOWED_INTERNAL_CALLERS } from './internal-token';

/**
 * Shared admin gate for mutation endpoints.
 *
 * Accepts the token from EITHER:
 *   - `Authorization: Bearer <token>` (preferred)
 *   - `X-Admin-Token: <token>` (legacy header)
 *   - `admin_session` cookie (HttpOnly, set by /api/v1/admin/session)
 *
 * Backed by the single `ADMIN_TOKEN` Worker secret. One token, all admin
 * surfaces — campaigns, external-resources, telegram custom channels,
 * case-study pipeline, and intel-bundle inspect.
 *
 * TOKEN VERSION: The admin token can be invalidated by incrementing the
 * `ADMIN_TOKEN_VERSION` environment variable (or Worker secret). When set,
 * the session cookie endpoint stamps the version into the cookie, and the
 * auth gate rejects cookies with a stale version. This allows server-side
 * token revocation without rotating the ADMIN_TOKEN secret itself.
 *
 * Caller pattern:
 *
 *   const gate = requireAdmin(c);
 *   if ('error' in gate) return gate.error;
 */

type AdminCtx = Context<{ Bindings: Env }>;

// The implementation lives in a leaf module so Durable Objects and other
// non-Hono callers can import the constant-time compare without pulling Hono +
// Env into their module graph. Re-exported (not redefined) so route call sites
// keep working unchanged and the two can never drift apart.
import { safeEqual } from './safe-equal';
export { safeEqual };

/**
 * Extract a candidate token from the request, checking in order:
 *   1. `Authorization: Bearer <token>` (preferred)
 *   2. `X-Admin-Token: <token>` (legacy header)
 *   3. `admin_session` cookie (HttpOnly, set by /api/v1/admin/session)
 *
 * For cookies, the value may be `token:version` — if a version is set
 * in the env, the cookie version must match or the token is rejected.
 * This allows server-side revocation without rotating the token itself.
 *
 * Returns empty string when none is present.
 */
function extractToken(c: AdminCtx): string {
  const authz = c.req.header('authorization') ?? '';
  const bearer = /^Bearer\s+(.+)$/i.exec(authz)?.[1];
  if (bearer) return bearer;
  const headerToken = c.req.header('x-admin-token');
  if (headerToken) return headerToken;
  // HttpOnly cookie — set by POST /api/v1/admin/session. The browser
  // sends it automatically; JS cannot read it (HttpOnly), so XSS
  // cannot exfiltrate the token from the cookie jar.
  const cookie = c.req.header('cookie') ?? '';
  const match = /(?:^|;\s*)admin_session=([^;]+)/.exec(cookie);
  if (!match?.[1]) return '';
  let rawCookie: string;
  try {
    rawCookie = decodeURIComponent(match[1]);
  } catch {
    return ''; // malformed percent-encoding — reject
  }
  // Cookie format: "token" or "token:version"
  // Only parse version if versioning is configured — otherwise the token
  // itself might contain colons and we'd incorrectly strip them.
  const requiredVersion = c.env.ADMIN_TOKEN_VERSION;
  if (requiredVersion) {
    const lastColon = rawCookie.lastIndexOf(':');
    if (lastColon > 0) {
      const cookieVersion = rawCookie.slice(lastColon + 1);
      if (cookieVersion !== requiredVersion) {
        return ''; // stale version — reject
      }
      return rawCookie.slice(0, lastColon);
    }
    // Versioning enabled but no version in cookie — force re-auth
    return '';
  }
  return rawCookie;
}

export function requireAdmin(c: AdminCtx): { error: Response } | { ok: true } {
  const required = c.env.ADMIN_TOKEN;
  if (!required) {
    return { error: c.json({ error: 'admin endpoint disabled' }, 403) };
  }
  const token = extractToken(c);
  if (!token || !safeEqual(token, required)) {
    return { error: c.json({ error: 'unauthorized' }, 401) };
  }
  return { ok: true };
}

/** Hono middleware version of requireAdmin (for app-level guards). */
export const requireAdminMiddleware: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  // Internal requests from our own Durable Objects bypass admin gate
  // via a signed internal token (HMAC-SHA256, short TTL).
  const internalToken = c.req.header('x-internal-token') ?? '';
  if (internalToken) {
    const result = await validateInternalToken(internalToken, c.env?.INTERNAL_TOKEN_SECRET);
    if (result.ok && ALLOWED_INTERNAL_CALLERS.has(result.caller)) {
      return next();
    }
  }
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;
  await next();
};
