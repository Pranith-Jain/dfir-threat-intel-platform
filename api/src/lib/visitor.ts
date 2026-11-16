import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import type { Env } from './env';
import { requireAdmin } from './admin-auth';

/**
 * Anonymous visitor identity for chat sessions.
 *
 * ## Why this exists
 *
 * The public SPA has no user accounts. Before this module, keyless callers
 * were treated as one shared identity: every anonymous visitor could list,
 * read, and delete every `owner_hash IS NULL` chat session. A random session
 * id was the only thing protecting a conversation, and ids are visible in
 * URLs, browser history, and logs.
 *
 * A cookie gives each browser a stable, unguessable identity without adding
 * accounts. The cookie is:
 *   - HttpOnly (XSS cannot read it),
 *   - Secure (HTTPS only),
 *   - SameSite=Lax (not sent on cross-site subrequests),
 *   - Path=/api (never sent to static assets),
 *   - random 256-bit, stored hashed in `owner_hash` so a DB leak does not
 *     hand out impersonation tokens.
 *
 * The identity is deliberately scoped to chat routes. Other public playground
 * stores (saved reports, watchlists, …) keep their existing shared-pool
 * semantics; changing those is a product decision, not a security fix.
 *
 * API-key callers keep their key id as the owner. The operator (ADMIN_TOKEN /
 * admin session cookie) bypasses ownership entirely.
 */

const VISITOR_COOKIE = 'pj_vid';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 365; // one year
const VISITOR_RE = /^[0-9a-f]{64}$/;

type VisitorCtx = Context<{ Bindings: Env }> & {
  visitorHash?: string;
  user?: { keyId?: string; role?: string };
};

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Ensure the request has a visitor identity. Mount after `authenticate()` so
 * `c.user` is available, and before the chat handlers.
 */
export function visitorIdentity(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    // Preflight requests never need a cookie, and issuing one there would be
    // wasted work.
    if (c.req.method === 'OPTIONS') return next();

    // The operator already has full visibility. Don't mint a visitor cookie
    // for an authenticated admin session.
    if (!('error' in requireAdmin(c))) return next();

    // Keyed callers are identified by their API key; a cookie would be a
    // second, weaker identity.
    if ((c as VisitorCtx).user?.keyId) return next();

    let token = getCookie(c, VISITOR_COOKIE);
    if (!token || !VISITOR_RE.test(token)) {
      token = randomHex(32);
      setCookie(c, VISITOR_COOKIE, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        path: '/api',
        maxAge: COOKIE_MAX_AGE,
      });
    }

    (c as VisitorCtx).visitorHash = await sha256Hex(token);
    await next();
  };
}

/**
 * Owner id for a chat session. API keys keep their existing raw key id so
 * rows created before this change remain visible to the same key. Anonymous
 * visitors are namespaced with `anon:` to avoid colliding with a key id.
 */
export function visitorOwnerId(c: Context<{ Bindings: Env }>): string | null {
  const ctx = c as VisitorCtx;
  if (ctx.user?.keyId) return ctx.user.keyId;
  return ctx.visitorHash ? `anon:${ctx.visitorHash}` : null;
}

/**
 * Listing filter for chat sessions. Legacy rows with `owner_hash IS NULL`
 * are intentionally hidden: they predate per-visitor ownership and cannot
 * be attributed safely. The operator still sees them.
 */
export function visitorVisibilityFilter(
  c: Context<{ Bindings: Env }>,
  column = 'owner_hash'
): { clause: string; bindings: unknown[] } {
  if (!('error' in requireAdmin(c))) return { clause: '1 = 1', bindings: [] };
  const owner = visitorOwnerId(c);
  if (!owner) return { clause: '1 = 0', bindings: [] };
  return { clause: `${column} = ?`, bindings: [owner] };
}

/**
 * Row-level ownership check for chat sessions. Returns false for legacy
 * ownerless rows so an anonymous visitor cannot read another visitor's
 * pre-fix conversation by guessing its id.
 */
export function visitorOwns(c: Context<{ Bindings: Env }>, rowOwner: string | null | undefined): boolean {
  if (!('error' in requireAdmin(c))) return true;
  if (rowOwner == null) return false;
  return visitorOwnerId(c) === rowOwner;
}
