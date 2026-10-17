import type { Context, Next } from 'hono';
import type { Env } from '../env';
import { getAllowedOrigins } from './site-config';

/**
 * CSRF protection via origin / referer header validation.
 *
 * For every mutation request (POST, DELETE, PATCH, PUT), checks that the
 * request's `Origin` or `Referer` header matches the canonical origin.
 * This prevents a malicious site from tricking a logged-in operator's
 * browser into issuing a state-changing request (briefing build, admin
 * action, etc.) while they browse another tab.
 *
 * The `X-Admin-Token` header already authenticates mutation endpoints;
 * this middleware adds defence-in-depth against CSRF on top of that.
 *
 * Fail-closed: if the origin cannot be verified, the request is rejected
 * with 403. The only bypass is `Origin` header not being sent AND `Referer`
 * header not being sent, which is extremely rare for browser-initiated
 * mutations (browsers always send `Origin` on cross-origin POST and
 * `Referer` on same-origin mutations).
 *
 * Same-origin policy: for same-origin requests (Origin matches the
 * canonical domain), the request passes. For cross-origin requests
 * (which should never happen for our API since the frontend is on the
 * same domain), the request is rejected. For server-to-server callers
 * (no Origin / Referer headers) the guard passes through.
 *
 * ── Known gap: this guard is NOT an authorization boundary ──────────────
 *
 * Two independent reasons, both current:
 *
 * 1. `authenticate('external-only')` waives the API-key requirement for ANY
 *    same-origin-looking request, including mutations — its `isSameOrigin()`
 *    check runs before any method check. It trusts `Sec-Fetch-Site`,
 *    `Origin`, and `Referer`, all of which any non-browser client can set:
 *
 *      curl -X POST -H 'Sec-Fetch-Site: same-origin' \
 *           https://<host>/api/v1/estate/alerts -d '{...}'   # reaches the handler
 *
 *    This is deliberate, not an oversight: the site is prerendered static
 *    HTML with no capability to hold a secret, and ~128 SPA features POST
 *    to /api/v1/* keylessly. Restricting the exemption to GET/HEAD was
 *    evaluated and measured (it passes the auth suite) but breaks those
 *    callers, so it is not applied.
 *
 * 2. Because of (1), the no-Origin/no-Referer passthrough below is reachable
 *    by a plain unauthenticated POST, so the invariant this file previously
 *    claimed — "every mutation endpoint behind this guard also requires
 *    authentication" — does not hold for /api/v1/* routes under
 *    `external-only`. It DOES still hold for `authenticate('required')`
 *    routes (e.g. /api/v1/admin/*) and for MCP, which authenticates in
 *    `DfirMcpServer.onConnect` before any tool runs.
 *
 * ── What now closes this, and what is still open ─────────────────────────
 *
 * The shared-state write prefixes listed in `api/src/lib/turnstile.ts`
 * (TURNSTILE_PREFIXES: estate, SOC playbooks, saved reports, workspaces,
 * watchlists, campaigns, tool chains, cyberpulse scan, X probe batch) carry an
 * opt-in bot gate ahead of the handler. Once the operator sets
 * `TURNSTILE_SECRET`, a keyless non-browser caller on those routes must either
 * present an API key or clear a real Cloudflare Turnstile challenge — no
 * forgeable header suffices. The gate is off until that secret exists, and the
 * internal-token exemption is HMAC-verified, so it does not reopen the header
 * gap described above.
 *
 * Everything NOT on that prefix list still relies on this header check (CSRF
 * defence-in-depth for browsers) plus the rate limiter. Widening the gate means
 * adding a prefix there AND teaching the SPA caller to send a token — the two
 * halves move together.
 *
 * Genuine protection therefore comes from: `authenticate('required')` on
 * sensitive routes, the Turnstile gate on shared-state writes, rate limiting,
 * and Cloudflare-level controls — not from these headers.
 */
export async function csrfGuard(c: Context<{ Bindings: Env }>, next: Next): Promise<Response | void> {
  const method = c.req.method;
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return next();
  }

  const url = new URL(c.req.url);
  if (!url.pathname.startsWith('/api/v1/') && !url.pathname.startsWith('/api/taxii2/')) {
    return next();
  }

  const allowedOrigins = getAllowedOrigins(c.env as { SITE_URL?: string });

  const origin = c.req.header('Origin');
  const referer = c.req.header('Referer');

  if (origin && allowedOrigins.includes(origin)) {
    return next();
  }

  // Check referer as fallback (browsers always send one of the two).
  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (allowedOrigins.includes(refererOrigin)) {
        return next();
      }
    } catch {
      // Malformed referer — reject.
    }
  }

  // No Origin AND no Referer → this is a server-to-server or CLI request,
  // not a browser-initiated mutation. Browsers always send at least one
  // of these headers on POST/DELETE/PATCH/PUT. Let it through.
  //
  // SECURITY NOTE: this comment previously read "auth (admin token, API key)
  // provides the real protection for non-browser callers". That is accurate
  // only for `authenticate('required')` routes and for MCP. It is NOT accurate
  // for /api/v1/* under `authenticate('external-only')`, whose same-origin
  // exemption also covers mutations and trusts forgeable headers — so this
  // passthrough is reachable with no credential at all. See the "Known gap"
  // section at the top of this file. Kept as-is because removing it would
  // break keyless server-to-server callers; the header check remains useful
  // defence-in-depth against *browser*-initiated cross-site CSRF, which is
  // what this middleware is actually for.
  if (!origin && !referer) {
    return next();
  }

  return c.json(
    {
      error: 'csrf_rejected',
      message: 'invalid origin',
    },
    403,
    { 'cache-control': 'no-store' }
  );
}
