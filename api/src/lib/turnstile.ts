import type { Context, MiddlewareHandler, Next } from 'hono';
import type { Env } from '../env';
import { ALLOWED_INTERNAL_CALLERS, validateInternalToken } from './internal-token';

/**
 * Turnstile bot gate for keyless mutations.
 *
 * ## Why this exists
 *
 * `authenticate('external-only')` (lib/auth.ts) grants the same-origin
 * exemption when a request carries `Origin`, `Referer`, or
 * `Sec-Fetch-Site: same-origin`, and `csrfGuard` passes a mutation that
 * carries none of them. Those headers are the right CSRF defence against a
 * hostile *browser* and the wrong authorisation defence against anything else:
 * a script with a socket can set any header, so every route that is merely
 * "same-origin OR valid API key" is reachable with zero credentials. The
 * routes listed in TURNSTILE_PREFIXES are the ones where that actually costs
 * something — they write shared, single-tenant state (estate config, SOC
 * playbooks, saved reports, workspaces, watchlists) or spend upstream quota
 * (tool chains, CyberPulse ingestion, the X firehose batch).
 *
 * The SPA is public by design and has no user accounts, so there is no session
 * to require. Turnstile is the credential that fits: it is free, invisible for
 * real visitors, and it proves the caller ran the site's JavaScript.
 *
 * ## Deployment model — opt-in, fail-closed once on
 *
 * With no `TURNSTILE_SECRET` this middleware is a **no-op**. That is what makes
 * it safe to land: nothing changes for the operator or for callers until the
 * secret exists. The moment it does, every keyless mutation on a gated prefix
 * must present a token, and a missing/malformed/over-long token is rejected
 * before the handler runs — the same fail-closed posture as the rest of the
 * auth chain (see `requireAdmin`, which 403s when `ADMIN_TOKEN` is unset).
 *
 * Never widen this to "verify and continue on failure": siteverify errors,
 * non-JSON bodies and 5xx all fail closed. If Cloudflare's endpoint is down the
 * gated writes fail too, which is the correct trade for endpoints that mutate
 * shared state — and why the prefix list stays short and deliberate.
 *
 * ## Exemptions
 *
 * - **Reads (GET/HEAD/OPTIONS)** are never gated, so every browse/read surface
 *   keeps working and the read-path cache budget is untouched.
 * - **Callers with a valid API key** are exempt: `authenticate()` has already
 *   proven identity for them, and MCP clients can't run a browser widget. Same
 *   reasoning as `requireAdminRole`, which exempts non-key callers because
 *   they are the site itself.
 * - **Internal callers bearing a valid `x-internal-token`** are exempt. Our own
 *   Durable Objects self-fetch gated routes (the investigator agent creates SOC
 *   playbooks, the report builder shares saved reports) and cannot run a
 *   widget. The token is HMAC-verified here, not merely detected: a bogus
 *   `x-internal-token` falls through the auth chain to the same-origin
 *   exemption, so trusting the header's presence would be a one-header bypass
 *   of this gate.
 */

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TOKEN_HEADER = 'cf-turnstile-response';
/** Turnstile tokens are ~1KB; anything wildly larger is junk or an attack. */
const MAX_TOKEN_LENGTH = 2048;
const VERIFY_TIMEOUT_MS = 5_000;

/**
 * Route prefixes whose keyless mutations must clear the challenge.
 *
 * Criteria for adding a prefix: it writes shared state with no per-user
 * ownership, OR it fans out to paid/slow upstream on a caller-supplied trigger.
 * Cheap per-caller work stays out — it is already covered by the rate limiter.
 *
 * Deliberately NOT gated: `/api/v1/intel-bundle` (and its `/build`). Its POST
 * fires on IntelCard render, not on a deliberate write, so a challenge per card
 * would be pure friction; the AI-strict bucket (10/min) plus the GET-side
 * compute throttle in lib/ratelimit.ts is the right instrument there.
 */
export const TURNSTILE_PREFIXES = [
  '/api/v1/estate',
  '/api/v1/soc/playbooks',
  '/api/v1/saved-reports',
  '/api/v1/workspaces',
  '/api/v1/ioc-watchlist',
  '/api/v1/tg-saved-searches',
  '/api/v1/campaigns',
  '/api/v1/watchlist',
  '/api/v1/tool-chains',
  '/api/v1/cyberpulse/scan',
  '/api/v1/x-firehose/probe-batch',
  // #301: the batch scanner probes up to 10 caller-supplied hosts across 4
  // ports each on our egress IP. The GET /check sibling stays gated only by
  // the strict limiter + per-target cache (it is the SPA flow and GETs are
  // never challenged); the POST batch has no SPA caller, so keyless scripted
  // use must carry a key or a token.
  '/api/v1/fortibleed',
] as const;

type TurnstileEnv = Pick<Env, 'TURNSTILE_SECRET' | 'TURNSTILE_SITE_KEY' | 'TURNSTILE_HOSTNAMES'>;

export interface TurnstileConfig {
  enabled: boolean;
  siteKey: string;
  hostnames: string[];
}

/** Resolved gate configuration. `enabled` is false until a secret is set. */
export function turnstileConfig(env: Partial<TurnstileEnv>): TurnstileConfig {
  const secret = env.TURNSTILE_SECRET?.trim() ?? '';
  return {
    enabled: secret.length > 0,
    siteKey: env.TURNSTILE_SITE_KEY?.trim() ?? '',
    hostnames: (env.TURNSTILE_HOSTNAMES ?? '')
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  };
}

interface SiteverifyResult {
  success?: boolean;
  action?: string;
  hostname?: string;
  'error-codes'?: string[];
}

/**
 * Verify one token against Cloudflare's siteverify endpoint.
 *
 * Returns a discriminated result rather than throwing: the caller turns a
 * rejection into a 403 with a machine-readable reason, and the tests can stub
 * `fetch` to exercise every branch without a network.
 */
export async function verifyTurnstileToken(
  env: Partial<TurnstileEnv>,
  token: string,
  opts: { remoteIp?: string; expectedAction?: string; fetcher?: typeof fetch } = {}
): Promise<{ ok: true } | { ok: false; reason: string; codes?: string[] }> {
  const secret = env.TURNSTILE_SECRET?.trim() ?? '';
  if (!secret) return { ok: false, reason: 'not_configured' };

  if (typeof token !== 'string' || token.length === 0) return { ok: false, reason: 'missing_token' };
  if (token.length > MAX_TOKEN_LENGTH) return { ok: false, reason: 'token_too_large' };

  const doFetch = opts.fetcher ?? fetch;
  const body = new URLSearchParams({ secret, response: token });
  if (opts.remoteIp) body.set('remoteip', opts.remoteIp);

  let result: SiteverifyResult;
  try {
    const res = await doFetch(SITEVERIFY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, reason: 'siteverify_unavailable' };
    result = (await res.json()) as SiteverifyResult;
  } catch {
    // Network error, timeout, or unparseable body → fail closed.
    return { ok: false, reason: 'siteverify_unavailable' };
  }

  if (!result?.success) {
    return { ok: false, reason: 'verification_failed', codes: result?.['error-codes'] };
  }

  // Optional action binding: ties a token to the surface it was minted for, so
  // one surface's token can't be replayed against another.
  if (opts.expectedAction && result.action && result.action !== opts.expectedAction) {
    return { ok: false, reason: 'action_mismatch' };
  }

  // Optional hostname binding. A token minted on an attacker's own domain
  // (or a look-alike) must not unlock these routes. An absent hostname from
  // siteverify is treated as a mismatch once a list is configured — fail closed.
  const allowed = turnstileConfig(env).hostnames;
  if (allowed.length > 0) {
    const hostname = (result.hostname ?? '').toLowerCase();
    if (!hostname || !allowed.includes(hostname)) return { ok: false, reason: 'hostname_mismatch' };
  }

  return { ok: true };
}

/** True when `pathname` is one of the gated prefixes (or a sub-path of one). */
export function isTurnstileGated(pathname: string): boolean {
  return TURNSTILE_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Middleware form. Mount it once, before the routes it covers:
 *
 *   for (const prefix of TURNSTILE_PREFIXES) {
 *     app.use(prefix, turnstileGuard());
 *     app.use(`${prefix}/*`, turnstileGuard());
 *   }
 *
 * The caller context is narrowed to what the gate actually needs; anything
 * richer would couple this file to the auth layer's internals.
 */
export function turnstileGuard(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    const config = turnstileConfig(c.env as Partial<TurnstileEnv>);
    if (!config.enabled) return next();
    if (!MUTATING.has(c.req.method)) return next();

    // Already-authenticated callers (valid API key) skip: they proved identity
    // upstream in the auth chain and cannot run a browser widget.
    if ((c as Context<{ Bindings: Env }> & { user?: unknown }).user) return next();

    // Internal DO callers (investigator agent, report builder, …) can't run a
    // widget either — they sign an HMAC token instead. Validate it here rather
    // than trusting the header: `authenticate()` lets a request with a BOGUS
    // x-internal-token fall through to the same-origin exemption, so "header
    // present" would make this gate one spoofed header deep. Caller allow-list
    // and HMAC check mirror the auth-chain branch exactly (lib/auth.ts).
    const internalToken = c.req.header('x-internal-token') ?? '';
    if (internalToken) {
      const result = await validateInternalToken(internalToken, c.env?.INTERNAL_TOKEN_SECRET);
      if (result.ok && ALLOWED_INTERNAL_CALLERS.has(result.caller)) return next();
    }

    const token = c.req.header(TOKEN_HEADER) ?? '';
    const result = await verifyTurnstileToken(c.env as Partial<TurnstileEnv>, token, {
      remoteIp: c.req.header('cf-connecting-ip') ?? undefined,
    });

    if (!result.ok) {
      const body: Record<string, unknown> = { error: 'turnstile_required', reason: result.reason };
      if (result.codes?.length) body.codes = result.codes;
      return c.json(body, 403, {
        // Never cache a rejection: a client that fixes its token must not be
        // stuck behind a cached 403.
        'cache-control': 'no-store',
      });
    }

    await next();
  };
}
