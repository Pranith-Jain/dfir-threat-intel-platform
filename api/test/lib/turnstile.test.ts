import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import {
  TURNSTILE_PREFIXES,
  isTurnstileGated,
  turnstileConfig,
  turnstileGuard,
  verifyTurnstileToken,
} from '../../src/lib/turnstile';
import { signInternalToken } from '../../src/lib/internal-token';
import type { Env } from '../../src/env';

/**
 * The bot gate for keyless mutations.
 *
 * The properties that matter, in order of blast radius:
 *
 *  1. **Off by default.** With no `TURNSTILE_SECRET` the guard must be a pure
 *     no-op — that is what lets it ship ahead of the widget existing. A typo in
 *     the env name must not start 403-ing every write on the site.
 *  2. **Fail closed once on.** Missing/oversized token, siteverify down,
 *     non-JSON body, `success: false`, wrong hostname → 403, never a pass.
 *  3. **Reads and API-key callers are untouched.** The gate must not tax the
 *     browse surfaces, and an authenticated MCP client cannot run a browser
 *     widget, so a valid key short-circuits it.
 */

const SECRET = 'test-turnstile-secret';
const SITE_KEY = '0x4test-site-key';

function env(overrides: Partial<Env> = {}): Env {
  return {
    TURNSTILE_SECRET: SECRET,
    TURNSTILE_SITE_KEY: SITE_KEY,
    ...overrides,
  } as Env;
}

function siteverifyStub(payload: unknown, init: { ok?: boolean } = {}) {
  // Typed with the real fetch signature so assertions can read the request body
  // out of `mock.calls` under noUncheckedIndexedAccess.
  return vi.fn(
    async (_url: string | URL | Request, _init?: RequestInit) =>
      new Response(JSON.stringify(payload), { status: init.ok === false ? 500 : 200 })
  );
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe('turnstileConfig', () => {
  it('is disabled until a secret is configured', () => {
    expect(turnstileConfig({})).toEqual({ enabled: false, siteKey: '', hostnames: [] });
    expect(turnstileConfig({ TURNSTILE_SECRET: '   ' }).enabled).toBe(false);
  });

  it('reports the public site key and parsed hostname allowlist', () => {
    const cfg = turnstileConfig({
      TURNSTILE_SECRET: SECRET,
      TURNSTILE_SITE_KEY: SITE_KEY,
      TURNSTILE_HOSTNAMES: 'PranithJain.Qzz.io , example.com ,',
    });
    expect(cfg.enabled).toBe(true);
    expect(cfg.siteKey).toBe(SITE_KEY);
    expect(cfg.hostnames).toEqual(['pranithjain.qzz.io', 'example.com']);
  });
});

describe('isTurnstileGated', () => {
  it('covers each configured prefix and its sub-paths, and nothing else', () => {
    for (const prefix of TURNSTILE_PREFIXES) {
      expect(isTurnstileGated(prefix), prefix).toBe(true);
      expect(isTurnstileGated(`${prefix}/some/sub/path`), `${prefix}/sub`).toBe(true);
    }
    expect(isTurnstileGated('/api/v1/health')).toBe(false);
    expect(isTurnstileGated('/api/v1/estates')).toBe(false); // prefix must be a path boundary
    // intel-bundle is deliberately excluded: its POST fires on card render, not
    // on a deliberate write, so a challenge there would be friction.
    expect(isTurnstileGated('/api/v1/intel-bundle')).toBe(false);
  });
});

describe('verifyTurnstileToken', () => {
  it('rejects before any network call when nothing is configured', async () => {
    const fetcher = siteverifyStub({ success: true });
    const res = await verifyTurnstileToken({}, 'token', { fetcher: fetcher as unknown as typeof fetch });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('not_configured');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects a missing or oversized token without calling siteverify', async () => {
    const fetcher = siteverifyStub({ success: true });
    const opts = { fetcher: fetcher as unknown as typeof fetch };
    expect((await verifyTurnstileToken(env(), '', opts)).ok).toBe(false);
    const big = await verifyTurnstileToken(env(), 'x'.repeat(2049), opts);
    expect(big.ok).toBe(false);
    if (!big.ok) expect(big.reason).toBe('token_too_large');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('accepts a successful verification and forwards the client IP', async () => {
    const fetcher = siteverifyStub({ success: true, hostname: 'pranithjain.qzz.io' });
    const res = await verifyTurnstileToken(env(), 'good-token', {
      remoteIp: '203.0.113.9',
      fetcher: fetcher as unknown as typeof fetch,
    });
    expect(res.ok).toBe(true);
    const body = String(fetcher.mock.calls[0]?.[1]?.body ?? '');
    expect(body).toContain('response=good-token');
    expect(body).toContain('remoteip=203.0.113.9');
  });

  it('fails closed when siteverify errors, 5xxes, or returns non-JSON', async () => {
    const errFetcher = vi.fn(async () => {
      throw new Error('network down');
    });
    const bad = await verifyTurnstileToken(env(), 't', { fetcher: errFetcher as unknown as typeof fetch });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toBe('siteverify_unavailable');

    const fiveHundred = siteverifyStub({ success: true }, { ok: false });
    const res5xx = await verifyTurnstileToken(env(), 't', { fetcher: fiveHundred as unknown as typeof fetch });
    expect(res5xx.ok).toBe(false);

    const garbage = vi.fn(async () => new Response('<html>nope</html>', { status: 200 }));
    const resGarbage = await verifyTurnstileToken(env(), 't', { fetcher: garbage as unknown as typeof fetch });
    expect(resGarbage.ok).toBe(false);
    if (!resGarbage.ok) expect(resGarbage.reason).toBe('siteverify_unavailable');
  });

  it('surfaces siteverify error codes on a rejected token', async () => {
    const fetcher = siteverifyStub({ success: false, 'error-codes': ['timeout-or-duplicate'] });
    const res = await verifyTurnstileToken(env(), 'stale', { fetcher: fetcher as unknown as typeof fetch });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe('verification_failed');
      expect(res.codes).toEqual(['timeout-or-duplicate']);
    }
  });

  it('binds the token to a hostname when a list is configured', async () => {
    const okFetcher = siteverifyStub({ success: true, hostname: 'pranithjain.qzz.io' });
    const ok = await verifyTurnstileToken(env({ TURNSTILE_HOSTNAMES: 'pranithjain.qzz.io' }), 't', {
      fetcher: okFetcher as unknown as typeof fetch,
    });
    expect(ok.ok).toBe(true);

    const evil = siteverifyStub({ success: true, hostname: 'attacker.example' });
    const res = await verifyTurnstileToken(env({ TURNSTILE_HOSTNAMES: 'pranithjain.qzz.io' }), 't', {
      fetcher: evil as unknown as typeof fetch,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('hostname_mismatch');
  });

  it('fails closed when a hostname list is configured but siteverify returns none', async () => {
    const fetcher = siteverifyStub({ success: true });
    const res = await verifyTurnstileToken(env({ TURNSTILE_HOSTNAMES: 'pranithjain.qzz.io' }), 't', {
      fetcher: fetcher as unknown as typeof fetch,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('hostname_mismatch');
  });

  it('rejects a token minted for a different surface', async () => {
    const fetcher = siteverifyStub({ success: true, action: 'signup', hostname: 'pranithjain.qzz.io' });
    const res = await verifyTurnstileToken(env(), 't', {
      expectedAction: 'save-report',
      fetcher: fetcher as unknown as typeof fetch,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('action_mismatch');
  });
});

describe('turnstileGuard', () => {
  function app(bindings: Partial<Env>) {
    const h = new Hono<{ Bindings: Env }>();
    for (const base of TURNSTILE_PREFIXES) {
      h.use(base, turnstileGuard());
      h.use(`${base}/*`, turnstileGuard());
    }
    h.post('/api/v1/estate/alerts', (c) => c.json({ ok: true }));
    h.post('/api/v1/cyberpulse/scan', (c) => c.json({ ok: true }));
    h.get('/api/v1/estate/alerts', (c) => c.json({ ok: true }));
    // Internal DO callers self-fetch this one (investigator agent creating a
    // SOC playbook) — the guard must let them through on a signed token.
    h.post('/api/v1/soc/playbooks', (c) => c.json({ ok: true }));
    return h;
  }

  beforeEach(() => {
    globalThis.fetch = siteverifyStub({ success: true, hostname: 'pranithjain.qzz.io' }) as unknown as typeof fetch;
  });

  it('is a no-op when no secret is configured', async () => {
    const res = await app({}).request('/api/v1/estate/alerts', { method: 'POST' }, {} as Env);
    expect(res.status).toBe(200);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('403s a keyless mutation with no token, and never caches the rejection', async () => {
    const res = await app(env()).request('/api/v1/estate/alerts', { method: 'POST' }, env());
    expect(res.status).toBe(403);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.error).toBe('turnstile_required');
    expect(body.reason).toBe('missing_token');
  });

  it('403s a mutation whose token does not verify', async () => {
    globalThis.fetch = siteverifyStub({ success: false, 'error-codes': ['invalid-input-response'] }) as never;
    const res = await app(env()).request(
      '/api/v1/cyberpulse/scan',
      { method: 'POST', headers: { 'cf-turnstile-response': 'bogus' } },
      env()
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason: string; codes?: string[] };
    expect(body.reason).toBe('verification_failed');
    expect(body.codes).toEqual(['invalid-input-response']);
  });

  it('passes a mutation whose token verifies', async () => {
    const res = await app(env()).request(
      '/api/v1/estate/alerts',
      { method: 'POST', headers: { 'cf-turnstile-response': 'good' } },
      env()
    );
    expect(res.status).toBe(200);
  });

  it('never challenges reads, even over a gated prefix', async () => {
    const res = await app(env()).request('/api/v1/estate/alerts', {}, env());
    expect(res.status).toBe(200);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('exempts callers the auth chain already identified (API key holders)', async () => {
    const h = new Hono<{ Bindings: Env }>();
    h.use('/api/v1/estate', turnstileGuard());
    // Stand in for `authenticate()` having set c.user from a valid API key.
    h.use('/api/v1/estate', async (c, next) => {
      (c as unknown as { user?: unknown }).user = { role: 'readonly' };
      await next();
    });
    h.post('/api/v1/estate/alerts', (c) => c.json({ ok: true }));

    const res = await h.request('/api/v1/estate/alerts', { method: 'POST' }, env());
    expect(res.status).toBe(200);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('exempts internal DO callers holding a valid signed x-internal-token', async () => {
    // Regression guard: the investigator agent POSTs /api/v1/soc/playbooks via
    // the SELF binding with a signed token and no API key. If the gate ignored
    // that credential, enabling TURNSTILE_SECRET would break it (a DO cannot
    // run a browser widget).
    const secret = 'test-internal-token-secret';
    const token = await signInternalToken('investigator-do', secret);
    const res = await app(env({ INTERNAL_TOKEN_SECRET: secret })).request(
      '/api/v1/soc/playbooks',
      { method: 'POST', headers: { 'x-internal-token': token } },
      env({ INTERNAL_TOKEN_SECRET: secret })
    );
    expect(res.status).toBe(200);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('does not treat a bogus x-internal-token as an exemption', async () => {
    // The auth chain lets a request with an INVALID internal token fall
    // through to the same-origin exemption, so trusting the header's presence
    // would be a one-header bypass of this gate.
    const secret = 'test-internal-token-secret';
    const res = await app(env({ INTERNAL_TOKEN_SECRET: secret })).request(
      '/api/v1/estate/alerts',
      { method: 'POST', headers: { 'x-internal-token': 'not-a-signed-token' } },
      env({ INTERNAL_TOKEN_SECRET: secret })
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('missing_token');
  });

  it('does not exempt an expired internal token', async () => {
    const secret = 'test-internal-token-secret';
    const expired = await signInternalToken('investigator-do', secret);
    // Rewind: re-sign with time mocked forward so the TTL lapses, then restore.
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 6 * 60_000);
    const res = await app(env({ INTERNAL_TOKEN_SECRET: secret })).request(
      '/api/v1/soc/playbooks',
      { method: 'POST', headers: { 'x-internal-token': expired } },
      env({ INTERNAL_TOKEN_SECRET: secret })
    );
    vi.useRealTimers();
    expect(res.status).toBe(403);
  });
});
