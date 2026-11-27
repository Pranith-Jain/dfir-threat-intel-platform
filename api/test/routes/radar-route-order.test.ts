/**
 * Regression test for the /api/v1/radar/scan registration order.
 *
 * The route used to be mounted before both `authenticate('external-only')`
 * and its exact-path Turnstile gate. In Hono, middleware registered after a
 * handler never runs for that handler, so neither control applied. This test
 * builds the same chain in the corrected order with real middleware and dummy
 * bindings — no network, no D1, no production secrets.
 */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { authenticate } from '../../src/lib/auth';
import { turnstileGuard } from '../../src/lib/turnstile';

const SITE = 'https://example.test';
const PATH = '/api/v1/radar/scan';

function env(turnstileSecret = ''): Env {
  return {
    SITE_URL: SITE,
    TURNSTILE_SECRET: turnstileSecret,
  } as unknown as Env;
}

function app(turnstileSecret = ''): Hono<{ Bindings: Env }> {
  const a = new Hono<{ Bindings: Env }>();
  a.use('/api/v1/*', authenticate('external-only'));
  a.use(PATH, turnstileGuard({ exactPath: PATH }));
  a.post(PATH, (c) => c.json({ ok: true }));
  return a;
}

const sameOrigin = { origin: SITE, 'sec-fetch-site': 'same-origin' };

describe('radar scan route order', () => {
  it('rejects an external unauthenticated POST before the handler runs', async () => {
    const res = await app().request(PATH, { method: 'POST', headers: { 'content-type': 'application/json' } }, env());
    expect(res.status).toBe(401);
  });

  it('keeps the same-origin SPA caller working when the gate is not configured', async () => {
    const res = await app().request(
      PATH,
      { method: 'POST', headers: { ...sameOrigin, 'content-type': 'application/json' } },
      env()
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { ok: boolean }).ok).toBe(true);
  });

  it('runs the Turnstile gate on the same-origin POST once configured', async () => {
    const res = await app('test-secret').request(
      PATH,
      { method: 'POST', headers: { ...sameOrigin, 'content-type': 'application/json' } },
      env('test-secret')
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe('turnstile_required');
  });
});
