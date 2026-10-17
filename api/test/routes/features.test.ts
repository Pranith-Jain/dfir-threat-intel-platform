import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { featuresHandler } from '../../src/routes/features';

function app() {
  const a = new Hono<any>();
  a.get('/api/v1/features', featuresHandler);
  return a;
}

describe('GET /api/v1/features', () => {
  it('reports only the always-on samples flag (CAPE/recon bridges removed)', async () => {
    const r = await app().request('/api/v1/features', {}, {});
    expect(r.status).toBe(200);
    // `turnstile_*` are the only additions: the site key is public by design
    // (it is rendered into every widget) and the required flag lets the SPA
    // decide whether to load the Turnstile script at all.
    expect(await r.json()).toEqual({
      samples: true,
      turnstile_required: false,
      turnstile_site_key: '',
    });
  });

  it('never includes cape or recon keys (those bridges were removed)', async () => {
    const r = await app().request('/api/v1/features', {}, {});
    const body = (await r.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['samples', 'turnstile_required', 'turnstile_site_key']);
  });

  it('advertises the challenge only once a secret is configured', async () => {
    const configured = new Hono<any>();
    configured.get('/api/v1/features', featuresHandler);
    const r = await configured.request('/api/v1/features', {}, {
      TURNSTILE_SECRET: 'shhh',
      TURNSTILE_SITE_KEY: '0xsitekey',
    } as never);
    expect(await r.json()).toEqual({
      samples: true,
      turnstile_required: true,
      turnstile_site_key: '0xsitekey',
    });
  });

  it('sets a short public cache header', async () => {
    const r = await app().request('/api/v1/features', {}, {});
    expect(r.headers.get('cache-control')).toBe('public, max-age=60');
  });

  it('always reports samples=true regardless of any leftover env', async () => {
    // /api/v1/sample/scan is always-on; verify it stays advertised even
    // when unrelated env is present.
    const r = await app().request('/api/v1/features', {}, {});
    const body = (await r.json()) as { samples: boolean };
    expect(body.samples).toBe(true);
  });
});
