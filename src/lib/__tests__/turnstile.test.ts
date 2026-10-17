import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { turnstileHeaders, turnstileFeatures, resetTurnstileFeatures } from '../turnstile';

/**
 * Client half of the bot gate.
 *
 * The deployment story is "off until the operator sets a secret", so the
 * property that matters most is the boring one: with no challenge configured,
 * this module must add no header, load no third-party script, and make exactly
 * one cheap call it already makes elsewhere. If that regresses, turning the
 * gate on would quietly cost every visitor a script load.
 */

function stubFeatures(payload: unknown, ok = true) {
  const spy = vi.fn(async () => new Response(JSON.stringify(payload), { status: ok ? 200 : 500 }));
  vi.stubGlobal('fetch', spy);
  return spy;
}

beforeEach(() => {
  resetTurnstileFeatures();
  vi.restoreAllMocks();
  document.head.innerHTML = '';
  document.body.innerHTML = '';
  delete (window as { turnstile?: unknown }).turnstile;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('turnstileFeatures', () => {
  it('reports not-required when the deployment has no widget', async () => {
    stubFeatures({ samples: true });
    expect(await turnstileFeatures()).toEqual({ required: false, siteKey: '' });
  });

  it('requires both the flag and a site key before enabling the challenge', async () => {
    stubFeatures({ turnstile_required: true });
    expect((await turnstileFeatures()).required).toBe(false); // key missing

    resetTurnstileFeatures();
    stubFeatures({ turnstile_required: false, turnstile_site_key: 'k' });
    expect((await turnstileFeatures()).required).toBe(false); // flag off
  });

  it('reads the probe once per page and caches it', async () => {
    const spy = stubFeatures({ turnstile_required: true, turnstile_site_key: 'site-key' });
    await turnstileFeatures();
    await turnstileFeatures();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('treats a failed probe as "not required" rather than blocking writes', async () => {
    stubFeatures({}, false);
    expect((await turnstileFeatures()).required).toBe(false);

    resetTurnstileFeatures();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('offline');
      })
    );
    expect((await turnstileFeatures()).required).toBe(false);
  });
});

describe('turnstileHeaders', () => {
  it('returns no headers for reads without even probing', async () => {
    const spy = stubFeatures({ turnstile_required: true, turnstile_site_key: 'site-key' });
    expect(await turnstileHeaders('save-report', 'GET')).toEqual({});
    expect(spy).not.toHaveBeenCalled();
  });

  it('returns no headers and loads no script when the gate is unconfigured', async () => {
    stubFeatures({ samples: true });
    expect(await turnstileHeaders('save-report', 'POST')).toEqual({});
    // The whole point of the opt-in design: no third-party script on a page
    // whose deployment has no Turnstile secret.
    expect(document.querySelector('script[src*="challenges.cloudflare.com"]')).toBeNull();
  });

  it('throws rather than silently sending an empty header when the challenge fails', async () => {
    stubFeatures({ turnstile_required: true, turnstile_site_key: 'site-key' });
    // A widget that throws on execute stands in for every real failure mode
    // (blocked script, bad site key, refused challenge). The contract under
    // test is that the error propagates: if this resolved to `{}`, the request
    // would go out without a token and come back as an unexplained 403.
    (window as { turnstile?: unknown }).turnstile = {
      render: () => 'widget-0',
      execute: () => {
        throw new Error('challenge refused');
      },
    };
    await expect(turnstileHeaders('save-report', 'POST')).rejects.toThrow(/challenge refused/);
  });
});
