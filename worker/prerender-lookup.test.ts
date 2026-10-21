/**
 * Regression test for the prerender lookup on the tools surface.
 *
 * The bug: ASSETS runs with `not_found_handling: "single-page-application"`,
 * so a MISSING asset is answered with the SPA shell and a **200**, not a
 * 404. The candidate loop in `fetchPrerenderedOrShell` used to accept any
 * non-404, so on the tools surface the tools-tree candidate — which
 * deliberately does not carry AppShell routes — won the comparison and every
 * /threatintel and /dfir page served the empty shell instead of its
 * prerendered HTML.
 *
 * The fix compares the body against the shell's empty-root marker, so a miss
 * is detected even when ASSETS answers it with a 200.
 *
 * These tests exercise the real lookup against a stub ASSETS that behaves
 * the way the real binding does (a miss returns the shell with 200).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { fetchPrerenderedOrShell } from './router';

/** The shell exactly as scripts/prerender.mjs writes it. */
const SPA_SHELL = `<!doctype html><html><head><title>shell</title></head><body><div id="root"></div></body></html>`;

/** A prerendered page: the root div has content in it. */
const PRERENDERED = `<!doctype html><html><head><title>page</title></head><body><div id="root"><h1>CVE Triage</h1></div></body></html>`;

/**
 * A stub ASSETS binding that mirrors the real one's miss behaviour: a
 * missing path returns the SPA shell with 200, never a 404.
 */
function makeAssets(files: Record<string, string>) {
  return {
    fetch: async (req: Request) => {
      const path = new URL(req.url).pathname;
      const hit = files[path];
      if (hit === undefined) {
        // `not_found_handling: "single-page-application"`
        return new Response(SPA_SHELL, {
          status: 200,
          headers: { 'content-type': 'text/html;charset=UTF-8' },
        });
      }
      return new Response(hit, {
        status: 200,
        headers: { 'content-type': 'text/html;charset=UTF-8' },
      });
    },
  } as unknown as Fetcher;
}

function makeEnv(files: Record<string, string>) {
  return { ASSETS: makeAssets(files) } as never;
}

const mockCtx = () =>
  ({
    waitUntil: (_p: Promise<unknown>) => {},
    passThroughOnException: () => {},
  }) as unknown as ExecutionContext;

const NONCE = 'test-nonce';

// The shell-fallback path goes through getOrInjectOg, which uses the
// Cache API. jsdom has no `caches`, so stub the two methods it touches.
const realCaches = (globalThis as { caches?: unknown }).caches;
beforeAll(() => {
  (globalThis as { caches?: unknown }).caches = {
    default: {
      match: async () => undefined,
      put: async () => undefined,
    },
  };
});
afterAll(() => {
  (globalThis as { caches?: unknown }).caches = realCaches;
});

describe('fetchPrerenderedOrShell — tools surface', () => {
  it('serves the portfolio prerender when the tools tree has no entry', async () => {
    // The tools tree is empty for this route (AppShell routes are not
    // written there), the portfolio tree has it.
    const env = makeEnv({ '/__prerendered/threatintel__cve-triage': PRERENDERED });
    const res = await fetchPrerenderedOrShell(
      new Request('https://panopticon.pranithjain.qzz.io/threatintel/cve-triage'),
      env,
      mockCtx(),
      new URL('https://panopticon.pranithjain.qzz.io/threatintel/cve-triage'),
      NONCE,
      'tools'
    );
    const body = await res.text();
    expect(body).toContain('CVE Triage');
    expect(body).not.toContain('<div id="root"></div>');
  });

  it('falls back to the shell when no candidate has real content', async () => {
    const env = makeEnv({});
    const res = await fetchPrerenderedOrShell(
      new Request('https://panopticon.pranithjain.qzz.io/threatintel/cve-triage'),
      env,
      mockCtx(),
      new URL('https://panopticon.pranithjain.qzz.io/threatintel/cve-triage'),
      NONCE,
      'tools'
    );
    const body = await res.text();
    expect(body).toContain('<div id="root"></div>');
    expect(res.headers.get('x-ssr-source')).toBe('shell-fallback-404');
  });
});

describe('fetchPrerenderedOrShell — portfolio surface', () => {
  it('serves the prerender directly', async () => {
    const env = makeEnv({ '/__prerendered/threatintel__cve-triage': PRERENDERED });
    const res = await fetchPrerenderedOrShell(
      new Request('https://pranithjain.qzz.io/threatintel/cve-triage'),
      env,
      mockCtx(),
      new URL('https://pranithjain.qzz.io/threatintel/cve-triage'),
      NONCE,
      'portfolio'
    );
    const body = await res.text();
    expect(body).toContain('CVE Triage');
    expect(res.headers.get('x-ssr-source')).toBe('prerendered');
  });
});
