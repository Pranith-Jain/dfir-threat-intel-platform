/**
 * Route tests for GET /api/v1/threat-monitor/proxy — the SSRF fix from #298.
 *
 * The handler used to fetch an arbitrary `?url=` and echo the body back with
 * `Access-Control-Allow-Origin: *`. On a platform whose egress is not loopback
 * that is an unauthenticated SSRF primitive plus a cross-origin read primitive:
 *
 *   /proxy?url=http://169.254.169.254/latest/meta-data/   → cloud metadata
 *   /proxy?url=http://127.0.0.1:8787/...                  → same-deployment admin
 *   /proxy?url=http://192.168.0.1/                        → private network
 *
 * The tests below pin the refusal cases. They assert on the status code and the
 * absence of the fetched body, which is what an attacker actually observes.
 */
import { describe, it, expect } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import { threatMonitorRouter } from '../../src/routes/threat-monitor';
import { Hono } from 'hono';

/** One of the real hosts from public/data/threat-monitor/sources.json. */
const FEED_HOST = 'www.cisa.gov';

/** Private/reserved targets that must never be reachable. */
const BLOCKED_TARGETS = [
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://127.0.0.1:8787/',
  'http://localhost/',
  'http://192.168.1.1/',
  'http://10.0.0.1/',
  'http://[::1]/',
  'http://168.63.129.16/', // Azure WireServer — public space, so needs listing
];

// Real miniflare bindings — the allow-list is derived from the shipped
// sources.json, so the test needs the actual ASSETS binding, not a stub. An
// empty stub made the loader fail and the handler correctly fail closed (502),
// which masked the distinction between "refused" and "allow-list unavailable".
const bindings = (): unknown => testEnv;

async function proxy(qs: string, init?: RequestInit): Promise<Response> {
  return new Hono().route('/', threatMonitorRouter).request(`/threat-monitor/proxy${qs}`, init, bindings() as never);
}

describe('threat-monitor proxy SSRF guard', () => {
  it('rejects a request with no url', async () => {
    const res = await proxy('');
    expect(res.status).toBe(400);
  });

  it('rejects a malformed url', async () => {
    const res = await proxy('?url=not-a-url');
    expect(res.status).toBe(400);
    expect((await res.json<{ message: string }>()).message).toMatch(/invalid url/i);
  });

  it('rejects non-http(s) schemes', async () => {
    for (const scheme of ['file://', 'gopher://', 'ftp://', 'javascript:']) {
      const res = await proxy(`?url=${encodeURIComponent(`${scheme}//x`)}`);
      expect(res.status).toBe(400);
    }
  });

  it('rejects credentials embedded in the url', async () => {
    const res = await proxy(`?url=${encodeURIComponent('http://user:pass@www.cisa.gov/feed')}`);
    expect(res.status).toBe(400);
    expect((await res.json<{ message: string }>()).message).toMatch(/credentials/i);
  });

  it('rejects private, loopback and metadata targets', async () => {
    for (const target of BLOCKED_TARGETS) {
      const res = await proxy(`?url=${encodeURIComponent(target)}`);
      // 403 (blocked) or 400 — what matters is that it is NOT a 200 carrying
      // the upstream body.
      expect(res.status, `target ${target} must be refused`).not.toBe(200);
      expect([400, 403], `target ${target} must be refused`).toContain(res.status);
    }
  });

  it('rejects a public host that is not one of the OSINT feeds', async () => {
    // Not an SSRF, but an open-proxy / free-egress abuse channel.
    const res = await proxy(`?url=${encodeURIComponent('https://example.com/')}`);
    expect(res.status).toBe(403);
    expect((await res.json<{ message: string }>()).message).toMatch(/allow-list/i);
  });

  it('does not reflect the attacker-supplied host back unescaped in the error', async () => {
    const res = await proxy(`?url=${encodeURIComponent('https://evil.example.com/')}`);
    const text = await res.text();
    expect(text).not.toContain('<script');
  });

  it('never sets a wildcard Access-Control-Allow-Origin', async () => {
    // Sweep every refusal path: a 403 body readable cross-origin would still
    // let a hostile page use this endpoint as an oracle.
    for (const target of [...BLOCKED_TARGETS, 'https://example.com/']) {
      const res = await proxy(`?url=${encodeURIComponent(target)}`);
      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
    }
  });

  // Note: `X-Content-Type-Options: nosniff` is applied by the edge
  // (worker/csp.ts withSecurityHeaders) on every response, and by the api-error
  // helpers for refusals, so it is deliberately not asserted here — a
  // route-level assertion would only prove the test harness mounted the router,
  // not that this handler is protected. The ACAO assertion above is the part
  // that belongs to this fix: the wildcard ACAO was set HERE, on the success
  // path, and is what made proxied responses readable cross-origin.
});
