/**
 * Regression tests for the bounded-fetch guard in `src/lib/darknet.ts`.
 *
 * Onion pages are reached through tor2web gateways, which proxy arbitrary and
 * potentially hostile third-party content. A plain `await res.text()` buffers
 * the whole body with no ceiling, so a single oversized (or malicious) gateway
 * response can exhaust the 128 MB Worker isolate before any parsing happens.
 *
 * `fetchTextBounded()` enforces a hard 5 MB cap. These tests pin both halves of
 * that contract:
 *   1. an oversized Content-Length is rejected without buffering, and
 *   2. a lying/absent Content-Length is still truncated at the cap.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { torFetchOnion } from '../../src/lib/darknet';

const MAX_FETCH_BYTES = 5_000_000;

// A syntactically valid v3 .onion address, as required by extractOnionHostname().
const ONION = 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion';

function onionResponse(body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status: 200, headers });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('darknet bounded fetch', () => {
  it('rejects an oversized Content-Length before buffering the body', async () => {
    // Advertise a body far beyond the cap. The guard must trust this header and
    // bail out rather than reading gigabytes into the isolate.
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => onionResponse('x', { 'content-length': String(MAX_FETCH_BYTES * 10) }))
    );

    await expect(torFetchOnion(ONION)).rejects.toThrow(/response too large/);
  });

  it('truncates at the cap when the upstream omits Content-Length', async () => {
    // No content-length header: the streaming reader must still enforce the cap.
    const oversized = 'a'.repeat(MAX_FETCH_BYTES + 1024);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => onionResponse(oversized))
    );

    const result = await torFetchOnion(ONION);

    expect(result.statusCode).toBe(200);
    expect(result.html.length).toBeLessThanOrEqual(MAX_FETCH_BYTES);
  });

  it('passes through a normal-sized response intact', async () => {
    const html = '<html><body><h1>ok</h1></body></html>';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => onionResponse(html, { 'content-length': String(html.length) }))
    );

    const result = await torFetchOnion(ONION);

    expect(result.html).toBe(html);
  });

  it('builds a tor2web subdomain URL', async () => {
    // Guards against a regression to the path-style form
    // (`https://host.onion/gateway`), which does not resolve.
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => onionResponse('ok'))
    );

    const result = await torFetchOnion(ONION);

    expect(result.fetchedVia).toBe(`${ONION}.tor2web.io`);
  });
});

/**
 * #300 hardening: tor2web gateways are third parties we do not control, so
 * their redirects must be followed manually (re-checking each hop), never
 * `redirect: 'follow'`, and never without a bound.
 */
describe('darknet bounded redirects (#300)', () => {
  it('follows a redirect chain manually and returns the final page', async () => {
    let calls = 0;
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      calls += 1;
      if (calls === 1) {
        return new Response('', { status: 302, headers: { location: `https://${ONION}.tor2web.io/next` } });
      }
      return onionResponse('<html><head><title>Final</title></head><body>ok</body></html>');
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await torFetchOnion(ONION);

    expect(calls).toBe(2);
    expect(result.html).toContain('Final');
    // The runtime must never fetch redirects itself — each hop goes through
    // the manual loop so it can be counted and bounded.
    for (const call of fetchMock.mock.calls) {
      expect(call[1]?.redirect).toBe('manual');
    }
  });

  it('refuses an unbounded redirect chain instead of following it forever', async () => {
    const fetchMock = vi.fn(
      async () => new Response('', { status: 302, headers: { location: `https://${ONION}.tor2web.io/loop` } })
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(torFetchOnion(ONION)).rejects.toThrow(/too many redirects/);
    // 1 initial request + ONION_MAX_REDIRECTS hops, then refuse — not an
    // open-ended chain.
    expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(6);
  });

  it('treats a redirect with no Location header as the final response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('', { status: 302 }))
    );

    const result = await torFetchOnion(ONION);

    expect(result.statusCode).toBe(302);
  });
});
