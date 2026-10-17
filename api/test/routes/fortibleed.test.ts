import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, afterEach } from 'vitest';

/**
 * #301 hardening for the FortiBleed scanner.
 *
 * The endpoint probes caller-supplied hosts on our egress IP, so these tests
 * pin the three bounds:
 *   1. private/internal targets are refused before any connection;
 *   2. upstream probes are pinned + redirect-bounded — a public target that
 *      302s to an internal address must not carry the scan onto it (the old
 *      `redirect: 'follow'` did exactly that after the one-time host check);
 *   3. repeat scans of the same target are served from the Cache API instead
 *      of re-probing third-party hosts from our egress.
 */

afterEach(() => {
  vi.restoreAllMocks();
});

const FORTIGATE_BODY =
  '<html><head><title>FortiGate SSL VPN</title></head><body><form action="/remote/login"></form></body></html>';

const PRIVATE_REDIRECT_TARGET = '169.254.169.254';

interface FetchCall {
  url: string;
  init?: RequestInit;
}

/** Mock fetch, recording every call. DoH requests answer with `dohIp`. */
function setupFetch(opts: { dohIp?: string; probes: (url: string, hop: number) => Response | undefined }): {
  calls: FetchCall[];
  upstream: () => FetchCall[];
} {
  const calls: FetchCall[] = [];
  const dohIp = opts.dohIp ?? '93.184.216.34';
  let probeCount = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    calls.push({ url, init: init as RequestInit | undefined });
    if (url.includes('cloudflare-dns.com')) {
      const isAaaa = url.includes('type=AAAA');
      return new Response(
        JSON.stringify({ Status: 0, Answer: isAaaa ? [] : [{ name: 'x', type: 1, TTL: 60, data: dohIp }] }),
        {
          status: 200,
          headers: { 'content-type': 'application/dns-json' },
        }
      );
    }
    const res = opts.probes(url, probeCount++);
    return res ?? new Response('not found', { status: 404 });
  });
  return {
    calls,
    upstream: () => calls.filter((c) => !c.url.includes('cloudflare-dns.com')),
  };
}

describe('GET /api/v1/fortibleed/check', () => {
  it('returns 400 when target is missing', async () => {
    const r = await SELF.fetch('https://x/api/v1/fortibleed/check');
    expect(r.status).toBe(400);
  });

  it('refuses a private literal target before any connection', async () => {
    const { calls } = setupFetch({ probes: () => undefined });
    const r = await SELF.fetch('https://x/api/v1/fortibleed/check?target=127.0.0.1');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { isFortiGate: boolean; details: string[] };
    expect(body.isFortiGate).toBe(false);
    expect(body.details.join(' ')).toMatch(/not allowed/i);
    // Nothing was dialled — not even DNS.
    expect(calls).toHaveLength(0);
  });

  it('detects a FortiGate banner and pins the probe with manual redirects', async () => {
    const { upstream } = setupFetch({
      probes: () => new Response(FORTIGATE_BODY, { status: 200, headers: { 'content-type': 'text/html' } }),
    });
    const r = await SELF.fetch('https://x/api/v1/fortibleed/check?target=fortigate-a.example');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { isFortiGate: boolean; vulnerability: string | null; details: string[] };
    expect(body.isFortiGate).toBe(true);
    expect(body.vulnerability).toBe('CVE-2024-21762');

    const probe = upstream().find((c) => c.url.includes('fortigate-a.example'));
    expect(probe).toBeDefined();
    // The runtime must never follow redirects for us here (#301): each hop is
    // validated and pinned by pinnedFetchFollow.
    expect(probe!.init?.redirect).toBe('manual');
  });

  it('never follows a redirect from a public target onto an internal address', async () => {
    const { upstream } = setupFetch({
      probes: () =>
        new Response('', { status: 302, headers: { location: `http://${PRIVATE_REDIRECT_TARGET}/latest/meta-data/` } }),
    });
    const r = await SELF.fetch('https://x/api/v1/fortibleed/check?target=fortigate-b.example');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { isFortiGate: boolean };
    expect(body.isFortiGate).toBe(false);
    // The redirect hop must be refused, not fetched: the internal address
    // appears in no outbound request.
    expect(upstream().some((c) => c.url.includes(PRIVATE_REDIRECT_TARGET))).toBe(false);
  });

  it('serves a repeat scan of the same target from cache', async () => {
    const target = 'fortigate-c.example';
    const { upstream } = setupFetch({
      probes: () => new Response(FORTIGATE_BODY, { status: 200, headers: { 'content-type': 'text/html' } }),
    });

    const first = await SELF.fetch(`https://x/api/v1/fortibleed/check?target=${target}`);
    expect(first.status).toBe(200);
    const probesAfterFirst = upstream().length;
    expect(probesAfterFirst).toBeGreaterThan(0);

    // cachedJson writes through `waitUntil`; poll briefly so the test does not
    // race the cache put.
    const cacheKey = new Request(`https://route-cache.internal/v1/${encodeURIComponent(`fortibleed:check:${target}`)}`);
    for (let i = 0; i < 50; i++) {
      if (await caches.default.match(cacheKey)) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }

    const second = await SELF.fetch(`https://x/api/v1/fortibleed/check?target=${target}`);
    expect(second.status).toBe(200);
    const body = (await second.json()) as { isFortiGate: boolean };
    expect(body.isFortiGate).toBe(true);
    // No additional outbound probes — the cached result was served.
    expect(upstream().length).toBe(probesAfterFirst);
  });
});

describe('POST /api/v1/fortibleed/batch', () => {
  it('rejects an empty target list', async () => {
    const r = await SELF.fetch('https://x/api/v1/fortibleed/batch', {
      method: 'POST',
      // Same-origin marks the SPA caller, exactly as other route tests do:
      // a keyless mutation must carry it to clear the auth chain.
      headers: { 'content-type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
      body: JSON.stringify({ targets: [] }),
    });
    expect(r.status).toBe(400);
  });

  it('scans each target and returns one result per entry', async () => {
    setupFetch({
      probes: (url) =>
        url.includes('fortigate-d.example')
          ? new Response(FORTIGATE_BODY, { status: 200, headers: { 'content-type': 'text/html' } })
          : new Response('<html><body>nginx</body></html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    });
    const r = await SELF.fetch('https://x/api/v1/fortibleed/batch', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
      body: JSON.stringify({ targets: ['fortigate-d.example', 'plain-e.example'] }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { results: Array<{ target: string; isFortiGate: boolean }>; total: number };
    expect(body.total).toBe(2);
    expect(body.results[0]?.isFortiGate).toBe(true);
    expect(body.results[1]?.isFortiGate).toBe(false);
  });
});
