import { describe, it, expect, vi, afterEach } from 'vitest';
import { btcAbuseCheck, extractOnionHostname, isValidOnionAddress, parseHtmlBasic, tor2webUrl } from './darknet';

const ADDR = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';

describe('isValidOnionAddress', () => {
  it('accepts v2 onion address', () => {
    expect(isValidOnionAddress('facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion')).toBe(true);
  });

  it('accepts v3 onion address', () => {
    expect(isValidOnionAddress('2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion')).toBe(true);
  });

  it('rejects non-onion strings', () => {
    expect(isValidOnionAddress('example.com')).toBe(false);
    expect(isValidOnionAddress('not-an-onion')).toBe(false);
    expect(isValidOnionAddress('')).toBe(false);
  });

  it('is case sensitive (lowercase only)', () => {
    expect(isValidOnionAddress('FACEBOOKWKPILNEMXJ7ASANIU7VNJJ.BILT...')).toBe(false);
  });
});

describe('extractOnionHostname', () => {
  it('extracts hostname from full URL', () => {
    expect(extractOnionHostname('http://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion/page')).toBe(
      'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion'
    );
  });

  it('accepts bare hostname', () => {
    expect(extractOnionHostname('2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion')).toBe(
      '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion'
    );
  });

  it('returns null for invalid input', () => {
    expect(extractOnionHostname('example.com')).toBe(null);
    expect(extractOnionHostname('')).toBe(null);
  });
});

const V2_ONION = 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion';
const V3_ONION = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion';

describe('isValidOnionAddress — exact lengths only (#300)', () => {
  // The two validators disagreed before #300: this one accepted exactly 16 or
  // 56, while darkweb-osint's inline copy used {16,56} and accepted anything in
  // between. Pin the exact-length rule so the dedupe cannot regress to a range.

  it('rejects lengths between v2 and v3', () => {
    for (const n of [15, 17, 20, 40, 55]) {
      expect(isValidOnionAddress('a'.repeat(n) + '.onion')).toBe(false);
    }
  });

  it('rejects a bare hostname with no .onion suffix', () => {
    expect(isValidOnionAddress('facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd')).toBe(false);
  });

  it('rejects a double suffix', () => {
    expect(isValidOnionAddress(`${V2_ONION}.onion`)).toBe(false);
  });

  it('accepts uppercase and surrounding whitespace', () => {
    expect(isValidOnionAddress(V2_ONION.toUpperCase())).toBe(true);
    expect(isValidOnionAddress(`  ${V2_ONION}  `)).toBe(true);
  });
});

describe('tor2webUrl', () => {
  it('builds correct tor2web URL', () => {
    const result = tor2webUrl('facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion', 'tor2web.io');
    expect(result).toBe('https://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion.tor2web.io/');
  });

  it('strips protocol prefix from input', () => {
    const result = tor2webUrl('http://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion', 'onion.ws');
    expect(result).toBe('https://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion.onion.ws/');
  });

  it('uses the subdomain form, not a path segment', () => {
    // Regression guard: tor2web gateways are addressed as a subdomain of the
    // onion host (`<onion>.<gateway>`). The path form (`<onion>/<gateway>`)
    // requests a path on the onion address itself and never resolves.
    expect(tor2webUrl(V2_ONION, 'tor2web.io')).not.toContain('.onion/');
  });

  // ── #300: the builder validates, not just the callers ──────────────────
  // Before this, tor2webUrl concatenated whatever it was given, and safety came
  // entirely from the caller. These assert the guard now lives in the builder.

  it('throws on a non-onion host rather than building a URL from it', () => {
    expect(() => tor2webUrl('example.com', 'tor2web.io')).toThrow(/Invalid \.onion/);
    expect(() => tor2webUrl('evil.com', 'tor2web.io')).toThrow(/Invalid \.onion/);
  });

  it('throws on an onion-suffix host whose label is not a valid length', () => {
    // `example.onion` is 7 chars — not v2 (16) or v3 (56). The old builder
    // accepted it and produced a gateway URL that resolves to whatever that
    // subdomain happens to be, i.e. not to the intended onion service.
    expect(() => tor2webUrl('example.onion', 'tor2web.io')).toThrow(/Invalid \.onion/);
    expect(() => tor2webUrl('a'.repeat(20) + '.onion', 'tor2web.io')).toThrow(/Invalid \.onion/);
  });

  it('throws on base32 characters outside the onion alphabet', () => {
    // a-z2-7 only: 0, 1, 8 and 9 are not base32, so an address containing them
    // is not a real onion address even at the right length.
    expect(() => tor2webUrl('0'.repeat(16) + '.onion', 'tor2web.io')).toThrow(/Invalid \.onion/);
    expect(() => tor2webUrl('a'.repeat(15) + '8' + '.onion', 'tor2web.io')).toThrow(/Invalid \.onion/);
  });

  it('throws when the input carries a path or port', () => {
    // Both reach the URL authority component via concatenation: a path would be
    // dropped, and a port would change the destination port. Neither is a valid
    // bare onion address, so both are rejected.
    expect(() => tor2webUrl(`${V2_ONION}/admin`, 'tor2web.io')).toThrow(/Invalid \.onion/);
    expect(() => tor2webUrl(`${V2_ONION}:8443`, 'tor2web.io')).toThrow(/Invalid \.onion/);
  });

  it('strips credentials rather than forwarding them to the gateway', () => {
    // The old builder removed the scheme with a regex, leaving
    // `user:pass@<onion>` in the string — so the credentials were concatenated
    // into the authority and SENT to the gateway. Normalising through URL
    // parsing drops them, which is the property that matters here.
    expect(tor2webUrl(`http://user:pass@${V2_ONION}`, 'tor2web.io')).toBe(`https://${V2_ONION}.tor2web.io/`);
  });

  it('throws on an attacker-supplied gateway', () => {
    // The gateway also lands in the authority component. It is a module
    // constant at every call site, but the builder should not depend on that.
    expect(() => tor2webUrl(V2_ONION, 'evil.example.com/path')).toThrow(/Invalid tor2web gateway/);
    expect(() => tor2webUrl(V2_ONION, 'has space')).toThrow(/Invalid tor2web gateway/);
    expect(() => tor2webUrl(V2_ONION, 'a.com/x#y')).toThrow(/Invalid tor2web gateway/);
  });

  it('accepts an uppercase onion address and normalises it', () => {
    expect(tor2webUrl(V2_ONION.toUpperCase(), 'tor2web.io')).toBe(`https://${V2_ONION}.tor2web.io/`);
  });

  it('still accepts the real v2 and v3 addresses unchanged', () => {
    expect(tor2webUrl(V2_ONION, 'tor2web.io')).toBe(`https://${V2_ONION}.tor2web.io/`);
    expect(tor2webUrl(V3_ONION, 'tor2web.io')).toBe(`https://${V3_ONION}.tor2web.io/`);
  });
});

describe('btcAbuseCheck', () => {
  afterEach(() => vi.restoreAllMocks());

  it('degrades gracefully (no throw) when no API key is configured', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const r = await btcAbuseCheck(ADDR);
    expect(r.unavailable).toBe(true);
    expect(r.count).toBe(0);
    expect(r.reports).toHaveLength(0);
    expect(r.note).toMatch(/API key/i);
    // No upstream call should happen without credentials.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('degrades gracefully when ChainAbuse returns 401', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"message":"Invalid credentials"}', { status: 401 }));
    const r = await btcAbuseCheck(ADDR, 'fake-key');
    expect(r.unavailable).toBe(true);
    expect(r.note).toMatch(/HTTP 401/);
  });

  it('sends HTTP Basic auth with the key as both user and pass', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{"reports":[],"count":0}', { status: 200 }));
    await btcAbuseCheck(ADDR, 'k3y');
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    const auth = (init.headers as Record<string, string>)['Authorization'];
    expect(auth).toBe(`Basic ${btoa('k3y:k3y')}`);
  });

  it('parses reports on a successful response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ reports: [{ id: '1', address: ADDR, category: 'SCAM' }], count: 1 }), {
        status: 200,
      })
    );
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.unavailable).toBeUndefined();
    expect(r.count).toBe(1);
    expect(r.reports).toHaveLength(1);
  });

  it('treats 404 as a clean empty result (address not in DB)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 404 }));
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.unavailable).toBeUndefined();
    expect(r.count).toBe(0);
    expect(r.reports).toHaveLength(0);
  });

  // ── verdict: the field that stops "couldn't check" reading as "clean" ──

  it('reports verdict=unknown (not clean) when no API key is configured', async () => {
    const r = await btcAbuseCheck(ADDR);
    expect(r.verdict).toBe('unknown');
    // The dangerous shape this guards against: an empty result set that a
    // consumer could read as a cleared address.
    expect(r.count).toBe(0);
    expect(r.reports).toHaveLength(0);
  });

  it('reports verdict=unknown on upstream error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('boom', { status: 500 }));
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.verdict).toBe('unknown');
    expect(r.unavailable).toBe(true);
  });

  it('reports verdict=unknown when the network throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('ECONNRESET'));
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.verdict).toBe('unknown');
  });

  it('reports verdict=flagged when abuse reports exist', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ reports: [{ id: '1', address: ADDR, category: 'RANSOMWARE' }], count: 1 }), {
        status: 200,
      })
    );
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.verdict).toBe('flagged');
    expect(r.unavailable).toBeUndefined();
  });

  it('reports verdict=clean on a completed lookup with no reports', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"reports":[],"count":0}', { status: 200 }));
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.verdict).toBe('clean');
    expect(r.unavailable).toBeUndefined();
  });

  it('reports verdict=clean on 404 (address absent from ChainAbuse DB)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 404 }));
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.verdict).toBe('clean');
  });

  it('falls back to reports.length when upstream omits count', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ reports: [{ id: '1', address: ADDR, category: 'SCAM' }] }), { status: 200 })
    );
    const r = await btcAbuseCheck(ADDR, 'k3y');
    expect(r.count).toBe(1);
    expect(r.verdict).toBe('flagged');
  });

  it('never reports verdict=clean on a failed lookup', async () => {
    for (const res of [
      new Response('', { status: 401 }),
      new Response('', { status: 403 }),
      new Response('', { status: 429 }),
      new Response('', { status: 500 }),
      new Response('', { status: 503 }),
    ]) {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(res);
      const r = await btcAbuseCheck(ADDR, 'k3y');
      expect(r.verdict).toBe('unknown');
    }
  });
});

describe('parseHtmlBasic', () => {
  it('extracts title from HTML', () => {
    const { title } = parseHtmlBasic('<html><head><title>Test Page</title></head></html>');
    expect(title).toBe('Test Page');
  });

  it('extracts links from HTML', () => {
    const { links } = parseHtmlBasic('<a href="http://example.onion/page">click here</a>');
    expect(links).toHaveLength(1);
    expect(links[0]!.href).toBe('http://example.onion/page');
    expect(links[0]!.text).toBe('click here');
  });

  it('extracts body text from HTML', () => {
    const { bodyText } = parseHtmlBasic('<html><body><p>Hello world</p><script>alert(1)</script></body></html>');
    expect(bodyText).toContain('Hello world');
    expect(bodyText).not.toContain('alert');
  });

  it('returns empty strings for empty input', () => {
    const { title, links, bodyText } = parseHtmlBasic('');
    expect(title).toBe('');
    expect(links).toHaveLength(0);
    expect(bodyText).toBe('');
  });
});
