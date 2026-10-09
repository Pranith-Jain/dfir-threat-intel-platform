/**
 * Tests for the shared onion validator after the #300 dedupe.
 *
 * `darkweb-osint.ts` used to carry its own inline validator
 * (`/^[a-z2-7]{16,56}\.onion$/`) alongside `isValidOnionAddress` in `darknet.ts`
 * (exactly 16 or 56). They disagreed: the inline copy accepted lengths in
 * between, so an invalid address could reach `tor2webUrl` and produce a gateway
 * URL resolving to whatever that subdomain happens to be.
 *
 * The point of these tests is the DEDUPE, not the regex — `onionHost` is private
 * to the module, so these drive the exported `darkwebCrawl` / `darkwebScrapeDeep`
 * and assert that invalid input is refused before any fetch happens. That is the
 * property that actually matters: an address that never reaches the network is
 * safer than one that reaches it and fails.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { darkwebCrawl, darkwebScrapeDeep } from '../../api/src/lib/darkweb-osint';
import { isValidOnionAddress, extractOnionHostname } from '../../api/src/lib/darknet';

const V2 = 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion';

/** Addresses the OLD `{16,56}` validator accepted but the correct one must not. */
const WRONG_LENGTH = [
  'a'.repeat(17) + '.onion',
  'a'.repeat(20) + '.onion',
  'a'.repeat(32) + '.onion',
  'a'.repeat(40) + '.onion',
  'a'.repeat(55) + '.onion',
];

describe('onion validation is shared, not duplicated', () => {
  afterEach(() => vi.restoreAllMocks());

  it('both entry points agree on the valid v2 address', () => {
    expect(isValidOnionAddress(V2)).toBe(true);
    expect(extractOnionHostname(V2)).toBe(V2);
    expect(extractOnionHostname(`http://${V2}`)).toBe(V2);
  });

  it('rejects between-length labels that the old range validator allowed', () => {
    // The disagreement itself: {16,56} said true, exact-length says false.
    for (const addr of WRONG_LENGTH) {
      expect(isValidOnionAddress(addr), `${addr} has no valid onion length`).toBe(false);
      expect(extractOnionHostname(addr)).toBeNull();
    }
  });

  it('scrapeDeep refuses a between-length onion before any network call', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    await expect(darkwebScrapeDeep('a'.repeat(20) + '.onion')).rejects.toThrow(/Invalid \.onion/);
    expect(spy).not.toHaveBeenCalled();
  });

  it('crawl refuses a between-length onion before any network call', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    await expect(darkwebCrawl('a'.repeat(40) + '.onion')).rejects.toThrow(/Invalid \.onion/);
    expect(spy).not.toHaveBeenCalled();
  });

  it('refuses a non-onion host outright', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    for (const bad of ['example.com', 'localhost', '127.0.0.1', '169.254.169.254']) {
      await expect(darkwebScrapeDeep(bad)).rejects.toThrow(/Invalid \.onion/);
    }
    expect(spy).not.toHaveBeenCalled();
  });

  it('refuses a non-base32 onion label', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    // 0, 1, 8, 9 are not in the base32 alphabet (a-z2-7).
    await expect(darkwebScrapeDeep('0'.repeat(16) + '.onion')).rejects.toThrow(/Invalid \.onion/);
    await expect(darkwebScrapeDeep('a'.repeat(15) + '9' + '.onion')).rejects.toThrow(/Invalid \.onion/);
    expect(spy).not.toHaveBeenCalled();
  });

  it('accepts a valid v3 onion (56 chars)', async () => {
    const v3 = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion';
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html><body><p>hello</p></body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      })
    );
    // Reaching fetch is the assertion: validation passed and the request went out.
    await darkwebScrapeDeep(v3);
    expect(spy).toHaveBeenCalled();
    const called = String((spy.mock.calls[0]?.[0] as Request | string) ?? '');
    expect(called).toContain(`${v3}.`);
  });

  it('normalises the onion host before building the gateway URL', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html><body><p>hi</p></body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      })
    );
    await darkwebScrapeDeep(`http://${V2}/`);
    const called = String((spy.mock.calls[0]?.[0] as Request | string) ?? '');
    // Lowercased, scheme stripped, gateway appended as a subdomain.
    expect(called).toContain(`${V2}.`);
    expect(called).not.toContain('http://');
  });
});
