import { describe, it, expect } from 'vitest';
import { candidateUsesBlockedSource } from '../../src/case-study/source-blocklist';

/**
 * ExploitGrid is barred from discovery and from the admin pending queue
 * (product decision, 2026-10-19). The guard is the only thing standing between
 * a stale KV candidate and the operator's screen, so its exact matching rules
 * are pinned here — especially the "match URLs, not prose" rule, which is what
 * keeps a legitimate article *about* ExploitGrid from being dropped.
 */
describe('candidateUsesBlockedSource', () => {
  it.each([
    ['url', { url: 'https://exploitgrid.net/exploits/EGE-GH-abc' }],
    ['sourceUrl', { sourceUrl: 'https://www.exploitgrid.net/exploits/x' }],
    ['urls[]', { urls: ['https://nvd.nist.gov/vuln/detail/CVE-2026-1', 'https://exploitgrid.net/exploits/y'] }],
    ['sources[]', { sources: ['https://exploitgrid.net/exploits/z'] }],
    ['victims[].url', { victims: [{ url: 'https://exploitgrid.net/exploits/v' }] }],
  ])('matches a blocked host in evidence.%s', (_field, evidence) => {
    expect(candidateUsesBlockedSource({ evidence })).toBe(true);
  });

  it('keeps a candidate that merely cites the host in prose', () => {
    expect(
      candidateUsesBlockedSource({
        evidence: {
          description: 'Researchers showed the chain on exploitgrid.net last week.',
          url: 'https://example.com/post',
        },
      })
    ).toBe(false);
  });

  it('keeps a lookalike host that is not the blocked domain', () => {
    expect(candidateUsesBlockedSource({ evidence: { url: 'https://notexploitgrid.net/exploits/1' } })).toBe(false);
  });

  it('tolerates missing or malformed evidence', () => {
    expect(candidateUsesBlockedSource(null)).toBe(false);
    expect(candidateUsesBlockedSource({})).toBe(false);
    expect(candidateUsesBlockedSource({ evidence: { url: 'not-a-url' } })).toBe(false);
    expect(candidateUsesBlockedSource({ evidence: { urls: [null, 42, 'ftp://exploitgrid.net/x'] } })).toBe(false);
  });
});
