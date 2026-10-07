import { describe, it, expect } from 'vitest';
import { cveKey, actorKey, malwareKey, topicKey, slotIdFor } from '../../src/case-study/stable-keys';

describe('stable-keys', () => {
  it('cveKey lowercases and normalizes', () => {
    expect(cveKey('CVE-2026-1234')).toBe('cve-2026-1234');
    expect(cveKey('cve-2026-1234')).toBe('cve-2026-1234');
  });

  it('actorKey slugifies group name', () => {
    expect(actorKey('FIN7')).toBe('actor-fin7');
    expect(actorKey('APT29 (Cozy Bear)')).toBe('actor-apt29-cozy-bear');
  });

  it('malwareKey slugifies family name', () => {
    expect(malwareKey('Lumma Stealer')).toBe('malware-lumma-stealer');
  });

  it('topicKey prefixes and bounds the seed', () => {
    expect(topicKey('infostealer', 'Warden Stealer v1.9')).toBe('infostealer-warden-stealer-v1-9');
    // Long seeds are truncated so KV keys stay bounded and dedupe-stable.
    const long = topicKey('darkweb', 'x'.repeat(200));
    expect(long.length).toBeLessThanOrEqual('darkweb-'.length + 60);
  });

  it('slotIdFor is deterministic per slot', () => {
    expect(slotIdFor('2026-05-19T14:23:00Z')).toBe('slot-2026-05-19t14-23-00z');
  });

  it('rejects empty input', () => {
    expect(() => cveKey('')).toThrow();
    expect(() => actorKey('')).toThrow();
  });
});
