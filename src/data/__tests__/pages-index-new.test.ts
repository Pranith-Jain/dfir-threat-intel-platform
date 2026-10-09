import { describe, it, expect } from 'vitest';
import { searchPages } from '../pages-index';

describe('new pages in catalog', () => {
  it.each([
    ['/dfir/dnscope', 'dnscope'],
    ['/dfir/tracerules', 'tracerules'],
    ['/dfir/passive-dns', 'passive dns'],
    ['/dfir/sigbase', 'yara'],
  ])('has catalog entry for %s', (path, query) => {
    const matches = searchPages(query, { limit: 5 });
    const found = matches.some((m) => m.page.path === path);
    expect(found, `Path ${path} should be found via search for "${query}"`).toBe(true);
  });

  // /threatintel/extremists and /threatintel/predators were dropped as
  // duplicates of the Actor Hub; their routes now redirect there. The
  // assertions that pinned them in the catalog were removed with them.

  it('registry query finds Registry Hive', () => {
    const matches = searchPages('registry');
    expect(matches.some((m) => m.page.path === '/dfir/registry-hive')).toBe(true);
  });

  it('mitre query finds the ATT&CK Navigator', () => {
    const matches = searchPages('mitre');
    expect(matches.some((m) => m.page.path === '/dfir/attack-navigator')).toBe(true);
  });
});
