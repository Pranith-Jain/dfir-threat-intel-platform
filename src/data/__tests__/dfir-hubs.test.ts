/**
 * DFIR catalog completeness tests.
 *
 * Mirrors the threatintel/policy test pattern. Ensures:
 *   - The catalog has at least one page per hub.
 *   - The catalog has at least 100 pages (we currently have ~125).
 *   - Every page path is unique.
 *   - Every page has a non-empty label, desc, compVar, path, tabId.
 *   - The catalog search returns ranked matches.
 *   - The catalog covers every DFIR route registered in App.tsx.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { HUB_META, getAllPages, getHub, getPageByPath, flattenPages } from '../dfir-hubs';
import { CATALOG, catalogSearch } from '../dfir-catalog';

function extractDfirRoutes(): string[] {
  const appPath = resolve(__dirname, '..', '..', 'App.tsx');
  const src = readFileSync(appPath, 'utf8');
  const matches = src.matchAll(/path:\s*'(\/dfir\/[^']+)'/g);
  const out = new Set<string>();
  for (const m of matches) out.add(m[1]);
  return Array.from(out).sort();
}

describe('dfir-hubs (DFIR catalog registry)', () => {
  it('contains at least one hub', () => {
    expect(HUB_META.length).toBeGreaterThan(0);
  });

  it('every hub has a non-empty id, label, blurb, icon, and tone', () => {
    for (const h of HUB_META) {
      expect(h.id.length).toBeGreaterThan(0);
      expect(h.label.length).toBeGreaterThan(0);
      expect(h.blurb.length).toBeGreaterThan(0);
      expect(h.icon).toBeTruthy();
      expect(h.tone.length).toBeGreaterThan(0);
      expect(h.pages.length).toBeGreaterThan(0);
    }
  });

  it('has a healthy number of pages (>= 100)', () => {
    const total = HUB_META.reduce((sum, h) => sum + h.pages.length, 0);
    expect(total).toBeGreaterThanOrEqual(100);
  });

  it('every hub id is unique', () => {
    const ids = HUB_META.map((h) => h.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every page has non-empty path, tabId, label, desc, and compVar', () => {
    for (const h of HUB_META) {
      for (const p of h.pages) {
        expect(p.path.length).toBeGreaterThan(0);
        expect(p.tabId.length).toBeGreaterThan(0);
        expect(p.label.length).toBeGreaterThan(0);
        expect(p.desc.length).toBeGreaterThan(0);
        expect(p.compVar.length).toBeGreaterThan(0);
      }
    }
  });

  it('every page path is unique', () => {
    const paths = flattenPages().map((p) => p.path);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it('every page path starts with /dfir/', () => {
    for (const p of flattenPages()) {
      expect(p.path.startsWith('/dfir/')).toBe(true);
    }
  });

  it('getHub returns the right hub for a known id', () => {
    const hub = getHub('malware');
    expect(hub).toBeDefined();
    expect(hub?.label).toBe('Malware Analysis');
  });

  it('getPageByPath returns the right page for a known path', () => {
    const result = getPageByPath('/dfir/ioc-investigate');
    expect(result).toBeDefined();
    expect(result?.page.label).toBe('IOC Investigator');
    expect(result?.hub.id).toBe('ioc-triage');
  });

  it('getAllPages returns one entry per page', () => {
    const all = getAllPages();
    const total = HUB_META.reduce((sum, h) => sum + h.pages.length, 0);
    expect(all.length).toBe(total);
  });

  it('CATALOG matches HUB_META', () => {
    expect(CATALOG.length).toBe(HUB_META.length);
  });

  it('catalogSearch returns ranked matches for a real query', () => {
    const results = catalogSearch('ransomware');
    expect(results.length).toBeGreaterThan(0);
    for (let i = 1; i < results.length; i++) {
      expect(results[i - 1].score).toBeGreaterThanOrEqual(results[i].score);
    }
  });

  it('catalogSearch returns empty for an empty query', () => {
    expect(catalogSearch('')).toEqual([]);
    expect(catalogSearch('   ')).toEqual([]);
  });

  it('catalogSearch puts ATT&CK Navigator in the top results for mitre', () => {
    const results = catalogSearch('mitre');
    const topPaths = results.slice(0, 10).map((r) => r.path);
    expect(topPaths).toContain('/dfir/attack-navigator');
  });

  it('catalogSearch finds pages by hub label', () => {
    const results = catalogSearch('Detection Engineering');
    expect(results.length).toBeGreaterThan(0);
  });

  it('newly added pages are findable', () => {
    // dnscope / passive-dns / cert-search / whois-history / asn / wayback /
    // host-graph used to be listed here. They are tabs of
    // /dfir/domain-investigator now, so they are covered by
    // hub-tab-deeplinks.test.ts rather than as catalog pages.
    for (const p of ['/dfir/domain-investigator', '/dfir/sigbase']) {
      const result = getPageByPath(p);
      expect(result, `${p} is missing from the catalog`).toBeDefined();
    }
  });

  it('covers every DFIR route registered in App.tsx', () => {
    const routes = extractDfirRoutes();
    const registered = new Set(flattenPages().map((p) => p.path));
    // Read the redirects from App.tsx so a route added to REDIRECTS
    // doesn't break this test. Keeps the hubs/catalog in sync with
    // collapsed aliases (e.g. /dfir/dork-builder → /dfir/google-dorks).
    const appSrc = readFileSync(resolve(__dirname, '..', '..', 'App.tsx'), 'utf8');
    const appRedirects = new Set<string>();
    const redirectBlock = appSrc.match(/const REDIRECTS[\s\S]*?\n\];/);
    if (redirectBlock) {
      for (const m of redirectBlock[0].matchAll(/path:\s*'([^']+)'/g)) {
        if (m[1].startsWith('/dfir/')) appRedirects.add(m[1]);
      }
    }
    const REDIRECTS = new Set([
      '/dfir/infostealer-intel',
      '/dfir/host',
      '/dfir/sigma-convert',
      '/dfir/detection-lab',
      '/dfir/dashboard',
      '/dfir/atlas',
      '/dfir/discord-watch',
      '/dfir/industry-news',
      ...appRedirects,
    ]);
    // Catalog + per-hub landings are not in the registry - they're the
    // pages that DISPLAY the catalog. The catalog page itself is its own
    // route (/dfir/catalog) and the per-hub landings use /dfir/c/:cat.
    const CATALOG_ROUTES = new Set(['/dfir/catalog']);
    // Standalone pages that exist in App.tsx but are not part of the hub catalog system
    const STANDALONE_ROUTES = new Set([
      '/dfir/attack-chains',
      '/dfir/attack-surface',
      '/dfir/phishing-identity',
      '/dfir/ransomware-killchain',
      '/dfir/traceix',
      '/dfir/winreg',
    ]);
    // Note: chokepoints/framework, chokepoints/cross-chain, attack-chains/*,
    // and trends/* are now consolidated into DetectionChokepointsHub (single route).
    const expected = routes.filter(
      (r) => !REDIRECTS.has(r) && !CATALOG_ROUTES.has(r) && !STANDALONE_ROUTES.has(r) && !r.includes(':')
    );
    const missing = expected.filter((r) => !registered.has(r));
    if (missing.length > 0) {
      throw new Error(`dfir-hubs is missing entries for these App.tsx routes:\n  - ${missing.join('\n  - ')}`);
    }
  });
});
