import { describe, it, expect } from 'vitest';
import { enrichFromPlatform } from '../../../src/case-study/research/enrich';

/**
 * Platform-facts enrichment (`enrichFromPlatform`).
 *
 * These assertions pin three shape bugs found in a 2026-10-18 audit — all of
 * them silent, because `selfFetchJson` swallows everything into `null`/empty
 * results and nothing downstream distinguishes "no data" from "wrong path":
 *
 *  1. The writeups call carried `?q=`, but `/api/v1/writeups` only reads
 *     `tier` — the param was ignored and unfiltered newest writeups were
 *     presented to the writer as "about this topic". Filtering now happens
 *     client-side via `matchesTopic`.
 *  2. The writeup summary was read from `w.summary`, but the route's item
 *     type carries it in `description` — summaries never reached the dossier.
 *  3. `relatedCves` claimed to be the "highest-severity slice" but sliced the
 *     corpus order; it is now sorted by CVSS before slicing.
 *
 * Fixtures are synthetic (CVE-2099-*, examplecorp) so they never rot.
 */

const SECRET = 'test-internal-secret';

/** SELF stub that records every requested URL and answers by path prefix. */
function selfStub(payloads: Record<string, unknown>) {
  const requested: string[] = [];
  return {
    requested,
    fetch: (async (req: RequestInfo) => {
      const raw = typeof req === 'string' ? req : req instanceof URL ? req.href : (req as Request).url;
      requested.push(raw);
      const path = new URL(raw).pathname;
      for (const [prefix, body] of Object.entries(payloads)) {
        if (path === prefix) {
          return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
        }
      }
      return new Response('[]', { headers: { 'content-type': 'application/json' } });
    }) as never,
  };
}

describe('enrichFromPlatform', () => {
  it('keeps only writeups that match the topic keyword client-side', async () => {
    const stub = selfStub({
      '/api/v1/writeups': {
        items: [
          {
            title: 'Examplecorp edge gateway deep dive',
            url: 'https://example.test/matching',
            description: 'How researchers chained bugs in the examplecorp appliance.',
            tags: ['research'],
          },
          {
            title: 'Kubernetes hardening checklist',
            url: 'https://example.test/unrelated',
            description: 'Cluster security basics.',
            tags: ['cloud'],
          },
          {
            title: 'Weekly roundup',
            url: 'https://example.test/tags-only',
            description: 'A general roundup.',
            tags: ['examplecorp', 'edge'],
          },
        ],
      },
      '/api/v1/cve-recent': { cves: [] },
      '/api/v1/cve-trends': { cves: [] },
      '/api/v1/misp-galaxy-actors': { actors: [] },
    });

    const facts = await enrichFromPlatform(stub, { INTERNAL_TOKEN_SECRET: SECRET }, 'examplecorp');

    expect(facts.writeups.map((w) => w.url)).toEqual([
      'https://example.test/matching',
      'https://example.test/tags-only',
    ]);
    // Summary is sourced from `description`, not the nonexistent `summary`.
    expect(facts.writeups[0]?.summary).toContain('chained bugs');

    // Regression: the writeups request must not carry a keyword param the
    // route ignores — the filter is ours, not the endpoint's.
    const writeupsUrl = stub.requested.find((u) => u.includes('/api/v1/writeups'));
    expect(writeupsUrl).toBeDefined();
    expect(writeupsUrl).not.toContain('q=');
    expect(writeupsUrl).not.toContain('limit=');
  });

  it('returns no writeups when nothing matches the keyword', async () => {
    const stub = selfStub({
      '/api/v1/writeups': {
        items: [{ title: 'Unrelated cloud piece', url: 'https://example.test/x', description: 'Nothing here.' }],
      },
      '/api/v1/cve-recent': { cves: [] },
      '/api/v1/cve-trends': { cves: [] },
      '/api/v1/misp-galaxy-actors': { actors: [] },
    });

    const facts = await enrichFromPlatform(stub, { INTERNAL_TOKEN_SECRET: SECRET }, 'netscaler');
    expect(facts.writeups).toEqual([]);
  });

  it('sorts related CVEs by CVSS before slicing and drops malformed ids', async () => {
    const stub = selfStub({
      '/api/v1/writeups': { items: [] },
      '/api/v1/cve-recent': {
        cves: [
          { id: 'CVE-2099-0001', score: 3.1, severity: 'LOW' },
          { id: 'not-a-cve', score: 10 },
          { id: 'CVE-2099-0002', score: 9.8, severity: 'CRITICAL' },
          { id: 'CVE-2099-0003', score: 7.5, severity: 'HIGH' },
        ],
      },
      '/api/v1/cve-trends': { cves: [] },
      '/api/v1/misp-galaxy-actors': { actors: [] },
    });

    const facts = await enrichFromPlatform(stub, { INTERNAL_TOKEN_SECRET: SECRET }, 'examplecorp');

    expect(facts.relatedCves.map((c) => c.id)).toEqual(['CVE-2099-0002', 'CVE-2099-0003', 'CVE-2099-0001']);
  });

  it('maps trending CVEs and MISP Galaxy actors from their real field names', async () => {
    const stub = selfStub({
      '/api/v1/writeups': { items: [] },
      '/api/v1/cve-recent': { cves: [] },
      '/api/v1/cve-trends': {
        cves: [
          { id: 'CVE-2099-0002', rank: 2, hypeScore: 40 },
          { id: 'CVE-2099-0009', rank: 1, hypeScore: 90 },
        ],
      },
      '/api/v1/misp-galaxy-actors': {
        actors: [{ value: 'APT-Example', slug: 'apt-example', mitre_id: 'G9999' }],
      },
    });

    const facts = await enrichFromPlatform(stub, { INTERNAL_TOKEN_SECRET: SECRET }, 'examplecorp');

    expect(facts.trendingCves.map((c) => c.id)).toEqual(['CVE-2099-0009', 'CVE-2099-0002']);
    expect(facts.trendingCves[0]?.hypeScore).toBe(90);
    expect(facts.actors).toEqual([{ name: 'APT-Example', slug: 'apt-example', mitre: 'G9999' }]);
  });

  it('is inert without the SELF binding, the secret, or a keyword', async () => {
    const stub = selfStub({});
    const empty = { writeups: [], relatedCves: [], trendingCves: [], actors: [] };

    await expect(enrichFromPlatform(undefined, { INTERNAL_TOKEN_SECRET: SECRET }, 'x')).resolves.toEqual(empty);
    await expect(enrichFromPlatform(stub, {}, 'x')).resolves.toEqual(empty);
    await expect(enrichFromPlatform(stub, { INTERNAL_TOKEN_SECRET: SECRET }, '')).resolves.toEqual(empty);
    expect(stub.requested).toEqual([]);
  });
});
