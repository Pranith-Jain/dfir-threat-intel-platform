import { describe, it, expect, vi } from 'vitest';
import { discoverTrendResearch } from '../../../src/case-study/discovery/trend-research';
import type { DedupRecord } from '../../../src/case-study/types';

/**
 * Trend research — the replacement for the LLM-invented trends runner.
 *
 * The behaviour worth pinning is the negative space: this runner must produce
 * NOTHING when the corpus is empty or unavailable. Its predecessor
 * guaranteed three candidates a day by asking an LLM to invent story ideas,
 * which is why it needed a fabricated-host blocklist and an NVD existence
 * probe to catch its own output. Inverting the order — read the corpus first,
 * only then phrase the material — removes that whole failure class.
 *
 * The positive tests are about grounding: a candidate is only emitted when its
 * source URL is either a canonical authority or verifiably resolves.
 */

const NOW = new Date('2026-10-07T12:00:00Z');
const noDedup = async (): Promise<DedupRecord | null> => null;

/**
 * SELF stub returning one fixed payload per path.
 *
 * `selfFetchJson` passes a real `Request` to `fetch`, so the URL has to be
 * read from `req.url` — `String(req)` yields "[object Request]" and the stub
 * silently matches nothing.
 */
function selfStub(payloads: Record<string, unknown>) {
  return {
    fetch: (async (req: RequestInfo) => {
      const raw = typeof req === 'string' ? req : req instanceof URL ? req.href : (req as Request).url;
      const path = new URL(raw).pathname;
      for (const [prefix, body] of Object.entries(payloads)) {
        if (path.startsWith(prefix)) {
          return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
        }
      }
      return new Response('[]', { headers: { 'content-type': 'application/json' } });
    }) as never,
  };
}

/** A KEV entry added inside the window. */
function kevEntry(overrides: Record<string, unknown> = {}) {
  return {
    cveId: 'CVE-2099-0100',
    vendorProject: 'examplecorp',
    product: 'edgegateway',
    vulnerabilityName: 'Synthetic authentication bypass',
    dateAdded: '2026-10-07T06:00:00Z',
    dueDate: '2026-10-28',
    shortDescription: 'Exploitation observed.',
    knownRansomwareCampaignUse: 'Known',
    ...overrides,
  };
}

describe('discoverTrendResearch — produces nothing when the corpus is silent', () => {
  it('returns [] when the SELF binding is absent', async () => {
    const out = await discoverTrendResearch({
      now: NOW,
      getDedup: noDedup,
      self: undefined,
      internalTokenSecret: 'secret',
    });
    expect(out).toEqual([]);
  });

  it('returns [] when the internal token secret is absent', async () => {
    const out = await discoverTrendResearch({
      now: NOW,
      getDedup: noDedup,
      self: selfStub({}),
      internalTokenSecret: undefined,
    });
    expect(out).toEqual([]);
  });

  it('returns [] when every endpoint comes back empty', async () => {
    const out = await discoverTrendResearch({
      now: NOW,
      getDedup: noDedup,
      self: selfStub({
        '/api/v1/cve-trends': { cves: [] },
        '/api/v1/cisa-kev': { vulnerabilities: [] },
        '/api/v1/cve-recent': { cves: [] },
        '/api/v1/writeups': { items: [] },
        '/api/v1/darkweb-monitor': { items: [] },
      }),
      internalTokenSecret: 'secret',
    });
    // A quiet day should mean no post, not an invented one.
    expect(out).toEqual([]);
  });

  it('returns [] when the SELF binding throws', async () => {
    const self = {
      fetch: (async () => {
        throw new Error('binding unavailable');
      }) as never,
    };
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toEqual([]);
  });
});

describe('discoverTrendResearch — KEV additions are the top signal', () => {
  it('emits a candidate for a KEV entry added inside the window', async () => {
    const self = selfStub({ '/api/v1/cisa-kev': { vulnerabilities: [kevEntry()] } });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('exploit');
    expect(out[0]?.evidence.cveId).toBe('CVE-2099-0100');
    expect(out[0]?.evidence.kev).toBe(true);
    expect(out[0]?.rationale).toMatch(/Known Exploited Vulnerabilities/i);
    expect(out[0]?.rationale).toMatch(/ransomware/i);
  });

  it('ignores a KEV entry added outside the window', async () => {
    const self = selfStub({
      '/api/v1/cisa-kev': { vulnerabilities: [kevEntry({ dateAdded: '2026-09-01T06:00:00Z' })] },
    });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toEqual([]);
  });

  it('classifies a non-ransomware KEV addition as a vuln explainer', async () => {
    const self = selfStub({
      '/api/v1/cisa-kev': {
        vulnerabilities: [kevEntry({ knownRansomwareCampaignUse: 'Unknown' })],
      },
    });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out[0]?.type).toBe('vulnfaq');
  });

  it('anchors the candidate to the CISA KEV permalink', async () => {
    const self = selfStub({ '/api/v1/cisa-kev': { vulnerabilities: [kevEntry()] } });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out[0]?.evidence.url).toContain('known-exploited-vulnerabilities-catalog');
  });
});

describe('discoverTrendResearch — trending CVEs', () => {
  it('emits a candidate for a high-hype trending CVE', async () => {
    const self = selfStub({
      '/api/v1/cve-trends': {
        cves: [
          {
            id: 'CVE-2099-0200',
            rank: 1,
            hype_score: 13,
            description: 'Synthetic remote code execution in a widely deployed appliance.',
          },
        ],
      },
    });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('vulnfaq');
    expect(out[0]?.evidence.hypeScore).toBe(13);
    expect(out[0]?.title).toContain('CVE-2099-0200');
  });

  it('ignores a trending row with no CVE id', async () => {
    const self = selfStub({
      '/api/v1/cve-trends': { cves: [{ id: 'not-a-cve', rank: 1, hype_score: 9 }] },
    });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toEqual([]);
  });
});

describe('discoverTrendResearch — grounding gate', () => {
  it('drops a candidate whose source URL does not verify', async () => {
    // A writeup URL that the link checker cannot confirm is exactly where a
    // fabricated citation hides. Unlike the old LLM runner, every candidate
    // here is anchored to a real corpus record — so 'unchecked' is not enough.
    const self = selfStub({
      '/api/v1/writeups': {
        items: [
          {
            title: 'Synthetic analysis',
            url: 'https://nowhere.example.org/post',
            slug: 'synthetic-analysis',
            published_at: '2026-10-07T08:00:00Z',
          },
        ],
      },
    });
    const verify = await import('../../../src/lib/verify-url');
    const spy = vi
      .spyOn(verify, 'verifyUrls')
      .mockResolvedValue(
        new Map([['https://nowhere.example.org/post', { linkStatus: 'broken', ok: false, status: 404 }]]) as never
      );

    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toEqual([]);
    spy.mockRestore();
  });

  it('drops a candidate whose source URL is only unchecked', async () => {
    const self = selfStub({
      '/api/v1/writeups': {
        items: [
          {
            title: 'Synthetic analysis',
            url: 'https://waf.example.org/post',
            slug: 'synthetic-analysis',
            published_at: '2026-10-07T08:00:00Z',
          },
        ],
      },
    });
    const verify = await import('../../../src/lib/verify-url');
    const spy = vi
      .spyOn(verify, 'verifyUrls')
      .mockResolvedValue(
        new Map([['https://waf.example.org/post', { linkStatus: 'unchecked', ok: false, status: 403 }]]) as never
      );

    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toEqual([]);
    spy.mockRestore();
  });

  it('keeps a candidate whose source URL verifies ok', async () => {
    const self = selfStub({
      '/api/v1/writeups': {
        items: [
          {
            title: 'Synthetic analysis',
            url: 'https://blog.example.com/post',
            slug: 'synthetic-analysis',
            published_at: '2026-10-07T08:00:00Z',
          },
        ],
      },
    });
    const verify = await import('../../../src/lib/verify-url');
    const spy = vi
      .spyOn(verify, 'verifyUrls')
      .mockResolvedValue(
        new Map([['https://blog.example.com/post', { linkStatus: 'ok', ok: true, status: 200 }]]) as never
      );

    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toHaveLength(1);
    expect(out[0]?.title).toBe('Synthetic analysis');
    spy.mockRestore();
  });

  it('skips a key already published', async () => {
    const self = selfStub({ '/api/v1/cisa-kev': { vulnerabilities: [kevEntry()] } });
    const out = await discoverTrendResearch({
      now: NOW,
      getDedup: async () => ({ lastSeenAt: NOW.toISOString(), publishedSlug: 'some-slug' }),
      self,
      internalTokenSecret: 'secret',
    });
    expect(out).toEqual([]);
  });
});

describe('discoverTrendResearch — EPSS outliers', () => {
  it('flags a remotely-reachable CVE well above the cohort median', async () => {
    // A realistic cohort: a spread of scores plus one clear outlier that is
    // also remotely reachable.
    const rows = [
      { id: 'CVE-2099-0301', epss: 0.02, description: 'Local privilege escalation.' },
      { id: 'CVE-2099-0302', epss: 0.03, description: 'Requires an authenticated session.' },
      { id: 'CVE-2099-0303', epss: 0.04, description: 'Information disclosure only.' },
      { id: 'CVE-2099-0304', epss: 0.05, description: 'Stored XSS in a component.' },
      { id: 'CVE-2099-0305', epss: 0.06, description: 'Path traversal in an archive handler.' },
      { id: 'CVE-2099-0306', epss: 0.07, description: 'Denial of service via a crafted request.' },
      { id: 'CVE-2099-0307', epss: 0.08, description: 'Cross-site scripting in a web console.' },
      { id: 'CVE-2099-0308', epss: 0.09, description: 'Missing authorisation on an API endpoint.' },
      { id: 'CVE-2099-0399', epss: 0.94, description: 'Unauthenticated remote attacker can execute code.' },
    ];
    const self = selfStub({ '/api/v1/cve-recent': { cves: rows } });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });

    const ids = out.map((c) => c.evidence.cveId);
    expect(ids).toContain('CVE-2099-0399');
    // The cohort itself must not be surfaced as outliers.
    expect(ids).not.toContain('CVE-2099-0301');
  });

  it('does not flag an outlier that needs local access', async () => {
    // High EPSS but a strong precondition is a different operational problem;
    // ranking it as a remote exploitation story would be misleading.
    const rows = Array.from({ length: 9 }, (_, i) => ({
      id: `CVE-2099-04${String(i).padStart(2, '0')}`,
      epss: 0.05 + i * 0.005,
      description: 'A local attacker with physical access can read memory.',
    }));
    rows.push({ id: 'CVE-2099-0499', epss: 0.95, description: 'A local attacker can escalate privileges.' });
    const self = selfStub({ '/api/v1/cve-recent': { cves: rows } });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out.map((c) => c.evidence.cveId)).not.toContain('CVE-2099-0499');
  });

  it('needs a cohort before it will call anything an outlier', async () => {
    const self = selfStub({
      '/api/v1/cve-recent': {
        cves: [{ id: 'CVE-2099-0599', epss: 0.99, description: 'Unauthenticated remote code execution.' }],
      },
    });
    // A single high score with no comparison set is not an outlier.
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out).toEqual([]);
  });
});

describe('discoverTrendResearch — provenance', () => {
  it('records which corpus signal produced the candidate', async () => {
    const self = selfStub({ '/api/v1/cisa-kev': { vulnerabilities: [kevEntry()] } });
    const out = await discoverTrendResearch({ now: NOW, getDedup: noDedup, self, internalTokenSecret: 'secret' });
    expect(out[0]?.evidence.signal).toBe('new-kev');
    expect(String(out[0]?.evidence.provenance)).toMatch(/platform corpus/);
  });
});
