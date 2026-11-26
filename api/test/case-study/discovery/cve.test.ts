import { describe, it, expect, vi } from 'vitest';
import { discoverCves } from '../../../src/case-study/discovery/cve';

const fakeKev = {
  vulnerabilities: [
    {
      cveID: 'CVE-2026-1234',
      vendorProject: 'Fortinet',
      product: 'FortiGate',
      vulnerabilityName: 'Authentication Bypass',
      dateAdded: '2026-05-14',
      shortDescription: 'Auth bypass',
      knownRansomwareCampaignUse: 'Known',
    },
  ],
};

describe('discoverCves', () => {
  it('returns candidates from KEV with kev=true severity', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes('cisa.gov')) return new Response(JSON.stringify(fakeKev));
      return new Response(JSON.stringify({ vulnerabilities: [] }));
    });
    const now = new Date('2026-05-14T06:00:00Z');
    const cands = await discoverCves({ fetch: fetchMock as any, now, getDedup: async () => null });
    expect(cands.length).toBeGreaterThan(0);
    const c = cands.find((x) => x.key === 'cve-2026-1234');
    expect(c).toBeDefined();
    expect(c!.type).toBe('cve');
    expect(c!.evidence.kev).toBe(true);
    expect(c!.score).toBeGreaterThan(0.6);
  });

  it('never probes canonical NVD pages and caps NVD enrichment at eight', async () => {
    // A 14-day KEV window held 26 entries on a busy day. The old code spent
    // one HEAD probe per entry plus one NVD lookup per entry (~53 requests),
    // exhausting the Free-plan budget before later runners even fetched.
    const entries = Array.from({ length: 12 }, (_, i) => ({
      cveID: `CVE-2026-${String(1000 + i)}`,
      vendorProject: 'Acme',
      product: 'Gateway',
      vulnerabilityName: 'Bug',
      dateAdded: '2026-05-14',
      shortDescription: 'Synthetic description',
    }));
    const urls: string[] = [];
    const fetchMock = vi.fn(async (url: string) => {
      urls.push(url);
      if (url.includes('cisa.gov')) return new Response(JSON.stringify({ vulnerabilities: entries }));
      return new Response(
        JSON.stringify({
          vulnerabilities: [{ cve: { id: url, metrics: {}, configurations: [], weaknesses: [] } }],
        })
      );
    });
    const cands = await discoverCves({
      fetch: fetchMock as any,
      now: new Date('2026-05-14T06:00:00Z'),
      getDedup: async () => null,
    });

    expect(cands).toHaveLength(12);
    expect(urls.filter((u) => /nvd\.nist\.gov\/vuln\/detail/.test(u))).toHaveLength(0);
    expect(urls.filter((u) => u.includes('services.nvd.nist.gov'))).toHaveLength(8);
    for (const c of cands) {
      const statuses = c.evidence.sourceLinkStatuses as Record<string, string> | undefined;
      expect(statuses?.[`https://nvd.nist.gov/vuln/detail/${c.evidence.cveId}`]).toBe('ok');
    }
  });

  it('penalizes novelty if previously seen', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(fakeKev)));
    const now = new Date('2026-05-14T06:00:00Z');
    const dedup = async (_key: string) => ({ lastSeenAt: now.toISOString() });
    const cands = await discoverCves({ fetch: fetchMock as any, now, getDedup: dedup });
    expect(cands[0]!.score).toBeLessThan(0.76);
  });
});
