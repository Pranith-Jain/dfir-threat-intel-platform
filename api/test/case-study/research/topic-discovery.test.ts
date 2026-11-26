import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Candidate } from '../../../src/case-study/types';

/**
 * Bare-topic research regression.
 *
 * The admin Generate tab used to hand the writer a dossier with zero sources
 * read: the operator supplies a subject, not a candidate with source URLs, so
 * `candidateUrls()` returned [] and no page was ever fetched or verified.
 * These tests pin the fix: a topic's URLs and CVE ids are discovered from the
 * operator's text and the platform corpus, then actually fetched before the
 * dossier reaches the prompt.
 */

const SECRET = 'test-internal-secret';

vi.mock('../../../src/case-study/research/extract', async () => {
  const actual = await vi.importActual<typeof import('../../../src/case-study/research/extract')>(
    '../../../src/case-study/research/extract'
  );
  return {
    ...actual,
    extractPage: vi.fn(async (url: string) => ({
      url,
      ok: true,
      status: 200,
      title: `Page at ${url}`,
      publisher: new URL(url).host,
      publishedAt: '',
      text: 'Synthetic source excerpt with concrete details about the topic.',
    })),
  };
});

vi.mock('../../../src/lib/cve-lookup', async () => {
  const actual = await vi.importActual<typeof import('../../../src/lib/cve-lookup')>('../../../src/lib/cve-lookup');
  return {
    ...actual,
    lookupCve: vi.fn(async (id: string) => ({
      ok: true,
      data: {
        cve_id: id,
        description: 'Synthetic vulnerability description.',
        published: '2026-01-01T00:00:00Z',
        cvss: { version: '3.1', base_score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N' },
        cwe: ['CWE-89'],
        affected_products: [],
        references: [],
      },
    })),
  };
});

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

const UNIFIED = {
  sections: [
    {
      label: 'Writeups',
      kind: 'writeups',
      total: 3,
      items: [
        {
          label: 'Examplecorp gateway advisory',
          description: 'Patch notes for CVE-2099-0001.',
          url: 'https://example.test/advisory',
          source: 'writeups',
          score: 90,
        },
        {
          label: 'NVD record',
          url: 'https://nvd.nist.gov/vuln/detail/CVE-2099-0001',
          source: 'cve',
          score: 100,
        },
      ],
    },
    {
      label: 'Cybercrime',
      kind: 'cybercrime',
      total: 2,
      items: [
        {
          label: 'Examplecorp exploit listing',
          description: 'Actors discussing CVE-2099-0002.',
          url: 'https://example.test/forum',
          score: 40,
        },
        {
          label: 'No URL hit',
          description: 'A corpus record with no upstream page.',
          score: 20,
        },
      ],
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('suppliedUrls / suppliedCveIds', () => {
  it('pulls pasted URLs out of operator text, cleaned and de-duplicated', async () => {
    const { suppliedUrls } = await import('../../../src/case-study/research/topic');
    const hits = suppliedUrls(
      'Read https://example.test/a and (https://example.test/b). Then https://example.test/a again.'
    );
    expect(hits.map((h) => h.url)).toEqual(['https://example.test/a', 'https://example.test/b']);
    expect(hits.every((h) => h.source === 'operator')).toBe(true);
  });

  it('finds CVE ids in operator-supplied text', async () => {
    const { suppliedCveIds } = await import('../../../src/case-study/research/topic');
    expect(suppliedCveIds('cve-2099-0001 and CVE-2099-0002, plus CVE-2099-0001')).toEqual([
      'CVE-2099-0001',
      'CVE-2099-0002',
    ]);
  });
});

describe('discoverTopicCorpus', () => {
  it('maps unified-search hits to ranked, deduped URLs and CVE ids', async () => {
    const { discoverTopicCorpus } = await import('../../../src/case-study/research/topic');
    const stub = selfStub({ '/api/v1/unified-search': UNIFIED });
    const out = await discoverTopicCorpus({
      keyword: 'examplecorp gateway',
      self: stub,
      env: { INTERNAL_TOKEN_SECRET: SECRET },
    });
    expect(stub.requested[0]).toContain('/api/v1/unified-search?q=examplecorp%20gateway');
    // NVD deep links are dropped (lookupCve covers them), highest score first.
    expect(out.hits.map((h) => h.url)).toEqual(['https://example.test/advisory', 'https://example.test/forum']);
    expect(out.cveIds).toContain('CVE-2099-0001');
    expect(out.cveIds).toContain('CVE-2099-0002');
  });

  it('falls back to the distinctive first token when the full phrase finds nothing', async () => {
    const { discoverTopicCorpus } = await import('../../../src/case-study/research/topic');
    const seen: string[] = [];
    const stub = {
      fetch: (async (req: RequestInfo) => {
        const url = new URL(typeof req === 'string' ? req : (req as Request).url);
        const q = url.searchParams.get('q') ?? '';
        seen.push(q);
        const body = q === 'examplecorp gateway' ? { sections: [] } : UNIFIED;
        return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
      }) as never,
    };
    const out = await discoverTopicCorpus({
      keyword: 'examplecorp gateway',
      self: stub,
      env: { INTERNAL_TOKEN_SECRET: SECRET },
    });
    expect(seen).toEqual(['examplecorp gateway', 'examplecorp']);
    expect(out.hits.map((h) => h.url)).toEqual(['https://example.test/advisory', 'https://example.test/forum']);
  });

  it('returns nothing when there is no SELF binding or internal secret', async () => {
    const { discoverTopicCorpus } = await import('../../../src/case-study/research/topic');
    const stub = selfStub({ '/api/v1/unified-search': UNIFIED });
    expect(await discoverTopicCorpus({ keyword: 'examplecorp', self: stub, env: {} })).toEqual({
      hits: [],
      cveIds: [],
    });
    expect(await discoverTopicCorpus({ keyword: 'examplecorp', env: { INTERNAL_TOKEN_SECRET: SECRET } })).toEqual({
      hits: [],
      cveIds: [],
    });
  });
});

const NEWS_RSS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item>
    <title>Novel Topic advisory</title>
    <link>https://www.bing.com/apiclick.aspx?url=https%3A%2F%2Fvendor.example%2Fadvisory</link>
    <description>Patch details for the novel topic.</description>
  </item>
  <item>
    <title>NVD record</title>
    <link>https://nvd.nist.gov/vuln/detail/CVE-2099-0001</link>
    <description>Canonical record, must be skipped.</description>
  </item>
</channel></rss>`;

describe('searchTopicNews', () => {
  it('parses Bing News RSS into citable, unwrapped publisher URLs', async () => {
    const { searchTopicNews } = await import('../../../src/case-study/research/topic');
    const fetchStub = vi.fn(async (url: string) => {
      expect(url).toContain('q=novel%20topic');
      return new Response(NEWS_RSS, { status: 200 });
    });
    const hits = await searchTopicNews('novel topic', fetchStub as any);
    expect(hits).toEqual([
      {
        url: 'https://vendor.example/advisory',
        label: 'Novel Topic advisory',
        source: 'news-web',
        description: 'Patch details for the novel topic.',
      },
    ]);
  });

  it('returns nothing on a failed feed instead of inventing sources', async () => {
    const { searchTopicNews } = await import('../../../src/case-study/research/topic');
    const fetchStub = vi.fn(async () => new Response('', { status: 403 }));
    expect(await searchTopicNews('novel topic', fetchStub as any)).toEqual([]);
  });
});

describe('findCveIds', () => {
  it('treats a CVE in the topic title as the subject regardless of content type', async () => {
    const { findCveIds } = await import('../../../src/case-study/research/enrich');
    // The Generate tab defaults to `analysis`; a named CVE is still the topic.
    expect(findCveIds('analysis', 'What CVE-2099-0001 means for defenders', {})).toEqual(['CVE-2099-0001']);
    // A CVE merely present in non-vulnerability evidence stays context.
    expect(findCveIds('breach', 'Acme breach writeup', { references: [{ id: 'CVE-2099-0002' }] })).toEqual([]);
  });
});

describe('researchCandidate on a bare topic', () => {
  it('discovers, fetches and enriches sources before building the dossier', async () => {
    const { researchCandidate } = await import('../../../src/case-study/research');
    const { extractPage } = await import('../../../src/case-study/research/extract');
    const stub = selfStub({ '/api/v1/unified-search': UNIFIED });

    const candidate: Candidate = {
      key: 'custom-examplecorp',
      type: 'cve',
      title: 'Examplecorp gateway flaw CVE-2099-0001 explained',
      rationale: 'Operator-supplied topic.',
      score: 0.8,
      evidence: { userContent: 'Read https://example.test/operator-note for context.' },
      discoveredAt: '2026-11-26T00:00:00Z',
      status: 'pending',
    };

    const dossier = await researchCandidate({
      candidate,
      now: new Date(),
      self: stub,
      internalTokenSecret: SECRET,
    });

    // The operator URL and both corpus URLs were actually fetched.
    const fetched = vi.mocked(extractPage).mock.calls.map((c) => c[0]);
    expect(fetched).toContain('https://example.test/operator-note');
    expect(fetched).toContain('https://example.test/advisory');
    expect(fetched).toContain('https://example.test/forum');
    expect(fetched).not.toContain('https://nvd.nist.gov/vuln/detail/CVE-2099-0001');

    // Read pages and CVE facts reached the dossier the writer sees.
    expect(dossier.pages.length).toBe(3);
    expect(dossier.cves.some((c) => c.id === 'CVE-2099-0001')).toBe(true);
    expect(dossier.platform.topicHits?.length).toBe(2);
    expect(dossier.meta.corpusHits).toBe(2);
    expect(dossier.meta.pagesRead).toBe(3);
  });

  it('uses the news fallback when the platform corpus is empty', async () => {
    const { researchCandidate } = await import('../../../src/case-study/research');
    const { extractPage } = await import('../../../src/case-study/research/extract');
    const stub = selfStub({ '/api/v1/unified-search': { sections: [] } });
    const fetchStub = vi.fn(async (url: string) => {
      if (url.includes('bing.com/news/search')) return new Response(NEWS_RSS, { status: 200 });
      return new Response('', { status: 200 });
    });

    const dossier = await researchCandidate({
      candidate: {
        key: 'custom-novel',
        type: 'analysis',
        title: 'Novel topic explained',
        rationale: 'Operator-supplied topic.',
        score: 0.8,
        evidence: { userContent: 'Context only, no pasted URLs.' },
        discoveredAt: '2026-11-26T00:00:00Z',
        status: 'pending',
      },
      now: new Date(),
      self: stub,
      internalTokenSecret: SECRET,
      fetchFn: fetchStub as any,
    });

    const fetched = vi.mocked(extractPage).mock.calls.map((c) => c[0]);
    expect(fetched).toContain('https://vendor.example/advisory');
    expect(dossier.meta.corpusHits).toBe(1);
    expect(dossier.platform.topicHits?.[0]?.source).toBe('news-web');
    expect(dossier.pages.length).toBe(1);
  });
});
