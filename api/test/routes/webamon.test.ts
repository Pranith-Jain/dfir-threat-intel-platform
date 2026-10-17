import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, afterEach } from 'vitest';

/**
 * Regression guards for the Webamon upstream contract (2026-10 rework):
 *
 *   basic search : search=<term>&results=<fields to search within>
 *   field search : lucene_query=<q>&index=scans&fields=<fields to return>
 *
 * The old shape — Lucene syntax inside `search` plus `results` as a return
 * projection — fails upstream with `query_shard_exception`, and
 * `meta.risk_score` in `results` alone was enough to break every query. These
 * tests assert the outbound request shape and the normalization the UI
 * depends on (`domain.name` populated, `<mark>` highlights stripped).
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

afterEach(() => vi.restoreAllMocks());

/** Capture the upstream URL(s) the route hits and reply with `body`. */
function mockUpstream(body: unknown, status = 200) {
  const urls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const u = String(input);
    if (u.startsWith('https://search.webamon.com')) {
      urls.push(u);
      return json(body, status);
    }
    return new Response('not found', { status: 404 });
  });
  return urls;
}

const basicHit = {
  search_string: 'example.com',
  total_hits: 1,
  results: [
    {
      _index: 'scans-2026.10.16',
      'domain.name': '<mark>example.com</mark>',
      page_title: 'Example Domain',
      resolved_url: 'https://example.com/',
      sub_domain: '',
      tag: 'community',
      date: '2026-10-16',
      meta: { risk_score: 3, report_id: 'rep-1', script_count: 1 },
      fingerprint: { tech: 'abc123', ssl: '' },
      matched_fields: ['domain.name'],
    },
  ],
  pagination: {
    from: 0,
    size: 20,
    returned: 1,
    has_more: false,
    current_page: 1,
    total_pages: 1,
    next_from: null,
    prev_from: null,
  },
};

const luceneHit = {
  search_string: '',
  lucene_query: 'domain_name:"example.com"',
  index: 'scans',
  total_hits: 2,
  results: [
    {
      domain_name: 'example.com',
      page_title: 'Example Domain',
      resolved_url: 'https://example.com/',
      sub_domain: '',
      tag: 'community',
      date: '2026-10-16',
      report_id: 'rep-1',
      scan_status: 'success',
      meta: { risk_score: 3, report_id: 'rep-1' },
      fingerprint: { tech: 'abc123' },
    },
  ],
};

describe('GET /api/v1/webamon/search', () => {
  it('rejects a missing query', async () => {
    const res = await SELF.fetch('https://self.internal/api/v1/webamon/search');
    expect(res.status).toBe(400);
  });

  it('sends free text as basic search and never asks for meta.risk_score in results', async () => {
    const urls = mockUpstream(basicHit);
    const res = await SELF.fetch('https://self.internal/api/v1/webamon/search?search=example.com&size=5');
    expect(res.status).toBe(200);
    expect(urls[0]).toContain('search=example.com');
    expect(urls[0]).toContain('results=');
    // The upstream chokes on meta.risk_score inside `results`.
    expect(urls[0]).not.toContain('meta.risk_score');
    expect(urls[0]).not.toContain('lucene_query');
  });

  it('sends field syntax as lucene_query + index + fields', async () => {
    const urls = mockUpstream(luceneHit);
    const res = await SELF.fetch(
      'https://self.internal/api/v1/webamon/search?search=' +
        encodeURIComponent('domain_name:"example.com"') +
        '&size=3'
    );
    expect(res.status).toBe(200);
    expect(urls[0]).toContain('lucene_query=domain_name');
    expect(urls[0]).toContain('index=scans');
    expect(urls[0]).toContain('fields=');
    expect(urls[0]).not.toContain('results=');
  });

  it('normalizes basic-mode hits: marks stripped, meta.risk_score preserved', async () => {
    mockUpstream(basicHit);
    const res = await SELF.fetch('https://self.internal/api/v1/webamon/search?search=example.com');
    const body = (await res.json()) as {
      total_hits: number;
      results: Array<{ 'domain.name'?: string; meta?: { risk_score?: number } }>;
    };
    expect(body.total_hits).toBe(1);
    expect(body.results[0]!['domain.name']).toBe('example.com');
    expect(body.results[0]!.meta?.risk_score).toBe(3);
  });

  it('normalizes lucene-mode hits onto domain.name', async () => {
    mockUpstream(luceneHit);
    const res = await SELF.fetch(
      'https://self.internal/api/v1/webamon/search?search=' + encodeURIComponent('domain_name:"example.com"')
    );
    const body = (await res.json()) as {
      results: Array<{ 'domain.name'?: string; meta?: { risk_score?: number }; scan_status?: string }>;
    };
    expect(body.results[0]!['domain.name']).toBe('example.com');
    expect(body.results[0]!.meta?.risk_score).toBe(3);
  });

  it('surfaces an upstream query error as 502 instead of caching an empty result set', async () => {
    mockUpstream({ search_string: 'x', total_hits: 0, results: [], error: "Unknown field 'risk_score'." });
    const res = await SELF.fetch(
      'https://self.internal/api/v1/webamon/search?search=' + encodeURIComponent('risk_score:>5')
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error?: string; message?: string };
    expect(body.error).toBe('upstream_fetch_failed');
    expect(body.message).toMatch(/Unknown field/);
  });
});

describe('GET /api/v1/webamon/domain/:name', () => {
  it('uses the exact-match domain_name field', async () => {
    const urls = mockUpstream(luceneHit);
    const res = await SELF.fetch('https://self.internal/api/v1/webamon/domain/example.com');
    expect(res.status).toBe(200);
    expect(urls[0]).toContain('lucene_query=domain_name%3A%22example.com%22');
    expect(urls[0]).toContain('index=scans');
    expect(urls[0]).not.toContain('meta.risk_score');
    const body = (await res.json()) as { results: Array<{ 'domain.name'?: string }> };
    expect(body.results[0]!['domain.name']).toBe('example.com');
  });

  it('escapes quotes in the name so the lucene query cannot break out', async () => {
    const urls = mockUpstream({ total_hits: 0, results: [] });
    await SELF.fetch('https://self.internal/api/v1/webamon/domain/evil%22%20OR%20*:*%22');
    expect(urls[0]).toContain('lucene_query=');
    expect(urls[0]).not.toContain('*:*');
  });
});

describe('GET /api/v1/webamon/report/:id', () => {
  it('looks the report up by report_id and keeps heavy fields', async () => {
    const urls = mockUpstream({
      total_hits: 1,
      results: [
        {
          domain_name: 'example.com',
          report_id: 'rep-1',
          certificate: [{ issuer: "Let's Encrypt" }],
          server: [{ ip: '1.2.3.4' }],
          dom: '<html>…</html>',
        },
      ],
    });
    const res = await SELF.fetch('https://self.internal/api/v1/webamon/report/rep-1');
    expect(res.status).toBe(200);
    expect(urls[0]).toContain('lucene_query=report_id');
    expect(urls[0]).toContain('fields=');
    const body = (await res.json()) as {
      results: Array<{ 'domain.name'?: string; certificate?: unknown[]; dom?: unknown }>;
    };
    expect(body.results[0]!['domain.name']).toBe('example.com');
    expect(body.results[0]!.certificate).toHaveLength(1);
    expect(body.results[0]!.dom).toBe('<html>…</html>');
  });
});

describe('GET /api/v1/webamon/screenshot/:id', () => {
  it('serves the decoded image with the content-type it actually is', async () => {
    // JPEG magic (ff d8 ff e0 00 10), base64 — upstream labels the payload PNG.
    mockUpstream({ report: { screenshot: '/9j/4AAQ' } });
    const res = await SELF.fetch('https://self.internal/api/v1/webamon/screenshot/rep-1');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/jpeg');
    const bytes = new Uint8Array(await res.arrayBuffer());
    expect([bytes[0], bytes[1], bytes[2]]).toEqual([0xff, 0xd8, 0xff]);
  });
});
