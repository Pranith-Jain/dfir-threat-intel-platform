import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { buildAiLlmIntel, AI_LLM_ENDPOINTS, AI_LLM_BASE } from '../../src/lib/ai-llm-intel';

/**
 * Fixtures shaped like the real upstream payloads (captured 2026-10-05).
 * Every field here exists in production payloads, so a shape change upstream
 * surfaces as a test failure rather than a silently empty section.
 */
const IOCs_DOC = {
  last_updated: '2026-10-05T14:03:23Z',
  iocs: [
    {
      value: 'third-party.com',
      type: 'domain',
      context: 'Placeholder hostname serving a Windows ClickFix lure.',
      first_seen: '2026-09-23',
      source: 'Manifold Security',
      campaign: '2026-09-30-third-party-com-clickfix-skills-mcp',
      status: 'active',
    },
    {
      value: '1.2.3.4',
      type: 'ipv4',
      context: 'C2 for a fake MCP registry.',
      first_seen: '2026-10-01',
      source: 'LLM ThreatIntel',
      campaign: 'mcp-typo-squat',
      status: 'removed',
    },
  ],
};

const ACTORS_DOC = {
  last_updated: '2026-10-05T12:00:00Z',
  entries: [
    {
      id: 'third-party-com-clickfix',
      names: ['third-party.com ClickFix'],
      type: 'supply_chain_campaign',
      first_seen: '2026-06',
      status: 'active',
      distribution: ['third-party.com ClickFix page', 'MCP server docs'],
      ttps: ['T1204 - User Execution', 'T1059.001 - PowerShell', 'T1036 - Masquerading'],
      description: 'Unknown operator serving a Windows ClickFix lure.',
    },
    {
      id: 'undated-actor',
      names: ['Undated'],
      type: 'malware_cluster',
      status: 'active',
    },
  ],
};

const POSTS_DOC = {
  posts: [
    {
      id: '2026-10-05-island-sponsored-search',
      title: 'Island Sponsored Search Custom GPT ClickFix Campaign',
      date: '2026-10-05',
      author: 'LLM ThreatIntel',
      tags: ['phishing', 'malware', 'clickfix'],
      tlp: 'TLP:CLEAR',
      excerpt: 'Island reported a campaign abusing paid search ads and Custom GPTs.',
      file: '2026-10-05-island.md',
    },
    { title: 'no id', date: '2026-10-04' },
    { id: 'no-title', date: '2026-10-04' },
    { id: 'no-date', title: 'No date' },
  ],
};

const BLOG_DOC = {
  posts: [
    {
      id: '2026-09-30-inside-chatgpt-work',
      title: 'Inside ChatGPT Work: The Machine Underneath the Chat',
      date: '2026-09-30',
      author: 'Lucas L.',
      category: 'GenAI Security',
      tags: ['chatgpt', 'sandbox', 'agent-harnesses'],
      excerpt: 'A look underneath a ChatGPT Work thread.',
      readTime: '12 min',
    },
  ],
};

const HONEYPOT_DOC = {
  published: '2026-10-05T14:03:23.328770Z',
  window_days: 7,
  summary: {
    total_iocs: 1000,
    by_category: { 'RELAY-CUSTOMER': 84, 'SCANNER-MASS': 417, 'MCP-SCANNER': 173 },
  },
  taxonomy: {
    actor_categories: {
      'SCANNER-MASS': 'High-volume single-purpose endpoint scanners',
      'MCP-SCANNER': 'Dedicated Model Context Protocol endpoint probers',
    },
  },
  indicators: [
    {
      // `ioc_type` is present on every real indicator and the parser requires it
      // to classify the row; omitting it here previously made the honeypot trend
      // dimension silently empty in this suite.
      ioc_type: 'ip',
      value: '185.226.197.32',
      actor_category: 'MCP-SCANNER',
      confidence: 'low',
      ttps: ['T1046', 'T1190'],
      last_seen: '2026-10-03T08:32:13.446106+00:00',
      first_seen: '2026-10-03T05:14:03.315237+00:00',
      total_hits: 6,
      distinct_personas: 2,
    },
    {
      ioc_type: 'ip',
      value: '123.160.223.73',
      actor_category: 'SCANNER-ENUM',
      confidence: 'high',
      ttps: ['T1046'],
      last_seen: '2026-10-05T10:37:36.995708+00:00',
      first_seen: '2026-10-01T08:56:05.143014+00:00',
      total_hits: 6,
      distinct_personas: 5,
    },
  ],
};

/** Route each manifest URL to its fixture; unknown URLs → 404. */
function mockUpstreams(overrides: Record<string, unknown> = {}, failures: string[] = []) {
  const map: Record<string, unknown> = {
    [`${AI_LLM_BASE}/data/iocs.json`]: IOCs_DOC,
    [`${AI_LLM_BASE}/data/actors.json`]: ACTORS_DOC,
    [`${AI_LLM_BASE}/data/posts-index.json`]: POSTS_DOC,
    [`${AI_LLM_BASE}/data/blog-index.json`]: BLOG_DOC,
    'https://ai-honeypots.com/feeds/iocs.json': HONEYPOT_DOC,
    ...overrides,
  };
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (failures.some((f) => url.includes(f))) return new Response('upstream down', { status: 503 });
    const body = map[url];
    if (body === undefined) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(body), { status: 200 });
  });
}

beforeEach(() => {
  // A 200 with an HTML body must be treated as a failure, not parsed as JSON.
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AI_LLM_ENDPOINTS', () => {
  it('only references https upstreams on the two known hosts', () => {
    for (const ep of AI_LLM_ENDPOINTS) {
      expect(ep.url.startsWith('https://'), ep.id).toBe(true);
      const host = new URL(ep.url).host;
      expect([AI_LLM_BASE.replace('https://', ''), 'ai-honeypots.com']).toContain(host);
    }
  });

  it('covers every surface the response promises', () => {
    const feeds = new Set(AI_LLM_ENDPOINTS.map((e) => e.feeds));
    for (const f of ['iocs', 'actors', 'posts', 'blog', 'honeypot', 'honeypot_taxonomy']) {
      expect(feeds.has(f as never), f).toBe(true);
    }
  });
});

describe('buildAiLlmIntel', () => {
  it('assembles every surface from a fully-healthy set of upstreams', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();

    expect(res.degraded).toBe(false);
    expect(res.sources.every((s) => s.ok)).toBe(true);
    expect(res.actors).toHaveLength(2);
    expect(res.posts).toHaveLength(1);
    expect(res.blog).toHaveLength(1);
    expect(res.iocs).toHaveLength(1); // the retired one is dropped
    expect(res.honeypot_actor_classes.length).toBeGreaterThan(0);
    expect(res.trends.length).toBeGreaterThan(0);
  });

  it('drops stood-down indicators but keeps untriaged ones', async () => {
    // Live statuses (2026-10-05): active / unknown / removed / inactive.
    // Only removed+inactive are stood down; `unknown` is "not yet triaged".
    mockUpstreams({
      [`${AI_LLM_BASE}/data/iocs.json`]: {
        iocs: [
          { value: 'a.example', type: 'domain', status: 'active' },
          { value: 'b.example', type: 'domain', status: 'unknown' },
          { value: 'c.example', type: 'domain', status: 'removed' },
          { value: 'd.example', type: 'domain', status: 'inactive' },
          { value: 'e.example', type: 'domain' },
        ],
      },
    });
    const res = await buildAiLlmIntel();
    expect(res.iocs.map((i) => i.value)).toEqual(['a.example', 'b.example', 'e.example']);
  });

  it('agrees with the live-IOC parser on which indicators are current', async () => {
    // Both read the same feed; if their lifecycle filters drift, the stream and
    // the AI/LLM page report different counts for the same upstream.
    const { parseLlmThreatintelIocs } = await import('../../src/lib/ioc-feed-parsers');
    const doc = {
      iocs: [
        { value: 'a.example', type: 'domain', status: 'active' },
        { value: 'b.example', type: 'domain', status: 'unknown' },
        { value: 'c.example', type: 'domain', status: 'removed' },
        { value: 'd.example', type: 'domain', status: 'inactive' },
      ],
    };
    mockUpstreams({ [`${AI_LLM_BASE}/data/iocs.json`]: doc });
    const res = await buildAiLlmIntel();
    const parsed = parseLlmThreatintelIocs(JSON.stringify(doc), 1000);
    expect(parsed.map((p) => p.value).sort()).toEqual(res.iocs.map((i) => i.value).sort());
  });

  it('folds campaign + reporter into the IOC context', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    expect(res.iocs[0]!.context).toBe(
      'Placeholder hostname serving a Windows ClickFix lure. (Manifold Security · 2026-09-30-third-party-com-clickfix-skills-mcp)'
    );
  });

  it('drops posts missing an id, title, or date', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    // 4 upstream rows, 3 of which are incomplete.
    expect(res.posts).toHaveLength(1);
    expect(res.posts[0]!.id).toBe('2026-10-05-island-sponsored-search');
  });

  it('gives every post an absolute upstream permalink', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    expect(res.posts[0]!.url).toBe(`${AI_LLM_BASE}/#2026-10-05-island-sponsored-search`);
    expect(res.blog[0]!.url).toBe(`${AI_LLM_BASE}/#2026-09-30-inside-chatgpt-work`);
  });

  it('carries blog metadata through (author, category, readTime)', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    expect(res.blog[0]).toMatchObject({ author: 'Lucas L.', category: 'GenAI Security', readTime: '12 min' });
  });

  it('orders posts and actors newest-first, deterministically', async () => {
    mockUpstreams({
      [`${AI_LLM_BASE}/data/posts-index.json`]: {
        posts: [
          { id: 'b', title: 'B', date: '2026-10-01', tags: [] },
          { id: 'a', title: 'A', date: '2026-10-05', tags: [] },
          { id: 'c', title: 'C', date: '2026-10-01', tags: [] },
        ],
      },
    });
    const res = await buildAiLlmIntel();
    expect(res.posts.map((p) => p.id)).toEqual(['a', 'b', 'c']);
    const again = await buildAiLlmIntel();
    expect(again.posts.map((p) => p.id)).toEqual(res.posts.map((p) => p.id));
  });

  it('aggregates honeypot actor classes with the upstream taxonomy text', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    const mcp = res.honeypot_actor_classes.find((c) => c.category === 'MCP-SCANNER');
    expect(mcp).toBeDefined();
    expect(mcp!.description).toBe('Dedicated Model Context Protocol endpoint probers');
    expect(mcp!.count).toBe(1);
  });

  it('builds trends across all four dimensions from data already held', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    const dims = new Set(res.trends.map((t) => t.dimension));
    expect(dims.has('ttp')).toBe(true);
    expect(dims.has('tag')).toBe(true);
    expect(dims.has('actor_type')).toBe(true);
    expect(dims.has('honeypot_category')).toBe(true);
    // Every trend is capped well below the payload sizes.
    expect(res.trends.length).toBeLessThan(70);
  });

  it('aggregates ATT&CK technique ids across actors, stripping the prose suffix', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    const ttps = res.trends.filter((t) => t.dimension === 'ttp').map((t) => t.key);
    expect(ttps).toContain('T1204');
    expect(ttps).toContain('T1059.001');
    // Keys are technique ids, not the full "T1204 - User Execution" string.
    expect(ttps.every((k) => /^T\d+(\.\d+)?$/.test(k))).toBe(true);
  });

  it('counts distinct campaigns and tags in stats', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    expect(res.stats.campaigns).toBe(1);
    expect(res.stats.tags).toBe(6); // 3 post tags + 3 blog tags
    expect(res.stats.actors).toBe(2);
    expect(res.stats.honeypot_indicators).toBe(2);
  });

  it('reports the newest upstream timestamp as last_updated', async () => {
    mockUpstreams();
    const res = await buildAiLlmIntel();
    expect(res.last_updated).toBe('2026-10-05T14:03:23.328770Z');
  });

  it('degrades and omits the failed surface instead of throwing', async () => {
    mockUpstreams({}, ['data/actors.json']);
    const res = await buildAiLlmIntel();

    expect(res.degraded).toBe(true);
    expect(res.actors).toEqual([]);
    // The rest still built.
    expect(res.iocs).toHaveLength(1);
    expect(res.posts).toHaveLength(1);
    const actors = res.sources.find((s) => s.id === 'actors');
    expect(actors).toMatchObject({ ok: false, count: 0 });
    expect(actors!.error).toBe('fetch failed');
  });

  it('treats an HTML challenge page as a failed fetch, not as data', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<!DOCTYPE html><html><body>Cloudflare</body></html>', { status: 200 })
    );
    const res = await buildAiLlmIntel();
    expect(res.degraded).toBe(true);
    expect(res.sources.every((s) => !s.ok)).toBe(true);
    expect(res.actors).toEqual([]);
    expect(res.iocs).toEqual([]);
  });

  it('tolerates malformed JSON and unexpected shapes without throwing', async () => {
    mockUpstreams({
      [`${AI_LLM_BASE}/data/iocs.json`]: 'not-an-object',
      [`${AI_LLM_BASE}/data/actors.json`]: { entries: 'not-an-array' },
      [`${AI_LLM_BASE}/data/posts-index.json`]: { posts: null },
      [`${AI_LLM_BASE}/data/blog-index.json`]: {},
      'https://ai-honeypots.com/feeds/iocs.json': { indicators: 'nope' },
    });
    const res = await buildAiLlmIntel();
    expect(res.iocs).toEqual([]);
    expect(res.actors).toEqual([]);
    expect(res.posts).toEqual([]);
    expect(res.blog).toEqual([]);
    expect(res.honeypot_actor_classes).toEqual([]);
    // Fetches succeeded, so this is "empty", not "degraded".
    expect(res.sources.every((s) => s.ok)).toBe(true);
  });

  it('is resilient to one upstream throwing', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url.includes('posts-index')) throw new Error('ECONNRESET');
      return new Response(JSON.stringify(IOCs_DOC), { status: 200 });
    });
    const res = await buildAiLlmIntel();
    expect(res.posts).toEqual([]);
    expect(res.degraded).toBe(true);
  });

  it('makes exactly one request per distinct upstream (not one per manifest entry)', async () => {
    // The honeypot URL appears twice in the manifest (indicators + taxonomy) but
    // must be fetched once, or the hourly warm doubles its load on a third party.
    mockUpstreams();
    await buildAiLlmIntel();
    const calls = (globalThis.fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const urls = calls.map((c) => c[0] as string);
    expect(urls.length).toBe(new Set(urls).size);
    expect(urls.length).toBe(AI_LLM_ENDPOINTS.length - 1); // honeypot listed twice
  });
});
