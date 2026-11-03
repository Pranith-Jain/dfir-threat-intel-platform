/**
 * Tests for the AI Security hub routes (/api/v1/ai-security*).
 *
 * Same stub-ASSETS approach as ai-escape.test.ts. Run from the
 * repo root with the api workers pool (sandbox disabled).
 */
import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { aiSecurityRouter } from '../../src/routes/ai-security';

function makeAssets() {
  const data = new Map<string, unknown>();

  data.set('/data/ai-security/index.json', {
    hub: 'AI Security',
    builtAt: new Date().toISOString(),
    sources: {},
    counts: { matrixTools: 2, matrixCategories: 1, incidentReports: 2, escapeDrift: true },
    matrixByCategory: { scanner: 2 },
    latestIncidentAt: '2026-09-16T00:00:00.000Z',
    latestMatrixCheck: '2026-09-17T08:40:33.000Z',
  });
  data.set('/data/ai-security/matrix/index.json', {
    updatedAt: new Date().toISOString(),
    total: 2,
    byCategory: { scanner: 2 },
    tools: [
      {
        slug: 'b__y',
        repo: 'b/y',
        category: 'scanner',
        scope: ['llm'],
        stars: 5000,
        description: 'llm scanner',
        homepage: null,
        added: null,
        checkedAt: null,
        pushedAt: null,
        daysIdle: 0,
        archived: false,
        license: 'MIT',
      },
      {
        slug: 'c__z',
        repo: 'c/z',
        category: 'scanner',
        scope: ['agentic'],
        stars: 50,
        description: 'old',
        homepage: null,
        added: null,
        checkedAt: null,
        pushedAt: null,
        daysIdle: 90,
        archived: true,
        license: null,
      },
    ],
  });
  data.set('/data/ai-security/matrix/tools/b__y.json', {
    slug: 'b__y',
    repo: 'b/y',
    category: 'scanner',
    scope: ['llm'],
    stars: 5000,
    description: 'llm scanner',
    homepage: null,
    added: null,
    checkedAt: null,
    pushedAt: null,
    daysIdle: 0,
    archived: false,
    license: 'MIT',
  });
  data.set('/data/ai-security/incidents/index.json', {
    updatedAt: new Date().toISOString(),
    source: 'https://incidentdatabase.ai/rss.xml',
    total: 2,
    reports: [
      {
        id: '7954',
        guid: 'g1',
        title: 'Flock camera misuse',
        link: 'https://example.invalid/1',
        pubDate: '2026-09-16T00:00:00.000Z',
        citeId: '1689',
        reportNum: '7954',
      },
      {
        id: '7971',
        guid: 'g2',
        title: 'Agentic breach',
        link: 'https://example.invalid/2',
        pubDate: '2026-09-15T00:00:00.000Z',
        citeId: '1693',
        reportNum: '7971',
      },
    ],
  });
  data.set('/data/ai-security/incidents/bodies.json', {
    '7954': {
      id: '7954',
      guid: 'g1',
      title: 'Flock camera misuse',
      link: 'https://example.invalid/1',
      pubDate: '2026-09-16T00:00:00.000Z',
      citeId: '1689',
      reportNum: '7954',
      description: 'officers misused cameras',
    },
  });
  data.set('/data/ai-security/escape-parity.json', {
    checkedAt: new Date().toISOString(),
    upstream: { registryEntries: 0, queuePending: 0, embeddedIds: 19, ids: [] },
    local: { entries: 15, version: 'v0.1', compiled: '2026-09-06' },
    drift: true,
    onlyUpstream: ['CB-2025-0001'],
    onlyLocal: [],
    note: 'parity only',
  });
  data.set('/data/ai-security/vulns/index.json', {
    updatedAt: new Date().toISOString(),
    total: 2,
    kev: 1,
    vulns: [
      {
        id: 'CVE-2026-42271',
        title: 'LiteLLM RCE',
        sources: ['euvd', 'kev'],
        severity: '8.7',
        cvssBase: 8.7,
        epss: 0.8359,
        kev: true,
        kevSources: ['cisa_kev'],
        published: '2026-06-08',
        link: 'https://example.invalid/v',
        aliases: [],
        packages: ['PyPI:litellm'],
        vendor: 'berriai',
        product: 'LiteLLM',
      },
      {
        id: 'CVE-2026-33626',
        title: 'LMDeploy SSRF',
        sources: ['nvd'],
        severity: '7.5',
        cvssBase: 7.5,
        epss: 0.1,
        kev: false,
        kevSources: [],
        published: '2026-04-21',
        link: 'https://example.invalid/w',
        aliases: [],
        packages: [],
        vendor: null,
        product: 'LMDeploy',
      },
    ],
  });
  data.set('/data/ai-security/vulns/bodies.json', {
    'CVE-2026-42271': {
      id: 'CVE-2026-42271',
      title: 'LiteLLM RCE',
      sources: ['euvd', 'kev'],
      severity: '8.7',
      cvssBase: 8.7,
      epss: 0.8359,
      kev: true,
      kevSources: ['cisa_kev'],
      published: '2026-06-08',
      link: 'https://example.invalid/v',
      aliases: [],
      packages: ['PyPI:litellm'],
      vendor: 'berriai',
      product: 'LiteLLM',
      description: 'RCE chain',
      references: [],
      euvdId: null,
      kevDateAdded: '2026-06-08',
      epssPercentile: 99,
    },
  });
  data.set('/data/ai-security/advisories/index.json', {
    updatedAt: new Date().toISOString(),
    total: 1,
    bySource: { garak: 1 },
    items: [
      {
        id: 'a1',
        title: 'garak release',
        link: 'https://example.invalid/g',
        updated: '2026-09-17',
        source: 'garak',
        kind: 'release',
        cves: [],
        description: '',
      },
    ],
  });
  data.set('/data/ai-security/research/index.json', {
    updatedAt: new Date().toISOString(),
    total: 1,
    bySource: { hacktron: 1 },
    items: [
      {
        id: 'r1',
        title: 'HEIF Heist',
        link: 'https://example.invalid/h',
        pubDate: '2026-09-15',
        source: 'hacktron',
        description: 'image parsers',
      },
    ],
  });

  return {
    fetch: vi.fn(async (req: Request) => {
      const path = new URL(req.url).pathname;
      const hit = data.get(path);
      if (!hit) return new Response('not found', { status: 404 });
      return new Response(JSON.stringify(hit), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }),
  } as unknown as Fetcher;
}

function makeEnv(): Env {
  return { ASSETS: makeAssets() } as Env;
}

function setup() {
  const app = new Hono<{ Bindings: Env }>();
  app.route('/api/v1', aiSecurityRouter);
  return app;
}

describe('ai-security routes', () => {
  it('GET / returns hub meta + counts', async () => {
    const r = await setup().request('/api/v1/ai-security/', {}, makeEnv());
    expect(r.status).toBe(200);
    const body = (await r.json()) as { counts: { matrixTools: number } };
    expect(body.counts.matrixTools).toBe(2);
  });

  it('GET /matrix filters by query + min_stars', async () => {
    const app = setup();
    const env = makeEnv();
    const q = (await (await app.request('/api/v1/ai-security/matrix?q=llm', {}, env)).json()) as {
      tools: { repo: string }[];
    };
    expect(q.tools.map((t) => t.repo)).toEqual(['b/y']);
    const s = (await (await app.request('/api/v1/ai-security/matrix?min_stars=1000', {}, env)).json()) as {
      tools: { repo: string }[];
    };
    expect(s.tools.map((t) => t.repo)).toEqual(['b/y']);
  });

  it('GET /matrix/:slug returns the tool or 404', async () => {
    const app = setup();
    const env = makeEnv();
    expect((await app.request('/api/v1/ai-security/matrix/b__y', {}, env)).status).toBe(200);
    expect((await app.request('/api/v1/ai-security/matrix/nope', {}, env)).status).toBe(404);
  });

  it('GET /incidents filters by cite + q, /incidents/:id returns body or 404', async () => {
    const app = setup();
    const env = makeEnv();
    const c = (await (await app.request('/api/v1/ai-security/incidents?cite=1693', {}, env)).json()) as {
      reports: { id: string }[];
    };
    expect(c.reports.map((r) => r.id)).toEqual(['7971']);
    expect((await app.request('/api/v1/ai-security/incidents/7954', {}, env)).status).toBe(200);
    expect((await app.request('/api/v1/ai-security/incidents/nope', {}, env)).status).toBe(404);
  });

  it('GET /escape-parity returns drift report', async () => {
    const r = await setup().request('/api/v1/ai-security/escape-parity', {}, makeEnv());
    expect(r.status).toBe(200);
    const body = (await r.json()) as { drift: boolean; onlyUpstream: string[] };
    expect(body.drift).toBe(true);
    expect(body.onlyUpstream).toEqual(['CB-2025-0001']);
  });

  it('GET /vulns filters by kev_only + min_epss, /vulns/:id returns body or 404', async () => {
    const app = setup();
    const env = makeEnv();
    const k = (await (await app.request('/api/v1/ai-security/vulns?kev_only=true', {}, env)).json()) as {
      kev: number;
      vulns: { id: string }[];
    };
    expect(k.kev).toBe(1);
    expect(k.vulns.map((v) => v.id)).toEqual(['CVE-2026-42271']);
    const e = (await (await app.request('/api/v1/ai-security/vulns?min_epss=0.8', {}, env)).json()) as {
      vulns: { id: string }[];
    };
    expect(e.vulns.map((v) => v.id)).toEqual(['CVE-2026-42271']);
    expect((await app.request('/api/v1/ai-security/vulns/CVE-2026-42271', {}, env)).status).toBe(200);
    expect((await app.request('/api/v1/ai-security/vulns/CVE-1999-0000', {}, env)).status).toBe(404);
  });

  it('GET /vulns classifies and filters by AI stack facet', async () => {
    const app = setup();
    const env = makeEnv();
    const all = (await (await app.request('/api/v1/ai-security/vulns', {}, env)).json()) as {
      stackFacets: { id: string; count: number }[];
      vulns: { id: string; stack?: string[] }[];
    };
    const inference = all.stackFacets.find((f) => f.id === 'inference');
    expect(inference?.count).toBe(2);
    expect(all.vulns.find((v) => v.id === 'CVE-2026-42271')?.stack).toContain('inference');

    const filtered = (await (await app.request('/api/v1/ai-security/vulns?stack=inference', {}, env)).json()) as {
      returned: number;
      vulns: { id: string }[];
    };
    expect(filtered.returned).toBe(2);

    const none = (await (await app.request('/api/v1/ai-security/vulns?stack=agents', {}, env)).json()) as {
      returned: number;
    };
    expect(none.returned).toBe(0);

    const body = (await (await app.request('/api/v1/ai-security/vulns/CVE-2026-42271', {}, env)).json()) as {
      stack?: string[];
    };
    expect(body.stack).toContain('inference');
  });

  it('GET /advisories + /research filter by source + q', async () => {
    const app = setup();
    const env = makeEnv();
    const a = (await (await app.request('/api/v1/ai-security/advisories?source=garak', {}, env)).json()) as {
      items: { id: string }[];
    };
    expect(a.items.map((i) => i.id)).toEqual(['a1']);
    const r = (await (await app.request('/api/v1/ai-security/research?q=heist', {}, env)).json()) as {
      items: { id: string }[];
    };
    expect(r.items.map((i) => i.id)).toEqual(['r1']);
  });
});
