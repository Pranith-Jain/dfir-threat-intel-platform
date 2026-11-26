/**
 * Route tests for the Agentic Attack Detections + Atomic Red Team verticals.
 * The routers read static manifests through env.ASSETS, stubbed with in-memory
 * maps. Run from the repo root with the api workers pool (sandbox disabled).
 */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { aadRouter } from '../../src/routes/aad-edge-tools';
import { artRouter } from '../../src/routes/art-edge-tools';

const data = new Map<string, unknown>();

data.set('/data/aad/index.json', {
  generatedAt: '2026-11-26T00:00:00.000Z',
  source: 'github.com/ThreatDefence/agentic-attack-detections',
  sourceUrl: 'https://github.com/ThreatDefence/agentic-attack-detections',
  license: 'MIT',
  description: 'test',
  stats: { frameworks: 1, indicators: 2, indicatorTypes: 1, attackTechniques: 1, behaviorRules: 0, generalRules: 0 },
  indicatorTypes: [{ type: 'user_agent', count: 2 }],
  frameworks: [
    {
      slug: 'artex',
      name: 'ARTEX',
      description: 'Go planner',
      seenIn: 'Storm-0940',
      counts: { kqlHunts: 15, analytics: 3, sigma: 16, suricata: 46, yara: 4, indicators: 2 },
      techniqueCount: 1,
    },
  ],
  shared: { behaviors: { count: 0, rules: [] }, general: { count: 0, rules: [] } },
});
data.set('/data/aad/frameworks/artex.json', {
  slug: 'artex',
  name: 'ARTEX',
  description: 'Go planner',
  seenIn: 'Storm-0940',
  counts: { kqlHunts: 15, analytics: 3, sigma: 16, suricata: 46, yara: 4, indicators: 2 },
  techniqueCount: 1,
  techniques: [{ id: 'T1046', score: 2, comment: 'KQL hunt' }],
  indicators: [
    {
      value: 'artex-readonly/1.0',
      confidence: 'high',
      context: 'UA',
      actor: '',
      source: 'Datadog',
      sourceUrl: '',
      reported: '',
      framework: 'artex',
    },
  ],
  indicatorsTruncated: false,
  upstreamUrl: 'https://github.com/ThreatDefence/agentic-attack-detections/tree/main/frameworks/artex',
  source: 'github.com/ThreatDefence/agentic-attack-detections',
  license: 'MIT',
});
data.set('/data/aad/indicators/user_agent.json', {
  type: 'user_agent',
  count: 2,
  items: [
    {
      value: 'artex-readonly/1.0',
      confidence: 'high',
      context: 'UA',
      actor: '',
      source: 'Datadog',
      sourceUrl: '',
      reported: '',
      framework: 'artex',
    },
    {
      value: 'cairn/1.0',
      confidence: 'low',
      context: 'UA',
      actor: '',
      source: 'Report',
      sourceUrl: '',
      reported: '',
      framework: 'cairn',
    },
  ],
});
data.set('/data/aad/attack.json', {
  source: 'github.com/ThreatDefence/agentic-attack-detections',
  sourceUrl: 'https://example.com',
  description: 'layer',
  maxValue: 2,
  techniques: [{ id: 'T1046', score: 2, comment: 'KQL hunt' }],
});
data.set('/data/art/index.json', {
  generatedAt: '2026-11-26T00:00:00.000Z',
  source: 'github.com/redcanaryco/atomic-red-team',
  sourceUrl: 'https://github.com/redcanaryco/atomic-red-team',
  siteUrl: 'https://www.atomicredteam.io',
  license: 'MIT',
  description: 'test',
  stats: { techniques: 1, tests: 2, platforms: 1, executors: 1, failed: 0 },
  platformCounts: { windows: 1 },
  executorCounts: { powershell: 1 },
  techniques: [
    {
      id: 'T1059.001',
      displayName: 'PowerShell',
      testCount: 2,
      platforms: ['windows'],
      executors: ['powershell'],
      subtechnique: true,
      upstreamUrl: 'https://example.com',
    },
  ],
});
data.set('/data/art/techniques/T1059.001.json', {
  id: 'T1059.001',
  displayName: 'PowerShell',
  testCount: 2,
  platforms: ['windows'],
  executors: ['powershell'],
  subtechnique: true,
  upstreamUrl: 'https://example.com',
  siteUrl: 'https://www.atomicredteam.io/atomic-red-team/attack-technique/T1059.001',
  tests: [
    {
      name: 'Mimikatz',
      guid: 'f3132740',
      description: 'Dump credentials',
      platforms: ['windows'],
      executor: { name: 'powershell', elevationRequired: true, hasCleanup: true },
      inputArguments: [],
      dependencyCount: 0,
    },
  ],
});

function makeAssets(): Fetcher {
  return {
    fetch: async (req: Request) => {
      const body = data.get(new URL(req.url).pathname);
      if (body === undefined) return new Response(null, { status: 404 });
      return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

function mockCtx(): ExecutionContext {
  return { waitUntil: (_p: Promise<unknown>) => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
}
function makeEnv(): Env {
  return { ASSETS: makeAssets() } as Env;
}

describe('AAD routes', () => {
  function setup() {
    const app = new Hono<{ Bindings: Env }>();
    app.route('/api/v1', aadRouter);
    return app;
  }

  it('serves the index and stats', async () => {
    const r = await setup().request('/api/v1/aad/', {}, makeEnv(), mockCtx());
    expect(r.status).toBe(200);
    const b = (await r.json()) as { frameworks: Array<{ slug: string }> };
    expect(b.frameworks[0]?.slug).toBe('artex');

    const s = await setup().request('/api/v1/aad/stats', {}, makeEnv(), mockCtx());
    expect(s.status).toBe(200);
    const sb = (await s.json()) as { stats: { indicators: number } };
    expect(sb.stats.indicators).toBe(2);
  });

  it('filters frameworks and indicators', async () => {
    const app = setup();
    const env = makeEnv();
    const f = await app.request('/api/v1/aad/frameworks?q=storm', {}, env, mockCtx());
    const fb = (await f.json()) as { frameworks: Array<{ slug: string }> };
    expect(fb.frameworks.map((x) => x.slug)).toEqual(['artex']);

    const i = await app.request('/api/v1/aad/indicators?framework=cairn', {}, env, mockCtx());
    const ib = (await i.json()) as { indicators: Array<{ value: string }> };
    expect(ib.indicators.map((x) => x.value)).toEqual(['cairn/1.0']);
  });

  it('serves a framework body and the ATT&CK layer, 404 for unknown slug', async () => {
    const app = setup();
    const env = makeEnv();
    const r = await app.request('/api/v1/aad/frameworks/artex', {}, env, mockCtx());
    expect(r.status).toBe(200);
    const a = await app.request('/api/v1/aad/attack', {}, env, mockCtx());
    expect(a.status).toBe(200);
    const n = await app.request('/api/v1/aad/frameworks/nope', {}, env, mockCtx());
    expect(n.status).toBe(404);
  });
});

describe('ART routes', () => {
  function setup() {
    const app = new Hono<{ Bindings: Env }>();
    app.route('/api/v1', artRouter);
    return app;
  }

  it('serves the index and stats', async () => {
    const app = setup();
    const env = makeEnv();
    const r = await app.request('/api/v1/art/', {}, env, mockCtx());
    expect(r.status).toBe(200);
    const b = (await r.json()) as { techniques: Array<{ id: string }> };
    expect(b.techniques[0]?.id).toBe('T1059.001');
    const s = await app.request('/api/v1/art/stats', {}, env, mockCtx());
    expect(s.status).toBe(200);
  });

  it('filters techniques and serves a body, 404 for unknown id', async () => {
    const app = setup();
    const env = makeEnv();
    const f = await app.request('/api/v1/art/techniques?platform=linux', {}, env, mockCtx());
    const fb = (await f.json()) as { techniques: unknown[] };
    expect(fb.techniques).toHaveLength(0);
    const b = await app.request('/api/v1/art/techniques/t1059.001', {}, env, mockCtx());
    expect(b.status).toBe(200);
    const bb = (await b.json()) as { tests: Array<{ name: string }> };
    expect(bb.tests[0]?.name).toBe('Mimikatz');
    const n = await app.request('/api/v1/art/techniques/T9999', {}, env, mockCtx());
    expect(n.status).toBe(404);
  });
});
