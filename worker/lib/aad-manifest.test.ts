import { beforeEach, describe, expect, it } from 'vitest';
import {
  _resetAadCacheForTests,
  aadCacheStats,
  filterAadFrameworks,
  filterAadIndicators,
  getAadFramework,
  loadAadAttack,
  loadAadIndex,
  type AadIndex,
} from './aad-manifest';

function mockAssets(files: Record<string, unknown>): Fetcher {
  return {
    fetch: async (req: Request) => {
      const path = new URL(req.url).pathname;
      const data = files[path];
      if (data === undefined) return new Response(null, { status: 404 });
      return new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

const FAKE_INDEX: AadIndex = {
  generatedAt: '2026-11-26T00:00:00.000Z',
  source: 'github.com/ThreatDefence/agentic-attack-detections',
  sourceUrl: 'https://github.com/ThreatDefence/agentic-attack-detections',
  license: 'MIT',
  description: 'test',
  stats: {
    frameworks: 2,
    indicators: 4,
    indicatorTypes: 1,
    attackTechniques: 2,
    behaviorRules: 1,
    generalRules: 1,
  },
  indicatorTypes: [{ type: 'user_agent', count: 4 }],
  frameworks: [
    {
      slug: 'artex',
      name: 'ARTEX',
      description: 'Go planner and worker agents',
      seenIn: 'Storm-0940',
      counts: { kqlHunts: 15, analytics: 3, sigma: 16, suricata: 46, yara: 4, indicators: 3 },
      techniqueCount: 2,
    },
    {
      slug: 'cairn',
      name: 'Cairn',
      description: 'Python engine driving coding agents',
      seenIn: 'Retail',
      counts: { kqlHunts: 6, analytics: 2, sigma: 3, suricata: 26, yara: 6, indicators: 1 },
      techniqueCount: 1,
    },
  ],
  shared: {
    behaviors: { count: 1, rules: [{ path: 'behaviors/sigma/web/a.yml', kind: 'sigma', name: 'a.yml' }] },
    general: { count: 1, rules: [{ path: 'general/sigma/web/b.yml', kind: 'sigma', name: 'b.yml' }] },
  },
};

const ASSETS = mockAssets({
  '/data/aad/index.json': FAKE_INDEX,
  '/data/aad/frameworks/artex.json': {
    ...FAKE_INDEX.frameworks[0],
    techniques: [{ id: 'T1046', score: 2, comment: 'KQL hunt' }],
    indicators: [
      {
        value: 'artex-readonly/1.0',
        confidence: 'high',
        context: 'UA',
        actor: '',
        source: 'Datadog',
        sourceUrl: 'https://example.com',
        reported: '2026-11-09',
        framework: 'artex',
      },
    ],
    indicatorsTruncated: false,
    upstreamUrl: 'https://github.com/ThreatDefence/agentic-attack-detections/tree/main/frameworks/artex',
    source: 'github.com/ThreatDefence/agentic-attack-detections',
    license: 'MIT',
  },
  '/data/aad/indicators/user_agent.json': {
    type: 'user_agent',
    count: 4,
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
        value: 'cairn-agent/1.0',
        confidence: 'medium',
        context: 'UA',
        actor: '',
        source: 'Report',
        sourceUrl: '',
        reported: '',
        framework: 'cairn',
      },
      {
        value: 'artex-pentest/1.0',
        confidence: 'high',
        context: 'UA',
        actor: '',
        source: 'Datadog',
        sourceUrl: '',
        reported: '',
        framework: 'artex',
      },
      {
        value: 'other/1.0',
        confidence: 'low',
        context: 'UA',
        actor: '',
        source: '',
        sourceUrl: '',
        reported: '',
        framework: 'general',
      },
    ],
  },
  '/data/aad/attack.json': {
    source: 'github.com/ThreatDefence/agentic-attack-detections',
    sourceUrl: 'https://example.com',
    description: 'layer',
    maxValue: 420,
    techniques: [{ id: 'T1046', score: 420, comment: 'rules' }],
  },
});

beforeEach(() => _resetAadCacheForTests());

describe('aad-manifest', () => {
  it('loads the slim index', async () => {
    const idx = await loadAadIndex(ASSETS);
    expect(idx.frameworks).toHaveLength(2);
    expect(idx.stats.indicators).toBe(4);
  });

  it('throws a helpful error when the index is missing', async () => {
    const empty = mockAssets({});
    await expect(loadAadIndex(empty)).rejects.toThrow(/build-aad-manifest\.mjs/);
  });

  it('filters frameworks by keyword and counts', async () => {
    const idx = await loadAadIndex(ASSETS);
    expect(filterAadFrameworks(idx.frameworks, { keyword: 'storm' }).map((f) => f.slug)).toEqual(['artex']);
    expect(filterAadFrameworks(idx.frameworks, { minRules: 50 }).map((f) => f.slug)).toEqual(['artex']);
    expect(filterAadFrameworks(idx.frameworks, { limit: 1 })).toHaveLength(1);
  });

  it('rejects unsafe framework slugs', async () => {
    expect(await getAadFramework(ASSETS, '../attacks')).toBeNull();
  });

  it('loads a framework body and caches it', async () => {
    const body = await getAadFramework(ASSETS, 'artex');
    expect(body?.techniques[0]?.id).toBe('T1046');
    expect(body?.indicators).toHaveLength(1);
    await getAadFramework(ASSETS, 'artex');
    expect(aadCacheStats().hits).toBeGreaterThan(0);
  });

  it('filters indicator shards by framework and keyword', async () => {
    const rows = await filterAadIndicators(ASSETS, { framework: 'artex' });
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.type === 'user_agent')).toBe(true);
    const needles = await filterAadIndicators(ASSETS, { keyword: 'pentest' });
    expect(needles).toHaveLength(1);
  });

  it('respects an indicator limit', async () => {
    expect(await filterAadIndicators(ASSETS, { limit: 1 })).toHaveLength(1);
  });

  it('loads the ATT&CK layer', async () => {
    const layer = await loadAadAttack(ASSETS);
    expect(layer?.maxValue).toBe(420);
    expect(layer?.techniques[0]?.id).toBe('T1046');
  });
});
