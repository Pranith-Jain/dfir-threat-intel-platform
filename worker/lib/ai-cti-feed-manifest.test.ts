import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadAiCtiIndex,
  filterAiCtiRows,
  getAiCtiBody,
  aiCtiCacheStats,
  _resetAiCtiCacheForTests,
  type AiCtiIndex,
} from './ai-cti-feed-manifest';

function assets(files: Record<string, unknown>): Fetcher {
  return {
    fetch: async (req: Request) => {
      const data = files[new URL(req.url).pathname];
      return data === undefined
        ? new Response(null, { status: 404 })
        : new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

const row = (id: string, name: string, category: string | null) => ({
  id,
  slug: id.split('--')[1] ?? id,
  name,
  category,
  created: null,
  labels: [],
  refCount: 1,
});

const INDEX: AiCtiIndex = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'OWASP GenAI Threat Intelligence Initiative',
  sourceUrl: 'https://aithreatintelfeed.org/stix/threat-actors-ai-stix2.1.json',
  repoUrl: 'https://github.com/GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative',
  license: 'metadata only',
  counts: {
    objects: 5,
    actors: 2,
    techniques: 1,
    malware: 0,
    reports: 0,
    indicators: 1,
    relationships: 1,
    categoryA: 1,
    categoryB: 1,
  },
  actors: [row('intrusion-set--a', 'Actor A', 'A'), row('intrusion-set--b', 'Actor B', 'B')],
  techniques: [row('attack-pattern--c', 'Prompt injection', 'B')],
  malware: [],
  reports: [],
  indicators: [{ id: 'indicator--d', name: 'IOC', category: 'A', labels: [], created: null }],
};

beforeEach(() => _resetAiCtiCacheForTests());

describe('AI-CTI manifest', () => {
  it('caches the STIX index and reports counts', async () => {
    const idx = await loadAiCtiIndex(assets({ '/data/ai-cti-feed/index.json': INDEX }));
    expect(idx.counts.actors).toBe(2);
    expect(aiCtiCacheStats().loaded).toBe(true);
  });

  it('filters actors by category and keyword', () => {
    expect(filterAiCtiRows(INDEX.actors, { category: 'A' }).map((r) => r.name)).toEqual(['Actor A']);
    expect(filterAiCtiRows(INDEX.actors, { q: 'actor b' }).map((r) => r.name)).toEqual(['Actor B']);
    expect(filterAiCtiRows(INDEX.actors, { limit: 1 })).toHaveLength(1);
  });

  it('reads a body and rejects an unsafe slug', async () => {
    const body = {
      ...row('intrusion-set--a', 'Actor A', 'A'),
      description: 'full',
      labels: [],
      modified: null,
      refs: [],
      links: [],
    };
    const got = await getAiCtiBody(assets({ '/data/ai-cti-feed/actors/a.json': body }), 'actors', 'a');
    expect(got?.description).toBe('full');
    expect(await getAiCtiBody(assets({}), 'actors', '../etc')).toBeNull();
  });
});
