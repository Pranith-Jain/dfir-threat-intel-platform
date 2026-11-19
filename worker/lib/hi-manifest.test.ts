import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadHiIndex,
  filterHiIncidents,
  getHiIncident,
  loadHiStats,
  hiCacheStats,
  _resetHiCacheForTests,
  type HiIndex,
  type HiIncidentSlim,
} from './hi-manifest';

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

function row(overrides: Partial<HiIncidentSlim>): HiIncidentSlim {
  return {
    id: 'x-2026',
    title: 'AI-assisted intrusion',
    date: '2026-03',
    year: '2026',
    month: '2026-03',
    actor: 'ARTEX operator',
    actorType: 'criminal',
    nexus: null,
    targets: 'a bank',
    aiRole: ['recon'],
    models: ['Claude'],
    modelBasis: 'stated',
    autonomy: 'semi-autonomous',
    confidence: 'confirmed',
    sourceCount: 2,
    primarySourceCount: 1,
    modelNamed: true,
    harnessUsed: true,
    harnessNames: ['ARTEX'],
    countries: ['US'],
    sectors: ['finance'],
    ...overrides,
  };
}

const ROWS: HiIncidentSlim[] = [
  row({ id: 'x-2026', title: 'AI-assisted intrusion' }),
  row({
    id: 'y-2025',
    title: 'Deepfake CEO fraud',
    date: '2025-07',
    year: '2025',
    month: '2025-07',
    confidence: 'strong',
    autonomy: 'assist',
    aiRole: ['deepfake'],
    harnessUsed: false,
    sourceCount: 1,
  }),
  row({
    id: 'z-2024',
    title: 'LLM phishing content',
    date: '2024-01',
    year: '2024',
    month: '2024-01',
    confidence: 'suspected',
    aiRole: ['phishing-content'],
  }),
];

const INDEX: HiIndex = {
  source: 'hackingincidents.ai',
  sourceUrl: 'https://hackingincidents.ai/',
  license: 'metadata only',
  builtAt: '2026-11-19',
  upstreamUpdated: '2026-11-17',
  counts: {
    records: 3,
    months: 3,
    confirmed: 1,
    strong: 1,
    suspected: 1,
    namedModels: 2,
    harnessUse: 1,
    sourceLinks: 4,
  },
  stats: {
    count: 3,
    months: {},
    byYear: { '2026': 1, '2025': 1, '2024': 1 },
    byConfidence: { confirmed: 1, strong: 1, suspected: 1 },
    byAutonomy: { 'semi-autonomous': 1, assist: 1 },
    byActorType: { criminal: 2 },
    byRole: { recon: 1, deepfake: 1, 'phishing-content': 1 },
    byCountry: { US: 1 },
    bySector: { finance: 1 },
    sources: { links: 4, primary: 2, uniqueUrls: 4 },
    namedModels: 2,
    harnessUse: 1,
  },
  months: ['2024-01', '2025-07', '2026-03'],
  incidents: ROWS,
  webPages: {},
};

beforeEach(() => _resetHiCacheForTests());

describe('hi-manifest', () => {
  it('loads the slim index from /data/hi/index.json and caches it', async () => {
    const assets = mockAssets({ '/data/hi/index.json': INDEX });
    expect((await loadHiIndex(assets)).counts.records).toBe(3);
    await loadHiIndex(assets);
    expect(hiCacheStats().index.hits).toBe(1);
  });

  it('throws a helpful error when the index is missing', async () => {
    await expect(loadHiIndex(mockAssets({}))).rejects.toThrow(/build-hi-manifest\.mjs/);
  });

  it('filters by grade, autonomy, role, year and keyword', () => {
    expect(filterHiIncidents(ROWS, { confidence: 'strong' }).map((r) => r.id)).toEqual(['y-2025']);
    expect(filterHiIncidents(ROWS, { autonomy: 'assist' }).map((r) => r.id)).toEqual(['y-2025']);
    expect(filterHiIncidents(ROWS, { role: 'recon' }).map((r) => r.id)).toEqual(['x-2026']);
    expect(filterHiIncidents(ROWS, { year: '2024' }).map((r) => r.id)).toEqual(['z-2024']);
    expect(filterHiIncidents(ROWS, { keyword: 'deepfake' }).map((r) => r.id)).toEqual(['y-2025']);
    expect(filterHiIncidents(ROWS, { harness: true }).map((r) => r.id)).toEqual(['x-2026', 'z-2024']);
    expect(filterHiIncidents(ROWS, { limit: 2 })).toHaveLength(2);
  });

  it('resolves a body from the id month shard and reuses the cached shard', async () => {
    const body = { ...ROWS[0], summary: 'a summary', sources: [], upstreamUrl: 'u' };
    const assets = mockAssets({
      '/data/hi/index.json': INDEX,
      '/data/hi/incidents/2026-03.json': { month: '2026-03', incidents: [body] },
    });
    expect((await getHiIncident(assets, 'x-2026'))?.summary).toBe('a summary');
    expect((await getHiIncident(assets, 'x-2026'))?.id).toBe('x-2026');
    expect(hiCacheStats().shards.hits).toBe(1);
    expect(await getHiIncident(assets, 'unknown')).toBeNull();
  });

  it('reads stats from the stats file', async () => {
    const stats = { ...INDEX.stats, count: 99 };
    expect((await loadHiStats(mockAssets({ '/data/hi/stats.json': { stats } })))?.count).toBe(99);
  });
});
