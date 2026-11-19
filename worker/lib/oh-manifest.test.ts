import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadOhIndex,
  filterOhHarnesses,
  getOhHarness,
  loadOhSideFile,
  ohCacheStats,
  _resetOhCacheForTests,
  type OhIndex,
  type OhHarnessSlim,
} from './oh-manifest';

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

function harness(overrides: Partial<OhHarnessSlim>): OhHarnessSlim {
  return {
    slug: 'artex',
    name: 'ARTEX',
    table: 'evidence',
    tier: 'confirmed',
    kind: 'multi-agent pentest platform',
    description: 'weaponised agentic platform',
    repo: 'https://github.com/example/artex',
    url: 'https://offsecharnesses.ai/#h-artex',
    stars: 100,
    license: 'MIT',
    lastPush: '2026-10-01',
    archived: false,
    actors: [{ name: 'VAPOR PANDA', note: 'China-nexus' }],
    useTags: ['recon', 'exploit'],
    useBasis: ['attack report'],
    breach: 'Yes',
    keyFigure: '200+ orgs',
    sourceCount: 14,
    incidentCount: 13,
    ...overrides,
  };
}

const ROWS = [
  harness({ slug: 'artex' }),
  harness({
    slug: 'cairn',
    name: 'Cairn',
    tier: 'observed',
    actors: [],
    useTags: ['vuln'],
    breach: null,
    stars: 50,
  }),
  harness({
    slug: 'shannon',
    name: 'Shannon',
    table: 'field',
    tier: 'no attack on record',
    actors: [],
    breach: null,
    stars: 52000,
  }),
];

const INDEX: OhIndex = {
  source: 'offsecharnesses.ai',
  sourceUrl: 'https://offsecharnesses.ai/',
  license: 'metadata only',
  builtAt: '2026-11-19',
  upstreamData: 'https://github.com/danielmiessler/substrate',
  evidenceReviewed: '2026-11-17',
  githubFacts: '2026-11-18',
  tiers: {},
  useTags: [{ key: 'recon', label: 'Recon', def: 'maps a target' }],
  related: {},
  counts: { tracked: 3, inTheWild: 2, confirmed: 1, observed: 1, actors: 1, sources: 2, breaches: 1 },
  stats: {
    tracked: 3,
    evidenceRows: 2,
    fieldRows: 1,
    byTier: {},
    byTable: {},
    byKind: {},
    byLicense: {},
    byUseTag: [],
    actors: [],
    sourceCount: 2,
    referenceCount: 3,
    breaches: 1,
    withRepo: 3,
  },
  harnesses: ROWS,
  webPages: {},
};

beforeEach(() => _resetOhCacheForTests());

describe('oh-manifest', () => {
  it('loads the index and caches it', async () => {
    const assets = mockAssets({ '/data/oh/index.json': INDEX });
    expect((await loadOhIndex(assets)).counts.tracked).toBe(3);
    await loadOhIndex(assets);
    expect(ohCacheStats().index.hits).toBe(1);
  });

  it('filters by table, tier, use tag, actor and keyword', () => {
    expect(filterOhHarnesses(ROWS, { table: 'evidence' }).map((h) => h.slug)).toEqual(['artex', 'cairn']);
    expect(filterOhHarnesses(ROWS, { tier: 'confirmed' }).map((h) => h.slug)).toEqual(['artex']);
    expect(filterOhHarnesses(ROWS, { useTag: 'vuln' }).map((h) => h.slug)).toEqual(['cairn']);
    expect(filterOhHarnesses(ROWS, { actor: 'VAPOR PANDA' }).map((h) => h.slug)).toEqual(['artex']);
    expect(filterOhHarnesses(ROWS, { keyword: 'shannon' }).map((h) => h.slug)).toEqual(['shannon']);
  });

  it('rejects unsafe slugs before touching assets', async () => {
    expect(await getOhHarness(mockAssets({}), '../index')).toBeNull();
  });

  it('reads one harness body from its shard and caches it', async () => {
    const body = {
      ...ROWS[0],
      whatItDid: 'ran 25 operations',
      uses: [],
      sourceIds: [],
      incidents: [],
      upstreamUrl: 'u',
    };
    const assets = mockAssets({
      '/data/oh/harnesses/artex.json': { harness: body },
    });
    expect((await getOhHarness(assets, 'artex'))?.whatItDid).toBe('ran 25 operations');
    await getOhHarness(assets, 'artex');
    expect(ohCacheStats().bodies.hits).toBe(1);
    expect(await getOhHarness(assets, 'missing')).toBeNull();
  });

  it('loads side files verbatim', async () => {
    const sources = [
      { id: 'x', publisher: 'CrowdStrike', kind: 'Vendor', date: '2026-10-29', title: 'ARTEX', url: 'u' },
    ];
    const out = await loadOhSideFile<{ sources: unknown[] }>(
      mockAssets({ '/data/oh/sources.json': { sources } }),
      'sources'
    );
    expect(out?.sources).toEqual(sources);
  });
});
