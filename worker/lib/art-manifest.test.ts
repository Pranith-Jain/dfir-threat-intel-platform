import { beforeEach, describe, expect, it } from 'vitest';
import {
  _resetArtCacheForTests,
  artCacheStats,
  filterArtTechniques,
  getArtTechnique,
  loadArtIndex,
  type ArtIndex,
} from './art-manifest';

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

const FAKE_INDEX: ArtIndex = {
  generatedAt: '2026-11-26T00:00:00.000Z',
  source: 'github.com/redcanaryco/atomic-red-team',
  sourceUrl: 'https://github.com/redcanaryco/atomic-red-team',
  siteUrl: 'https://www.atomicredteam.io',
  license: 'MIT',
  description: 'test',
  stats: { techniques: 2, tests: 3, platforms: 2, executors: 2, failed: 0 },
  platformCounts: { windows: 2, linux: 1 },
  executorCounts: { powershell: 2, sh: 1 },
  techniques: [
    {
      id: 'T1059.001',
      displayName: 'Command and Scripting Interpreter: PowerShell',
      testCount: 2,
      platforms: ['windows'],
      executors: ['powershell'],
      subtechnique: true,
      upstreamUrl: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.yaml',
    },
    {
      id: 'T1003',
      displayName: 'OS Credential Dumping',
      testCount: 1,
      platforms: ['windows', 'linux'],
      executors: ['sh'],
      subtechnique: false,
      upstreamUrl: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.yaml',
    },
  ],
};

const ASSETS = mockAssets({
  '/data/art/index.json': FAKE_INDEX,
  '/data/art/techniques/T1059.001.json': {
    ...FAKE_INDEX.techniques[0],
    tests: [
      {
        name: 'Mimikatz',
        guid: 'f3132740-55bc-48c4-bcc0-758a459cd027',
        description: 'Download Mimikatz and dump credentials.',
        platforms: ['windows'],
        executor: { name: 'powershell', elevationRequired: true, hasCleanup: true },
        inputArguments: ['mimurl'],
        dependencyCount: 1,
      },
    ],
  },
});

beforeEach(() => _resetArtCacheForTests());

describe('art-manifest', () => {
  it('loads the slim index', async () => {
    const idx = await loadArtIndex(ASSETS);
    expect(idx.techniques).toHaveLength(2);
    expect(idx.stats.tests).toBe(3);
  });

  it('throws a helpful error when the index is missing', async () => {
    await expect(loadArtIndex(mockAssets({}))).rejects.toThrow(/build-art-manifest\.mjs/);
  });

  it('filters techniques by keyword, platform, executor and subtechnique', async () => {
    const idx = await loadArtIndex(ASSETS);
    expect(filterArtTechniques(idx.techniques, { keyword: 'powershell' }).map((t) => t.id)).toEqual(['T1059.001']);
    expect(filterArtTechniques(idx.techniques, { platform: 'linux' }).map((t) => t.id)).toEqual(['T1003']);
    expect(filterArtTechniques(idx.techniques, { executor: 'sh' }).map((t) => t.id)).toEqual(['T1003']);
    expect(filterArtTechniques(idx.techniques, { subtechnique: false }).map((t) => t.id)).toEqual(['T1003']);
    expect(filterArtTechniques(idx.techniques, { minTests: 2 })).toHaveLength(1);
    expect(filterArtTechniques(idx.techniques, { limit: 1 })).toHaveLength(1);
  });

  it('rejects malformed technique ids', async () => {
    expect(await getArtTechnique(ASSETS, '../T1003')).toBeNull();
  });

  it('loads a technique body and caches it', async () => {
    const body = await getArtTechnique(ASSETS, 't1059.001');
    expect(body?.tests[0]?.name).toBe('Mimikatz');
    expect(body?.tests[0]?.executor.elevationRequired).toBe(true);
    expect(body?.tests[0]?.executor).not.toHaveProperty('command');
    await getArtTechnique(ASSETS, 'T1059.001');
    expect(artCacheStats().hits).toBeGreaterThan(0);
  });

  it('returns null for a missing technique', async () => {
    expect(await getArtTechnique(ASSETS, 'T9999')).toBeNull();
  });
});
