import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadDbIndex,
  getDbBrief,
  filterBriefs,
  dbCacheStats,
  _resetDbCacheForTests,
  type DbIndex,
  type DbBriefBody,
} from '../lib/daily-briefs-manifest';

const MOCK_INDEX: DbIndex = {
  source: 'test',
  license: 'MIT',
  generatedAt: '2026-07-21',
  counts: { cyber: 2, deepfake: 1, disaster: 1, maritime: 0, water: 0, french: 0 },
  briefs: [
    { type: 'cyber', date: '2026-07-20', sizeBytes: 1000 },
    { type: 'cyber', date: '2026-07-19', sizeBytes: 900 },
    { type: 'deepfake', date: '2026-07-20', sizeBytes: 800 },
    { type: 'disaster', date: '2026-07-21', sizeBytes: 700 },
  ],
};

const MOCK_CYBER: DbBriefBody = {
  type: 'cyber',
  date: '2026-07-20',
  threatLevel: 'CRITICAL',
  executiveSummary: 'Test summary',
  keyFindings: [],
  dashboard: { kpis: [], activelyExploited: [], vendors: [], sectors: [] },
  topThreats: [],
  threatActors: [],
  cveWatch: [],
  events: [],
  ttps: { descriptions: [], mitreIds: ['T1190'] },
  outlook72h: 'Test outlook',
  relatedCves: [],
  rawMarkdown: 'test',
};

function makeAssets(data: Record<string, unknown>): Fetcher {
  return {
    fetch: async (req: Request) => {
      const url = new URL(req.url);
      const path = url.pathname;
      const body = data[path];
      if (body === undefined) return new Response('Not found', { status: 404 });
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

describe('daily-briefs-manifest', () => {
  beforeEach(() => {
    _resetDbCacheForTests();
  });

  it('loadDbIndex returns index', async () => {
    const assets = makeAssets({ '/data/daily-briefs/index.json': MOCK_INDEX });
    const idx = await loadDbIndex(assets);
    expect(idx.counts.cyber).toBe(2);
    expect(idx.briefs).toHaveLength(4);
  });

  it('loadDbIndex caches by default', async () => {
    let calls = 0;
    const assets = {
      fetch: async () => {
        calls++;
        return new Response(JSON.stringify(MOCK_INDEX));
      },
    } as unknown as Fetcher;
    await loadDbIndex(assets);
    await loadDbIndex(assets);
    expect(calls).toBe(1);
  });

  it('loadDbIndex forceRefresh bypasses cache', async () => {
    let calls = 0;
    const assets = {
      fetch: async () => {
        calls++;
        return new Response(JSON.stringify(MOCK_INDEX));
      },
    } as unknown as Fetcher;
    await loadDbIndex(assets);
    await loadDbIndex(assets, { forceRefresh: true });
    expect(calls).toBe(2);
  });

  it('getDbBrief returns brief body', async () => {
    const assets = makeAssets({
      '/data/daily-briefs/index.json': MOCK_INDEX,
      '/data/daily-briefs/cyber/2026-07-20.json': MOCK_CYBER,
    });
    const brief = await getDbBrief(assets, 'cyber', '2026-07-20');
    expect(brief).not.toBeNull();
    expect(brief!.type).toBe('cyber');
    if (brief && brief.type === 'cyber') {
      expect(brief.threatLevel).toBe('CRITICAL');
    }
  });

  it('getDbBrief returns null for missing date', async () => {
    const assets = makeAssets({ '/data/daily-briefs/index.json': MOCK_INDEX });
    const brief = await getDbBrief(assets, 'cyber', '2099-01-01');
    expect(brief).toBeNull();
  });

  it('getDbBrief caches bodies', async () => {
    let calls = 0;
    const assets = {
      fetch: async () => {
        calls++;
        return new Response(JSON.stringify(MOCK_CYBER));
      },
    } as unknown as Fetcher;
    await getDbBrief(assets, 'cyber', '2026-07-20');
    await getDbBrief(assets, 'cyber', '2026-07-20');
    expect(calls).toBe(1);
  });

  it('filterBriefs by type', () => {
    const result = filterBriefs(MOCK_INDEX, { type: 'cyber' });
    expect(result).toHaveLength(2);
    expect(result.every((b) => b.type === 'cyber')).toBe(true);
  });

  it('filterBriefs by date range', () => {
    const result = filterBriefs(MOCK_INDEX, { dateFrom: '2026-07-20', dateTo: '2026-07-20' });
    expect(result).toHaveLength(2); // cyber + deepfake on 07-20
  });

  it('filterBriefs respects limit', () => {
    const result = filterBriefs(MOCK_INDEX, { limit: 2 });
    expect(result).toHaveLength(2);
  });

  it('dbCacheStats reports state', async () => {
    const assets = makeAssets({
      '/data/daily-briefs/index.json': MOCK_INDEX,
      '/data/daily-briefs/cyber/2026-07-20.json': MOCK_CYBER,
    });
    await loadDbIndex(assets);
    await getDbBrief(assets, 'cyber', '2026-07-20');
    const stats = dbCacheStats();
    expect(stats.indexLoaded).toBe(true);
    expect(stats.indexAgeMs).not.toBeNull();
    expect(stats.bodyCache.size).toBe(1);
    expect(stats.bodyCache.hits).toBe(0);
    expect(stats.bodyCache.misses).toBe(1);
  });

  it('_resetDbCacheForTests clears all state', async () => {
    const assets = makeAssets({
      '/data/daily-briefs/index.json': MOCK_INDEX,
      '/data/daily-briefs/cyber/2026-07-20.json': MOCK_CYBER,
    });
    await loadDbIndex(assets);
    await getDbBrief(assets, 'cyber', '2026-07-20');
    _resetDbCacheForTests();
    const stats = dbCacheStats();
    expect(stats.indexLoaded).toBe(false);
    expect(stats.bodyCache.size).toBe(0);
  });
});
