import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadPrtfIndex,
  filterPrtfTechniques,
  getPrtfTechnique,
  normalizePrtfId,
  prtfCacheStats,
  _resetPrtfCacheForTests,
  type PrtfIndex,
} from './prtf-manifest';

function mockAssets(files: Record<string, unknown>): Fetcher {
  return {
    fetch: async (req: Request) => {
      const data = files[new URL(req.url).pathname];
      if (data === undefined) return new Response(null, { status: 404 });
      return new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

const row = (id: string, tacticId: string) => ({
  id,
  name: `Technique ${id}`,
  tacticId,
  tacticName: tacticId === 'PRTF-1' ? 'Reconnaissance' : 'Evasion',
  summary: 'short description',
  toolCount: 2,
  url: `https://redteam.vip/prtf/#${id}`,
});

const INDEX: PrtfIndex = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'PRTF',
  sourceUrl: 'https://redteam.vip/prtf/',
  license: 'CC BY 4.0',
  version: '1.1',
  counts: { tactics: 2, techniques: 2 },
  tactics: [
    { id: 'PRTF-1', name: 'Reconnaissance', description: 'Gather information', count: 1 },
    { id: 'PRTF-2', name: 'Evasion', description: 'Avoid detection', count: 1 },
  ],
  techniques: [row('PRTF-1.01', 'PRTF-1'), row('PRTF-2.01', 'PRTF-2')],
};

beforeEach(() => _resetPrtfCacheForTests());

describe('PRTF manifest', () => {
  it('loads the index and reports cache state', async () => {
    const idx = await loadPrtfIndex(mockAssets({ '/data/prtf/index.json': INDEX }));
    expect(idx.counts.techniques).toBe(2);
    expect(prtfCacheStats().loaded).toBe(true);
  });

  it('validates ids before touching the asset path', () => {
    expect(normalizePrtfId(' prtf-1.01 ')).toBe('PRTF-1.01');
    expect(normalizePrtfId('../../etc/passwd')).toBeNull();
    expect(normalizePrtfId('CVE-2026-1')).toBeNull();
  });

  it('fetches one technique body', async () => {
    const body = { ...row('PRTF-1.01', 'PRTF-1'), description: 'full', tools: [], chains: [], blue: null };
    const got = await getPrtfTechnique(mockAssets({ '/data/prtf/techniques/PRTF-1.01.json': body }), 'prtf-1.01');
    expect(got?.description).toBe('full');
  });

  it('filters by tactic and keyword with a cap', () => {
    expect(filterPrtfTechniques(INDEX, { tactic: 'prtf-2' }).map((t) => t.id)).toEqual(['PRTF-2.01']);
    expect(filterPrtfTechniques(INDEX, { q: 'recon' }).map((t) => t.id)).toEqual(['PRTF-1.01']);
    expect(filterPrtfTechniques(INDEX, { limit: 1 })).toHaveLength(1);
  });
});
