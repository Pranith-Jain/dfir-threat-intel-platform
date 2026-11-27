import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadBttIndex,
  filterBttTools,
  getBttTool,
  bttCacheStats,
  _resetBttCacheForTests,
  type BttIndex,
} from './blue-team-tools-manifest';

function mockAssets(data: unknown): Fetcher {
  return {
    fetch: async () => new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } }),
  } as unknown as Fetcher;
}

const INDEX: BttIndex = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'BlueTeam-Tools',
  sourceUrl: 'https://github.com/A-poc/BlueTeam-Tools',
  license: 'metadata only',
  counts: { categories: 2, tools: 3, withLinks: 2 },
  categories: [
    { name: 'Threat Hunting', statedCount: '2 tools', toolCount: 2, tools: ['hunt-io', 'validin'] },
    { name: 'Network Discovery', statedCount: '1 tools', toolCount: 1, tools: ['nmap'] },
  ],
  tools: [
    {
      slug: 'hunt-io',
      name: 'hunt.io',
      category: 'Threat Hunting',
      summary: 'Discover active C2 servers',
      url: 'https://hunt.io',
      upstreamUrl: 'https://github.com/A-poc/BlueTeam-Tools/blob/main/README.md#huntio',
    },
    {
      slug: 'validin',
      name: 'Validin',
      category: 'Threat Hunting',
      summary: 'Pivot through DNS',
      url: null,
      upstreamUrl: 'https://github.com/A-poc/BlueTeam-Tools/blob/main/README.md#validin',
    },
    {
      slug: 'nmap',
      name: 'Nmap',
      category: 'Network Discovery',
      summary: 'Network scanner',
      url: 'https://nmap.org',
      upstreamUrl: 'https://github.com/A-poc/BlueTeam-Tools/blob/main/README.md#nmap',
    },
  ],
};

beforeEach(() => _resetBttCacheForTests());

describe('loadBttIndex', () => {
  it('loads and caches the mirrored index', async () => {
    const first = await loadBttIndex(mockAssets(INDEX));
    expect(first.counts.tools).toBe(3);
    expect((await loadBttIndex(mockAssets({}))).counts.tools).toBe(3);
    expect(bttCacheStats().loaded).toBe(true);
  });
});

describe('filterBttTools', () => {
  it('filters by category slug, keyword and link availability', () => {
    expect(filterBttTools(INDEX, { category: 'threat-hunting' }).map((t) => t.slug)).toEqual(['hunt-io', 'validin']);
    expect(filterBttTools(INDEX, { q: 'dns' }).map((t) => t.slug)).toEqual(['validin']);
    expect(filterBttTools(INDEX, { linked: true }).map((t) => t.slug)).toEqual(['hunt-io', 'nmap']);
    expect(filterBttTools(INDEX, { limit: 1 })).toHaveLength(1);
  });
});

describe('getBttTool', () => {
  it('resolves a slug case-insensitively and returns null for unknown ids', () => {
    expect(getBttTool(INDEX, ' Nmap ')?.name).toBe('Nmap');
    expect(getBttTool(INDEX, 'missing')).toBeNull();
  });
});
