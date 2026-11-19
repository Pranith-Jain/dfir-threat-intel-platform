import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadKpIndex,
  filterKpTools,
  filterKpExploits,
  getKpFeed,
  kpCacheStats,
  _resetKpCacheForTests,
  type KpIndex,
  type KpTool,
  type KpExploit,
} from './kp-manifest';

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

const TOOLS: KpTool[] = [
  {
    id: 'github/a/iottack',
    title: 'iottack',
    url: 'u1',
    provider: 'GitHub',
    repo: 'a/iottack',
    description: 'IoT protocol testing',
    image: null,
    categories: ['iot-security'],
    stars: '2',
  },
  {
    id: 'gitlab/b/scanner',
    title: 'scanner',
    url: 'u2',
    provider: 'GitLab',
    repo: 'b/scanner',
    description: 'SAST scanner',
    image: null,
    categories: ['static-code-analysis'],
    stars: '10',
  },
];

const EXPLOITS: KpExploit[] = [
  {
    id: 'cve-2026-1306',
    cve: 'CVE-2026-1306',
    title: 'midi-Synth file upload',
    url: 'e1',
    cvssScore: 9.8,
    cvssSeverity: 'High',
    epss: '4.8%; Low',
    exploitCount: 2,
    evidence: 'Evidence Aug 25',
  },
  {
    id: 'cve-2026-1405',
    cve: 'CVE-2026-1405',
    title: 'Slider Future upload',
    url: 'e2',
    cvssScore: 7.5,
    cvssSeverity: 'Medium',
    epss: '3.5%; Low',
    exploitCount: 1,
    evidence: 'Evidence Aug 28',
  },
];

const INDEX: KpIndex = {
  source: 'kitploit.com',
  sourceUrl: 'https://kitploit.com/en',
  license: 'metadata only',
  robots: 'HTML and feeds allowed; /api/ disallowed',
  builtAt: '2026-11-19',
  counts: { tools: 2, exploits: 2, updates: 50, exploitUpdates: 100, blogPosts: 2 },
  stats: {
    listedTools: 2,
    listedExploits: 2,
    feedItems: {},
    byProvider: { GitHub: 1, GitLab: 1 },
    byCategory: {},
    byCvssSeverity: {},
    sourceLinks: 4,
  },
  tools: TOOLS,
  exploits: EXPLOITS,
  feeds: { updates: [{ title: 'Aliens_eye', url: 'u', published: 'Thu, 19 Nov 2026' }] },
  webPages: {},
};

beforeEach(() => _resetKpCacheForTests());

describe('kp-manifest', () => {
  it('loads the index and caches it', async () => {
    const assets = mockAssets({ '/data/kp/index.json': INDEX });
    expect((await loadKpIndex(assets)).counts.tools).toBe(2);
    await loadKpIndex(assets);
    expect(kpCacheStats().index.hits).toBe(1);
  });

  it('filters tools by category, provider and keyword', () => {
    expect(filterKpTools(TOOLS, { provider: 'GitLab' }).map((t) => t.id)).toEqual(['gitlab/b/scanner']);
    expect(filterKpTools(TOOLS, { category: 'iot-security' }).map((t) => t.id)).toEqual(['github/a/iottack']);
    expect(filterKpTools(TOOLS, { keyword: 'sast' }).map((t) => t.id)).toEqual(['gitlab/b/scanner']);
  });

  it('filters exploits by severity and keyword', () => {
    expect(filterKpExploits(EXPLOITS, { severity: 'High' }).map((e) => e.id)).toEqual(['cve-2026-1306']);
    expect(filterKpExploits(EXPLOITS, { keyword: 'CVE-2026-1405' }).map((e) => e.id)).toEqual(['cve-2026-1405']);
  });

  it('reads a feed shard and rejects unsafe names', async () => {
    const assets = mockAssets({
      '/data/kp/feeds/updates.json': {
        items: [{ title: 'x', url: 'u', published: null, description: null, guid: 'g', image: null }],
      },
    });
    expect((await getKpFeed(assets, 'updates'))?.[0]?.title).toBe('x');
    await getKpFeed(assets, 'updates');
    expect(kpCacheStats().feeds.hits).toBe(1);
    expect(await getKpFeed(assets, '../index')).toBeNull();
  });
});
