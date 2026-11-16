import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadMmdIndex,
  listMmdTools,
  getMmdCategory,
  loadMmdCommits,
  loadMmdReadme,
  mmdCacheStats,
  _resetMmdCacheForTests,
  type MmdIndex,
  type MmdCategoryBody,
} from './mmd-manifest';

function mockAssets(files: Record<string, unknown>): Fetcher {
  return {
    fetch: async (_req: Request) => {
      const url = new URL(_req.url);
      const data = files[url.pathname];
      if (data === undefined) return new Response(null, { status: 404 });
      return new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

const FAKE_INDEX: MmdIndex = {
  source: 'github.com/unixfreaxjp/malwaremustdie',
  sourceUrl: 'https://github.com/unixfreaxjp/malwaremustdie',
  siteUrl: 'https://unixfreaxjp.github.io/malwaremustdie/',
  license: 'Unlicensed (public share, upstream disclaimer applies)',
  builtAt: '2026-11-16',
  branch: 'master',
  about: 'MMD shared codes & tools.',
  counts: {
    files: 4,
    categories: 2,
    scripts: 2,
    docs: 1,
    binaries: 0,
    totalSize: 20000,
    commitsTracked: 427,
    recentCommits: 2,
  },
  categories: [
    { category: 'Bash', description: 'Shell utilities', count: 3, totalSize: 12000, kinds: { script: 2, doc: 1 } },
    { category: 'Python', description: 'Python tooling', count: 1, totalSize: 8000, kinds: { script: 1 } },
  ],
  files: [
    { path: 'Bash/911diff.sh', name: '911diff.sh', category: 'Bash', ext: 'sh', kind: 'script', size: 7696 },
    {
      path: 'Bash/ransomware_payment_crawler.sh',
      name: 'ransomware_payment_crawler.sh',
      category: 'Bash',
      ext: 'sh',
      kind: 'script',
      size: 1489,
    },
    { path: 'Bash/NOTES.md', name: 'NOTES.md', category: 'Bash', ext: 'md', kind: 'doc', size: 200 },
    { path: 'Python/pcap_dump.py', name: 'pcap_dump.py', category: 'Python', ext: 'py', kind: 'script', size: 8000 },
  ],
  recentCommits: [
    { sha: 'abc1234', date: '2026-11-16T07:18:03Z', author: 'unixfreaxjp', message: 'update wiki' },
    { sha: 'def5678', date: '2026-10-02T01:00:00Z', author: 'unixfreaxjp', message: 'add script' },
  ],
  lastCommit: '2026-11-16T07:18:03Z',
};

const FAKE_CATEGORY: MmdCategoryBody = {
  category: 'Bash',
  description: 'Shell utilities',
  count: 3,
  totalSize: 12000,
  source: 'github.com/unixfreaxjp/malwaremustdie',
  sourceUrl: 'https://github.com/unixfreaxjp/malwaremustdie/tree/master/Bash',
  license: 'Unlicensed (public share, upstream disclaimer applies)',
  files: FAKE_INDEX.files.filter((f) => f.category === 'Bash'),
};

const FAKE_COMMITS = {
  source: 'github.com/unixfreaxjp/malwaremustdie',
  sourceUrl: 'https://github.com/unixfreaxjp/malwaremustdie',
  license: 'Unlicensed (public share, upstream disclaimer applies)',
  builtAt: '2026-11-16',
  count: 2,
  commits: FAKE_INDEX.recentCommits,
};

describe('mmd-manifest', () => {
  beforeEach(() => _resetMmdCacheForTests());

  it('loads the index from ASSETS', async () => {
    const idx = await loadMmdIndex(mockAssets({ '/data/mmd/index.json': FAKE_INDEX }));
    expect(idx.counts.files).toBe(4);
    expect(idx.branch).toBe('master');
    expect(idx.files).toHaveLength(4);
  });

  it('throws a helpful error when the manifest is missing', async () => {
    await expect(loadMmdIndex(mockAssets({}))).rejects.toThrow(/build-mmd-manifest/);
  });

  it('lists tools filtered by category', () => {
    const out = listMmdTools(FAKE_INDEX, { category: 'bash' });
    expect(out).toHaveLength(3);
    expect(out.every((f) => f.category === 'Bash')).toBe(true);
  });

  it('lists tools filtered by kind and ext', () => {
    expect(listMmdTools(FAKE_INDEX, { kind: 'script' })).toHaveLength(3);
    expect(listMmdTools(FAKE_INDEX, { ext: 'sh' }).map((f) => f.name)).toEqual([
      '911diff.sh',
      'ransomware_payment_crawler.sh',
    ]);
    expect(listMmdTools(FAKE_INDEX, { ext: 'py' }).map((f) => f.category)).toEqual(['Python']);
  });

  it('keyword-matches full paths', () => {
    const out = listMmdTools(FAKE_INDEX, { keyword: 'ransomware' });
    expect(out.map((f) => f.path)).toEqual(['Bash/ransomware_payment_crawler.sh']);
  });

  it('respects limit', () => {
    expect(listMmdTools(FAKE_INDEX, { limit: 2 })).toHaveLength(2);
  });

  it('fetches a category body and caches it', async () => {
    const assets = mockAssets({ '/data/mmd/categories/Bash.json': FAKE_CATEGORY });
    const first = await getMmdCategory(assets, 'Bash');
    expect(first?.files).toHaveLength(3);
    await getMmdCategory(assets, 'Bash');
    expect(mmdCacheStats().bodyHits).toBe(1);
    expect(mmdCacheStats().bodyMisses).toBe(1);
  });

  it('returns null for an unknown category', async () => {
    expect(await getMmdCategory(mockAssets({}), 'Nope')).toBeNull();
  });

  it('loads recent commits', async () => {
    const body = await loadMmdCommits(mockAssets({ '/data/mmd/commits.json': FAKE_COMMITS }));
    expect(body?.count).toBe(2);
    expect(body?.commits[0]?.sha).toBe('abc1234');
  });

  it('loads the README body', async () => {
    const body = await loadMmdReadme(
      mockAssets({ '/data/mmd/readme.json': { source: 'x', body: '# MalwareMustDie shared codes repository' } })
    );
    expect(body).toContain('MalwareMustDie');
  });
});
