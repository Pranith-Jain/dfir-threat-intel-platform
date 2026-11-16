import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadOrcaIndex,
  filterOrcaIncidents,
  getOrcaIncident,
  loadOrcaStats,
  loadOrcaCommits,
  monthForId,
  orcaCacheStats,
  _resetOrcaCacheForTests,
  type OrcaIndex,
  type OrcaIncidentSlim,
} from './orca-manifest';

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

function row(overrides: Partial<OrcaIncidentSlim>): OrcaIncidentSlim {
  return {
    id: '2026-07-09-openai-agents-breach-huggingface',
    title: 'OpenAI agents breach Hugging Face',
    date: '2026-07-09',
    dateEnd: null,
    month: '2026-07',
    kind: 'incident',
    types: ['EVAL', 'WEAPON'],
    severity: 'critical',
    confidence: 'A',
    realHarm: true,
    aiInvolvement: 'confirmed',
    regions: ['GLOBAL'],
    landmark: true,
    disputed: false,
    sourceCount: 3,
    ...overrides,
  };
}

const FAKE_ROWS: OrcaIncidentSlim[] = [
  row({
    id: '2026-11-08-operation-snowball',
    title: 'Operation Snowball',
    date: '2026-11-08',
    month: '2026-11',
    kind: 'incident',
    severity: 'high',
    confidence: 'B',
    types: ['WEAPON', 'EXFIL'],
    regions: ['EU'],
    realHarm: true,
    landmark: false,
    disputed: true,
    sourceCount: 2,
  }),
  row({
    id: '2026-07-09-openai-agents-breach-huggingface',
    title: 'OpenAI agents breach Hugging Face',
    date: '2026-07-09',
    month: '2026-07',
    kind: 'incident',
    severity: 'critical',
    confidence: 'A',
    types: ['EVAL', 'WEAPON'],
    regions: ['GLOBAL'],
    realHarm: true,
    landmark: true,
  }),
  row({
    id: '2026-06-01-meta-support-bot',
    title: 'Meta AI support bot hands over Instagram',
    date: '2026-06-01',
    month: '2026-06',
    kind: 'incident',
    severity: 'high',
    confidence: 'B',
    types: ['IPI', 'CRED'],
    regions: ['GLOBAL'],
    realHarm: true,
    landmark: false,
  }),
  row({
    id: '2026-05-10-autonomous-post-exploitation',
    title: 'First in-the-wild LLM agent post-exploitation',
    date: '2026-05-10',
    month: '2026-05',
    kind: 'research',
    severity: 'critical',
    confidence: 'A',
    types: ['WEAPON'],
    regions: ['GLOBAL'],
    realHarm: false,
    landmark: false,
  }),
  row({
    id: '2026-02-01-some-policy-move',
    title: 'Regulator publishes agent guidance',
    date: '2026-02-01',
    month: '2026-02',
    kind: 'policy',
    severity: 'info',
    confidence: 'A',
    types: ['OTHER'],
    regions: ['EU'],
    realHarm: null,
    aiInvolvement: 'not-applicable',
    landmark: false,
  }),
];

const FAKE_INDEX: OrcaIndex = {
  source: 'github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
  sourceUrl: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
  license: 'CC BY 4.0',
  builtAt: '2026-11-16',
  upstreamVersion: '2026-11-08',
  upstreamSchema: 2,
  languages: ['en'],
  counts: { records: 5, months: 4, realHarm: 3, critical: 2, incidents: 3, disputed: 1, landmark: 1, sources: 8 },
  stats: {
    version: '2026-11-08',
    count: 5,
    months: {},
    by_severity: { critical: 2, high: 2, info: 1 },
    by_kind: { incident: 3, research: 1, policy: 1 },
    by_type: {},
    by_confidence: { A: 4, B: 1 },
    by_region: {},
    real_harm: { true: 3, false: 1, null: 1 },
    ai_involvement: { confirmed: 4, 'not-applicable': 1 },
    sources: { links: 8, unique_urls: 7 },
  },
  months: ['2026-02', '2026-05', '2026-06', '2026-07', '2026-11'],
  incidents: FAKE_ROWS,
  lastCommit: '2026-11-12T06:49:11Z',
  lastCommitSha: 'a0d118c',
  recentCommits: [
    {
      sha: 'a0d118c',
      date: '2026-11-12T06:49:11Z',
      author: 'Xizhuo',
      message: 'Merge pull request #23 from Continuum-AI-Corp/records/2026-11-12-sweep',
    },
  ],
  webPages: {
    repo: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
    commits: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive/commits/main',
    offlineViewer: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive/blob/main/index.html',
    primarySources: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive/blob/main/dist/README.md',
  },
};

const SHARD_2026_07 = {
  month: '2026-07',
  count: 1,
  source: 'github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
  sourceUrl: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
  license: 'CC BY 4.0',
  incidents: [
    {
      ...row({}),
      datePrecision: 'day',
      dateRaw: '2026-07-09',
      summary: 'OpenAI disclosed that its agents breached Hugging Face infrastructure.',
      sources: [{ url: 'https://example.com/a', label: 'Example' }],
      upstreamPath: 'incidents/2026-07/2026-07-09-openai-agents-breach-huggingface.md',
      upstreamUrl:
        'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive/blob/main/incidents/2026-07/2026-07-09-openai-agents-breach-huggingface.md',
    },
  ],
};

describe('orca-manifest', () => {
  beforeEach(() => _resetOrcaCacheForTests());

  it('loads the index from ASSETS', async () => {
    const idx = await loadOrcaIndex(mockAssets({ '/data/orca/index.json': FAKE_INDEX }));
    expect(idx.counts.records).toBe(5);
    expect(idx.license).toBe('CC BY 4.0');
    expect(idx.incidents).toHaveLength(5);
  });

  it('throws a helpful error when the manifest is missing', async () => {
    await expect(loadOrcaIndex(mockAssets({}))).rejects.toThrow(/build-orca-manifest/);
  });

  it('caches the index (second load hits cache)', async () => {
    const assets = mockAssets({ '/data/orca/index.json': FAKE_INDEX });
    await loadOrcaIndex(assets);
    await loadOrcaIndex(assets);
    expect(orcaCacheStats().indexLoaded).toBe(true);
    expect(orcaCacheStats().indexAgeMs).not.toBeNull();
  });

  it('filters by kind', () => {
    const out = filterOrcaIncidents(FAKE_ROWS, { kind: 'incident' });
    expect(out).toHaveLength(3);
    expect(out.every((r) => r.kind === 'incident')).toBe(true);
  });

  it('filters by severity', () => {
    const out = filterOrcaIncidents(FAKE_ROWS, { severity: 'critical' });
    expect(out).toHaveLength(2);
  });

  it('filters by type', () => {
    const out = filterOrcaIncidents(FAKE_ROWS, { type: 'WEAPON' });
    expect(out.map((r) => r.id)).toEqual([
      '2026-11-08-operation-snowball',
      '2026-07-09-openai-agents-breach-huggingface',
      '2026-05-10-autonomous-post-exploitation',
    ]);
  });

  it('filters by realHarm true', () => {
    const out = filterOrcaIncidents(FAKE_ROWS, { realHarm: true });
    expect(out).toHaveLength(3);
    expect(out.every((r) => r.realHarm === true)).toBe(true);
  });

  it('filters realHarm null (policy/report records)', () => {
    const out = filterOrcaIncidents(FAKE_ROWS, { realHarm: null });
    expect(out).toHaveLength(1);
    expect(out[0]?.kind).toBe('policy');
  });

  it('filters by region and month', () => {
    expect(filterOrcaIncidents(FAKE_ROWS, { region: 'EU' }).map((r) => r.id)).toEqual([
      '2026-11-08-operation-snowball',
      '2026-02-01-some-policy-move',
    ]);
    expect(filterOrcaIncidents(FAKE_ROWS, { month: '2026-06' }).map((r) => r.id)).toEqual([
      '2026-06-01-meta-support-bot',
    ]);
  });

  it('filters landmark and disputed', () => {
    expect(filterOrcaIncidents(FAKE_ROWS, { landmark: true }).map((r) => r.id)).toEqual([
      '2026-07-09-openai-agents-breach-huggingface',
    ]);
    expect(filterOrcaIncidents(FAKE_ROWS, { disputed: true }).map((r) => r.id)).toEqual([
      '2026-11-08-operation-snowball',
    ]);
  });

  it('keyword-matches titles', () => {
    const out = filterOrcaIncidents(FAKE_ROWS, { keyword: 'meta ai' });
    expect(out.map((r) => r.id)).toEqual(['2026-06-01-meta-support-bot']);
  });

  it('respects limit', () => {
    expect(filterOrcaIncidents(FAKE_ROWS, { limit: 2 })).toHaveLength(2);
  });

  it('maps id → month shard', () => {
    expect(monthForId('2026-07-09-openai-agents-breach-huggingface')).toBe('2026-07');
    expect(monthForId('bad-id')).toBe('bad-id');
  });

  it('fetches a full incident body via its month shard', async () => {
    const body = await getOrcaIncident(
      mockAssets({ '/data/orca/incidents/2026-07.json': SHARD_2026_07 }),
      '2026-07-09-openai-agents-breach-huggingface'
    );
    expect(body).not.toBeNull();
    expect(body?.sources).toHaveLength(1);
    expect(body?.upstreamUrl).toContain('blob/main/incidents/2026-07');
  });

  it('returns null for an unknown incident', async () => {
    const body = await getOrcaIncident(
      mockAssets({ '/data/orca/incidents/2026-07.json': SHARD_2026_07 }),
      '2026-07-09-does-not-exist'
    );
    expect(body).toBeNull();
  });

  it('returns null for a malformed id without fetching', async () => {
    const body = await getOrcaIncident(mockAssets({}), 'not-a-date');
    expect(body).toBeNull();
  });

  it('loads stats', async () => {
    const stats = await loadOrcaStats(
      mockAssets({ '/data/orca/stats.json': { source: 'x', stats: FAKE_INDEX.stats } })
    );
    expect(stats?.count).toBe(5);
    expect(stats?.real_harm.true).toBe(3);
  });

  it('caches month shards', async () => {
    const assets = mockAssets({ '/data/orca/incidents/2026-07.json': SHARD_2026_07 });
    await getOrcaIncident(assets, '2026-07-09-openai-agents-breach-huggingface');
    await getOrcaIncident(assets, '2026-07-09-openai-agents-breach-huggingface');
    expect(orcaCacheStats().shardHits).toBe(1);
    expect(orcaCacheStats().shardMisses).toBe(1);
  });

  it('exposes the web page links from the index', async () => {
    const idx = await loadOrcaIndex(mockAssets({ '/data/orca/index.json': FAKE_INDEX }));
    expect(idx.webPages.offlineViewer).toContain('blob/main/index.html');
    expect(idx.lastCommitSha).toBe('a0d118c');
  });

  it('loads the recent commit activity feed', async () => {
    const assets = mockAssets({
      '/data/orca/commits.json': {
        source: 'github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
        sourceUrl: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive',
        commitsUrl: 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive/commits/main',
        license: 'CC BY 4.0',
        builtAt: '2026-11-16',
        count: 1,
        commits: FAKE_INDEX.recentCommits,
      },
    });
    const body = await loadOrcaCommits(assets);
    expect(body?.commits[0]?.sha).toBe('a0d118c');
    expect(body?.commitsUrl).toContain('/commits/main');
    await loadOrcaCommits(assets);
    expect(orcaCacheStats().bodies).toBe(1);
  });
});
