import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  listCampaigns,
  listChanges,
  listClusters,
  getCampaignIntel,
  type WebamonChangeEvent,
} from './webamon-campaigns';

const env = { WEBAMON_API_KEY: 'fake-key' };

beforeEach(() => vi.restoreAllMocks());

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe('listCampaigns', () => {
  it('returns null when the API key is missing (no fetch)', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    const r = await listCampaigns({});
    expect(r).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it('builds the pro.webamon.com/v2 request with x-api-key + sort params', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      json({ total_hits: 1, results: [{ campaign_id: 'c1', name: 'Kit A', unique_domains_total: 10 }] })
    );
    const r = await listCampaigns(env, { size: 25, sortBy: 'delta_24h', order: 'desc' });
    expect(r?.results).toHaveLength(1);
    expect(r?.results[0]!.campaign_id).toBe('c1');
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0]!;
    const u = String(url);
    expect(u).toContain('https://pro.webamon.com/v2/campaigns?');
    expect(u).toContain('size=25');
    expect(u).toContain('sort_by=delta_24h');
    expect(u).toContain('sort_order=desc');
    expect((init as RequestInit).headers).toMatchObject({ 'x-api-key': 'fake-key' });
  });

  it('falls back to the legacy bare path when /v2 rejects the key', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ message: 'Unauthorized' }, 401))
      .mockResolvedValueOnce(json({ total_hits: 1, results: [{ campaign_id: 'c9' }] }));
    const r = await listCampaigns(env);
    expect(r?.results[0]!.campaign_id).toBe('c9');
    const urls = vi.mocked(globalThis.fetch).mock.calls.map((c) => String(c[0]));
    expect(urls[0]).toContain('https://pro.webamon.com/v2/campaigns');
    expect(urls[1]).toBe('https://pro.webamon.com/campaigns?size=25&sort_by=delta_24h&sort_order=desc');
  });

  it('returns null when every base rejects the key', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ message: 'Forbidden' }, 403));
    const r = await listCampaigns(env);
    expect(r).toBeNull();
    // One attempt per base — no retry loop on an auth rejection.
    expect(spy).toHaveBeenCalledTimes(2);
  });
});

describe('listChanges / listClusters params', () => {
  it('forwards since + campaign_id to /changes', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ total_hits: 0, results: [] }));
    await listChanges(env, { since: '2026-07-28T00:00:00.000Z', campaignId: 'c1', hasChanges: true });
    const u = String(vi.mocked(globalThis.fetch).mock.calls[0]![0]);
    expect(u).toContain('/changes?');
    expect(u).toContain('campaign_id=c1');
    expect(u).toContain('has_changes=true');
    expect(u).toContain('since=2026-07-28');
  });

  it('parses cluster facets', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      json({
        index: 'emerging_clusters',
        total_hits: 2,
        facets: { total: 136, by_severity: { critical: 33, high: 102 }, by_type: {} },
        results: [{ cluster_id: 'ssl:abc', severity: 'critical', unique_domains: 9312, delta_24h: 82 }],
      })
    );
    const r = await listClusters(env, { severity: 'critical' });
    expect(r?.facets.by_severity.critical).toBe(33);
    expect(r?.results[0]!.unique_domains).toBe(9312);
    expect(String(vi.mocked(globalThis.fetch).mock.calls[0]![0])).toContain('severity=critical');
  });
});

describe('getCampaignIntel aggregation', () => {
  const changes: WebamonChangeEvent[] = [
    {
      campaign_id: 'c1',
      campaign_name: 'Gambling kit',
      run_at: '2026-07-29T00:00:00.000Z',
      window: 'last 24h',
      is_baseline: false,
      has_changes: true,
      scan_count_window: 100,
      totals: { scan_count_total: 1000, unique_domains_total: 500 },
      new_counts: { domains: 467, went_offline: 10, ips: 57, asns: 4, cert_issuers: 2, servers: 1, titles: 727 },
    },
    {
      campaign_id: 'c2',
      campaign_name: 'ClickFix',
      run_at: '2026-07-29T00:00:00.000Z',
      window: 'last 24h',
      is_baseline: false,
      has_changes: true,
      scan_count_window: 30,
      totals: { scan_count_total: 174, unique_domains_total: 174 },
      new_counts: { domains: 3, went_offline: 0, ips: 18, asns: 4, titles: 0 },
    },
  ];

  function mockIntel() {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const u = String(input);
      if (u.includes('/campaigns/stats')) return json({ campaigns: 63, online_pct: 83.2 });
      if (u.includes('/clusters'))
        return json({
          index: 'emerging_clusters',
          total_hits: 1,
          facets: { total: 136, by_severity: { critical: 33, high: 102 }, by_type: {} },
          results: [{ cluster_id: 'ssl:x', severity: 'critical', unique_domains: 9312, delta_24h: 82 }],
        });
      if (u.includes('/changes')) return json({ total_hits: 2, results: changes });
      if (u.includes('/campaigns'))
        return json({
          total_hits: 2,
          results: [
            { campaign_id: 'c1', name: 'Gambling kit', delta_24h: 467, unique_domains_total: 30571 },
            { campaign_id: 'c2', name: 'ClickFix', delta_24h: 3, unique_domains_total: 174 },
          ],
        });
      return json({ message: 'not found' }, 404);
    });
  }

  it('rolls up the daily-digest totals from change events', async () => {
    mockIntel();
    const intel = await getCampaignIntel(env);
    expect(intel.ok).toBe(true);
    expect(intel.totals.campaigns_with_activity).toBe(2);
    expect(intel.totals.new_domains).toBe(470);
    expect(intel.totals.went_offline).toBe(10);
    // infra = ips(57+18) + asns(4+4) + cert_issuers(2) + servers(1) = 86
    expect(intel.totals.infra_changes).toBe(86);
    expect(intel.totals.new_titles).toBe(727);
  });

  it('surfaces stats, top campaigns, and cluster facets', async () => {
    mockIntel();
    const intel = await getCampaignIntel(env);
    expect(intel.stats).toMatchObject({ campaigns: 63 });
    expect(intel.top_campaigns).toHaveLength(2);
    expect(intel.top_campaigns[0]!.campaign_id).toBe('c1');
    expect(intel.clusters.total).toBe(136);
    expect(intel.clusters.by_severity.critical).toBe(33);
    expect(intel.clusters.top[0]!.unique_domains).toBe(9312);
  });

  it('flags ok:false when every upstream fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ message: 'Forbidden' }, 403));
    const intel = await getCampaignIntel(env);
    expect(intel.ok).toBe(false);
    expect(intel.top_campaigns).toHaveLength(0);
    expect(intel.totals.new_domains).toBe(0);
  });
});
