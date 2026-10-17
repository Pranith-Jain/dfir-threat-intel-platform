/**
 * Webamon campaign-intelligence client.
 *
 * Live client for the Webamon pro campaign-tracking API (pro.webamon.com),
 * the product behind the intel.webamon.com daily estate brief: tracked
 * phishing / malware-delivery campaigns, their 24h domain deltas, infrastructure
 * rotation, takedowns, and emerging fingerprint clusters.
 *
 * Auth: `x-api-key` header (the `WEBAMON_API_KEY` secret).
 *
 * Routes (2026-10): the campaign/changes/clusters endpoints moved under
 * `/v2` — `/v2/campaigns`, `/v2/campaigns/{id}`, `/v2/campaigns/{id}/domains`,
 * `/v2/campaigns/{id}/changes`, `/v2/campaigns/tags`, `/v2/changes`,
 * `/v2/clusters`. The bare paths still exist in the route table but now
 * reject API keys with `403 Forbidden` (they are Cognito-only), which made
 * every campaign call fail. The bare base is kept as a fallback so a key
 * that still maps to the legacy table keeps working.
 *
 * Modelled on the traceix/whoxy live-fetch modules (pure fetchers, no manifest):
 * every function returns `null` on a missing key or upstream failure so callers
 * degrade gracefully rather than throwing.
 */

import { errMessage } from './err';

const WEBAMON_PRO = 'https://pro.webamon.com';
/** v2 first — see the route note in the module header. */
const WEBAMON_PRO_BASES = [`${WEBAMON_PRO}/v2`, WEBAMON_PRO];
const TIMEOUT_MS = 20_000;
const UA = 'pranithjain-dfir/1.0';

export interface WebamonAuth {
  WEBAMON_API_KEY?: string;
}

/* ─── Types (mirror the upstream docs) ──────────────────────────────────── */

export type WebamonDim =
  | 'domains'
  | 'ips'
  | 'tlds'
  | 'countries'
  | 'asns'
  | 'tags'
  | 'servers'
  | 'technologies'
  | 'cert_issuers'
  | 'titles'
  | 'went_offline'
  | 'came_online';

export interface WebamonPagination {
  from: number;
  size: number;
  total: number;
  has_more: boolean;
  next_from: number | null;
  prev_from: number | null;
}

export interface WebamonCampaignCard {
  campaign_id: string;
  name: string;
  lucene_query: string;
  index: string;
  description?: string;
  tags?: string[];
  created_at: string;
  initial_run_at?: string;
  last_run_at?: string;
  run_count: number;
  scan_count_total: number;
  unique_domains_total: number;
  first_seen?: string;
  last_seen?: string;
  delta_24h?: number;
  recent_7d?: number;
  severity?: string;
  day_active?: number[];
}

export interface WebamonDomainRow {
  domain: string;
  count: number;
  first_seen: string;
  last_seen: string;
  online?: boolean;
  last_checked?: string;
  offline_since?: string;
}

export interface WebamonChangeEvent {
  campaign_id: string;
  campaign_name: string;
  run_at: string;
  window: string;
  is_baseline: boolean;
  has_changes: boolean;
  scan_count_window: number;
  totals: { scan_count_total: number; unique_domains_total: number };
  new_counts: Partial<Record<WebamonDim, number>>;
  changes?: Partial<Record<WebamonDim, string[]>>;
}

export type WebamonClusterSeverity = 'critical' | 'high' | 'watch';

export interface WebamonCluster {
  cluster_id: string;
  fingerprint_type: string;
  fingerprint: string;
  seed_query: string;
  severity: WebamonClusterSeverity;
  unique_domains: number;
  delta_24h: number;
  recent_7d: number;
  first_seen: string;
  last_seen: string;
  detected_at: string;
}

export interface WebamonListResponse<T> {
  index?: string;
  search_string?: string;
  lucene_query?: string;
  total_hits: number;
  results: T[];
  facets?: { tags?: Array<{ tag: string; count: number }> };
  pagination?: WebamonPagination;
}

export interface WebamonDomainsResponse {
  campaign_id: string;
  total: number;
  results: WebamonDomainRow[];
  pagination?: WebamonPagination;
}

export interface WebamonClustersResponse {
  index: string;
  total_hits: number;
  facets: { total: number; by_severity: Record<string, number>; by_type: Record<string, number> };
  sort?: string;
  order?: 'asc' | 'desc';
  results: WebamonCluster[];
  pagination?: WebamonPagination;
}

/* ─── Low-level fetch ───────────────────────────────────────────────────── */

type QueryParams = Record<string, string | number | boolean | undefined>;

async function webamonProFetch<T>(auth: WebamonAuth, path: string, params?: QueryParams): Promise<T | null> {
  const key = auth?.WEBAMON_API_KEY;
  if (!key) return null;

  for (const base of WEBAMON_PRO_BASES) {
    const url = new URL(`${base}${path}`);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
      }
    }

    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const res = await fetch(url.toString(), {
          signal: AbortSignal.timeout(TIMEOUT_MS),
          headers: { accept: 'application/json', 'user-agent': UA, 'x-api-key': key },
        });
        if (res.ok) return (await res.json()) as T;
        // Auth rejection on this base — the other base may still be mapped
        // for this key, so move on instead of giving up.
        if (res.status === 401 || res.status === 403) break;
        // 4xx (other than 429) is a client/auth error — retrying won't help.
        if (res.status !== 429 && res.status >= 400 && res.status < 500) return null;
      } catch (err) {
        console.error('webamonProFetch failed:', errMessage(err));
      }
      if (attempt < 2) await new Promise((r) => setTimeout(r, 800 * attempt));
    }
  }
  return null;
}

/* ─── High-level methods ────────────────────────────────────────────────── */

export function listCampaigns(
  auth: WebamonAuth,
  opts: { tag?: string; search?: string; size?: number; from?: number; sortBy?: string; order?: string } = {}
): Promise<WebamonListResponse<WebamonCampaignCard> | null> {
  return webamonProFetch<WebamonListResponse<WebamonCampaignCard>>(auth, '/campaigns', {
    tag: opts.tag,
    search: opts.search,
    size: Math.min(opts.size ?? 25, 100),
    from: opts.from && opts.from > 0 ? opts.from : undefined,
    // `sort_order`, not `order` — matches what the upstream console sends.
    sort_by: opts.sortBy ?? 'delta_24h',
    sort_order: opts.order ?? 'desc',
  });
}

export function getCampaign(auth: WebamonAuth, campaignId: string): Promise<WebamonCampaignCard | null> {
  return webamonProFetch<WebamonCampaignCard>(auth, `/campaigns/${encodeURIComponent(campaignId)}`);
}

export function getCampaignStats(auth: WebamonAuth, campaignId?: string): Promise<Record<string, unknown> | null> {
  const path = campaignId ? `/campaigns/${encodeURIComponent(campaignId)}/stats` : '/campaigns/stats';
  return webamonProFetch<Record<string, unknown>>(auth, path);
}

export function listCampaignDomains(
  auth: WebamonAuth,
  campaignId: string,
  opts: { size?: number; from?: number } = {}
): Promise<WebamonDomainsResponse | null> {
  return webamonProFetch<WebamonDomainsResponse>(auth, `/campaigns/${encodeURIComponent(campaignId)}/domains`, {
    size: opts.size ?? 500,
    from: opts.from && opts.from > 0 ? opts.from : undefined,
  });
}

export function listCampaignTags(
  auth: WebamonAuth,
  opts: { q?: string; tag?: string } = {}
): Promise<Record<string, unknown> | null> {
  return webamonProFetch<Record<string, unknown>>(auth, '/campaigns/tags', { q: opts.q, tag: opts.tag });
}

export function listChanges(
  auth: WebamonAuth,
  opts: {
    since?: string;
    campaignId?: string;
    dim?: WebamonDim;
    hasChanges?: boolean;
    size?: number;
    from?: number;
  } = {}
): Promise<WebamonListResponse<WebamonChangeEvent> | null> {
  return webamonProFetch<WebamonListResponse<WebamonChangeEvent>>(auth, '/changes', {
    since: opts.since,
    campaign_id: opts.campaignId,
    dim: opts.dim,
    has_changes: opts.hasChanges,
    size: opts.size ?? 100,
    from: opts.from && opts.from > 0 ? opts.from : undefined,
  });
}

export function listClusters(
  auth: WebamonAuth,
  opts: { severity?: WebamonClusterSeverity; fingerprintType?: string; size?: number; from?: number } = {}
): Promise<WebamonClustersResponse | null> {
  return webamonProFetch<WebamonClustersResponse>(auth, '/clusters', {
    severity: opts.severity,
    fingerprint_type: opts.fingerprintType,
    size: opts.size ?? 50,
    from: opts.from && opts.from > 0 ? opts.from : undefined,
  });
}

/* ─── Aggregated digest ─────────────────────────────────────────────────── */

export interface WebamonCampaignIntelTotals {
  campaigns_with_activity: number;
  new_domains: number;
  went_offline: number;
  came_online: number;
  infra_changes: number;
  new_titles: number;
}

export interface WebamonCampaignIntel {
  generated_at: string;
  ok: boolean;
  since: string;
  stats: Record<string, unknown> | null;
  top_campaigns: WebamonCampaignCard[];
  changes: WebamonChangeEvent[];
  clusters: {
    total: number;
    by_severity: Record<string, number>;
    top: WebamonCluster[];
  };
  totals: WebamonCampaignIntelTotals;
}

const sumDim = (events: WebamonChangeEvent[], dim: WebamonDim): number =>
  events.reduce((n, e) => n + (e.new_counts?.[dim] ?? 0), 0);

/**
 * One-shot aggregated digest: global stats + top campaigns by 24h delta + the
 * change events within the window + emerging clusters, rolled up into the same
 * "by the numbers" totals the intel.webamon.com daily brief leads with. Used by
 * the REST route, the Global Pulse warmer, and the briefing collector.
 */
export async function getCampaignIntel(
  auth: WebamonAuth,
  opts: { since?: string; topCampaigns?: number; topClusters?: number } = {}
): Promise<WebamonCampaignIntel> {
  const since = opts.since ?? new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const [stats, campaigns, changes, clusters] = await Promise.all([
    getCampaignStats(auth),
    listCampaigns(auth, { size: opts.topCampaigns ?? 25, sortBy: 'delta_24h', order: 'desc' }),
    listChanges(auth, { since, hasChanges: true, size: 100 }),
    listClusters(auth, { size: opts.topClusters ?? 25 }),
  ]);

  const changeEvents = changes?.results ?? [];
  const activeCampaignIds = new Set(changeEvents.map((e) => e.campaign_id));
  const totals: WebamonCampaignIntelTotals = {
    campaigns_with_activity: activeCampaignIds.size,
    new_domains: sumDim(changeEvents, 'domains'),
    went_offline: sumDim(changeEvents, 'went_offline'),
    came_online: sumDim(changeEvents, 'came_online'),
    infra_changes:
      sumDim(changeEvents, 'ips') +
      sumDim(changeEvents, 'asns') +
      sumDim(changeEvents, 'cert_issuers') +
      sumDim(changeEvents, 'servers'),
    new_titles: sumDim(changeEvents, 'titles'),
  };

  const ok = Boolean(stats || campaigns || changes || clusters);
  return {
    generated_at: new Date().toISOString(),
    ok,
    since,
    stats,
    top_campaigns: campaigns?.results ?? [],
    changes: changeEvents,
    clusters: {
      total: clusters?.facets?.total ?? clusters?.total_hits ?? 0,
      by_severity: clusters?.facets?.by_severity ?? {},
      top: clusters?.results ?? [],
    },
    totals,
  };
}
