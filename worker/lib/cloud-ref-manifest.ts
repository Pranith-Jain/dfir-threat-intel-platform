/**
 * Cloud Security Reference manifest loader.
 *
 * Reads the static cloud reference manifest shipped in /public/data/cloud-ref/
 * (shared responsibility matrix across AWS/Azure/GCP × IaaS/PaaS/SaaS + 40
 * cloud hunt queries) through the env.ASSETS binding — no D1, no KV, no
 * public fetch.
 *
 * Shape:
 *   /data/cloud-ref/index.json        (SRM full + query index)
 *   /data/cloud-ref/queries/<id>.json (full hunt query)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export interface CloudSrmDomainCell {
  aws: string;
  azure: string;
  gcp: string;
}

export interface CloudSrmDomain {
  id: string;
  name: string;
  description: string;
  iaas: CloudSrmDomainCell;
  paas: CloudSrmDomainCell;
  saas: CloudSrmDomainCell;
}

export interface CloudQueryIndexEntry {
  id: string;
  name: string;
  provider: string;
  mitre?: string | null;
}

export interface CloudRefIndex {
  metadata: { description: string; totalDomains: number; totalQueries: number };
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: { domains: number; queries: number; providers: number };
  providerCounts: Record<string, number>;
  srm: { title: string; description: string; stakeholders?: string[]; domains: CloudSrmDomain[] };
  queryIndex: CloudQueryIndexEntry[];
}

export interface CloudHuntQueryBody {
  id: string;
  name: string;
  provider: 'AWS' | 'Azure' | 'GCP' | 'K8s';
  service?: string;
  description: string;
  mitre?: string | null;
  query: string;
  params?: string[];
  falsePositives?: string;
  tags: string[];
}

const DATA_PREFIX = '/data/cloud-ref';
const MAX_BODY_CACHE = 80;

const queryCache: BodyCache<CloudHuntQueryBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: CloudRefIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://cloudref.local');
}

export async function loadCloudRefIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<CloudRefIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<CloudRefIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Cloud Ref index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-cloud-ref.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getCloudHuntQuery(assets: Fetcher, id: string): Promise<CloudHuntQueryBody | null> {
  const hit = trackHit(queryCache, id);
  if (hit) return hit;
  const body = await fetchJson<CloudHuntQueryBody>(assets, `${DATA_PREFIX}/queries/${id}.json`);
  if (!body) return null;
  return recordHit(queryCache, id, body, MAX_BODY_CACHE);
}

export interface CloudQueryListOptions {
  provider?: string;
  mitre?: string;
  keyword?: string;
  limit?: number;
}

export function filterCloudQueries(idx: CloudRefIndex, opts: CloudQueryListOptions = {}): CloudQueryIndexEntry[] {
  const { provider, mitre, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: CloudQueryIndexEntry[] = [];
  for (const q of idx.queryIndex) {
    if (provider && q.provider.toLowerCase() !== provider.toLowerCase()) continue;
    if (mitre && q.mitre !== mitre) continue;
    if (needle) {
      const hay = `${q.id} ${q.name} ${q.provider}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(q);
    if (out.length >= limit) break;
  }
  return out;
}

export function cloudRefCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  queries: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    queries: { size: queryCache.map.size, hits: queryCache.hits, misses: queryCache.misses },
  };
}

export function _resetCloudRefCacheForTests(): void {
  queryCache.map.clear();
  queryCache.hits = queryCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
