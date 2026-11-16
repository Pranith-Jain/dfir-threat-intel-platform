/**
 * ORCA AI Incident Archive manifest — open database of real-world AI agent
 * security incidents.
 *
 * Edge loader for the replicated export of
 * github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive (CC BY 4.0):
 * 417 records (2024-12 → 2026-11), each an upstream Markdown record with a
 * YAML header and at least one clickable primary source. Three fields
 * structure everything: `kind` (incident / vulnerability / research /
 * report / policy), `real_harm` (confirmed victim vs. research demo) and
 * `ai_involvement` (confirmed / unverified / disputed / not-applicable).
 *
 * Data source: public/data/orca/ (built by scripts/build-orca-manifest.mjs),
 * read through env.ASSETS — no D1, no KV, no public fetch. Month shards keep
 * the index slim; lookups resolve the shard from the record id's date prefix
 * (`YYYY-MM-DD-…` → `YYYY-MM`).
 */

export type OrcaKind = 'incident' | 'vulnerability' | 'research' | 'report' | 'policy';
export type OrcaSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type OrcaConfidence = 'A' | 'B' | 'C' | 'D';
export type OrcaAiInvolvement = 'confirmed' | 'unverified' | 'disputed' | 'not-applicable';

export interface OrcaSource {
  url: string;
  label: string;
}

export interface OrcaIncidentSlim {
  id: string;
  title: string;
  date: string;
  dateEnd: string | null;
  month: string;
  kind: string;
  types: string[];
  severity: string;
  confidence: string;
  realHarm: boolean | null;
  aiInvolvement: string;
  regions: string[];
  landmark: boolean;
  disputed: boolean;
  sourceCount: number;
}

export interface OrcaIncidentBody extends OrcaIncidentSlim {
  datePrecision: string;
  dateRaw: string | null;
  summary: string;
  sources: OrcaSource[];
  upstreamPath: string | null;
  upstreamUrl: string;
}

export interface OrcaStats {
  version: string;
  count: number;
  months: Record<string, number>;
  by_severity: Record<string, number>;
  by_kind: Record<string, number>;
  by_type: Record<string, number>;
  by_confidence: Record<string, number>;
  by_region: Record<string, number>;
  real_harm: { true: number; false: number; null: number };
  ai_involvement: Record<string, number>;
  sources: { links: number; unique_urls: number };
}

export interface OrcaIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  upstreamVersion: string;
  upstreamSchema: number | string | null;
  languages: string[];
  counts: {
    records: number;
    months: number;
    realHarm: number;
    critical: number;
    incidents: number;
    disputed: number;
    landmark: number;
    sources: number | null;
  };
  stats: OrcaStats;
  months: string[];
  incidents: OrcaIncidentSlim[];
}

const DATA_PREFIX = '/data/orca';

let cachedIndex: OrcaIndex | null = null;
let cachedIndexAt: number | null = null;
const shardCache = new Map<string, OrcaIncidentBody[]>();
let bodyHits = 0;
let bodyMisses = 0;
const SHARD_CACHE_MAX = 30;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://orca.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

function shardGet(key: string): OrcaIncidentBody[] | null {
  const v = shardCache.get(key);
  if (v === undefined) {
    bodyMisses++;
    return null;
  }
  bodyHits++;
  // LRU refresh.
  shardCache.delete(key);
  shardCache.set(key, v);
  return v;
}

function shardSet(key: string, value: OrcaIncidentBody[]): void {
  if (shardCache.has(key)) shardCache.delete(key);
  shardCache.set(key, value);
  while (shardCache.size > SHARD_CACHE_MAX) {
    const oldest = shardCache.keys().next();
    if (oldest.done) break;
    shardCache.delete(oldest.value);
  }
}

export async function loadOrcaIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<OrcaIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<OrcaIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `ORCA index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-orca-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export interface OrcaFilterOptions {
  kind?: string;
  severity?: string;
  type?: string;
  realHarm?: boolean | null;
  aiInvolvement?: string;
  region?: string;
  month?: string;
  landmark?: boolean;
  disputed?: boolean;
  keyword?: string;
  limit?: number;
}

/** Filter + sort slim rows. Newest first by date (matches the upstream index order). */
export function filterOrcaIncidents(rows: OrcaIncidentSlim[], opts: OrcaFilterOptions = {}): OrcaIncidentSlim[] {
  const {
    kind,
    severity,
    type,
    realHarm,
    aiInvolvement,
    region,
    month,
    landmark,
    disputed,
    keyword,
    limit = 100,
  } = opts;
  const needle = keyword?.toLowerCase();
  const out: OrcaIncidentSlim[] = [];
  for (const r of rows) {
    if (kind && r.kind.toLowerCase() !== kind.toLowerCase()) continue;
    if (severity && r.severity.toLowerCase() !== severity.toLowerCase()) continue;
    if (type && !r.types.some((t) => t.toLowerCase() === type.toLowerCase())) continue;
    if (realHarm !== undefined && realHarm !== null && r.realHarm !== realHarm) continue;
    if (realHarm === null && r.realHarm !== null) continue;
    if (aiInvolvement && r.aiInvolvement.toLowerCase() !== aiInvolvement.toLowerCase()) continue;
    if (region && !r.regions.some((g) => g.toLowerCase() === region.toLowerCase())) continue;
    if (month && r.month !== month) continue;
    if (landmark !== undefined && r.landmark !== landmark) continue;
    if (disputed !== undefined && r.disputed !== disputed) continue;
    if (needle) {
      const hay = `${r.title} ${r.types.join(' ')} ${r.regions.join(' ')} ${r.kind} ${r.severity}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

/** The id's date prefix maps 1:1 onto the month shard (`2026-07-09-…` → `2026-07`). */
export function monthForId(id: string): string {
  return id.slice(0, 7);
}

export async function getOrcaIncident(assets: Fetcher, id: string): Promise<OrcaIncidentBody | null> {
  const month = monthForId(id);
  if (!/^\d{4}-\d{2}$/.test(month)) return null;
  const key = `shard:${month}`;
  let shard = shardGet(key);
  if (!shard) {
    const data = await fetchJson<{ incidents: OrcaIncidentBody[] }>(assets, `${DATA_PREFIX}/incidents/${month}.json`);
    if (!data?.incidents) return null;
    shard = data.incidents;
    shardSet(key, shard);
  }
  return shard.find((r) => r.id === id) ?? null;
}

export async function loadOrcaStats(assets: Fetcher): Promise<OrcaStats | null> {
  const data = await fetchJson<{ stats: OrcaStats }>(assets, `${DATA_PREFIX}/stats.json`);
  return data?.stats ?? null;
}

export function orcaCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  shards: number;
  shardHits: number;
  shardMisses: number;
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    shards: shardCache.size,
    shardHits: bodyHits,
    shardMisses: bodyMisses,
  };
}

export function _resetOrcaCacheForTests(): void {
  cachedIndex = null;
  cachedIndexAt = null;
  shardCache.clear();
  bodyHits = 0;
  bodyMisses = 0;
}
