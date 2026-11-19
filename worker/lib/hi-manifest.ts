/**
 * Hacking Incidents ledger manifest — sourced cyberattacks where AI use is
 * stated or credibly suspected (hackingincidents.ai).
 *
 * Edge loader for the replicated /incidents.json export (286 published
 * reports, Jan 2023 → Nov 2026). Grading is the backbone: `confidence`
 * (confirmed / strong / suspected), `autonomy` (assist / semi-autonomous /
 * autonomous) and the enrichment block (models, harness, countries, sectors).
 *
 * Data source: public/data/hi/ (built by scripts/build-hi-manifest.mjs), read
 * through env.ASSETS — no D1, no KV, no public fetch. Month shards keep the
 * index slim; the id → shard mapping comes from the slim index.
 *
 * Upstream publishes no reuse licence: only structured metadata and short
 * factual summaries are stored, and every record deep-links its incident page
 * and primary sources.
 */

export type HiConfidence = 'confirmed' | 'strong' | 'suspected';
export type HiAutonomy = 'assist' | 'semi-autonomous' | 'autonomous';

export interface HiSource {
  title: string | null;
  publisher: string | null;
  url: string;
  date: string | null;
  verifiedOn: string | null;
  primary: boolean;
  quoteFound: boolean;
}

export interface HiIncidentSlim {
  id: string;
  title: string;
  date: string;
  year: string;
  month: string;
  actor: string | null;
  actorType: string | null;
  nexus: string | null;
  targets: string | null;
  aiRole: string[];
  models: string[];
  modelBasis: string | null;
  autonomy: string | null;
  confidence: string;
  sourceCount: number;
  primarySourceCount: number;
  modelNamed: boolean;
  harnessUsed: boolean;
  harnessNames: string[];
  countries: string[];
  sectors: string[];
}

export interface HiIncidentBody extends HiIncidentSlim {
  outcome: string | null;
  confidenceReason: string | null;
  summary: string;
  quote: string | null;
  singleSourceReason: string | null;
  disclosed: unknown;
  activity: unknown;
  enrichment: unknown;
  sources: HiSource[];
  upstreamUrl: string;
}

export interface HiStats {
  count: number;
  months: Record<string, number>;
  byYear: Record<string, number>;
  byConfidence: Record<string, number>;
  byAutonomy: Record<string, number>;
  byActorType: Record<string, number>;
  byRole: Record<string, number>;
  byCountry: Record<string, number>;
  bySector: Record<string, number>;
  sources: { links: number; primary: number; uniqueUrls: number };
  namedModels: number;
  harnessUse: number;
}

export interface HiIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  upstreamUpdated: string | null;
  counts: {
    records: number;
    months: number;
    confirmed: number;
    strong: number;
    suspected: number;
    namedModels: number;
    harnessUse: number;
    sourceLinks: number;
  };
  stats: HiStats;
  months: string[];
  incidents: HiIncidentSlim[];
  webPages: Record<string, string>;
}

const DATA_PREFIX = '/data/hi';
let cachedIndex: HiIndex | null = null;
let indexHits = 0;
let indexMisses = 0;
const shardCache = new Map<string, HiIncidentBody[]>();
let shardHits = 0;
let shardMisses = 0;
const SHARD_CACHE_MAX = 30;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://hi.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

function shardGet(key: string): HiIncidentBody[] | null {
  const v = shardCache.get(key);
  if (v === undefined) {
    shardMisses++;
    return null;
  }
  shardHits++;
  shardCache.delete(key);
  shardCache.set(key, v);
  return v;
}

function shardSet(key: string, value: HiIncidentBody[]): void {
  shardCache.delete(key);
  shardCache.set(key, value);
  while (shardCache.size > SHARD_CACHE_MAX) {
    const oldest = shardCache.keys().next();
    if (oldest.done) break;
    shardCache.delete(oldest.value);
  }
}

export async function loadHiIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<HiIndex> {
  if (cachedIndex && !opts.forceRefresh) {
    indexHits++;
    return cachedIndex;
  }
  indexMisses++;
  const idx = await fetchJson<HiIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Hacking Incidents index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-hi-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  return idx;
}

export interface HiFilterOptions {
  confidence?: string;
  autonomy?: string;
  role?: string;
  year?: string;
  month?: string;
  actorType?: string;
  country?: string;
  sector?: string;
  model?: string;
  harness?: boolean;
  keyword?: string;
  limit?: number;
}

/** Filter + sort slim rows; newest first, matching the upstream ledger. */
export function filterHiIncidents(rows: HiIncidentSlim[], opts: HiFilterOptions = {}): HiIncidentSlim[] {
  const {
    confidence,
    autonomy,
    role,
    year,
    month,
    actorType,
    country,
    sector,
    model,
    harness,
    keyword,
    limit = 100,
  } = opts;
  const needle = keyword?.toLowerCase();
  const out: HiIncidentSlim[] = [];
  for (const r of rows) {
    if (confidence && r.confidence !== confidence.toLowerCase()) continue;
    if (autonomy && String(r.autonomy).toLowerCase() !== autonomy.toLowerCase()) continue;
    if (role && !r.aiRole.some((t) => t.toLowerCase() === role.toLowerCase())) continue;
    if (year && r.year !== year) continue;
    if (month && r.month !== month) continue;
    if (actorType && String(r.actorType).toLowerCase() !== actorType.toLowerCase()) continue;
    if (country && !r.countries.some((c) => c.toLowerCase() === country.toLowerCase())) continue;
    if (sector && !r.sectors.some((c) => c.toLowerCase() === sector.toLowerCase())) continue;
    if (model && !r.models.some((m) => m.toLowerCase() === model.toLowerCase())) continue;
    if (harness === true && !r.harnessUsed) continue;
    if (harness === false && r.harnessUsed) continue;
    if (needle) {
      const hay =
        `${r.title} ${r.actor ?? ''} ${r.targets ?? ''} ${r.aiRole.join(' ')} ${r.models.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getHiIncident(assets: Fetcher, id: string): Promise<HiIncidentBody | null> {
  const idx = await loadHiIndex(assets);
  const row = idx.incidents.find((r) => r.id === id);
  if (!row) return null;
  const key = `shard:${row.month}`;
  let shard = shardGet(key);
  if (!shard) {
    const data = await fetchJson<{ incidents: HiIncidentBody[] }>(assets, `${DATA_PREFIX}/incidents/${row.month}.json`);
    if (!data?.incidents) return null;
    shard = data.incidents;
    shardSet(key, shard);
  }
  return shard.find((r) => r.id === id) ?? null;
}

export async function loadHiStats(assets: Fetcher): Promise<HiStats | null> {
  const data = await fetchJson<{ stats: HiStats }>(assets, `${DATA_PREFIX}/stats.json`);
  return data?.stats ?? null;
}

/** Test-only: drop all cached state so consecutive cases stay independent. */
export function _resetHiCacheForTests(): void {
  cachedIndex = null;
  shardCache.clear();
  indexHits = indexMisses = shardHits = shardMisses = 0;
}

export function hiCacheStats(): {
  index: { hits: number; misses: number };
  shards: { hits: number; misses: number; entries: number };
} {
  return {
    index: { hits: indexHits, misses: indexMisses },
    shards: { hits: shardHits, misses: shardMisses, entries: shardCache.size },
  };
}
