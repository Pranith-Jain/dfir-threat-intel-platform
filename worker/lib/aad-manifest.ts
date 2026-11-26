/**
 * Agentic Attack Detections manifest — detection coverage for AI-agent attack
 * frameworks, sourced indicators and ATT&CK mapping.
 *
 * Edge loader for the replication of github.com/ThreatDefence/agentic-attack-
 * detections (MIT), built by scripts/build-aad-manifest.mjs into
 * public/data/aad/. Read through env.ASSETS — no D1, no KV, no public fetch.
 *
 * The slim index carries framework cards; full bodies (coverage counts,
 * ATT&CK techniques, sourced indicators) live in per-framework shards and
 * indicator shards are keyed by IOC type.
 */

export interface AadCounts {
  kqlHunts: number;
  analytics: number;
  sigma: number;
  suricata: number;
  yara: number;
  indicators: number;
}

export interface AadFrameworkSlim {
  slug: string;
  name: string;
  description: string;
  seenIn: string;
  counts: AadCounts;
  techniqueCount: number;
}

export interface AadIndicator {
  value: string;
  confidence: string;
  context: string;
  actor: string;
  source: string;
  sourceUrl: string;
  reported: string;
  /** Primary framework (display) — the first of `frameworks` for shared IOCs. */
  framework: string;
  /** All frameworks this indicator is attributed to (CSV cells can list several). */
  frameworks: string[];
  type?: string;
}

export interface AadTechnique {
  id: string;
  score: number;
  comment: string;
}

export interface AadFrameworkBody extends AadFrameworkSlim {
  techniques: AadTechnique[];
  indicators: AadIndicator[];
  indicatorsTruncated: boolean;
  upstreamUrl: string;
  source: string;
  license: string;
}

export interface AadSharedRule {
  path: string;
  kind: string;
  name: string;
}

export interface AadIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  license: string;
  description: string;
  stats: {
    frameworks: number;
    indicators: number;
    indicatorTypes: number;
    attackTechniques: number;
    behaviorRules: number;
    generalRules: number;
  };
  indicatorTypes: Array<{ type: string; count: number }>;
  frameworks: AadFrameworkSlim[];
  shared: {
    behaviors: { count: number; rules: AadSharedRule[] };
    general: { count: number; rules: AadSharedRule[] };
  };
}

export interface AadIndicatorShard {
  type: string;
  count: number;
  items: AadIndicator[];
}

export interface AadAttackLayer {
  source: string;
  sourceUrl: string;
  description: string;
  maxValue: number;
  techniques: AadTechnique[];
}

const DATA_PREFIX = '/data/aad';

let cachedIndex: AadIndex | null = null;
let cachedIndexAt: number | null = null;
const bodyCache = new Map<string, AadFrameworkBody>();
const indicatorCache = new Map<string, AadIndicatorShard>();
let cachedAttack: AadAttackLayer | null = null;
let cacheHits = 0;
let cacheMisses = 0;
const BODY_CACHE_MAX = 80;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://aad.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

function cachedGet<T>(map: Map<string, T>, key: string): T | null {
  const v = map.get(key);
  if (v === undefined) {
    cacheMisses++;
    return null;
  }
  cacheHits++;
  map.delete(key);
  map.set(key, v);
  return v;
}

function cachedSet<T>(map: Map<string, T>, key: string, value: T, max: number): void {
  if (map.has(key)) map.delete(key);
  map.set(key, value);
  while (map.size > max) {
    const oldest = map.keys().next();
    if (oldest.done) break;
    map.delete(oldest.value);
  }
}

export async function loadAadIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<AadIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<AadIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Agentic Attack Detections index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-aad-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export interface AadFrameworkFilter {
  keyword?: string;
  minIndicators?: number;
  minRules?: number;
  limit?: number;
}

export function filterAadFrameworks(rows: AadFrameworkSlim[], opts: AadFrameworkFilter = {}): AadFrameworkSlim[] {
  const { keyword, minIndicators, minRules, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: AadFrameworkSlim[] = [];
  for (const r of rows) {
    if (needle && !`${r.name} ${r.slug} ${r.description} ${r.seenIn}`.toLowerCase().includes(needle)) continue;
    if (minIndicators !== undefined && r.counts.indicators < minIndicators) continue;
    if (minRules !== undefined && r.counts.kqlHunts + r.counts.sigma + r.counts.suricata + r.counts.yara < minRules)
      continue;
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getAadFramework(assets: Fetcher, slug: string): Promise<AadFrameworkBody | null> {
  if (!/^[a-z0-9-]+$/.test(slug)) return null;
  const key = `framework:${slug}`;
  const hit = cachedGet(bodyCache, key);
  if (hit) return hit;
  const body = await fetchJson<AadFrameworkBody>(assets, `${DATA_PREFIX}/frameworks/${slug}.json`);
  if (!body) return null;
  cachedSet(bodyCache, key, body, BODY_CACHE_MAX);
  return body;
}

export interface AadIndicatorFilter {
  type?: string;
  framework?: string;
  keyword?: string;
  limit?: number;
}

/** Indicator shards are keyed by type; loading all of them is bounded by the
 * 16 upstream IOC types and cached per isolate. */
export async function filterAadIndicators(assets: Fetcher, opts: AadIndicatorFilter = {}): Promise<AadIndicator[]> {
  const { type, framework, keyword, limit = 100 } = opts;
  const idx = await loadAadIndex(assets);
  const types = type
    ? idx.indicatorTypes.filter((t) => t.type.toLowerCase() === type.toLowerCase()).map((t) => t.type)
    : idx.indicatorTypes.map((t) => t.type);
  const needle = keyword?.toLowerCase();
  const out: AadIndicator[] = [];
  for (const t of types) {
    const key = `indicator:${t}`;
    let shard = cachedGet(indicatorCache, key);
    if (!shard) {
      shard = await fetchJson<AadIndicatorShard>(assets, `${DATA_PREFIX}/indicators/${t}.json`);
      if (!shard) continue;
      cachedSet(indicatorCache, key, shard, 32);
    }
    for (const item of shard.items) {
      const owners = item.frameworks?.length ? item.frameworks : [item.framework];
      if (framework && !owners.some((f) => f.toLowerCase() === framework.toLowerCase())) continue;
      if (needle && !`${item.value} ${item.context} ${item.source}`.toLowerCase().includes(needle)) continue;
      out.push({ ...item, type: shard.type });
      if (out.length >= limit) return out;
    }
  }
  return out;
}

export async function loadAadAttack(assets: Fetcher): Promise<AadAttackLayer | null> {
  if (cachedAttack) {
    cacheHits++;
    return cachedAttack;
  }
  cacheMisses++;
  cachedAttack = await fetchJson<AadAttackLayer>(assets, `${DATA_PREFIX}/attack.json`);
  return cachedAttack;
}

export function aadCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodies: number;
  indicatorShards: number;
  attackLoaded: boolean;
  hits: number;
  misses: number;
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodies: bodyCache.size,
    indicatorShards: indicatorCache.size,
    attackLoaded: cachedAttack !== null,
    hits: cacheHits,
    misses: cacheMisses,
  };
}

export function _resetAadCacheForTests(): void {
  cachedIndex = null;
  cachedIndexAt = null;
  bodyCache.clear();
  indicatorCache.clear();
  cachedAttack = null;
  cacheHits = 0;
  cacheMisses = 0;
}
