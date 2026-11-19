/**
 * Offsec Harness Index manifest — open-source offensive-AI agent harnesses
 * (offsecharnesses.ai).
 *
 * Edge loader for the replicated data.json export: 154 tracked harnesses,
 * 14 seen in real attacks (9 confirmed / 5 observed), 26 actors, 32 primary
 * reports. The two tables drive the page: `evidence` rows carry a tier,
 * named actors and quoted source lines; `field` rows carry GitHub facts
 * (stars, licence, last push, use tags from the project's own README).
 *
 * Data source: public/data/oh/ (built by scripts/build-oh-manifest.mjs), read
 * through env.ASSETS — no D1, no KV, no public fetch. One JSON shard per
 * harness slug keeps bodies lazy. Upstream publishes no reuse licence, so
 * only structured metadata is stored and every row deep-links upstream.
 */

export interface OhActor {
  name: string;
  note: string | null;
}

export interface OhHarnessSlim {
  slug: string;
  name: string;
  table: string | null;
  tier: string | null;
  kind: string | null;
  description: string | null;
  repo: string | null;
  url: string;
  stars: number | null;
  license: string | null;
  lastPush: string | null;
  archived: boolean;
  actors: OhActor[];
  useTags: string[];
  useBasis: string[];
  breach: string | null;
  keyFigure: string | null;
  sourceCount: number;
  incidentCount: number;
}

export interface OhUse {
  tag: string;
  basis: string | null;
  source: string | null;
  quote: string | null;
}

export interface OhIncidentLink {
  id: string;
  title: string;
  date: string;
  url: string;
}

export interface OhHarnessBody extends OhHarnessSlim {
  whatItDid: string | null;
  note: string | null;
  uses: OhUse[];
  sourceIds: string[];
  incidents: OhIncidentLink[];
  upstreamUrl: string;
}

export interface OhSource {
  id: string;
  publisher: string;
  kind: string;
  date: string;
  title: string;
  url: string;
}

export interface OhReference {
  name: string;
  url: string;
  type: string;
  what: string;
  discovery?: boolean;
}

export interface OhStats {
  tracked: number;
  evidenceRows: number;
  fieldRows: number;
  byTier: Record<string, number>;
  byTable: Record<string, number>;
  byKind: Record<string, number>;
  byLicense: Record<string, number>;
  byUseTag: Array<{ name: string; count: number }>;
  actors: Array<{ name: string; count: number }>;
  sourceCount: number;
  referenceCount: number;
  breaches: number;
  withRepo: number;
}

export interface OhIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  upstreamData: string;
  evidenceReviewed: string | null;
  githubFacts: string | null;
  tiers: Record<string, string>;
  useTags: Array<{ key: string; label: string; def: string }>;
  related: Record<string, string>;
  counts: {
    tracked: number;
    inTheWild: number;
    confirmed: number;
    observed: number;
    actors: number;
    sources: number;
    breaches: number;
  };
  stats: OhStats;
  harnesses: OhHarnessSlim[];
  webPages: Record<string, string>;
}

const DATA_PREFIX = '/data/oh';
let cachedIndex: OhIndex | null = null;
let indexHits = 0;
let indexMisses = 0;
const bodyCache = new Map<string, OhHarnessBody>();
let bodyHits = 0;
let bodyMisses = 0;
const BODY_CACHE_MAX = 60;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://oh.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

function bodyGet(key: string): OhHarnessBody | null {
  const v = bodyCache.get(key);
  if (v === undefined) {
    bodyMisses++;
    return null;
  }
  bodyHits++;
  bodyCache.delete(key);
  bodyCache.set(key, v);
  return v;
}

function bodySet(key: string, value: OhHarnessBody): void {
  bodyCache.delete(key);
  bodyCache.set(key, value);
  while (bodyCache.size > BODY_CACHE_MAX) {
    const oldest = bodyCache.keys().next();
    if (oldest.done) break;
    bodyCache.delete(oldest.value);
  }
}

export async function loadOhIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<OhIndex> {
  if (cachedIndex && !opts.forceRefresh) {
    indexHits++;
    return cachedIndex;
  }
  indexMisses++;
  const idx = await fetchJson<OhIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Offsec Harness index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-oh-manifest.mjs' first.`
    );
  }
  cachedIndex = idx;
  return idx;
}

export interface OhFilterOptions {
  table?: string;
  tier?: string;
  useTag?: string;
  actor?: string;
  kind?: string;
  keyword?: string;
  limit?: number;
}

export function filterOhHarnesses(rows: OhHarnessSlim[], opts: OhFilterOptions = {}): OhHarnessSlim[] {
  const { table, tier, useTag, actor, kind, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: OhHarnessSlim[] = [];
  for (const r of rows) {
    if (table && String(r.table).toLowerCase() !== table.toLowerCase()) continue;
    if (tier && String(r.tier).toLowerCase() !== tier.toLowerCase()) continue;
    if (useTag && !r.useTags.some((t) => t.toLowerCase() === useTag.toLowerCase())) continue;
    if (actor && !r.actors.some((a) => a.name.toLowerCase() === actor.toLowerCase())) continue;
    if (kind && String(r.kind).toLowerCase() !== kind.toLowerCase()) continue;
    if (needle) {
      const hay =
        `${r.name} ${r.description ?? ''} ${r.actors.map((a) => a.name).join(' ')} ${r.useTags.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getOhHarness(assets: Fetcher, slug: string): Promise<OhHarnessBody | null> {
  if (!/^[a-z0-9-]+$/.test(slug)) return null;
  let body = bodyGet(slug);
  if (!body) {
    const data = await fetchJson<{ harness: OhHarnessBody }>(assets, `${DATA_PREFIX}/harnesses/${slug}.json`);
    if (!data?.harness) return null;
    body = data.harness;
    bodySet(slug, body);
  }
  return body;
}

export async function loadOhSideFile<T>(assets: Fetcher, name: 'sources' | 'references'): Promise<T | null> {
  return await fetchJson<T>(assets, `${DATA_PREFIX}/${name}.json`);
}

/** Test-only: drop all cached state so consecutive cases stay independent. */
export function _resetOhCacheForTests(): void {
  cachedIndex = null;
  bodyCache.clear();
  indexHits = indexMisses = bodyHits = bodyMisses = 0;
}

export function ohCacheStats(): {
  index: { hits: number; misses: number };
  bodies: { hits: number; misses: number; entries: number };
} {
  return {
    index: { hits: indexHits, misses: indexMisses },
    bodies: { hits: bodyHits, misses: bodyMisses, entries: bodyCache.size },
  };
}
