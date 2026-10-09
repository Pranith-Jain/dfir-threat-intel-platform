/**
 * AI Escape Watch manifest loader — registry of AI agent containment failures.
 *
 * Reads the static JSON manifest shipped in /public/data/ai-escape/ (built by
 * scripts/build-ai-escape.mjs from the curatorial seed in
 * threat-intel-staging/ai-escape/seed.json). Served through env.ASSETS —
 * no per-request upstream, no secrets.
 *
 * Shape:
 *   /data/ai-escape/index.json              (slim rows + stats + guardrail counts)
 *   /data/ai-escape/incidents.json           (all dockets as {id: body}; bundled — see build script)
 *   /data/ai-escape/guardrails.json         (10 control definitions)
 *   /data/ai-escape/trackers.json           (provenance table)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export type EscapeKlass = 'containment-breach' | 'agent-hijack' | 'supply-chain' | 'tool-misuse' | 'injection';
export type EscapeSev = 'critical' | 'severe' | 'notable' | 'contained';
export type EscapeTier = 'A' | 'B' | 'C' | 'D' | 'X';

export interface EscapeSlim {
  id: string;
  title: string;
  klass: EscapeKlass;
  sev: EscapeSev;
  tier: EscapeTier;
  cbs: number;
  occurred: string;
  disclosed: string;
  dwell: number | null;
  autonomous: boolean;
  developer: string;
  purpose: string;
  failed: string[];
}

export interface EscapeChain {
  PRESSURE: string | null;
  PROBE: string | null;
  BREACH: string | null;
  CHANNEL: string | null;
  ESCALATE: string | null;
  PROPAGATE: string | null;
  HALT: string | null;
}

export interface EscapeSource {
  label: string;
  url: string;
}

export interface EscapeIncident extends EscapeSlim {
  actor: string;
  systems: string;
  targets: string;
  summary: string;
  disputed: string | null;
  chain: EscapeChain;
  sources: EscapeSource[];
}

export interface EscapeGuardrail {
  id: string;
  title: string;
  def: string;
}

export interface EscapeTracker {
  name: string;
  url: string;
  kind: string;
  holds: string;
  checked: string;
}

export interface EscapeIndex {
  registry: string;
  version: string;
  compiled: string;
  builtAt: string;
  cbsScale: string;
  cbsWeights: Record<string, number>;
  chainStages: string[];
  stats: {
    entries: number;
    tierA: number;
    evalEnvBreaches: number;
    autonomous: number;
    medianDwellDays: number | null;
    dwellRange: [number, number] | null;
    mostAbsentGuardrail: { id: string; entries: number } | null;
    lastDisclosedAt: string | null;
    lastDisclosedId: string | null;
    jobExactCount: number;
  };
  guardrailCounts: Record<string, number>;
  incidents: EscapeSlim[];
}

export const ESCAPE_CHAIN_STAGES = ['PRESSURE', 'PROBE', 'BREACH', 'CHANNEL', 'ESCALATE', 'PROPAGATE', 'HALT'] as const;

const DATA_PREFIX = '/data/ai-escape';
const MAX_BODY_CACHE = 100;

const bodyCache: BodyCache<EscapeIncident> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: EscapeIndex | null = null;
let cachedIndexAt: number | null = null;
let cachedGuardrails: EscapeGuardrail[] | null = null;
let cachedTrackers: EscapeTracker[] | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://ai-escape.local');
}

export async function loadEscapeIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<EscapeIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<EscapeIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `AI Escape index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-ai-escape.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

let cachedDockets: Record<string, EscapeIncident> | null = null;

export async function getEscapeIncident(assets: Fetcher, id: string): Promise<EscapeIncident | null> {
  const hit = trackHit(bodyCache, id);
  if (hit) return hit;
  if (!cachedDockets) {
    const all = await fetchJson<Record<string, EscapeIncident>>(assets, `${DATA_PREFIX}/incidents.json`);
    if (!all) return null;
    cachedDockets = all;
  }
  const body = cachedDockets[id];
  if (!body) return null;
  return recordHit(bodyCache, id, body, MAX_BODY_CACHE);
}

export async function loadEscapeGuardrails(assets: Fetcher): Promise<EscapeGuardrail[]> {
  if (cachedGuardrails) return cachedGuardrails;
  const doc = await fetchJson<{ guardrails: EscapeGuardrail[] }>(assets, `${DATA_PREFIX}/guardrails.json`);
  cachedGuardrails = doc?.guardrails ?? [];
  return cachedGuardrails;
}

export async function loadEscapeTrackers(assets: Fetcher): Promise<EscapeTracker[]> {
  if (cachedTrackers) return cachedTrackers;
  const doc = await fetchJson<{ trackers: EscapeTracker[] }>(assets, `${DATA_PREFIX}/trackers.json`);
  cachedTrackers = doc?.trackers ?? [];
  return cachedTrackers;
}

export interface EscapeListOptions {
  klass?: EscapeKlass;
  sev?: EscapeSev;
  tier?: EscapeTier;
  guardrail?: string;
  autonomous?: boolean;
  q?: string;
  limit?: number;
}

export function filterEscapes(idx: EscapeIndex, opts: EscapeListOptions = {}): EscapeSlim[] {
  const { klass, sev, tier, guardrail, autonomous, q, limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const out: EscapeSlim[] = [];
  for (const e of idx.incidents) {
    if (klass && e.klass !== klass) continue;
    if (sev && e.sev !== sev) continue;
    if (tier && e.tier !== tier) continue;
    if (guardrail && !e.failed.includes(guardrail)) continue;
    if (autonomous !== undefined && e.autonomous !== autonomous) continue;
    if (needle && !`${e.id} ${e.title} ${e.developer} ${e.purpose}`.toLowerCase().includes(needle)) continue;
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

/** Month buckets for the chronology strip: [{ month: 'YYYY-MM', ids: [...] }]. */
export function escapeTimelineBuckets(idx: EscapeIndex): { month: string; ids: string[] }[] {
  const buckets = new Map<string, string[]>();
  const sorted = [...idx.incidents].sort((a, b) => a.occurred.localeCompare(b.occurred));
  for (const e of sorted) {
    const month = e.occurred.slice(0, 7);
    if (!buckets.has(month)) buckets.set(month, []);
    buckets.get(month)!.push(e.id);
  }
  return [...buckets.entries()].map(([month, ids]) => ({ month, ids }));
}

export function escapeCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodies: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodies: { size: bodyCache.map.size, hits: bodyCache.hits, misses: bodyCache.misses },
  };
}

export function _resetEscapeCacheForTests(): void {
  bodyCache.map.clear();
  cachedIndex = null;
  cachedIndexAt = null;
  cachedGuardrails = null;
  cachedTrackers = null;
  cachedDockets = null;
  bodyCache.hits = bodyCache.misses = 0;
}
