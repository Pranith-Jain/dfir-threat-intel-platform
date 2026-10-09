/**
 * Daily Briefs manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/daily-briefs/.
 * Three daily intelligence brief types:
 *   - cyber:     OT/ICS Cyber Threat Intelligence
 *   - deepfake:  DeepFake and Generative AI Intelligence
 *   - disaster:  Global Disaster Intelligence
 *
 * Data layout:
 *   /data/daily-briefs/index.json              (slim — no bodies)
 *   /data/daily-briefs/cyber/<date>.json       (one per date)
 *   /data/daily-briefs/deepfake/<date>.json    (one per date)
 *   /data/daily-briefs/disaster/<date>.json    (one per date)
 *
 * In-memory cache: index is small so we keep it forever after first fetch.
 * Bodies cached on demand with a 100-entry LRU.
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export type DbBriefType = 'cyber' | 'deepfake' | 'disaster' | 'maritime';

export interface DbIndexEntry {
  type: DbBriefType;
  date: string;
  sizeBytes: number;
}

export interface DbIndex {
  source: string;
  license: string;
  generatedAt: string;
  counts: { cyber: number; deepfake: number; disaster: number; maritime: number };
  briefs: DbIndexEntry[];
}

export interface DbCyberBrief {
  type: 'cyber';
  date: string;
  threatLevel: string;
  executiveSummary: string;
  keyFindings: { title: string; summary: string }[];
  dashboard: {
    kpis: { value: string; label: string }[];
    activelyExploited: string[];
    vendors: string[];
    sectors: string[];
  };
  topThreats: { title: string; action: string }[];
  threatActors: { category: string; items: string[] }[];
  cveWatch: { category: string; items: string[] }[];
  events: {
    title: string;
    severity: string;
    text: string;
    chips: string[];
    sources: { url: string; label: string }[];
  }[];
  ttps: { descriptions: string[]; mitreIds: string[] };
  outlook72h: string;
  relatedCves: string[];
  /**
   * Present on only a subset of published briefs (16 of 196 in the shipped
   * `public/data/daily-briefs` corpus), so it must stay optional — declaring
   * it required misrepresents the on-disk data shape.
   */
  rawMarkdown?: string;
}

export interface DbDeepfakeBrief {
  type: 'deepfake';
  date: string;
  riskOutlook: string;
  executiveSummary: string;
  keyFindings: { title: string; summary: string }[];
  incidents: {
    title: string;
    badges: string[];
    fields: Record<string, string>;
    summary: string;
    sources: { url: string; label: string }[];
  }[];
  emergingTrends: string[];
  geographicObservations: string[];
  detectionDevelopments: string[];
  /** Present on only a subset of published briefs — see `DbCyberBrief.rawMarkdown`. */
  rawMarkdown?: string;
}

export interface DbDisasterBrief {
  type: 'disaster';
  date: string;
  overallThreat: string;
  executiveSummary: string;
  dashboard: { kpis: { value: string; label: string }[] };
  topEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[];
  escalateEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[];
  monitorEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[];
  outlook72h: string;
  regionalTrends: string[];
  /** Present on only a subset of published briefs — see `DbCyberBrief.rawMarkdown`. */
  rawMarkdown?: string;
}

export type DbBriefBody = DbCyberBrief | DbDeepfakeBrief | DbDisasterBrief;

const DATA_PREFIX = '/data/daily-briefs';
const MAX_BODY_CACHE = 100;

const bodyCache: BodyCache<DbBriefBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: DbIndex | null = null;
let cachedIndexAt: number | null = null;

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://db.local');
}

export async function loadDbIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<DbIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<DbIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Daily Briefs manifest not found at ${DATA_PREFIX}/index.json — ` +
        'did the build run? Run `node scripts/build-daily-briefs.mjs`.'
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getDbBrief(assets: Fetcher, type: DbBriefType, date: string): Promise<DbBriefBody | null> {
  const key = `${type}:${date}`;
  const hit = trackHit(bodyCache, key);
  if (hit) return hit;
  const body = await fetchJson<DbBriefBody>(assets, `${DATA_PREFIX}/${type}/${date}.json`);
  if (!body) return null;
  return recordHit(bodyCache, key, body, MAX_BODY_CACHE);
}

// ─── Filter helpers ─────────────────────────────────────────────────────

export interface DbListOptions {
  type?: DbBriefType;
  dateFrom?: string;
  dateTo?: string;
  limit?: number;
}

export function filterBriefs(idx: DbIndex, opts: DbListOptions = {}): DbIndexEntry[] {
  const { type, dateFrom, dateTo, limit = 100 } = opts;
  const out: DbIndexEntry[] = [];
  for (const b of idx.briefs) {
    if (type && b.type !== type) continue;
    if (dateFrom && b.date < dateFrom) continue;
    if (dateTo && b.date > dateTo) continue;
    out.push(b);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── Cache stats ───────────────────────────────────────────────────────

export function dbCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodyCache: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodyCache: { size: bodyCache.map.size, hits: bodyCache.hits, misses: bodyCache.misses },
  };
}

export function _resetDbCacheForTests(): void {
  bodyCache.map.clear();
  bodyCache.hits = bodyCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
}
