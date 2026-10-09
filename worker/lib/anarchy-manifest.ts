/**
 * Anarchy (kazamadono.github.io) manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/anarchy/
 * (replicated daily from https://kazamadono.github.io/courses.json).
 * The Worker fetches them through env.ASSETS — no D1, no KV, no public
 * internet at runtime.
 *
 * Shape:
 *   /data/anarchy/index.json          (≈368 KB, slim index + counts)
 *   /data/anarchy/courses/<id>.json   (one per course, full body)
 *   /data/anarchy/by-tag/<tag>.json   (one per tag, slim list)
 *
 * Source: https://kazamadono.github.io/ (public GitHub Pages, KazamaDono)
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';
import {
  recommendCourses,
  similarCourses,
  type RecommendInput,
  type ScoredCourse,
} from '../../src/lib/anarchy-recommend';

export interface AnarchyProvider {
  name: string;
  host: string;
  icon: string;
}

export type AnarchyDifficulty = 'beginner' | 'intermediate' | 'advanced';

export interface AnarchyCourseSlim {
  id: string;
  title: string;
  href: string;
  img: string | null;
  tags: string[];
  provider: AnarchyProvider;
  difficulty: AnarchyDifficulty;
  hours: number;
  preview: string;
  sizeBytes: number;
}

export interface AnarchyIndex {
  source: string;
  url: string;
  coursesUrl: string;
  description: string;
  license: string;
  author: string;
  authorUrl: string;
  syncedAt: string;
  builtAt: string;
  counts: {
    courses: number;
    categories: number;
  };
  topProviders: { name: string; count: number }[];
  prereqGraph: Record<string, { tag: string; weight: number }[]>;
  categories: { tag: string; count: number }[];
  topTags: { tag: string; count: number }[];
  courses: AnarchyCourseSlim[];
}

export interface AnarchyCourseBody {
  id: string;
  title: string;
  desc: string;
  href: string;
  img: string | null;
  tags: string[];
  provider: AnarchyProvider;
  difficulty: AnarchyDifficulty;
  hours: number;
  prereqs: string[];
  source: string;
  sourceUrl: string;
}

export interface AnarchyTagBody {
  tag: string;
  count: number;
  courses: AnarchyCourseSlim[];
}

const DATA_PREFIX = '/data/anarchy';
const MAX_BODY_CACHE = 200;

const courseCache: BodyCache<AnarchyCourseBody> = { map: new Map(), hits: 0, misses: 0 };
const tagCache: BodyCache<AnarchyTagBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: AnarchyIndex | null = null;
let cachedIndexAt: number | null = null;

function safeFilename(slug: string): string {
  return slug.replace(/\//g, '__').replace(/[^A-Za-z0-9._-]/g, '_');
}

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://anarchy.local');
}

export async function loadAnarchyIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<AnarchyIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<AnarchyIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Anarchy manifest not found at ${DATA_PREFIX}/index.json — did the build run? Run \`node scripts/sync-anarchy.mjs && node scripts/build-anarchy.mjs\`.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getAnarchyCourse(assets: Fetcher, id: string): Promise<AnarchyCourseBody | null> {
  const key = id.toLowerCase();
  const hit = trackHit(courseCache, key);
  if (hit) return hit;
  const body = await fetchJson<AnarchyCourseBody>(assets, `${DATA_PREFIX}/courses/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(courseCache, key, body, MAX_BODY_CACHE);
}

export async function getAnarchyTag(assets: Fetcher, tag: string): Promise<AnarchyTagBody | null> {
  const key = tag.toLowerCase();
  const hit = trackHit(tagCache, key);
  if (hit) return hit;
  const body = await fetchJson<AnarchyTagBody>(assets, `${DATA_PREFIX}/by-tag/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(tagCache, key, body, MAX_BODY_CACHE);
}

export interface AnarchyListOptions {
  tag?: string;
  q?: string;
  difficulty?: AnarchyDifficulty;
  provider?: string;
  maxHours?: number;
  limit?: number;
  sort?: 'id' | 'hours' | 'difficulty';
}

export function filterAnarchyCourses(idx: AnarchyIndex, opts: AnarchyListOptions = {}): AnarchyCourseSlim[] {
  const { tag, q, difficulty, provider, maxHours, limit = 100, sort } = opts;
  const needle = q?.toLowerCase();
  const tagNeedle = tag?.toLowerCase();
  const providerNeedle = provider?.toLowerCase();
  let out: AnarchyCourseSlim[] = [];
  for (const c of idx.courses) {
    if (tagNeedle && !c.tags.includes(tagNeedle)) continue;
    if (difficulty && c.difficulty !== difficulty) continue;
    if (
      providerNeedle &&
      !c.provider.name.toLowerCase().includes(providerNeedle) &&
      !c.provider.host.toLowerCase().includes(providerNeedle)
    )
      continue;
    if (maxHours !== undefined && c.hours > maxHours) continue;
    if (needle) {
      const hay = `${c.title} ${c.preview} ${c.tags.join(' ')} ${c.provider.name}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(c);
    if (!sort && out.length >= limit) break;
  }
  if (sort === 'hours') out.sort((a, b) => a.hours - b.hours);
  else if (sort === 'difficulty') {
    const rank: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };
    out.sort((a, b) => (rank[a.difficulty] ?? 1) - (rank[b.difficulty] ?? 1));
  }
  if (sort) out = out.slice(0, limit);
  return out;
}

// ─── Recommendations (deterministic, no LLM) ─────────────────────────
// Scoring lives in src/lib/anarchy-recommend.ts (zero-DOM pure module shared
// with the SPA); these wrappers adapt the worker manifest types to it.
export type { RecommendInput, ScoredCourse } from '../../src/lib/anarchy-recommend';

export type AnarchyRecommendOptions = RecommendInput;

export function recommendAnarchyCourses(
  idx: AnarchyIndex,
  opts: AnarchyRecommendOptions = {}
): ScoredCourse<AnarchyCourseSlim>[] {
  const popularity: Record<string, number> = {};
  for (const { tag, count } of idx.categories) popularity[tag] = count;
  return recommendCourses(idx.courses, { ...opts, tagPopularity: popularity });
}

export function similarAnarchyCourses(idx: AnarchyIndex, id: string, limit = 4): ScoredCourse<AnarchyCourseSlim>[] {
  return similarCourses(idx.courses, id, limit);
}

export function anarchyCacheStats() {
  return {
    index: cachedIndex ? { cachedAt: cachedIndexAt, counts: cachedIndex.counts } : null,
    course: { hits: courseCache.hits, misses: courseCache.misses, size: courseCache.map.size },
    tag: { hits: tagCache.hits, misses: tagCache.misses, size: tagCache.map.size },
  };
}
