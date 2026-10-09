/**
 * Security Investigator manifest loader.
 *
 * Reads the static JSON manifest we ship in /public/data/si/ (the 25
 * SKILL.md files + 45 KQL queries replicated from upstream
 * github.com/SCStelz/security-investigator, MIT). The Worker fetches
 * them through the env.ASSETS binding — the data lives in dist/data/si/
 * after `npm run build`, and the Worker can pull it back through ASSETS
 * without going over the public internet.
 *
 * Shape:
 *   /data/si/index.json              (~37 KB, slim — no bodies)
 *   /data/si/skills/<slug>.json      (1 per skill, body markdown inline)
 *   /data/si/queries/<slug>.json     (1 per query, body markdown inline)
 *   /data/si/automations/<slug>.json (3 workflow definitions)
 *
 * In-memory cache: the index is small (~37 KB) so we keep it forever
 * after the first fetch. Bodies are cached on demand with an LRU bound
 * of 200 entries to keep the Worker from blowing its 128 MB memory
 * limit when many distinct skills are requested back-to-back.
 */

import { recordHit, trackHit, type BodyCache } from './manifest-cache';

export type SiSkillCategory =
  | 'Quick Scan'
  | 'Core Investigation'
  | 'Auth & Access'
  | 'Behavioral Drift'
  | 'Posture & Exposure'
  | 'Data Security'
  | 'Visualization'
  | 'Tooling'
  | 'Other';

export interface SiSkillIndexEntry {
  slug: string;
  name: string;
  category: SiSkillCategory;
  description: string;
  triggerKeywords: string[];
  hasAssets: boolean;
  sizeBytes: number;
}

export interface SiQueryIndexEntry {
  slug: string;
  domain: string;
  subdomain: string | null;
  title: string;
  filename: string;
  sizeBytes: number;
}

export interface SiAutomationIndexEntry {
  slug: string;
  title: string;
  filename: string;
  interval: 'daily' | 'weekly';
  sizeBytes: number;
}

export interface SiIndex {
  source: string;
  license: string;
  replicatedAt: string;
  counts: { skills: number; queries: number; automations: number };
  skills: SiSkillIndexEntry[];
  queries: SiQueryIndexEntry[];
  automations: SiAutomationIndexEntry[];
}

export interface SiSkillBody extends SiSkillIndexEntry {
  bodyMarkdown: string;
  domain: string;
}

export interface SiQueryBody extends SiQueryIndexEntry {
  bodyMarkdown: string;
}

export interface SiAutomationBody extends SiAutomationIndexEntry {
  bodyMarkdown: string;
}

const DATA_PREFIX = '/data/si';
const MAX_BODY_CACHE = 200;

const skillBodyCache: BodyCache<SiSkillBody> = { map: new Map(), hits: 0, misses: 0 };
const queryBodyCache: BodyCache<SiQueryBody> = { map: new Map(), hits: 0, misses: 0 };
const automationBodyCache: BodyCache<SiAutomationBody> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: SiIndex | null = null;
let cachedIndexAt: number | null = null;

function safeFilename(slug: string): string {
  return slug
    .replace(/\//g, '__')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/^\.+/, '');
}

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  // The asset binding wants a fully qualified URL; we use any origin because
  // env.ASSETS ignores the host header and serves from the bundled static dir.
  const url = `https://si.local${path}`;
  const res = await assets.fetch(new Request(url));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

/**
 * Fetch + cache the slim index. Safe to call on every cold start; the
 * subsequent calls return the in-memory copy. Set `forceRefresh=true`
 * to bypass the cache (used in tests).
 */
export async function loadSiIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<SiIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<SiIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `SI manifest not found at ${DATA_PREFIX}/index.json — did the build run? ` +
        'The /data/si/ directory must be copied to dist/ (see scripts/copy-si-data.mjs).'
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getSiSkill(assets: Fetcher, slug: string): Promise<SiSkillBody | null> {
  const hit = trackHit(skillBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<SiSkillBody>(assets, `${DATA_PREFIX}/skills/${safeFilename(slug)}.json`);
  if (!body) return null;
  return recordHit(skillBodyCache, slug, body, MAX_BODY_CACHE);
}

export async function getSiQuery(assets: Fetcher, slug: string): Promise<SiQueryBody | null> {
  const hit = trackHit(queryBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<SiQueryBody>(assets, `${DATA_PREFIX}/queries/${safeFilename(slug)}.json`);
  if (!body) return null;
  return recordHit(queryBodyCache, slug, body, MAX_BODY_CACHE);
}

export async function getSiAutomation(assets: Fetcher, slug: string): Promise<SiAutomationBody | null> {
  const hit = trackHit(automationBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<SiAutomationBody>(assets, `${DATA_PREFIX}/automations/${safeFilename(slug)}.json`);
  if (!body) return null;
  return recordHit(automationBodyCache, slug, body, MAX_BODY_CACHE);
}

export interface SiListSkillsOptions {
  category?: SiSkillCategory;
  keyword?: string;
  limit?: number;
}

export interface SiListQueriesOptions {
  domain?: string;
  keyword?: string;
  limit?: number;
}

/**
 * Filter helpers for the index. Keep these simple and pure so they're
 * cheap to call from MCP tool handlers. The index never contains
 * bodies, so these don't touch the LRU cache.
 */
export function filterSkills(idx: SiIndex, opts: SiListSkillsOptions = {}): SiSkillIndexEntry[] {
  const { category, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: SiSkillIndexEntry[] = [];
  for (const s of idx.skills) {
    if (category && s.category !== category) continue;
    if (needle) {
      const hay = `${s.slug} ${s.name} ${s.description} ${s.triggerKeywords.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(s);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterQueries(idx: SiIndex, opts: SiListQueriesOptions = {}): SiQueryIndexEntry[] {
  const { domain, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: SiQueryIndexEntry[] = [];
  for (const q of idx.queries) {
    if (domain && q.domain !== domain) continue;
    if (needle) {
      const hay = `${q.slug} ${q.title} ${q.filename} ${q.domain} ${q.subdomain ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(q);
    if (out.length >= limit) break;
  }
  return out;
}

export function siCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  skills: { size: number; hits: number; misses: number };
  queries: { size: number; hits: number; misses: number };
  automations: { size: number; hits: number; misses: number };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    skills: { size: skillBodyCache.map.size, hits: skillBodyCache.hits, misses: skillBodyCache.misses },
    queries: { size: queryBodyCache.map.size, hits: queryBodyCache.hits, misses: queryBodyCache.misses },
    automations: {
      size: automationBodyCache.map.size,
      hits: automationBodyCache.hits,
      misses: automationBodyCache.misses,
    },
  };
}

/**
 * Test-only helper to reset the in-memory caches. Production code
 * should not call this; the cache is intentionally persistent for
 * the life of the isolate.
 */
export function _resetSiCacheForTests(): void {
  skillBodyCache.map.clear();
  queryBodyCache.map.clear();
  automationBodyCache.map.clear();
  cachedIndex = null;
  cachedIndexAt = null;
  skillBodyCache.hits = skillBodyCache.misses = 0;
  queryBodyCache.hits = queryBodyCache.misses = 0;
  automationBodyCache.hits = automationBodyCache.misses = 0;
}

// ─── New content types: docs, ref data, routing prompt ───────────────

export interface SiDocIndexEntry {
  slug: string;
  title: string;
  filename: string;
  sizeBytes: number;
}

export interface SiDocsIndex {
  source: string;
  license: string;
  count: number;
  docs: SiDocIndexEntry[];
}

export interface SiDoc {
  slug: string;
  title: string;
  filename: string;
  bodyMarkdown: string;
}

const docsIndexCache: { value: SiDocsIndex | null } = { value: null };
const docBodyCache: BodyCache<SiDoc> = { map: new Map(), hits: 0, misses: 0 };
const refBodyCache: BodyCache<unknown> = { map: new Map(), hits: 0, misses: 0 };
let routingPromptCache: string | null = null;

export async function loadDocsIndex(assets: Fetcher): Promise<SiDocsIndex> {
  if (docsIndexCache.value) return docsIndexCache.value;
  const idx = await fetchJson<SiDocsIndex>(assets, `${DATA_PREFIX}/docs-index.json`);
  if (!idx) throw new Error('docs-index.json not found — rebuild via scripts/build-si-manifest.mjs');
  docsIndexCache.value = idx;
  return idx;
}

export async function getDoc(assets: Fetcher, slug: string): Promise<SiDoc | null> {
  const hit = trackHit(docBodyCache, slug);
  if (hit) return hit;
  // Read the raw markdown body (it's a .md file, not JSON). Special-case here.
  const safeSlug = safeFilename(slug);
  const path = `${DATA_PREFIX}/docs/${safeSlug}.md`;
  const url = `https://si.local${path}`;
  const res = await assets.fetch(new Request(url));
  if (!res.ok) return null;
  const text = await res.text();
  // Title = first H1 in the file (best effort).
  const m = /^#\s+(.+)$/m.exec(text);
  const doc: SiDoc = {
    slug,
    title: m?.[1] ?? slug,
    filename: `${safeSlug}.md`,
    bodyMarkdown: text,
  };
  return recordHit(docBodyCache, slug, doc, MAX_BODY_CACHE);
}

export async function getRef<T = unknown>(assets: Fetcher, name: string): Promise<T | null> {
  const key = safeFilename(name.replace(/\.json$/, ''));
  const hit = trackHit(refBodyCache, key);
  if (hit !== undefined) return hit as T;
  const v = await fetchJson<T>(assets, `${DATA_PREFIX}/ref/${key}.json`);
  if (v === null) return null;
  return recordHit(refBodyCache, key, v, MAX_BODY_CACHE) as T;
}

export async function getRoutingPrompt(assets: Fetcher): Promise<string> {
  if (routingPromptCache !== null) return routingPromptCache;
  const url = `https://si.local${DATA_PREFIX}/routing-prompt.md`;
  const res = await assets.fetch(new Request(url));
  if (!res.ok) throw new Error('routing-prompt.md not found — rebuild via scripts/build-si-manifest.mjs');
  routingPromptCache = await res.text();
  return routingPromptCache;
}

export function clearDocsCache(): void {
  docsIndexCache.value = null;
  docBodyCache.map.clear();
  docBodyCache.hits = docBodyCache.misses = 0;
  refBodyCache.map.clear();
  refBodyCache.hits = refBodyCache.misses = 0;
  routingPromptCache = null;
}

// ─── PowerShell + detection-manifest scripts ─────────────────────────

export interface SiScriptIndexEntry {
  name: string;
  sizeBytes: number;
}

export interface SiScriptsIndex {
  source: string;
  license: string;
  count: number;
  scripts: SiScriptIndexEntry[];
}

const scriptsIndexCache: { value: SiScriptsIndex | null } = { value: null };
const scriptBodyCache: BodyCache<string> = { map: new Map(), hits: 0, misses: 0 };

export async function loadScriptsIndex(assets: Fetcher): Promise<SiScriptsIndex> {
  if (scriptsIndexCache.value) return scriptsIndexCache.value;
  const idx = await fetchJson<SiScriptsIndex>(assets, `${DATA_PREFIX}/scripts-index.json`);
  if (!idx) throw new Error('scripts-index.json not found — rebuild via scripts/build-si-manifest.mjs');
  scriptsIndexCache.value = idx;
  return idx;
}

export async function getScript(
  assets: Fetcher,
  name: string
): Promise<{ name: string; body: string; sizeBytes: number } | null> {
  const hit = trackHit(scriptBodyCache, name);
  if (hit !== undefined) return { name, body: hit, sizeBytes: hit.length };
  const url = `https://si.local${DATA_PREFIX}/scripts/${name}`;
  const res = await assets.fetch(new Request(url));
  if (!res.ok) return null;
  const text = await res.text();
  recordHit(scriptBodyCache, name, text, MAX_BODY_CACHE);
  return { name, body: text, sizeBytes: text.length };
}
