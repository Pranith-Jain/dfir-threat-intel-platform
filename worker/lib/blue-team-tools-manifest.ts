/**
 * BlueTeam-Tools metadata manifest.
 *
 * Edge loader for the metadata-only mirror of github.com/A-poc/BlueTeam-Tools
 * (no reuse licence — names, one-line summaries and public links only).
 * Data: public/data/blue-team-tools/index.json, read through env.ASSETS.
 */
import { fetchJsonAsset } from './manifest-cache';

export interface BttTool {
  slug: string;
  name: string;
  category: string;
  summary: string;
  url: string | null;
  upstreamUrl: string;
}

export interface BttCategory {
  name: string;
  statedCount: string;
  toolCount: number;
  tools: string[];
}

export interface BttIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  license: string;
  counts: { categories: number; tools: number; withLinks: number };
  categories: BttCategory[];
  tools: BttTool[];
}

const DATA = '/data/blue-team-tools/index.json';
let cached: BttIndex | null = null;

export async function loadBttIndex(assets: Fetcher): Promise<BttIndex> {
  if (cached) return cached;
  const idx = await fetchJsonAsset<BttIndex>(assets, DATA, 'https://blue-team-tools.local');
  if (!idx) throw new Error(`BlueTeam-Tools manifest missing at ${DATA} — run scripts/build-blue-team-tools.mjs`);
  cached = idx;
  return idx;
}

export interface BttFilter {
  category?: string;
  q?: string;
  linked?: boolean;
  limit?: number;
}

export function filterBttTools(index: BttIndex, opts: BttFilter = {}): BttTool[] {
  const { category, q, linked, limit = 200 } = opts;
  const needle = q?.trim().toLowerCase();
  const cat = category?.trim().toLowerCase();
  const out: BttTool[] = [];
  for (const t of index.tools) {
    if (cat && t.category.toLowerCase() !== cat && t.category.toLowerCase().replace(/[^a-z0-9]+/g, '-') !== cat)
      continue;
    if (linked && !t.url) continue;
    if (needle && !`${t.name} ${t.summary} ${t.category}`.toLowerCase().includes(needle)) continue;
    out.push(t);
    if (out.length >= limit) break;
  }
  return out;
}

export function getBttTool(index: BttIndex, slug: string): BttTool | null {
  const key = String(slug ?? '')
    .trim()
    .toLowerCase();
  return index.tools.find((t) => t.slug === key) ?? null;
}

export function bttCacheStats(): { loaded: boolean; categories: number; tools: number; generatedAt: string | null } {
  return {
    loaded: cached !== null,
    categories: cached?.categories.length ?? 0,
    tools: cached?.tools.length ?? 0,
    generatedAt: cached?.generatedAt ?? null,
  };
}

export function _resetBttCacheForTests(): void {
  cached = null;
}
