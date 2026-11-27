/** OWASP GenAI Threat Intelligence Initiative (STIX 2.1) edge manifest. */
import { fetchJsonAsset } from './manifest-cache';

export interface AiCtiSlim {
  id: string;
  slug: string;
  name: string;
  category: string | null;
  created: string | null;
  labels: string[];
  refCount: number;
}

export interface AiCtiBody extends AiCtiSlim {
  description: string;
  labels: string[];
  modified: string | null;
  refs: Array<{ source: string | null; id: string | null; url: string | null }>;
  links: Array<{ type: string; target: string }>;
}

export interface AiCtiIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  repoUrl: string;
  license: string;
  counts: {
    objects: number;
    actors: number;
    techniques: number;
    malware: number;
    reports: number;
    indicators: number;
    relationships: number;
    categoryA: number;
    categoryB: number;
  };
  actors: AiCtiSlim[];
  techniques: AiCtiSlim[];
  malware: AiCtiSlim[];
  reports: AiCtiSlim[];
  indicators: Array<{ id: string; name: string; category: string | null; labels: string[]; created: string | null }>;
}

const ROOT = '/data/ai-cti-feed';
let cached: AiCtiIndex | null = null;

export async function loadAiCtiIndex(assets: Fetcher): Promise<AiCtiIndex> {
  if (cached) return cached;
  const idx = await fetchJsonAsset<AiCtiIndex>(assets, `${ROOT}/index.json`, 'https://ai-cti.local');
  if (!idx) throw new Error(`AI-CTI feed manifest missing — run scripts/build-ai-cti-feed.mjs`);
  cached = idx;
  return idx;
}

export type AiCtiKind = 'actors' | 'ttps' | 'malware';

export interface AiCtiFilter {
  category?: string;
  q?: string;
  limit?: number;
}

export function filterAiCtiRows(rows: AiCtiSlim[], opts: AiCtiFilter = {}): AiCtiSlim[] {
  const { category, q, limit = 100 } = opts;
  const needle = q?.trim().toLowerCase();
  const cat = category?.trim().toUpperCase();
  const out: AiCtiSlim[] = [];
  for (const r of rows) {
    if (cat && r.category !== cat) continue;
    if (needle && !`${r.name} ${r.id} ${r.labels?.join?.(' ') ?? ''}`.toLowerCase().includes(needle)) continue;
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export async function getAiCtiBody(assets: Fetcher, kind: AiCtiKind, slug: string): Promise<AiCtiBody | null> {
  if (!['actors', 'ttps', 'malware'].includes(kind)) return null;
  const safe = String(slug ?? '')
    .replace(/[^a-z0-9-]/gi, '')
    .slice(0, 140);
  if (!safe) return null;
  return fetchJsonAsset<AiCtiBody>(assets, `${ROOT}/${kind}/${safe}.json`, 'https://ai-cti.local');
}

export function aiCtiCacheStats(): { loaded: boolean; actors: number; techniques: number } {
  return { loaded: cached !== null, actors: cached?.actors.length ?? 0, techniques: cached?.techniques.length ?? 0 };
}

export function _resetAiCtiCacheForTests(): void {
  cached = null;
}
