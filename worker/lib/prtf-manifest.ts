/**
 * PRTF manifest — Physical Red Team Framework (CC BY 4.0) edge loader.
 * Data: public/data/prtf/ read through env.ASSETS.
 */
import { fetchJsonAsset } from './manifest-cache';

export interface PrtfTechnique {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  summary: string;
  toolCount: number;
  url: string;
}

export interface PrtfTactic {
  id: string;
  name: string;
  description: string;
  count: number;
}

export interface PrtfBody {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  section: string | null;
  description: string;
  tools: Array<{ name: string; url: string | null }>;
  chains: Array<{ id: string; name: string }>;
  blue: { det?: string; cm?: string; refs?: unknown } | null;
  url: string;
}

export interface PrtfIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  license: string;
  version: string;
  counts: { tactics: number; techniques: number };
  tactics: PrtfTactic[];
  techniques: PrtfTechnique[];
}

const ROOT = '/data/prtf';
let cached: PrtfIndex | null = null;
const bodies = new Map<string, PrtfBody>();

export async function loadPrtfIndex(assets: Fetcher): Promise<PrtfIndex> {
  if (cached) return cached;
  const idx = await fetchJsonAsset<PrtfIndex>(assets, `${ROOT}/index.json`, 'https://prtf.local');
  if (!idx) throw new Error(`PRTF manifest missing at ${ROOT}/index.json — run scripts/build-prtf.mjs`);
  cached = idx;
  return idx;
}

export function normalizePrtfId(raw: string): string | null {
  const id = String(raw ?? '')
    .trim()
    .toUpperCase();
  return /^PRTF-\d{1,2}\.\d{2}$/.test(id) ? id : null;
}

export async function getPrtfTechnique(assets: Fetcher, rawId: string): Promise<PrtfBody | null> {
  const id = normalizePrtfId(rawId);
  if (!id) return null;
  const hit = bodies.get(id);
  if (hit) return hit;
  const body = await fetchJsonAsset<PrtfBody>(assets, `${ROOT}/techniques/${id}.json`, 'https://prtf.local');
  if (!body) return null;
  if (bodies.size > 120) bodies.clear();
  bodies.set(id, body);
  return body;
}

export interface PrtfFilter {
  tactic?: string;
  q?: string;
  limit?: number;
}

export function filterPrtfTechniques(index: PrtfIndex, opts: PrtfFilter = {}): PrtfTechnique[] {
  const { tactic, q, limit = 200 } = opts;
  const t = tactic?.trim().toUpperCase();
  const needle = q?.trim().toLowerCase();
  const out: PrtfTechnique[] = [];
  for (const row of index.techniques) {
    if (t && row.tacticId.toUpperCase() !== t && row.tacticName.toUpperCase() !== t) continue;
    if (needle && !`${row.id} ${row.name} ${row.summary} ${row.tacticName}`.toLowerCase().includes(needle)) continue;
    out.push(row);
    if (out.length >= limit) break;
  }
  return out;
}

export function prtfCacheStats(): { loaded: boolean; bodies: number; techniques: number } {
  return { loaded: cached !== null, bodies: bodies.size, techniques: cached?.techniques.length ?? 0 };
}

export function _resetPrtfCacheForTests(): void {
  cached = null;
  bodies.clear();
}
