import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { notFound, badGateway, respondError } from '../lib/api-error';
import { load as loadYaml } from 'js-yaml';

/**
 * ATLAS technique lookup.
 *
 * Upstream contract (2026-10): `mitre-atlas/atlas-data` no longer publishes a
 * STIX JSON bundle — `atlas_json/atlas.json` 404s, so every lookup answered
 * `atlas_upstream 404`. Current releases are the ATLAS v6 YAML documents in
 * `dist/v6/ATLAS-<YYYY.MM>.yaml`, and `dist/v6/ATLAS-latest.yaml` is a
 * SYMLINK: raw.githubusercontent.com serves the symlink's target TEXT, not
 * its content, so the pointer is resolved explicitly before the data fetch.
 *
 * v6 shape (all we consume):
 *   techniques:    { "AML.T0000": { name, description, ... } }
 *   tactics:       { "AML.TA0002": { name, ... } }
 *   relationships: { "AML.T0000": { achieves:    [{ target: "AML.TA0002" }],
 *                                    specializes: [{ target: "AML.T0000" }] } }
 *
 * Parsing the ~840 KB YAML costs ~330 ms CPU, so only the EXTRACTED INDEX is
 * cached: in-memory per isolate for a day, and in KV_CACHE so a fresh isolate
 * pays the parse at most once a week.
 */
const ATLAS_LATEST_POINTER_URL =
  'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-latest.yaml';
const ATLAS_V6_BASE = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6';
const ATLAS_INDEX_KV_KEY = 'atlas:technique-index:v1';
const ATLAS_INDEX_KV_TTL_S = 7 * 24 * 3600;

interface AtlasTechnique {
  id: string;
  name: string;
  description: string;
  tactic: string | null;
  tacticId: string | null;
  url: string;
}

interface TechniqueLookupResponse {
  technique: AtlasTechnique | null;
  relatedTechniques: string[];
  error?: string;
}

const CACHE_TTL = 86400;

/** Response-relevant fields per technique, keyed by the dotted AML id. */
interface AtlasIndexEntry {
  name: string;
  description: string;
  /** Tactic display name, resolved from `relationships[].achieves`. */
  tactic: string | null;
  /** Tactic id (`AML.TAxxxx`). */
  tacticId: string | null;
  /** Parent technique id for sub-techniques (`specializes` target). */
  parent: string | null;
}

type AtlasIndex = Record<string, AtlasIndexEntry>;

/** The subset of the v6 document we read; everything else is ignored. */
interface AtlasV6Document {
  techniques?: Record<string, { name?: string; description?: string }>;
  tactics?: Record<string, { name?: string }>;
  relationships?: Record<
    string,
    {
      achieves?: Array<{ target?: string }>;
      specializes?: Array<{ target?: string }>;
    }
  >;
}

let atlasCache: { data: AtlasIndex; timestamp: number } | null = null;

class UpstreamError extends Error {
  constructor(
    public upstreamStatus: number,
    public retryAfter: string | null
  ) {
    super(`ATLAS API failed: ${upstreamStatus}`);
  }
}

function buildIndex(doc: AtlasV6Document): AtlasIndex {
  const tactics = doc.tactics ?? {};
  const rels = doc.relationships ?? {};
  const index: AtlasIndex = {};
  for (const [id, t] of Object.entries(doc.techniques ?? {})) {
    const rel = rels[id];
    const tacticId = rel?.achieves?.[0]?.target ?? null;
    index[id] = {
      name: t.name ?? '',
      description: t.description ?? '',
      tacticId,
      tactic: tacticId ? (tactics[tacticId]?.name ?? null) : null,
      parent: rel?.specializes?.[0]?.target ?? null,
    };
  }
  return index;
}

/**
 * Resolve the `ATLAS-latest.yaml` symlink and return the YAML text.
 *
 * The pointer's body is either the target FILENAME (today's behaviour on
 * raw.githubusercontent.com) or the YAML itself (if GitHub ever follows
 * symlinks on raw) — both are handled.
 */
async function fetchAtlasYaml(): Promise<string> {
  const pointerRes = await fetch(ATLAS_LATEST_POINTER_URL, { signal: AbortSignal.timeout(30_000) });
  if (!pointerRes.ok) {
    throw new UpstreamError(pointerRes.status, pointerRes.headers.get('retry-after'));
  }
  const pointerBody = await pointerRes.text();
  const trimmed = pointerBody.trim();
  if (/^[A-Za-z0-9._-]+\.ya?ml$/.test(trimmed)) {
    const res = await fetch(`${ATLAS_V6_BASE}/${trimmed}`, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) {
      throw new UpstreamError(res.status, res.headers.get('retry-after'));
    }
    return res.text();
  }
  return pointerBody;
}

async function fetchAtlasIndex(kv: KVNamespace | undefined): Promise<AtlasIndex> {
  if (atlasCache && Date.now() - atlasCache.timestamp < CACHE_TTL * 1000) {
    return atlasCache.data;
  }
  if (kv) {
    try {
      const cached = await kv.get(ATLAS_INDEX_KV_KEY);
      if (cached) {
        const parsed = JSON.parse(cached) as AtlasIndex;
        atlasCache = { data: parsed, timestamp: Date.now() };
        return parsed;
      }
    } catch (err) {
      logError('atlas index KV read failed', err);
    }
  }
  const yamlText = await fetchAtlasYaml();
  const doc = loadYaml(yamlText) as AtlasV6Document | undefined;
  const index = buildIndex(doc ?? {});
  if (Object.keys(index).length === 0) {
    throw new Error('ATLAS document contained no techniques');
  }
  atlasCache = { data: index, timestamp: Date.now() };
  if (kv) {
    // Best-effort persistence so a fresh isolate reuses this instead of
    // paying the ~330 ms YAML parse again. A lost write only costs CPU.
    await kv.put(ATLAS_INDEX_KV_KEY, JSON.stringify(index), { expirationTtl: ATLAS_INDEX_KV_TTL_S }).catch(() => {});
  }
  return index;
}

export async function atlasTechniqueHandler(c: Context<{ Bindings: Env }>) {
  const q = c.req.query('technique') ?? c.req.query('t') ?? c.req.query('q');
  if (!q) {
    return respondError(c, 'missing technique param (e.g. AML-T1234)', 'technique parameter is required', 400);
  }

  // Accept BOTH our local dash format (`AML-T0000`, used by the static
  // matrix in `src/data/dfir/atlas-matrix.ts`) AND MITRE's upstream dot
  // format (`AML.T0000`). The v6 document keys techniques by the dot form,
  // so lookups are canonicalised to dots below.
  const techniqueId = q.toUpperCase();
  if (!techniqueId.match(/^AML[-.]T\d{4}(\.\d{3})?$/i)) {
    return respondError(
      c,
      'invalid ATLAS technique ID (expected AML-T0000 or AML.T0000)',
      'technique ID format is invalid',
      400
    );
  }
  // Canonicalise both forms — `AML-T0000.001` → `AML.T0000.001` for the lookup.
  const techniqueIdDot = techniqueId.replace(/^AML-/, 'AML.');

  let index: AtlasIndex;
  try {
    index = await fetchAtlasIndex(c.env.KV_CACHE);
  } catch (err) {
    logError('atlasTechniqueHandler failed', err);
    if (err instanceof UpstreamError) {
      const status = err.upstreamStatus === 429 ? 429 : 502;
      return c.json(
        { error: 'atlas_upstream', upstream: 'raw.githubusercontent.com', upstream_status: err.upstreamStatus },
        status,
        {
          ...(err.retryAfter
            ? { 'retry-after': err.retryAfter }
            : err.upstreamStatus === 429
              ? { 'retry-after': '60' }
              : {}),
          'cache-control': 'no-store',
        }
      );
    }
    if (err instanceof Error) console.warn('atlas fetch failed:', err.message);
    return badGateway(c, 'atlas_unreachable');
  }

  const entry = index[techniqueIdDot];
  if (!entry) {
    return notFound(c, 'technique not found');
  }

  // Related = this technique's specializations (sub-techniques) when it has
  // any, otherwise its parent plus the parent's other sub-techniques —
  // nearest neighbours first, still capped at 5 like the earlier response.
  const related: string[] = [];
  for (const [id, e] of Object.entries(index)) {
    if (e.parent === techniqueIdDot && id !== techniqueIdDot) related.push(id);
    if (related.length >= 5) break;
  }
  if (related.length === 0 && entry.parent) {
    related.push(entry.parent);
    for (const [id, e] of Object.entries(index)) {
      if (e.parent === entry.parent && id !== techniqueIdDot && id !== entry.parent) related.push(id);
      if (related.length >= 5) break;
    }
  }

  const response: TechniqueLookupResponse = {
    technique: {
      id: techniqueId,
      name: entry.name,
      description: entry.description.slice(0, 500),
      tactic: entry.tactic,
      tacticId: entry.tacticId,
      url: `https://atlas.mitre.org/techniques/${techniqueId}`,
    },
    relatedTechniques: related,
  };

  return c.json(response, 200, { 'Cache-Control': `public, max-age=${CACHE_TTL}` });
}
