import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { githubHeaders } from '../lib/github-api';
import { notFound, badGateway } from '../lib/api-error';
import { fetchResilient } from '../lib/fetch-resilient';
import { shouldWriteLastGood } from '../lib/lastgood-debounce';

/**
 * GET /api/v1/attack-flow-library
 *
 * Mirrors the Center for Threat-Informed Defense (CTID) Attack Flow corpus —
 * ~40 real-incident attack-flows (Black Basta, Conti, NotPetya, SolarWinds,
 * REvil, Equifax, Target, Uber, …) authored as Attack Flow Builder (`.afb`)
 * source and published as STIX 2.1 bundles. Public, key-gated read (NOT
 * admin-gated). Apache-2.0.
 *
 * DESIGN — manifest + on-demand (NO per-invocation fan-out):
 *
 *  • The corpus has NO single aggregate file; the flows live under the repo's
 *    `corpus/` directory. So the default request fetches ONE thing: the GitHub
 *    Contents API listing of `corpus/` (1 subrequest) and returns a *manifest*
 *    of available flows — name, size, sha, the GitHub source (`.afb`) URL, the
 *    human `html_url`, and the DERIVED published STIX 2.1 bundle URL on the
 *    project's GitHub Pages site. It does NOT fetch any of the ~40 bundles.
 *
 *  • `?flow=<name>` fetches+returns exactly ONE STIX 2.1 bundle on demand
 *    (1 extra subrequest). The name is matched case-insensitively against the
 *    manifest entries — we NEVER build the upstream path from the raw query
 *    (path-traversal / SSRF guard); the URL comes from the trusted manifest
 *    entry we resolved. The flow view is itself dual-cached per flow.
 *
 * Footguns honored: ONE upstream subrequest for the manifest refresh, ONE more
 * only when a single flow is explicitly requested (never the full corpus). KV
 * read only on miss; KV write debounced via shouldWriteLastGood in waitUntil.
 * NOT added to the /api/v1/snapshot composer (already near the 50-subrequest
 * cap). Untrusted upstream strings are length-capped, arrays coerced. Every
 * upstream URL echoed to the client is validated as http(s) by the page's
 * safeHref before it reaches an href.
 *
 * Attribution: the CTID Attack Flow project is Apache-2.0. We echo `source`,
 * `source_url`, and `license` in every response so attribution is structural,
 * and the UI credits + links back to CTID. Neutral framing only.
 */

// GitHub Contents API for the corpus directory. The corpus stores `.afb`
// (Attack Flow Builder) source; the matching STIX 2.1 `.json` bundles are
// published on the project's GitHub Pages site (see STIX_BASE below).
const MANIFEST_API = 'https://api.github.com/repos/center-for-threat-informed-defense/attack-flow/contents/corpus';
// Published STIX 2.1 bundle base (GitHub Pages). A `.afb` named "<Name>.afb"
// has its STIX export at "<STIX_BASE>/<Name>.json".
const STIX_BASE = 'https://center-for-threat-informed-defense.github.io/attack-flow/corpus';

const SOURCE = 'Center for Threat-Informed Defense — Attack Flow';
const SOURCE_URL = 'https://center-for-threat-informed-defense.github.io/attack-flow/';
const DEFAULT_LICENSE = 'Apache-2.0 — © Center for Threat-Informed Defense (MITRE Engenuity).';

// Manifest changes very slowly (new flows land over weeks) → long TTL.
const MANIFEST_CACHE_TTL_SECONDS = 6 * 60 * 60; // 6h
// A single resolved STIX bundle is immutable per commit → cache hard.
const FLOW_CACHE_TTL_SECONDS = 24 * 60 * 60; // 24h
const KV_LAST_GOOD_KEY = 'attack-flow-library:lastgood:v1';
const KV_LAST_GOOD_TTL_SECONDS = 14 * 24 * 60 * 60;

const MAX_ENTRIES = 500; // defensive cap on the untrusted directory listing (corpus is ~40)
const MAX_LIMIT = 500;
const MAX_BUNDLE_BYTES = 4_000_000; // a single corpus bundle is well under this
const MAX_BUNDLE_OBJECTS = 20_000; // structural cap before we hand objects to the client

interface FlowEntry {
  /** Display name, e.g. "Black Basta Ransomware" (the `.afb` basename). */
  name: string;
  /** Raw filename as it appears in the repo, e.g. "Black Basta Ransomware.afb". */
  filename: string;
  /** Byte size of the `.afb` source (from the Contents API `size` field). */
  size: number;
  /** Git blob sha (stable per revision). */
  sha: string;
  /** Human GitHub page for the `.afb` source. */
  html_url: string;
  /** Raw `.afb` source download URL (Attack Flow Builder format). */
  afb_url: string;
  /** Derived published STIX 2.1 bundle URL (machine-readable). */
  stix_url: string;
}

interface ManifestResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  /** Number of flows AFTER any query filter. */
  count: number;
  /** Total flows in the corpus BEFORE filtering. */
  total: number;
  flows: FlowEntry[];
  stale?: boolean;
  upstream_error?: string;
}

interface FlowBundleResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  flow: {
    name: string;
    filename: string;
    html_url: string;
    afb_url: string;
    stix_url: string;
  };
  /** The STIX 2.1 bundle exactly as published (objects length-capped). */
  bundle: {
    type: string;
    id: string;
    spec_version: string;
    objects: Array<Record<string, unknown>>;
  };
}

// Raw GitHub Contents API element shape (we read only what we need).
interface RawContentEntry {
  name?: unknown;
  size?: unknown;
  sha?: unknown;
  type?: unknown;
  html_url?: unknown;
  download_url?: unknown;
}

function asString(v: unknown, max = 4000): string {
  return typeof v === 'string' ? v.slice(0, max) : '';
}
function asNumber(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

/** Strip the `.afb` extension to get the display name + the STIX `.json` URL. */
function deriveFlow(raw: RawContentEntry): FlowEntry | null {
  if (asString(raw.type, 20) !== 'file') return null;
  const filename = asString(raw.name, 200);
  if (!filename.toLowerCase().endsWith('.afb')) return null; // ignore .gitignore etc.
  const base = filename.slice(0, -4); // drop ".afb"
  if (!base) return null;
  return {
    name: base,
    filename,
    size: asNumber(raw.size),
    sha: asString(raw.sha, 80),
    html_url: asString(raw.html_url, 600),
    afb_url: asString(raw.download_url, 600),
    // The published STIX export mirrors the basename with a `.json` extension.
    // encodeURIComponent handles spaces + parentheses in the corpus filenames.
    stix_url: `${STIX_BASE}/${encodeURIComponent(base)}.json`,
  };
}

/** Newest-irrelevant: corpus has no dates, so sort alphabetically (stable). */
function byName(a: FlowEntry, b: FlowEntry): number {
  return a.name.localeCompare(b.name);
}

/** Apply the optional manifest filters to a normalized full manifest. */
function applyFilters(full: ManifestResponse, q: { search?: string; limit?: number }): ManifestResponse {
  let flows = full.flows;
  if (q.search) {
    const s = q.search.toLowerCase();
    flows = flows.filter((f) => f.name.toLowerCase().includes(s));
  }
  if (typeof q.limit === 'number') flows = flows.slice(0, q.limit);
  return { ...full, flows, count: flows.length };
}

/** Build (or serve cached) the manifest of available flows — ONE upstream hit. */
async function loadManifest(
  c: Context<{ Bindings: Env }>
): Promise<{ full: ManifestResponse | null; stale: boolean; error: string }> {
  const kv = c.env.KV_CACHE;
  let upstreamError = '';

  try {
    const res = await fetchResilient(
      MANIFEST_API,
      {
        // GitHub Contents API requires the vnd.github+json Accept; the shared
        // githubHeaders() also attaches GITHUB_TOKEN when configured, because
        // an anonymous 403 here takes the entire corpus offline.
        headers: githubHeaders(c.env, { accept: 'application/vnd.github+json' }),
        cf: { cacheTtl: MANIFEST_CACHE_TTL_SECONDS, cacheEverything: true },
      } as RequestInit,
      { attempts: 3, timeoutMs: 15_000 }
    );
    if (res.ok) {
      const data = (await res.json()) as unknown;
      const rawList = Array.isArray(data) ? (data as RawContentEntry[]).slice(0, MAX_ENTRIES) : [];
      const flows = rawList
        .map((r) => deriveFlow((r ?? {}) as RawContentEntry))
        .filter((f): f is FlowEntry => f !== null)
        .sort(byName);
      const full: ManifestResponse = {
        source: SOURCE,
        source_url: SOURCE_URL,
        license: DEFAULT_LICENSE,
        generated_at: new Date().toISOString(),
        count: flows.length,
        total: flows.length,
        flows,
      };
      // Refresh KV last-good with the FULL manifest (debounced).
      if (kv && flows.length) {
        c.executionCtx.waitUntil(
          (async () => {
            if (await shouldWriteLastGood('attack-flow-library')) {
              await kv.put(KV_LAST_GOOD_KEY, JSON.stringify(full), {
                expirationTtl: KV_LAST_GOOD_TTL_SECONDS,
              });
            }
          })()
        );
      }
      return { full, stale: false, error: '' };
    }
    upstreamError = `upstream ${res.status}`;
  } catch (err) {
    logError('handler failed', err);
    upstreamError = err instanceof Error ? err.message : 'fetch failed';
  }

  // Upstream failed → serve KV last-good manifest, marked stale.
  if (kv) {
    try {
      const staleRaw = await kv.get(KV_LAST_GOOD_KEY);
      if (staleRaw) {
        const staleFull = JSON.parse(staleRaw) as ManifestResponse;
        return { full: staleFull, stale: true, error: upstreamError };
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* stale read failed; fall through */
    }
  }
  return { full: null, stale: false, error: upstreamError || 'no data' };
}

/** Fetch ONE STIX 2.1 bundle on demand (1 extra subrequest). */
async function loadFlowBundle(c: Context<{ Bindings: Env }>, entry: FlowEntry): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(
    `https://attack-flow-library-cache.internal/v1/flow?sha=${encodeURIComponent(entry.sha)}`
  );
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  let res: Response;
  try {
    res = await fetchResilient(
      entry.stix_url,
      {
        headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
        cf: { cacheTtl: FLOW_CACHE_TTL_SECONDS, cacheEverything: true },
      } as RequestInit,
      { attempts: 3, timeoutMs: 20_000 }
    );
  } catch (err) {
    logError('loadFlowBundle failed', err);
    return c.json(
      {
        error: 'Attack Flow bundle unavailable',
        message: err instanceof Error ? err.message : 'fetch failed',
        source: SOURCE,
        source_url: SOURCE_URL,
      },
      502,
      { 'Cache-Control': 'no-store' }
    );
  }

  if (!res.ok) {
    return c.json(
      {
        error: 'Attack Flow bundle unavailable',
        message: `upstream ${res.status}`,
        source: SOURCE,
        source_url: SOURCE_URL,
        // The repo `.afb` source is always reachable even if the STIX export 404s.
        afb_url: entry.afb_url,
      },
      res.status === 404 ? 404 : 502,
      { 'Cache-Control': 'no-store' }
    );
  }

  // Guard against an oversized body before parsing.
  const lenHeader = parseInt(res.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(lenHeader) && lenHeader > MAX_BUNDLE_BYTES) {
    return badGateway(c, 'Attack Flow bundle too large');
  }

  let parsed: { type?: unknown; id?: unknown; spec_version?: unknown; objects?: unknown };
  try {
    parsed = (await res.json()) as typeof parsed;
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return badGateway(c, 'Attack Flow bundle not valid JSON');
  }

  const rawObjects = Array.isArray(parsed.objects) ? (parsed.objects as unknown[]).slice(0, MAX_BUNDLE_OBJECTS) : [];
  const objects = rawObjects.map((o) => (o ?? {}) as Record<string, unknown>);

  const body: FlowBundleResponse = {
    source: SOURCE,
    source_url: SOURCE_URL,
    license: DEFAULT_LICENSE,
    generated_at: new Date().toISOString(),
    flow: {
      name: entry.name,
      filename: entry.filename,
      html_url: entry.html_url,
      afb_url: entry.afb_url,
      stix_url: entry.stix_url,
    },
    bundle: {
      type: asString(parsed.type, 40) || 'bundle',
      id: asString(parsed.id, 200),
      spec_version: asString(parsed.spec_version, 20),
      objects,
    },
  };

  const response = c.json(body, 200, {
    'Cache-Control': `public, max-age=${FLOW_CACHE_TTL_SECONDS}`,
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}

export async function attackFlowLibraryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const flowParam = c.req.query('flow')?.trim();
  const search = c.req.query('q')?.trim();
  const limitRaw = c.req.query('limit');
  const limit = limitRaw ? Math.min(parseInt(limitRaw, 10) || MAX_LIMIT, MAX_LIMIT) : undefined;

  // We always need the manifest: either to return it (default) or to RESOLVE
  // the requested flow to its trusted upstream URL (never build a path from the
  // raw query). The manifest is heavily cached, so this is ~free on a warm colo.
  // ── Single-flow on-demand path ─────────────────────────────────────────
  if (flowParam) {
    const { full } = await loadManifest(c);
    if (!full) {
      return c.json(
        {
          error: 'Attack Flow corpus listing unavailable',
          message: 'manifest fetch failed',
          source: SOURCE,
          source_url: SOURCE_URL,
        },
        502,
        { 'Cache-Control': 'no-store' }
      );
    }
    const wanted = flowParam.toLowerCase();
    const entry =
      full.flows.find((f) => f.name.toLowerCase() === wanted) ??
      full.flows.find((f) => f.filename.toLowerCase() === wanted);
    if (!entry) {
      return notFound(c, 'flow not found');
    }
    return loadFlowBundle(c, entry);
  }

  // ── Manifest path (default) — dual-cache by filter combo ───────────────
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(
    `https://attack-flow-library-cache.internal/v1/manifest?q=${search ?? ''}&lim=${limit ?? ''}`
  );
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const { full, stale, error } = await loadManifest(c);
  if (!full) {
    return c.json(
      {
        error: 'Attack Flow corpus listing unavailable',
        message: error,
        source: SOURCE,
        source_url: SOURCE_URL,
      },
      502,
      { 'Cache-Control': 'no-store' }
    );
  }

  const filterQ = { search, limit };
  if (stale) {
    const out = applyFilters(full, filterQ);
    return c.json({ ...out, stale: true, upstream_error: error }, 200, {
      'Cache-Control': 'public, max-age=300',
    });
  }

  const body = applyFilters(full, filterQ);
  const response = c.json(body, 200, {
    'Cache-Control': `public, max-age=${MANIFEST_CACHE_TTL_SECONDS}`,
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
