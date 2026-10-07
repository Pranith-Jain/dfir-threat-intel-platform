/**
 * Intel-bundle pipeline route.
 *
 * GET  /api/v1/intel-bundle?source=<id>&ref=<itemRef>
 *      → { bundle, view } from D1 (hit) or computed+persisted (miss).
 *
 * POST /api/v1/intel-bundle/build
 *      body: { mode: 'text' | 'iocs' | 'url', input: string, sourceName?: string, tlp?: 'WHITE'|'AMBER' }
 *      → { bundle, view } for ad-hoc input (the `/dfir/stix-builder` tool).
 *
 * Lazy-on-render at MVP. The first card render for a (source, ref) triggers:
 *   extract → bulk-enrich → stix-build → D1 INSERT (via waitUntil).
 * Subsequent reads hit D1 directly. Determ STIX IDs (UUIDv5 from
 * `lib/uuidv5.ts`) keep IDs stable across re-renders.
 *
 * Defensive boundary: combolist-style credentials are dropped by the
 * extractor and never enter the bundle. The URL-fetch mode is allowlisted.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { detectType, type IndicatorType } from '../lib/indicator';
import { extract, type ExtractedEntities } from '../lib/extract';
import { enrichBulk, type BulkEnrichResult } from '../lib/enrich-bulk';
import { enrichCves, type CveEnrichment } from '../lib/cve-enrich';
import { extractLlm, EMPTY_LLM_ENTITIES, type LlmEntities } from '../lib/extract-llm';
import { buildStixBundle, type BuildResult, type ReportInput, type Tlp } from '../lib/stix-build';
import { pinnedFetchFollow, SsrfError } from '../lib/ssrf-guard';
import { requireAdmin } from '../lib/admin-auth';
import { safeJsonBody } from '../lib/safe-body';
import { payloadTooLarge } from '../lib/api-error';

/** Distinguishes enrichment vs assembly failure for the 502 mapping. */
export class BundleBuildError extends Error {
  constructor(public code: 'enrichment_failed' | 'build_failed') {
    super(code);
    this.name = 'BundleBuildError';
  }
}

export const INTEL_BUNDLE_CACHE_KEY = 'https://intel-bundle-status.internal/v1';

const FETCH_BODY_MAX = 200 * 1024;
const FETCH_TIMEOUT = 10_000;
const FETCH_ALLOWED_PREFIXES = ['http://', 'https://'];

/** Sanity caps on POST inputs. */
const MAX_BRIEF_BYTES = 50 * 1024;
const MAX_IOC_LIST_LINES = 500;

interface IntelBundleRow {
  id: string;
  source_id: string;
  item_ref: string;
  report_id: string;
  title: string;
  published_at: string | null;
  extracted_hash: string;
  bundle_json: string;
  view_json: string;
  created_at: string;
  updated_at: string;
  ioc_count: number;
  actor_count: number;
  malware_count: number;
}

async function readBundle(db: D1Database, sourceId: string, itemRef: string): Promise<IntelBundleRow | null> {
  const row = await db
    .prepare(
      'SELECT id, source_id, item_ref, report_id, title, published_at, extracted_hash, bundle_json, view_json, created_at, updated_at, ioc_count, actor_count, malware_count FROM intel_bundles WHERE source_id = ? AND item_ref = ? LIMIT 1'
    )
    .bind(sourceId, itemRef)
    .first<IntelBundleRow>();
  return row ?? null;
}

/**
 * Publish a tiny status snapshot to the edge cache so `feed-status.ts` can
 * observe the pipeline's health without a D1 query of its own. Called from
 * `writeBundle` via waitUntil — best-effort; never blocks the bundle write.
 *
 * The `last_*` fields carry the bulk-enrichment stats from the most recent
 * build so feed-status can tell whether the MAX_FRESH_SUBREQUESTS=35 cap is
 * biting in production. `last_dropped_subrequests` is the number of
 * provider lookups skipped because the per-invocation budget was exhausted
 * — sustained nonzero values are the signal to retune the cap or split the
 * pipeline.
 */
async function publishStatusSnapshot(
  db: D1Database,
  latest: { id: string; updated_at: string },
  bulkStats: {
    freshSubrequests: number;
    droppedSubrequests: number;
    partial: boolean;
    overflow: number;
  }
): Promise<void> {
  try {
    // Throttle: if a snapshot is already cached, it is at most TTL old, and the
    // only consumer (feed-status) reads it through that same cache. Recomputing
    // on every bundle write bought nothing observable while costing a full scan
    // of intel_bundles — a table whose every row carries a full STIX 2.1
    // bundle_json blob — per write. This turns a per-write table scan into at
    // most one per cache TTL per colo, and is self-tuning: if the cache is cold
    // or missing we simply fall through and refresh, so worst case equals the
    // old behaviour.
    //
    // The cache entry is written below with `public, max-age=600`, so a hit
    // here means the cached snapshot cannot be older than 10 minutes.
    //
    // The match is guarded separately and fails OPEN: if the cache API itself
    // throws we must still refresh, otherwise a cache-layer fault would
    // silently freeze the status panel at whatever it last held.
    let snapshotIsFresh = false;
    try {
      snapshotIsFresh = (await caches.default.match(new Request(INTEL_BUNDLE_CACHE_KEY))) !== undefined;
    } catch {
      snapshotIsFresh = false;
    }
    if (snapshotIsFresh) return;

    const totals = await db
      .prepare(
        `SELECT COUNT(*) as total,
                SUM(ioc_count) as ioc_total,
                SUM(actor_count) as actor_total,
                SUM(malware_count) as malware_total
           FROM intel_bundles`
      )
      .first<{ total: number; ioc_total: number; actor_total: number; malware_total: number }>();
    const body = {
      generated_at: new Date().toISOString(),
      latest_bundle_id: latest.id,
      latest_updated_at: latest.updated_at,
      bundles: totals?.total ?? 0,
      ioc_total: totals?.ioc_total ?? 0,
      actor_total: totals?.actor_total ?? 0,
      malware_total: totals?.malware_total ?? 0,
      last_fresh_subrequests: bulkStats.freshSubrequests,
      last_dropped_subrequests: bulkStats.droppedSubrequests,
      last_partial: bulkStats.partial,
      last_overflow: bulkStats.overflow,
    };
    await caches.default.put(
      new Request(INTEL_BUNDLE_CACHE_KEY),
      new Response(JSON.stringify(body), {
        headers: {
          'content-type': 'application/json',
          'cache-control': 'public, max-age=600',
        },
      })
    );
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* best-effort; feed-status falls back to 'cold' */
  }
}

async function writeBundle(
  db: D1Database,
  built: BuildResult,
  report: ReportInput,
  bulk: BulkEnrichResult
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO intel_bundles
         (id, source_id, item_ref, report_id, title, published_at,
          extracted_hash, bundle_json, view_json, ioc_count, actor_count, malware_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         updated_at = datetime('now'),
         extracted_hash = excluded.extracted_hash,
         bundle_json = excluded.bundle_json,
         view_json = excluded.view_json,
         ioc_count = excluded.ioc_count,
         actor_count = excluded.actor_count,
         malware_count = excluded.malware_count
       WHERE intel_bundles.extracted_hash != excluded.extracted_hash`
    )
    .bind(
      built.bundle.id,
      report.sourceId,
      report.itemRef,
      built.view.reportId,
      built.view.title,
      report.publishedAt ?? null,
      built.view.extractedHash,
      JSON.stringify(built.bundle),
      JSON.stringify(built.view),
      built.view.iocs.length,
      built.view.threatActors.length,
      built.view.malware.length
    )
    .run();
  await publishStatusSnapshot(
    db,
    { id: built.bundle.id, updated_at: new Date().toISOString() },
    {
      freshSubrequests: bulk.freshSubrequests,
      droppedSubrequests: bulk.droppedSubrequests,
      partial: bulk.partial,
      overflow: bulk.overflow.length,
    }
  );
}

async function pipeline(
  report: ReportInput,
  env: Env
): Promise<
  BuildResult & {
    bulk: BulkEnrichResult;
    entities: ExtractedEntities;
    cveEnrichments: Map<string, CveEnrichment>;
  }
> {
  const entities = extract(report.title, report.body);
  // Bulk IoC enrichment, CVE enrichment, and LLM extraction are independent
  // — fan them out. Each is best-effort: failures leave the corresponding
  // arrays empty and the bundle still ships.
  //
  // The LLM call was previously omitted from the on-demand pipeline (only
  // the cron warmer invoked it), so STIX-builder ad-hoc inputs got no
  // sectors / affected products / candidate actors. Wiring it in here means
  // /dfir/stix-builder, cache-miss renders, and the build route all get
  // the same enrichment shape — the warmer's `.catch()` boundary inside
  // extractLlm prevents a stalled LLM from blocking the bundle.
  const [bulk, cveEnrichments, llmEntities] = await Promise.all([
    enrichBulk(
      entities.iocs.map((i) => ({ type: i.type, value: i.value })),
      env
    ),
    enrichCves(entities.cves),
    extractLlm(report.title, report.body, entities, env).catch(() => ({
      ...EMPTY_LLM_ENTITIES,
      ran: false,
      partial: false,
    })),
  ]);
  const built = await buildStixBundle(report, entities, bulk, cveEnrichments, llmEntities);
  return { ...built, bulk, entities, cveEnrichments };
}

function jsonResponse<T>(c: Context<{ Bindings: Env }>, body: T, status = 200, ccSeconds = 0): Response {
  const headers: Record<string, string> = { 'content-type': 'application/json; charset=utf-8' };
  if (ccSeconds > 0) headers['cache-control'] = `public, max-age=${ccSeconds}, s-maxage=${ccSeconds}`;
  else headers['cache-control'] = 'no-store';
  return new Response(JSON.stringify(body), { status, headers });
}

/** Friendly source-name guessing for surfaces that just supply `source=rss:host`. */
function deriveSourceName(sourceId: string): string {
  if (sourceId.startsWith('rss:')) return sourceId.slice(4);
  if (sourceId.startsWith('telegram:')) return `Telegram: ${sourceId.slice(9)}`;
  if (sourceId.startsWith('reddit:')) return `r/${sourceId.slice(7)}`;
  if (sourceId.startsWith('darkweb:')) return `Dark Web: ${sourceId.slice(8)}`;
  if (sourceId.startsWith('breach-forums:')) return `Breach Forums: ${sourceId.slice(14)}`;
  switch (sourceId) {
    case 'briefings':
      return 'Briefings';
    case 'todays-read':
      return "Today's Read";
    case 'tool':
      return 'STIX Builder (manual)';
    default:
      return sourceId;
  }
}

// ============================================================
// GET /api/v1/intel-bundle
// ============================================================

export async function intelBundleHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const sourceId = (c.req.query('source') ?? '').trim();
  const itemRef = (c.req.query('ref') ?? '').trim();
  const title = (c.req.query('title') ?? '').trim();
  const body = (c.req.query('body') ?? '').trim();
  const publishedAt = c.req.query('publishedAt') ?? null;

  if (!sourceId || !itemRef) {
    return jsonResponse(c, { error: 'missing source or ref' }, 400);
  }

  const db = c.env.BRIEFINGS_DB;
  if (!db) {
    return jsonResponse(c, { error: 'persistence_unavailable' }, 503);
  }

  // Cache hit: serve directly.
  const row = await readBundle(db, sourceId, itemRef);
  if (row) {
    try {
      return jsonResponse(
        c,
        { bundle: JSON.parse(row.bundle_json), view: JSON.parse(row.view_json), cache: 'hit' },
        200,
        300
      );
    } catch (_catchErr) {
      logError('intelBundleHandler failed', _catchErr);
      // Corrupt row — fall through to recompute below.
    }
  }

  // Miss: caller must supply title+body inline (GET keeps the API stateless
  // and lets the frontend pass exactly what the user sees on the page).
  if (!title || !body) {
    return jsonResponse(
      c,
      {
        error: 'cache_miss',
        message:
          'No persisted bundle for this (source, ref). Re-call with `title` and `body` query params to compute and persist.',
      },
      404
    );
  }

  const report: ReportInput = {
    sourceId,
    sourceName: deriveSourceName(sourceId),
    itemRef,
    title,
    body,
    url: /^https?:\/\//i.test(itemRef) ? itemRef : undefined,
    publishedAt,
    tlp: 'WHITE',
  };

  const built = await pipeline(report, c.env);

  c.executionCtx.waitUntil(
    writeBundle(db, built, report, built.bulk).catch(() => {
      /* persistence failure is non-fatal: next render re-computes (idempotent) */
    })
  );

  return jsonResponse(c, { bundle: built.bundle, view: built.view, cache: 'miss' }, 200, 300);
}

// ============================================================
// POST /api/v1/intel-bundle
// (cache-miss compute path for aggregate cards / large bodies)
// ============================================================

interface BundlePostBody {
  source: string;
  ref: string;
  title?: string;
  body?: string;
  publishedAt?: string | null;
}

/** Loose ISO-8601 sniff: full date or RFC3339 timestamp. Rejects "foo".
 *  We don't need strict parsing — the STIX `report.published` field just
 *  has to round-trip through Date.parse() reliably. */
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

function parseBundlePostBody(body: unknown): BundlePostBody | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;
  if (typeof b.source !== 'string' || !b.source.trim()) return null;
  if (typeof b.ref !== 'string' || !b.ref.trim()) return null;
  // Validate publishedAt — bogus strings would leak into STIX `report.published`
  // and break consumers that strict-parse it.
  let publishedAt: string | null = null;
  if (typeof b.publishedAt === 'string' && b.publishedAt && ISO_TIMESTAMP_RE.test(b.publishedAt)) {
    publishedAt = b.publishedAt;
  }
  return {
    source: b.source.trim(),
    ref: b.ref.trim(),
    title: typeof b.title === 'string' ? b.title : undefined,
    body: typeof b.body === 'string' ? b.body : undefined,
    publishedAt,
  };
}

/**
 * Cache-miss compute path that takes title/body in a POST body instead of
 * the URL. Used by the aggregate-card hook on /threatintel pages where the
 * pooled-item body easily blows past Cloudflare's ~16 KB URL limit. Same
 * semantics as `GET /api/v1/intel-bundle?source=...&ref=...&title=...&body=...`
 * — D1 hit returns directly; on miss computes + persists + returns.
 */
export async function intelBundlePostHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  let parsed: unknown;
  try {
    parsed = await c.req.json();
  } catch (_catchErr) {
    logError('intelBundlePostHandler failed', _catchErr);
    return jsonResponse(c, { error: 'invalid_json' }, 400);
  }
  const body = parseBundlePostBody(parsed);
  if (!body) return jsonResponse(c, { error: 'invalid_body' }, 400);

  // Cap body size — aggregate cards POST up to ~45KB of pooled feed text;
  // anything past the 50KB build-mode limit is rejected so a malicious
  // client can't fill D1 with multi-MB bundles. Title + body checked
  // independently so a tiny title with a giant body still fails.
  const titleBytes = (body.title ?? '').length;
  const bodyBytes = (body.body ?? '').length;
  if (titleBytes + bodyBytes > MAX_BRIEF_BYTES) {
    return jsonResponse(c, { error: 'input_too_large', limit_bytes: MAX_BRIEF_BYTES }, 413);
  }

  const db = c.env.BRIEFINGS_DB;
  if (!db) return jsonResponse(c, { error: 'persistence_unavailable' }, 503);

  // D1 hit short-circuit — same as the GET path.
  const row = await readBundle(db, body.source, body.ref);
  if (row) {
    try {
      return jsonResponse(
        c,
        { bundle: JSON.parse(row.bundle_json), view: JSON.parse(row.view_json), cache: 'hit' },
        200,
        300
      );
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* corrupt row — recompute below */
    }
  }

  if (!body.title || !body.body) {
    return jsonResponse(c, { error: 'cache_miss', message: 'POST title and body to compute and persist.' }, 404);
  }

  const report: ReportInput = {
    sourceId: body.source,
    sourceName: deriveSourceName(body.source),
    itemRef: body.ref,
    title: body.title,
    body: body.body,
    url: /^https?:\/\//i.test(body.ref) ? body.ref : undefined,
    publishedAt: body.publishedAt ?? null,
    tlp: 'WHITE',
  };

  const built = await pipeline(report, c.env);
  c.executionCtx.waitUntil(
    writeBundle(db, built, report, built.bulk).catch(() => {
      /* non-fatal */
    })
  );
  return jsonResponse(c, { bundle: built.bundle, view: built.view, cache: 'miss' }, 200, 300);
}

// ============================================================
// POST /api/v1/intel-bundle/build
// ============================================================

interface BuildBody {
  mode: 'text' | 'iocs' | 'url';
  input: string;
  sourceName?: string;
  tlp?: Tlp;
}

function parseBuildBody(body: unknown): BuildBody | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;
  const mode = b.mode;
  if (mode !== 'text' && mode !== 'iocs' && mode !== 'url') return null;
  if (typeof b.input !== 'string' || !b.input.trim()) return null;
  const sourceName = typeof b.sourceName === 'string' ? b.sourceName.trim() : undefined;
  const tlp = b.tlp === 'WHITE' || b.tlp === 'AMBER' ? b.tlp : 'AMBER';
  return { mode, input: b.input, sourceName, tlp };
}

/** Build a synthetic body+title for IoC-list mode that exercises the same pipeline. */
function fromIocList(input: string): { title: string; body: string } {
  const lines = input
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, MAX_IOC_LIST_LINES);
  // Optional `value | context` per-line syntax used by the tool's IoC mode.
  const parts = lines.map((l) => {
    const [val, ...rest] = l.split('|').map((s) => s.trim());
    return rest.length > 0 && val ? `${val} (${rest.join(' ').slice(0, 200)})` : (val ?? l);
  });
  return {
    title: `STIX builder — ${lines.length} indicators`,
    body: parts.join('\n'),
  };
}

async function fromUrlFetch(url: string): Promise<{ title: string; body: string; url: string }> {
  if (!FETCH_ALLOWED_PREFIXES.some((p) => url.toLowerCase().startsWith(p))) {
    throw new Error('unsupported_scheme');
  }
  const res = await pinnedFetchFollow(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; pranithjain-stix-builder/1.0; +https://pranithjain.qzz.io)',
      Accept: 'text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5',
    },
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
    // Hono Context types don't know about CF-specific request options, but
    // `pinnedFetch` validates and rewrites these. Cast through unknown.
  } as unknown as RequestInit);
  if (!res.ok) throw new Error(`fetch_failed:${res.status}`);
  const text = await res.text();
  const trimmed = text.slice(0, FETCH_BODY_MAX);
  // Best-effort title extraction. We deliberately don't pull in an HTML parser
  // here — the extractor doesn't need clean prose, just raw text it can match
  // entities against.
  const titleMatch = trimmed.match(/<title[^>]*>([\s\S]{1,400}?)<\/title>/i);
  const title = titleMatch?.[1]?.replace(/\s+/g, ' ').trim() || url;
  // Strip script/style + tags to keep extraction signal-to-noise high.
  const body = trimmed
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return { title, body, url };
}

/**
 * Shared STIX assembly core: given a ReportInput (and optional pre-detected
 * IoCs from list-mode), run extraction → enrichment fan-out → buildStixBundle,
 * persist to D1 (non-fatal), and return the BuildResult. Throws BundleBuildError
 * on enrichment/assembly failure so callers can map to 502.
 */
export async function buildBundleFromReport(
  c: Context<{ Bindings: Env }>,
  report: ReportInput,
  extraIocs: { type: IndicatorType; value: string }[] = []
): Promise<BuildResult> {
  const entities = extract(report.title, report.body);
  if (extraIocs.length) {
    const seen = new Set(entities.iocs.map((i) => `${i.type}|${i.value.toLowerCase()}`));
    for (const i of extraIocs) {
      const k = `${i.type}|${i.value.toLowerCase()}`;
      if (!seen.has(k)) {
        entities.iocs.push(i);
        seen.add(k);
      }
    }
  }

  let bulk: Awaited<ReturnType<typeof enrichBulk>> = {
    enrichments: [],
    partial: false,
    overflow: [],
    freshSubrequests: 0,
    droppedSubrequests: 0,
  };
  let cveEnrichments = new Map<string, CveEnrichment>();
  let llmEntities: LlmEntities = { ...EMPTY_LLM_ENTITIES };
  try {
    [bulk, cveEnrichments, llmEntities] = await Promise.all([
      enrichBulk(
        entities.iocs.map((i) => ({ type: i.type, value: i.value })),
        c.env
      ),
      enrichCves(entities.cves),
      extractLlm(report.title, report.body, entities, c.env).catch(() => ({
        ...EMPTY_LLM_ENTITIES,
        ran: false,
        partial: false,
      })),
    ]);
  } catch (err) {
    logError('STIX build enrichment phase failed:', err);
    throw new BundleBuildError('enrichment_failed');
  }

  let built: BuildResult;
  try {
    built = await buildStixBundle(report, entities, bulk, cveEnrichments, llmEntities);
  } catch (err) {
    logError('STIX build bundle assembly failed:', err);
    throw new BundleBuildError('build_failed');
  }

  const db = c.env.BRIEFINGS_DB;
  if (db) {
    c.executionCtx.waitUntil(
      writeBundle(db, built, report, bulk).catch(() => {
        /* persistence failure is non-fatal */
      })
    );
  }
  return built;
}

export async function intelBundleBuildHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const parsedResult = await safeJsonBody<unknown>(c, { maxBytes: 60 * 1024, maxDepth: 6 });
  if ('error' in parsedResult) return parsedResult.error;

  const body = parseBuildBody(parsedResult.value);
  if (!body) return jsonResponse(c, { error: 'invalid_body' }, 400);

  let inputTitle = '';
  let inputBody = '';
  let inputUrl: string | undefined;

  try {
    if (body.mode === 'text') {
      const first = body.input.split(/\r?\n/, 1)[0] ?? '';
      inputTitle = first.length > 0 && first.length <= 200 ? first : 'STIX builder — manual brief';
      inputBody = body.input;
    } else if (body.mode === 'iocs') {
      const ioc = fromIocList(body.input);
      inputTitle = ioc.title;
      inputBody = ioc.body;
    } else if (body.mode === 'url') {
      const fetched = await fromUrlFetch(body.input.trim());
      inputTitle = fetched.title;
      inputBody = fetched.body;
      inputUrl = fetched.url;
    }
  } catch (err) {
    logError('intelBundleBuildHandler failed', err);
    if (err instanceof SsrfError) {
      return jsonResponse(c, { error: 'ssrf_blocked', detail: 'blocked' }, 400);
    }
    return jsonResponse(c, { error: 'input_processing_failed', detail: 'processing error' }, 400);
  }

  // For IoC mode where the extractor wouldn't naturally classify a flat list
  // (no surrounding text), seed the entity set by walking each line through
  // `detectType` directly so the indicator objects still emit.
  const preIocs: { type: IndicatorType; value: string }[] = [];
  if (body.mode === 'iocs') {
    const lines = body.input
      .split(/\r?\n/)
      .map((l) => l.split('|')[0]?.trim() ?? '')
      .filter(Boolean)
      .slice(0, MAX_IOC_LIST_LINES);
    for (const l of lines) {
      const t = detectType(l);
      if (t !== 'unknown') preIocs.push({ type: t, value: l });
    }
  }

  const report: ReportInput = {
    sourceId: 'tool',
    sourceName: body.sourceName?.trim() || (body.mode === 'url' ? 'Tool: URL fetch' : 'STIX Builder (manual)'),
    itemRef: await deriveToolItemRef(body),
    title: inputTitle,
    body: inputBody,
    url: inputUrl,
    publishedAt: new Date().toISOString(),
    tlp: body.tlp ?? 'AMBER',
  };

  let built: BuildResult;
  try {
    built = await buildBundleFromReport(c, report, preIocs);
  } catch (err) {
    logError('handler failed', err);
    if (err instanceof BundleBuildError) {
      return jsonResponse(c, { error: err.code }, 502);
    }
    return jsonResponse(c, { error: 'build_failed' }, 502);
  }
  return jsonResponse(c, { bundle: built.bundle, view: built.view, cache: 'computed' }, 200);
}

// ============================================================
// GET /api/v1/intel-bundle/by-id/:bundleId
//   Lookup a persisted bundle by its deterministic STIX bundle ID and
//   return `{ bundle, view }` so the frontend deep-link view can render
//   it without knowing the original (source, ref) pair. Public — same
//   audience as the on-demand card.
// ============================================================

export async function intelBundleByIdHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const id = c.req.param('bundleId') ?? '';
  if (!BUNDLE_ID_RE.test(id)) {
    return jsonResponse(c, { error: 'invalid_bundle_id' }, 400);
  }
  const db = c.env.BRIEFINGS_DB;
  if (!db) return jsonResponse(c, { error: 'persistence_unavailable' }, 503);

  const row = await db
    .prepare('SELECT bundle_json, view_json FROM intel_bundles WHERE id = ? LIMIT 1')
    .bind(id)
    .first<{ bundle_json: string; view_json: string }>();
  if (!row) return jsonResponse(c, { error: 'not_found' }, 404);

  try {
    return jsonResponse(
      c,
      {
        bundle: JSON.parse(row.bundle_json),
        view: JSON.parse(row.view_json),
        cache: 'hit',
      },
      200,
      300
    );
  } catch (_catchErr) {
    logError('intelBundleByIdHandler failed', _catchErr);
    return jsonResponse(c, { error: 'corrupt_view_json' }, 500);
  }
}

// ============================================================
// GET /api/v1/intel-bundle/:id/export.stix.json
//   Content-addressable download of the persisted STIX 2.1 bundle.
//   `:id` is the bundle's deterministic UUIDv5 (`bundle--<uuid>`), so the
//   URL is stable across re-renders and the same input always yields the
//   same download URL. Public — the bundle content is already visible via
//   the card; this just re-serves it as a strict, standards-compliant
//   STIX 2.1 download for MISP/OpenCTI/TAXII consumers.
// ============================================================

const BUNDLE_ID_RE = /^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Hard cap on the export payload. STIX 2.1 bundles are JSON and D1
 * stores them as TEXT — a single bundle could be tens of MB if the
 * extractor ever fed a multi-MB document into the pipeline. Returning
 * a 5 MB+ body from a single Worker response pins the isolate memory
 * budget (128 MB) and the streaming response path that downstream
 * TAXII clients rely on. 5 MB is well above the realistic 99th
 * percentile (≤200 KB) and still below the Worker free-tier per-
 * response memory cap.
 */
const EXPORT_MAX_BYTES = 5 * 1024 * 1024;

export async function intelBundleExportHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const id = c.req.param('id') ?? '';
  if (!BUNDLE_ID_RE.test(id)) {
    return jsonResponse(c, { error: 'invalid_bundle_id' }, 400);
  }
  const db = c.env.BRIEFINGS_DB;
  if (!db) return jsonResponse(c, { error: 'persistence_unavailable' }, 503);

  const row = await db
    .prepare('SELECT bundle_json, LENGTH(bundle_json) as size_bytes FROM intel_bundles WHERE id = ? LIMIT 1')
    .bind(id)
    .first<{ bundle_json: string; size_bytes: number }>();
  if (!row) return jsonResponse(c, { error: 'not_found' }, 404);

  // Size cap before materialising the body. A bundle that grew past
  // EXPORT_MAX_BYTES almost certainly means a runaway extractor loop,
  // not a legitimate analyst export — short-circuit with 413 and a
  // pointer to the underlying source so the operator can inspect it
  // directly via the card.
  if (row.size_bytes > EXPORT_MAX_BYTES) {
    return payloadTooLarge(c, 'bundle exceeds export size cap; inspect the source record via the intel-bundle card', {
      size_bytes: row.size_bytes,
      max_bytes: EXPORT_MAX_BYTES,
    });
  }

  // `application/stix+json` is the IANA-registered media type for STIX 2.1.
  // Strict consumers (MISP/OpenCTI/TAXII clients) sniff on it. Adding the
  // `version=2.1` parameter is a no-op for tools that don't care and a
  // useful hint for those that do.
  // ACAO:* so the URL works from analyst tools or other origins.
  const filename = `${id}.stix.json`;
  return new Response(row.bundle_json, {
    status: 200,
    headers: {
      'content-type': 'application/stix+json; version=2.1',
      'content-disposition': `attachment; filename="${filename}"`,
      'content-length': String(row.size_bytes),
      // Bundle JSON for a given id is immutable in practice (extracted_hash
      // re-writes the row but the id stays the same; the json may change
      // when the row is updated). 1h cache is the same TTL the card uses.
      'cache-control': 'public, max-age=3600',
      'access-control-allow-origin': '*',
      'x-content-type-options': 'nosniff',
    },
  });
}

async function deriveToolItemRef(b: BuildBody): Promise<string> {
  const buf = new TextEncoder().encode(`${b.mode}|${b.input}`);
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  let hex = '';
  for (let i = 0; i < 12; i++) hex += d[i]!.toString(16).padStart(2, '0');
  return `tool:${b.mode}:${hex}`;
}

// ============================================================
// GET /api/v1/admin/intel-bundle/:source/:ref
//   Admin-only introspection for the LLM enrichment slice of a persisted
//   bundle. Returns just the LLM-relevant view fields so an operator can
//   verify the warmer is landing data without hand-parsing the full
//   STIX bundle JSON. Gated by `X-Admin-Token: <ADMIN_TOKEN>`; fails
//   closed when the token is unset.
//
//   Examples:
//     curl -H "X-Admin-Token: $T" \
//       https://pranithjain.qzz.io/api/v1/admin/intel-bundle/briefings/daily-2026-05-22
//     curl -H "X-Admin-Token: $T" \
//       https://pranithjain.qzz.io/api/v1/admin/intel-bundle/telegram:cti/<encoded-ref>
// ============================================================

interface AdminInspectShape {
  source: { id: string; name: string };
  title: string;
  bundleId: string;
  reportId: string;
  generatedAt: string;
  extractedHash: string;
  counts: { iocs: number; threatActors: number; malware: number; cves: number };
  sectors: string[];
  affectedProducts: { vendor: string; product: string }[];
  attackPatterns: { name: string; mitreId: string }[];
  actorCandidates: { name: string; rationale: string }[];
  malwareCandidates: { name: string; rationale: string }[];
  llmEnrichment: { ran: boolean; partial: boolean; modelUsed?: string };
}

export async function intelBundleAdminHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;

  const source = (c.req.param('source') ?? '').trim();
  const ref = (c.req.param('ref') ?? '').trim();
  if (!source || !ref) return jsonResponse(c, { error: 'missing source or ref' }, 400);

  const db = c.env.BRIEFINGS_DB;
  if (!db) return jsonResponse(c, { error: 'persistence_unavailable' }, 503);

  const row = await db
    .prepare('SELECT view_json FROM intel_bundles WHERE source_id = ? AND item_ref = ? LIMIT 1')
    .bind(source, decodeURIComponent(ref))
    .first<{ view_json: string }>();
  if (!row) return jsonResponse(c, { error: 'not_found' }, 404);

  let view: Record<string, unknown>;
  try {
    view = JSON.parse(row.view_json) as Record<string, unknown>;
  } catch (_catchErr) {
    logError('intelBundleAdminHandler failed', _catchErr);
    return jsonResponse(c, { error: 'corrupt_view_json' }, 500);
  }

  // Slim projection — surface ONLY the LLM-relevant slice plus a few headers
  // so the response stays compact and copy-pastable into a ticket / chat.
  const out: AdminInspectShape = {
    source: (view.source as AdminInspectShape['source']) ?? { id: source, name: source },
    title: String(view.title ?? ''),
    bundleId: String(view.bundleId ?? ''),
    reportId: String(view.reportId ?? ''),
    generatedAt: String(view.generatedAt ?? ''),
    extractedHash: String(view.extractedHash ?? ''),
    counts: {
      iocs: Array.isArray(view.iocs) ? (view.iocs as unknown[]).length : 0,
      threatActors: Array.isArray(view.threatActors) ? (view.threatActors as unknown[]).length : 0,
      malware: Array.isArray(view.malware) ? (view.malware as unknown[]).length : 0,
      cves: Array.isArray(view.cves) ? (view.cves as unknown[]).length : 0,
    },
    sectors: Array.isArray(view.sectors) ? (view.sectors as string[]) : [],
    affectedProducts: Array.isArray(view.affectedProducts)
      ? (view.affectedProducts as AdminInspectShape['affectedProducts'])
      : [],
    attackPatterns: Array.isArray(view.attackPatterns)
      ? (view.attackPatterns as AdminInspectShape['attackPatterns'])
      : [],
    actorCandidates: Array.isArray(view.actorCandidates)
      ? (view.actorCandidates as AdminInspectShape['actorCandidates'])
      : [],
    malwareCandidates: Array.isArray(view.malwareCandidates)
      ? (view.malwareCandidates as AdminInspectShape['malwareCandidates'])
      : [],
    llmEnrichment: (view.llmEnrichment as AdminInspectShape['llmEnrichment']) ?? { ran: false, partial: false },
  };
  return jsonResponse(c, out, 200);
}
