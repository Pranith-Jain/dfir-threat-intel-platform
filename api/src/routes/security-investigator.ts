/**
 * Security Investigator REST routes.
 *
 * Exposes the public/data/si/ manifest as JSON HTTP routes so the
 * frontend (or any other client) can browse skills / queries / docs /
 * ref data without speaking MCP. Mirrors the si_* MCP tool shapes.
 *
 * The actual data lives in dist/data/si/ at the edge, served by the
 * Worker via env.ASSETS. We hit that binding directly instead of going
 * over HTTPS so the read is in-process.
 *
 * Endpoints:
 *   GET /api/v1/si/index                       (slim manifest)
 *   GET /api/v1/si/skills                      (skill index)
 *   GET /api/v1/si/skills/:slug                (full skill body, may include svgWidgetsYaml)
 *   GET /api/v1/si/queries                     (query index)
 *   GET /api/v1/si/queries/:domain/:file       (full KQL body)
 *   GET /api/v1/si/automations                 (workflow index)
 *   GET /api/v1/si/automations/:slug           (workflow body)
 *   GET /api/v1/si/docs                        (docs index)
 *   GET /api/v1/si/docs/:slug                  (doc markdown)
 *   GET /api/v1/si/ref                         (reference data index)
 *   GET /api/v1/si/ref/:name                   (reference data)
 *   GET /api/v1/si/routing-prompt              (Markdown; clients should cache)
 *
 * The query :file is the raw filename stem (e.g. "aitm_threat_detection").
 * The doc :slug is the lowercase version of the upstream filename stem.
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, internalError } from '../lib/api-error';

const DATA_PREFIX = '/data/si';

async function fetchAsset(env: Env, path: string): Promise<Response> {
  // The api/src/env.ts doesn't include ASSETS yet (the worker's Env does).
  // We accept the optional binding through a narrow type cast.
  const assets = (env as unknown as { ASSETS?: Fetcher }).ASSETS;
  if (!assets) {
    throw new Error('ASSETS binding missing — Worker has no /public/data/si/ access');
  }
  return assets.fetch(new Request(`https://si-internal${path}`));
}

async function fetchJson<T>(env: Env, path: string): Promise<T | null> {
  const r = await fetchAsset(env, path);
  if (!r.ok) return null;
  return (await r.json()) as T;
}

async function fetchText(env: Env, path: string): Promise<string | null> {
  const r = await fetchAsset(env, path);
  if (!r.ok) return null;
  return r.text();
}

/**
 * Slice a UTF-8 string by line range, returning a tuple
 * [startLine, endLine, chunked, totalLines]. The chunked body is the
 * raw markdown — clients can read it as text without JSON-parsing.
 * Used by the /api/v1/si/{skill,doc,query} handlers' ?stream=true mode
 * and the ?from_line=&max_lines= range reader, both of which can serve
 * bodies that are too large (up to ~100KB for threat-pulse) for a
 * single JSON round-trip to be pleasant.
 */
function sliceMarkdownLines(
  text: string,
  fromLine?: number,
  maxLines?: number
): { startLine: number; endLine: number; totalLines: number; chunk: string } {
  // Count by splitting on newlines; preserve a trailing-empty-line invariant.
  const lines = text.split('\n');
  const total = lines.length;
  const start = Math.max(0, Math.floor(fromLine ?? 0));
  const end = maxLines && maxLines > 0 ? Math.min(total, start + Math.floor(maxLines)) : total;
  return { startLine: start, endLine: end, totalLines: total, chunk: lines.slice(start, end).join('\n') };
}

/**
 * Wrap a string in a ReadableStream. The full body is held in memory
 * (we already fetched it from ASSETS to compute the line range), but
 * the client reads it as a stream so we don't pay the JSON encoding +
 * transfer cost of the bodyMarkdown field for ~100KB skill bodies.
 */
function stringToStream(s: string, chunkSize = 8192): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      let i = 0;
      const push = () => {
        if (i >= s.length) {
          controller.close();
          return;
        }
        const slice = s.slice(i, i + chunkSize);
        controller.enqueue(enc.encode(slice));
        i += chunkSize;
        // schedule the next chunk so the caller's reader can interleave.
        setTimeout(push, 0);
      };
      push();
    },
  });
}

function safeFilename(slug: string): string {
  return slug.replace(/\//g, '__');
}

interface SiIndex {
  counts: Record<string, number>;
  skills: Array<{ slug: string; category: string; [k: string]: unknown }>;
  queries: Array<{ slug: string; domain: string; [k: string]: unknown }>;
  automations: Array<{ slug: string; [k: string]: unknown }>;
}

export async function siIndexHandler(c: Context<{ Bindings: Env }>) {
  const idx = await fetchJson<SiIndex>(c.env, `${DATA_PREFIX}/index.json`);
  if (!idx) return notFound(c, 'public/data/si/index.json not found');
  return c.json(idx, 200, { 'Cache-Control': 'public, max-age=300, s-maxage=3600' });
}

export async function siSkillsHandler(c: Context<{ Bindings: Env }>) {
  const idx = await fetchJson<SiIndex>(c.env, `${DATA_PREFIX}/index.json`);
  if (!idx) return notFound(c, 'si_index_missing');
  const { category, keyword, limit } = c.req.query();
  const cap = Math.min(Number(limit) || 100, 100);
  const needle = keyword?.toLowerCase();
  let out = idx.skills;
  if (category) out = out.filter((s) => s.category === category);
  if (needle) {
    out = out.filter((s) => {
      const hay =
        `${s.slug} ${(s as { name?: string }).name ?? ''} ${(s as { description?: string }).description ?? ''}`.toLowerCase();
      return hay.includes(needle);
    });
  }
  out = out.slice(0, cap);
  return c.json({ total: idx.skills.length, returned: out.length, skills: out }, 200, {
    'Cache-Control': 'public, max-age=300, s-maxage=3600',
  });
}

export async function siSkillHandler(c: Context<{ Bindings: Env }>) {
  const slug = c.req.param('slug');
  if (!slug) return badRequest(c, 'missing_slug');
  const body = await fetchJson<Record<string, unknown>>(c.env, `${DATA_PREFIX}/skills/${safeFilename(slug)}.json`);
  if (!body) return notFound(c, `no skill with slug "${slug}"`);
  // ?stream=true returns the bodyMarkdown as text/markdown stream (no
  // JSON envelope), and ?from_line / ?max_lines select a slice. Useful
  // for large skills (threat-pulse ~100KB) when the client only needs
  // the first ~200 lines to decide whether to fetch the rest.
  if (c.req.query('stream') === 'true') {
    const text = String(body.bodyMarkdown ?? '');
    const slice = sliceMarkdownLines(
      text,
      c.req.query('from_line') ? Number(c.req.query('from_line')) : undefined,
      c.req.query('max_lines') ? Number(c.req.query('max_lines')) : undefined
    );
    return new Response(stringToStream(slice.chunk), {
      status: 200,
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Cache-Control': 'public, max-age=300, s-maxage=3600',
        'X-SI-Start-Line': String(slice.startLine),
        'X-SI-End-Line': String(slice.endLine),
        'X-SI-Total-Lines': String(slice.totalLines),
        'X-SI-Bytes': String(slice.chunk.length),
      },
    });
  }
  return c.json(body, 200, { 'Cache-Control': 'public, max-age=300, s-maxage=3600' });
}

export async function siQueriesHandler(c: Context<{ Bindings: Env }>) {
  const idx = await fetchJson<SiIndex>(c.env, `${DATA_PREFIX}/index.json`);
  if (!idx) return notFound(c, 'si_index_missing');
  const { domain, keyword, limit } = c.req.query();
  const cap = Math.min(Number(limit) || 100, 200);
  const needle = keyword?.toLowerCase();
  let out = idx.queries;
  if (domain) out = out.filter((q) => q.domain === domain);
  if (needle) {
    out = out.filter((q) => {
      const hay =
        `${q.slug} ${(q as { title?: string }).title ?? ''} ${(q as { filename?: string }).filename ?? ''}`.toLowerCase();
      return hay.includes(needle);
    });
  }
  out = out.slice(0, cap);
  return c.json({ total: idx.queries.length, returned: out.length, queries: out }, 200, {
    'Cache-Control': 'public, max-age=300, s-maxage=3600',
  });
}

export async function siQueryHandler(c: Context<{ Bindings: Env }>) {
  const domain = c.req.param('domain');
  const file = c.req.param('file');
  if (!domain || !file) return badRequest(c, 'missing_params');
  // threat-intelligence queries have a month in the path: threat-intelligence/2026-04/foo
  // The REST route collapses that to domain="threat-intelligence" and file="2026-04__foo" or
  // we can use a wildcard catch-all. The simpler shape is /queries?slug=... — see below.
  return notFound(c, 'use GET /api/v1/si/query?slug=...');
}

export async function siQueryBySlugHandler(c: Context<{ Bindings: Env }>) {
  const slug = c.req.query('slug');
  if (!slug) return badRequest(c, 'pass ?slug=cloud/aitm_threat_detection');
  const body = await fetchJson<Record<string, unknown>>(c.env, `${DATA_PREFIX}/queries/${safeFilename(slug)}.json`);
  if (!body) return notFound(c, `no query with slug "${slug}"`);
  if (c.req.query('stream') === 'true') {
    const text = String(body.bodyMarkdown ?? '');
    const slice = sliceMarkdownLines(
      text,
      c.req.query('from_line') ? Number(c.req.query('from_line')) : undefined,
      c.req.query('max_lines') ? Number(c.req.query('max_lines')) : undefined
    );
    return new Response(stringToStream(slice.chunk), {
      status: 200,
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Cache-Control': 'public, max-age=300, s-maxage=3600',
        'X-SI-Start-Line': String(slice.startLine),
        'X-SI-End-Line': String(slice.endLine),
        'X-SI-Total-Lines': String(slice.totalLines),
        'X-SI-Bytes': String(slice.chunk.length),
      },
    });
  }
  return c.json(body, 200, { 'Cache-Control': 'public, max-age=300, s-maxage=3600' });
}

export async function siAutomationsHandler(c: Context<{ Bindings: Env }>) {
  const idx = await fetchJson<SiIndex>(c.env, `${DATA_PREFIX}/index.json`);
  if (!idx) return notFound(c, 'si_index_missing');
  return c.json({ total: idx.automations.length, automations: idx.automations }, 200, {
    'Cache-Control': 'public, max-age=300, s-maxage=3600',
  });
}

export async function siAutomationHandler(c: Context<{ Bindings: Env }>) {
  const slug = c.req.param('slug');
  if (!slug) return badRequest(c, 'missing_slug');
  const body = await fetchJson<Record<string, unknown>>(c.env, `${DATA_PREFIX}/automations/${slug}.json`);
  if (!body) return notFound(c, 'automation_not_found');
  return c.json(body, 200, { 'Cache-Control': 'public, max-age=300, s-maxage=3600' });
}

interface DocsIndex {
  count: number;
  docs: Array<{ slug: string; title: string; filename: string; sizeBytes: number }>;
}

export async function siDocsHandler(c: Context<{ Bindings: Env }>) {
  const idx = await fetchJson<DocsIndex>(c.env, `${DATA_PREFIX}/docs-index.json`);
  if (!idx) return notFound(c, 'docs_index_missing');
  return c.json(idx, 200, { 'Cache-Control': 'public, max-age=300, s-maxage=3600' });
}

export async function siDocHandler(c: Context<{ Bindings: Env }>) {
  const slug = c.req.param('slug');
  if (!slug) return badRequest(c, 'missing_slug');
  const text = await fetchText(c.env, `${DATA_PREFIX}/docs/${slug}.md`);
  if (text === null) return notFound(c, 'doc_not_found');
  // Get title from index
  const idx = await fetchJson<DocsIndex>(c.env, `${DATA_PREFIX}/docs-index.json`);
  const entry = idx?.docs.find((d) => d.slug === slug);
  // ?stream=true returns the raw markdown as a chunked text stream with
  // line-range metadata in response headers. For docs that are 50KB+
  // (most of /docs/) this avoids the JSON-encode round-trip cost.
  if (c.req.query('stream') === 'true') {
    const slice = sliceMarkdownLines(
      text,
      c.req.query('from_line') ? Number(c.req.query('from_line')) : undefined,
      c.req.query('max_lines') ? Number(c.req.query('max_lines')) : undefined
    );
    return new Response(stringToStream(slice.chunk), {
      status: 200,
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Cache-Control': 'public, max-age=300, s-maxage=3600',
        'X-SI-Slug': slug,
        'X-SI-Title': entry?.title ?? slug,
        'X-SI-Start-Line': String(slice.startLine),
        'X-SI-End-Line': String(slice.endLine),
        'X-SI-Total-Lines': String(slice.totalLines),
        'X-SI-Bytes': String(slice.chunk.length),
      },
    });
  }
  return c.json(
    {
      slug,
      title: entry?.title ?? slug,
      filename: entry?.filename ?? `${slug}.md`,
      bodyMarkdown: text,
      sizeBytes: text.length,
    },
    200,
    {
      'Cache-Control': 'public, max-age=300, s-maxage=3600',
    }
  );
}

export async function siRefListHandler(c: Context<{ Bindings: Env }>) {
  // The build script writes a known set of ref files; probe each to discover what's there.
  const known = [
    'mitre-attck-enterprise',
    'known-kql-tables',
    'm365-platform-coverage',
    'ingestion-q2',
    'ingestion-q6a',
    'ingestion-q6b',
    'ingestion-q6c',
    'ingestion-q9',
    'ingestion-q9b',
    'ingestion-q10',
    'ingestion-q12',
    'ingestion-q13',
    'ingestion-q16',
    'ingestion-q17',
  ];
  const found: Array<{ name: string; bytes: number }> = [];
  for (const name of known) {
    const v = await fetchJson<unknown>(c.env, `${DATA_PREFIX}/ref/${name}.json`);
    if (v !== null) found.push({ name, bytes: JSON.stringify(v).length });
  }
  return c.json({ count: found.length, refs: found }, 200, {
    'Cache-Control': 'public, max-age=300, s-maxage=3600',
  });
}

export async function siRefHandler(c: Context<{ Bindings: Env }>) {
  const name = c.req.param('name');
  if (!name) return badRequest(c, 'missing_name');
  const clean = name.replace(/\.json$/, '');
  const v = await fetchJson<unknown>(c.env, `${DATA_PREFIX}/ref/${clean}.json`);
  if (v === null) return notFound(c, 'ref_not_found');
  return c.json({ name: clean, data: v, bytes: JSON.stringify(v).length }, 200, {
    'Cache-Control': 'public, max-age=300, s-maxage=3600',
  });
}

export async function siRoutingPromptHandler(c: Context<{ Bindings: Env }>) {
  const text = await fetchText(c.env, `${DATA_PREFIX}/routing-prompt.md`);
  if (text === null) return notFound(c, 'routing_prompt_missing');
  return c.json({ bytes: text.length, promptMarkdown: text }, 200, {
    'Cache-Control': 'public, max-age=300, s-maxage=3600',
  });
}

/**
 * GET /api/v1/si/scripts — list the 5 PowerShell / detection-manifest files.
 * The MCP tool si_list_scripts returns the same shape.
 */
export async function siScriptsHandler(c: Context<{ Bindings: Env }>) {
  const spec = ['..', '..', '..', 'worker', 'lib', 'si-manifest'].join('/');
  const mod = (await import(/* @vite-ignore */ spec)) as {
    loadScriptsIndex(assets: Fetcher): Promise<{
      source: string;
      license: string;
      count: number;
      scripts: Array<{ name: string; sizeBytes: number; language?: string }>;
    }>;
  };
  const assets = (c.env as unknown as { ASSETS?: Fetcher }).ASSETS;
  if (!assets) return internalError(c, 'no_assets_binding');
  try {
    const idx = await mod.loadScriptsIndex(assets);
    return c.json({ total: idx.count, returned: idx.scripts.length, scripts: idx.scripts }, 200, {
      'Cache-Control': 'public, max-age=300, s-maxage=3600',
    });
  } catch (e) {
    logError('siScriptsHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
}

/**
 * GET /api/v1/si/scripts/:name — return the raw body of a PowerShell
 * script or detection-manifest. The body is text/plain; clients should
 * not execute these on the Worker — they're meant to be copied to a
 * local PowerShell 7+ session to run.
 */
export async function siScriptHandler(c: Context<{ Bindings: Env }>) {
  const name = c.req.param('name');
  if (!name) return badRequest(c, 'missing_name');
  // Path-traversal guard: no slashes, no parent refs.
  if (name.includes('/') || name.includes('\\') || name.includes('..')) {
    return badRequest(c, 'invalid_name');
  }
  const spec = ['..', '..', '..', 'worker', 'lib', 'si-manifest'].join('/');
  const mod = (await import(/* @vite-ignore */ spec)) as {
    getScript(assets: Fetcher, name: string): Promise<{ name: string; body: string; sizeBytes: number } | null>;
  };
  const assets = (c.env as unknown as { ASSETS?: Fetcher }).ASSETS;
  if (!assets) return internalError(c, 'no_assets_binding');
  const body = await mod.getScript(assets, name);
  if (!body) return notFound(c, 'script_not_found');
  // Detect content-type from filename extension for the convenience GET.
  const isMarkdown = name.endsWith('.md');
  const isJson = name.endsWith('.json');
  const ct = isMarkdown
    ? 'text/markdown; charset=utf-8'
    : isJson
      ? 'application/json; charset=utf-8'
      : 'text/plain; charset=utf-8';
  return new Response(body.body, {
    status: 200,
    headers: {
      'Content-Type': ct,
      'Cache-Control': 'public, max-age=300, s-maxage=3600',
      'X-SI-Bytes': String(body.sizeBytes),
    },
  });
}

import { parseMiniYaml } from '../lib/si-yaml-mini';
import { renderDashboard, type RenderManifest } from '../lib/si-svg-renderer';

/**
 * Flatten upstream `rows[].widgets[]` manifests into the flat `widgets: []`
 * shape the renderer expects. Some upstream skills (notably `threat-pulse`)
 * declare the layout as a list of rows, each row having its own widgets
 * array. The 2D grid layout in renderDashboard operates on a single flat
 * widget list, so we collapse the rows at the render boundary. Row-level
 * `height` and `id` are preserved on the widget when present.
 *
 * If the manifest already has a flat `widgets:` array, this is a no-op.
 * Other top-level keys (canvas, palette, …) pass through unchanged.
 */
function flattenRowsManifest(parsed: unknown): RenderManifest {
  if (!parsed || typeof parsed !== 'object') return parsed as RenderManifest;
  const obj = parsed as Record<string, unknown>;
  const rows = obj.rows;
  if (!Array.isArray(rows) || obj.widgets) return obj as RenderManifest;
  const flat: Array<Record<string, unknown>> = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const ws = r.widgets;
    if (Array.isArray(ws)) {
      for (const w of ws) {
        if (w && typeof w === 'object') {
          const widget = { ...(w as Record<string, unknown>) };
          // Preserve row-level metadata as widget hints (e.g. height).
          if (typeof r.height === 'number' && widget.height === undefined) widget.height = r.height;
          if (typeof r.id === 'string' && widget.row_id === undefined) widget.row_id = r.id;
          flat.push(widget);
        }
      }
    }
  }
  const { rows: _drop, ...rest } = obj;
  return { ...rest, widgets: flat } as RenderManifest;
}
// The PNG rasteriser is in the Worker tree (it needs the resvg-wasm
// import which is bundled into the Worker). The relative path
// resolves from api/src/routes/ → worker/lib/si-svg-png.ts.
// Wrapped in a dynamic import so the route file still typechecks
// in api/tsconfig.json (which doesn't include worker/).
import { svgDashboardToPng as _svgDashboardToPng } from '../lib/si-svg-png';

async function renderPngFromSvg(svg: string, env: unknown): Promise<Uint8Array> {
  // The PNG rasteriser lives in worker/lib/si-svg-png.ts and is exposed
  // to the api/ tree via the api/src/lib/si-svg-png.ts symlink. The static
  // import resolves at Vite + wrangler build time (no runtime fetch), so
  // /api/v1/si/render?format=png doesn't fail with "No such module" in
  // the Worker runtime (the previous dynamic-import hack worked at type-
  // check time but not in the wrangler bundle).
  return _svgDashboardToPng(env as Parameters<typeof _svgDashboardToPng>[0], svg);
}

// Cached manifest YAMLs are pulled from the skills' svgWidgetsYaml field.
// We re-fetch through the si index file which embeds the manifest text in
// the per-skill JSON (round 2 added that).
interface SiSkillWithManifest {
  slug: string;
  name: string;
  svgWidgetsYaml?: string;
  bodyMarkdown?: string;
}

/**
 * GET /api/v1/si/render?slug=threat-pulse&data=<urlencoded-json>
 *
 * Renders an SVG dashboard from a skill's embedded svgWidgetsYaml
 * manifest. Pass `data` as a URL-encoded JSON object mapping widget
 * name → data; the renderer merges it with the manifest.
 *
 * Alternatively, POST /api/v1/si/render with a JSON body
 *   { manifest: <parsed manifest object>, data: {...} }
 * or a YAML body
 *   { manifestYaml: "<yaml text>", data: {...} }
 */
export async function siRenderHandler(c: Context<{ Bindings: Env }>) {
  const slug = c.req.query('slug');
  const dataQuery = c.req.query('data');

  let manifest: RenderManifest;
  let data: Record<string, unknown> = {};

  if (slug) {
    const skill = await fetchJson<SiSkillWithManifest>(c.env, `${DATA_PREFIX}/skills/${safeFilename(slug)}.json`);
    if (!skill || !skill.svgWidgetsYaml) {
      return c.json(
        {
          error: 'no_manifest',
          slug,
          hint: 'This skill does not ship an svg-widgets.yaml. Use si_render_svg_dashboard or pass manifest explicitly.',
        },
        404,
        { 'Cache-Control': 'no-store' }
      );
    }
    try {
      manifest = flattenRowsManifest(parseMiniYaml(skill.svgWidgetsYaml));
    } catch (e) {
      logError('siRenderHandler failed', e);
      return badRequest(c, e instanceof Error ? e.message : String(e));
    }
  } else {
    // POST or GET with body — accept JSON or YAML.
    const ct = c.req.header('content-type') ?? '';
    if (ct.includes('yaml') || ct.includes('text/plain')) {
      const text = await c.req.text();
      try {
        manifest = parseMiniYaml(text) as RenderManifest;
      } catch (e) {
        logError('handler failed', e);
        return badRequest(c, e instanceof Error ? e.message : String(e));
      }
    } else {
      let body: Record<string, unknown>;
      try {
        body = await c.req.json();
      } catch {
        return badRequest(c, 'invalid_json_body');
      }
      if (!body || typeof body !== 'object') {
        return c.json(
          {
            error: 'missing_manifest',
            hint: 'Pass ?slug=<skill> or POST a JSON/YAML body with {manifest|manifestYaml, data}.',
          },
          400,
          { 'Cache-Control': 'no-store' }
        );
      }
      if (typeof body.manifestYaml === 'string') {
        try {
          manifest = parseMiniYaml(body.manifestYaml) as RenderManifest;
        } catch (e) {
          logError('handler failed', e);
          return badRequest(c, e instanceof Error ? e.message : String(e));
        }
      } else if (body.manifest) {
        manifest = body.manifest as RenderManifest;
      } else {
        return badRequest(c, 'missing_manifest');
      }
      if (body.data && typeof body.data === 'object') {
        data = body.data as Record<string, unknown>;
      }
    }
  }

  if (dataQuery && Object.keys(data).length === 0) {
    try {
      const parsed = JSON.parse(decodeURIComponent(dataQuery));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        // Reject prototype-pollution payloads
        const hasDangerousKey = (obj: unknown, seen = new Set<unknown>()): boolean => {
          if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
          if (seen.has(obj)) return false;
          seen.add(obj);
          for (const k of Object.keys(obj as Record<string, unknown>)) {
            if (k === '__proto__' || k === 'constructor' || k === 'prototype') return true;
            if (hasDangerousKey((obj as Record<string, unknown>)[k], seen)) return true;
          }
          return false;
        };
        if (hasDangerousKey(parsed)) {
          return badRequest(c, 'invalid_data');
        }
        data = parsed as Record<string, unknown>;
      } else if (parsed !== null) {
        return badRequest(c, 'data_must_be_object');
      }
    } catch (e) {
      logError('handler failed', e);
      return badRequest(c, e instanceof Error ? e.message : String(e));
    }
  }

  try {
    const svg = renderDashboard(manifest, data);
    // format=png rasterises the dashboard via @resvg/resvg-wasm. Used by
    // GitHub social previews, readme thumbnails, and X/Twitter unfurls.
    // This check runs BEFORE the default SVG-with-slug response so that
    // a slug + format=png URL doesn't get short-circuited to SVG.
    if (c.req.query('format') === 'png') {
      try {
        const width = Number(c.req.query('width')) || 1400;
        const png = await renderPngFromSvg(svg, c.env);
        return new Response(png, {
          status: 200,
          headers: {
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=300, s-maxage=3600',
            'X-PNG-Bytes': String(png.length),
            'X-Render-Width': String(width),
          },
        });
      } catch (e) {
        logError('handler failed', e);
        return internalError(c, e instanceof Error ? e.message : String(e));
      }
    }
    // SVG-with-slug or explicit format=svg returns image/svg+xml.
    if (slug || c.req.query('format') === 'svg') {
      return new Response(svg, {
        status: 200,
        headers: {
          'Content-Type': 'image/svg+xml; charset=utf-8',
          'Cache-Control': 'public, max-age=300, s-maxage=3600',
          'X-SVG-Bytes': String(svg.length),
          // Defense-in-depth for the SVG-XSS class: even if an unescaped value
          // ever slips through the renderer's safeColor()/esc() guards, this
          // CSP neutralizes script execution when the image/svg+xml URL is
          // opened as a top-level document. `sandbox` + script-src 'none'
          // block inline/embedded scripts; nosniff stops content-type tricks.
          'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; sandbox",
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }
    return c.json({ svg, bytes: svg.length, widgetCount: (manifest.widgets ?? []).length }, 200, {
      'Cache-Control': 'public, max-age=300, s-maxage=3600',
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
}
