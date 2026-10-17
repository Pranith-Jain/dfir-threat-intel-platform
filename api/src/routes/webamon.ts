import type { Context } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, internalError, badGateway } from '../lib/api-error';
import { cachedJson } from '../lib/route-cache';

const WEBAMON_SEARCH = 'https://search.webamon.com';
const TIMEOUT = 20_000;
const CACHE_TTL = 300;
const UA = 'pranithjain-dfir/1.0';

/**
 * Webamon reworked the public search API (2026-10). The contract is now:
 *
 *   basic search:  search=<term>&results=<fields to SEARCH WITHIN>
 *   field search:  lucene_query=<query>&index=<scans|servers|resources>
 *                  &fields=<fields to RETURN>
 *
 * The old shape — Lucene syntax inside `search` plus `results` as a return
 * projection — now fails upstream: field queries in `search` 500 with
 * `query_shard_exception`, and a `meta.risk_score` entry in `results` makes
 * the query builder parse the search term as a number. Both handlers below
 * translate to the new contract and normalize the response back to the
 * `domain.name` / `meta.risk_score` shape that every caller expects.
 */

/**
 * Fields the free-text mode searches within. Deliberately excludes `dom`:
 * that field stores raw page HTML, so including it turns every term into a
 * multi-million-hit sweep of the corpus. `meta` and `fingerprint` come back
 * on every hit regardless of this list.
 */
const BASIC_SEARCH_FIELDS = 'domain.name,page_title,sub_domain,resolved_url';

/**
 * Lucene-mode return projection. Without `fields` the upstream returns the
 * full document — raw DOM HTML, certificate SCT chains, resource listings —
 * which is megabytes per page and a Worker memory hazard.
 */
const LUCENE_SEARCH_FIELDS =
  'domain_name,page_title,resolved_url,tag,sub_domain,meta,fingerprint,date,report_id,scan_status';

/** Full document projection for the report view (needs certs/servers/cookies/resources). */
const REPORT_FIELDS =
  'domain_name,domain.name,page_title,report_id,meta,resolved_url,tag,sub_domain,certificate,server,cookie,technology,resource,page_links,page_scripts,fingerprint,monitor,dom,scan_status,scan_time,submission_url,submission_utc,completion_utc,errors,feed,engine_id,resolved_domain,resolved_sub_domain,resolved_tld,save_resources,source,tld';

/* ─── Types ──────────────────────────────────────────────────────────────── */

interface WebamonResult {
  _index?: string;
  'domain.name'?: string;
  /** Canonical underscore field returned by lucene-mode queries. */
  domain_name?: string;
  date?: string;
  page_title?: string;
  resolved_url?: string;
  sub_domain?: string;
  tag?: string;
  /** Top-level report id on lucene-mode documents. */
  report_id?: string;
  scan_status?: string;
  meta?: {
    submission_url?: string;
    script_count?: number;
    risk_score?: number;
    report_id?: string;
    domain_count?: number;
    submission?: string;
    submission_utc?: string;
    request_count?: number;
  };
  fingerprint?: {
    tech?: string;
    scan_fingerprint?: string;
    dom?: string;
    domains?: string;
    links?: string;
    scripts?: string;
    ssl?: string;
    asn?: string;
    cookies?: string;
    [key: string]: unknown;
  };
  matched_fields?: string[];
}

interface WebamonSearchResponse {
  search_string: string;
  fields?: string[];
  total_hits: number;
  results: WebamonResult[];
  pagination?: {
    from: number;
    size: number;
    returned: number;
    has_more: boolean;
    current_page: number;
    total_pages: number;
    next_from: number | null;
    prev_from: number | null;
  };
}

/* ─── Upstream fetch ─────────────────────────────────────────────────────── */

async function webamonFetch(path: string, retries = 2): Promise<Response | null> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
      const res = await fetch(`${WEBAMON_SEARCH}${path}`, {
        signal: ctrl.signal,
        headers: { accept: 'application/json', 'user-agent': UA },
      });
      clearTimeout(timer);
      if (res.ok || res.status !== 429) return res;
    } catch (_catchErr) {
      logError('webamonFetch failed', _catchErr);
      /* retry */
    }
    if (attempt < retries) await new Promise((r) => setTimeout(r, 800 * attempt));
  }
  return null;
}

/**
 * Fetch + parse an upstream JSON payload, converting upstream failures into
 * thrown errors so `cachedJson` surfaces a 502 instead of caching garbage.
 *
 * The upstream answers HTTP 200 with an `error` string for query build
 * failures (unknown Lucene field, malformed range, …). Those are surfaced
 * verbatim — the message lists valid fields, which is exactly what the
 * caller needs to fix their query.
 */
async function fetchJson<T>(path: string): Promise<T> {
  const res = await webamonFetch(path);
  if (!res) throw new Error('webamon upstream unreachable');
  if (!res.ok) {
    throw new Error(`webamon upstream error (status ${res.status})`);
  }
  const data = (await res.json()) as T & { error?: string };
  if (data && typeof data === 'object' && typeof data.error === 'string' && data.error) {
    throw new Error(`webamon upstream query error: ${data.error}`);
  }
  return data;
}

/* ─── Query routing + normalization ──────────────────────────────────────── */

/**
 * True when the query uses Lucene field syntax (`field:value`) and must be
 * sent as `lucene_query` + `index`, rather than as free text.
 *
 * Free text is the default; a URL (`https://…`), an IPv6 literal (`…::…`) or
 * a host:port pair (`example.com:8080`) never routes to Lucene despite
 * containing colons.
 */
function usesFieldSyntax(query: string): boolean {
  if (!query) return false;
  if (query.includes('://') || query.includes('::')) return false;
  if (/\.[\w-]+:\d+/.test(query)) return false;
  return /(^|\s|\(|\[)[A-Za-z_][\w.]*\s*:/.test(query);
}

/** Build the upstream path for a user-supplied query (basic vs lucene mode). */
function upstreamSearchPath(query: string, size: number, from: number): string {
  return usesFieldSyntax(query)
    ? `/search?lucene_query=${encodeURIComponent(query)}&index=scans&fields=${encodeURIComponent(LUCENE_SEARCH_FIELDS)}&size=${size}&from=${from}`
    : `/search?search=${encodeURIComponent(query)}&results=${encodeURIComponent(BASIC_SEARCH_FIELDS)}&size=${size}&from=${from}`;
}

/** Strip upstream `<mark>` highlighting so strings render literally in the UI. */
function stripHighlight(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  return value.replace(/<\/?mark>/g, '');
}

/**
 * Normalize a hit to the shape callers have always consumed:
 * `domain.name` populated (basic mode returns it highlighted, lucene mode
 * returns `domain_name`), plus `meta`/`fingerprint` untouched.
 */
function normalizeDoc(doc: Record<string, unknown>): WebamonResult {
  // Basic mode searches within several fields, so a hit can match on
  // page_title/resolved_url while carrying no domain.name — fall back to the
  // resolved host rather than rendering an empty cell.
  let domainName = stripHighlight(doc['domain.name']) || stripHighlight(doc.domain_name) || '';
  if (!domainName) {
    const resolved = stripHighlight(doc.resolved_url);
    try {
      domainName = resolved ? new URL(resolved).hostname : '';
    } catch {
      domainName = '';
    }
  }
  const meta = (doc.meta ?? {}) as WebamonResult['meta'];
  return {
    _index: typeof doc._index === 'string' ? doc._index : undefined,
    'domain.name': domainName,
    domain_name: typeof doc.domain_name === 'string' ? doc.domain_name : domainName,
    page_title: stripHighlight(doc.page_title),
    resolved_url: stripHighlight(doc.resolved_url),
    sub_domain: stripHighlight(doc.sub_domain) ?? stripHighlight(doc.resolved_sub_domain) ?? '',
    tag: stripHighlight(doc.tag),
    date: typeof doc.date === 'string' ? doc.date : undefined,
    report_id: typeof doc.report_id === 'string' ? doc.report_id : meta?.report_id,
    scan_status: typeof doc.scan_status === 'string' ? doc.scan_status : undefined,
    meta,
    fingerprint: doc.fingerprint as WebamonResult['fingerprint'],
    matched_fields: Array.isArray(doc.matched_fields) ? (doc.matched_fields as string[]) : undefined,
  };
}

function normalizeSearch(data: WebamonSearchResponse, query: string): WebamonSearchResponse {
  return {
    search_string: data.search_string || query,
    total_hits: data.total_hits ?? 0,
    results: Array.isArray(data.results)
      ? data.results.map((r) => normalizeDoc(r as unknown as Record<string, unknown>))
      : [],
    pagination: data.pagination,
  };
}

/* ─── Search (public) ───────────────────────────────────────────────────── */

export async function webamonSearchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const search = c.req.query('search')?.trim();
  if (!search) return badRequest(c, 'missing search query');
  const size = Math.min(Math.max(Number(c.req.query('size')) || 20, 1), 100);
  const from = Math.max(Number(c.req.query('from')) || 0, 0);

  const upstream = upstreamSearchPath(search, size, from);

  return cachedJson(c, `webamon:search:v2:${upstream}`, CACHE_TTL, async () =>
    normalizeSearch(await fetchJson<WebamonSearchResponse>(upstream), search)
  );
}

/* ─── Scan (public via search.webamon.com/scan) ──────────────────────────── */

/**
 * The webamon `/scan` endpoint answers `{ report_id }` as plain JSON. Older
 * deployments streamed Server-Sent Events (`event: message` / `data: {…}`
 * lines); consume the text, take the LAST `data:` payload, and fall back to
 * whole-body JSON.
 */
async function webamonConsume(res: Response): Promise<unknown> {
  const text = await res.text();
  const dataLines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('data:'))
    .map((l) => l.slice(5).trim());
  if (dataLines.length > 0) {
    const last = dataLines[dataLines.length - 1];
    if (typeof last === 'string') {
      try {
        return JSON.parse(last);
      } catch {
        /* fall through to whole-body parse */
      }
    }
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function webamonScanHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const body = (await c.req.json<{ submission_url?: string }>().catch(() => ({}))) as { submission_url?: string };
    if (!body.submission_url) return badRequest(c, 'missing submission_url');
    const res = await webamonFetch(`/scan?submission_url=${encodeURIComponent(body.submission_url)}`);
    if (!res) return badGateway(c, 'webamon upstream unreachable');
    const data = await webamonConsume(res);
    return c.json(data, (res.ok ? 200 : res.status) as ContentfulStatusCode);
  } catch (err) {
    logError('webamonScanHandler failed', err);
    return c.json(
      { error: 'internal_error', message: err instanceof Error ? err.message : 'scan handler failed' },
      500
    );
  }
}

/* ─── Report lookup (public) ─────────────────────────────────────────────── */

/** Search reports by an arbitrary query (lucene field syntax or free text). */
export async function webamonReportsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const q = c.req.query('q')?.trim();
  if (!q) return badRequest(c, 'missing search query (q)');
  const upstream = upstreamSearchPath(q, 20, 0);

  return cachedJson(c, `webamon:reports:v2:${upstream}`, CACHE_TTL, async () =>
    normalizeSearch(await fetchJson<WebamonSearchResponse>(upstream), q)
  );
}

/** Full scan report by report_id. */
export async function webamonReportHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const id = c.req.param('id');
  if (!id) return badRequest(c, 'missing report id');
  const query = `report_id:"${id.replace(/"/g, '')}"`;
  const upstream = `/search?lucene_query=${encodeURIComponent(query)}&index=scans&fields=${encodeURIComponent(REPORT_FIELDS)}&size=1`;

  // Short TTL on purpose: a scan that was just submitted is not in the index
  // yet, and the sandbox UI re-reads while waiting for it to appear. 30s keeps
  // the slow upstream from being hammered without freezing the empty result.
  return cachedJson(c, `webamon:report:v2:${id}`, 30, async () => {
    const data = await fetchJson<WebamonSearchResponse>(upstream);
    return {
      ...data,
      results: (data.results ?? []).map((r) => {
        const doc = r as unknown as Record<string, unknown>;
        const domainName = stripHighlight(doc['domain.name']) ?? stripHighlight(doc.domain_name) ?? '';
        return { ...doc, 'domain.name': domainName, domain_name: doc.domain_name ?? domainName } as WebamonResult;
      }),
    };
  });
}

/* ─── Screenshot (public via search.webamon.com/screenshot) ──────────────── */

export async function webamonScreenshotHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const id = c.req.param('id');
    if (!id) return badRequest(c, 'missing report id');
    const res = await webamonFetch(`/screenshot?report_id=${encodeURIComponent(id)}`);
    if (!res || !res.ok) return notFound(c, 'screenshot not found');
    const data = await res.json();
    const screenshot = (data as { report?: { screenshot?: string } })?.report?.screenshot;
    if (screenshot) {
      const base64 = screenshot.replace(/^data:image\/\w+;base64,/, '');
      // The upstream labels this PNG but now serves JPEG (and has served PNG
      // historically) — sniff the magic so the content-type never lies.
      const contentType =
        base64.startsWith('/9j/') || base64.startsWith('/9J/')
          ? 'image/jpeg'
          : base64.startsWith('iVBOR')
            ? 'image/png'
            : 'application/octet-stream';
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return new Response(bytes, {
        status: 200,
        headers: { 'content-type': contentType, 'cache-control': 'public, max-age=86400' },
      });
    }
    return notFound(c, 'no screenshot in response');
  } catch (err) {
    logError('webamonScreenshotHandler failed', err);
    return c.json(
      { error: 'internal_error', message: err instanceof Error ? err.message : 'screenshot handler failed' },
      500
    );
  }
}

/* ─── Infrastructure lookups (lucene queries over the other indices) ─────── */

export async function webamonDomainHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const name = c.req.param('name')?.trim();
  if (!name) return badRequest(c, 'missing domain name');
  // `domain_name` is the exact-match keyword field; `domain.name` is
  // analyzed text and matches substring tokens, not the domain itself.
  const query = `domain_name:"${name.replace(/"/g, '')}"`;
  const upstream = `/search?lucene_query=${encodeURIComponent(query)}&index=scans&fields=${encodeURIComponent(LUCENE_SEARCH_FIELDS)}&size=20`;

  return cachedJson(c, `webamon:domain:v2:${name.toLowerCase()}`, CACHE_TTL, async () =>
    normalizeSearch(await fetchJson<WebamonSearchResponse>(upstream), query)
  );
}

export async function webamonServerHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const ip = c.req.param('ip')?.trim();
  if (!ip) return badRequest(c, 'missing ip');
  const query = `ip:${ip.replace(/"/g, '')}`;
  const upstream = `/search?lucene_query=${encodeURIComponent(query)}&index=servers&size=20`;

  return cachedJson(c, `webamon:server:v2:${ip}`, CACHE_TTL, () => fetchJson<Record<string, unknown>>(upstream));
}

export async function webamonResourceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const sha256 = c.req.param('sha256')?.trim();
    if (!sha256) return badRequest(c, 'missing sha256');
    const query = `sha256:${sha256.replace(/"/g, '')}`;
    const upstream = `/search?lucene_query=${encodeURIComponent(query)}&index=resources&size=20`;

    return await cachedJson(c, `webamon:resource:v2:${sha256.toLowerCase()}`, CACHE_TTL, () =>
      fetchJson<Record<string, unknown>>(upstream)
    );
  } catch (_catchErr) {
    logError('webamonResourceHandler failed', _catchErr);
    return internalError(c, 'resource handler failed');
  }
}
