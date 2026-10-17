/**
 * Browser-side client for the TI Mindmap HUB MCP server
 * (https://mcp.ti-mindmap-hub.com/mcp, JSON-RPC over HTTPS + SSE).
 *
 * Mirrors the official mcp-bridge.js stdio script
 * (https://github.com/TI-Mindmap-HUB-Org/ti-mindmap-hub-research/blob/main/mcp-integration/mcp-bridge.js)
 * but runs in the browser, keeps the API key in localStorage, and exposes a
 * typed surface for the /threatintel/ai-report page. Server is the source of
 * truth on auth (`X-API-Key` or `Authorization: Bearer <token>`), session id
 * (`Mcp-Session-Id` header returned by `initialize` and re-sent on every
 * subsequent request), and transport (`Accept: application/json, text/event-stream`
 * with the actual response being either plain JSON or an SSE `data:` frame).
 *
 * 25 tools across 7 categories: reports (5), briefings (3), IOC search (1),
 * CVE intelligence (5), STIX bundles (3), statistics & submissions (2),
 * knowledge graph (6). We wrap the ones the AI Report page needs.
 */
import { errMessage } from './log';

const MCP_URL = 'https://mcp.ti-mindmap-hub.com/mcp';
/**
 * Our Worker-side CORS proxy. The upstream MCP server does not send
 * CORS headers, so a browser cross-origin POST from our origin fails
 * the preflight with `NetworkError when attempting to fetch resource`.
 * The proxy at /api/v1/mcp/proxy terminates the request on our origin,
 * forwards it upstream with the user's X-API-Key (carried in the
 * request body so the browser preflight stays minimal), and relays
 * the response back. Same-origin (external-only auth) only -- the
 * key never reaches a third party.
 */
const PROXY_URL = '/api/v1/mcp/proxy';

/**
 * Sanitize an API key before putting it on the wire.
 *
 * TI-Mindmap-Hub returns keys as `tim_xxxxxxxxxxxx` (lowercase ASCII
 * alnum + underscore). The Cloudflare Workers fetch() validates header
 * values as `record<ByteString, ByteString>` and refuses any value that
 * contains a code point > 255 (it throws a `DataCloneError`-style
 * error like 'Cannot convert value ... character at index N has value
 * 8212 which is greater than 255'). The most common way a user hits
 * this in the wild is by copy-pasting the key from a webpage that
 * renders it with smart quotes, em-dash, NBSP, or zero-width spaces
 * around it -- all of which the X-API-Key header then rejects.
 *
 * Strip whitespace + any character outside printable ASCII, warn if
 * anything was removed, and validate the shape so we fail loud in the
 * popover instead of mid-fetch.
 */
export interface SanitizedKey {
  key: string;
  /** Characters we had to remove. Empty when the input was already clean. */
  removed: string;
  /** True when the input didn't start with `tim_`. */
  wrongShape: boolean;
}

const KEY_RE = /^tim_[a-z0-9_]+$/;

export function sanitizeKey(raw: string): SanitizedKey {
  // Strip leading/trailing whitespace and any character outside printable ASCII.
  const trimmed = raw.trim();
  const kept: string[] = [];
  const removedSet = new Set<string>();
  for (const ch of trimmed) {
    if (ch >= '\x20' && ch <= '\x7E') kept.push(ch);
    else removedSet.add(ch);
  }
  const key = kept.join('');
  return {
    key,
    removed: Array.from(removedSet).join(' '),
    wrongShape: key.length > 0 && !KEY_RE.test(key),
  };
}
const KEY_STORAGE = 'ti-mindmap:api-key';
const SESSION_STORAGE = 'ti-mindmap:session-id';
const PROBE_TIMEOUT_MS = 8_000;
const CALL_TIMEOUT_MS = 25_000;

export interface McpConfig {
  apiKey: string;
  endpoint?: string;
}

/** Read the persisted API key, or empty string if not set. */
export function getStoredApiKey(): string {
  if (typeof window === 'undefined') return '';
  try {
    return window.localStorage.getItem(KEY_STORAGE) ?? '';
  } catch {
    return '';
  }
}

/** Persist the API key in localStorage. */
export function setStoredApiKey(key: string): void {
  if (typeof window === 'undefined') return;
  try {
    if (key) {
      // Always persist the sanitized form. Non-ASCII characters (smart
      // quotes, em-dash, NBSP from copy-paste) would otherwise make
      // every later fetch() throw a 'character at index N has value
      // 8212 which is greater than 255' DataCloneError.
      const { key: clean } = sanitizeKey(key);
      window.localStorage.setItem(KEY_STORAGE, clean);
    } else {
      window.localStorage.removeItem(KEY_STORAGE);
    }
    // Any new key invalidates the previous session id.
    window.localStorage.removeItem(SESSION_STORAGE);
  } catch {
    /* private mode / blocked storage - accept the loss, key still works for this session */
  }
}

let sessionId = '';
function loadSession(): string {
  if (sessionId) return sessionId;
  if (typeof window === 'undefined') return '';
  try {
    sessionId = window.localStorage.getItem(SESSION_STORAGE) ?? '';
  } catch {
    sessionId = '';
  }
  return sessionId;
}
function saveSession(id: string): void {
  sessionId = id;
  if (typeof window === 'undefined') return;
  try {
    if (id) window.localStorage.setItem(SESSION_STORAGE, id);
    else window.localStorage.removeItem(SESSION_STORAGE);
  } catch {
    /* ignore */
  }
}

export class McpError extends Error {
  code: number;
  hint?: string;
  constructor(message: string, code: number, hint?: string) {
    super(message);
    this.name = 'McpError';
    this.code = code;
    this.hint = hint;
  }
}

interface JsonRpcResponse<T> {
  jsonrpc: '2.0';
  id?: number | string;
  result?: T;
  error?: { code: number; message: string; data?: unknown };
}

/** Initialize (or re-initialize) the MCP session. Returns the session id. */
export async function initSession(apiKey: string, endpoint = PROXY_URL): Promise<string> {
  const existing = loadSession();
  if (existing) return existing;
  const res = await callRaw<{ serverInfo?: { name?: string; version?: string } }>(
    'initialize',
    {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'pranithjain-qzz-io', version: '1.0.0' },
    },
    apiKey,
    endpoint,
    /* fresh */ true
  );
  const id = res.headers.get('mcp-session-id') ?? '';
  if (id) saveSession(id);
  return id;
}

/** Low-level JSON-RPC POST. Handles SSE-or-JSON response, session header, timeout. */
async function callRaw<T>(
  method: string,
  params: Record<string, unknown> | undefined,
  apiKey: string,
  endpoint: string,
  fresh = false
): Promise<{ data: JsonRpcResponse<T>; headers: Headers }> {
  const id = method === 'initialize' ? 1 : Math.floor(Math.random() * 1e9);
  // Two transport modes:
  //  - same-origin proxy (default): the key is sent in the body so
  //    the browser preflight stays minimal. The proxy reads it and
  //    forwards to the upstream.
  //  - direct upstream (MCP_URL): the key goes in the X-API-Key
  //    header per the MCP server's spec. Only used for testing --
  //    production callers always go through the proxy.
  const useProxy = endpoint !== MCP_URL;
  const sid = fresh ? '' : loadSession();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  };
  if (!useProxy) headers['X-API-Key'] = apiKey;
  if (sid) headers['Mcp-Session-Id'] = sid;

  // When using the proxy, embed the apiKey + sessionId in the body
  // (the proxy reads these and forwards them upstream). The direct
  // upstream path keeps the spec-compliant header-only shape.
  const body: Record<string, unknown> = { jsonrpc: '2.0', id, method, params: params ?? {} };
  if (useProxy) {
    if (apiKey) body.apiKey = apiKey;
    if (sid) body.sessionId = sid;
  }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), method === 'initialize' ? PROBE_TIMEOUT_MS : CALL_TIMEOUT_MS);
  let res: Response;
  let resInfo = `endpoint=${endpoint} method=${method}`;
  try {
    res = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body), signal: ctl.signal });
  } catch (e) {
    clearTimeout(timer);
    const msg = errMessage(e);
    // Distinguish a CORS preflight failure (Safari/Chrome report
    // these as "NetworkError when attempting to fetch resource") from
    // a real network error. We can't tell with 100% certainty from
    // the message alone, but if the user is hitting the same-origin
    // proxy path, a fetch() error here means the browser blocked the
    // request BEFORE we got a response -- almost always a stale cache,
    // a service worker, or a browser extension interfering.
    const isCorsStyle = /NetworkError|fetch resource|Failed to fetch|Load failed/i.test(msg);
    const isAbort = msg.toLowerCase().includes('aborted') || msg.toLowerCase().includes('aborts');
    if (isAbort) {
      throw new McpError(
        `MCP request timed out after ${Math.round(CALL_TIMEOUT_MS / 1000)}s`,
        -32000,
        `(${resInfo}) Check your network and re-probe.`
      );
    }
    if (isCorsStyle && endpoint === PROXY_URL) {
      throw new McpError(
        `Browser blocked the MCP call: ${msg}`,
        -32000,
        `(${resInfo}) The request goes to our same-origin /api/v1/mcp/proxy, so CORS is not the cause. Try a hard refresh (Cmd/Ctrl+Shift+R) to clear the cached JS bundle, or open the page in an incognito window. If that still fails, paste your key into the popover and re-probe.`
      );
    }
    if (isCorsStyle) {
      throw new McpError(
        `Browser blocked the MCP call: ${msg}`,
        -32000,
        `(${resInfo}) The upstream MCP server does not send CORS headers. The request should go through our /api/v1/mcp/proxy -- open the MCP pill in the header to re-probe.`
      );
    }
    throw new McpError(`Network error: ${msg}`, -32000, `(${resInfo}) Check your network connection and try again.`);
  }
  clearTimeout(timer);
  resInfo += ` status=${res.status}`;

  if (res.status === 401 || res.status === 403) {
    saveSession('');
    let upstreamMsg = '';
    try {
      const errBody = (await res.json()) as { error_description?: string; error?: string };
      upstreamMsg = errBody.error_description || errBody.error || '';
    } catch {
      /* ignore */
    }
    const hint = /format/i.test(upstreamMsg)
      ? 'Key must start with tim_ and contain only lowercase letters, numbers, and underscores. Open the MCP pill to re-enter it.'
      : 'Open My Profile -> MCP Server API Keys at ti-mindmap-hub.com and generate a new key.';
    throw new McpError(
      upstreamMsg ? `TI-Mindmap-Hub: ${upstreamMsg}` : 'TI-Mindmap-Hub rejected the API key',
      res.status,
      `(${resInfo}) ${hint}`
    );
  }
  if (!res.ok) {
    const detail = (await res.text()).slice(0, 200);
    throw new McpError(`MCP ${method} failed: HTTP ${res.status} ${detail}`, res.status);
  }

  // 202/204 = notification acknowledged, no body.
  if (res.status === 202 || res.status === 204) {
    return { data: { jsonrpc: '2.0', id } as JsonRpcResponse<T>, headers: res.headers };
  }

  const ct = res.headers.get('content-type') ?? '';
  let parsed: JsonRpcResponse<T>;
  if (ct.includes('text/event-stream')) {
    const text = await res.text();
    parsed = parseSseFrame<T>(text, id);
  } else {
    const text = await res.text();
    if (!text.trim()) {
      parsed = { jsonrpc: '2.0', id } as JsonRpcResponse<T>;
    } else {
      try {
        parsed = JSON.parse(text) as JsonRpcResponse<T>;
      } catch {
        throw new McpError(`MCP returned non-JSON response: ${text.slice(0, 120)}`, -32700);
      }
    }
  }

  if (parsed.error) {
    throw new McpError(parsed.error.message, parsed.error.code);
  }
  return { data: parsed, headers: res.headers };
}

function parseSseFrame<T>(text: string, _id: number | string): JsonRpcResponse<T> {
  // Strip a UTF-8 BOM some proxies tack on.
  const cleaned = text.replace(/^\uFEFF/, '');

  // SSE messages are separated by blank lines (\n\n). Each message block
  // may contain event:, data:, id:, and retry: fields. We split into
  // blocks first, then extract data: lines per block - this avoids
  // concatenating data from *different* messages into one JSON blob.
  const blocks = cleaned.split(/\r?\n\r?\n/);
  const candidates: JsonRpcResponse<T>[] = [];

  for (const block of blocks) {
    const dataLines: string[] = [];
    for (const raw of block.split(/\r?\n/)) {
      const line = raw.replace(/\r$/, '');
      if (!line || line.startsWith(':')) continue; // skip empty + comments
      if (line.startsWith('data:')) {
        dataLines.push(line.startsWith('data: ') ? line.substring(6) : line.substring(5));
      }
    }
    if (dataLines.length === 0) continue;
    const joined = dataLines.join('\n');
    try {
      candidates.push(JSON.parse(joined) as JsonRpcResponse<T>);
    } catch {
      /* not valid JSON - try per-line fallback for this block */
      for (const part of dataLines) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        try {
          candidates.push(JSON.parse(trimmed) as JsonRpcResponse<T>);
          break;
        } catch {
          /* try next line */
        }
      }
    }
  }

  // Return the first valid JSON-RPC response found.
  if (candidates.length > 0) return candidates[0]!;

  // Last-ditch: maybe the server sent a plain JSON body labelled
  // content-type: text/event-stream by mistake.
  try {
    return JSON.parse(cleaned) as JsonRpcResponse<T>;
  } catch {
    throw new McpError(
      `MCP SSE response could not be parsed: ${cleaned.slice(0, 200)}`,
      -32700,
      'The upstream did not return a JSON-RPC payload on any data: line. Re-probe the key.'
    );
  }
}

interface McpToolResult {
  /** MCP spec: a list of typed content blocks. We only need text. */
  content?: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

async function callTool<T>(name: string, args: Record<string, unknown>, apiKey: string): Promise<T> {
  if (!apiKey) {
    throw new McpError('API key not set', -32000, 'Add your TI-Mindmap-Hub API key in the page header.');
  }
  // Always (re-)use an existing session; initialize lazily on the first call.
  if (!loadSession()) await initSession(apiKey);
  try {
    const { data, headers } = await callRaw<McpToolResult>('tools/call', { name, arguments: args }, apiKey, PROXY_URL);
    // Some servers return a fresh session id on the first call -- pick it up.
    const newSid = headers.get('mcp-session-id');
    if (newSid && newSid !== loadSession()) saveSession(newSid);
    const result = data.result;
    if (!result) throw new McpError(`MCP ${name} returned empty result`, -32000);
    if (result.isError) {
      const msg =
        result.content
          ?.map((c) => c.text)
          .filter(Boolean)
          .join('\n') || 'tool reported an error';
      throw new McpError(msg, -32000);
    }
    // The TI-Mindmap-Hub tools return a single JSON-encoded text block.
    // Concatenate all text blocks (defensive against future multi-block results)
    // and JSON.parse the union.
    const text = (result.content ?? [])
      .filter((c) => c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text ?? '')
      .join('\n');
    if (!text) throw new McpError(`MCP ${name} returned no text content`, -32000);
    try {
      return JSON.parse(text) as T;
    } catch {
      // If the tool returned a plain string (e.g. raw text content), pass it through.
      return text as unknown as T;
    }
  } catch (e) {
    // 401 wipes the session; on the next call we re-initialize.
    if (e instanceof McpError && (e.code === 401 || e.code === 403)) {
      saveSession('');
    }
    throw e;
  }
}

// ── Typed wrappers for the tools the AI Report page actually uses ─────

export interface TiReportSummary {
  /**
   * The upstream has been inconsistent across versions about which
   * field name carries the report id -- some rows return
   * `report_id`, others `id`, others `article_id`. We accept all
   * three and normalize them in `idForReport()` so the rest of the
   * client can treat them uniformly.
   */
  report_id?: string;
  id?: string;
  article_id?: string;
  title?: string;
  source?: string;
  published_at?: string;
  url?: string;
  tags?: string[];
  summary?: string;
  actor?: string;
  malware?: string[];
  cves?: string[];
  ioc_count?: number;
  ttp_count?: number;
  cve_count?: number;
}

/** Normalize the various id-field names a report row can use. */
export function idForReport(r: TiReportSummary): string {
  return r.report_id ?? r.id ?? r.article_id ?? '';
}

export interface ListReportsResult {
  reports?: TiReportSummary[];
  total?: number;
}

export async function listReports(
  apiKey: string,
  opts: { search?: string; tags?: string[]; source?: string; timeRange?: string; limit?: number } = {}
): Promise<ListReportsResult> {
  const args: Record<string, unknown> = {};
  if (opts.search) args.search = opts.search;
  if (opts.tags?.length) args.tags = opts.tags;
  if (opts.source) args.source = opts.source;
  if (opts.timeRange) args.time_range = opts.timeRange;
  if (opts.limit) args.limit = opts.limit;
  return callTool<ListReportsResult>('list_reports', args, apiKey);
}

// ── Report content fetchers (used by the AI Report showcase to load
//    any of the 1,628+ reports on ti-mindmap-hub.com on demand) ──────

export type ReportContentType =
  'summary' | 'raw' | 'mindmap' | 'ttps_table' | 'ttps_execution' | 'five_whats' | 'stix' | 'iocs';

export interface ReportDetailsResult {
  report_id: string;
  title?: string;
  source?: string;
  published_at?: string;
  url?: string;
  tags?: string[];
  summary?: string;
  actor?: string;
  malware?: string[];
  cves?: string[];
  iocs?: Array<{ type?: string; value: string }>;
  ttps?: Array<{ id?: string; name?: string; tactic?: string }>;
  cvss?: number;
  severity?: string;
  epss?: number;
}

/** Detailed metadata for a single report. */
export async function getReportDetails(apiKey: string, reportId: string): Promise<ReportDetailsResult> {
  return callTool<ReportDetailsResult>('get_report_details', { report_id: reportId }, apiKey);
}

/**
 * Same as getReportDetails but with `article_id` -- some versions of
 * the upstream tool are named after articles, not reports. We try
 * `report_id` first (per the published docs) and fall back to
 * `article_id` if the server rejects it as a missing field.
 */
export async function getReportDetailsFlexible(apiKey: string, reportId: string): Promise<ReportDetailsResult> {
  try {
    return await getReportDetails(apiKey, reportId);
  } catch (e) {
    if (e instanceof McpError && /report_id|Missing required/i.test(e.message)) {
      return callTool<ReportDetailsResult>('get_report_details', { article_id: reportId }, apiKey);
    }
    throw e;
  }
}

/**
 * Fetch one of the eight content slices for a report. The MCP server
 * returns each slice as a JSON-encoded text block; for the `raw` text
 * the payload is just the article body, so we return a string.
 */
export async function getReportContent(
  apiKey: string,
  reportId: string,
  contentType: ReportContentType
): Promise<unknown> {
  if (!reportId) {
    throw new McpError(
      'reportId is empty -- the upstream returned a row with no report_id / id / article_id field',
      -32000,
      'The list_reports response shape may have changed. Check the proxy log for the raw row.'
    );
  }
  try {
    return await callTool<unknown>('get_report_content', { report_id: reportId, content_type: contentType }, apiKey);
  } catch (e) {
    // Some versions of the upstream tool are named after articles.
    // If the server rejects report_id as missing, retry with
    // article_id before giving up.
    if (e instanceof McpError && /report_id|Missing required/i.test(e.message)) {
      return callTool<unknown>('get_report_content', { article_id: reportId, content_type: contentType }, apiKey);
    }
    throw e;
  }
}

export interface SourcesListResult {
  sources?: Array<{ name: string; count?: number }>;
}

export async function listAvailableSources(apiKey: string): Promise<SourcesListResult> {
  return callTool<SourcesListResult>('get_available_sources', {}, apiKey);
}

export interface TagsListResult {
  tags?: Array<{ name: string; count?: number }>;
}

export async function listAvailableTags(apiKey: string): Promise<TagsListResult> {
  return callTool<TagsListResult>('get_available_tags', {}, apiKey);
}

export interface IocSearchResult {
  ioc_value: string;
  ioc_type?: string;
  reports?: TiReportSummary[];
  total_reports?: number;
  first_seen?: string;
  last_seen?: string;
}

export async function searchIoc(apiKey: string, iocValue: string): Promise<IocSearchResult> {
  return callTool<IocSearchResult>('search_ioc', { ioc_value: iocValue }, apiKey);
}

export interface CveSearchResult {
  cve_id: string;
  cvss_score?: number;
  severity?: string;
  epss_score?: number;
  exploited?: boolean;
  description?: string;
  affected_products?: string[];
  references?: string[];
}

export async function searchCve(apiKey: string, cveId: string): Promise<CveSearchResult> {
  return callTool<CveSearchResult>('search_cve', { cve_id: cveId }, apiKey);
}

export interface BriefingSummary {
  briefing_id: string;
  date?: string;
  type?: 'daily' | 'weekly';
  title?: string;
  summary?: string;
}

export interface BriefingListResult {
  briefings?: BriefingSummary[];
}

export async function getLatestBriefing(apiKey: string): Promise<BriefingSummary | null> {
  const res = await callTool<BriefingListResult>('get_latest_briefing', {}, apiKey);
  return res.briefings?.[0] ?? null;
}

export async function listBriefings(apiKey: string, limit = 10): Promise<BriefingSummary[]> {
  const res = await callTool<BriefingListResult>('list_briefings', { limit }, apiKey);
  return res.briefings ?? [];
}

export interface PlatformStats {
  total_reports?: number;
  total_iocs?: number;
  total_cves?: number;
  total_briefings?: number;
  sources_count?: number;
  last_report_at?: string;
}

export async function getStats(apiKey: string): Promise<PlatformStats> {
  return callTool<PlatformStats>('get_statistics', {}, apiKey);
}

// ── Tool discovery ──────────────────────────────────────────────────

export interface McpToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export async function listTools(apiKey: string, endpoint = PROXY_URL): Promise<McpToolDef[]> {
  const { data } = await callRaw<{ tools: McpToolDef[] }>('tools/list', undefined, apiKey, endpoint);
  return data.result?.tools ?? [];
}

// ── Briefings (3 tools - wrapping the 1 missing one) ────────────────

export async function getBriefingByDate(apiKey: string, date: string): Promise<BriefingSummary | null> {
  const res = await callTool<BriefingListResult>('get_briefing_by_date', { date }, apiKey);
  return res.briefings?.[0] ?? null;
}

// ── CVE Intelligence (5 tools - wrapping the 4 missing ones) ────────

export interface CveSummary {
  cve_id: string;
  cvss_score?: number;
  severity?: string;
  epss_score?: number;
  exploited?: boolean;
  description?: string;
  published_at?: string;
}

export interface CveListResult {
  cves?: CveSummary[];
  total?: number;
  page?: number;
  size?: number;
}

export async function searchCvesByKeyword(apiKey: string, query: string, limit = 12): Promise<CveListResult> {
  return callTool<CveListResult>('search_cves_by_keyword', { query, limit }, apiKey);
}

export async function listCves(
  apiKey: string,
  opts: { page?: number; size?: number; severity?: string; sort_by?: string; sort_order?: string } = {}
): Promise<CveListResult> {
  return callTool<CveListResult>('list_cves', opts, apiKey);
}

export async function getCvesByArticle(apiKey: string, articleId: string): Promise<CveListResult> {
  return callTool<CveListResult>('get_cves_by_article', { article_id: articleId }, apiKey);
}

export interface CveStatistics {
  total_cves?: number;
  by_severity?: Record<string, number>;
  top_vendors?: Array<{ vendor: string; count: number }>;
  exploited_count?: number;
  avg_cvss?: number;
  trend?: Array<{ month: string; count: number }>;
}

export async function getCveStatistics(apiKey: string): Promise<CveStatistics> {
  return callTool<CveStatistics>('get_cve_statistics', {}, apiKey);
}

// ── STIX Bundles (3 tools - all missing) ────────────────────────────

export interface StixBundleSummary {
  article_id: string;
  title?: string;
  stix_size?: number;
  created_at?: string;
}

export interface StixBundleListResult {
  bundles?: StixBundleSummary[];
  total?: number;
}

export async function getStixBundle(apiKey: string, articleId: string): Promise<Record<string, unknown>> {
  return callTool<Record<string, unknown>>('get_stix_bundle', { article_id: articleId }, apiKey);
}

export async function listStixBundles(
  apiKey: string,
  opts: { limit?: number; offset?: number } = {}
): Promise<StixBundleListResult> {
  return callTool<StixBundleListResult>('list_stix_bundles', opts, apiKey);
}

export interface StixStatistics {
  total_bundles?: number;
  total_objects?: number;
  by_type?: Record<string, number>;
}

export async function getStixStatistics(apiKey: string): Promise<StixStatistics> {
  return callTool<StixStatistics>('get_stix_statistics', {}, apiKey);
}

// ── Submissions (1 missing) ─────────────────────────────────────────

export interface SubmitArticleResult {
  article_id?: string;
  status?: string;
  message?: string;
}

export async function submitArticle(apiKey: string, url: string): Promise<SubmitArticleResult> {
  return callTool<SubmitArticleResult>('submit_article', { url }, apiKey);
}

// ── Knowledge Graph - STIX Constellation (6 tools - all missing) ────

export interface KgStatsResult {
  total_entities?: number;
  total_relationships?: number;
  entity_types?: Record<string, number>;
  relationship_types?: Record<string, number>;
}

export async function kgStats(apiKey: string): Promise<KgStatsResult> {
  return callTool<KgStatsResult>('kg_stats', {}, apiKey);
}

export interface KgEntity {
  canon_id: string;
  name: string;
  entity_type: string;
  aliases?: string[];
  description?: string;
}

export interface KgSearchResult {
  entities?: KgEntity[];
  total?: number;
}

export async function kgSearch(
  apiKey: string,
  query: string,
  opts: { entity_type?: string; limit?: number } = {}
): Promise<KgSearchResult> {
  return callTool<KgSearchResult>('kg_search', { query, ...opts }, apiKey);
}

export interface KgRelationship {
  source_id: string;
  source_name: string;
  target_id: string;
  target_name: string;
  relationship_type: string;
  confidence?: number;
}

export interface KgClusterResult {
  center: KgEntity;
  entities?: KgEntity[];
  relationships?: KgRelationship[];
}

export async function kgCluster(
  apiKey: string,
  canonId: string,
  opts: { depth?: number; include_inferred?: boolean } = {}
): Promise<KgClusterResult> {
  return callTool<KgClusterResult>('kg_cluster', { canon_id: canonId, ...opts }, apiKey);
}

export interface KgTimelineEntry {
  report_id: string;
  title?: string;
  date?: string;
  summary?: string;
}

export interface KgTimelineResult {
  entity: KgEntity;
  timeline?: KgTimelineEntry[];
}

export async function kgTimeline(apiKey: string, canonId: string): Promise<KgTimelineResult> {
  return callTool<KgTimelineResult>('kg_timeline', { canon_id: canonId }, apiKey);
}

export interface KgAttackPathResult {
  paths?: Array<{
    source: KgEntity;
    target: KgEntity;
    steps: Array<{ entity: KgEntity; relationship: KgRelationship }>;
  }>;
}

export async function kgAttackPath(
  apiKey: string,
  ttpQuery: string,
  opts: { depth?: number } = {}
): Promise<KgAttackPathResult> {
  return callTool<KgAttackPathResult>('kg_attack_path', { ttp_query: ttpQuery, ...opts }, apiKey);
}

export interface KgCrossReportResult {
  report_a: string;
  report_b: string;
  shared_entities?: KgEntity[];
  shared_count?: number;
}

export async function kgCrossReport(
  apiKey: string,
  reportIdA: string,
  reportIdB: string
): Promise<KgCrossReportResult> {
  return callTool<KgCrossReportResult>('kg_cross_report', { report_id_a: reportIdA, report_id_b: reportIdB }, apiKey);
}

/** One-shot probe: validates the key by initializing a session.
 *  Returns `{ ok, error? }` -- never throws. */
export async function probeConnection(
  apiKey: string,
  endpoint = PROXY_URL
): Promise<{ ok: boolean; serverInfo?: { name?: string; version?: string }; error?: string }> {
  if (!apiKey) return { ok: false, error: 'No API key set' };
  try {
    saveSession('');
    const { headers } = await callRaw<{ serverInfo?: { name?: string; version?: string } }>(
      'initialize',
      {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'pranithjain-qzz-io', version: '1.0.0' },
      },
      apiKey,
      endpoint,
      /* fresh */ true
    );
    const id = headers.get('mcp-session-id');
    if (id) saveSession(id);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: errMessage(e) };
  }
}
