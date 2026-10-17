/**
 * Intelligence X API client — typed wrapper around intelx.io endpoints.
 *
 * Requires `INTELX_API_KEY` (paid). Two search modes:
 *   1. Leaked-data search — emails, domains, URLs, BTC addresses, IBANs,
 *      credit cards, phone numbers, etc. across paste sites, breach archives,
 *      and dark-web collections.
 *   2. Phonebook — reverse email/username lookup returning associated emails,
 *      domains, and URLs.
 *
 * Both are async: POST /search → get search_id, then GET /search/result?id=…
 * to poll for results. This module wraps both steps into a single call.
 */

import { errMessage } from './err';

const INTELX_BASE = 'https://2.intelx.io';
const TIMEOUT_MS = 15_000;

interface IntelxEnv {
  INTELX_API_KEY?: string;
}

// ─── Types ──────────────────────────────────────────────────────────────

export interface IntelxSearchRecord {
  /** Media type — 0 = website, 11 = phone, 12 = domain, etc. */
  media?: number;
  /** Record type label (e.g. "phone", "domain", "email"). */
  name?: string;
  /** Value (phone number, email, domain, URL, etc.). */
  value?: string;
  /** Breach / source identifier. */
  source?: string;
  /** Date string if available. */
  date?: string;
  /** Size in bytes. */
  size?: number;
  /** Whether this record was indexed from a public or private source. */
  system?: string;
  /** Additional metadata. */
  [key: string]: unknown;
}

export interface IntelxSearchResponse {
  success: boolean;
  query: string;
  search_id?: string;
  records: IntelxSearchRecord[];
  total: number;
  elapsed_ms: number;
  mode: 'search' | 'phonebook';
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'skipped' | 'failed';
    ms: number;
    error?: string;
  }>;
}

// ─── Internal helpers ───────────────────────────────────────────────────

function requireKey(env: IntelxEnv): string {
  const key = env.INTELX_API_KEY;
  if (!key) {
    throw new Error('INTELX_API_KEY not set — get a paid key at intelx.io');
  }
  return key;
}

interface IntelxRawSearchResponse {
  id?: string;
  records_fetched?: number;
  status?: number;
  [key: string]: unknown;
}

interface IntelxRawResultResponse {
  records?: IntelxSearchRecord[];
  [key: string]: unknown;
}

/**
 * POST a search query and return the search_id. This is the first async step.
 */
async function initiateSearch(
  key: string,
  endpoint: string,
  q: string,
  maxResults: number
): Promise<{ search_id: string; ms: number }> {
  const t0 = Date.now();
  // IntelligenceX uses GET with query params for search initiation
  const url = new URL(`${INTELX_BASE}${endpoint}`);
  url.searchParams.set('term', q);
  url.searchParams.set('key', key);
  url.searchParams.set('maxresults', String(maxResults));

  const res2 = await fetch(url.toString(), {
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });

  if (!res2.ok) {
    throw new Error(`IntelligenceX ${endpoint} returned ${res2.status}`);
  }

  const body = (await res2.json()) as IntelxRawSearchResponse;
  if (!body.id) {
    throw new Error('IntelligenceX returned no search_id');
  }

  return { search_id: body.id, ms: Date.now() - t0 };
}

/**
 * Poll for search results by search_id.
 */
async function fetchResults(
  key: string,
  resultEndpoint: string,
  searchId: string
): Promise<{ records: IntelxSearchRecord[]; ms: number }> {
  const t0 = Date.now();
  const url = new URL(`${INTELX_BASE}${resultEndpoint}`);
  url.searchParams.set('id', searchId);
  url.searchParams.set('key', key);
  url.searchParams.set('limit', '50');

  const res = await fetch(url.toString(), {
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });

  if (!res.ok) {
    throw new Error(`IntelligenceX results returned ${res.status}`);
  }

  const body = (await res.json()) as IntelxRawResultResponse;
  return { records: body.records ?? [], ms: Date.now() - t0 };
}

// ─── Public API ─────────────────────────────────────────────────────────

/**
 * Search Intelligence X for leaked data, paste sites, breach archives,
 * dark-web content. Supports emails, domains, URLs, BTC addresses, IBANs,
 * credit cards, phone numbers, and more.
 */
export async function intelxSearch(
  env: IntelxEnv,
  query: string,
  opts: { maxResults?: number } = {}
): Promise<IntelxSearchResponse> {
  const result: IntelxSearchResponse = {
    success: false,
    query,
    records: [],
    total: 0,
    elapsed_ms: 0,
    mode: 'search',
    diagnostics: [],
  };

  if (!query || !query.trim()) {
    result.diagnostics.push({ provider: 'validator', status: 'failed', ms: 0, error: 'empty query' });
    return result;
  }

  const t0 = Date.now();
  try {
    const key = requireKey(env);
    const maxResults = opts.maxResults ?? 20;

    const { search_id, ms: initMs } = await initiateSearch(key, '/intelligent/search', query.trim(), maxResults);
    result.search_id = search_id;
    result.diagnostics.push({ provider: 'intelx-init', status: 'ok', ms: initMs });

    // Wait a moment for async indexing, then poll
    await new Promise((r) => setTimeout(r, 1000));

    const { records, ms: resultMs } = await fetchResults(key, '/intelligent/search/result', search_id);
    result.records = records;
    result.total = records.length;
    result.diagnostics.push({ provider: 'intelx-results', status: 'ok', ms: resultMs });
    result.success = true;
  } catch (e) {
    result.diagnostics.push({
      provider: 'intelx',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  result.elapsed_ms = Date.now() - t0;
  return result;
}

/**
 * Intelligence X Phonebook — find emails, domains, and URLs associated with
 * a search term (name, domain, keyword).
 */
export async function intelxPhonebook(
  env: IntelxEnv,
  query: string,
  opts: { maxResults?: number } = {}
): Promise<IntelxSearchResponse> {
  const result: IntelxSearchResponse = {
    success: false,
    query,
    records: [],
    total: 0,
    elapsed_ms: 0,
    mode: 'phonebook',
    diagnostics: [],
  };

  if (!query || !query.trim()) {
    result.diagnostics.push({ provider: 'validator', status: 'failed', ms: 0, error: 'empty query' });
    return result;
  }

  const t0 = Date.now();
  try {
    const key = requireKey(env);
    const maxResults = opts.maxResults ?? 20;

    const { search_id, ms: initMs } = await initiateSearch(key, '/phonebook/search', query.trim(), maxResults);
    result.search_id = search_id;
    result.diagnostics.push({ provider: 'intelx-phonebook-init', status: 'ok', ms: initMs });

    // Wait a moment for async indexing, then poll
    await new Promise((r) => setTimeout(r, 1000));

    const { records, ms: resultMs } = await fetchResults(key, '/phonebook/search/result', search_id);
    result.records = records;
    result.total = records.length;
    result.diagnostics.push({ provider: 'intelx-phonebook-results', status: 'ok', ms: resultMs });
    result.success = true;
  } catch (e) {
    result.diagnostics.push({
      provider: 'intelx-phonebook',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  result.elapsed_ms = Date.now() - t0;
  return result;
}
