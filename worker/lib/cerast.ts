/**
 * Cerast Intelligence — domain exposure search.
 *
 * Proxies the free Cerast Intelligence OSINT tool at
 * search.cerast-intelligence.com. Finds exposed paths and
 * misconfigurations across observed domains.
 *
 * API: GET https://search.cerast-intelligence.com/api/search?q=<query>
 * Response: { results: CerastResult[], count: number, limited: boolean }
 */

import { errMessage } from './err';

export interface CerastResult {
  domain: string;
  path: string;
  category: string;
  impact: 'HIGH' | 'MEDIUM' | 'LOW';
  page_rank: number;
  version: string;
  created: string;
  multihost: boolean;
}

export interface CerastSearchResult {
  query: string;
  results: CerastResult[];
  count: number;
  limited: boolean;
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'rate_limited' | 'failed';
    ms: number;
    error?: string;
  }>;
}

const CERAST_BASE = 'https://search.cerast-intelligence.com';
const MIN_QUERY_LEN = 3;

export function isValidCerastQuery(q: string): boolean {
  return q.trim().length >= MIN_QUERY_LEN;
}

export async function cerastSearch(query: string): Promise<CerastSearchResult> {
  const result: CerastSearchResult = {
    query,
    results: [],
    count: 0,
    limited: false,
    diagnostics: [],
  };

  if (!isValidCerastQuery(query)) {
    result.diagnostics.push({
      provider: 'validator',
      status: 'failed',
      ms: 0,
      error: `query must be at least ${MIN_QUERY_LEN} characters`,
    });
    return result;
  }

  const t0 = Date.now();
  try {
    const res = await fetch(`${CERAST_BASE}/api/search?q=${encodeURIComponent(query)}`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });

    if (res.status === 429) {
      const retryAfter = res.headers.get('Retry-After');
      result.diagnostics.push({
        provider: 'cerast',
        status: 'rate_limited',
        ms: Date.now() - t0,
        error: retryAfter ? `retry in ${retryAfter}s` : 'rate limited',
      });
      return result;
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      result.diagnostics.push({
        provider: 'cerast',
        status: 'failed',
        ms: Date.now() - t0,
        error: `cerast returned ${res.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const data = (await res.json()) as {
      results?: CerastResult[];
      count?: number;
      limited?: boolean;
      error?: string;
    };

    if (data.error) {
      result.diagnostics.push({
        provider: 'cerast',
        status: 'failed',
        ms: Date.now() - t0,
        error: data.error,
      });
      return result;
    }

    result.results = data.results ?? [];
    result.count = data.count ?? 0;
    result.limited = data.limited ?? false;
    result.diagnostics.push({ provider: 'cerast', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'cerast',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}
