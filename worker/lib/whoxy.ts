import { errMessage } from './err';
export interface WhoxyDomainResult {
  domain_name: string;
  registrant_name?: string;
  company_name?: string;
  registrant_email?: string;
  creation_date?: string;
  expiry_date?: string;
}

export interface WhoxyReverseWhoisResult {
  search_type: 'email' | 'name' | 'company' | 'keyword';
  search_value: string;
  domains: WhoxyDomainResult[];
  total_results: number;
  pages_fetched: number;
  success: boolean;
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'skipped' | 'failed';
    ms: number;
    error?: string;
  }>;
}

interface EnvWithWhoxy {
  WHOXY_API_KEY?: string;
}

const WHOXY_BASE = 'https://api.whoxy.com';

export async function whoxyReverseWhois(
  env: EnvWithWhoxy,
  query: string,
  searchType: 'email' | 'name' | 'company' | 'keyword' = 'email'
): Promise<WhoxyReverseWhoisResult> {
  const result: WhoxyReverseWhoisResult = {
    search_type: searchType,
    search_value: query,
    domains: [],
    total_results: 0,
    pages_fetched: 0,
    success: false,
    diagnostics: [],
  };

  if (!query || !query.trim()) {
    result.diagnostics.push({
      provider: 'validator',
      status: 'failed',
      ms: 0,
      error: 'empty search query',
    });
    return result;
  }

  if (!env.WHOXY_API_KEY) {
    result.diagnostics.push({
      provider: 'whoxy',
      status: 'skipped',
      ms: 0,
      error: 'WHOXY_API_KEY not set',
    });
    return result;
  }

  const identifierParam = searchType === 'keyword' ? 'keyword' : searchType;
  const url = `${WHOXY_BASE}/?key=${env.WHOXY_API_KEY}&reverse=whois&${identifierParam}=${encodeURIComponent(query.trim())}`;

  const t0 = Date.now();
  try {
    let page = 1;
    let totalPages = 1;

    while (page <= totalPages && page <= 10) {
      const pageUrl = page === 1 ? url : `${url}&page=${page}`;
      const res = await fetch(pageUrl, { signal: AbortSignal.timeout(10_000) });

      if (!res.ok) {
        const body = await res.text().catch(() => '');
        result.diagnostics.push({
          provider: 'whoxy',
          status: 'failed',
          ms: Date.now() - t0,
          error: `whoxy returned ${res.status}: ${body.slice(0, 200)}`,
        });
        return result;
      }

      const body = (await res.json()) as {
        status: number;
        total_results?: number;
        total_pages?: number;
        search_result?: Array<{
          domain_name: string;
          registrant_name?: string;
          company_name?: string;
          registrant_email?: string;
          creation_date?: string;
          expiry_date?: string;
        }>;
        result?: Array<{
          domain_name: string;
          registrant_name?: string;
          company_name?: string;
          registrant_email?: string;
          creation_date?: string;
          expiry_date?: string;
        }>;
        message?: string;
      };

      if (body.status !== 1) {
        result.diagnostics.push({
          provider: 'whoxy',
          status: 'failed',
          ms: Date.now() - t0,
          error: body.message ?? 'whoxy returned status=0',
        });
        return result;
      }

      const records = body.search_result ?? body.result ?? [];
      result.domains.push(
        ...records.map((r) => ({
          domain_name: r.domain_name,
          registrant_name: r.registrant_name,
          company_name: r.company_name,
          registrant_email: r.registrant_email,
          creation_date: r.creation_date,
          expiry_date: r.expiry_date,
        }))
      );

      result.total_results = body.total_results ?? result.domains.length;
      totalPages = body.total_pages ?? 1;
      result.pages_fetched = page;
      page++;
    }

    result.success = true;
    result.diagnostics.push({
      provider: 'whoxy',
      status: 'ok',
      ms: Date.now() - t0,
    });
  } catch (e) {
    result.diagnostics.push({
      provider: 'whoxy',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}
