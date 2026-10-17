/**
 * Hudson Rock Cavalier API v3 client.
 *
 * Typed wrapper around every public Cavalier endpoint. Requires an API key
 * (free tier: hudsonrock.com/free-api-key). When the key is missing, callers
 * get a clear error rather than a silent 401 from upstream.
 *
 * Base URL: https://api.hudsonrock.com/json/v3
 * Auth:     `api-key` header
 *
 * Rate limits (free tier): conservative — this module does NOT enforce its own
 * throttling; callers should cache aggressively (1 h TTL recommended).
 */

import { errMessage } from './err';

const HR_BASE = 'https://api.hudsonrock.com/json/v3';
const TIMEOUT_MS = 15_000;

// ─── Shared types ──────────────────────────────────────────────────────────

export interface HRCredential {
  url: string;
  domain: string;
  username: string;
  password: string;
  type: 'employee' | 'user' | 'third_party' | 'client';
}

export interface HRStealerEntry {
  _id: string;
  stealer: string;
  date_compromised: string;
  date_uploaded: string;
  stealer_family: string;
  ip: string;
  computer_name: string;
  operating_system: string;
  malware_path?: string;
  antiviruses?: string[];
  employeeAt?: string[];
  clientAt?: string[];
  credentials: HRCredential[];
  installed_software?: Array<{ program: string; version: string }>;
  employee_session_cookies?: Array<{
    url: string;
    url_stripped: string;
    name: string;
    value: string;
    expiry: string;
  }>;
  search_data?: Array<{ engine: string; term: string }>;
  sensitive_applications?: string[];
  dir_tree?: string[];
}

export interface HRSearchResponse {
  data: HRStealerEntry[];
  nextCursor?: string;
}

export interface HRDomainOverview {
  _id: string;
  domain: string;
  compromised_employees: number;
  compromised_users: number;
  last_employee_compromised?: string;
  last_user_compromised?: string;
  last_employee_uploaded?: string;
  last_user_uploaded?: string;
}

export interface HRDomainOverviewResponse {
  data: HRDomainOverview[];
  nextCursor?: string;
}

export interface HRDiscoveryEntry {
  _id: string;
  url: string;
  domain: string;
  type: string;
  last_uploaded_date: string;
  occurrence: number;
}

export interface HRDiscoveryResponse {
  data: HRDiscoveryEntry[];
  nextCursor?: string;
}

export interface HRAssessmentResponse {
  employee_urls: Array<{ url: string; occurrence: number }>;
  third_party_urls: Array<{ url: string; occurrence: number; domain: string }>;
  user_urls: Array<{ url: string; occurrence: number }>;
}

export interface HRInfectionAnalysis {
  likely_infection_url: string;
  infection_confidence: number;
  infection_reasoning: string;
  infection_flow: Array<{
    timestamp: string;
    url: string;
    notes: string;
  }>;
  analyst_summary: string;
}

export interface HRInfectionAnalysisResponse {
  data: HRInfectionAnalysis;
}

export interface HRAccountInfo {
  email: string;
  api_key: string;
  permissions: string[];
  company?: string;
}

// ─── Request helpers ───────────────────────────────────────────────────────

interface HREnv {
  HUDSONROCK_API_KEY?: string;
}

function requireKey(env: HREnv): string {
  const key = env.HUDSONROCK_API_KEY;
  if (!key)
    throw new Error('HUDSONROCK_API_KEY is not set — get a free key at https://www.hudsonrock.com/free-api-key');
  return key;
}

async function hrPost<T>(env: HREnv, path: string, body: Record<string, unknown>): Promise<T> {
  const apiKey = requireKey(env);
  const res = await fetch(`${HR_BASE}${path}`, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'api-key': apiKey,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Hudson Rock ${path} returned ${res.status}: ${text.slice(0, 300)}`);
  }
  return res.json() as Promise<T>;
}

async function hrGet<T>(env: HREnv, path: string): Promise<T> {
  const apiKey = requireKey(env);
  const res = await fetch(`${HR_BASE}${path}`, {
    method: 'GET',
    headers: {
      accept: 'application/json',
      'api-key': apiKey,
    },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Hudson Rock ${path} returned ${res.status}: ${text.slice(0, 300)}`);
  }
  return res.json() as Promise<T>;
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Search for domain-wide infostealer compromises.
 *
 * @see https://docs.hudsonrock.com/docs/domain-search
 */
export async function searchByDomain(
  env: HREnv,
  domains: string[],
  opts: {
    types?: Array<'employees' | 'users' | 'third_parties'>;
    keywords?: string[];
    keywords_match?: 'any' | 'all';
    filter_credentials?: boolean;
    sort_by?: 'date_compromised' | 'date_uploaded';
    sort_direction?: 'asc' | 'desc';
    start_date?: string;
    end_date?: string;
    cursor?: string;
    additional_fields?: Array<
      | 'installed_software'
      | 'employee_session_cookies'
      | 'search_data'
      | 'password_strength'
      | 'sensitive_applications'
      | 'dir_tree'
    >;
  } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-domain', {
    domains,
    ...opts,
    filter_credentials: opts.filter_credentials ?? true,
  });
}

/**
 * Batch search for compromised credentials by email addresses (up to 50).
 *
 * @see https://docs.hudsonrock.com/docs/email-search
 */
export async function searchByEmails(
  env: HREnv,
  emails: string[],
  opts: {
    types?: Array<'employees' | 'users' | 'third_parties'>;
    domains?: string[];
    keywords?: string[];
    keywords_match?: 'any' | 'all';
    filter_credentials?: boolean;
    sort_by?: 'date_compromised' | 'date_uploaded';
    sort_direction?: 'asc' | 'desc';
    start_date?: string;
    end_date?: string;
    cursor?: string;
  } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-login/emails', {
    logins: emails.slice(0, 50),
    ...opts,
    filter_credentials: opts.filter_credentials ?? true,
  });
}

/**
 * Search for compromised credentials by usernames.
 *
 * @see https://docs.hudsonrock.com/docs/username-search
 */
export async function searchByUsername(
  env: HREnv,
  usernames: string[],
  opts: {
    types?: Array<'employees' | 'users' | 'third_parties'>;
    domains?: string[];
    keywords?: string[];
    keywords_match?: 'any' | 'all';
    filter_credentials?: boolean;
    sort_by?: 'date_compromised' | 'date_uploaded';
    sort_direction?: 'asc' | 'desc';
    cursor?: string;
  } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-login/usernames', {
    logins: usernames.slice(0, 50),
    ...opts,
    filter_credentials: opts.filter_credentials ?? true,
  });
}

/**
 * Search for compromises by IP address or CIDR range.
 *
 * @see https://docs.hudsonrock.com/docs/ipcidr-search
 */
export async function searchByIp(
  env: HREnv,
  ips: string[],
  opts: {
    filter_credentials?: boolean;
    sort_by?: 'date_compromised' | 'date_uploaded';
    sort_direction?: 'asc' | 'desc';
    cursor?: string;
  } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-ip', {
    logins: ips.slice(0, 50),
    ...opts,
    filter_credentials: opts.filter_credentials ?? true,
  });
}

/**
 * Search for compromises by stealer ID.
 *
 * @see https://docs.hudsonrock.com/docs/stealer-search
 */
export async function searchByStealer(
  env: HREnv,
  stealerId: string,
  opts: {
    additional_fields?: Array<'installed_software' | 'employee_session_cookies' | 'search_data'>;
  } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-stealer', {
    stealer: stealerId,
    ...opts,
  });
}

/**
 * Get domain compromise overview statistics.
 *
 * @see https://docs.hudsonrock.com/docs/domain-overview
 */
export async function domainOverview(
  env: HREnv,
  domains: string[],
  opts: {
    min_employees_compromised?: number;
    max_employees_compromised?: number;
    min_users_compromised?: number;
    max_users_compromised?: number;
    last_employee_compromised?: string;
    last_user_compromised?: string;
    sort_by?:
      'last_employee_compromised' | 'last_user_compromised' | 'compromised_employees' | 'last_employee_uploaded';
    sort_direction?: 'asc' | 'desc';
    cursor?: string;
  } = {}
): Promise<HRDomainOverviewResponse> {
  return hrPost(env, '/search-by-domain/overview', {
    domains,
    ...opts,
  });
}

/**
 * Discover all compromised URLs for a domain (attack surface mapping).
 *
 * @see https://docs.hudsonrock.com/docs/assets-discovery
 */
export async function assetsDiscovery(
  env: HREnv,
  domains: string[],
  opts: {
    types?: Array<'employees' | 'users'>;
    keywords?: string[];
    keywords_match?: 'any' | 'all';
    cursor?: string;
  } = {}
): Promise<HRDiscoveryResponse> {
  return hrPost(env, '/search-by-domain/discovery', {
    domains,
    ...opts,
  });
}

/**
 * Third-party / supply-chain risk assessment for a single domain.
 *
 * @see https://docs.hudsonrock.com/docs/third-party-risk-assessment
 */
export async function thirdPartyRiskAssessment(env: HREnv, domain: string): Promise<HRAssessmentResponse> {
  return hrPost(env, '/search-by-domain/assessment', { domain });
}

/**
 * AI-powered infection source analysis (works best with Lumma stealers).
 *
 * @see https://docs.hudsonrock.com/docs/ai-infection-analysis-new
 */
export async function infectionAnalysis(env: HREnv, stealerId: string): Promise<HRInfectionAnalysisResponse> {
  return hrPost(env, '/search-by-stealer/infection-analysis', {
    stealer: stealerId,
  });
}

/**
 * Advanced multi-filter search across domains, industries, countries.
 *
 * @see https://docs.hudsonrock.com/reference/advancedsearch
 */
export async function advancedSearch(
  env: HREnv,
  opts: {
    domains?: string[];
    employees?: string[];
    users?: string[];
    last_compromised_start?: string;
    last_compromised_end?: string;
    last_uploaded_start?: string;
    last_uploaded_end?: string;
    min_company_size?: number;
    max_company_size?: number;
    industry?: string;
    country?: string;
    cursor?: string;
  }
): Promise<HRSearchResponse> {
  return hrPost(env, '/advancedsearch', opts);
}

/**
 * Find domains by keyword (recon / external attack surface).
 *
 * @see https://docs.hudsonrock.com/reference/search-by-keyword
 */
export async function searchByKeyword(
  env: HREnv,
  keyword: string,
  opts: { cursor?: string } = {}
): Promise<{ data: Array<{ domain: string }>; nextCursor?: string }> {
  return hrPost(env, '/search-by-keyword', { keyword, ...opts });
}

/**
 * Find URLs by keyword (external attack surface).
 *
 * @see https://docs.hudsonrock.com/reference/searchbykeywordurls
 */
export async function searchUrlsByKeyword(
  env: HREnv,
  keyword: string,
  opts: { cursor?: string } = {}
): Promise<{ data: Array<{ url: string; domain: string }>; nextCursor?: string }> {
  return hrPost(env, '/searchbykeywordurls', { keyword, ...opts });
}

/**
 * Search for credentials based on password (password-reuse detection).
 *
 * @see https://docs.hudsonrock.com/docs/password-search
 */
export async function searchByPassword(
  env: HREnv,
  password: string,
  opts: { cursor?: string } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-password', { password, ...opts });
}

/**
 * Search for credentials based on file names found on infected machines.
 *
 * @see https://docs.hudsonrock.com/reference/search-by-file
 */
export async function searchByFile(
  env: HREnv,
  fileName: string,
  opts: { cursor?: string } = {}
): Promise<HRSearchResponse> {
  return hrPost(env, '/search-by-file', { file_name: fileName, ...opts });
}

/**
 * Get the authenticated user's account info and permissions.
 *
 * @see https://docs.hudsonrock.com/reference/getmyaccount
 */
export async function getAccount(env: HREnv): Promise<HRAccountInfo> {
  return hrGet(env, '/getmyaccount');
}

/**
 * Check if the API key is valid by fetching account info.
 * Returns true if the key works, false if it's invalid/expired.
 */
export async function validateKey(env: HREnv): Promise<boolean> {
  try {
    await getAccount(env);
    return true;
  } catch (_catchErr) {
    console.error('validateKey failed:', errMessage(_catchErr));
    return false;
  }
}
