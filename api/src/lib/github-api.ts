/**
 * Shared GitHub REST access.
 *
 * # Why this exists
 *
 * Every `api.github.com` call made from the Worker shares one egress IP pool.
 * Unauthenticated, that pool has a 60 req/hour budget that anything can exhaust
 * — after which GitHub answers **403** (or 429) to everyone. Observed in
 * production 2026-10-16: `/api/v1/cve-health` reported
 * `github_api: fail — GitHub API returned 403`, which silently starved every
 * feature built on it (CVE PoC search, supply-chain advisories, GenDigital IOC
 * lists, Maltrail trails, ATT&CK flow corpus, …).
 *
 * `GITHUB_TOKEN` is already a declared, optional Env secret (see Env in
 * api/src/env.ts) and was already threaded through a handful of call sites
 * (github-security, depx, malicious-packages, supply-chain-attacks,
 * cve-poc-scan, cve-poc-map). The rest of the callers simply never asked, so
 * they ran anonymously and absorbed the shared quota.
 *
 * # Contract
 *
 *  - `githubHeaders(env, extra)` returns the base headers **plus**
 *    `Authorization: Bearer <token>` when one is configured. Passing `env` is
 *    what turns a 403-prone call into a 5000 req/hour one.
 *  - `githubFetchJson` adds the same headers, keeps the response JSON, and
 *    surfaces 403/429 as a `rate_limited` result rather than an opaque HTTP
 *    error, so callers can degrade instead of failing.
 *
 * Token choice matters: a classic PAT needs only `public_repo` (or nothing at
 * all for public data) to lift the limit from 60/h to 5000/h. Set it with
 * `wrangler secret put GITHUB_TOKEN`. With no token set, everything still works
 * — just anonymously, and it is the anonymous quota that produced the 403s.
 */

/** Minimal shape so lib functions can take `env` without importing Env. */
export interface GithubEnv {
  GITHUB_TOKEN?: string;
}

const API_VERSION = '2022-11-28';
const BASE = 'https://api.github.com';

/** Base headers for any api.github.com request, authenticated when possible. */
export function githubHeaders(env?: GithubEnv, extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'user-agent': 'pranithjain-dfir/1.0 (+https://pranithjain.qzz.io)',
    accept: 'application/vnd.github+json',
    'x-github-api-version': API_VERSION,
    ...extra,
  };
  const token = env?.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export interface GithubFetchResult<T> {
  ok: boolean;
  /** HTTP status, or 0 when the request never completed (timeout/network). */
  status: number;
  /** Parsed body when ok. */
  data?: T;
  /** True for 403/429 — a quota problem, not a data problem. */
  rateLimited?: boolean;
  /** `x-ratelimit-reset` epoch seconds, when GitHub sent one. */
  rateLimitReset?: number;
  /** Short diagnostic for logs. Never contains the token. */
  error?: string;
}

/**
 * GET + JSON with the shared headers and rate-limit awareness.
 *
 * Deliberately does NOT retry: a 403 here means the shared quota is gone, and
 * retrying multiplies the load that caused it. Callers are expected to degrade
 * (serve last-good, return an empty array) rather than hammer.
 */
export async function githubFetchJson<T>(
  env: GithubEnv | undefined,
  url: string,
  init?: { timeoutMs?: number; accept?: string }
): Promise<GithubFetchResult<T>> {
  const abs = url.startsWith('http') ? url : `${BASE}${url.startsWith('/') ? '' : '/'}${url}`;
  try {
    const res = await fetch(abs, {
      headers: githubHeaders(env, init?.accept ? { accept: init.accept } : undefined),
      signal: AbortSignal.timeout(init?.timeoutMs ?? 8000),
      cf: { cacheTtlByStatus: { '200-299': 900, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    const resetHeader = res.headers.get('x-ratelimit-reset');
    const rateLimitReset = resetHeader ? Number(resetHeader) : undefined;
    if (!res.ok) {
      const rateLimited = res.status === 403 || res.status === 429;
      return {
        ok: false,
        status: res.status,
        rateLimited,
        rateLimitReset,
        error: rateLimited
          ? env?.GITHUB_TOKEN
            ? `GitHub ${res.status} (token present — likely the token's own quota; check its scopes)`
            : 'GitHub 403/429 — anonymous egress quota exhausted; set the GITHUB_TOKEN Worker secret'
          : `GitHub ${res.status}`,
      };
    }
    return { ok: true, status: res.status, data: (await res.json()) as T };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      error: e instanceof Error ? `github fetch failed: ${e.message.slice(0, 80)}` : 'github fetch failed',
    };
  }
}

/** Convenience: the advisories list, used by CVE lookup and the supply chain. */
export function advisoriesUrl(params: Record<string, string | number>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) q.set(k, String(v));
  return `${BASE}/advisories?${q.toString()}`;
}

/** Convenience: a single repository file by path, base64 contents. */
export function repoContentsUrl(owner: string, repo: string, path: string, ref?: string): string {
  const q = ref ? `?ref=${encodeURIComponent(ref)}` : '';
  return `${BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path
    .split('/')
    .map(encodeURIComponent)
    .join('/')}${q}`;
}
