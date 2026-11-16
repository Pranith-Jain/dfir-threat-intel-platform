/**
 * HexBrain CVE enrichment client (https://hexbrainai.com/docs).
 *
 * Auth: `Authorization: Bearer <HEXBRAIN_API_KEY>` (free key from
 * hexbrainai.com/account). Free-tier limits: 90 req/min, 200 req/day, so
 * every successful (or definitively-missing) response is cached in KV for
 * 24h — a given CVE costs the daily budget at most once, across all colos.
 *
 * The upstream response schema is intentionally loose (the OpenAPI doc for
 * `get_cve` declares only `additionalProperties: true`), so every field is
 * read DEFENSIVELY across candidate names — the same posture as vulncheck.ts.
 * Tighten the reads after verifying against a live response once a key is
 * configured.
 *
 * What get_cve adds that our other sources do not: a predicted likelihood of
 * exploitation for the next 30 days, the public exploit corpus (GitHub PoC
 * repos with stars, Metasploit, Exploit-DB), and a detection check (nuclei
 * command plus what a positive result looks like).
 */
import type { KVNamespace } from '@cloudflare/workers-types';
import { kvBackedGet, kvBackedPut } from './route-cache';

const BASE = 'https://hexbrainai.com/api/v1';
const UA = 'pranithjain.qzz.io dfir';
const TIMEOUT = 10_000;
/** 24h — matches the free key's 200/day budget (one fetch per CVE per day). */
const CACHE_TTL = 86_400;
const CACHE_PREFIX = 'hexbrain:cve:';
/** Bounds the cached payload; the UI shows a subset of these. */
const MAX_EXPLOITS = 12;
const MAX_REFERENCES = 20;

export interface HbExploit {
  /** `github` | `metasploit` | `exploitdb` | ... when upstream names it. */
  kind?: string;
  name?: string;
  url?: string;
  stars?: number;
  date?: string;
  desc?: string;
}

export interface HbCveIntel {
  cve: string;
  /** False = HexBrain has no record for this id (cached so 404s don't burn quota). */
  found: boolean;
  title?: string;
  cwe?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  /** In-the-wild exploitation / CISA KEV listing. */
  exploited_in_wild?: boolean;
  kev_date?: string;
  ransomware?: boolean;
  /** Predicted likelihood of exploitation in the next 30 days, 0..1. */
  likelihood_30d?: number;
  /** "N% of all CVEs are less likely", 0..100. */
  likelihood_percentile?: number;
  exploit_count?: number;
  exploits: HbExploit[];
  /** Ready-to-run nuclei command when a detection check exists. */
  nuclei_command?: string;
  /** What a positive check result looks like ("Positive when: ..."). */
  positive_when?: string;
  impact?: string;
  fix?: string;
  references: string[];
}

export type HbErrorInfo = {
  code: 'auth' | 'rate_limited' | 'not_found' | 'upstream_5xx' | 'network_error' | 'bad_payload';
  status?: number;
};

const str = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const bool = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** First present (non-null) value across candidate keys. */
function pick(obj: Record<string, unknown>, ...keys: string[]): unknown {
  for (const k of keys) {
    const v = obj[k];
    if (v !== undefined && v !== null) return v;
  }
  return undefined;
}

function asObj(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

const SEVERITY_BANDS = [undefined, 'low', 'medium', 'high', 'critical'] as const;

function normalizeSeverity(v: unknown): HbCveIntel['severity'] {
  const s = typeof v === 'string' ? v.toLowerCase() : undefined;
  if (s === 'low' || s === 'medium' || s === 'high' || s === 'critical') return s;
  if (s === 'moderate') return 'medium';
  // The public page renders severity as a 1..4 band (data-k=3 -> "high").
  if (typeof v === 'number' && v >= 1 && v <= 4) return SEVERITY_BANDS[v];
  return undefined;
}

function normalizeExploit(e: unknown): HbExploit | null {
  if (typeof e === 'string') {
    return { url: e, kind: e.includes('github.com') ? 'github' : e.includes('exploit-db') ? 'exploitdb' : undefined };
  }
  const o = asObj(e);
  if (!o) return null;
  const url = str(pick(o, 'url', 'html_url', 'link', 'repo', 'repository'));
  const name = str(pick(o, 'name', 'title', 'repo_name', 'repository', 'module'));
  const desc = str(pick(o, 'desc', 'description', 'summary'));
  if (!url && !name && !desc) return null;
  return {
    kind: str(pick(o, 'kind', 'type', 'source')) ?? (url?.includes('github.com') ? 'github' : undefined),
    name,
    url,
    stars: num(pick(o, 'stars', 'stargazers', 'stargazers_count', 'stars_count')),
    date: str(pick(o, 'date', 'created', 'created_at', 'updated', 'updated_at', 'published')),
    desc,
  };
}

function normalizeCve(cve: string, body: unknown): HbCveIntel {
  const intel: HbCveIntel = { cve, found: false, exploits: [], references: [] };
  let d = asObj(body);
  if (!d) return intel;
  // Unwrap common envelopes ({data: {...}} / {cve: {...}} / {result: {...}}).
  d = asObj(pick(d, 'data', 'cve', 'result')) ?? d;

  intel.title = str(pick(d, 'title', 'name', 'cve_title'));
  intel.cwe = str(pick(d, 'cwe', 'cwe_id', 'weakness')) ?? arr(pick(d, 'cwe')).map(str).find(Boolean);
  intel.severity = normalizeSeverity(pick(d, 'severity', 'sev'));

  // Exploitation flags. `kev` may be a boolean or an object with its own date.
  const kevRaw = pick(d, 'kev', 'cisa_kev', 'in_kev');
  intel.exploited_in_wild = bool(pick(d, 'exploited_in_wild', 'exploited', 'in_the_wild', 'in_wild'));
  intel.kev_date = str(pick(d, 'kev_date', 'kev_added', 'cisa_date', 'cisa_kev_date', 'date_added'));
  const kevObj = asObj(kevRaw);
  if (kevRaw === true || kevObj?.in_kev === true || kevObj?.listed === true) {
    intel.exploited_in_wild = intel.exploited_in_wild ?? true;
  }
  if (kevObj) intel.kev_date = intel.kev_date ?? str(pick(kevObj, 'date_added', 'date', 'added'));
  // Ransomware flag may be boolean or a word like "Known".
  const rwRaw = pick(d, 'ransomware', 'ransomware_use', 'used_by_ransomware');
  if (typeof rwRaw === 'boolean') intel.ransomware = rwRaw;
  else if (typeof rwRaw === 'string' && rwRaw) {
    const s = rwRaw.toLowerCase();
    if (s === 'known' || s === 'yes') intel.ransomware = true;
    else if (s === 'no' || s === 'none') intel.ransomware = false;
  }

  // Likelihood is a 0..1 fraction upstream (the page meter uses 0.99999);
  // tolerate a 0..100 number by dividing. Percentile is the reverse.
  const like = num(
    pick(d, 'likelihood_next_30d', 'likelihood_30d', 'likelihood', 'next_30d', 'exploitation_likelihood')
  );
  if (like !== undefined) intel.likelihood_30d = like > 1 ? like / 100 : like;
  const pct = num(pick(d, 'likelihood_percentile', 'percentile', 'percent_less_likely', 'less_likely_pct'));
  if (pct !== undefined) intel.likelihood_percentile = pct <= 1 ? pct * 100 : pct;

  const checkObj = asObj(pick(d, 'check', 'detection', 'detection_check', 'confirm'));
  intel.positive_when =
    str(pick(d, 'positive_when')) ??
    (checkObj ? str(pick(checkObj, 'positive_when', 'positive', 'positive_result', 'match_when', 'match')) : undefined);
  const nucleiRaw =
    str(pick(d, 'nuclei_command', 'nuclei')) ??
    (checkObj ? str(pick(checkObj, 'nuclei_command', 'nuclei', 'command')) : undefined);
  intel.nuclei_command = nucleiRaw ?? (checkObj || intel.positive_when ? `nuclei -id ${cve} -u <target>` : undefined);

  intel.exploit_count = num(pick(d, 'exploit_count', 'public_exploits', 'exploits_count', 'poc_count'));
  for (const e of arr(pick(d, 'exploits', 'public_exploit_code', 'exploit_code', 'pocs', 'poc'))) {
    const n = normalizeExploit(e);
    if (n) intel.exploits.push(n);
    if (intel.exploits.length >= MAX_EXPLOITS) break;
  }
  if (intel.exploit_count === undefined && intel.exploits.length > 0) intel.exploit_count = intel.exploits.length;

  intel.impact = str(pick(d, 'impact', 'impact_summary'));
  intel.fix = str(pick(d, 'fix', 'remediation', 'fix_summary'));

  for (const r of arr(pick(d, 'references', 'refs', 'links'))) {
    const u = typeof r === 'string' ? r : str(asObj(r)?.url);
    if (u) intel.references.push(u);
    if (intel.references.length >= MAX_REFERENCES) break;
  }

  // "Found" = we extracted anything usable. A bare {} or an error envelope
  // means HexBrain has no record for this id.
  const hasPayload =
    Boolean(
      intel.title ||
      intel.impact ||
      intel.fix ||
      intel.severity ||
      intel.exploited_in_wild !== undefined ||
      intel.likelihood_30d !== undefined ||
      intel.exploits.length ||
      intel.references.length
    ) || str(pick(d, 'description')) !== undefined;
  intel.found = hasPayload;
  return intel;
}

/**
 * One call to POST /api/v1/get_cve. Never throws — transport and upstream
 * failures come back as `{ err }` so the route can degrade to the base record.
 */
export async function hexbrainCve(
  apiKey: string,
  cve: string,
  signal?: AbortSignal
): Promise<{ ok: HbCveIntel } | { err: HbErrorInfo }> {
  if (!apiKey) return { err: { code: 'auth' } };
  let r: Response;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
    const combined = signal ? (AbortSignal.any ? AbortSignal.any([signal, ctrl.signal]) : ctrl.signal) : ctrl.signal;
    r = await fetch(`${BASE}/get_cve`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': UA,
      },
      body: JSON.stringify({ id: cve.toUpperCase() }),
      signal: combined,
    });
    clearTimeout(timer);
  } catch {
    return { err: { code: 'network_error' } };
  }
  if (r.ok) {
    try {
      const body = (await r.json()) as unknown;
      return { ok: normalizeCve(cve.toUpperCase(), body) };
    } catch {
      return { err: { code: 'bad_payload', status: r.status } };
    }
  }
  const status = r.status;
  if (status === 401 || status === 403) return { err: { code: 'auth', status } };
  if (status === 429) return { err: { code: 'rate_limited', status } };
  if (status === 404 || status === 400) return { err: { code: 'not_found', status } };
  if (status >= 500) return { err: { code: 'upstream_5xx', status } };
  return { err: { code: 'not_found', status } };
}

/**
 * Cache-first `get_cve` for the route handler.
 *
 * KV key `hexbrain:cve:<ID>`, TTL 24h. Successful lookups AND not-found
 * markers are cached (a missing record would otherwise cost one API call
 * per request until someone queries a different CVE); auth, rate-limit, and
 * upstream failures are NOT cached so the next request retries upstream.
 * Returns null when there is nothing to attach.
 */
export async function hexbrainCveCached(
  kv: KVNamespace | undefined | null,
  waitUntil: ((p: Promise<unknown>) => void) | undefined,
  apiKey: string,
  cve: string
): Promise<HbCveIntel | null> {
  const key = `${CACHE_PREFIX}${cve.toUpperCase()}`;
  const cached = await kvBackedGet<HbCveIntel>(kv, key, CACHE_TTL);
  if (cached.value) return cached.value.found ? cached.value : null;

  const res = await hexbrainCve(apiKey, cve, AbortSignal.timeout(8_000));
  if ('err' in res) return null;
  const intel = res.ok;
  // Cache both hits and explicit misses (the miss marker keeps a dead id
  // from re-spending the daily quota on every request).
  await kvBackedPut(kv, key, intel, CACHE_TTL, waitUntil);
  return intel.found ? intel : null;
}
