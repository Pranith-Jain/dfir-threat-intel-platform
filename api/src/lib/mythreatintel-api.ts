/**
 * Typed gateway for the official MyThreatIntel REST API.
 *
 * MIGRATION (2026-10): the product moved off mythreatintel.com — that domain
 * now serves an unrelated app and its old `/api/` prefix 404s (every source
 * answered `{"detail":"Not Found"}`). The maker's site 301s to
 * `mythreatintel.secureit.es`, so the API base moved with it. (The new origin
 * was itself down — Cloudflare 522 — at migration time; callers already
 * degrade to last-good/KV while it recovers.)
 *
 * One upstream endpoint, multiplexed by `?source=`:
 *
 *   GET https://mythreatintel.secureit.es/api/?source=<src>&q=<text>&limit=<n>
 *   Authorization: Bearer <MYTHREATINTEL_API_TOKEN>
 *
 * Envelope (all sources):
 *   { "status": "success",
 *     "metadata": { "total", "count", "limit", "offset" },
 *     "data": [ ... ] }
 *
 * This is the single auth + cache surface. The Bearer token is a Worker
 * secret and is injected here server-side — it never reaches the browser.
 * `fetchMtiSource` NEVER throws and NEVER returns a partial: on a missing
 * token, non-2xx, timeout, or parse failure it returns `{ ok: false }` so
 * in-process consumers (live-iocs, ransomware-recent) can fall back to the
 * existing t.me/s/mythreatintel scraper without special-casing errors.
 *
 * The per-source `data[]` shapes below mirror the documented examples. They
 * are intentionally permissive (every field optional) — the upstream is a
 * third party and the consumers render defensively.
 */

import type { Env } from '../env';

const API_BASE = 'https://mythreatintel.secureit.es/api/';
const FETCH_TIMEOUT_MS = 12_000;
/**
 * The `source=dns` scan is an active, real-time dnstwist run (40 threads) the
 * upstream docs put at 30–120s. It needs a far larger budget than the static
 * sources — anything short aborts mid-scan.
 */
const DNS_FETCH_TIMEOUT_MS = 115_000;

/** Canonical `?source=` values. Matches the documented curl examples. */
export const MTI_SOURCES = [
  'cve',
  'malware',
  'iocs',
  'ransomware',
  'onions',
  'markets',
  'leaks',
  'groups',
  'events',
] as const;

export type MtiSource = (typeof MTI_SOURCES)[number];

export function isMtiSource(s: string): s is MtiSource {
  return (MTI_SOURCES as readonly string[]).includes(s);
}

/** Per-source edge-cache TTL (seconds). IOC/malware churn fastest. */
export const MTI_TTL: Record<MtiSource, number> = {
  iocs: 30 * 60,
  malware: 30 * 60,
  cve: 60 * 60,
  ransomware: 60 * 60,
  events: 60 * 60,
  leaks: 60 * 60,
  groups: 6 * 60 * 60,
  markets: 6 * 60 * 60,
  onions: 6 * 60 * 60,
};

/**
 * Canonical upstream fetch depth. Every consumer fetches at this single
 * depth and slices locally, so the per-source edge-cache entry is shared
 * platform-wide — one upstream call per source per TTL instead of one per
 * distinct caller `limit`. (Was: ransomware fetched 3× and iocs 2× per
 * window because the cache key varied by limit.) 500 = the proxy's max, so
 * external `?limit=` callers stay correct while reusing the same entry.
 */
export const MTI_CANONICAL_LIMIT = 500;

// ─── Documented per-source record shapes (all fields optional) ─────────────

export interface MtiIoc {
  date?: string;
  sha256?: string;
  file_name?: string;
  /** Malware family / detection signature, when present. */
  signature?: string;
  tags?: string;
  type?: string;
  _source?: string;
  dataType?: string;
}

export interface MtiMalware {
  date?: string;
  sha256?: string;
  file_name?: string;
  signature?: string;
  tags?: string;
  type?: string;
  _source?: string;
  dataType?: string;
}

export interface MtiCveRecord {
  cve?: string;
  published?: string;
  severity?: string;
  score?: string;
  cvss_version?: string;
  description?: string;
  url?: string;
  type?: string;
  _source?: string;
}

export interface MtiLeak {
  name?: string;
  url?: string;
  size?: string;
  date?: string;
  type?: string;
  _source?: string;
}

/** Live shape: the documented actor/origin/motivation fields don't exist. */
export interface MtiGroup {
  group_id?: string;
  description?: string;
  type?: string;
  _source?: string;
}

/**
 * Live shape of the `ransomware` source — victim claims, NOT an operator
 * directory (the documented onion/status/page_title fields don't exist).
 * The upstream `events` source is empty; this carries the CTI victim data.
 */
export interface MtiRansomwareClaim {
  victim?: string;
  gang?: string;
  date?: string;
  country?: string;
  website?: string;
  description?: string;
  message?: string;
  type?: string;
  ingested_at?: string;
  _source?: string;
}

export interface MtiMarket {
  market?: string;
  onion?: string;
  status?: string;
  page_title?: string;
  last_visit?: string;
  type?: string;
  _source?: string;
}

export interface MtiOnion {
  onion?: string;
  status?: string;
  page_title?: string;
  last_visit?: string;
  type?: string;
  _source?: string;
}

export interface MtiEvent {
  date?: string;
  victim?: string;
  gang?: string;
  description?: string;
  type?: string;
  _source?: string;
}

/** Discriminated by call site — consumers cast `items` to the right shape. */
export type MtiRecord =
  MtiIoc | MtiMalware | MtiCveRecord | MtiLeak | MtiGroup | MtiRansomwareClaim | MtiMarket | MtiOnion | MtiEvent;

export interface MtiResult {
  /** False on missing token / upstream failure — callers then fall back. */
  ok: boolean;
  /** Records in this response (`metadata.count`). */
  count: number;
  /** Total matching records upstream (`metadata.total`). */
  total: number;
  items: MtiRecord[];
  /**
   * When `ok` is false: the upstream HTTP status that caused it (e.g. 401 =
   * token rejected, 429 = rate-limited, 5xx = upstream error), or 0 for a
   * network error / timeout. Surfaced so operators can tell a dead token from
   * a transient outage instead of staring at an opaque 502.
   */
  upstreamStatus?: number;
  /** When `ok` is false: a short snippet of the upstream's error body, so the
   *  exact reason (expired vs invalid vs rate-limited) is visible, not guessed. */
  upstreamDetail?: string;
}

const EMPTY: MtiResult = { ok: false, count: 0, total: 0, items: [] };

interface MtiEnvelope {
  status?: string;
  metadata?: { total?: number; count?: number; limit?: number; offset?: number };
  data?: unknown;
}

/** Edge-cache key. Exported so feed-status can probe the exact cached body. */
export function mtiCacheKey(source: MtiSource, q: string, limit: number): string {
  return `https://mti-api-cache.internal/v1/${source}/${encodeURIComponent(q)}/${limit}`;
}

export interface MtiQuery {
  /** Free-text search across all fields (`?q=`). */
  q?: string;
  /** 1–500. Upstream default 100. */
  limit?: number;
}

/**
 * Fetch one MyThreatIntel source through the shared edge cache. Never
 * throws. Returns `ok:false` (and empty data) when the token is unset or
 * the upstream is unhealthy, so callers degrade by falling back rather than
 * by catching.
 */
export async function fetchMtiSource(env: Env, source: MtiSource, query: MtiQuery = {}): Promise<MtiResult> {
  const token = env.MYTHREATINTEL_API_TOKEN;
  if (!token) return EMPTY;

  const q = (query.q ?? '').trim();
  // What this caller wants back vs. what we actually fetch upstream. We
  // always fetch (and cache) at the canonical depth and slice locally, so
  // every caller — regardless of its requested limit — reuses one shared
  // cache entry / one upstream call per source+q per TTL.
  const want = Math.min(MTI_CANONICAL_LIMIT, Math.max(1, Math.trunc(query.limit ?? 100)));
  const slice = (r: MtiResult): MtiResult =>
    r.items.length <= want ? r : { ...r, items: r.items.slice(0, want), count: want };

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(mtiCacheKey(source, q, MTI_CANONICAL_LIMIT));
  const cached = await cache.match(cacheReq);
  if (cached) {
    try {
      return slice((await cached.json()) as MtiResult);
    } catch {
      /* fall through to a fresh fetch */
    }
  }

  const url = new URL(API_BASE);
  url.searchParams.set('source', source);
  if (q) url.searchParams.set('q', q);
  url.searchParams.set('limit', String(MTI_CANONICAL_LIMIT));

  let env_envelope: MtiEnvelope;
  try {
    const res = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'User-Agent': 'pranithjain.qzz.io DFIR toolkit (read-only)',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) {
      const detail = await res
        .text()
        .then((t) => t.slice(0, 200))
        .catch(() => '');
      return { ...EMPTY, upstreamStatus: res.status, upstreamDetail: detail };
    }
    env_envelope = (await res.json()) as MtiEnvelope;
  } catch (err) {
    return { ...EMPTY, upstreamStatus: 0, upstreamDetail: err instanceof Error ? err.message : String(err) };
  }

  const data = Array.isArray(env_envelope.data) ? (env_envelope.data as MtiRecord[]) : [];
  const result: MtiResult = {
    ok: true,
    count: typeof env_envelope.metadata?.count === 'number' ? env_envelope.metadata.count : data.length,
    total: typeof env_envelope.metadata?.total === 'number' ? env_envelope.metadata.total : data.length,
    items: data,
  };

  // Cache only non-empty successes so a transient empty isn't pinned.
  if (result.items.length > 0) {
    const toCache = new Response(JSON.stringify(result), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${MTI_TTL[source]}`,
      },
    });
    await cache.put(cacheReq, toCache);
  }

  // Cache holds the full canonical payload; this caller gets its slice.
  return slice(result);
}

// ─── DNS permutation scan (source=dns) ─────────────────────────────────────
//
// Structurally distinct from the static sources: it takes a `domain` (plus
// optional `tlds`/`words`), runs a live dnstwist scan, and returns one object
// PER GENERATED DOMAIN — not the `{status, metadata, data}` envelope. The docs
// show a bare top-level array; the jq examples reference `.data[]`. We accept
// either shape defensively.

export interface MtiDnsRecord {
  /** Permutation type: original, addition, tld-swap, keyword, … */
  fuzzer?: string;
  domain?: string;
  dns_a?: string[];
  dns_aaaa?: string[];
  dns_mx?: string[];
  dns_ns?: string[];
}

export interface MtiDnsResult {
  ok: boolean;
  count: number;
  items: MtiDnsRecord[];
  upstreamStatus?: number;
  upstreamDetail?: string;
}

export interface MtiDnsQuery {
  /** Target apex domain, e.g. "company.com". */
  domain: string;
  /** Extra comma-separated TLDs to broaden typosquatting detection. */
  tlds?: string;
  /** Comma-separated keywords for login-/secure- style variants. */
  words?: string;
}

const DNS_EMPTY: MtiDnsResult = { ok: false, count: 0, items: [] };

/** Edge-cache key for a DNS scan — varies by every input that changes results. */
export function mtiDnsCacheKey(domain: string, tlds: string, words: string): string {
  return `https://mti-dns-cache.internal/v1/${encodeURIComponent(domain)}/${encodeURIComponent(tlds)}/${encodeURIComponent(words)}`;
}

/** Scan TTL — a live scan is expensive (30–120s); reuse for 30 min. */
const DNS_TTL_SECONDS = 30 * 60;

/**
 * Run a MyThreatIntel DNS permutation scan. Never throws; returns `ok:false`
 * on missing token / upstream failure, with the upstream status + detail so
 * the handler can distinguish an expired token (401) from an outage.
 */
export async function fetchMtiDns(env: Env, query: MtiDnsQuery): Promise<MtiDnsResult> {
  const token = env.MYTHREATINTEL_API_TOKEN;
  if (!token) return DNS_EMPTY;

  const domain = query.domain.trim().toLowerCase();
  const tlds = (query.tlds ?? '').trim();
  const words = (query.words ?? '').trim();

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(mtiDnsCacheKey(domain, tlds, words));
  const cached = await cache.match(cacheReq);
  if (cached) {
    try {
      return (await cached.json()) as MtiDnsResult;
    } catch {
      /* fall through to a fresh scan */
    }
  }

  const url = new URL(API_BASE);
  url.searchParams.set('source', 'dns');
  url.searchParams.set('domain', domain);
  if (tlds) url.searchParams.set('tlds', tlds);
  if (words) url.searchParams.set('words', words);

  let parsed: unknown;
  try {
    const res = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'User-Agent': 'pranithjain.qzz.io DFIR toolkit (read-only)',
      },
      signal: AbortSignal.timeout(DNS_FETCH_TIMEOUT_MS),
    });
    if (!res.ok) {
      const detail = await res
        .text()
        .then((t) => t.slice(0, 200))
        .catch(() => '');
      return { ...DNS_EMPTY, upstreamStatus: res.status, upstreamDetail: detail };
    }
    parsed = await res.json();
  } catch (err) {
    return { ...DNS_EMPTY, upstreamStatus: 0, upstreamDetail: err instanceof Error ? err.message : String(err) };
  }

  // Accept either a bare array or a `{ data: [...] }` envelope.
  const data: MtiDnsRecord[] = Array.isArray(parsed)
    ? (parsed as MtiDnsRecord[])
    : Array.isArray((parsed as { data?: unknown })?.data)
      ? (parsed as { data: MtiDnsRecord[] }).data
      : [];

  const result: MtiDnsResult = { ok: true, count: data.length, items: data };

  if (result.items.length > 0) {
    const toCache = new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${DNS_TTL_SECONDS}` },
    });
    await cache.put(cacheReq, toCache);
  }
  return result;
}
