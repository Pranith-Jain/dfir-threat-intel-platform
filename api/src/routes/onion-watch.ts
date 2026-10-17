import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badGateway } from '../lib/api-error';
import { fetchResilient } from '../lib/fetch-resilient';
import { readLastGood, writeLastGood } from '../lib/lastgood';

/**
 * .onion leak-site mirror tracker.
 *
 * Pulls per-group profile data from Ransomlook.io and surfaces the
 * canonical Tor mirror URLs for the most-active leak sites. Each
 * Ransomlook profile contains a `locations[]` array with:
 *   - slug         full Tor URL (http://abc...xyz.onion/path)
 *   - fqdn         the bare .onion hostname
 *   - title        last-observed page title (fingerprints "site is down")
 *   - available    Ransomlook's reachability flag at last scrape
 *   - updated      ISO timestamp of the last scrape
 *   - version      Tor address version (3 = current standard)
 *   - chat / fs    leak-site has chat / file-share mirrors
 *
 * We DON'T fetch the .onion sites ourselves (Cloudflare Workers can't
 * route through Tor). We surface the Ransomlook-tracked status so
 * analysts can see which leak sites are currently reachable + their
 * mirror addresses without having to build a Tor client locally.
 *
 * The driver list is the most-recently-active groups from the
 * /api/recent feed — we already proxy that. To keep the request
 * bounded, we cap to the top N groups and fan out per-group fetches
 * with concurrency 5.
 */

const FETCH_TIMEOUT_MS = 12_000;
const CACHE_TTL = 6 * 3600; // 6h — Ransomlook scrapes hourly
/**
 * Per-group profile read budget.
 *
 * Ransomlook inlines scraped screenshots into every location as base64
 * (`screen` / `source` fields). Measured 2026-10-17: a single top-group
 * profile reaches 78 MB (lockbit5; ~0.7–7 MB for most) and streams at
 * ~25 KB/s, so the old "fetch the JSON, parse it whole" path buffered tens
 * of MB and blew the Worker's CPU/memory ceiling — readers got a bare
 * Cloudflare `error code: 1102` on cold builds even after the 2026-10-16
 * mitigation cut TOP_N to 10.
 *
 * We now read a bounded prefix and salvage only the complete location
 * objects that arrive inside it (`salvageLocationObjects`): memory stays at
 * ~1 MB/group and CPU goes to small per-object parses instead of one
 * multi-MB parse. Locations beyond the prefix are dropped — Ransomlook
 * orders each group's canonical mirror first, and the KV last-good cache
 * keeps the previous snapshot's fuller list.
 */
const GROUP_READ_MAX_BYTES = 1_000_000;
const GROUP_READ_MAX_OBJECTS = 12;
const GROUP_READ_TIMEOUT_MS = 10_000;
// Top-10 groups × ≤10 s per read, 5 at a time → worst-case cold build ~20 s
// wall, with ~1 fetch per group plus /api/recent. Was 15, which sat ON the
// subrequest ceiling rather than under it; the per-group read is now bounded
// so the count, not the payload, is what matters.
const TOP_N_GROUPS = 10;
const CONCURRENCY = 5;

/** Exported so /api/v1/feed-status can read the same cached payload directly. */
export const ONION_WATCH_CACHE_KEY = 'https://onion-watch-cache.internal/v2';

interface RansomlookLocation {
  slug?: string;
  fqdn?: string;
  title?: string;
  available?: boolean;
  updated?: string;
  version?: number;
  chat?: boolean;
  fs?: boolean;
  private?: boolean;
}

interface RecentEntry {
  group_name?: string;
  discovered?: string;
}

export interface OnionMirror {
  slug: string;
  fqdn: string;
  title?: string;
  available: boolean;
  updated?: string;
  version?: number;
  /** True if Ransomlook flagged this as a chat/negotiation endpoint. */
  is_chat?: boolean;
  /** True if Ransomlook flagged this as a file-share endpoint. */
  is_fs?: boolean;
}

export interface OnionGroup {
  group: string;
  /** Most-recent victim claim across all locations, ISO. */
  last_active?: string;
  /** True if at least one location was reachable at last scrape. */
  any_reachable: boolean;
  mirrors: OnionMirror[];
}

export interface OnionWatchResponse {
  generated_at: string;
  source: string;
  source_url: string;
  groups: OnionGroup[];
  /** Total reachable .onion mirrors across all groups, for the headline stat. */
  reachable_count: number;
  /** Total mirrors observed (reachable + offline). */
  total_count: number;
  warnings: string[];
}

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const r = await fetchResilient(
      url,
      {
        headers: { accept: 'application/json', 'user-agent': 'pranithjain-dfir/1.0' },
      },
      { attempts: 3, timeoutMs: FETCH_TIMEOUT_MS }
    );
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch (_catchErr) {
    logError('fetchJson failed', _catchErr);
    return null;
  }
}

/**
 * Read a response body as text, bounded by `maxBytes` and by `isEnough`.
 * Returns whatever was read when either bound trips — a deadline abort or a
 * mid-stream error yields the partial text (the salvage walker ignores the
 * truncated tail). Always cancels the reader so the upstream connection
 * stops streaming a payload we no longer need.
 */
async function readBoundedText(res: Response, maxBytes: number, isEnough: (text: string) => boolean): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let consumed = 0;
  try {
    while (consumed < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      consumed += value.byteLength;
      text += decoder.decode(value, { stream: true });
      if (isEnough(text)) break;
    }
  } catch {
    // Deadline abort / stream error — fall through with the partial text.
  } finally {
    reader.cancel().catch(() => {});
  }
  return text;
}

/**
 * Blank the two multi-KB base64 fields (`screen`, `source`) inside one
 * location object so `JSON.parse` never touches screenshot bytes. Both are
 * plain JSON strings with no nested structures; base64 contains no quotes or
 * backslashes, so the negated-class scan is linear.
 */
function stripProfileHeavyFields(obj: string): string {
  return obj
    .replace(/"screen"\s*:\s*"(?:[^"\\]|\\.)*"/g, '"screen":""')
    .replace(/"source"\s*:\s*"(?:[^"\\]|\\.)*"/g, '"source":""');
}

/**
 * Extract complete location objects from a (possibly truncated) Ransomlook
 * group payload.
 *
 * The payload is `[{captcha, meta, locations:[{…}, {…}]}]` and each location
 * object is FLAT (no nested objects) with the scalar mirror fields first.
 * We walk `{…}` objects that arrived whole, blank the heavy fields, and parse
 * each object individually — never the payload as a whole. A trailing object
 * cut off by the read bound is ignored. Older Ransomlook deployments returned
 * a flat `[{…}]` array; that shape is handled too.
 */
export function salvageLocationObjects(text: string): RansomlookLocation[] {
  let i: number;
  const anchor = text.indexOf('"locations"');
  if (anchor >= 0) {
    const arr = text.indexOf('[', anchor);
    if (arr < 0) return [];
    i = arr + 1;
  } else {
    const trimmed = text.trimStart();
    if (!trimmed.startsWith('[')) return [];
    i = text.length - trimmed.length + 1;
  }
  const out: RansomlookLocation[] = [];
  while (i < text.length) {
    // Skip whitespace and array separators between objects.
    while (i < text.length) {
      const c = text[i];
      if (c === ' ' || c === '\n' || c === '\r' || c === '\t' || c === ',') i++;
      else break;
    }
    if (i >= text.length || text[i] !== '{') break;
    const objStart = i;
    let depth = 0;
    let inStr = false;
    let esc = false;
    let objEnd = -1;
    for (; i < text.length; i++) {
      const ch = text[i];
      if (inStr) {
        if (esc) esc = false;
        else if (ch === '\\') esc = true;
        else if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') inStr = true;
      else if (ch === '{') depth++;
      else if (ch === '}' && --depth <= 0) {
        objEnd = i;
        i++;
        break;
      }
    }
    if (objEnd < 0) break; // truncated trailing object — stop
    try {
      out.push(JSON.parse(stripProfileHeavyFields(text.slice(objStart, objEnd + 1))) as RansomlookLocation);
    } catch {
      // Malformed object (shouldn't happen for whole objects) — skip it.
    }
  }
  return out;
}

async function fetchGroupMirrors(group: string): Promise<RansomlookLocation[]> {
  const url = `https://www.ransomlook.io/api/group/${encodeURIComponent(group)}`;
  try {
    // Deliberately a plain fetch with NO retries: a group that is slow or
    // failing costs one bounded read, not three. (Retry amplification is what
    // pushed the old fan-out into the subrequest ceiling.)
    const res = await fetch(url, {
      headers: { accept: 'application/json', 'user-agent': 'pranithjain-dfir/1.0' },
      signal: AbortSignal.timeout(GROUP_READ_TIMEOUT_MS),
    });
    if (!res.ok) return [];
    const text = await readBoundedText(
      res,
      GROUP_READ_MAX_BYTES,
      (t) => salvageLocationObjects(t).length >= GROUP_READ_MAX_OBJECTS
    );
    return salvageLocationObjects(text);
  } catch (e) {
    logError(`onion-watch group fetch failed: ${group}`, e);
    return [];
  }
}

/**
 * Pure-data fetcher exposed for /api/v1/snapshot. Returns the body or null
 * if the upstream is unreachable (vs the handler which returns a 502 in
 * that case). Snapshot wraps null into its envelope.
 */
export async function fetchOnionWatch(): Promise<OnionWatchResponse | null> {
  const warnings: string[] = [];

  const recent = await fetchJson<RecentEntry[]>('https://www.ransomlook.io/api/recent');
  if (!Array.isArray(recent)) return null;

  const byGroup = new Map<string, string>();
  for (const r of recent) {
    if (!r.group_name) continue;
    const existing = byGroup.get(r.group_name);
    const ts = r.discovered ?? '';
    if (!existing || ts > existing) byGroup.set(r.group_name, ts);
  }
  const groupOrder = [...byGroup.entries()]
    .sort((a, b) => (b[1] || '').localeCompare(a[1] || ''))
    .slice(0, TOP_N_GROUPS)
    .map(([g]) => g);

  const results = new Map<string, RansomlookLocation[]>();
  const queue = [...groupOrder];
  async function worker() {
    while (queue.length > 0) {
      const g = queue.shift();
      if (!g) return;
      const locs = await fetchGroupMirrors(g);
      results.set(g, locs);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  const groups: OnionGroup[] = [];
  let reachable = 0;
  let total = 0;
  for (const g of groupOrder) {
    const locs = results.get(g) ?? [];
    if (locs.length === 0) {
      warnings.push(`no profile data for ${g}`);
      continue;
    }
    const mirrors: OnionMirror[] = locs
      .filter((l) => l.fqdn && /\.onion$/i.test(l.fqdn) && !l.private)
      .map((l) => ({
        slug: l.slug ?? `http://${l.fqdn}`,
        fqdn: l.fqdn!,
        title: l.title,
        available: Boolean(l.available),
        updated: l.updated,
        version: l.version,
        is_chat: l.chat,
        is_fs: l.fs,
      }));
    if (mirrors.length === 0) continue;
    const anyReachable = mirrors.some((m) => m.available);
    if (anyReachable) reachable += 1;
    total += mirrors.length;
    groups.push({
      group: g,
      last_active: byGroup.get(g),
      any_reachable: anyReachable,
      mirrors,
    });
  }

  return {
    generated_at: new Date().toISOString(),
    source: 'Ransomlook.io',
    source_url: 'https://www.ransomlook.io',
    groups,
    reachable_count: reachable,
    total_count: total,
    warnings,
  };
}

const ONION_WATCH_LASTGOOD_KV_KEY = 'onion-watch:lastgood:v1';
const LASTGOOD_TTL = 172_800; // 48h — covers long upstream outages

/**
 * In-isolate single-flight for the cold-cache build. Same pattern and
 * rationale as `liveIocsHandler` (see the DOS-1 note in live-iocs.ts): this
 * route fans out to Ransomlook once per group (TOP_N_GROUPS × per-group
 * requests) plus /api/recent, against a hard 50-subrequest ceiling per
 * invocation. On a cache miss every concurrent request used to run its own
 * fan-out, so the ones that lost the race exceeded the ceiling and the reader
 * got Cloudflare's bare `error code: 1102` instead of data — reproduced on
 * ~1 in 3 requests to /api/v1/onion-watch (measured 2026-10-16). The payload
 * is request-agnostic global data, so sharing one build per isolate is correct.
 *
 * The `.catch` also closes the other 1102 path: an exception escaping
 * `fetchOnionWatch` (as opposed to it returning null on an upstream failure)
 * propagated out of the handler and produced the same opaque edge error
 * instead of falling through to the KV last-good path below.
 */
let inflightOnionWatchBuild: Promise<OnionWatchResponse | null> | null = null;

function buildOnionWatchSingleFlight(): Promise<OnionWatchResponse | null> {
  if (inflightOnionWatchBuild) return inflightOnionWatchBuild;
  inflightOnionWatchBuild = fetchOnionWatch()
    .catch((e: unknown) => {
      logError('onion-watch build failed', e);
      return null;
    })
    .finally(() => {
      inflightOnionWatchBuild = null;
    });
  return inflightOnionWatchBuild;
}

export async function onionWatchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(ONION_WATCH_CACHE_KEY);
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const body = await buildOnionWatchSingleFlight();
  if (body) {
    // Persist last-good payload to KV so stale data is served during
    // upstream outages. Non-blocking — the response goes out immediately.
    if (c.env.KV_CACHE) {
      c.executionCtx.waitUntil(
        // Shared last-good helper (lib/lastgood.ts): debounced KV write + free
        // per-colo Cache-API shadow write-through. The default debounce matches
        // the 6h edge-cache TTL in front of this write, so it only trims
        // duplicate cross-colo writes. keyPrefix '' keeps the legacy verbatim
        // KV key.
        writeLastGood(c.env, ONION_WATCH_LASTGOOD_KV_KEY, body, {
          keyPrefix: '',
          ttlSeconds: LASTGOOD_TTL,
        })
      );
    }
    const response = c.json(body, 200, { 'Cache-Control': `public, max-age=${CACHE_TTL}` });
    c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  }

  // Upstream unreachable — try KV last-good fallback.
  if (c.env.KV_CACHE) {
    try {
      // Shared helper: free per-colo Cache-API shadow first, then KV. Never throws.
      const lastGood = await readLastGood<OnionWatchResponse>(c.env, ONION_WATCH_LASTGOOD_KV_KEY, {
        keyPrefix: '',
      });
      if (lastGood && lastGood.groups && lastGood.groups.length > 0) {
        lastGood.warnings.push('ransomlook upstream unreachable — showing cached data');
        return c.json(lastGood, 200, {
          'Cache-Control': 'public, max-age=300',
          'X-SI-Stale': 'ransomlook-unreachable',
        });
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* fall through to 502 */
    }
  }

  return badGateway(c, 'ransomlook unreachable: failed to fetch /api/recent');
}
