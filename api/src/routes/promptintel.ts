/**
 * PromptIntel — Indicators of Prompt Compromise (IoPC).
 *
 * Upstream moved from `api.promptintel.novahunting.ai` (NovaHunting) to
 * `api.promptintel.securitybreak.io` (SecurityBreak); the old host still
 * answers a 301, which is why this file kept working while pointing at a
 * retired name. Everything below targets the current base.
 *
 * Two serving tiers, because the Community plan allows only **100 requests a
 * day** (20/min) and the scarce allowances are per account, not per colo:
 *
 *   MIRROR (no key, no quota, no upstream hop)
 *     /promptintel/taxonomy             domains + slim entries + mapping table
 *     /promptintel/taxonomy/entries/:id one technique body with its mappings
 *     /promptintel/taxonomy/mappings    flat `entry → framework:ref` table
 *     /promptintel/taxonomy/translate   framework item → IoPC → other frameworks
 *     /promptintel/frameworks           framework list with upstream versions
 *     /promptintel/stats                mirror counts + live-release drift check
 *
 *   LIVE (needs `PROMPTINTEL_API_KEY`, cached, quota-aware)
 *     /promptintel/health               keyless liveness probe
 *     /promptintel/prompts              approved prompts (list omits attack text)
 *     /promptintel/prompts/:id          one prompt in full (5/day on Community)
 *     /promptintel/agent-feed           curated, approved protections
 *     /promptintel/artifacts            malicious agent-file entries (Enterprise)
 *     /promptintel/artifacts/lookup     SHA-256 verdicts (20/day on Community)
 *     /promptintel/detection-rules      NOVA rule feed (Enterprise)
 *     /promptintel/scans                public scan history
 *     /promptintel/scans/:hash          one stored scan
 *     /promptintel/scan                 POST a skill/MCP/A2A scan (10/day)
 *     /promptintel/check                GET/POST indicator verdicts (5/day)
 *     /promptintel/taxonomy/releases    published taxonomy releases
 *     /promptintel/taxonomy/changelog   taxonomy audit trail
 *     /promptintel/quota                what this key has left today
 *
 * Why the mirror leads: the taxonomy is public and crawlable (robots.txt
 * allows every agent), it changes a few times a month, and reading it live
 * would spend a quarter of the daily allowance on a page that cannot change
 * between requests. The live routes exist for the data the mirror cannot
 * hold — prompt text, agent-file hashes, the protection feed — and every one
 * of them is cached so a repeated question costs nothing.
 *
 * Cache policy follows the repo's KV rules: `kvBackedGet`/`kvBackedPut` for
 * the quota-sensitive upstream reads (L1 Cache API + KV/Upstash L2, so the
 * 5-a-day prompt allowance is shared across colos), `readLastGood` for the
 * mirror-independent health probe. No raw KV access.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { kvBackedGet, kvBackedPut } from '../lib/route-cache';
import { readLastGood, writeLastGood } from '../lib/lastgood';
import {
  filterPromptIntelEntries,
  filterPromptIntelMappings,
  getPromptIntelEntry,
  loadPromptIntelIndex,
  normalizeIopcId,
  promptIntelCacheStats,
  translateAcrossFrameworks,
  translateFrameworkRef,
} from '../lib/promptintel-manifest';

const PROMPTINTEL_BASE = 'https://api.promptintel.securitybreak.io/api/v1';
/** The public site — no key needed for `/health`'s cousin `/iopc/latest.json`. */
const PROMPTINTEL_PUBLIC = 'https://promptintel.securitybreak.io';
const FETCH_TIMEOUT_MS = 12_000;

/** How long a live upstream answer is reused before another call is spent. */
const TTL = {
  health: 5 * 60,
  /** Taxonomy changes a few times a month; the release list barely moves. */
  releases: 6 * 60 * 60,
  changelog: 6 * 60 * 60,
  prompts: 15 * 60,
  /** 5 reads a day on Community — hold one answer for most of the day. */
  prompt: 12 * 60 * 60,
  agentFeed: 60 * 60,
  artifacts: 6 * 60 * 60,
  /** 20 hash lookups a day — a hash never changes verdict, so cache hard. */
  hashLookup: 24 * 60 * 60,
  detectionRules: 6 * 60 * 60,
  scans: 30 * 60,
  /** 5 indicator checks a day. */
  check: 24 * 60 * 60,
  scan: 60 * 60,
} as const;

const HEALTH_KV_KEY = 'promptintel:health:lastgood';
const MIRROR_RELEASE_KEY = 'promptintel:mirror:release';

/* ─── Upstream plumbing ────────────────────────────────────────────────── */

interface UpstreamResult {
  status: number;
  body: unknown;
  /** `retry-after` + `x-ratelimit-reason` — tells a 429 apart from a quota wall. */
  headers: Record<string, string>;
}

/**
 * One upstream call. Returns the parsed body for 2xx *and* for upstream
 * 4xx/429 — those carry the useful `{error, message}` envelope that tells the
 * caller whether they hit a plan gate or a daily limit, and swallowing it
 * would turn "upgrade to Enterprise" into a generic 502.
 */
async function upstream(path: string, token: string, init: RequestInit = {}): Promise<UpstreamResult | null> {
  try {
    const res = await fetch(`${PROMPTINTEL_BASE}${path}`, {
      ...init,
      headers: {
        accept: 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(init.body ? { 'content-type': 'application/json' } : {}),
        ...(init.headers as Record<string, string> | undefined),
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    const text = await res.text();
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      /* keep the raw text — an HTML error page is still a signal */
    }
    const headers: Record<string, string> = {};
    for (const name of ['retry-after', 'x-ratelimit-reason', 'x-ratelimit-remaining']) {
      const v = res.headers.get(name);
      if (v) headers[name] = v;
    }
    return { status: res.status, body, headers };
  } catch {
    return null;
  }
}

/**
 * Cached keyed read. The cache key includes the query string, so two callers
 * asking different questions each pay their own upstream call, while a
 * repeated question costs nothing.
 *
 * Upstream 429/403 is deliberately NOT cached: a quota reset at 00:00 UTC
 * must become visible immediately, and caching "you are out of allowance"
 * for 24h would outlive the limit it reports.
 */
async function cachedUpstream(
  c: Context<{ Bindings: Env }>,
  token: string,
  path: string,
  ttlSeconds: number
): Promise<Response> {
  const key = `promptintel:v2:${path}`;
  const hit = await kvBackedGet<UpstreamResult>(c.env, key, ttlSeconds);
  if (hit.value) {
    return c.json(hit.value.body, hit.value.status as 200, {
      'x-source': `promptintel-${hit.source}`,
      'cache-control': `public, max-age=${Math.min(ttlSeconds, 300)}`,
    });
  }
  const live = await upstream(path, token);
  if (!live) {
    return c.json({ error: 'upstream_error', message: 'PromptIntel unreachable — try again shortly' }, 502, {
      'cache-control': 'no-store',
    });
  }
  // A 3xx here means we are talking to the wrong host (the retired
  // NovaHunting base answers 301). Never relay it as a JSON redirect — turn
  // it into an explicit misconfiguration error. 4xx/5xx ARE relayed verbatim:
  // 403 `enterprise_required` and 429 `daily_limit_reached` carry the plan
  // and quota information the caller needs.
  if (live.status >= 300 && live.status < 400) {
    return c.json(
      {
        error: 'upstream_redirect',
        status: live.status,
        message: 'PromptIntel answered a redirect — check the configured API base URL',
      },
      502,
      { 'cache-control': 'no-store', ...live.headers }
    );
  }
  if (live.status >= 200 && live.status < 300) {
    await kvBackedPut(c.env, key, live, ttlSeconds, (p) => c.executionCtx.waitUntil(p));
  }
  return c.json(live.body, live.status as 200, {
    'x-source': 'promptintel-live',
    'cache-control': 'no-store',
    ...live.headers,
  });
}

function noKey(c: Context<{ Bindings: Env }>): Response {
  return c.json(
    {
      error: 'promptintel_key_missing',
      message:
        'Set PROMPTINTEL_API_KEY (`wrangler secret put PROMPTINTEL_API_KEY`) to enable the live PromptIntel endpoints. The IoPC taxonomy mirror (/promptintel/taxonomy*) and /promptintel/health work without a key.',
      docs: 'https://promptintel.securitybreak.io/docs/api',
    },
    501,
    { 'cache-control': 'no-store' }
  );
}

/** Allowlisted, length-capped query passthrough. */
function passthrough(c: Context<{ Bindings: Env }>, allowed: Array<[name: string, maxLen: number]>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [name, maxLen] of allowed) {
    const v = c.req.query(name);
    if (v !== undefined && v.length <= maxLen) params.set(name, v);
  }
  return params;
}

function withQuery(path: string, params: URLSearchParams): string {
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

/* ─── Cron warm ────────────────────────────────────────────────────────── */

/**
 * Hourly warm. Deliberately spends ZERO API requests: the old version fetched
 * the keyed taxonomy every hour, which is 24 of the Community plan's 100
 * daily calls for a document that changes monthly.
 *
 * Instead it probes the public `/iopc/latest.json` (no key, no quota) and
 * compares it with the mirrored taxonomy, so drift shows up in the cron log
 * as `mirrorStale: true` instead of silently rotting.
 */
export async function warmPromptintelCache(
  env?: Env
): Promise<{
  ok: boolean;
  taxonomy: boolean;
  mirrorVersion: string | null;
  liveVersion: string | null;
  mirrorStale: boolean;
}> {
  let healthOk = false;
  let mirrorVersion: string | null = null;
  let liveVersion: string | null = null;

  // Liveness — public, unkeyed.
  try {
    const res = await fetch(`${PROMPTINTEL_BASE}/health`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (res.ok) {
      healthOk = true;
      const body = (await res.json()) as unknown;
      await writeLastGood(env as Pick<Env, 'KV_CACHE'>, HEALTH_KV_KEY, body, {
        force: true,
        skipIfUnchanged: true,
        ttlSeconds: 24 * 60 * 60,
        keyPrefix: '',
      });
    }
  } catch {
    /* healthOk stays false */
  }

  // Release drift — public, unkeyed.
  try {
    const res = await fetch(`${PROMPTINTEL_PUBLIC}/iopc/latest.json`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (res.ok) {
      const body = (await res.json()) as { version?: string; content_digest?: string };
      liveVersion = body.version ?? null;
    }
  } catch {
    /* liveVersion stays null */
  }

  try {
    const mirror = await loadPromptIntelIndex(env?.ASSETS as Fetcher);
    mirrorVersion = mirror.taxonomyVersion;
  } catch {
    /* no mirror deployed yet */
  }

  const mirrorStale = Boolean(liveVersion && mirrorVersion && liveVersion !== mirrorVersion);
  if (!healthOk || mirrorStale) {
    console.warn(JSON.stringify({ job: 'promptintel-warm', healthOk, mirrorVersion, liveVersion, mirrorStale }));
  }
  return { ok: healthOk, taxonomy: Boolean(mirrorVersion), mirrorVersion, liveVersion, mirrorStale };
}

/* ─── Mirror routes (keyless) ──────────────────────────────────────────── */

/** GET /api/v1/promptintel/health — upstream liveness, no key needed. */
export async function promptintelHealthHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const key = 'promptintel:v2:health';
  const hit = await kvBackedGet<unknown>(c.env, key, TTL.health);
  if (hit.value) {
    return c.json(hit.value, 200, {
      'cache-control': `public, max-age=${TTL.health}`,
      'x-source': `promptintel-${hit.source}`,
    });
  }
  const live = await upstream('/health', '');
  if (live && live.status === 200) {
    await kvBackedPut(c.env, key, live.body, TTL.health, (p) => c.executionCtx.waitUntil(p));
    return c.json(live.body, 200, {
      'cache-control': `public, max-age=${TTL.health}`,
      'x-source': 'promptintel-live',
    });
  }
  const lastGood = await readLastGood<unknown>(c.env, HEALTH_KV_KEY, { keyPrefix: '' });
  if (lastGood) {
    return c.json(lastGood, 200, { 'cache-control': 'public, max-age=60', 'x-source': 'promptintel-lastgood' });
  }
  return c.json({ status: 'unknown', upstream: 'unreachable' }, 503, { 'retry-after': '300' });
}

/**
 * GET /api/v1/promptintel/taxonomy
 * Filters: domain, framework, maturity, q, limit.
 */
export async function promptintelTaxonomyHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadPromptIntelIndex(c.env.ASSETS);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 100, 200));
  const entries = filterPromptIntelEntries(index.entries, {
    domain: c.req.query('domain'),
    framework: c.req.query('framework'),
    maturity: c.req.query('maturity'),
    keyword: c.req.query('q'),
    limit,
  });
  const ids = new Set(entries.map((e) => e.id));
  return c.json(
    {
      source: index.source,
      sourceUrl: index.sourceUrl,
      license: index.license,
      syncedAt: index.syncedAt,
      taxonomyVersion: index.taxonomyVersion,
      counts: index.counts,
      frameworks: index.frameworks,
      domains: index.domains,
      entries,
      // Only the mapping rows for the entries actually returned, so a filtered
      // read stays small while an unfiltered one still carries the whole table.
      mappings: (index.mappings ?? []).filter((m) => ids.has(m.entry)),
    },
    200,
    { 'cache-control': 'public, max-age=3600', 'x-source': 'promptintel-mirror' }
  );
}

/** GET /api/v1/promptintel/taxonomy/entries/:id — one IoPC entry from the mirror. */
export async function promptintelEntryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const raw = c.req.param('id') ?? '';
  const id = normalizeIopcId(raw);
  if (!id)
    return c.json({ error: 'bad_entry_id', message: 'Expected an IoPC id such as IOPC-T1.001 or IOPC-R012' }, 400);
  const entry = await getPromptIntelEntry(c.env.ASSETS, id);
  if (!entry) return c.json({ error: 'not_found', message: `${id} is not in the mirrored taxonomy` }, 404);
  return c.json(entry, 200, { 'cache-control': 'public, max-age=86400', 'x-source': 'promptintel-mirror' });
}

/** GET /api/v1/promptintel/taxonomy/mappings — flat mapping table. */
export async function promptintelMappingsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadPromptIntelIndex(c.env.ASSETS);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 200, 500));
  const rows = filterPromptIntelMappings(index, {
    framework: c.req.query('framework'),
    ref: c.req.query('ref'),
    relationship: c.req.query('relationship'),
    entry: c.req.query('entry'),
    limit,
  });
  return c.json({ taxonomyVersion: index.taxonomyVersion, count: rows.length, mappings: rows }, 200, {
    'cache-control': 'public, max-age=3600',
    'x-source': 'promptintel-mirror',
  });
}

/**
 * GET /api/v1/promptintel/taxonomy/translate?framework=&ref=&to=
 *
 * `to` present → the other frameworks that item lands in (upstream's
 * `/taxonomy/translate`). `to` absent → the IoPC techniques behind the item
 * (the inverse lookup). Both answer from the mirror.
 */
export async function promptintelTranslateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const framework = c.req.query('framework');
  const ref = c.req.query('ref');
  if (!framework || !ref) {
    return c.json(
      { error: 'missing_params', message: 'framework and ref are required, e.g. framework=OWASP_LLM&ref=LLM01' },
      400
    );
  }
  if (framework.length > 120 || ref.length > 120) return c.json({ error: 'bad_params' }, 400);
  const index = await loadPromptIntelIndex(c.env.ASSETS);
  const to = c.req.query('to');
  const across = translateAcrossFrameworks(index, framework, ref, to);
  if (!across.source) {
    const inverse = translateFrameworkRef(index, framework, ref);
    if (!inverse) {
      return c.json({ error: 'not_found', message: `No IoPC entry maps to ${framework}:${ref}` }, 404);
    }
    return c.json(
      { taxonomyVersion: index.taxonomyVersion, source: null, entries: inverse.entries, matches: [] },
      200,
      { 'cache-control': 'public, max-age=3600', 'x-source': 'promptintel-mirror' }
    );
  }
  return c.json(
    {
      taxonomyVersion: index.taxonomyVersion,
      source: across.source,
      entries: translateFrameworkRef(index, framework, ref)?.entries ?? [],
      matches: across.matches,
    },
    200,
    { 'cache-control': 'public, max-age=3600', 'x-source': 'promptintel-mirror' }
  );
}

/** GET /api/v1/promptintel/frameworks — the frameworks the taxonomy maps to. */
export async function promptintelFrameworksHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadPromptIntelIndex(c.env.ASSETS);
  return c.json({ taxonomyVersion: index.taxonomyVersion, frameworks: index.frameworks }, 200, {
    'cache-control': 'public, max-age=86400',
    'x-source': 'promptintel-mirror',
  });
}

/**
 * GET /api/v1/promptintel/stats — mirror inventory plus a drift check against
 * the public release file. The drift probe is unkeyed, so this route is safe
 * to call on every page load.
 */
export async function promptintelStatsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadPromptIntelIndex(c.env.ASSETS);
  let liveVersion: string | null = null;
  const cached = await kvBackedGet<{ version: string | null }>(c.env, MIRROR_RELEASE_KEY, 60 * 60);
  if (cached.value) {
    liveVersion = cached.value.version;
  } else {
    try {
      const res = await fetch(`${PROMPTINTEL_PUBLIC}/iopc/latest.json`, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        const body = (await res.json()) as { version?: string };
        liveVersion = body.version ?? null;
        await kvBackedPut(c.env, MIRROR_RELEASE_KEY, { version: liveVersion }, 60 * 60, (p) =>
          c.executionCtx.waitUntil(p)
        );
      }
    } catch {
      /* drift unknown — report null rather than guessing */
    }
  }
  return c.json(
    {
      taxonomyVersion: index.taxonomyVersion,
      liveVersion,
      mirrorStale: Boolean(liveVersion && liveVersion !== index.taxonomyVersion),
      syncedAt: index.syncedAt,
      counts: index.counts,
      cache: promptIntelCacheStats(),
      keyed: Boolean(c.env.PROMPTINTEL_API_KEY),
      plan: c.env.PROMPTINTEL_API_KEY ? 'community-or-enterprise' : 'mirror-only',
    },
    200,
    { 'cache-control': 'public, max-age=600', 'x-source': 'promptintel-mirror' }
  );
}

/* ─── Live routes (keyed, cached) ──────────────────────────────────────── */

/** GET /api/v1/promptintel/prompts — approved prompts, paged. */
export async function promptintelPromptsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const params = passthrough(c, [
    ['search', 200],
    ['entry', 32],
    ['severity', 20],
    ['category', 60],
  ]);
  const page = Math.max(1, Math.min(Number(c.req.query('page')) || 1, 100));
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 20, 50));
  params.set('page', String(page));
  params.set('limit', String(limit));
  return cachedUpstream(c, token, withQuery('/prompts', params), TTL.prompts);
}

/**
 * GET /api/v1/promptintel/prompts/:id — one prompt in full.
 * Community: 5 a day for the whole account, so the answer is held for 12h.
 */
export async function promptintelPromptHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const id = c.req.param('id') ?? '';
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(id)) return c.json({ error: 'bad_prompt_id' }, 400);
  return cachedUpstream(c, token, `/prompts/${encodeURIComponent(id)}`, TTL.prompt);
}

/** GET /api/v1/promptintel/agent-feed — curated, approved protections. */
export async function promptintelAgentFeedHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const params = passthrough(c, [
    ['category', 60],
    ['severity', 20],
    ['action', 40],
    ['since', 40],
    ['technique_id', 32],
  ]);
  return cachedUpstream(c, token, withQuery('/agent-feed', params), TTL.agentFeed);
}

/** GET /api/v1/promptintel/artifacts — malicious agent-file entries (Enterprise). */
export async function promptintelArtifactsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const params = passthrough(c, [
    ['q', 200],
    ['kind', 40],
    ['severity', 20],
    ['since', 40],
  ]);
  const page = Math.max(1, Math.min(Number(c.req.query('page')) || 1, 100));
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 25, 100));
  params.set('page', String(page));
  params.set('limit', String(limit));
  return cachedUpstream(c, token, withQuery('/artifacts', params), TTL.artifacts);
}

/**
 * GET /api/v1/promptintel/artifacts/lookup?sha256=a,b,c
 * Community: 20 lookups a day, and a hash's verdict does not change — the
 * cache is per-hash so a repeat costs nothing and a new hash costs one.
 */
export async function promptintelArtifactLookupHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  // Upstream accepts comma-separated OR repeated `sha256` parameters; handle
  // both instead of reading only the first value Hono exposes.
  const rawParams = c.req.queries('sha256') ?? [];
  const hashes = rawParams
    .flatMap((v) => v.split(','))
    .map((h) => h.trim().toLowerCase())
    .filter((h) => /^[a-f0-9]{64}$/.test(h));
  if (!hashes.length) {
    return c.json({ error: 'bad_hash', message: 'sha256 must be 1-50 comma-separated SHA-256 digests' }, 400);
  }
  if (hashes.length > 50) return c.json({ error: 'too_many_hashes', message: 'At most 50 per request' }, 400);
  const params = new URLSearchParams({ sha256: hashes.join(',') });
  return cachedUpstream(c, token, `/artifacts/lookup?${params.toString()}`, TTL.hashLookup);
}

/** GET /api/v1/promptintel/detection-rules — NOVA rule feed (Enterprise). */
export async function promptintelDetectionRulesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const params = passthrough(c, [['after', 200]]);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 100, 200));
  params.set('limit', String(limit));
  return cachedUpstream(c, token, withQuery('/detection-rules', params), TTL.detectionRules);
}

/** GET /api/v1/promptintel/scans — public scan history. */
export async function promptintelScansHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const params = passthrough(c, [
    ['q', 200],
    ['kind', 20],
    ['verdict', 40],
  ]);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 20, 100));
  params.set('limit', String(limit));
  return cachedUpstream(c, token, withQuery('/scans', params), TTL.scans);
}

/** GET /api/v1/promptintel/scans/:hash — one stored scan by content hash. */
export async function promptintelScanHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const hash = c.req.param('hash') ?? '';
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(hash)) return c.json({ error: 'bad_content_hash' }, 400);
  return cachedUpstream(c, token, `/scans/${encodeURIComponent(hash)}`, TTL.scans);
}

/**
 * POST /api/v1/promptintel/scan — scan a skill, MCP server or A2A agent.
 * Community: 10 scans a day. The body is forwarded verbatim (the upstream
 * form is documented), but its size is capped before it leaves the Worker.
 */
export async function promptintelScanPostHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const raw = await c.req.text();
  if (!raw) return c.json({ error: 'empty_body', message: 'Send the JSON body documented at /docs/api' }, 400);
  if (raw.length > 32_000) return c.json({ error: 'body_too_large', message: 'At most 32 KB' }, 413);
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return c.json({ error: 'bad_json' }, 400);
  }
  const live = await upstream('/scan', token, { method: 'POST', body: JSON.stringify(body) });
  if (!live) return c.json({ error: 'upstream_error' }, 502, { 'cache-control': 'no-store' });
  return c.json(live.body, live.status as 200, { 'x-source': 'promptintel-live', 'cache-control': 'no-store' });
}

/**
 * The one-value check, shared by GET and single-value POST so both forms land
 * on the same cache key — the Community allowance is 5 values a day, and
 * asking the same question two ways must not spend it twice.
 */
async function checkOne(c: Context<{ Bindings: Env }>, token: string, value: string, type?: string): Promise<Response> {
  const params = new URLSearchParams({ value });
  if (type && /^[a-z_]{2,20}$/.test(type)) params.set('type', type);
  return cachedUpstream(c, token, `/check?${params.toString()}`, TTL.check);
}

/** GET /api/v1/promptintel/check?value=&type= — one indicator verdict. */
export async function promptintelCheckGetHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const value = c.req.query('value');
  if (!value || value.length > 512) {
    return c.json(
      { error: 'missing_value', message: 'value is required (URL, domain, IP, SHA-256, file path, skill name)' },
      400
    );
  }
  return checkOne(c, token, value, c.req.query('type'));
}

/**
 * POST /api/v1/promptintel/check — up to 100 values.
 * Not cached as a whole (the value set is caller-chosen); single-value bodies
 * still land on the same per-value cache key as the GET form.
 */
export async function promptintelCheckPostHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const raw = await c.req.text();
  if (!raw) return c.json({ error: 'empty_body', message: 'Send {"indicators": [...]}' }, 400);
  if (raw.length > 32_000) return c.json({ error: 'body_too_large', message: 'At most 32 KB' }, 413);
  let parsed: { indicators?: unknown };
  try {
    parsed = JSON.parse(raw) as { indicators?: unknown };
  } catch {
    return c.json({ error: 'bad_json' }, 400);
  }
  const indicators = parsed?.indicators;
  const list = Array.isArray(indicators) ? indicators : typeof indicators === 'string' ? [indicators] : [];
  if (!list.length)
    return c.json({ error: 'bad_body', message: 'indicators must be a string or a non-empty array' }, 400);
  if (list.length > 100) return c.json({ error: 'too_many_indicators', message: 'At most 100 per request' }, 400);

  // A one-value body is exactly the GET form: reuse its cache entry so the
  // 5-a-day allowance is not spent twice on the same question.
  if (list.length === 1 && typeof list[0] === 'string') {
    if (list[0].length > 512) return c.json({ error: 'bad_indicator', message: 'Value too long' }, 400);
    return checkOne(c, token, list[0]);
  }

  const live = await upstream('/check', token, { method: 'POST', body: JSON.stringify({ indicators: list }) });
  if (!live) return c.json({ error: 'upstream_error' }, 502, { 'cache-control': 'no-store' });
  return c.json(live.body, live.status as 200, { 'x-source': 'promptintel-live', 'cache-control': 'no-store' });
}

/** GET /api/v1/promptintel/taxonomy/releases — published releases, newest first. */
export async function promptintelReleasesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  return cachedUpstream(c, token, '/taxonomy/releases', TTL.releases);
}

/** GET /api/v1/promptintel/taxonomy/changelog?since=&entry_id=&limit= */
export async function promptintelChangelogHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const params = passthrough(c, [
    ['since', 40],
    ['entry_id', 32],
  ]);
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 50, 200));
  params.set('limit', String(limit));
  return cachedUpstream(c, token, withQuery('/taxonomy/changelog', params), TTL.changelog);
}

/**
 * GET /api/v1/promptintel/quota — what this key has left today.
 * Never cached: the whole point is to answer after a 429.
 */
export async function promptintelQuotaHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKey(c);
  const [quota, limits] = await Promise.all([upstream('/quota', token), upstream('/agents/me/limits', token)]);
  if (!quota && !limits) return c.json({ error: 'upstream_error' }, 502, { 'cache-control': 'no-store' });
  return c.json({ quota: quota?.body ?? null, limits: limits?.body ?? null }, 200, {
    'x-source': 'promptintel-live',
    'cache-control': 'no-store',
  });
}
