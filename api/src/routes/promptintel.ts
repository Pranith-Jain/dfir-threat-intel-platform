/**
 * PromptIntel IoPC proxy — Indicators of Prompt Compromise.
 *
 * Upstream: `https://api.promptintel.novahunting.ai/api/v1` (NovaHunting).
 * The platform's prompt-injection surface today is client-side only
 * (`PromptInjection.tsx` regex scanner + `AiEscape.tsx` catalog); this route
 * adds LIVE upstream intel: the IoPC taxonomy (IOPC-T/IOPC-R entries with
 * maturity, framework mappings, changelog) and the prompt feed search.
 *
 * Shape mirrors `cve-recent.ts`: Cache-API splash → KV last-good → fast
 * 503. The hourly DO cron warms taxonomy+health via `warmPromptintelCache`
 * (single upstream fetch each — no fan-out). Keyed endpoints need
 * `PROMPTINTEL_API_KEY` (`wrangler secret put`); without it they degrade
 * to a 501 with setup instructions instead of failing obscurely.
 *
 * Zero D1 — KV reads only on cache miss.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { readLastGood, writeLastGood } from '../lib/lastgood';

const PROMPTINTEL_BASE = 'https://api.promptintel.novahunting.ai/api/v1';
const FETCH_TIMEOUT_MS = 12_000;

const TAX_CACHE_KEY = 'https://promptintel-cache.internal/v1/taxonomy';
const TAX_KV_KEY = 'promptintel:taxonomy:lastgood';
const TAX_TTL_SECONDS = 6 * 60 * 60;
const TAX_KV_TTL_SECONDS = 24 * 60 * 60;

const HEALTH_CACHE_KEY = 'https://promptintel-cache.internal/v1/health';
const HEALTH_TTL_SECONDS = 5 * 60;

function cacheApi(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch {
    return null;
  }
}

async function fetchUpstream(path: string, token?: string): Promise<unknown | null> {
  try {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(`${PROMPTINTEL_BASE}${path}`, {
      headers,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    return (await res.json()) as unknown;
  } catch {
    return null;
  }
}

async function putCache(key: string, body: unknown, maxAge: number, source: string): Promise<void> {
  const cache = cacheApi();
  if (!cache) return;
  try {
    await cache.put(
      new Request(key),
      new Response(JSON.stringify(body), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${maxAge}, stale-while-revalidate=${maxAge * 4}`,
          'x-source': source,
        },
      })
    );
  } catch {
    /* best-effort */
  }
}

/**
 * Cron-warm for PromptIntel. Must run inside the DO cron (30s CPU budget),
 * never a user/self fetch. Warms health (public) + taxonomy (keyed).
 */
export async function warmPromptintelCache(env?: Env): Promise<{ ok: boolean; taxonomy: boolean }> {
  const token = env?.PROMPTINTEL_API_KEY;
  let healthOk = false;
  let taxonomyOk = false;

  const health = await fetchUpstream('/health');
  if (health) {
    healthOk = true;
    await putCache(HEALTH_CACHE_KEY, health, HEALTH_TTL_SECONDS, 'cron-warm');
  }

  if (token) {
    const taxonomy = await fetchUpstream('/taxonomy', token);
    if (taxonomy) {
      taxonomyOk = true;
      await putCache(TAX_CACHE_KEY, taxonomy, TAX_TTL_SECONDS, 'cron-warm');
      // force: true — the cron runs on a fixed cadence and must always
      // refresh the global copy (mirrors ransomware-recent warm).
      // skipIfUnchanged keeps the hourly tick from spending a KV write (the
      // scarce free-plan quota) on a taxonomy that has not moved.
      await writeLastGood(env as Pick<Env, 'KV_CACHE'>, TAX_KV_KEY, taxonomy, {
        force: true,
        skipIfUnchanged: true,
        ttlSeconds: TAX_KV_TTL_SECONDS,
        keyPrefix: '',
      });
    }
  }
  if (!healthOk || (token && !taxonomyOk)) {
    console.warn(JSON.stringify({ job: 'promptintel-warm', healthOk, taxonomyOk, keyed: Boolean(token) }));
  }
  return { ok: healthOk, taxonomy: taxonomyOk };
}

function noKeyResponse(c: Context<{ Bindings: Env }>): Response {
  return c.json(
    {
      error: 'promptintel_key_missing',
      message:
        'Set PROMPTINTEL_API_KEY (`wrangler secret put PROMPTINTEL_API_KEY`) to enable the keyed PromptIntel endpoints. /health works without a key.',
      docs: 'https://promptintel.novahunting.ai/api',
    },
    501,
    { 'cache-control': 'no-store' }
  );
}

/** GET /api/v1/promptintel/health — upstream liveness, no key needed. */
export async function promptintelHealthHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = cacheApi();
  if (cache) {
    try {
      const hit = await cache.match(new Request(HEALTH_CACHE_KEY));
      if (hit) return new Response(hit.body, hit);
    } catch {
      /* fall through */
    }
  }
  const live = await fetchUpstream('/health');
  if (live) {
    await putCache(HEALTH_CACHE_KEY, live, HEALTH_TTL_SECONDS, 'live');
    return c.json(live, 200, {
      'cache-control': `public, max-age=${HEALTH_TTL_SECONDS}`,
      'x-source': 'promptintel-live',
    });
  }
  return c.json({ status: 'unknown', upstream: 'unreachable' }, 503, { 'retry-after': '300' });
}

/** GET /api/v1/promptintel/taxonomy — cached IoPC taxonomy (keyed). */
export async function promptintelTaxonomyHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKeyResponse(c);
  const cache = cacheApi();
  if (cache) {
    try {
      const hit = await cache.match(new Request(TAX_CACHE_KEY));
      if (hit) return new Response(hit.body, hit);
    } catch {
      /* fall through to KV */
    }
  }
  const kvBody = await readLastGood<unknown>(c.env, TAX_KV_KEY, { keyPrefix: '' });
  if (kvBody && typeof kvBody === 'object') {
    const kvRaw = JSON.stringify(kvBody);
    if (kvRaw.length > 20 && kvRaw.trimStart().startsWith('{')) {
      const res = new Response(kvRaw, {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=300, stale-while-revalidate=1200`,
          'x-source': 'promptintel-kv-lastgood',
        },
      });
      try {
        await cache?.put(new Request(TAX_CACHE_KEY), res.clone());
      } catch {
        /* best-effort */
      }
      return res;
    }
  }
  return c.json({ error: 'warming', message: 'taxonomy not cached yet — hourly cron warms within the hour' }, 503, {
    'retry-after': '300',
  });
}

/**
 * GET /api/v1/promptintel/prompts — live upstream search passthrough (keyed).
 * Allowlisted params only; single small fetch inline (no aggregate rebuild,
 * so the free-plan CPU cap is not a concern). Not cached: query space is
 * unbounded and calls are user-initiated.
 */
export async function promptintelPromptsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKeyResponse(c);
  const params = new URLSearchParams();
  const passthrough = (name: string, maxLen: number): void => {
    const v = c.req.query(name);
    if (v && v.length <= maxLen) params.set(name, v);
  };
  passthrough('search', 200);
  passthrough('severity', 20);
  passthrough('category', 20);
  const page = Math.max(1, Math.min(Number(c.req.query('page')) || 1, 100));
  const limit = Math.max(1, Math.min(Number(c.req.query('limit')) || 20, 100));
  params.set('page', String(page));
  params.set('limit', String(limit));
  const data = await fetchUpstream(`/prompts?${params.toString()}`, token);
  if (!data) return c.json({ error: 'upstream_error', message: 'PromptIntel unreachable or rate-limited' }, 502);
  return c.json(data, 200, { 'cache-control': 'no-store', 'x-source': 'promptintel-live' });
}

/** GET /api/v1/promptintel/taxonomy/entries/:id — single IoPC entry (keyed). */
export async function promptintelEntryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const token = c.env.PROMPTINTEL_API_KEY;
  if (!token) return noKeyResponse(c);
  const id = c.req.param('id') ?? '';
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(id)) return c.json({ error: 'bad_entry_id' }, 400);
  const data = await fetchUpstream(`/taxonomy/entries/${encodeURIComponent(id)}`, token);
  if (!data) return c.json({ error: 'not_found', message: 'entry not found or upstream unreachable' }, 404);
  return c.json(data, 200, { 'cache-control': 'public, max-age=3600', 'x-source': 'promptintel-live' });
}
