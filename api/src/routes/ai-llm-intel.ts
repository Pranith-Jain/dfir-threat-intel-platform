/**
 * GET /api/v1/ai-llm-intel — dedicated AI / LLM threat-intelligence surface.
 *
 * Backs the brief / trends / blog consumers and the AI-LLM hub page. Reads a
 * per-colo Cache API slice written by the hourly queue (`aiLlmWarm` message
 * shape) so a page view never fans out to five third-party upstreams; falls
 * back to an in-process build on a cold slice.
 *
 * Admin-gated `?health=1` runs `verifyAiLlmEndpoints` for real HTTP status /
 * payload size per upstream — the only place that distinguishes "upstream down"
 * from "our fetch broke".
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badGateway } from '../lib/api-error';
import { requireAdmin } from '../lib/admin-auth';
import { trackEvent, visitorCountry } from '../lib/analytics';
import { buildAiLlmIntel, verifyAiLlmEndpoints, type AiLlmIntelResponse } from '../lib/ai-llm-intel';

/** Slice TTL. 6h mirrors the live-IOC slices — the upstream publishes on an
 *  hourly-ish agent cadence, so 6h of last-good is generous and still self-heals
 *  within a cron cycle of a persistent failure. */
export const AI_LLM_SLICE_TTL_SECONDS = 6 * 60 * 60;
export const AI_LLM_SLICE_KEY = 'https://ai-llm-intel-slice.internal/v1';

/**
 * Edge-cache TTL. Deliberately shorter than the slice TTL: the slice is the
 * durable last-good, the edge cache is the hot read. When a build is degraded
 * (an upstream failed) drop to 5 min so it recovers promptly rather than
 * serving a stale-but-healthy-looking page for 30.
 */
const CACHE_TTL_SECONDS = 30 * 60;
const DEGRADED_TTL_SECONDS = 5 * 60;

function getDefaultCache(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch {
    return null;
  }
}

/** Async read of the warmed slice, or null. Safe from any context. */
export async function readAiLlmIntelSlice(): Promise<AiLlmIntelResponse | null> {
  const cache = getDefaultCache();
  if (!cache) return null;
  try {
    const hit = await cache.match(new Request(AI_LLM_SLICE_KEY));
    if (!hit) return null;
    const parsed = (await hit.json()) as AiLlmIntelResponse | null;
    if (!parsed || !Array.isArray(parsed.actors) || !Array.isArray(parsed.trends)) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Persist a built payload as the slice. Called by the queue consumer's warm
 * message and by the on-demand fallback path, so a cold colo self-warms on its
 * first request instead of waiting for the next cron tick.
 */
export async function writeAiLlmSlice(payload: AiLlmIntelResponse): Promise<void> {
  const cache = getDefaultCache();
  if (!cache) return;
  try {
    await cache.put(
      new Request(AI_LLM_SLICE_KEY),
      new Response(JSON.stringify(payload), {
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${AI_LLM_SLICE_TTL_SECONDS}`,
        },
      })
    );
  } catch {
    /* best-effort — a slice write failure must not fail the build that produced it */
  }
}

export async function aiLlmIntelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  // ── Admin health probe ──────────────────────────────────────────────────
  if (c.req.query('health') === '1') {
    const gate = requireAdmin(c);
    if ('error' in gate) return gate.error;
    const endpoints = await verifyAiLlmEndpoints();
    const slice = await readAiLlmIntelSlice();
    return c.json(
      {
        checked_at: new Date().toISOString(),
        endpoints,
        slice: slice
          ? {
              present: true,
              generated_at: slice.generated_at,
              last_updated: slice.last_updated,
              degraded: !!slice.degraded,
            }
          : { present: false },
      },
      200,
      { 'Cache-Control': 'no-store' }
    );
  }

  const cache = getDefaultCache();
  const cacheKey = new Request(AI_LLM_SLICE_KEY);

  // Cache HIT → serve. Stale-while-revalidate: once the entry is past 80% of
  // its TTL, serve immediately but rebuild in the background so the next request
  // gets fresh data. Age comes from the `date` header the Cache API stamps,
  // matching live-iocs' SWR path.
  if (cache) {
    const hit = await cache.match(cacheKey);
    if (hit) {
      const cacheDate = hit.headers.get('date');
      const ageS = cacheDate ? (Date.now() - new Date(cacheDate).getTime()) / 1000 : 0;
      if (ageS > AI_LLM_SLICE_TTL_SECONDS * 0.8) {
        c.executionCtx.waitUntil(
          (async () => {
            try {
              await writeAiLlmSlice(await buildAiLlmIntel());
            } catch (e) {
              logError('ai-llm-intel swr rebuild failed', e);
            }
          })()
        );
      }
      trackEvent(c.env, 'ai_llm_intel_fetch', {
        blobs: ['hit'],
        indexes: [visitorCountry(c.req.raw)],
      });
      return new Response(hit.body, hit);
    }
  }

  // Cold slice → build in-process (5 upstreams, one Promise.all) and self-warm
  // so the next request is a hit.
  let payload: AiLlmIntelResponse;
  try {
    payload = await buildAiLlmIntel();
  } catch (e) {
    logError('aiLlmIntelHandler build failed', e);
    return badGateway(c, e instanceof Error ? e.message : 'Build failed');
  }

  if (!payload.sources.some((s) => s.ok)) {
    // Every upstream failed — there is nothing worth serving or caching.
    return badGateway(c, 'All AI/LLM intel upstreams unreachable');
  }

  await writeAiLlmSlice(payload);

  const ttl = payload.degraded ? DEGRADED_TTL_SECONDS : CACHE_TTL_SECONDS;
  trackEvent(c.env, 'ai_llm_intel_fetch', {
    blobs: ['miss'],
    doubles: [payload.stats.iocs, payload.stats.actors, payload.stats.posts],
    indexes: [visitorCountry(c.req.raw), payload.degraded ? 'degraded' : 'ok'],
  });
  return c.json(payload, 200, { 'Cache-Control': `public, max-age=${ttl}` });
}
