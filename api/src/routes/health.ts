import { Hono } from 'hono';
import type { Env } from '../env';
import { serviceUnavailable } from '../lib/api-error';
import { getSiteUrl } from '../lib/site-config';
import { healthDetailedHandler } from './health-detailed';
import { featuresHandler } from './features';
import { generateOpenApiSpec } from '../lib/openapi';
import { API_DOCS_HTML } from '../lib/api-docs-html';

const health = new Hono<{ Bindings: Env }>();

health.get('/api/v1/health', (c) =>
  c.json({ ok: true, timestamp: new Date().toISOString() }, 200, { 'Cache-Control': 'public, max-age=60' })
);

health.get('/api/v1/health/detailed', healthDetailedHandler);
health.get('/api/v1/features', featuresHandler);

health.get('/api/v1/openapi.json', (c) => {
  return c.json(generateOpenApiSpec(), 200, {
    'Cache-Control': 'public, max-age=3600',
    'Access-Control-Allow-Origin': getSiteUrl(c.env as { SITE_URL?: string }),
  });
});

health.get('/api/docs', (c) => {
  return c.body(API_DOCS_HTML, 200, {
    'content-type': 'text/html; charset=utf-8',
    'Cache-Control': 'public, max-age=300',
  });
});

health.get('/api/v1/docs', (c) => c.redirect('/api/docs', 301));

health.post('/api/v1/csp-report', async (c) => {
  try {
    const body = await c.req.json();
    if (body && typeof body === 'object') {
    }
  } catch {
    // silently ignore malformed reports
  }
  return c.body(null, 204);
});

health.get('/api/v1/health/d1', async (c) => {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return c.json({ status: 'unavailable', binding: 'BRIEFINGS_DB' }, 503);
  try {
    const start = Date.now();
    await db.prepare('SELECT 1').first();
    return c.json({ status: 'ok', latency_ms: Date.now() - start }, 200, { 'Cache-Control': 'no-store' });
  } catch (e) {
    return serviceUnavailable(c, e instanceof Error ? e.message : 'unknown');
  }
});

/**
 * KV liveness probe.
 *
 * Reads are billed per key on the free plan whether or not the key exists, so
 * this probe used to spend one of the 100k/day reads on every call — against
 * `__health_check__`, which nothing ever writes, making it a guaranteed miss.
 * `Cache-Control: no-store` also meant no upstream or browser could dedupe it,
 * so a monitor polling every minute burned 1,440 reads/day to learn "the
 * binding still resolves".
 *
 * The probe is now memoised per-colo for 60s in the Cache API, which costs
 * nothing and is well inside the window any uptime monitor tolerates. It still
 * proves the binding works on a cold colo, and a KV outage is reported on the
 * next check rather than silently cached — the cached entry only exists after
 * a successful probe.
 */
const KV_HEALTH_CACHE_KEY = 'https://health-kv.internal/v1';
const KV_HEALTH_TTL_S = 60;

health.get('/api/v1/health/kv', async (c) => {
  const kv = c.env.KV_CACHE;
  if (!kv) return c.json({ status: 'unavailable', binding: 'KV_CACHE' }, 503);

  const cache = (caches as unknown as { default?: Cache }).default;
  const cacheReq = new Request(KV_HEALTH_CACHE_KEY);
  try {
    const hit = cache ? await cache.match(cacheReq) : null;
    if (hit) return new Response(hit.body, hit);
  } catch {
    /* cache miss is fine — fall through and probe */
  }

  try {
    const start = Date.now();
    // Reading any key exercises the binding end to end. Kept as an explicit
    // miss-only probe rather than reading live data: it must never perturb or
    // depend on the contents of a real cache key.
    await kv.get('__health_check__');
    // `max-age` (not `no-store`) so the Cache API actually retains it — a
    // no-store response is not cached, which is what made the previous version
    // a billed read on every single poll. Only SUCCESSFUL probes are ever
    // cached, so a KV outage is still reported on the next check.
    const res = c.json({ status: 'ok', latency_ms: Date.now() - start }, 200, {
      'Cache-Control': `public, max-age=${KV_HEALTH_TTL_S}`,
    });
    if (cache) c.executionCtx.waitUntil(cache.put(cacheReq, res.clone()).catch(() => {}));
    return res;
  } catch (e) {
    return serviceUnavailable(c, e instanceof Error ? e.message : 'unknown');
  }
});

health.get('/api/v1/health/ai', async (c) => {
  const ai = c.env.AI;
  if (!ai) return c.json({ status: 'unavailable', binding: 'AI' }, 503);
  try {
    const start = Date.now();
    await ai.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [{ role: 'user', content: 'ping' }],
      max_tokens: 5,
    });
    return c.json({ status: 'ok', latency_ms: Date.now() - start, model: 'llama-3.1-8b' }, 200, {
      'Cache-Control': 'no-store',
    });
  } catch (e) {
    return serviceUnavailable(c, e instanceof Error ? e.message : 'unknown');
  }
});

health.get('/api/v1/health/vectorize', async (c) => {
  const vec = c.env.VECTORIZE;
  if (!vec) return c.json({ status: 'unavailable', binding: 'VECTORIZE' }, 503);
  try {
    const start = Date.now();
    await vec.query(new Array(768).fill(0), { topK: 1 });
    return c.json({ status: 'ok', latency_ms: Date.now() - start }, 200, { 'Cache-Control': 'no-store' });
  } catch (e) {
    return serviceUnavailable(c, e instanceof Error ? e.message : 'unknown');
  }
});

health.get('/api/v1/debug/llm', async (c) => {
  const env = c.env;
  const ping = { messages: [{ role: 'user', content: 'ping' }], max_tokens: 5 };
  const testEndpoint = async (url: string, key: string | undefined, body: unknown) => {
    if (!key) return { status: 'no_key' };
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
      const text = await res.text().catch(() => '');
      return { status: res.status, ok: res.ok, body: text.slice(0, 300) };
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) };
    }
  };
  return c.json(
    {
      keys: {
        nvidia: !!env.NVIDIA_API_KEY,
        groq: !!env.GROQ_API_KEY,
        google: !!env.GOOGLE_AI_STUDIO_API_KEY,
      },
      nvidia: await testEndpoint('https://integrate.api.nvidia.com/v1/chat/completions', env.NVIDIA_API_KEY, {
        ...ping,
        model: 'minimaxai/minimax-m2.7',
      }),
      nvidiaFallback: await testEndpoint('https://integrate.api.nvidia.com/v1/chat/completions', env.NVIDIA_API_KEY, {
        ...ping,
        model: 'z-ai/glm-5.2',
      }),
      groq: await testEndpoint('https://api.groq.com/openai/v1/chat/completions', env.GROQ_API_KEY, {
        model: 'llama-3.1-8b-instant',
        messages: [{ role: 'user', content: 'ping' }],
        max_completion_tokens: 5,
      }),
      groqFallback: await testEndpoint('https://api.groq.com/openai/v1/chat/completions', env.GROQ_API_KEY, {
        model: 'openai/gpt-oss-20b',
        messages: [{ role: 'user', content: 'ping' }],
        max_completion_tokens: 5,
      }),
      google: await testEndpoint(
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=' +
          env.GOOGLE_AI_STUDIO_API_KEY,
        env.GOOGLE_AI_STUDIO_API_KEY,
        { contents: [{ role: 'user', parts: [{ text: 'ping' }] }], generationConfig: { maxOutputTokens: 5 } }
      ),
      googleMid: await testEndpoint(
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.7-flash:generateContent?key=' +
          env.GOOGLE_AI_STUDIO_API_KEY,
        env.GOOGLE_AI_STUDIO_API_KEY,
        { contents: [{ role: 'user', parts: [{ text: 'ping' }] }], generationConfig: { maxOutputTokens: 5 } }
      ),
      googleFallback: await testEndpoint(
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' +
          env.GOOGLE_AI_STUDIO_API_KEY,
        env.GOOGLE_AI_STUDIO_API_KEY,
        { contents: [{ role: 'user', parts: [{ text: 'ping' }] }], generationConfig: { maxOutputTokens: 5 } }
      ),
    },
    200,
    { 'Cache-Control': 'no-store' }
  );
});

export default health;
