import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { getBindingStatus, validateRequiredBindings, type BindingStatus } from '../../../worker/bindings';

/**
 * GET /api/v1/health/detailed
 *
 * One-shot health probe that reports the status of every binding the
 * Worker is expected to have — critical + optional — plus a live
 * `ok: true/false` flag for the four user-facing deps (D1, KV, AI,
 * Vectorize). Used by:
 *
 *   1. Operators debugging a misconfigured deploy. The per-binding
 *      `bound` flag and the `ok` aggregate are the answer to "why is
 *      /briefings returning 503?" without needing to read the worker
 *      code.
 *   2. Uptime monitors that want a single endpoint covering every dep.
 *      `status` is `ok` only when every critical binding is bound AND
 *      the live probes (D1 SELECT 1, KV read, AI run, Vectorize query)
 *      all succeed. A `degraded` status means one optional probe
 *      failed; `down` means one critical probe failed.
 *
 * Probes are bounded to a 2s budget each so a slow probe never
 * pins the response. Bypasses auth + rate-limit (it sits behind the
 * /api/v1/* middleware chain, but the handlers below are GETs with no
 * user input — see lib/ratelimit.ts BYPASS_EXACT for the explicit
 * health bypass).
 */
export async function healthDetailedHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const env = c.env as unknown as Record<string, unknown>;
  const bindings: BindingStatus[] = getBindingStatus(env);

  const PROBE_BUDGET_MS = 2_000;
  const probe = async (fn: () => Promise<unknown>): Promise<{ ok: boolean; latency_ms: number; error?: string }> => {
    const start = Date.now();
    try {
      let raceTimerId: ReturnType<typeof setTimeout> | undefined;
      const raceTimeout = new Promise<never>((_, reject) => {
        raceTimerId = setTimeout(() => reject(new Error('probe timeout')), PROBE_BUDGET_MS);
        // In Node.js tests, .unref() prevents the timeout from keeping the event loop open
        if (typeof raceTimerId === 'object' && 'unref' in raceTimerId) {
          (raceTimerId as { unref?: () => void }).unref?.();
        }
      });
      await Promise.race([fn(), raceTimeout]);
      if (raceTimerId !== undefined) clearTimeout(raceTimerId);
      return { ok: true, latency_ms: Date.now() - start };
    } catch (e) {
      logError('healthDetailedHandler failed', e);
      return { ok: false, latency_ms: Date.now() - start, error: e instanceof Error ? e.message : 'unknown' };
    }
  };

  const [d1, kv, ai, vectorize] = await Promise.all([
    probe(async () => {
      const db = env.BRIEFINGS_DB as { prepare: (q: string) => { first: () => Promise<unknown> } } | undefined;
      if (!db) throw new Error('binding missing');
      await db.prepare('SELECT 1').first();
    }),
    probe(async () => {
      const k = env.KV_CACHE as { get: (k: string) => Promise<unknown> } | undefined;
      if (!k) throw new Error('binding missing');
      await k.get('__health__');
    }),
    probe(async () => {
      const a = env.AI as { run: (m: string, p: unknown) => Promise<unknown> } | undefined;
      if (!a) throw new Error('binding missing');
      await a.run('@cf/meta/llama-3.1-8b-instruct-fp8', {
        messages: [{ role: 'user', content: 'ping' }],
        max_tokens: 5,
      });
    }),
    probe(async () => {
      const v = env.VECTORIZE as { query: (v: number[], o: unknown) => Promise<unknown> } | undefined;
      if (!v) throw new Error('binding missing');
      await v.query(new Array(768).fill(0), { topK: 1 });
    }),
  ]);

  const missingCritical = validateRequiredBindings(env).missing.map((m: BindingStatus) => m.key);
  const criticalDown = !d1.ok || !kv.ok;

  const status: 'ok' | 'degraded' | 'down' =
    missingCritical.length > 0 || criticalDown ? 'down' : !ai.ok || !vectorize.ok ? 'degraded' : 'ok';

  return c.json(
    {
      ok: status !== 'down',
      status,
      generated_at: new Date().toISOString(),
      bindings: {
        list: bindings,
        missing_critical: missingCritical,
      },
      probes: { d1, kv, ai, vectorize },
    },
    status === 'down' ? 503 : 200,
    { 'Cache-Control': 'no-store' }
  );
}
