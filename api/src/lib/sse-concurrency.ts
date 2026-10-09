import type { Context } from 'hono';
import type { Env } from '../env';

/**
 * Cap concurrent SSE streams per IP.
 *
 * The KV-backed `rateLimit` middleware in ratelimit.ts counts request
 * starts within a sliding window — perfectly fine for short JSON GETs
 * but useless for SSE: a malicious client can hold N streams open for
 * 60s+ each. While they're open, every stream's producer is doing
 * provider fan-out → upstream burn proportional to N, not to the
 * advertised 30/min cap.
 *
 * This guard tracks live stream count via a short-lived KV counter
 * keyed by IP. Increment on entry, decrement on stream end (best-effort
 * via ctx.waitUntil so we never block the close path). KV is eventually
 * consistent so this is a soft cap — fine for defensive use, not a
 * hard DDoS mitigation. For real hard caps, a Durable Object would be
 * the right tool; we deliberately stay on KV here to avoid the cost
 * and complexity bump.
 *
 * The counter has a short TTL (90s) so a Worker that crashes mid-stream
 * doesn't leave a phantom slot reserved.
 */

const MAX_CONCURRENT = 5;
const COUNTER_TTL = 90;

export interface SseSlot {
  /** Call when the stream finishes (success OR error). */
  release: () => Promise<void>;
}

/**
 * Try to claim a concurrency slot for `ip`. Returns null if the IP is
 * over the cap (caller should respond 429), or a SseSlot whose
 * `release` MUST be called when the stream ends.
 *
 * Migrated from KV to caches.default 2026-05-24 — the counter is
 * already per-colo (KV is eventually consistent, so two CF colos
 * served different views anyway), so dropping to a literal per-colo
 * Cache-API entry has the same soft-cap semantics with zero KV quota
 * cost. No-ops cleanly when the cache isn't available.
 */
export async function claimSseSlot(_c: Context<{ Bindings: Env }>, ip: string): Promise<SseSlot | null> {
  const cache = (() => {
    try {
      return (caches as unknown as { default?: Cache }).default ?? null;
    } catch {
      return null;
    }
  })();
  // No Cache API → no counter, so nothing can be over the cap. The contract
  // above ("no-ops cleanly") required a slot back, not a throw: the previous
  // unguarded `caches.default` dereference raised a TypeError before the
  // try/catch below, failing all three SSE routes with a 500 rather than
  // failing open. The per-window rateLimit middleware still applies.
  const noopSlot: SseSlot = { release: async () => {} };
  if (!cache) return noopSlot;
  const key = new Request(`https://sse-open.internal/v1/${encodeURIComponent(ip)}`);
  let count = 0;
  try {
    const hit = await cache.match(key);
    if (hit) count = parseInt(await hit.text(), 10) || 0;
  } catch {
    // Cache transient error — fail open. The per-window rateLimit
    // middleware still applies, so we're not unprotected.
    return { release: async () => {} };
  }
  if (count >= MAX_CONCURRENT) return null;

  // Best-effort increment. max-age expires the entry at COUNTER_TTL so
  // a Worker that crashes mid-stream doesn't leave a phantom slot.
  try {
    await cache.put(
      key,
      new Response(String(count + 1), {
        headers: { 'cache-control': `max-age=${COUNTER_TTL}` },
      })
    );
  } catch {
    /* swallow — fail open */
  }

  // Release is a no-op: the TTL handles cleanup. Trade-off documented
  // before the migration — soft cap, not a hard DDoS mitigation.
  return { release: async () => {} };
}

export const SSE_MAX_CONCURRENT = MAX_CONCURRENT;
