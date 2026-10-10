// Cloudflare Workers runtime exposes caches.default but the TypeScript
// lib types only define `caches.open()`. Cast is required for `caches.default`.
// The batched mode of ProviderCache (used by the IOC fan-out) is intentionally
// L1-only (caches.default) — see the class docstring for why.
import { safeNullLog } from './safe-catch';
const CACHE_PLATFORM = caches as unknown as { default: Cache };

export function getCache(): Cache {
  return CACHE_PLATFORM.default;
}

import type { Indicator, ProviderResult } from '../providers/types';

/** One provider's cached result plus its absolute expiry (epoch seconds). */
interface BatchEntry {
  r: ProviderResult;
  exp: number;
}

/**
 * Provider result cache (per-colo Cache API, with legacy KV read fallback).
 *
 * Caches upstream provider responses (VirusTotal, AbuseIPDB, etc.) to
 * reduce API quota consumption and improve response times.
 *   - L1: per-colo `caches.default` (free, sub-millisecond) — the ONLY
 *     write path. KV writes were removed to stay under the free-plan
 *     1,000 writes/day KV quota.
 *   - L2 (read-only legacy): KV namespace. Old entries written before
 *     the KV-write removal are still readable; they phase out as their
 *     TTLs expire. No new KV entries are created by `set()`.
 *
 * The batched mode (used by the IOC fan-out) is L1-only — it coalesces
 * an entire indicator's worth of provider results into a single Cache
 * API entry to stay under the 50-subrequest-per-invocation limit.
 *
 * Gracefully degrades when Cache API is unavailable — all operations
 * become no-ops so the IOC check still works (just without caching).
 */
export class ProviderCache {
  private kv: KVNamespace | null;

  /**
   * Batched-mode state. The IOC fan-out checks N providers in a single
   * Worker invocation; doing a per-provider KV get + set (and the Cache
   * API front below) burns ~2N+ subrequests, which on the Workers Free
   * plan trips the 50-subrequests-per-invocation ceiling once N grows
   * past ~12. Batched mode collapses that to ONE Cache API read
   * (`primeBatch`) and ONE Cache API write (`flushBatch`) for the whole
   * indicator, keyed by a single combined entry holding every provider's
   * result. (Note: the batched mode is intentionally Cache-API-only — the
   * class docstring used to claim this was KV; that was wrong.)
   */
  private primed: Record<string, BatchEntry> | null = null;
  private staged: Record<string, BatchEntry> = {};

  constructor(kv: KVNamespace | undefined | null) {
    this.kv = kv ?? null;
  }

  private buildKey(provider: string, indicator: Indicator): string {
    return `provider:${provider}:${indicator.value.toLowerCase()}`;
  }

  private batchKey(indicator: Indicator): string {
    return `iocbatch:${indicator.type}:${indicator.value.toLowerCase()}`;
  }

  private cacheUrl(provider: string, indicator: Indicator): string {
    return `https://provider-cache.internal/v1/${provider}/${indicator.value.toLowerCase()}`;
  }

  private cacheApi(): Cache | null {
    try {
      return (caches as unknown as { default: Cache }).default;
    } catch {
      return null;
    }
  }

  /**
   * Cache TTL (seconds) per indicator type, with per-provider overrides.
   * Hashes are the most stable (24h), IPv4 the most volatile (1h), URLs and
   * domains fall in between. Specific providers override when their
   * upstream feed churns at a different cadence than the type default.
   */
  static ttlSeconds(type: Indicator['type'], provider?: string): number {
    const typeDefault: Record<Indicator['type'], number> = {
      hash: 86400,
      ipv4: 3600,
      ipv6: 3600,
      domain: 21600,
      url: 3600,
      email: 3600,
      cve: 86400,
      unknown: 3600,
    };
    const overrides: Record<string, number> = {
      'urlhaus:url': 1800,
      'sslbl:ipv4': 14400,
      'hashlookup:hash': 604800,
    };
    if (provider) {
      const key = `${provider}:${type}`;
      const override = overrides[key];
      if (override !== undefined) return override;
    }
    return typeDefault[type];
  }

  /**
   * Get a cached provider result.
   * Returns null if not found, expired, or KV unavailable.
   * The returned result's `cached` flag is set to true so callers can
   * distinguish a hit from a fresh upstream response.
   */
  async get(provider: string, indicator: Indicator): Promise<ProviderResult | null> {
    // Check per-colo Cache API first — same-colо repeat queries skip KV entirely
    const cache = this.cacheApi();
    if (cache) {
      try {
        const r = await cache.match(new Request(this.cacheUrl(provider, indicator)));
        if (r) return { ...((await r.json()) as ProviderResult), cached: true };
      } catch {
        /* fall through to KV */
      }
    }
    // No KV L2 read here on purpose.
    //
    // This tier used to do `kv.get(provider:<provider>:<indicator>)`, but the
    // corresponding KV write was removed from set() to stay under the free-plan
    // 1,000 writes/day quota (see set()'s comment). Nothing has written those
    // keys since, so every Cache-API miss was paying a BILLED KV read that was
    // guaranteed to return null — on the free plan reads bill per key whether or
    // not the key exists (100k/day). Across the four entry points that build a
    // ProviderCache (ioc-providers, enrich-bulk, sample-scan, url-risk,
    // ioc-verdict) that is one wasted read per provider lookup, on the hot IOC
    // path, for data that cannot exist.
    //
    // The Cache API tier above is the only durable layer, which is exactly what
    // set() now maintains. `kv` is still held for delete(), which purges any
    // legacy keys written before the write tier was removed.
    return null;
  }

  /**
   * Cache a provider result with TTL derived from the indicator type.
   * Writes to the per-colo Cache API only — KV L2 writes were removed to
   * stay under the free-plan 1,000 writes/day KV quota. Provider results
   * are ephemeral (1h–24h TTL) and same-colo repeats are the dominant
   * access pattern; the batched IOC fan-out already proved Cache-API-only
   * is sufficient. Cross-colo durability is a nice-to-have, not a
   * requirement, for provider response caching.
   */
  async set(provider: string, indicator: Indicator, data: ProviderResult, ttlSeconds?: number): Promise<void> {
    const ttl = ttlSeconds ?? ProviderCache.ttlSeconds(indicator.type, provider);
    const cache = this.cacheApi();
    if (cache) {
      const cacheResp = new Response(JSON.stringify(data), {
        headers: { 'cache-control': `public, max-age=${ttl}` },
      });
      // Await so callers that `await cache.set(...)` (and tests) see the
      // write complete before a subsequent read. Production callers that
      // want fire-and-forget can wrap this in executionCtx.waitUntil.
      await safeNullLog(
        'cache-put-provider-set',
        cache.put(new Request(this.cacheUrl(provider, indicator)), cacheResp)
      );
    }
  }

  /**
   * Delete a cached provider result.
   * No-op when KV is unavailable.
   */
  async delete(provider: string, indicator: Indicator): Promise<void> {
    if (!this.kv) return;
    const key = this.buildKey(provider, indicator);
    try {
      await this.kv.delete(key);
    } catch {
      /* best-effort */
    }
    // Purge from per-colo cache
    const cache = this.cacheApi();
    if (cache) {
      void safeNullLog('cache-delete-provider', cache.delete(new Request(this.cacheUrl(provider, indicator))));
    }
  }

  // ---- Batched mode (used by the IOC fan-out) ------------------------------
  //
  // Every provider result for one indicator lives under a single combined
  // KV key. `primeBatch` reads it once; `getBatched` serves per-provider hits
  // from memory (zero subrequests); `stageBatched` queues fresh results; and
  // `flushBatch` writes them all back in one KV put. This keeps the whole
  // fan-out to 2 cache subrequests total instead of ~2 per provider, staying
  // under the Workers Free-plan 50-subrequests-per-invocation limit.

  /** Cache-API request key for an indicator's combined batch entry. */
  private batchCacheReq(indicator: Indicator): Request {
    return new Request(`https://ioc-batch.internal/v1/${encodeURIComponent(this.batchKey(indicator))}`);
  }

  /**
   * Load the combined cache entry for `indicator` from the per-colo
   * Cache API (free, does NOT count against the KV quota). The batched
   * mode is intentionally L1-only — the payload shape (a per-indicator
   * map of every provider's result) is not stable enough to version in
   * KV cost-effectively. Provider results are ephemeral, so per-colo
   * caching is sufficient for the IOC-fanout hot path.
   */
  async primeBatch(indicator: Indicator): Promise<void> {
    this.primed = {};
    this.staged = {};
    try {
      const hit = await CACHE_PLATFORM.default.match(this.batchCacheReq(indicator));
      if (hit) {
        const map = (await hit.json()) as Record<string, BatchEntry> | null;
        if (map) this.primed = map;
      }
    } catch {
      /* best-effort — treat as cold */
    }
  }

  /**
   * Per-provider lookup against the primed batch. Returns the cached result
   * (with `cached: true`) when present and unexpired, else null. No subrequest.
   * Caller must have awaited `primeBatch` first.
   */
  getBatched(provider: string): ProviderResult | null {
    const now = Math.floor(Date.now() / 1000);
    const entry = this.primed?.[provider];
    if (entry && entry.exp > now) return { ...entry.r, cached: true };
    return null;
  }

  /** Queue a fresh provider result for the next `flushBatch`. No subrequest. */
  stageBatched(provider: string, indicator: Indicator, data: ProviderResult): void {
    const ttl = ProviderCache.ttlSeconds(indicator.type, provider);
    this.staged[provider] = { r: data, exp: Math.floor(Date.now() / 1000) + ttl };
  }

  /**
   * Write the merged batch (still-valid primed entries + freshly staged
   * ones) back to the per-colo Cache API in a single put. The cache
   * entry's TTL tracks the longest-lived entry so storage is bounded;
   * per-entry `exp` gates reads. Note: this is intentionally Cache-API
   * only, not KV — see the primeBatch comment for why the batched mode
   * avoids KV entirely.
   */
  async flushBatch(indicator: Indicator): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const merged: Record<string, BatchEntry> = {};
    for (const [p, e] of Object.entries(this.primed ?? {})) {
      if (e.exp > now) merged[p] = e;
    }
    Object.assign(merged, this.staged);
    const entries = Object.values(merged);
    if (entries.length === 0) return;
    const maxExp = entries.reduce((m, e) => Math.max(m, e.exp), now);
    const ttl = Math.max(60, maxExp - now);
    try {
      // Cache API instead of KV — per-colo, free, no KV-write quota cost.
      const res = new Response(JSON.stringify(merged), {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttl}` },
      });
      await CACHE_PLATFORM.default.put(this.batchCacheReq(indicator), res);
    } catch {
      /* best-effort — a cache write failure shouldn't break the request */
    }
  }
}
