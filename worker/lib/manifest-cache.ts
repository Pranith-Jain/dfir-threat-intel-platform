/**
 * Shared cache + asset-fetch primitives for the manifest loaders.
 *
 * The `worker/lib/*-manifest.ts` family each grew their own copy of the same
 * three helpers. Normalizing every function body across the tree showed:
 *
 *   - `BodyCache<T>`      1 distinct shape  x 20 files (byte-identical)
 *   - `trackHit<T>`       3 distinct shapes x 20 files (18 canonical)
 *   - `recordHit<T>`      4 distinct shapes x 20 files (17 canonical;
 *                         the rest differ only in their MAX_* constant name)
 *   - `fetchJson<T>`      6 distinct shapes x 41 files (36 canonical,
 *                         differing only in the asset host string)
 *
 * The non-canonical copies were behaviour-preserving variants — one-line
 * reformats, a comment, or a differently-named capacity constant — so they are
 * folded in here rather than kept as separate code paths.
 *
 * Deliberately NOT abstracted:
 *   - `detection-wiki-manifest`'s `fetchJson` (Cache API tier + SPA-shell
 *     content-type guard), `flowviz`'s (throws instead of returning null),
 *     `si`'s and `threat-monitor`'s. They are genuinely different behaviour.
 *   - the `cachedIndex` + `forceRefresh` loader blocks. They are similar but
 *     each carries its own error message and types; a factory there would
 *     obscure the per-manifest failure text that operators rely on.
 */

/** Insertion-ordered LRU cache with hit/miss counters. */
export interface BodyCache<T> {
  map: Map<string, T>;
  hits: number;
  misses: number;
}

/**
 * Look up `key`, refreshing its recency on hit.
 * Returns undefined and increments `misses` when absent.
 */
export function trackHit<T>(cache: BodyCache<T>, key: string): T | undefined {
  const v = cache.map.get(key);
  if (v === undefined) {
    cache.misses += 1;
    return undefined;
  }
  cache.hits += 1;
  cache.map.delete(key);
  cache.map.set(key, v);
  return v;
}

/**
 * Insert `value`, refreshing recency if the key already exists, then evict
 * oldest-first until the map is back within `max` entries.
 *
 * `max` is a parameter rather than a module constant because the original
 * per-file `MAX_BODY_CACHE` / `MAX_CACHE` / `MAX_CATEGORY_CACHE` values range
 * from 20 to 200 and each manifest sized its own caches deliberately.
 */
export function recordHit<T>(cache: BodyCache<T>, key: string, value: T, max: number): T {
  // Refresh insertion order so LRU eviction works correctly.
  if (cache.map.has(key)) cache.map.delete(key);
  cache.map.set(key, value);
  while (cache.map.size > max) {
    const oldest = cache.map.keys().next().value;
    if (oldest === undefined) break;
    cache.map.delete(oldest);
  }
  return value;
}

/**
 * Fetch and parse a JSON asset, returning null on any non-ok response.
 *
 * `host` is only used as the request origin: `env.ASSETS` ignores the Host
 * header and serves from the bundled static dir, so any absolute URL resolves
 * the same asset. Each manifest keeps its own conventional host
 * (`https://<name>.local`) for readable cache keys.
 */
export async function fetchJsonAsset<T>(assets: Fetcher, path: string, host: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`${host}${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}
