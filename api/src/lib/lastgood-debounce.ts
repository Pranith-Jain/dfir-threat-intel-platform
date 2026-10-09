/**
 * Debounce KV `lastgood` writes so we burn write quota only when needed.
 *
 * Each "lastgood" fallback (phishing-urls, malicious-packages, live-iocs,
 * cybercrime, deepdarkcti) used to call `kv.put` on every cache-miss-success
 * — which on a moderate-traffic colo can fire dozens of times a day even
 * though the underlying upstream data changes much more slowly. The KV
 * write is only useful as a stale fallback during upstream outages; a
 * lastgood refreshed in the last few hours is plenty.
 *
 * This helper records a tiny "wrote recently" marker in `caches.default`
 * (per-colo, free, no KV cost) with a configurable TTL. Callers check
 * `shouldWriteLastGood(name)` before issuing a KV put — if the marker is
 * still hot we skip the write entirely. On a cold marker we return true
 * AND write the marker so the next caller skips for `ttlSeconds`.
 *
 * The downside is that an unlucky colo that's served by a single visitor
 * an hour will only ever refresh lastgood once per `ttlSeconds`. That's
 * acceptable — KV is cross-colo durable, so a successful write in any
 * colo benefits every reader.
 */

const DEFAULT_DEBOUNCE_TTL_SECONDS = 6 * 60 * 60; // 6 hours

/**
 * The Cache API, or null when the runtime doesn't provide one.
 *
 * Dereferencing `caches.default` unguarded threw before the `try` below could
 * catch it, so a runtime without the Cache API turned ~20 call sites — lastgood
 * writes across the IOC, CVE, matrix and radar routes — from "writes a little
 * more often" into "throws". The debounce is a KV-quota optimisation; losing it
 * must cost writes, not availability.
 */
function cacheApi(): Cache | null {
  try {
    return (caches as unknown as { default?: Cache }).default ?? null;
  } catch {
    return null;
  }
}

export async function shouldWriteLastGood(
  name: string,
  ttlSeconds: number = DEFAULT_DEBOUNCE_TTL_SECONDS
): Promise<boolean> {
  const cache = cacheApi();
  // No Cache API — nothing to debounce against. Fail open: the caller performs
  // the write, which is exactly the pre-cache behaviour.
  if (!cache) return true;
  const key = new Request(`https://lastgood-debounce.internal/v1/${encodeURIComponent(name)}`);
  try {
    const hit = await cache.match(key);
    if (hit) return false;
    // Write the debounce marker BEFORE returning true so a parallel
    // request landing in the same window also short-circuits. Empty
    // body — only the presence and TTL matter.
    await cache.put(
      key,
      new Response('1', {
        headers: { 'cache-control': `max-age=${ttlSeconds}` },
      })
    );
    return true;
  } catch {
    // Cache transient error — fail OPEN (let the write through). The
    // worst case here is the original behaviour: more frequent KV
    // writes. The best case is the marker just gets re-set on the
    // next call. Either way no data is lost.
    return true;
  }
}
