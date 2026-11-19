/**
 * Upstash Redis REST adapter for Global Pulse cache/warm state.
 *
 * The Worker runs on Cloudflare, but cached data does not have to live in
 * Cloudflare KV. KV's free tier allows 1,000 writes/day, which the hourly
 * warm fan-out plus per-build response writes routinely exceeded. Upstash's
 * permanent free tier is 250 MB / 500k commands per month with a REST API that
 * works from Workers (no TCP), plus native TTLs and MGET for batched reads.
 *
 * Every helper is best-effort and never throws: when either secret is missing
 * the call returns null/false and callers keep their existing fallback path.
 * That makes the switchover a secrets-only change, not a coordinated deploy.
 *
 * Secrets: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
 */

export interface UpstashEnv {
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
}

export function upstashConfigured(env: UpstashEnv | undefined): boolean {
  return !!(env?.UPSTASH_REDIS_REST_URL && env?.UPSTASH_REDIS_REST_TOKEN);
}

async function cmd<T>(env: UpstashEnv | undefined, parts: unknown[]): Promise<T | null> {
  if (!upstashConfigured(env)) return null;
  try {
    const res = await fetch(env!.UPSTASH_REDIS_REST_URL!, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${env!.UPSTASH_REDIS_REST_TOKEN}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(parts),
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { result?: T; error?: string };
    if (body.error) return null;
    return body.result ?? null;
  } catch {
    return null;
  }
}

/** GET one key. Null means miss, unconfigured, or a transient error. */
export async function upstashGet(env: UpstashEnv | undefined, key: string): Promise<string | null> {
  const value = await cmd<unknown>(env, ['GET', key]);
  return typeof value === 'string' ? value : null;
}

/** SET with TTL in seconds. Returns true only when Upstash is configured and accepted the write. */
export async function upstashSet(
  env: UpstashEnv | undefined,
  key: string,
  value: string,
  ttlSeconds: number
): Promise<boolean> {
  const ttl = Math.max(1, Math.floor(ttlSeconds));
  const result = await cmd<string>(env, ['SET', key, value, 'EX', ttl]);
  return result === 'OK';
}

/**
 * MGET many keys in one REST call (one Upstash command). The returned map
 * contains only keys that had a string value.
 */
export async function upstashMGet(env: UpstashEnv | undefined, keys: readonly string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (keys.length === 0) return out;
  const result = await cmd<unknown[]>(env, ['MGET', ...keys]);
  if (!Array.isArray(result)) return out;
  keys.forEach((key, i) => {
    const value = result[i];
    if (typeof value === 'string') out.set(key, value);
  });
  return out;
}
