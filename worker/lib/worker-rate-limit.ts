/**
 * Cache-API-based rate limiter for worker-level routes that bypass the Hono
 * middleware chain (MCP, OG images, ARGUS proxy, WebSockets, etc.).
 *
 * Uses the Cloudflare Cache API (per-colo, no KV quota) with a fixed-window
 * counter. Each bucket is keyed by (namespace, identifier, window). The
 * counter is stored as a small Response body so it participates in the
 * same cache eviction semantics as any other cached asset.
 *
 * Trade-off: per-colo, eventually-consistent — the effective limit is
 * ~limit per edge location. Adequate for abuse prevention on public/keyed
 * worker routes where the Hono per-IP limiter doesn't run.
 */

export interface WorkerRateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetSeconds: number;
}

const WINDOW_SEC = 60;

function windowBucket(nowMs: number): number {
  return Math.floor(nowMs / (WINDOW_SEC * 1000));
}

/**
 * Check and increment a fixed-window counter in the Cache API.
 *
 * @param namespace - short prefix grouping related routes (e.g. "mcp", "og")
 * @param identifier - per-caller key (IP, API key hash, etc.)
 * @param limit - max requests per window
 */
export async function workerRateLimit(
  namespace: string,
  identifier: string,
  limit: number
): Promise<WorkerRateLimitResult> {
  const now = Date.now();
  const bucket = windowBucket(now);
  const resetAt = (bucket + 1) * WINDOW_SEC * 1000;
  const resetSeconds = Math.max(1, Math.ceil((resetAt - now) / 1000));

  const cacheKey = new Request(`https://worker-rl.internal/${namespace}/${identifier}/${bucket}`);

  try {
    const cached = await caches.default.match(cacheKey);
    let count = 0;
    if (cached) {
      const body = await cached.text();
      count = parseInt(body, 10) || 0;
    }

    count++;
    const allowed = count <= limit;

    const entry = new Response(String(count), {
      headers: {
        'content-type': 'text/plain',
        'cache-control': `private, max-age=${WINDOW_SEC + 5}`,
      },
    });
    // Await so the incremented counter is durable before the next request in
    // this colo reads it; otherwise concurrent requests all see count 0.
    try {
      await caches.default.put(cacheKey, entry);
    } catch {
      /* best-effort */
    }

    return { allowed, remaining: Math.max(0, limit - count), limit, resetSeconds };
  } catch {
    // Cache-API failure — fail open (allow) rather than blocking all traffic.
    return { allowed: true, remaining: limit, limit, resetSeconds };
  }
}

/** Build a 429 response with standard rate-limit headers. */
export function rateLimitResponse(result: WorkerRateLimitResult): Response {
  return new Response(JSON.stringify({ error: 'rate limit exceeded', retry_after: result.resetSeconds }), {
    status: 429,
    headers: {
      'content-type': 'application/json',
      'retry-after': String(result.resetSeconds),
      'x-ratelimit-limit': String(result.limit),
      'x-ratelimit-remaining': String(result.remaining),
      'x-ratelimit-reset': String(result.resetSeconds),
    },
  });
}

/** Extract the caller IP from CF headers. */
export function callerIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'anon';
}
