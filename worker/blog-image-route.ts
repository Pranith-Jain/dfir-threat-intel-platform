import type { Env } from './env';
import { workerRateLimit, rateLimitResponse, callerIp } from './lib/worker-rate-limit';

const SLUG_RE = /^[a-z0-9-]+$/;
const NAME_RE = /^[a-z0-9-]+$/;
const BLOG_IMG_LIMIT = 30;

// Per-colo Cache-API shadow for the immutable post images in CASE_STUDIES.
// Every <img> on a blog page used to be 1 KV read per request; the shadow
// collapses that to ~1 KV read per colo per TTL window. The images are
// content-addressed by slug+name and only regenerated on a fresh publish —
// and the served cache-control is already max-age=86400, immutable — so a
// 24h shadow (the shadow entry inherits that cache-control from the stored
// response) matches the browser/CDN freshness contract exactly. A publish
// that changes bytes under the same key self-heals within a day (same bound
// the old browser caching already imposed).
function imgShadowReq(slug: string, name: string): Request {
  return new Request(`https://blog-img-cache.internal/v1/${encodeURIComponent(slug)}/${encodeURIComponent(name)}`);
}

/**
 * Serve an AI-generated blog illustration: GET /api/v1/blog-image/:slug/:name.
 * Public (the blog is public) and handled before the /api/v1/* key-gate, like
 * the OG card route. Bytes live in CASE_STUDIES under `post-img:<slug>:<name>`.
 * Validates slug/name against a strict charset to refuse path traversal.
 */
export async function handleBlogImage(request: Request, url: URL, env: Env): Promise<Response> {
  const m = url.pathname.match(/^\/api\/v1\/blog-image\/([^/]+)\/([^/.]+)(?:\.(jpe?g|png))?$/);
  if (!m) return new Response('not found', { status: 404 });
  const slug = m[1]!;
  const name = m[2]!;
  const ext = (m[3] ?? 'jpeg').toLowerCase();
  if (slug.length > 200 || !SLUG_RE.test(slug) || !NAME_RE.test(name)) {
    return new Response('bad request', { status: 400 });
  }

  const rl = await workerRateLimit('blog-img', callerIp(request), BLOG_IMG_LIMIT);
  if (!rl.allowed) return rateLimitResponse(rl);

  // L1: per-colo Cache-API shadow (free) before the KV read.
  let cache: Cache | null = null;
  try {
    cache = (caches as unknown as { default: Cache }).default;
  } catch {
    cache = null;
  }
  const shadowReq = imgShadowReq(slug, name);
  if (cache) {
    try {
      const hit = await cache.match(shadowReq);
      if (hit) return hit;
    } catch {
      /* fall through to KV */
    }
  }

  if (!env.CASE_STUDIES) return new Response('not found', { status: 404 });
  const bytes = await env.CASE_STUDIES.get(`post-img:${slug}:${name}`, 'arrayBuffer');
  if (!bytes) return new Response('not found', { status: 404 });
  const res = new Response(bytes, {
    status: 200,
    headers: {
      'content-type': ext === 'png' ? 'image/png' : 'image/jpeg',
      // Images are content-addressed by slug+name and regenerated only on a
      // fresh publish, so a long immutable cache is safe.
      'cache-control': 'public, max-age=86400, immutable',
    },
  });
  // Write-through the L1 shadow so the next read in this colo skips KV.
  if (cache) {
    try {
      await cache.put(shadowReq, res.clone());
    } catch {
      /* best-effort shadow */
    }
  }
  return res;
}
