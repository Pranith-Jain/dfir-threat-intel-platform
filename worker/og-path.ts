/**
 * Pure OG-image route parsing — deliberately import-free so it can be unit
 * tested (and imported by data/loader code) WITHOUT pulling in og-raster, which
 * statically imports the resvg wasm module (that import is not loadable in a
 * Node/vitest environment).
 *
 * Two card URL shapes:
 *   - Entity cards:  /api/v1/og-image/(briefing|blog)/<slug>.png
 *                    data-driven from D1 / KV (one card per briefing / post).
 *   - Page cards:    /api/v1/og-image/page/<dot-encoded-path>.png
 *                    generated for ANY route so every URL has a unique card.
 *                    The route path is dot-encoded (slashes → dots, so
 *                    /dfir/cve → "dfir.cve") and embedded in the URL PATH.
 *                    Percent-encoded (`%2F`) and query (`?p=`) forms were
 *                    both tried and FAILED on X/Twitter: its card parser
 *                    decodes `%2F` when re-fetching the image and hits a
 *                    404, while query-string image URLs are dropped
 *                    outright — in both cases the card renders as a chip
 *                    with no image. The legacy forms are still accepted
 *                    for already-cached meta.
 *
 *                    Page cards are KV-backed build-time renders: the URL
 *                    emitted is /og-image/v<BUILD>/page/<dot>.png (version
 *                    bumps per deploy so X re-crawls fresh image URLs);
 *                    worker/og-route.ts strips the prefix and serves the
 *                    pre-rendered PNG from KV (ogpage:v1:<dot>.png).
 */
// Tiny generated constant (no wasm) — safe despite this module otherwise
// staying import-free.
import { OG_BUILD_VERSION } from './og-version.generated';

// Shared-report cards: slug is a 32-hex capability token — same charset
// as the generic slug rule but semantically distinct (D1 lookup by token).
// The optional /v<ver> segment matches the versioned alias emitted by
// pageCardUrl() (worker/index.ts maps it to this legacy prefix, but the
// version segment survives the rewrite and must be tolerated here too).
const OG_ROUTE_RE = /^\/api\/v1\/og-image\/(?:v[a-z0-9]+\/)?(briefing|blog|report)\/([a-z0-9][a-z0-9-]{0,199})\.png$/i;

/** Pathname of the generic per-page card endpoint (legacy query form). */
export const OG_PAGE_PATH = '/api/v1/og-image/page.png';

/** Path prefix of the dot-encoded per-page card endpoint (legacy, unversioned). */
export const OG_PAGE_PREFIX = '/api/v1/og-image/page/';

const OG_PAGE_DOT_RE =
  /^\/(?:api\/v1\/)?og-image(?:\/v[a-z0-9]+)?\/page\/([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*)\.png$/i;

export type OgImageType = 'briefing' | 'blog' | 'page' | 'report';

/** Parse `/api/v1/og-image/:type/:slug.png` into its parts, or null if the
 *  path is not a valid entity-card OG-image request. */
export function matchOgImagePath(pathname: string): { type: 'briefing' | 'blog' | 'report'; slug: string } | null {
  const m = OG_ROUTE_RE.exec(pathname);
  if (!m) return null;
  return { type: m[1]!.toLowerCase() as 'briefing' | 'blog' | 'report', slug: m[2]! };
}

/** Parse the generic page-card endpoint. Returns the decoded route path the
 *  card should represent (e.g. "/dfir/cve"), or null when the URL is not a
 *  valid page-card request. Rejects empty paths and anything that isn't a
 *  site-relative path starting with "/". */
export function matchOgPagePath(url: URL): string | null {
  // Legacy static-form URLs first: /og/pages/<dot>.png — emitted by
  // pageCardUrl() during an intermediate deploy. Cards are rasterized into
  // .og-cache/pages/ and uploaded to Workers KV (key prefix ogpage:v1:) by
  // scripts/upload-page-og.mjs; served KV-first from worker/og-route.ts.
  const sm = /^\/og\/pages\/([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*)\.png$/i.exec(url.pathname);
  if (sm) return `/${sm[1]!.replace(/\./g, '/')}`;
  // Versioned dynamic form: /og-image/v<build>/page/<dot>.png — emitted by
  // earlier deploys; still resolves through the dynamic rasterizer.
  const vm = /^\/og-image\/v[a-z0-9]+\/page\/([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*)\.png$/i.exec(url.pathname);
  if (vm) return `/${vm[1]!.replace(/\./g, '/')}`;
  // Legacy `?p=` form first — `/page.png` is the exact legacy pathname and
  // also matches the dot-form regex below, so it must win before that.
  if (url.pathname === OG_PAGE_PATH) {
    const p = url.searchParams.get('p');
    if (!p) return null;
    if (!p.startsWith('/') || p.length > 200) return null;
    return p;
  }
  // Preferred slash-free dot form: /api/v1/og-image/page/dfir.cve.png
  // (no encoded separators — X's parser re-encodes %2F wrongly and
  // kills the image, and it drops query-string image URLs outright).
  const dm = OG_PAGE_DOT_RE.exec(url.pathname);
  if (dm) return `/${dm[1]!.replace(/\./g, '/')}`;
  // Percent-encoded path form — accepted for meta already emitted by
  // intermediate deployments.
  const pm = /^\/api\/v1\/og-image\/page\/(.+)\.png$/i.exec(url.pathname);
  if (pm) {
    try {
      const p = decodeURIComponent(pm[1]!);
      if (p.startsWith('/') && p.length <= 200) return p;
    } catch {
      /* malformed percent-encoding → not a valid page card */
    }
    return null;
  }
  return null;
}

/** Build the page-card URL for a route path (used by the meta rewriter to set
 *  og:image / twitter:image to a unique generated card). Slash-free dot
 *  encoding: X's card parser corrupts percent-encoded slashes when it
 *  re-fetches the image, so the path must contain no encoded separators. */
export function pageCardUrl(pathname: string): string {
  const flat = pathname
    .replace(/^\/+/, '')
    .replace(/\/+/g, '.')
    .replace(/\.png$/i, '');
  // KV-backed pre-rendered card under a PER-DEPLOY VERSIONED, /api/-free
  // path: scripts/generate-page-og.mjs rasterizes every prerendered route's
  // card at build time; og:upload ships them to KV; worker/og-route.ts
  // strips the /og-image/v<ver>/ prefix and serves the PNG from KV. The
  // version segment changes each deploy so X treats every image URL as new
  // (its per-URL cache holds failures for days) and re-fetches cleanly.
  return `/og-image/${OG_BUILD_VERSION}/page/${flat}.png`;
}
