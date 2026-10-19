/**
 * Build the CSP value. When `nonce` is provided (HTML responses only),
 * `script-src` uses nonce-based enforcement — the one inline `<script>`
 * in index.html (the theme-flash preventer) gets a matching `nonce`
 * attribute injected, and every other inline script (i.e. anything an
 * attacker manages to inject) is blocked.
 *
 * `'unsafe-inline'` is NOT included in `script-src` for HTML responses.
 * Per the CSP spec, when both a nonce and `'unsafe-inline'` are present,
 * the nonce is ignored — `'unsafe-inline'` takes precedence, allowing
 * any inline script to execute and completely negating the nonce defense.
 *
 * `style-src 'unsafe-inline'` is retained because React components ship
 * inline `style={...}` attributes throughout the SPA — removing it would
 * require a much bigger refactor (CSS-in-JS extraction, no inline style
 * props) than the threat warrants given XSS is multi-layer-blocked
 * (server regex sanitiser → client DOMPurify → blocked by script-src).
 */
// NOTE: script-src does NOT include 'unsafe-inline'. API responses are JSON or
// server-built HTML (briefing print, RSS, OG image) that never need inline
// scripts, so disallowing them means an injected inline <script> cannot execute
// even if an output-escaping gap is reintroduced (defence-in-depth for CSP-1).
const CSP_REPORT_URI = 'https://pranithjain.qzz.io/api/v1/csp-report';
const CSP_API = `default-src 'self';script-src 'self' 'wasm-unsafe-eval' https://static.cloudflareinsights.com;style-src 'self' 'unsafe-inline';img-src 'self' data: https:;connect-src 'self' https://api.cloudflare.com https://cloudflare-dns.com https://cloudflareinsights.com https://*.cloudflareinsights.com wss://pranithjain.qzz.io;frame-src 'none';font-src 'self' data:;frame-ancestors 'none';base-uri 'self';form-action 'self';object-src 'none';report-uri ${CSP_REPORT_URI}`;

export function cspHeader(nonce?: string, origin?: string): string {
  const s = origin ?? "'self'";
  if (!nonce) return CSP_API.replace(/'self'/g, s);
  return [
    `default-src ${s}`,
    // Nonce-based script-src: only the theme-flash preventer (matching nonce)
    // and external module scripts (by source) can execute. Inline event handlers
    // (onload/onerror) are not needed — the font <link> uses media="all" and
    // no other inline handlers exist. This is critical: 'unsafe-inline' alongside
    // a nonce causes the nonce to be IGNORED per the CSP spec.
    `script-src ${s} 'nonce-${nonce}' 'wasm-unsafe-eval' https://static.cloudflareinsights.com`,
    `style-src ${s} 'unsafe-inline'`,
    `img-src ${s} data: https:`,
    `connect-src ${s} https://api.cloudflare.com https://cloudflare-dns.com https://cloudflareinsights.com https://*.cloudflareinsights.com https://unpkg.com https://mr-akuma.github.io https://nominatim.openstreetmap.org https://goxdr.fyi https://mr-r3b00t.github.io wss://pranithjain.qzz.io`,
    `font-src ${s} data:`,
    "frame-ancestors 'none'",
    `base-uri ${s}`,
    `form-action ${s}`,
    "object-src 'none'",
    `report-uri ${CSP_REPORT_URI}`,
  ].join(';');
}

export function withSecurityHeaders(response: Response, nonce?: string, origin?: string): Response {
  // ASSETS binding returns responses with immutable headers. Clone into
  // a mutable Headers object so we can add CSP and other security headers.
  const h = new Headers(response.headers);
  const ct = (h.get('content-type') ?? '').toLowerCase();

  // Image responses (OG cards, OG PNGs, blog illustrations) must NOT carry
  // CSP / X-Frame-Options / frame-ancestors. Social platforms (X/Twitter,
  // LinkedIn, Facebook, Slack) fetch the twitter:image / og:image URL to
  // render a preview card; restrictive security headers on the image
  // response cause their validators to reject the image and show no
  // preview. Images can't execute scripts, so CSP adds no protection here.
  const isImage = ct.startsWith('image/');
  if (isImage) {
    h.set('x-content-type-options', 'nosniff');
    h.set('referrer-policy', 'strict-origin-when-cross-origin');
    h.set('strict-transport-security', 'max-age=63072000; includeSubDomains; preload');
    // Images must not carry framing/CSP headers — see comment above.
    h.delete('x-frame-options');
    h.delete('content-security-policy');
    h.delete('cross-origin-opener-policy');
    h.delete('server');
    const status = response.status;
    const bodyless = status === 101 || status === 204 || status === 205 || status === 304;
    return new Response(bodyless ? null : response.body, {
      status,
      statusText: response.statusText,
      headers: h,
    });
  }

  h.set('content-security-policy', cspHeader(nonce, origin));
  // Always override security headers with canonical secure values.
  // Previous behavior checked has() first, which allowed a misconfigured
  // upstream (ARGUS proxy, DO response) to pass through weakened headers.
  h.set('x-content-type-options', 'nosniff');
  h.set('x-frame-options', 'DENY');
  h.set('referrer-policy', 'strict-origin-when-cross-origin');
  h.set('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  h.set('strict-transport-security', 'max-age=63072000; includeSubDomains; preload');
  h.set('cross-origin-opener-policy', 'same-origin');
  // COEP require-corp removed: it blocks cross-origin map tiles (CARTO, OSM)
  // that lack Cross-Origin-Resource-Policy headers. Nothing in this app
  // requires SharedArrayBuffer or needs COEP enforcement.
  // Remove the default Cloudflare server header but don't replace it with
  // a custom value — no need to advertise the server identity.
  h.delete('server');
  // Bodyless statuses (101 switching-protocols, 204/205/304) are defined to
  // carry a null body — passing response.body for one throws RangeError. The
  // current call graph never emits these here, but guarding keeps
  // withSecurityHeaders total in case a route later adds ETag/304 support.
  const status = response.status;
  const bodyless = status === 101 || status === 204 || status === 205 || status === 304;
  return new Response(bodyless ? null : response.body, {
    status,
    statusText: response.statusText,
    headers: h,
  });
}

/**
 * Generate a CSP nonce. 128 random bits → base64url-encoded (≈22 chars).
 * Single-pass: no intermediate strings from chained replace() calls.
 */
export function generateNonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode.apply(null, b as unknown as number[])).replace(/[=+/]/g, (c) =>
    c === '=' ? '' : c === '+' ? '-' : '_'
  );
}

/**
 * Inject `nonce="…"` into the one inline `<script>` in our index.html
 * (the theme-flash preventer). External scripts (`<script type="module"
 * crossorigin src="…">`) don't need a nonce — they're covered by
 * `script-src 'self'`. Matching `<script>` with no attributes scopes
 * the rewrite to the inline tag only. Idempotent (the cache stores the
 * nonce-less HTML; this runs per request).
 */
export function injectScriptNonce(html: string, nonce: string): string {
  return html.replace(/<script>/g, `<script nonce="${nonce}">`);
}
