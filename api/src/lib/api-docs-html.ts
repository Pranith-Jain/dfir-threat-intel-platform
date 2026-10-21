/**
 * Static HTML for the Scalar-mounted OpenAPI browser at /api/docs.
 *
 * Scalar is a fast, lightweight alternative to Swagger UI. The browser
 * fetches the spec from /api/v1/openapi.json at mount time, so the
 * page stays in sync with the live spec without a rebuild.
 *
 * Why inline the HTML rather than read from /public at request time?
 *   - Workers runtime has no filesystem access; static assets come
 *     from the ASSETS binding, not from a relative path.
 *   - Inlining guarantees the page is served even if the asset
 *     pipeline misses a file.
 *   - It's a 1.5 KB string; bundle cost is negligible.
 *
 * CSP note: Scalar's standalone bundle is loaded from a CDN. The
 * worker CSP needs to allow `cdn.jsdelivr.net` for the script tag,
 * and the page is served as HTML so the `text/html` MIME type is
 * what browsers expect.
 */
export const API_DOCS_HTML = /* html */ `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DFIR + Threat Intel API docs</title>
  <meta name="description" content="Live, browsable OpenAPI 3.1 spec for the DFIR and threat-intel platform API: IOC check, CVE/KEV, actor enrichment, domain intelligence, ransomware monitoring, briefings, and more." />
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <link rel="canonical" href="https://pranithjain.qzz.io/api/docs" />
  <style>
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .banner { max-width: 1200px; margin: 0 auto; padding: 18px 24px 0; }
    .banner h1 { font-size: 22px; margin: 0 0 6px; color: #0f172a; }
    .banner p { margin: 0 0 8px; color: #475569; font-size: 14px; }
    .banner a { color: #0e7490; }
    .dark .banner h1, .dark .banner p { color: #e2e8f0; }
  </style>
</head>
<body>
  <div class="banner">
    <h1>DFIR &amp; Threat Intel API</h1>
    <p>
      Live, browsable OpenAPI 3.1 spec.
      <a href="/mcp">MCP server (426 tools)</a> &middot;
      <a href="/api/v1/openapi.json" download>Download spec</a> &middot;
      <a href="/api/v1/health">Health</a>
    </p>
  </div>
  <script
    id="api-reference"
    type="application/json"
    data-url="/api/v1/openapi.json"
  ></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.x.x/dist/browser/standalone.min.js"></script>
</body>
</html>
`;
