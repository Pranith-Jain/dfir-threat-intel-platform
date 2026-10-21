import { injectScriptNonce } from './csp';
import { getOrInjectOg, injectOgMeta } from './og-rewriter';
// The prerendered-route map lives in worker/prerender-routes.ts (an
// import-free leaf module) so worker/og-rewriter.ts can consume the same
// list without creating an import cycle back through this file.
import { PRERENDERED_ROUTES } from './prerender-routes';
import type { Env } from './env';
import type { Surface } from './surface';

/**
 * Prerendered-route serving: see worker/prerender-routes.ts for the route
 * list and its slug rules; see fetchPrerenderedOrShell below for how the
 * files are served and OG-rewritten.
 */

export { PRERENDERED_ROUTES };

/**
 * Dynamic route patterns that should fall back to a parent page's
 * prerendered HTML. The client-side React Router handles the dynamic
 * parameter (e.g. :slug), but the Worker still has to serve real HTML
 * (not the empty SPA shell) so the page chrome paints before hydration
 * and the URL the user sees matches the actual content.
 *
 * Each entry: [regex matching the dynamic path, prerendered parent to
 * serve]. Patterns are case-insensitive because some slugs contain
 * uppercase letters — notably the ISO-week label in weekly briefings
 * (`weekly-2026-W22` from isoYearWeek() in api/src/lib/briefing-builder.ts),
 * but also actor handles and other identifiers that may mix case.
 *
 * Regression note: this table was originally added to worker/index.ts
 * in commit 743be0a ("fix: handle dynamic routes with fallback to
 * parent prerendered pages") and was lost when commit f921102 split
 * the worker into modules. The original patterns used `[a-z0-9-]+`
 * which never matched the uppercase `W` in weekly slugs, so even with
 * the table restored, `weekly-2026-W22` would still have shell-served.
 * Patterns below use `/i` to cover that case.
 *
 * The slug here is intentionally permissive (any non-empty path
 * segment) so future dynamic routes added to App.tsx don't need a
 * worker change to render — just an entry in PRERENDERED_ROUTES for
 * the parent and a slug-aware React Router <Route>.
 */
/**
 * The SPA shell's empty root div.
 *
 * Used to tell a real prerendered page apart from the shell that ASSETS
 * returns for a missing asset (`not_found_handling: "single-page-application"`
 * answers a miss with the shell and a 200, not a 404). A prerendered page
 * has content inside the root div; the shell does not.
 */
const EMPTY_ROOT_MARKER = '<div id="root"></div>';

const DYNAMIC_ROUTE_FALLBACKS: ReadonlyArray<[RegExp, string]> = [
  // ── ThreatIntel: category filter on the home (legacy) ─────────
  [/^\/threatintel\/c\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  // ── ThreatIntel: unknown sub-slugs (slug-aware routes) ─────────
  // Briefings detail pages intentionally do NOT fall back to the index
  // prerender: the index DOM (skeleton list, filter pills, aria-current on
  // Briefings) and the detail DOM (executive summary, findings, IOCs) are
  // completely different trees. React 18's hydration mismatch handler leaves
  // the SSR'd DOM in place and only logs a warning, so the user would see
  // the index skeleton forever. Serve the empty SPA shell instead — the
  // client hydrates clean and the detail component takes over.
  [/^\/threatintel\/wiki\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/actors\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/campaigns\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/research\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/infostealer\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/assessments\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  // ── Blog ───────────────────────────────────────────────────────
  [/^\/blog\/c\/[^/]+$/i, '/__prerendered/blog'],
  [/^\/blog\/t\/[^/]+$/i, '/__prerendered/blog'],
  [/^\/blog\/[^/]+$/i, '/__prerendered/blog'],
  // ── Projects ───────────────────────────────────────────────────
  [/^\/projects\/[^/]+$/i, '/__prerendered/projects'],
  // ── Anarchy: per-course deep links fall back to the /anarchy prerender;
  // the client opens the matching course modal from the :id param.
  [/^\/anarchy\/c\/[^/]+$/i, '/__prerendered/anarchy'],
  // ── DFIR tools category ────────────────────────────────────────
  [/^\/dfir\/tools\/[^/]+$/i, '/__prerendered/dfir__catalog'],
  // ── ThreatIntel: hub tab routes (14) — fall back to catalog ──
  // The catalog at /threatintel/catalog is the single navigation surface;
  // unknown sub-slugs in any hub render the catalog so the user can
  // browse to the correct page.
  [/^\/threatintel\/iocs\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  // NOTE: /threatintel/cves/<id> is deliberately absent, though its sibling
  // hub tabs are above. `App.tsx` routes `/threatintel/cves/:cveId` to
  // CveDetail — a per-CVE *detail* page — so serving it the catalog prerender
  // returned catalog HTML at a CVE URL, and the client then hydrated
  // CveDetail over it. Its twin `/threatintel/cve/:id` never had a fallback
  // and correctly fell through to the SPA shell; the two paths rendering the
  // same component were getting different SSR. Both now take the shell.
  [/^\/threatintel\/malware\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/feeds\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/social\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/phishing\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/infra\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/detections\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/research-hub\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/osint\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/tools\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/external\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/predictive\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
  [/^\/threatintel\/darkweb\/[^/]+$/i, '/__prerendered/threatintel__catalog'],
];

function resolveDynamicRoute(pathname: string): string | null {
  // Skip static assets (images, fonts, JS, CSS, etc.) — none of the
  // dynamic route patterns would match a file extension anyway, and
  // testing ~38 regexes per asset request adds needless CPU.
  if (pathname.includes('.')) return null;
  for (const [pattern, fallback] of DYNAMIC_ROUTE_FALLBACKS) {
    if (pattern.test(pathname)) {
      return fallback;
    }
  }
  return null;
}

export async function fetchPrerenderedOrShell(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL,
  nonce: string,
  surface: Surface = 'portfolio'
): Promise<Response> {
  // Try exact match first; fall back to a dynamic-route parent if the
  // exact path isn't a prerendered page.
  const prerenderedPath = PRERENDERED_ROUTES.get(url.pathname) ?? resolveDynamicRoute(url.pathname);
  if (!prerenderedPath) {
    const r = await getOrInjectOg(request, env, ctx, url);
    // Pass through non-HTML assets (images, fonts, WASM, JSON) as-is.
    // Calling r.text() on binary data would decode bytes as UTF-8 and
    // corrupt them — PNGs, WASM, and fonts contain non-UTF-8 byte
    // sequences that get replaced with U+FFFD.
    const ct = r.headers.get('content-type') ?? '';
    if (!ct.toLowerCase().includes('text/html')) return r;
    const body = injectScriptNonce(await r.text(), nonce);
    const h = new Headers(r.headers);
    h.set('x-ssr-source', 'spa-shell');
    // SPA shell references content-hashed JS/CSS chunks that are safe
    // to cache immutably, but the shell HTML itself must refresh on
    // every deploy so users pick up new lazy chunks (e.g. a new
    // NotFound page, the React Router table). Use no-cache (not no-store)
    // to force revalidation on every load while still allowing the page
    // into the back/forward cache - no-store blocks bfcache restoration.
    h.set('cache-control', 'no-cache, must-revalidate');
    h.set('pragma', 'no-cache');
    return new Response(body, { status: r.status, statusText: r.statusText, headers: h });
  }
  // Surface-aware lookup: the tools surface keeps its own prerendered tree
  // for routes whose HTML actually differs (portfolio chrome + the "/" landing
  // page). AppShell routes render identical markup on both surfaces and were
  // never written to the tools tree, so a 404 there falls through to the
  // portfolio file instead of dropping to the bare SPA shell.
  const candidatePaths =
    surface === 'tools'
      ? [prerenderedPath.replace('/__prerendered/', '/__prerendered-tools/'), prerenderedPath]
      : [prerenderedPath];

  let prerenderRes: Response | null = null;
  for (const candidate of candidatePaths) {
    const internal = new URL(request.url);
    internal.pathname = candidate;
    const r = await env.ASSETS.fetch(new Request(internal.toString(), request));
    if (r.status === 404) continue;
    const ct = r.headers.get('content-type') ?? '';
    if (!ct.toLowerCase().includes('text/html')) {
      prerenderRes = r;
      break;
    }
    // ASSETS runs with `not_found_handling: "single-page-application"`, so a
    // MISSING asset comes back as the SPA shell with a 200 — NOT a 404. The
    // status check above therefore cannot tell "found the prerender" from
    // "fell back to the shell", and on the tools surface the tools-tree
    // candidate (which deliberately does not carry AppShell routes) won that
    // comparison. Every /threatintel and /dfir page was serving the empty
    // shell instead of its prerendered HTML — the prerender pipeline was
    // dead on all seven tools hosts, which is where the threat-intel platform
    // actually lives.
    //
    // The shell's root div is empty; a prerendered page's is not. That is the
    // same marker scripts/prerender.mjs uses to detect drift, so comparing
    // against it is consistent with the build side.
    const html = await r.text();
    if (html.includes(EMPTY_ROOT_MARKER)) continue;
    prerenderRes = new Response(html, {
      status: r.status,
      statusText: r.statusText,
      headers: r.headers,
    });
    break;
  }
  if (!prerenderRes) {
    const r = await getOrInjectOg(request, env, ctx, url);
    const ct = r.headers.get('content-type') ?? '';
    if (!ct.toLowerCase().includes('text/html')) return r;
    const body = injectScriptNonce(await r.text(), nonce);
    const h = new Headers(r.headers);
    h.set('x-ssr-source', 'shell-fallback-404');
    // no-cache forces revalidation (fresh shell on every load) without
    // blocking back/forward cache restoration the way no-store does.
    h.set('cache-control', 'no-cache, must-revalidate');
    h.set('pragma', 'no-cache');
    return new Response(body, { status: r.status, statusText: r.statusText, headers: h });
  }
  const ogRewritten = await injectOgMeta(prerenderRes, url, env, ctx, nonce);
  const headers = new Headers(ogRewritten.headers);
  // A prerendered shell references the same content-hashed JS/CSS chunks as
  // the SPA shell, and those chunk filenames change (and the old ones are
  // deleted) on every deploy. Caching this HTML in the *browser* for a day
  // means a returning visitor serves a stale shell that imports a now-404'd
  // lazy chunk → the app crashes into the "Update available" boundary. So it
  // must revalidate on every load, exactly like the SPA-shell and 404 paths
  // above. The worker's own etag-keyed Cache API entry (see injectOgMeta)
  // is unaffected by this header, so server-side hit rate is preserved.
  headers.set('x-ssr-source', 'prerendered');
  // no-cache forces revalidation on every load (fresh shell, same as
  // before) while allowing bfcache - no-store would block back/forward
  // restoration for no freshness benefit.
  headers.set('cache-control', 'no-cache, must-revalidate');
  headers.set('pragma', 'no-cache');
  return new Response(ogRewritten.body, {
    status: ogRewritten.status,
    statusText: ogRewritten.statusText,
    headers,
  });
}
