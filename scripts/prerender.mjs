#!/usr/bin/env node
/**
 * SSR prerender step. Runs after `vite build` + `vite build --ssr`.
 *
 * For each route in ROUTES below, imports the SSR bundle's `render(url)`,
 * generates the route's HTML, and writes it into dist/<route>/index.html.
 * Cloudflare's Assets binding then serves the prerendered HTML for that
 * route instead of the empty SPA shell — meaning users see real content
 * before React even loads.
 *
 * Client-side React still mounts: main.tsx uses hydrateRoot() (added in
 * Phase 2) which adopts the existing DOM rather than creating new nodes.
 *
 * Production: all routes in ROUTES below are prerendered to static
 * HTML during the build. The Worker serves prerendered HTML for every
 * route (fast initial paint before React hydrates); the SPA shell is
 * only used for unmatched/404 routes.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { cpus } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
// Render up to N routes in parallel. CPU-bound (React SSR walks the full
// tree + serializes), so concurrency = CPU count keeps cores saturated
// without excessive memory from 100+ concurrent render streams.
const CONCURRENCY = Math.max(1, cpus().length);

// Expanded from `/` only to all 448 routes spanning portfolio, DFIR,
// content routes. Each was verified to make 0 /api/v1/ calls on mount,
// so renderToString actually produces useful content (not data-loading
// fallback states).
//
// Phase 3.1 (2026-05-12 later same day): added live-feed pages too.
// These DO fetch on mount, so the prerendered HTML contains the page
// chrome + initial "loading…" state. useEffect is client-only so SSR
// doesn't hang on data. Win: chrome paints from HTML (instant FCP)
// rather than waiting for JS parse + React mount, and hydration matches
// the initial loading-state tree so there's no tearing.
const ROUTES = [
  // ── Portfolio ──────────────────────────────────────────────────
  '/',
  '/about',
  '/skills',
  '/experience',
  '/projects',
  '/anarchy',
  '/daily-briefs',
  '/blog',

  // ── Landings (4) ───────────────────────────────────────────────
  '/dfir',
  '/dfir/catalog',
  '/radar',
  '/threatintel',
  '/threatintel/catalog',
  '/threatintel/actors/hub',
  '/threatintel/actors/attribution',
  '/threatintel/campaigns/cross',
  '/threatintel/campaigns/reference',
  '/threatintel/cves/advisories',
  '/threatintel/cves/cves',
  '/threatintel/cves/resources',
  '/threatintel/darkweb/crime',
  '/threatintel/darkweb/deepdark',
  '/threatintel/darkweb/infostealer',
  '/threatintel/darkweb/leaks',
  '/threatintel/darkweb/markets',
  '/threatintel/ransomware-hub',
  '/threatintel/darkweb/recon',
  '/threatintel/breach-hub',
  '/threatintel/darkweb/watch',
  '/threatintel/detections/detections',
  '/threatintel/detections/disarm',
  '/threatintel/detections/signal',
  '/threatintel/detections/yara',
  '/threatintel/detection-wiki',
  '/threatintel/external/awesome',
  '/threatintel/supply-chain',
  '/threatintel/external/external',
  '/threatintel/entity-graph',
  '/threatintel/feeds/catalog',
  '/threatintel/feeds/mythreatintel',
  '/threatintel/feeds/quality',
  '/threatintel/feeds/scheduler',
  '/threatintel/feeds/sources',
  '/threatintel/feeds/threatfeeds',
  '/threatintel/infra/cloud',
  '/threatintel/infra/domain',
  '/threatintel/infra/infra',
  '/threatintel/infra/webamon',
  '/threatintel/iocs/c2',
  '/threatintel/iocs/correlation',
  '/threatintel/iocs/enrichment',
  '/threatintel/iocs/entity',
  '/threatintel/iocs/feeds',
  '/threatintel/iocs/live',
  '/threatintel/iocs/map',
  '/threatintel/malware/iocs',
  '/threatintel/malware/malpedia',
  '/threatintel/malware/maltrail',
  '/threatintel/malware/sandbox',
  '/threatintel/osint/cli',
  '/threatintel/osint/framework',
  '/threatintel/osint/map',
  '/threatintel/osint/secops',
  '/threatintel/osint/directory',
  '/threatintel/cti-bookmarks',
  '/threatintel/osint/certs',
  '/threatintel/osint/toolbox',
  '/threatintel/phishing/phish',
  '/threatintel/phishing/scam',
  '/threatintel/phishing/urls',
  '/threatintel/predictive/certstream',
  '/threatintel/predictive/dashboard',
  '/threatintel/predictive/global-pulse',
  '/threatintel/predictive/metrics',
  '/threatintel/predictive/predictions',
  '/threatintel/predictive/predictive',
  '/threatintel/predictive/threat-pulse',
  '/threatintel/research-hub/ach',
  '/threatintel/research-hub/ai',
  '/threatintel/research-hub/agentic',
  '/threatintel/research-hub/attack-flow',
  '/threatintel/flowviz',
  '/threatintel/research-hub/knowledge',
  '/threatintel/research-hub/post',
  '/threatintel/research-hub/redhunt',
  '/threatintel/research-hub/redhunt-labs',
  '/threatintel/research-hub/reports',
  '/threatintel/research-hub/signal',
  '/threatintel/research-hub/volexity',
  '/threatintel/research-hub/writeups',
  '/threatintel/social/crypto-scam',
  '/threatintel/social/firehose',
  '/threatintel/social/news',
  '/threatintel/tools/copilot',
  '/threatintel/tools/mcp',
  '/threatintel/tools/directory',
  '/threatintel/tools/darknet-intel',
  '/threatintel/tools/stix-hub',
  '/threatintel/tools/stix-bundles',
  '/threatintel/tools/unified-search',
  '/threatintel/tools/tg-intel-search',
  '/threatintel/tools/socradar-tools',
  '/threatintel/vera',
  '/threatintel/wiki/f3ead',
  '/threatintel/wiki/f2t2ea',
  '/threatintel/wiki/ooda',
  '/threatintel/wiki/kill-chain-v2',
  '/threatintel/wiki/unified-kill-chain',
  '/threatintel/wiki/insider',
  '/threatintel/wiki/llm',
  '/threatintel/wiki/mitre',
  '/threatintel/wiki/owasp',
  '/threatintel/wiki/wiki',

  // ── DFIR: tools that were mapped in worker/router.ts PRERENDERED_ROUTES
  //    but missing here, so they were served as the bare SPA shell and
  //    cached 24h as "prerendered". Now generated like their siblings. ──
  '/dfir/threat-graph',
  '/dfir/ir-playbooks',
  '/dfir/stealer-parser',
  '/dfir/whois-history',
  '/dfir/passive-dns',
  '/dfir/open-directory',

  // ── DFIR: static catalogs & education (8) — 0 API calls ───────
  '/dfir/diamond',
  '/dfir/owasp',
  '/dfir/lolbins',
  '/dfir/kill-chain',
  '/dfir/grc',
  '/dfir/data-classification',
  '/dfir/privacy-hub',

  // ── DFIR: utilities & decoders (7) — 0 API calls ──────────────
  '/dfir/timestamp',
  '/dfir/hash-calc',
  '/dfir/codec',
  '/dfir/punycode',
  '/dfir/brand-impersonation',

  // ── DFIR: image / media (3) — 0 API calls ─────────────────────
  '/dfir/image-intel',
  '/dfir/exif',

  // ── DFIR: file format analyzers (8) — 0 API calls ─────────────
  '/dfir/plist-protobuf',
  '/dfir/pcap-triage',
  '/dfir/registry-hive',
  '/dfir/evtx',
  '/dfir/sqlite',
  '/dfir/ios-backup',
  '/dfir/apk-analyzer',

  // ── DFIR: binary / log analyzers (5) — 0 API calls ────────────
  '/dfir/web-log',
  '/dfir/prefetch',
  '/dfir/procedure-extract',
  '/dfir/powershell-deobf',

  // ── DFIR: detection & analysis (8) — 0 API calls ──────────────
  '/dfir/rule-converter',
  '/dfir/prompt-injection',
  '/dfir/pi-taxonomy',
  '/dfir/mcp-audit',
  '/dfir/cve-prioritizer',
  '/dfir/fusion-exposure',
  '/dfir/risk-register',
  '/dfir/attack-path',
  '/dfir/grc-evidence',
  '/dfir/vulnerability-ops',
  '/dfir/ransomware-quant',
  '/dfir/patch-task-mgr',
  '/dfir/soc-automation',

  // ── DFIR: cloud security (7) — 0 API calls ────────────────────
  '/dfir/iam-hub',
  '/dfir/sg-analyzer',
  '/dfir/cloudtrail-triage',
  '/dfir/terraform-scan',

  // ── DFIR: API security (6) — 0 API calls ──────────────────────
  '/dfir/openapi-audit',
  '/dfir/secret-scan',
  '/dfir/medusa-scan',
  '/dfir/graphql-audit',
  '/dfir/osv-scan',

  // ── DFIR: STIX (2) — 0 API calls ──────────────────────────────

  // ── DFIR: security frameworks (3) — 0 API calls ───────────────
  '/dfir/nhi',
  '/dfir/jwt',
  '/dfir/zero-trust-ai-agents',

  // ── DFIR: dark web workbench (2) — 0 API calls ────────────────
  '/dfir/pgp-tool',

  // ── DFIR: investigator workbenches (6) — 0 API calls ──────────
  '/dfir/domain-investigator',
  '/dfir/ioc-investigate',
  '/dfir/username-investigator',
  '/dfir/yara-workbench',
  '/dfir/stix-workbench',
  '/dfir/malware-analyzer',

  // ── DFIR: specialist tools (8) — 0 API calls ──────────────────
  '/dfir/attack-navigator',
  '/dfir/vuln-toolkit',
  '/dfir/sec-headers-live',
  '/dfir/osint-mapper',
  '/dfir/notebooks',

  // ── DFIR: triage & forensic tools (5) — 0 API calls ───────────
  '/dfir/dnscope',
  '/dfir/crypto-tracer',
  '/dfir/tracerules',
  '/dfir/phone-hub',
  '/dfir/infostealer-intel',

  // ── DFIR: AI agent tools (4) — 0 API calls ────────────────────
  '/dfir/agent-suite',

  // ── DFIR: tools that fetch /api/v1/* on mount (33) ────────────
  // Prerendered chrome + loading state, then client hydrates.
  '/dfir/phishing',
  '/dfir/exposure',
  '/dfir/exposed-host',
  '/dfir/cve',
  '/dfir/cert-search',
  '/dfir/asn',
  '/dfir/breach',
  '/dfir/traceix',
  '/dfir/nhi-scan',
  '/dfir/whoxy',
  '/dfir/ai-threats',
  '/dfir/oss-feeds',
  '/threatintel/external/cerast',
  '/threatintel/external/threatmon',
  '/dfir/winreg',
  '/dfir/sigbase',
  '/dfir/lots',
  '/dfir/malapi',
  '/dfir/car',
  '/dfir/capec',
  '/dfir/hijacklibs',
  '/dfir/veris',
  '/dfir/engage',
  '/dfir/url-preview',
  '/dfir/subdomain-takeover',
  '/dfir/extract',
  '/dfir/google-dorks',
  '/dfir/linux-triage',
  '/dfir/email-defense',
  '/dfir/dmarc-analyzer',
  '/dfir/dlp-scan',
  '/dfir/wayback',
  '/dfir/log-parser',
  '/dfir/socmint',
  '/dfir/eml',
  '/dfir/email-rep',
  '/dfir/email-osnit',

  // ── Static threatintel catalogs (11) — 0 API calls ────────────
  // '/threatintel/briefings' removed from prerender: list is data-driven
  // (fetches /api/v1/briefings/list on mount). Prerendering the empty
  // initial state causes a React 18 hydration mismatch that leaves the
  // stale SSR'd list visible. Same root cause as the detail-page fix in
  // worker/router.ts (DYNAMIC_ROUTE_FALLBACKS).

  // ── ThreatIntel pages (4) — 0 API calls ───────────────────────
  '/threatintel/about',
  '/threatintel/mcp-search',
  '/threatintel/live-center',
  '/threatintel/telegram',
  '/threatintel/source-health',
  '/threatintel/soc-dashboard',
  '/threatintel/cyberpulse',

  // ── ThreatIntel: static catalogs (5) — 0 API calls ────────────

  // ── H3AD-SEC AI suite (1 tab-hub) — prerendered chrome ─
  '/dfir/ai-suite',

  // ── H3AD-SEC hunting / detection / ops (5) — prerendered chrome ─
  '/dfir/pivex',
  '/dfir/phishops',
  '/dfir/phishbook',

  // ── ThreatIntel: live-feed surfaces (38) — prerendered chrome ─
  // Client hydrates and fetches /api/v1/* on mount.
  // '/threatintel/reddit' removed — redirect to /threatintel/social/firehose
  // '/threatintel/status' removed — redirect to /threatintel/catalog?cat=social
  // '/threatintel/metrics' removed — redirect to /threatintel/predictive/dashboard
  '/threatintel/ransomware-live',
  '/threatintel/onion-watch',
  // Live-feed surfaces that were already prerendered

  // ── Phase 4 (2026-06-04): 43 real static routes that existed in App.tsx
  //    but had no entry here or in worker/router.ts PRERENDERED_ROUTES.
  //    Without this, those routes were served as the bare SPA shell and
  //    cached 24h as if "prerendered" (silent drift). Now they get the
  //    same chrome+loading-state treatment as their siblings.

  // ── Portfolio (2) ────────────────────────────────────────────
  '/admin',

  // ── DFIR: real pages (10) ────────────────────────────────────
  '/dfir/asset-intel',
  '/dfir/blocklists',
  '/dfir/ct-monitor',
  '/dfir/file',
  '/dfir/host-graph',
  '/dfir/report-hub',

  // ── Phase 5: New gap features ─────────────────────────────────
  '/dfir/export-hub',

  // ── ThreatIntel: real pages, not redirects (28) ──────────────
  '/dfir/copilot',
  '/dfir/orkl',
  '/dfir/wifi-investigation',
  // ── Detection Chokepoints: unified hub ─

  // ── ThreatIntel: hub pages (11) — Suspense-wrapped tabs, prerendered chrome ─

  // ── Previously shell-only static pages (SEO/CWV: crawlable first paint) ─
  '/argus',
  '/dfir/agent-history',
  '/dfir/csrf-poc',
  '/dfir/detection-chokepoints',
  '/dfir/one-time-secret',
  '/dfir/xss-payloads',
  '/threatintel/detection-wiki',
  '/threatintel/threat-actor-monitor',
  '/threatintel/alerts',
  '/threatintel/infra/ai-honeypot',
  '/threatintel/infra/ai-llm-intel',
];

// Mirrors `appMode` in src/App.tsx: routes under these prefixes render the
// AppShell chrome, which never reads navLinks — so their HTML is identical
// on both surfaces and only the portfolio tree needs to carry it. Must stay
// in sync with the four `location.pathname.startsWith(...)` checks there.
const APP_ROUTE_PREFIXES = ['/dfir', '/argus', '/threatintel', '/radar'];

const SHELL_PATH = resolve(ROOT, 'dist/index.html');
const SERVER_BUNDLE = resolve(ROOT, '.ssr-build/entry-server.js');

async function main() {
  if (!existsSync(SHELL_PATH)) {
    console.error(`prerender: missing ${SHELL_PATH} — run \`vite build\` first.`);
    process.exit(1);
  }
  if (!existsSync(SERVER_BUNDLE)) {
    console.error(`prerender: missing ${SERVER_BUNDLE} — run \`vite build --ssr src/entry-server.tsx\` first.`);
    process.exit(1);
  }

  const shell = await readFile(SHELL_PATH, 'utf8');
  // Dynamic import of the local file via file:// URL (ESM requirement).
  const { render } = await import(pathToFileURL(SERVER_BUNDLE).href);
  if (typeof render !== 'function') {
    throw new Error('prerender: server bundle does not export render(url)');
  }

  // Prerendered HTML goes under dist/__prerendered/ so Cloudflare Assets
  // doesn't auto-serve it for the matching route. The Worker's fetch
  // handler explicitly looks up __prerendered/<slug>.html and falls back
  // to the SPA shell (dist/index.html) when it's missing. Keeping the
  // SPA shell untouched means unknown routes still get the correct
  // fallback behavior.
  const prerenderDir = resolve(ROOT, 'dist/__prerendered');
  await mkdir(prerenderDir, { recursive: true });

  // Tools surface: a second tree under dist/__prerendered-tools/, chosen by
  // the Worker when the request Host matches a hostname in TOOLS_HOSTS
  // (crucible./panopticon./scout.…). Only routes whose HTML
  // actually differs are rendered — /dfir/*, /threatintel/*, /argus/* and
  // /radar/* render AppShell, which never reads navLinks, so their portfolio
  // HTML is already correct for the tools host. The Worker falls back to the
  // portfolio tree whenever this one has no file, so an under-rendered tools
  // route degrades to portfolio chrome rather than to a bare shell.
  const toolsPrerenderDir = resolve(ROOT, 'dist/__prerendered-tools');
  // `/` is EXCLUDED from the tools tree on purpose. It is the one route whose
// content depends on which tools host is asking: crucible serves the CRUCIBLE
// toolkit, panopticon the threat-intel platform, scout recon, argus Argus, and
// agent/copilot/brief their single tool. SSR only receives a `surface`
// ('portfolio' | 'tools'), not a hostname, so it cannot pick between them —
// prerendering `/` once for the tools surface would bake one tool's landing
// into every host's first paint.
//
// Leaving it out makes the worker fall through to the portfolio file, whose
// `/` is the SPA shell; the client then resolves the landing from
// `location.hostname` before paint. `/daily-briefs` is excluded for the same
// reason: it now has its own host (brief.) and its own landing.
const toolsRoutes = ROUTES.filter(
  (route) => !APP_ROUTE_PREFIXES.some((p) => route.startsWith(p)) && route !== '/' && route !== '/daily-briefs',
);
  await mkdir(toolsPrerenderDir, { recursive: true });

  const manifest = [];
  const toolsManifest = [];
  let okCount = 0;
  let toolsOkCount = 0;

  async function renderOne(route, surface, dir, treeLabel) {
    const { html: appHtml } = await render(route, surface);
    // Stamp `data-surface` onto <html> in BOTH prerender trees. The
    // portfolio-only smooth-scroll anchor offset is scoped to
    // `html[data-surface='portfolio']`, and this attribute is what
    // main.tsx re-applies client-side. Without it in the served HTML the
    // offset is missing on first paint — exactly when someone clicking an
    // in-page anchor would land under the sticky header — and the tools tree
    // would be wrong even if the attribute arrived after hydration.
    const stamped = shell
      .replace(/<html([^>]*)>/, `<html$1 data-surface="${surface}">`)
      .replace(/<div id="root"><\/div>/, `<div id="root">${appHtml}</div>`);
    const finalHtml = stamped;
    // Check the ROOT placeholder specifically, not `finalHtml === shell`.
    // The <html> stamp above always changes the string, so an equality check
    // against `shell` could never fire again - a shell missing the root div
    // would silently prerender to an empty page instead of failing loudly.
    if (!/<div id="root">/.test(finalHtml)) {
      throw new Error('prerender: shell did not contain <div id="root"></div> placeholder');
    }
    const slug = route === '/' ? 'home' : route.slice(1).replace(/\//g, '__');
    const outFile = resolve(dir, `${slug}.html`);
    await writeFile(outFile, finalHtml, 'utf8');
    const sizeKB = (finalHtml.length / 1024).toFixed(1);
    console.log(`  ✓ ${route.padEnd(30)} → ${treeLabel}/${slug}.html  (${sizeKB} KB)`);
    return { route, file: `${treeLabel}/${slug}.html` };
  }

  // Process routes in concurrent batches to saturate CPU without
  // overwhelming memory from N simultaneous render streams.
  async function runPass(routes, surface, dir, treeLabel) {
    const passManifest = [];
    let passOk = 0;
    for (let i = 0; i < routes.length; i += CONCURRENCY) {
      const batch = routes.slice(i, i + CONCURRENCY);
      const results = await Promise.allSettled(batch.map((r) => renderOne(r, surface, dir, treeLabel)));
      for (const result of results) {
        if (result.status === 'fulfilled') {
          passManifest.push(result.value);
          passOk++;
        } else {
          console.error(`  ✗ ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
        }
      }
    }
    return { passManifest, passOk };
  }

  const { passManifest, passOk } = await runPass(ROUTES, 'portfolio', prerenderDir, '__prerendered');
  manifest.push(...passManifest);
  okCount += passOk;

  const toolsResult = await runPass(toolsRoutes, 'tools', toolsPrerenderDir, '__prerendered-tools');
  toolsManifest.push(...toolsResult.passManifest);
  toolsOkCount += toolsResult.passOk;

  // Manifest tells the Worker which routes have prerendered HTML available.
  await writeFile(
    resolve(prerenderDir, 'manifest.json'),
    JSON.stringify({ generated_at: new Date().toISOString(), routes: manifest }, null, 2),
    'utf8'
  );
  // Tools-surface manifest — same shape, separate tree.
  await writeFile(
    resolve(toolsPrerenderDir, 'manifest.json'),
    JSON.stringify({ generated_at: new Date().toISOString(), surface: 'tools', routes: toolsManifest }, null, 2),
    'utf8'
  );

  console.log(`\nprerender: ${okCount}/${ROUTES.length} routes rendered → dist/__prerendered/`);
  console.log(`prerender: ${toolsOkCount}/${toolsRoutes.length} routes rendered → dist/__prerendered-tools/`);
  if (okCount === 0) process.exit(1);

  // ── Drift guard ─────────────────────────────────────────────────────────
  // worker/router.ts (PRERENDERED_ROUTES) maps each route to /__prerendered/
  // <slug>. With not_found_handling:"single-page-application", a MISSING
  // prerendered asset is served as the SPA shell at status 200 — so a route
  // listed there without a generated file is silently served (and cached 24h)
  // as the bare shell labelled "prerendered". Fail the build on that drift,
  // including a route here that failed to render (absent from the manifest).
  const generated = new Set(manifest.map((m) => m.file.replace(/^__prerendered\//, '').replace(/\.html$/, '')));
  const routerSrc = await readFile(resolve(ROOT, 'worker/router.ts'), 'utf8');
  const expected = [...new Set([...routerSrc.matchAll(/\/__prerendered\/([a-zA-Z0-9_-]+)/g)].map((m) => m[1]))];
  const missing = expected.filter((slug) => !generated.has(slug));
  if (missing.length > 0) {
    console.error(
      `\nprerender: ✗ ${missing.length} PRERENDERED_ROUTES entr${missing.length === 1 ? 'y has' : 'ies have'} no generated HTML`
    );
    console.error('  (each is served as the bare SPA shell, cached 24h as "prerendered"):');
    for (const slug of missing) console.error(`    /__prerendered/${slug}`);
    console.error('\n  Fix: add the route to ROUTES above, or remove it from worker/router.ts PRERENDERED_ROUTES.\n');
    process.exit(1);
  }
  console.log(`prerender: ✓ all ${expected.length} PRERENDERED_ROUTES entries have generated HTML.`);
}

// Explicit exit: the SSR bundle keeps a handle on the event loop, so without
// this the process hangs forever after the work is done (the build never
// completes, which is what wedged `npm run build` / `npm run deploy`).
main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('prerender failed:', err);
    process.exit(1);
  });
