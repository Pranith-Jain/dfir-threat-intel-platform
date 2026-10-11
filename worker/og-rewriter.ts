import { injectScriptNonce } from './csp';
import { readBriefing } from '../api/src/lib/briefing-builder';
import { pageCardUrl } from './og-path';
// Per-deploy version token — mixed into the rewritten-HTML cache keys below so
// a redeploy always gets fresh cache entries exactly when emitted card URLs change.
import { OG_BUILD_VERSION } from './og-version.generated';
// Pure per-route copy-resolution lives in worker/og-copy.ts so the BUILD-TIME
// card generator (scripts/generate-page-og.mjs) can resolve the SAME
// title/description the rewriter serves — cards and meta can never drift.
import { clampToBytes, findOgOverride, ogMetaForPath, OG_OVERRIDES } from './og-copy';
import type { OgOverride } from './og-copy';
// Blog KV reads are shared with the public API routes (api/src/lib/blog-kv
// bridge) so the OG rewrite and /api/v1/blog/* hit the SAME per-colo shadow.
import { readBlogPostShadowed, readBlogIndexShadowed } from './lib/blog-kv';
import type { Env } from './env';
import { owningToolHost } from './surface';

/**
 * Per-route OG title/description resolution.
 *
 * Precedence (see `findOgOverride` / `ogMetaForPath`):
 *   1. Hand-tuned `OG_OVERRIDES` exact match (polished copy, hand-written)
 *   2. `OG_OVERRIDES` prefix match (section branding)
 *   3. `deriveOgFromPath` (mechanical slug-derived fallback)
 *
 * NOTE: a build-time-generated per-route map (`og-overrides.generated.json`,
 * produced by `scripts/build-og-overrides.mjs`) previously sat at precedence
 * level 2, filling the ~400-route gap between the hand-tuned entries and the
 * slug-derived fallback. The generator script was never committed, so the
 * import broke the build. It has been removed for now; deep links fall back
 * to the slug-derived description (always ≥55 chars, X-card-valid). Restore
 * the generated map by committing `scripts/build-og-overrides.mjs`, adding it
 * to `prebuild`, and re-adding the import + `generated` lookup in `ogMetaForPath`.
 */

/**
 * L1-shadowed read of a blog post record from CASE_STUDIES KV.
 * Implementation lives in worker/lib/blog-kv.ts (shared with the public API
 * routes); re-exported here for the existing og-data.ts import surface.
 */
export { readBlogPostShadowed } from './lib/blog-kv';
// Re-export the copy-resolution surface — existing consumers (tests,
// worker/og-data.ts) import it from here.
export { OG_OVERRIDES, ogMetaForPath } from './og-copy';
export type { OgOverride, OgPageMeta } from './og-copy';

/** The one true public origin. Used for canonical/OG URLs so they can never
 *  be poisoned by a request arriving on a non-canonical host. This is also the
 *  owner of every path that no tool host claims (portfolio routes, and any
 *  app prefix whose hostname is not configured in `TOOLS_HOSTS`). */
const CANONICAL_ORIGIN = 'https://pranithjain.qzz.io';

/**
 * Origin that owns `pathname`.
 *
 * Each tools host is authoritative for its own path prefix and only for it, so
 * `/dfir` canonicalises to crucible and `/threatintel` to panopticon no matter
 * which host the request arrived on. A prefix with no configured host falls
 * back to the apex — that fallback is what keeps `/argus` (whose hostname does
 * not exist yet) on a canonical that actually resolves.
 */
function canonicalOriginFor(pathname: string, env: Env): string {
  const host = owningToolHost(pathname, env);
  return host ? `https://${host}` : CANONICAL_ORIGIN;
}

/**
 * The full canonical URL for a request, redirect-only routes included.
 *
 * `REDIRECT_CANONICALS` targets are resolved through the same owner lookup,
 * so `/copilot` → `/threatintel/tools/copilot` points at panopticon rather than
 * at whatever host the visitor happened to land on.
 */
export function canonicalUrlFor(url: URL, env: Env): string {
  const redirectTarget = url.pathname && REDIRECT_CANONICALS[url.pathname];
  if (redirectTarget) return `${canonicalOriginFor(redirectTarget, env)}${redirectTarget}`;
  return `${canonicalOriginFor(url.pathname, env)}${url.pathname}${url.search}`;
}

/**
 * Rewritten-HTML cache-key namespace. v14 additionally scopes keys by
 * OG_BUILD_VERSION (see injectOgMeta / getOrInjectOg): asset etags are
 * content-derived, and prerendered HTML bytes frequently DON'T change between
 * deploys — so a pathname@etag key alone survives redeploys and keeps serving
 * pre-deploy rewritten HTML whose og:image references the PREVIOUS deploy's
 * card-version token (observed live: one route serving the old version while
 * every other page had healed). Keying by build version invalidates exactly
 * when emitted card URLs change.
 */
const OG_CACHE_VERSION = 'v14';

export const OG_CACHE_TTL_SECONDS = 86400;

const HTML_ATTR_ESCAPE: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ATTR_ESCAPE[c] ?? c);
}

/**
 * Redirect-only routes → their canonical targets. When a visitor lands on a
 * redirect URL (e.g. /threatintel/reddit → /threatintel/social/firehose),
 * the <link rel="canonical"> must point to the target so Google consolidates
 * ranking signals instead of treating the redirect URL as a separate page.
 * Auto-extracted from App.tsx REDIRECTS (only routes without a ROUTES entry).
 */
const REDIRECT_CANONICALS: Record<string, string> = {
  '/agent': '/dfir/agent-suite',
  '/copilot': '/threatintel/tools/copilot',
  '/dfir/agent': '/dfir/agent-suite',
  '/dfir/agent-enrich': '/dfir/agent-suite',
  '/dfir/agent-map': '/dfir/agent-suite',
  '/dfir/atlas': '/threatintel/wiki/llm',
  '/dfir/azure-rbac': '/dfir/iam-hub',
  '/dfir/chrono-ai': '/dfir/ai-suite',
  '/dfir/dashboard': '/dfir',
  '/dfir/decode': '/dfir/codec',
  '/dfir/detection-lab': '/dfir/rule-converter',
  '/dfir/discord-watch': '/threatintel/catalog',
  '/dfir/domain': '/dfir/domain-investigator',
  '/dfir/domain-rep': '/dfir/domain-investigator',
  '/dfir/dork-builder': '/dfir/google-dorks',
  '/dfir/encoder': '/dfir/codec',
  '/dfir/fleet-map': '/dfir/catalog',
  '/dfir/full-spectrum': '/dfir/domain-investigator',
  '/dfir/gcp-iam': '/dfir/iam-hub',
  '/dfir/host': '/dfir/asset-intel',
  '/dfir/iam-analyzer': '/dfir/iam-hub',
  '/dfir/identity-lookup': '/dfir/username-investigator',
  '/dfir/image-fingerprint': '/dfir/image-intel',
  '/dfir/industry-news': '/threatintel/catalog',
  '/dfir/insight-ai': '/dfir/ai-suite',
  '/dfir/ioc-check': '/dfir/ioc-investigate',
  '/dfir/ioc-pivot': '/dfir/ioc-investigate',
  '/dfir/k8s-rbac': '/dfir/iam-hub',
  '/dfir/malbrief-ai': '/dfir/ai-suite',
  '/dfir/malware-capabilities': '/dfir/malware-analyzer',
  '/dfir/malware-scan': '/dfir/malware-analyzer',
  '/dfir/mobile-sqlite': '/dfir/sqlite',
  '/dfir/phone-intel': '/dfir/phone-hub',
  '/dfir/phone-osint': '/dfir/phone-hub',
  '/dfir/privacy': '/dfir/privacy-hub',
  '/dfir/querycraft-ai': '/dfir/ai-suite',
  '/dfir/report-analyzer': '/dfir/report-hub',
  '/dfir/report-composer': '/dfir/report-hub',
  '/dfir/report-ingest': '/dfir/stix-workbench',
  '/dfir/report-parser': '/dfir/report-hub',
  '/dfir/reverse-image': '/dfir/image-intel',
  '/dfir/rhysida-intrusion': '/dfir/catalog',
  '/dfir/rule-playground': '/dfir/yara-workbench',
  '/dfir/sample-scan': '/dfir/malware-analyzer',
  '/dfir/sandbox': '/dfir/malware-analyzer',
  '/dfir/screenshot-intel': '/dfir/image-intel',
  '/dfir/sec-headers': '/dfir/sec-headers-live',
  '/dfir/sigma-convert': '/dfir/rule-converter',
  '/dfir/stix': '/dfir/stix-workbench',
  '/dfir/stix-builder': '/dfir/stix-workbench',
  '/dfir/takeover': '/dfir/subdomain-takeover',
  '/dfir/taxii': '/dfir/stix-workbench',
  '/dfir/threat-hunt': '/dfir/ioc-investigate',
  '/dfir/tools/:group': '/dfir/catalog',
  '/dfir/tor-gateway': '/dfir/catalog',
  '/dfir/username': '/dfir/username-investigator',
  '/dfir/username-osint': '/dfir/username-investigator',
  '/dfir/verdikt-ai': '/dfir/ai-suite',
  '/dfir/vs': '/dfir/catalog',
  '/dfir/web-scan': '/dfir/domain-investigator',
  '/dfir/webcheck': '/dfir/domain-investigator',
  '/dfir/wordpress-sim': '/dfir/catalog',
  '/dfir/yara': '/dfir/yara-workbench',
  '/difr': '/dfir',
  '/nhi': '/dfir/nhi-scan',
  '/nhi-scan': '/dfir/nhi-scan',
  '/osint': '/dfir',
  '/osint-tools': '/threatintel/osint/cli',
  '/sigbase': '/dfir/sigbase',
  '/threat-intel': '/threatintel',
  '/threatintel/ach': '/threatintel/catalog',
  '/threatintel/actor-dna': '/threatintel/catalog',
  '/threatintel/actor-kb': '/threatintel/catalog',
  '/threatintel/actor-timeline': '/threatintel/actors/hub',
  '/threatintel/actor-usernames': '/threatintel/actors/hub',
  '/threatintel/actors/directory': '/threatintel/actors/hub',
  '/threatintel/actors/dna': '/threatintel/actors/hub',
  '/threatintel/actors/graph': '/threatintel/actors/hub',
  '/threatintel/actors/profiles': '/threatintel/actors/hub',
  '/threatintel/actors/timeline': '/threatintel/actors/hub',
  '/threatintel/actors/usernames': '/threatintel/actors/hub',
  '/threatintel/aggregated-feeds': '/threatintel/feeds/threatfeeds',
  '/threatintel/ai-report': '/threatintel/research-hub/ai',
  '/threatintel/analyze': '/threatintel/predictive/analyze',
  '/threatintel/assessments': '/threatintel/predictive/assessments',
  '/threatintel/atlas': '/threatintel/catalog',
  '/threatintel/attribution': '/threatintel/actors/attribution',
  '/threatintel/awesome-lists': '/threatintel/external/awesome',
  '/threatintel/bitwire-blocklist': '/threatintel/feeds/threatfeeds',
  '/threatintel/breach': '/threatintel/telegram',
  '/threatintel/breach-forums': '/threatintel/breach-hub',
  '/threatintel/c2-tracker': '/threatintel/iocs/c2',
  '/threatintel/campaign-generator': '/threatintel/catalog',
  '/threatintel/campaign-lifecycle': '/threatintel/campaigns/lifecycle',
  '/threatintel/certstream': '/threatintel/iocs/live',
  '/threatintel/collection-slo': '/threatintel/feeds/quality',
  '/threatintel/copilot': '/threatintel/tools/copilot',
  '/threatintel/copilot-chat': '/threatintel/tools/copilot',
  '/threatintel/correlation': '/threatintel/iocs/cross',
  '/threatintel/cross-campaign': '/threatintel/campaigns/cross',
  '/threatintel/cross-correlate': '/threatintel/catalog',
  '/threatintel/crypto-scams': '/threatintel/social/crypto-scam',
  '/threatintel/cti-dashboard': '/threatintel/dashboard-hub',
  '/threatintel/curated-toolbox': '/threatintel/osint/toolbox',
  '/threatintel/cve-list': '/threatintel/cves/cves',
  '/threatintel/cve-resources': '/threatintel/catalog',
  '/threatintel/cves': '/threatintel/cves/cves',
  '/threatintel/cves/exploitable': '/threatintel/cves/cves',
  '/threatintel/cves/k8s': '/threatintel/cves/cves',
  '/threatintel/cyber-crime': '/threatintel/telegram',
  '/threatintel/cybersec': '/threatintel/telegram',
  '/threatintel/darkweb-tools': '/threatintel/darkweb/watch',
  '/threatintel/darkweb/breach-watch': '/threatintel/breach-hub',
  '/threatintel/darkweb/disclosures': '/threatintel/breach-hub',
  '/threatintel/darkweb/forums': '/threatintel/breach-hub',
  '/threatintel/darkweb/ransom-activity': '/threatintel/ransomware-hub',
  '/threatintel/darkweb/ransom-map': '/threatintel/ransomware-hub',
  '/threatintel/darkweb/ransom-report': '/threatintel/ransomware-hub',
  '/threatintel/darkweb/ransomwhere': '/threatintel/ransomware-hub',
  '/threatintel/dashboard': '/threatintel/dashboard-hub',
  '/threatintel/deepdarkcti': '/threatintel/darkweb/deepdark',
  '/threatintel/depx': '/threatintel/supply-chain',
  '/threatintel/detections': '/threatintel/detections/detections',
  '/threatintel/disarm': '/threatintel/detections/disarm',
  '/threatintel/domain-monitor': '/threatintel/catalog',
  '/threatintel/entity-resolution': '/threatintel/iocs/entity',
  '/threatintel/external-resources': '/threatintel/external/external',
  '/threatintel/external/supply': '/threatintel/supply-chain',
  '/threatintel/f2t2ea': '/threatintel/wiki/f2t2ea',
  '/threatintel/f3ead': '/threatintel/wiki/f3ead',
  '/threatintel/facilities': '/threatintel/catalog',
  '/threatintel/feed-catalog': '/threatintel/feeds/catalog',
  '/threatintel/feed-quality': '/threatintel/feeds/quality',
  '/threatintel/feed-scheduler': '/threatintel/feeds/scheduler',
  '/threatintel/feed-sources': '/threatintel/feeds/sources',
  '/threatintel/feeds/reliability': '/threatintel/source-health',
  '/threatintel/feeds/status': '/threatintel/source-health',
  '/threatintel/infostealer': '/threatintel/catalog',
  '/threatintel/insider-threat-matrix': '/threatintel/wiki/insider',
  '/threatintel/intel-dashboard': '/threatintel/predictive/dashboard',
  '/threatintel/intelligence-gaps': '/threatintel/catalog',
  '/threatintel/investigations': '/threatintel/tools/investigations',
  '/threatintel/ioc-enrichment': '/threatintel/iocs/enrichment',
  '/threatintel/ioc-feeds': '/threatintel/feeds/threatfeeds',
  '/threatintel/iocs/soc': '/threatintel/soc-dashboard',
  '/threatintel/kill-chain-v2': '/threatintel/wiki/kill-chain-v2',
  '/threatintel/live-iocs': '/threatintel/iocs/live',
  '/threatintel/llm-threat-atlas': '/threatintel/wiki/llm',
  '/threatintel/malicious-packages': '/threatintel/supply-chain',
  '/threatintel/malpedia': '/threatintel/malware/malpedia',
  '/threatintel/maltrail': '/threatintel/malware/maltrail',
  '/threatintel/malware-iocs': '/threatintel/malware/iocs',
  '/threatintel/malware-sandbox': '/threatintel/malware/sandbox',
  '/threatintel/malware-vault': '/threatintel/malware/vault',
  '/threatintel/malware/packages': '/threatintel/supply-chain',
  '/threatintel/malware/supply-chain': '/threatintel/supply-chain',
  '/threatintel/metrics': '/threatintel/predictive/dashboard',
  '/threatintel/misp-browser': '/threatintel/tools/misp',
  '/threatintel/mitre': '/threatintel/wiki/mitre',
  '/threatintel/mythreatintel': '/threatintel/catalog',
  '/threatintel/negotiations': '/threatintel/darkweb/ransom-activity',
  '/threatintel/observable-db': '/threatintel/catalog',
  '/threatintel/observe': '/threatintel/predictive/observe',
  '/threatintel/ooda': '/threatintel/wiki/ooda',
  '/threatintel/osint-cli-tools': '/threatintel/osint/cli',
  '/threatintel/osint-framework': '/threatintel/osint/framework',
  '/threatintel/osint-map': '/threatintel/osint/map',
  '/threatintel/owasp-ai-landscape': '/threatintel/wiki/owasp',
  '/threatintel/phishing-wordlists': '/threatintel/phishing/urls',
  '/threatintel/pir-dashboard': '/threatintel/predictive/dashboard',
  '/threatintel/predictions': '/threatintel/predictive/predictions',
  '/threatintel/projectdiscovery': '/threatintel/catalog',
  '/threatintel/pulse': '/threatintel/catalog',
  '/threatintel/ransom-report': '/threatintel/darkweb/ransom-report',
  '/threatintel/ransomware-activity': '/threatintel/ransomware-hub',
  '/threatintel/ransomware-map': '/threatintel/darkweb/ransom-map',
  '/threatintel/ransomwhere': '/threatintel/darkweb/ransomwhere',
  '/threatintel/re-leaks': '/threatintel/darkweb/leaks',
  '/threatintel/reddit': '/threatintel/social/firehose',
  '/threatintel/redhunt-insights': '/threatintel/research-hub/redhunt',
  '/threatintel/redhunt-labs': '/threatintel/research-hub/redhunt',
  '/threatintel/relationship-graph': '/threatintel/actors/hub',
  '/threatintel/reports': '/threatintel/research-hub/reports',
  '/threatintel/research': '/threatintel/research-hub/research',
  '/threatintel/research-hub/campaign-gen': '/threatintel/campaigns/generator',
  '/threatintel/rules': '/threatintel/detections/detections',
  '/threatintel/scam-watch': '/threatintel/social/crypto-scam',
  '/threatintel/search': '/threatintel/catalog',
  '/threatintel/secops-tools': '/threatintel/osint/secops',
  '/threatintel/settings': '/threatintel/tools/settings',
  '/threatintel/signal': '/threatintel/detections/signal',
  '/threatintel/soc-iocs': '/threatintel/iocs/live',
  '/threatintel/soc-ransomware': '/threatintel/predictive/dashboard',
  '/threatintel/soc-vulns': '/threatintel/predictive/dashboard',
  '/threatintel/social/reddit': '/threatintel/social/firehose',
  '/threatintel/social/scraped-intel': '/threatintel/social/firehose',
  '/threatintel/social/telegram-channels': '/threatintel/telegram',
  '/threatintel/social/telegram-leaks': '/threatintel/telegram',
  '/threatintel/social/telegram-settings': '/threatintel/telegram',
  '/threatintel/social/telegram-stats': '/threatintel/telegram',
  '/threatintel/social/x-firehose': '/threatintel/social/x-hub',
  '/threatintel/social/x-live': '/threatintel/social/x-hub',
  '/threatintel/social/x-watch': '/threatintel/social/x-hub',
  '/threatintel/source-reliability': '/threatintel/catalog',
  '/threatintel/status': '/threatintel/catalog',
  '/threatintel/stix-bundles': '/threatintel/tools/stix',
  '/threatintel/tech-ai-news': '/threatintel/catalog',
  '/threatintel/telegram-iocs': '/threatintel/telegram',
  '/threatintel/telegram-leaks': '/threatintel/telegram',
  '/threatintel/telegram-leaks/channels': '/threatintel/telegram',
  '/threatintel/telegram-leaks/stats': '/threatintel/telegram',
  '/threatintel/telegram-monitor': '/threatintel/telegram',
  '/threatintel/telegram-settings': '/threatintel/telegram',
  '/threatintel/telegram-watch': '/threatintel/telegram',
  '/threatintel/threat-actor-catalog': '/threatintel/catalog',
  '/threatintel/threat-actor-db': '/threatintel/catalog',
  '/threatintel/threat-feeds': '/threatintel/feeds/threatfeeds',
  '/threatintel/threat-landscape': '/threatintel/predictive/dashboard',
  '/threatintel/threat-map': '/threatintel/iocs/map',
  '/threatintel/threatsignal': '/threatintel/detections/signal',
  '/threatintel/ti-dashboard': '/threatintel/dashboard-hub',
  '/threatintel/tools/graph': '/threatintel/actors/hub',
  '/threatintel/tools/investigations': '/threatintel/investigation-suite',
  '/threatintel/tools/kev-catalog': '/threatintel/cves',
  '/threatintel/tools/stix': '/threatintel/tools/stix-hub',
  '/threatintel/tools/stix-ip-export': '/threatintel/tools/stix-hub',
  '/threatintel/tools/watches': '/threatintel/investigation-suite',
  '/threatintel/tools/workspaces': '/threatintel/investigation-suite',
  '/threatintel/unified-kill-chain': '/threatintel/wiki/unified-kill-chain',
  '/threatintel/watches': '/threatintel/tools/watches',
  '/threatintel/workspaces': '/threatintel/tools/workspaces',
  '/threatintel/writeups': '/threatintel/research-hub/writeups',
  '/threatintel/x': '/threatintel/social/x-hub',
  '/threatintel/x-live': '/threatintel/social/x-hub',
  '/threatintel/x-watch': '/threatintel/social/x-hub',
  '/threatintel/yara': '/threatintel/detections/yara',
  '/threatintel/detection-wiki': '/threatintel/detection-wiki',
  '/threatnexus': '/argus',
  '/traceix': '/dfir/traceix',
  '/whoxy': '/dfir/whoxy',
  '/winreg': '/dfir/winreg',
};

/**
 * SEO content injected into prerendered pages that render an empty <main>
 * (just a Suspense loading spinner). Google sees zero unique content and
 * declines to index. This function detects the thin-content pattern and
 * replaces it with meaningful text — title (h1), description, and section
 * context — that Googlebot can index. React hydration replaces this on mount.
 */
function injectSeoContent(html: string, pathname?: string): string {
  if (!pathname || pathname === '/') return html;
  // Detect the thin-content pattern: <main> containing only the
  // animate-fade-in-up > SectionLoader (spinner + sr-only "Loading…").
  const mainMatch = html.match(/(<main[^>]*id="main-content"[^>]*>)(.*?)(<\/main>)/s);
  if (!mainMatch) return html;
  const mainOpen = mainMatch[1]!;
  const mainBody = mainMatch[2]!;
  const mainClose = mainMatch[3]!;
  // If the main body already has substantial content (≥200 chars of visible
  // text beyond the spinner), the component rendered during SSR — skip.
  const textOnly = mainBody.replace(/<[^>]+>/g, '').trim();
  if (textOnly.length > 200) return html;
  // Look up the page's metadata from OG overrides or derive from path.
  const meta = ogMetaForPath(pathname);
  if (!meta) return html;
  const title = escapeAttr(meta.title.replace(/\s*[·•]\s*pranithjain\.qzz\.io.*$/i, ''));
  const desc = escapeAttr(meta.description);
  // Section-aware context blurb for Google — different per top-level path.
  const section = pathname.startsWith('/dfir')
    ? 'DFIR toolkit'
    : pathname.startsWith('/threatintel')
      ? 'threat intelligence platform'
      : 'security tool';
  const seoBlock = `
    <section class="seo-prerender" aria-label="Page information">
      <h1>${title}</h1>
      <p>${desc}</p>
      <p>This is a free, browser-based ${section} on pranithjain.qzz.io. No signup required — all processing runs locally in your browser.</p>
    </section>`;
  // Inject the SEO block inside <main> before the thin content.
  // The SectionLoader div + Suspense markers will be replaced by React hydration.
  const patched = mainOpen + seoBlock + mainBody + mainClose;
  return html.replace(mainMatch[0], patched);
}

/**
 * Always corrects the canonical URL + og:url + twitter:url to the actual
 * requested page. Without this, EVERY non-overridden deep link (notably
 * /blog/:slug) was served index.html's build-time og:url/canonical pointing
 * at the site root — so LinkedIn/Twitter resolved a shared blog link to the
 * HOME page and showed the home card. Title/description are additionally
 * rewritten only when we have a route- or post-specific override.
 *
 * Also injects the CSP nonce into the inline <script> tag when provided.
 * Combining both passes avoids a second full-String copy of the HTML body
 * (the caller used to read body → OG rewrite → Response → read body again
 * for nonce injection, doubling memory traffic on every HTML response).
 *
 * `canonicalUrl` arrives fully resolved from `canonicalUrlFor()` — the caller
 * owns path→host resolution (including redirect-only routes) so this function
 * stays a pure string transform and every entry point agrees on ownership.
 */
function rewriteHtml(
  html: string,
  override: OgOverride | null,
  canonicalUrl: string,
  nonce?: string,
  pathname?: string
): string {
  const cu = escapeAttr(canonicalUrl);
  // NOTE: attribute gaps use `\s+`, not a literal space. index.html is
  // prettier-formatted, which wraps long meta tags across multiple lines (the
  // <meta name="description"> tag spans 3 lines). A single-space pattern
  // silently fails to match a wrapped tag — that was the bug that served the
  // 317-char home description (and the home twitter card) on every route.
  // Twitter tags use name= (the X/Twitter card spec requires name=, not
  // property=). LinkedIn only reads og:* so it never cared, but X is the sole
  // consumer of twitter:* and its parser expects name= — serving property=
  // was why per-page cards rendered on LinkedIn but not on X.
  let out = html
    .replace(/<link\s+rel="canonical"\s+href="[^"]*"/i, `<link rel="canonical" href="${cu}"`)
    .replace(/<meta\s+property="og:url"\s+content="[^"]*"/i, `<meta property="og:url" content="${cu}"`)
    .replace(/<meta\s+name="twitter:url"\s+content="[^"]*"/i, `<meta name="twitter:url" content="${cu}"`);
  if (override) {
    // Escape first, THEN clamp — HTML entity escaping (e.g. ' → &#39;) expands
    // the string by up to 4 bytes per char, so clamping the raw string leaves
    // the escaped output over the byte limit. Clamp the escaped string so the
    // final meta content attribute stays within X/Twitter card limits.
    const t = clampToBytes(escapeAttr(override.title), 70);
    const d = clampToBytes(escapeAttr(override.description), 200);
    out = out
      .replace(/<title>[^<]*<\/title>/i, `<title>${t}</title>`)
      .replace(/<meta\s+name="description"\s+content="[^"]*"/i, `<meta name="description" content="${d}"`)
      .replace(/<meta\s+property="og:title"\s+content="[^"]*"/i, `<meta property="og:title" content="${t}"`)
      .replace(/<meta\s+property="og:description"\s+content="[^"]*"/i, `<meta property="og:description" content="${d}"`)
      .replace(/<meta\s+name="twitter:title"\s+content="[^"]*"/i, `<meta name="twitter:title" content="${t}"`)
      .replace(
        /<meta\s+name="twitter:description"\s+content="[^"]*"/i,
        `<meta name="twitter:description" content="${d}"`
      );

    if (override.image) {
      const imgUrl = `${CANONICAL_ORIGIN}${override.image}`;
      const imgAttr = escapeAttr(imgUrl);
      // Every OG card — static branded (/og-*.png) and dynamic
      // (/api/v1/og-image/*) — is a 1200×630 PNG since the flat-design
      // regeneration (static cards were 800×418 before). One size for all
      // cards keeps the crawler-facing width/height in sync with reality
      // and matches the size LinkedIn/Twitter render best.
      const imgWidth = '1200';
      const imgHeight = '630';
      // Alt text for the OG image — must match the page-specific card, not
      // the generic homepage alt. Falls back to description when no explicit
      // imageAlt is set. Clamped to 125 chars (X/LinkedIn alt-text limit).
      const imgAlt = clampToBytes(escapeAttr(override.imageAlt ?? override.description), 125);
      out = out
        .replace(/<meta\s+property="og:image"\s+content="[^"]*"/gi, `<meta property="og:image" content="${imgAttr}"`)
        .replace(/<meta\s+name="twitter:image"\s+content="[^"]*"/gi, `<meta name="twitter:image" content="${imgAttr}"`)
        .replace(
          /<meta\s+property="og:image:width"\s+content="[^"]*"/gi,
          `<meta property="og:image:width" content="${imgWidth}"`
        )
        .replace(
          /<meta\s+property="og:image:height"\s+content="[^"]*"/gi,
          `<meta property="og:image:height" content="${imgHeight}"`
        )
        .replace(
          /<meta\s+property="og:image:alt"\s+content="[^"]*"/gi,
          `<meta property="og:image:alt" content="${imgAlt}"`
        )
        .replace(
          /<meta\s+name="twitter:image:alt"\s+content="[^"]*"/gi,
          `<meta name="twitter:image:alt" content="${imgAlt}"`
        );
    }
  }
  if (nonce) {
    out = out.replace(/<script>/g, `<script nonce="${nonce}">`);
  }
  // Strip duplicate OG/Twitter meta tags that React Helmet injects into the
  // prerendered #root HTML. The <head> tags (rewritten above) are the
  // authoritative set; the #root duplicates are stale build-time copies that
  // point at the wrong URL/title and lack twitter:image. X's crawler picks
  // up duplicate meta tags and serves no card when it sees a twitter:card
  // without a matching twitter:image; LinkedIn reads <head> only and is
  // unaffected. Removing the #root duplicates makes X match LinkedIn.
  const rootIdx = out.indexOf('<div id="root"');
  if (rootIdx !== -1) {
    const head = out.slice(0, rootIdx);
    let root = out.slice(rootIdx);
    // Remove OG/Twitter meta tags + duplicate <title> from the prerendered
    // app HTML. Helmet renders them self-closing with content="...".
    root = root.replace(
      /<meta\s+(?:property="og:(?:title|url|description|image|type|site_name|locale|image:(?:type|width|height|alt))"|name="twitter:(?:card|title|description|image|url|site|creator|image:alt)")[^>]*\/?>/gi,
      ''
    );
    root = root.replace(/<title>[^<]*<\/title>/g, '');
    out = head + root;
  }
  // ── SEO content injection for thin-content prerendered pages ──
  // Prerendered pages under <Suspense fallback={<SectionLoader />}> produce
  // an empty <main> with just a loading spinner. Googlebot sees zero unique
  // content → "Crawled - currently not indexed." Inject a visible <section>
  // with the page title + description + key context so Google has something
  // to index. React hydration replaces this on mount.
  out = injectSeoContent(out, pathname);
  return out;
}

/**
 * Section-aware branding for a generated page card, derived from the first
 * path segment. Keeps the dynamic per-page cards visually consistent with the
 * branded surface cards (CRUCIBLE / PANOPTICON / SCOUT / ARGUS).
 */

/**
 * Resolve per-route OG title/description: static map first, then a live
 * lookup for blog posts so a shared /blog/<slug> shows the POST's title and
 * excerpt (not the generic blog card). Returns null when there's no
 * meaningful override — the URL/canonical still get corrected regardless.
 */
export async function resolveOg(url: URL, env: Env): Promise<OgOverride | null> {
  // Shared investigation reports (capability-token links). Title/description
  // from D1; image is a per-report dynamic card. Token never appears in meta.
  const sr = /^\/share\/report\/([0-9a-f]{32})$/.exec(url.pathname);
  if (sr && env.BRIEFINGS_DB) {
    const token = sr[1]!;
    try {
      const row = await env.BRIEFINGS_DB.prepare(`SELECT title, branding_json FROM saved_reports WHERE share_token = ?`)
        .bind(token)
        .first<{ title: string; branding_json?: string }>();
      if (row) {
        let orgName = '';
        try {
          const branding = row.branding_json ? (JSON.parse(row.branding_json) as { orgName?: string }) : null;
          orgName = branding?.orgName ?? '';
        } catch {
          /* malformed branding */
        }
        const description = orgName
          ? `Threat investigation report shared by ${orgName} — findings, MITRE mapping and IOCs.`
          : 'Threat investigation report — findings, MITRE mapping and IOCs.';
        return {
          title: `Investigation Report — ${row.title}`.slice(0, 90),
          description,
          image: `/api/v1/og-image/report/${token}.png`,
          imageAlt: description,
        };
      }
    } catch {
      /* D1 miss → fall through to generic SPA card */
    }
  }

  const m = /^\/blog\/([a-z0-9-]{1,200})$/.exec(url.pathname);
  if (m && env.CASE_STUDIES) {
    const image = `/api/v1/og-image/blog/${m[1]}.png`;
    try {
      const post = await readBlogPostShadowed<{ title?: string; excerpt?: string }>(env, m[1]!);
      if (post?.title) {
        // Clamp to X/Twitter card limits: title ≤70, description ≤200 BYTES
        // (some validators count UTF-8 bytes, not codepoints — em-dashes are
        // 3 bytes). The `· pranithjain.qzz.io` suffix is reserved first so a
        // long post title doesn't push the combined title over the limit.
        const SUFFIX = ' · pranithjain.qzz.io';
        const maxTitle = 70 - Buffer.byteLength(SUFFIX, 'utf8');
        const rawTitle = clampToBytes(post.title, maxTitle);
        const description = clampToBytes(post.excerpt || OG_OVERRIDES['/blog']!.description, 199);
        return {
          title: `${rawTitle}${SUFFIX}`,
          description,
          image,
          imageAlt: description,
        };
      }
    } catch {
      /* fall through to the generic blog card (still with the dynamic image) */
    }
    return {
      ...(OG_OVERRIDES['/blog'] ?? { title: '', description: '' }),
      image,
      imageAlt: OG_OVERRIDES['/blog']?.description ?? '',
    };
  }

  // Briefing detail pages get a per-briefing card: dynamic PNG image always,
  // plus the briefing's own title/summary when it can be read from D1. A D1
  // miss still yields the dynamic image over the generic threat-intel card.
  const b = /^\/threatintel\/briefings\/([a-z0-9-]{1,200})$/i.exec(url.pathname);
  if (b) {
    const image = `/api/v1/og-image/briefing/${b[1]}.png`;
    if (env.BRIEFINGS_DB) {
      try {
        const briefing = await readBriefing(env.BRIEFINGS_DB, b[1]!);
        if (briefing) {
          // Clamp to X/Twitter card limits: title ≤70, description ≤200 BYTES.
          const SUFFIX = ' · pranithjain.qzz.io';
          const maxTitle = 70 - Buffer.byteLength(SUFFIX, 'utf8');
          const rawTitle = clampToBytes(briefing.title, maxTitle);
          const description = clampToBytes(
            briefing.executive_summary || OG_OVERRIDES['/threatintel']!.description,
            199
          );
          return {
            title: `${rawTitle}${SUFFIX}`,
            description,
            image,
            imageAlt: description,
          };
        }
      } catch {
        /* fall through to the generic threat-intel card (still with the image) */
      }
    }
    return {
      ...(OG_OVERRIDES['/threatintel'] ?? { title: '', description: '' }),
      image,
      imageAlt: OG_OVERRIDES['/threatintel']?.description ?? '',
    };
  }

  const override = findOgOverride(url.pathname);
  // Branded surface with its own static card (e.g. /dfir, /threatintel, /radar,
  // /threatnexus) → use its explicit override verbatim. These are the polished
  // section cards generated by scripts/generate-og-png.mjs.
  if (override?.image && OG_OVERRIDES[url.pathname]) return override;
  // Every other URL gets a UNIQUE generated card keyed to its path, so each
  // page has its own og:image instead of inheriting the section landing card.
  // Home '/' has no derived/override meta → null → index.html's default home
  // card is kept.
  const meta = ogMetaForPath(url.pathname);
  if (!meta) return override ?? null;
  return {
    title: meta.title,
    description: meta.description,
    image: pageCardUrl(url.pathname),
    imageAlt: meta.description,
  };
}

/* ── Blog structured data ─────────────────────────────────────────────────
 * Blog content lives in CASE_STUDIES KV and the index/posts render
 * client-side, so non-JS crawlers (and rich-results) see no BlogPosting/Blog
 * schema. The worker has KV access, so it injects JSON-LD at the edge. */

/** Minimal shape of a blog record in CASE_STUDIES KV — only the fields used for
 *  structured data (mirrors api/src/case-study/types Post / PostIndexEntry). */
interface BlogRecord {
  slug: string;
  title: string;
  excerpt?: string;
  publishedAt?: string;
  updatedAt?: string;
  tags?: string[];
  body?: string;
}

const BLOG_AUTHOR = {
  '@type': 'Person',
  name: 'Pranith Jain',
  url: CANONICAL_ORIGIN,
  // sameAs disambiguates the author entity across platforms — matches the
  // client-side BlogPosting JSON-LD in src/pages/BlogPost.tsx.
  sameAs: ['https://www.linkedin.com/in/pranithjain', 'https://x.com/Npj8448'],
};

/** Serialize as a JSON-LD <script>. `type="application/ld+json"` is DATA, not
 *  executable script, so CSP script-src does not apply and no nonce is needed.
 *  `<` is escaped so an author-supplied title can't close the block. */
function ldScript(obj: unknown): string {
  return `<script type="application/ld+json">${JSON.stringify(obj).replace(/</g, '\\u003c')}</script>`;
}

function plainText(s: string, max: number): string {
  return s
    .replace(/<[^>]+>/g, '')
    .replace(/[#*`>_[\]]/g, '')
    .trim()
    .slice(0, max);
}

function blogPostingLd(post: BlogRecord): string {
  const url = `${CANONICAL_ORIGIN}/blog/${post.slug}`;
  return ldScript({
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: post.title,
    description: plainText(post.excerpt || post.body || '', 200),
    datePublished: post.publishedAt,
    dateModified: post.updatedAt || post.publishedAt,
    url,
    mainEntityOfPage: url,
    author: BLOG_AUTHOR,
    publisher: { '@type': 'Person', name: 'Pranith Jain' },
    ...(post.tags && post.tags.length > 0 ? { keywords: post.tags.join(', ') } : {}),
  });
}

function blogIndexLd(posts: BlogRecord[]): string {
  return ldScript({
    '@context': 'https://schema.org',
    '@type': 'Blog',
    name: 'Pranith Jain — Blog',
    url: `${CANONICAL_ORIGIN}/blog`,
    blogPost: posts.slice(0, 50).map((p) => ({
      '@type': 'BlogPosting',
      headline: p.title,
      description: plainText(p.excerpt || '', 160),
      datePublished: p.publishedAt,
      url: `${CANONICAL_ORIGIN}/blog/${p.slug}`,
      author: { '@type': 'Person', name: 'Pranith Jain' },
    })),
  });
}

/**
 * Build the blog JSON-LD <script> for blog routes, read once from KV at the
 * edge. Returns '' for non-blog routes or when data is unavailable —
 * structured data is best-effort and never blocks the page. The result is
 * cached alongside the OG-rewritten HTML (pathname@etag), so it follows the
 * same ~1-day staleness window as the per-route OG metadata.
 */
export async function resolveBlogJsonLd(url: URL, env: Env): Promise<string> {
  if (!env.CASE_STUDIES) return '';
  try {
    const m = /^\/blog\/([a-z0-9-]{1,200})$/.exec(url.pathname);
    if (m && m[1] !== 'index') {
      const post = await readBlogPostShadowed<BlogRecord>(env, m[1]!);
      return post?.title ? blogPostingLd(post) : '';
    }
    if (url.pathname === '/blog') {
      const index = ((await readBlogIndexShadowed<BlogRecord[]>(env)) ?? []) as BlogRecord[];
      return index.length > 0 ? blogIndexLd(index) : '';
    }
  } catch {
    /* never let a KV hiccup blank the page */
  }
  return '';
}

/**
 * Routes that must be served `noindex`: ONLY the credential-input surfaces —
 * some DFIR tools read a password/passphrase/API key in a masked field, and
 * Google Safe Browsing classifies a masked password field on a non-login page
 * as credential harvesting ("Possible Phishing Detected on User Login"); the
 * admin login is private. These are kept CRAWLABLE (noindex, not robots
 * Disallow) on purpose — Google must be able to re-crawl a flagged page to
 * confirm it is clean and lift a Safe Browsing warning; Disallow would block
 * that re-review. /admin is additionally Disallow-ed in robots.txt (it is
 * genuinely private and never needs a Safe Browsing re-review).
 *
 * IMPORTANT: this list must stay minimal. Every content page with no
 * credential input must be indexable — an over-broad list lands dozens of
 * legitimate tool/darkweb/malware/phishing CONTENT pages in Google's
 * "Pages with noindex" report (Search Console "page indexing"): those pages
 * have no password fields and the Safe Browsing rationale does not apply.
 * The og-rewriter contract test (src/test/og-rewriter.contract.test.ts)
 * asserts noindex on exactly these surfaces and index everywhere else.
 */
const NOINDEX_PREFIXES = [
  '/dfir/breach',
  '/dfir/phishing',
  '/threatintel/telegram-leaks/channels',
  '/threatintel/misp-browser',
  '/admin',
];
function shouldNoindex(pathname: string): boolean {
  return NOINDEX_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/**
 * Mutate the static index.html so the OG / Twitter / canonical metadata
 * reflects the actual route. Only kicks in for HTML responses (asset router
 * returns text/html for SPA fallback paths). Anything else passes through.
 */
export async function injectOgMeta(
  response: Response,
  url: URL,
  env: Env,
  ctx: ExecutionContext,
  nonce?: string
): Promise<Response> {
  const etag = nonce ? (response.headers.get('etag') ?? response.headers.get('last-modified') ?? '') : '';
  if (etag) {
    const cacheKey = new Request(
      `https://og-html.internal/${OG_CACHE_VERSION}/${OG_BUILD_VERSION}/${encodeURIComponent(url.host)}${url.pathname}@${encodeURIComponent(etag)}`
    );
    const cached = await caches.default.match(cacheKey);
    const cachedText = cached ? await cached.text() : '';
    // Ignore a cached EMPTY body — a poisoned entry (see the write guard
    // below) must self-heal on the next request, not be served for the TTL.
    if (cached && cachedText.length > 0) {
      const body = nonce ? injectScriptNonce(cachedText, nonce) : cachedText;
      return new Response(body, {
        headers: {
          'content-type': cached.headers.get('content-type') ?? 'text/html;charset=UTF-8',
        },
      });
    }
  }

  const html = await response.text();
  // Never rewrite or cache a non-OK / empty upstream. A 304 or an empty read
  // during an asset-propagation race at deploy time would otherwise be cached
  // under `pathname@etag` and served blank for the full TTL — this is exactly
  // what blanked `/` and `/blog` on 2026-06-02. Returning the body uncached
  // lets the very next request re-read the (normally non-empty) asset.
  if (!response.ok || html.length === 0) {
    return new Response(html, {
      status: response.status,
      statusText: response.statusText,
      headers: { 'content-type': response.headers.get('content-type') ?? 'text/html;charset=UTF-8' },
    });
  }
  const ogOverride = await resolveOg(url, env);
  const blogLd = await resolveBlogJsonLd(url, env);
  let ogRewritten = rewriteHtml(html, ogOverride, canonicalUrlFor(url, env), undefined, url.pathname);
  if (blogLd) ogRewritten = ogRewritten.replace(/<\/head>/i, `${blogLd}</head>`);
  if (shouldNoindex(url.pathname)) {
    ogRewritten = ogRewritten.replace(
      /<meta\s+name="robots"\s+content="[^"]*"/i,
      '<meta name="robots" content="noindex, follow"'
    );
  }
  const final = nonce ? injectScriptNonce(ogRewritten, nonce) : ogRewritten;

  const result = new Response(final, {
    headers: {
      'content-type': response.headers.get('content-type') ?? 'text/html;charset=UTF-8',
    },
  });

  if (etag && ogRewritten.length > 0) {
    const toCache = new Response(ogRewritten, {
      headers: {
        'content-type': response.headers.get('content-type') ?? 'text/html;charset=UTF-8',
        'cache-control': `public, max-age=${OG_CACHE_TTL_SECONDS}`,
      },
    });
    const ck = new Request(
      `https://og-html.internal/${OG_CACHE_VERSION}/${OG_BUILD_VERSION}/${encodeURIComponent(url.host)}${url.pathname}@${encodeURIComponent(etag)}`
    );
    ctx.waitUntil(caches.default.put(ck, toCache).catch((e) => console.warn('og-html cache put failed:', e)));
  }

  return result;
}

/**
 * Cache the OG-rewritten HTML in the Cache API, keyed by `pathname @ etag`.
 *
 * Why the etag matters: a redeploy bumps Vite's chunk hashes inside index.html,
 * so the rewritten HTML now references new <script src> filenames. The OLD
 * filenames are deleted from the assets binding on deploy. If we cached only
 * by pathname, users would hit stale HTML referencing deleted bundles and
 * get 404s on the chunk fetch for up to TTL.
 *
 * The asset binding's etag is content-derived, so on every redeploy the
 * underlying index.html gets a new etag → new cache key → cold rewrite →
 * cached version always matches the assets currently on disk. That makes
 * it safe to use a much longer TTL than the 10 min we'd need without the
 * etag suffix; 1d gives us very high hit rate with zero staleness risk.
 */
export async function getOrInjectOg(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  const assetRes = await env.ASSETS.fetch(request);
  const ct = assetRes.headers.get('content-type') ?? '';
  if (!ct.toLowerCase().includes('text/html')) {
    // Image responses (OG cards, OG PNGs, blog illustrations) must NOT carry
    // x-frame-options: DENY — social platforms (X/Twitter, LinkedIn, Facebook,
    // Slack) fetch the twitter:image / og:image URL to render a preview card;
    // x-frame-options: DENY causes their validators to reject the image and
    // show no preview. The ASSETS binding adds x-frame-options: DENY by default;
    // strip it for image responses so OG images render correctly.
    if (ct.toLowerCase().startsWith('image/')) {
      const h = new Headers(assetRes.headers);
      h.delete('x-frame-options');
      h.delete('content-security-policy');
      h.delete('content-security-policy-report-only');
      return new Response(assetRes.body, {
        status: assetRes.status,
        statusText: assetRes.statusText,
        headers: h,
      });
    }
    return assetRes;
  }

  const etag = assetRes.headers.get('etag') ?? assetRes.headers.get('last-modified') ?? 'unversioned';
  const cache = caches.default;
  const cacheKey = new Request(
    `https://og-html.internal/${OG_CACHE_VERSION}/${OG_BUILD_VERSION}/${encodeURIComponent(url.host)}${url.pathname}@${encodeURIComponent(etag)}`
  );
  const cached = await cache.match(cacheKey);
  // Poisoned-cache guard. An empty cached body was being served to SPA
  // shell + 404-fallback responses on 2026-06-02 — the asset-propagation
  // race (see injectOgMeta's sibling guard) can write a zero-length body
  // here too, so check the length before serving. A clone is read so the
  // returned `cached` Response still has its body intact.
  if (cached) {
    const peeked = await cached.clone().text();
    if (peeked.length > 0) return cached;
  }

  const withOg = await injectOgMeta(assetRes, url, env, ctx);
  // Don't cache an empty body — the asset-propagation race at deploy
  // time can produce a 0-length read; serving that from cache for the
  // full TTL is the bug that hit `/`, `/blog`, and the 404 routes today.
  if (withOg.body) {
    const toCache = new Response(withOg.clone().body, {
      status: withOg.status,
      statusText: withOg.statusText,
      headers: (() => {
        const h = new Headers(withOg.headers);
        h.set('cache-control', `public, max-age=${OG_CACHE_TTL_SECONDS}`);
        return h;
      })(),
    });
    ctx.waitUntil(cache.put(cacheKey, toCache));
  }
  return withOg;
}
