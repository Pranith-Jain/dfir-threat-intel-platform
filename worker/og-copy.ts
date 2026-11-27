/**
 * Pure OG copy-resolution: per-route title/description/branding for ANY URL.
 *
 * Single source of truth consumed by BOTH sides of the card pipeline:
 *   - worker/og-rewriter.ts — rewrites served <head> meta at the edge
 *   - worker/og-data.ts — dynamic rasterizer text
 *   - scripts/generate-page-og.mjs (via an esbuild bundle) — build-time KV
 *     card text, so the PNG a crawler fetches says the same thing the meta
 *     tags promise. Before this module the generator trusted prerendered
 *     Helmet <title>s, which never render for Suspense-lazy pages — 268 of
 *     269 KV cards baked the shell's home copy (only 4 distinct images).
 *
 * Deliberately import-free except for the route list: must stay loadable in
 * plain Node (build scripts) AND inside the Workers bundle.
 */
import { PRERENDERED_ROUTES } from './prerender-routes';

/**
 * Per-route social metadata overrides. The SPA serves the same index.html
 * for every path, so without rewriting the OG tags at the edge, any social-
 * media bot that fetches `/threatintel/correlation` sees the portfolio-root
 * meta and routes preview-clicks back to `/`.
 *
 * Lookup is exact-match first, then longest-matching prefix (so
 * `/threatintel/anything-else` still inherits the `/threatintel` card).
 */
export interface OgOverride {
  title: string;
  description: string;
  /**
   * Optional per-surface OG image. When set, the worker rewrites
   * `og:image` + `twitter:image` to this URL so a share-preview of
   * /threatintel renders the CTI card, /dfir renders the toolkit card,
   * and everything else falls back to the portfolio default in
   * index.html. Use a relative path; the worker joins it with the
   * canonical origin.
   */
  image?: string;
  /**
   * Alt text for the OG image. When `image` is set, the worker rewrites
   * `og:image:alt` + `twitter:image:alt` to this value so the alt text
   * matches the page-specific card instead of the generic homepage alt.
   * If omitted when `image` is set, falls back to `description`.
   */
  imageAlt?: string;
}
/**
 * Clamp a string so its UTF-8 byte length stays within `maxBytes`. Some
 * social-preview validators (and X's crawler in some modes) count bytes, not
 * codepoints — an em-dash (—) is 1 char but 3 bytes. Slicing by `.length`
 * leaves multi-byte titles over the byte limit. This trims on codepoints but
 * re-checks the byte length, appending an ellipsis (3 bytes) when truncated.
 */
export function clampToBytes(s: string, maxBytes: number): string {
  if (Buffer.byteLength(s, 'utf8') <= maxBytes) return s;
  const ELLIPSIS = '…';
  const ellipsisBytes = Buffer.byteLength(ELLIPSIS, 'utf8');
  // Walk back codepoint-by-codepoint until (trimmed + ellipsis) fits.
  const chars = [...s];
  let trimmed = chars.join('');
  while (Buffer.byteLength(trimmed, 'utf8') + ellipsisBytes > maxBytes && chars.length > 0) {
    chars.pop();
    trimmed = chars.join('');
  }
  return trimmed.trimEnd() + ELLIPSIS;
}
export const OG_OVERRIDES: Record<string, OgOverride> = {
  '/about': {
    title: 'About Pranith Jain · Security Engineer & Detection Engineer',
    description:
      'Security engineer working across DFIR, threat intelligence, detection engineering, and cloud security. Background, focus areas, and how to get in touch.',
  },
  '/skills': {
    title: 'Security Skills · DFIR, Threat Intel & Detection Engineering',
    description:
      'Capabilities across digital forensics & incident response, threat intelligence, detection engineering, cloud & application security, and security automation.',
  },
  '/experience': {
    title: 'Experience · pranithjain.qzz.io',
    description: 'Professional experience and roles in security engineering, DFIR, and threat intelligence.',
  },
  '/projects': {
    title: 'Security Projects & Case Studies · Pranith Jain',
    description:
      'Selected security projects and case studies — detection tooling, threat-intel platforms, and DFIR utilities built and shipped on the edge.',
  },
  '/blog': {
    title: 'Security Blog · Threat Intelligence & DFIR Write-ups',
    description:
      'Writing on threat intelligence, detection engineering, DFIR, and cloud security — field notes, deep dives, and analysis.',
  },
  // The two highest-value organic-search surfaces previously fell through to
  // index.html's 97-char home <title>; give them their own short cards.
  '/dfir': {
    title: 'CRUCIBLE · Free DFIR Toolkit & IOC Analyzer',
    description:
      'CRUCIBLE — 90+ free, browser-side DFIR tools: IOC checker, CVE prioritizer, crypto tracer, decoders, YARA/Sigma converter. No signup.',
    image: '/og-dfir.png',
    imageAlt: 'CRUCIBLE DFIR toolkit — 90+ free browser-side digital forensics and incident response tools',
  },
  '/radar': {
    title: 'SCOUT · Free Web Recon & Security Scanner',
    description:
      'SCOUT — deep crawl, JS analysis, API discovery, secret detection, and 0-100 security scoring. Free, browser-driven recon.',
    image: '/og-scout.png',
    imageAlt: 'SCOUT recon scanner — deep crawl, JS analysis, API discovery, and security scoring',
  },
  '/copilot': {
    title: 'CTI Copilot',
    description:
      'An agentic CTI assistant that investigates indicators, actors, and CVEs across the platform feeds and returns a sourced, structured briefing.',
  },
  '/threatintel': {
    title: 'PANOPTICON · Threat Intel Platform',
    description:
      'PANOPTICON — live ransomware leaks, CVE × CISA KEV, cross-source IOC correlation, actor × MITRE, STIX 2.1 export. Edge-hosted and free.',
    image: '/og-threatintel.png',
    imageAlt: 'PANOPTICON threat intel platform — live ransomware leaks, CVE/KEV, IOC correlation, and STIX export',
  },
  '/threatintel/external-resources': {
    title: 'External Resources Catalog · pranithjain.qzz.io',
    description:
      'Off-site cross-references for threat-intel work — CTI dashboards, OSINT directories, training labs, malware samples, AI-security research.',
  },
  '/threatintel/facilities': {
    title: 'Facilities Database · pranithjain.qzz.io',
    description:
      'Strategic facilities worldwide — conflict zones, military bases, nuclear sites, disputed territories, sanctions targets, and critical infrastructure. Map view.',
  },
  '/threatnexus': {
    title: 'ARGUS · Threat Actor & Campaign Intelligence',
    description:
      'ARGUS — nation-state threat intel dashboard with 3D globe, actor dossiers, relationship graphs, and live threat feeds. Interactive D3 + three.js.',
    image: '/og-argus.png',
    imageAlt: 'ARGUS threat nexus — nation-state dashboard with 3D globe, actor dossiers, and relationship graphs',
  },
  '/threatintel/correlation': {
    title: 'Cross-source IOC correlation · pranithjain.qzz.io',
    description:
      'Indicators that appear in 2+ independent IOC feeds, ranked by source consensus. 18 feeds aggregated — overlap is the signal analysts trust.',
  },
  '/threatintel/live-iocs': {
    title: 'Live IOC stream · pranithjain.qzz.io',
    description:
      'Chronological firehose of individual indicators. Each entry carries a reporter handle, source feed, and first-observed timestamp across 10 sources.',
  },
  '/threatintel/detections': {
    title: 'Detections · pranithjain.qzz.io',
    description:
      'A detection-rule pack evaluated hourly against the live IOC stream. Cross-feed consensus, C2 + ransomware tagging, and phishing-campaign clustering.',
  },
  '/dfir/detection-lab': {
    title: 'Detection Lab · pranithjain.qzz.io',
    description:
      'Write a detection rule in a small JSON DSL and evaluate it in your browser against the live multi-feed IOC stream. Save, export, and re-use.',
  },
  '/dfir/rule-converter': {
    title: 'Rule Converter · pranithjain.qzz.io',
    description:
      'Universal detection-rule translation — Sigma, KQL, Splunk SPL, Elastic Lucene & EQL, YARA, DLP regex, and Semgrep. 100% client-side.',
  },
  '/dfir/netdraw': {
    title: 'NetDraw — Network Diagrams · pranithjain.qzz.io',
    description:
      'Browser-based network topology and architecture diagram editor. Drag-and-drop nodes, draw connections, build guided walkthroughs for DFIR, SOC, cloud security.',
  },
};

export function findOgOverride(pathname: string): OgOverride | null {
  const matches: Array<{ key: string; value: OgOverride }> = [];
  for (const [k, v] of Object.entries(OG_OVERRIDES)) {
    if (k === pathname || pathname.startsWith(`${k}/`)) {
      matches.push({ key: k, value: v });
    }
  }
  if (matches.length === 0) return null;

  matches.sort((a, b) => a.key.length - b.key.length);

  let merged: OgOverride = { title: '', description: '' };
  for (const { key, value } of matches) {
    if (key === pathname) {
      // EXACT match is authoritative: replace wholesale, don't field-merge.
      // Field-wise ?? merging let a parent's branded image (e.g. /dfir →
      // og-dfir.png) survive into a child that has its own exact entry WITHOUT
      // an image (e.g. /dfir/rule-converter); resolveOg then saw override.image
      // + an exact OG_OVERRIDES key and served the hub banner instead of the
      // child's unique generated card. An exact entry's absent image must
      // CLEAR the inherited one so the child falls through to pageCardUrl().
      merged = { ...value };
      continue;
    }
    merged = {
      title: value.title ?? merged.title,
      description: value.description ?? merged.description,
      image: value.image ?? merged.image,
      imageAlt: value.imageAlt ?? merged.imageAlt,
    };
  }
  return merged;
}
export interface OgPageMeta {
  title: string;
  description: string;
  /** Top type badge, e.g. "DFIR TOOLKIT". */
  badge: string;
  /** Footer product family, e.g. "PANOPTICON". */
  product: string;
}

/**
 * Resolve the best title/description + section branding for ANY route, so the
 * dynamic page-card generator (worker/og-data.ts) renders a card whose text
 * matches the meta tags the rewriter serves for the same URL.
 *
 * Title/description precedence:
 *   1. Hand-tuned `OG_OVERRIDES` exact match (polished copy)
 *   2. `deriveOgFromPath` (mechanical slug-derived fallback)
 *   3. `OG_OVERRIDES` prefix match (section branding)
 * Returns null only for the home page (which keeps the static home card).
 */
export function ogMetaForPath(pathname: string): OgPageMeta | null {
  const exact = OG_OVERRIDES[pathname];
  const override = findOgOverride(pathname);
  const derived = deriveOgFromPath(pathname);
  // The generated per-route map previously sat between `exact` and `derived`
  // here. It was removed (see file header) — deep links now fall through to
  // the slug-derived title/description, which is always ≥55 chars (X-card-valid).
  const title = exact?.title ?? derived?.title ?? override?.title;
  const description = exact?.description ?? derived?.description ?? override?.description;
  if (!title || !description) return null;

  const first = pathname.split('/').filter(Boolean)[0] ?? '';
  const badge =
    first === 'dfir'
      ? 'DFIR TOOLKIT'
      : first === 'threatintel'
        ? 'THREAT INTEL'
        : first === 'radar'
          ? 'RECON SCANNER'
          : first === 'blog'
            ? 'BLOG POST'
            : 'SECURITY TOOLS';
  const product =
    first === 'threatintel'
      ? 'PANOPTICON'
      : first === 'radar'
        ? 'SCOUT'
        : first === 'threatnexus'
          ? 'ARGUS'
          : 'CRUCIBLE';

  // Byte-clamp to X/Twitter card limits (some validators count UTF-8 bytes).
  return { title: clampToBytes(title, 70), description: clampToBytes(description, 200), badge, product };
}

/**
 * Last-segment titles collide when two sections expose the same slug tail
 * (e.g. /threatintel/catalog vs /threatintel/feeds/catalog both derived
 * "Catalog · Threat Intel" — five such pairs were live). Computed once from
 * the prerendered route list: every tail that appears under 2+ distinct
 * parent paths. deriveOgFromPath consults this to build two-segment titles
 * ONLY for colliding tails, so non-colliding routes keep byte-identical
 * output and the fix costs nothing at request time beyond one Set lookup.
 */
const COLLIDING_TAILS: Set<string> = (() => {
  const parentsByTail = new Map<string, Set<string>>();
  for (const route of PRERENDERED_ROUTES.keys()) {
    if (route === '/') continue;
    const segs = route.split('/').filter(Boolean);
    if (segs.length < 1) continue;
    const tail = segs[segs.length - 1]!;
    const parent = segs.length > 1 ? segs.slice(0, -1).join('/') : '';
    let set = parentsByTail.get(tail);
    if (!set) parentsByTail.set(tail, (set = new Set()));
    set.add(parent);
  }
  const colliding = new Set<string>();
  for (const [tail, parents] of parentsByTail) {
    // Same tail under different parent chains (root '' counts as one) → ambiguous.
    if (parents.size > 1) colliding.add(tail);
  }
  return colliding;
})();

/** Words that must keep specific branding in generated titles even though
 *  they're longer than the existing ≤3-char rule (mapped to their exact site
 *  spelling — e.g. IOCs, not IOCS). */
const TITLE_ACRONYMS: Record<string, string> = {
  ioc: 'IOC',
  iocs: 'IOCs',
  osint: 'OSINT',
  cve: 'CVE',
  cves: 'CVEs',
  dfir: 'DFIR',
  apt: 'APT',
  yara: 'YARA',
  stix: 'STIX',
  misp: 'MISP',
  llm: 'LLM',
  api: 'API',
  hub: 'Hub',
};

function titleCaseWord(w: string): string {
  const branded = TITLE_ACRONYMS[w];
  if (branded) return branded;
  if (w.length <= 3) return w.toUpperCase();
  return w.charAt(0).toUpperCase() + w.slice(1);
}
/**
 * Fallback OG override derived from the URL path. When no explicit
 * OG_OVERRIDES entry matches, the page would otherwise keep the home-page
 * <title> and <meta description> — meaning hundreds of deep links share
 * identical metadata, which Google reads as duplicate/thin content and
 * flags as "Crawled - currently not indexed."
 *
 * This generates a unique, human-readable title + description from the last
 * path segment so every page at least has its own title. When that tail is
 * ambiguous (COLLIDING_TAILS), the parent segment is folded in so two
 * sections' same-named tools don't share metadata. The home page and root
 * sections are excluded (they have explicit overrides or should keep the
 * home card).
 */
function deriveOgFromPath(pathname: string): OgOverride | null {
  if (pathname === '/' || pathname === '') return null;
  const segments = pathname.split('/').filter(Boolean);
  if (segments.length === 0) return null;

  const last = segments[segments.length - 1]!;
  const wordsOf = (seg: string) => seg.split(/[-_]/);
  // Ambiguous tail → include the parent segment ("feeds catalog", "iocs map")
  // so each section's tool gets distinct copy. Skip folding when the immediate
  // parent IS the top-level section (/threatintel/catalog → parent 'threatintel'
  // is already conveyed by "· Threat Intel ·" in the title suffix), otherwise
  // the fold just duplicates it ("Threatintel Catalog"). Single-segment routes
  // and non-colliding tails keep today's exact output.
  const foldParent = segments.length > 2 && COLLIDING_TAILS.has(last) && segments[segments.length - 2] !== segments[0];
  const titleSegs = foldParent ? segments.slice(-2) : [last];
  const titlePart = titleSegs.flatMap(wordsOf).map(titleCaseWord).join(' ');

  // Build a short context prefix from the first segment: "dfir" → "DFIR", "threatintel" → "Threat Intel"
  const first = segments[0]!;
  const sectionLabel =
    first === 'dfir'
      ? 'DFIR'
      : first === 'threatintel'
        ? 'Threat Intel'
        : first === 'blog'
          ? 'Blog'
          : first.charAt(0).toUpperCase() + first.slice(1);

  // Single-segment routes used to produce 20-29 char titles ("Skills ·
  // pranithjain.qzz.io"), below the 30-char SEO floor. Add a stable context
  // phrase instead of dropping the brand, so every derived title lands in the
  // 30-60 character sweet spot.
  const title =
    segments.length > 1
      ? `${titlePart} · ${sectionLabel} · pranithjain.qzz.io`
      : `${titlePart} · Security Tools & Intel · pranithjain.qzz.io`;
  const description = `${titlePart} — a free ${sectionLabel} tool on pranithjain.qzz.io. Browser-side security analysis, no signup required.`;
  // Byte-clamp to X/Twitter card limits (some validators count UTF-8 bytes).
  return { title: clampToBytes(title, 70), description: clampToBytes(description, 200) };
}
