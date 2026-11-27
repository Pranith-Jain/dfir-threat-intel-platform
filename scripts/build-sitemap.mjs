#!/usr/bin/env node
/**
 * Auto-generate `public/sitemap.xml` from:
 *   1. The `ROUTES` array in `scripts/prerender.mjs` (single source of
 *      truth for routes that should be in the sitemap)
 *   2. Published case studies in `src/data/case-studies.ts`
 *   3. Published research articles in `src/data/threatintel/research.ts`
 *
 * Why: previously the sitemap was hand-edited and silently drifted from
 * the prerender list (5–9 routes were missing on most audits). This
 * script regenerates from the same constants the rest of the build uses,
 * so the sitemap can never disagree with what's actually deployed.
 *
 * Run via:
 *   node scripts/build-sitemap.mjs
 *
 * Wired into the build pipeline via `prebuild` (see package.json). Can
 * also be run manually as a sanity check.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const TODAY_ISO = new Date().toISOString().slice(0, 10);
const BASE_URL = 'https://pranithjain.qzz.io';

// Mirrors wrangler.jsonc#vars.TOOLS_HOSTS (and TOOL_HOSTS_BY_PATH in
// src/lib/surface.ts) so a `<loc>` never disagrees with the canonical the
// Worker serves for that same path — Google treats that mismatch as a signal
// to ignore one of the two. Only prefixes whose hostname actually resolves may
// appear here: a sitemap URL on a host with no DNS record is wasted crawl.
const TOOL_HOSTS = {
  '/dfir': 'crucible.pranithjain.qzz.io',
  '/threatintel': 'panopticon.pranithjain.qzz.io',
  '/radar': 'scout.pranithjain.qzz.io',
};

/** Origin that owns `path` — longest segment-aware prefix match, else apex.
 *  Same rule as `toolHostForPath` in api/src/lib/surface-hosts.ts. */
function originFor(path) {
  let best = null;
  for (const [prefix, host] of Object.entries(TOOL_HOSTS)) {
    if (path === prefix || path.startsWith(`${prefix}/`)) {
      if (!best || prefix.length > best.length) best = prefix;
    }
  }
  return best ? `https://${TOOL_HOSTS[best]}` : BASE_URL;
}

function quote(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function readPrerenderRoutes() {
  const src = readFileSync(resolve(ROOT, 'scripts/prerender.mjs'), 'utf-8');
  // Match every `'/<path>'` string literal in the ROUTES array. The
  // array is the only place the prerender script enumerates paths.
  const matches = src.match(/^  '(\/[^']*)'/gm) ?? [];
  return matches.map((m) => m.replace(/^  '|'$/g, ''));
}

function readPublishedCaseStudySlugs() {
  const path = resolve(ROOT, 'src/data/case-studies.ts');
  if (!existsSync(path)) return [];
  const src = readFileSync(path, 'utf-8');
  // Find every `slug: 'foo'` pair where the surrounding object also
  // has `published: true`. Approximates `publishedCaseStudies` (which
  // also sorts but ordering doesn't matter for a sitemap).
  const blocks = src.split(/\{\s*slug:/);
  const slugs = [];
  for (let i = 1; i < blocks.length; i++) {
    const block = blocks[i].split(/\}/)[0];
    const slugMatch = block.match(/^\s*'([^']+)'/);
    if (!slugMatch) continue;
    if (!/published:\s*true/.test(block)) continue;
    slugs.push(slugMatch[1]);
  }
  return slugs;
}

function readPublishedResearchSlugs() {
  const path = resolve(ROOT, 'src/data/threatintel/research.ts');
  if (!existsSync(path)) return [];
  const src = readFileSync(path, 'utf-8');
  // Same heuristic as case-studies: find every published post.
  const blocks = src.split(/\{\s*slug:/);
  const slugs = [];
  for (let i = 1; i < blocks.length; i++) {
    const block = blocks[i].split(/\}/)[0];
    const slugMatch = block.match(/^\s*'([^']+)'/);
    if (!slugMatch) continue;
    if (!/published:\s*true/.test(block)) continue;
    slugs.push(slugMatch[1]);
  }
  return slugs;
}

/**
 * Blog posts live in CASE_STUDIES KV (not a local data file), so the static
 * build can't read them. Best-effort fetch the published list from the LIVE
 * deployed API; on ANY failure the build still succeeds (just without
 * /blog/<slug> entries this run). The worker-injected BlogPosting JSON-LD and
 * per-post OG card still cover the SEO basics when this is skipped.
 */
async function fetchBlogPosts() {
  const url = `${BASE_URL}/api/v1/blog/posts`;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'user-agent': 'build-sitemap' } });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const posts = Array.isArray(data?.posts) ? data.posts : [];
    return posts
      .filter((p) => p && typeof p.slug === 'string' && /^[a-z0-9-]+$/.test(p.slug) && p.slug !== 'index')
      .map((p) => ({ slug: p.slug, lastmod: (p.publishedAt || '').slice(0, 10) || undefined }));
  } catch (err) {
    console.warn(`build-sitemap: skipping /blog/<slug> entries (live API unreachable: ${err.message})`);
    return [];
  }
}

function classifyRoute(path) {
  // Returns { changefreq, priority, group } for a given prerender path.
  // The group is used to emit the right "<!-- group -->" comment in the
  // output so the sitemap stays human-readable.
  if (path === '/') return { changefreq: 'weekly', priority: '1.0', group: 'Portfolio' };
  if (['/about', '/skills', '/experience'].includes(path))
    return { changefreq: 'monthly', priority: '0.8', group: 'Portfolio' };
  if (path === '/projects') return { changefreq: 'weekly', priority: '0.9', group: 'Portfolio' };
  if (path === '/blog') return { changefreq: 'weekly', priority: '0.6', group: 'Portfolio' };
  if (path === '/dfir' || path === '/threatintel')
    return { changefreq: 'daily', priority: '0.9', group: 'Landings' };
  if (path.startsWith('/dfir/'))
    return { changefreq: 'monthly', priority: '0.7', group: 'DFIR tools' };
  if (path.startsWith('/threatintel/research'))
    return { changefreq: 'monthly', priority: '0.6', group: 'Threat Intel — research' };
  if (path.startsWith('/threatintel/'))
    return { changefreq: 'weekly', priority: '0.7', group: 'Threat Intel — pages' };
  return { changefreq: 'monthly', priority: '0.5', group: 'Misc' };
}

function entryFor(path, opts = {}) {
  const cls = classifyRoute(path);
  return [
    '  <url>',
    `    <loc>${quote(originFor(path) + path)}</loc>`,
    `    <lastmod>${opts.lastmod ?? TODAY_ISO}</lastmod>`,
    `    <changefreq>${opts.changefreq ?? cls.changefreq}</changefreq>`,
    `    <priority>${opts.priority ?? cls.priority}</priority>`,
    '  </url>',
  ].join('\n');
}

function buildSitemap(blogPosts = []) {
  // Guard against a path appearing in two source lists (prerender ROUTES has
  // done this before): a duplicate <loc> is a sitemap quality error and wastes
  // crawl budget. Keep the first entry for each final URL.
  const seen = new Set();
  const uniqueEntry = (path, opts) => {
    const entry = entryFor(path, opts);
    const loc = entry.match(/<loc>([^<]+)<\/loc>/)?.[1];
    if (!loc || seen.has(loc)) return null;
    seen.add(loc);
    return entry;
  };

  const prerenderRoutes = readPrerenderRoutes();
  const caseStudySlugs = readPublishedCaseStudySlugs();
  const researchSlugs = readPublishedResearchSlugs();

  // Exclude malware/sample-related pages from the sitemap — Google Safe
  // Browsing flags these as "uncommon download" or "malware" warnings.
  // These are analysis tools, not download sites, but Google's heuristic
  // treats them the same. Keep them accessible (just not indexed).
  const SITEMAP_EXCLUDED = new Set([
    '/threatintel/malware-vault',
    '/threatintel/malware-sandbox',
    '/threatintel/malware/vault',
    '/threatintel/malware/sandbox',
    '/dfir/malware-scan',
    '/dfir/sample-scan',
    '/dfir/sandbox',
    // /admin is Disallow'd in robots.txt AND noindex'd at the edge —
    // including it in the sitemap sends conflicting signals to Google
    // ("index this" vs "don't crawl/index this"), which hurts crawl
    // efficiency and can trigger "Crawled - currently not indexed".
    '/admin',
  ]);

  // Group prerender routes by their classifier group so the output keeps
  // the same sectioned layout the hand-edited sitemap had.
  const grouped = new Map();
  for (const path of prerenderRoutes) {
    if (SITEMAP_EXCLUDED.has(path)) continue;
    const { group } = classifyRoute(path);
    if (!grouped.has(group)) grouped.set(group, []);
    grouped.get(group).push(path);
  }

  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ];

  // Emit grouped prerender routes in the order they appear.
  for (const [group, paths] of grouped) {
    const entries = paths.map((path) => uniqueEntry(path)).filter(Boolean);
    lines.push(`  <!-- ${group} (${entries.length}) -->`);
    lines.push(...entries);
  }

  // Case studies (read from src/data/case-studies.ts)
  {
    const entries = caseStudySlugs
      .map((slug) => uniqueEntry(`/projects/${slug}`, { changefreq: 'yearly', priority: '0.8' }))
      .filter(Boolean);
    if (entries.length) {
      lines.push(`  <!-- Case studies (${entries.length}) -->`);
      lines.push(...entries);
    }
  }

  // Research articles (read from src/data/threatintel/research.ts)
  {
    const entries = researchSlugs
      .map((slug) => uniqueEntry(`/threatintel/research/${slug}`, { changefreq: 'monthly', priority: '0.6' }))
      .filter(Boolean);
    if (entries.length) {
      lines.push(`  <!-- Research articles (${entries.length}) -->`);
      lines.push(...entries);
    }
  }

  // Blog posts (fetched from the live KV-backed API; best-effort)
  {
    const entries = blogPosts
      .map(({ slug, lastmod }) => uniqueEntry(`/blog/${slug}`, { changefreq: 'monthly', priority: '0.6', lastmod }))
      .filter(Boolean);
    if (entries.length) {
      lines.push(`  <!-- Blog posts (${entries.length}) -->`);
      lines.push(...entries);
    }
  }

  lines.push('</urlset>');
  return {
    xml: lines.join('\n') + '\n',
    counts: {
      prerender: prerenderRoutes.length,
      caseStudies: caseStudySlugs.length,
      research: researchSlugs.length,
      blog: blogPosts.length,
      total: prerenderRoutes.length + caseStudySlugs.length + researchSlugs.length + blogPosts.length,
    },
  };
}

async function main() {
  const blogPosts = await fetchBlogPosts();
  const { xml, counts } = buildSitemap(blogPosts);
  const outPath = resolve(ROOT, 'public/sitemap.xml');
  await writeFile(outPath, xml, 'utf-8');
  console.log(
    `sitemap: wrote ${outPath} (${counts.total} urls — ${counts.prerender} prerender + ${counts.caseStudies} case studies + ${counts.research} research + ${counts.blog} blog)`
  );
}

main().catch((err) => {
  console.error('build-sitemap failed:', err);
  process.exit(1);
});
