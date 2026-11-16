#!/usr/bin/env node
/**
 * Sync the AX Intel Tools directory (tools.axi68.com) into site data.
 *
 * Upstream is a static Vercel site (no JSON API; /wp-json is 403) whose
 * homepage carries the whole directory as server-rendered markup:
 *   <div class="card" data-cat="Threat Intelligence"
 *        data-s="lowercased search text">
 *     <h3><a href="https://...">Tool name</a></h3>
 *     <div class="meta"><a class="tag" href="/category/slug/">Category</a>
 *     <span class="tag free">Free</span></div>
 *     <p>Practitioner note.</p></div>
 *
 * Staging (threat-intel-staging/axi68-tools/): raw.html snapshot.
 * Site data (public/data/axi68-tools/): index.json with every tool entry,
 * category rollup and upstream lastmod from the sitemap.
 *
 * Run: node scripts/sync-axi68-tools.mjs
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'axi68-tools');
const OUT = join(ROOT, 'public', 'data', 'axi68-tools');
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const BASE = 'https://tools.axi68.com';

async function fetchText(url) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: 'text/html,*/*' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`fetch failed: ${url} -> ${res.status} ${res.statusText}`);
  return await res.text();
}

function decodeEntities(s) {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#x27;/g, "'")
    .trim();
}

/**
 * Parse every directory card out of the homepage HTML. Cards are adjacent
 * `<div class="card" data-cat=...>` blocks, each ending in `</p></div>`;
 * anchoring on the closing pair keeps the last card (the lookahead-based
 * terminator lost it when the grid wrapper closes right after).
 */
function parseCards(html) {
  const tools = [];
  const cardRe = /<div class="card" data-cat="([^"]*)"[^>]*>([\s\S]*?)<\/p>\s*<\/div>/g;
  let m;
  while ((m = cardRe.exec(html)) !== null) {
    const cat = decodeEntities(m[1]);
    const body = m[2];
    const link = body.match(/<h3><a href="([^"]+)"[^>]*>([\s\S]*?)<\/a><\/h3>/);
    if (!link) continue;
    const pricing = body.match(/<span class="tag (free|paid)">\s*(Free|Paid)\s*<\/span>/i);
    const note = body.match(/<p>([\s\S]*?)<\/p>/);
    tools.push({
      name: decodeEntities(link[2].replace(/<[^>]+>/g, '')),
      url: decodeEntities(link[1]),
      category: cat,
      pricing: pricing ? pricing[2] : null,
      note: note ? decodeEntities(note[1].replace(/<[^>]+>/g, '')) : '',
    });
  }
  return tools;
}

/** Upstream sitemap lastmod for the homepage - the cheap freshness signal. */
function parseLastmod(sitemapXml) {
  const m = sitemapXml.match(/<url><loc>https:\/\/tools\.axi68\.com\/<\/loc><lastmod>([^<]+)<\/lastmod>/);
  return m ? m[1] : null;
}

async function main() {
  rmSync(STAGING, { recursive: true, force: true });
  mkdirSync(STAGING, { recursive: true });
  mkdirSync(OUT, { recursive: true });

  const html = await fetchText(`${BASE}/`);
  writeFileSync(join(STAGING, 'raw.html'), html);
  const tools = parseCards(html);
  if (tools.length === 0) throw new Error('parsed 0 tool cards - upstream markup changed');

  let lastmod = null;
  try {
    lastmod = parseLastmod(await fetchText(`${BASE}/sitemap.xml`));
  } catch (err) {
    console.error(`[axi68] sitemap lastmod unavailable: ${err instanceof Error ? err.message : err}`);
  }

  const byCat = new Map();
  for (const t of tools) byCat.set(t.category, (byCat.get(t.category) || 0) + 1);
  const categories = [...byCat.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const index = {
    generated_at: new Date().toISOString(),
    upstream: {
      directory: `${BASE}/`,
      sitemap_lastmod: lastmod,
      title: 'AX Intel Tools - The OSINT & Threat-Intel Tool Directory',
    },
    count: tools.length,
    categories,
    tools,
  };
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));

  console.log(`[axi68] tools=${tools.length} categories=${categories.length} lastmod=${lastmod ?? 'n/a'}`);
}

main().catch((err) => {
  console.error('[axi68] sync failed:', err);
  process.exitCode = 1;
});
