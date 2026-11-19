#!/usr/bin/env node
/**
 * Build the Kitploit directory manifest under public/data/kp/.
 *
 * Replicates the public, crawlable surface of kitploit.com/en — a directory
 * of hacking / pentest / cybersecurity tools, CVE exploit evidence and
 * project updates. The site's robots.txt allows HTML pages and feeds but
 * disallows /api/, so this builder deliberately never calls the JSON API:
 *   - /en/tools             newest tool cards (server-rendered markup)
 *   - /en                   newest CVE evidence cards (homepage)
 *   - /en/rss.xml           50 latest tool/project updates
 *   - /en/exploits/rss.xml  100 latest CVE evidence updates
 *   - /en/blog/rss.xml      latest research posts
 *
 * No reuse licence is published, so the manifest stores only structured
 * metadata and short factual descriptions; every item deep-links upstream.
 * Images are never vendored — only their upstream URLs are kept.
 *
 * Emits:
 *   public/data/kp/index.json         (slim index + stats + items)
 *   public/data/kp/feeds/<name>.json  (full RSS item bodies)
 *
 * Usage: node scripts/build-kp-manifest.mjs [--offline <dir>]
 * `--offline` reads snapshots previously saved under <dir> for reproducible
 * rebuilds. Safe to run repeatedly — wipes public/data/kp/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'kp');
const BASE = 'https://kitploit.com';
const SOURCE = 'kitploit.com';
const SOURCE_URL = `${BASE}/en`;
const LICENSE = 'No reuse licence published — structured metadata and deep links only';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

const args = process.argv.slice(2);
const offIdx = args.indexOf('--offline');
const OFFLINE = offIdx >= 0 ? args[offIdx + 1] : null;

async function fetchText(path, name) {
  if (OFFLINE) return readFileSync(join(OFFLINE, name), 'utf8');
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const resp = await fetch(`${BASE}${path}`, {
        headers: { 'user-agent': UA, accept: 'text/html,application/rss+xml,application/xml;q=0.9,*/*;q=0.8' },
        signal: AbortSignal.timeout(30_000),
      });
      if (!resp.ok) throw new Error(`fetch ${path}: ${resp.status} ${resp.statusText}`);
      return await resp.text();
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

function decodeEntities(s) {
  return String(s ?? '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .trim();
}

function stripTags(s) {
  return decodeEntities(
    String(s ?? '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' '),
  );
}

function first(html, re, group = 1) {
  const m = re.exec(html);
  return m ? decodeEntities(m[group]) : null;
}

/** Server-rendered new-tool cards. */
export function parseTools(html) {
  const out = [];
  const articleRe = /<article class="surface-card group flex flex-col overflow-hidden[\s\S]*?<\/article>/g;
  let m;
  while ((m = articleRe.exec(html)) !== null) {
    const card = m[0];
    const link = first(card, /href="(\/en\/tools\/[^"]+)"/);
    const title = first(card, /<h3[^>]*>([\s\S]*?)<\/h3>/);
    if (!link || !title) continue;
    const provider = first(card, /aria-label="(GitHub|GitLab)"/);
    const repo = first(card, /aria-label="Repository path">([\s\S]*?)<\/span>/);
    const description = first(card, /<p class="text-body-sm text-on-surface-variant line-clamp-2 flex-1">([\s\S]*?)<\/p>/);
    const image = first(card, /<img alt="[^"]*preview"[^>]*src="([^"]+)"/);
    const labels = [...card.matchAll(/<span class="label[^"]*">([\s\S]*?)<\/span>/g)]
      .map((x) => stripTags(x[1]))
      .filter((x) => x && !/^\+\d+$/.test(x));
    const stars = first(card, /title="Stars"[\s\S]*?<span>([\d,.kK]+)<\/span>/);
    out.push({
      id: link.replace(/^\/en\/tools\//, ''),
      title: stripTags(title),
      url: `${BASE}${link}`,
      provider: provider ?? null,
      repo: repo ?? null,
      description: description ? stripTags(description) : null,
      image: image ?? null,
      categories: labels.slice(0, 8),
      stars: stars ?? null,
    });
  }
  return out;
}

/** Server-rendered CVE evidence cards. */
export function parseExploits(html) {
  const out = [];
  const articleRe = /<article class="grid gap-3 p-4[\s\S]*?<\/article>/g;
  let m;
  while ((m = articleRe.exec(html)) !== null) {
    const card = m[0];
    const link = first(card, /href="(\/en\/exploits\/[^"]+)"/);
    const title = first(card, /<h3[^>]*><a[^>]*>([\s\S]*?)<\/a><\/h3>/);
    if (!link || !title) continue;
    const cvss = first(card, /aria-label="CVSS: ([0-9.]+); ([^"]+)"/, 1);
    const cvssLabel = first(card, /aria-label="CVSS: [0-9.]+; ([^"]+)"/, 1);
    const epss = first(card, /aria-label="EPSS: ([^"]+)"/, 1);
    const exploitCount = first(card, /<dt[^>]*>Exploits<\/dt>\s*<dd[^>]*>([\s\S]*?)<\/dd>/);
    const evidence = first(card, /<p class="mt-1 text-label-sm text-on-surface-variant">([\s\S]*?)<\/p>/);
    out.push({
      id: link.replace(/^\/en\/exploits\//, ''),
      cve: link.includes('/cve-') ? link.replace(/^\/en\/exploits\//, '').toUpperCase() : null,
      title: stripTags(title),
      url: `${BASE}${link}`,
      cvssScore: cvss ? parseFloat(cvss) : null,
      cvssSeverity: cvssLabel ?? null,
      epss: epss ?? null,
      exploitCount: exploitCount ? parseInt(stripTags(exploitCount), 10) : null,
      evidence: evidence ? stripTags(evidence) : null,
    });
  }
  return out;
}

/** Minimal RSS 2.0 item reader — the upstream feeds are well-formed and flat. */
export function parseRss(xml) {
  const items = [];
  const itemRe = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = itemRe.exec(xml)) !== null) {
    const block = m[1];
    const get = (tag) => {
      const mm = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`).exec(block);
      return mm ? decodeEntities(mm[1]) : null;
    };
    const image =
      first(block, /<enclosure[^>]*url="([^"]+)"/) ??
      first(block, /<media:content[^>]*url="([^"]+)"/) ??
      first(block, /<media:thumbnail[^>]*url="([^"]+)"/);
    const description = get('description');
    items.push({
      title: get('title'),
      url: get('link'),
      description: description ? stripTags(description.replace(/&lt;/g, '<').replace(/&gt;/g, '>')) : null,
      published: get('pubDate'),
      guid: get('guid'),
      image,
    });
  }
  return items;
}

function countBy(rows, key) {
  const out = {};
  for (const r of rows) {
    const v = r[key] == null || r[key] === '' ? 'null' : String(r[key]);
    out[v] = (out[v] ?? 0) + 1;
  }
  return out;
}

async function main() {
  const builtAt = new Date().toISOString();
  const [toolsHtml, exploitsHtml, updatesXml, exploitRssXml, blogXml] = await Promise.all([
    fetchText('/en/tools', 'tools.html'),
    fetchText('/en', 'home.html'),
    fetchText('/en/rss.xml', 'rss.xml'),
    fetchText('/en/exploits/rss.xml', 'exploits-rss.xml'),
    fetchText('/en/blog/rss.xml', 'blog-rss.xml'),
  ]);

  const tools = parseTools(toolsHtml);
  const exploits = parseExploits(exploitsHtml);
  const feeds = {
    updates: parseRss(updatesXml),
    exploits: parseRss(exploitRssXml),
    blog: parseRss(blogXml),
  };
  if (tools.length === 0 || exploits.length === 0) {
    throw new Error(`parsed 0 cards (tools=${tools.length}, exploits=${exploits.length}) — upstream markup changed`);
  }

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'feeds'), { recursive: true });

  for (const [name, items] of Object.entries(feeds)) {
    writeFileSync(
      join(OUT, 'feeds', `${name}.json`),
      JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, feed: name, count: items.length, items }, null, 2) + '\n',
    );
  }

  const allFeedItems = Object.values(feeds).flat();
  const stats = {
    listedTools: tools.length,
    listedExploits: exploits.length,
    feedItems: Object.fromEntries(Object.entries(feeds).map(([k, v]) => [k, v.length])),
    byProvider: countBy(tools, 'provider'),
    byCategory: tools.reduce((acc, t) => {
      for (const c of t.categories) acc[c] = (acc[c] ?? 0) + 1;
      return acc;
    }, {}),
    byCvssSeverity: countBy(exploits, 'cvssSeverity'),
    sourceLinks: tools.length + exploits.length + allFeedItems.length,
  };

  writeFileSync(
    join(OUT, 'index.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: SOURCE_URL,
        license: LICENSE,
        robots: 'HTML and feeds allowed; /api/ disallowed — this replication never calls the JSON API',
        builtAt,
        counts: {
          tools: tools.length,
          exploits: exploits.length,
          updates: feeds.updates.length,
          exploitUpdates: feeds.exploits.length,
          blogPosts: feeds.blog.length,
        },
        stats,
        tools,
        exploits,
        feeds: Object.fromEntries(Object.entries(feeds).map(([k, v]) => [k, v.map((i) => ({ title: i.title, url: i.url, published: i.published }))])),
        webPages: {
          home: SOURCE_URL,
          tools: `${SOURCE_URL}/tools`,
          exploits: `${SOURCE_URL}/exploits`,
          feeds: `${SOURCE_URL}/feeds`,
          rss: `${SOURCE_URL}/rss.xml`,
          exploitRss: `${SOURCE_URL}/exploits/rss.xml`,
        },
      },
      null,
      2,
    ) + '\n',
  );

  console.log(
    `[kp] tools=${tools.length} exploits=${exploits.length} feeds=${Object.entries(feeds).map(([k, v]) => `${k}:${v.length}`).join(' ')}`,
  );
}

const isMain = (() => {
  try {
    return resolvePath(process.argv[1] ?? '') === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();
if (isMain) {
  main().catch((e) => {
    console.error(`[kp] build failed: ${e.message}`);
    process.exit(1);
  });
}
