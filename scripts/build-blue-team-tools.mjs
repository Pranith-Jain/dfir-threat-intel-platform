#!/usr/bin/env node
/**
 * Mirror A-poc/BlueTeam-Tools as a metadata-only reference catalog.
 *
 * The repository has NO reuse licence (all rights reserved). We mirror only
 * category names, tool names, the short one-line descriptions from the tool
 * list and the public destination URLs. No article prose, commands, images or
 * code are vendored; every record deep-links its upstream anchor.
 *
 * Output: public/data/blue-team-tools/index.json
 * Run:    node scripts/build-blue-team-tools.mjs [--source <README.md>]
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'blue-team-tools', 'index.json');
const SOURCE = 'https://github.com/A-poc/BlueTeam-Tools';
const README = `${SOURCE}/blob/main/README.md`;
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

/** Stable slug from a tool name; used for lookups, never for upstream paths. */
export function slugify(name = '') {
  return String(name)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 90);
}

const decode = (s = '') =>
  String(s)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\*\*/g, '')
    .replace(/`/g, '')
    .trim();

/**
 * Parse the README's `<details>` category blocks and the `### [🔙]` detail
 * headings. Pure — all network access happens in main().
 */
export function parseBlueTeamTools(markdown) {
  const text = String(markdown ?? '');
  const detailLinks = new Map();
  for (const m of text.matchAll(/^###\s*\[🔙\]\(#tool-list\)\[([^\]]*)\]\(([^)]*)\)/gm)) {
    const name = decode(m[1]);
    const url = decode(m[2]);
    if (name && /^https?:\/\//i.test(url)) detailLinks.set(slugify(name), url);
  }

  const categories = [];
  const seen = new Set();
  for (const block of text.matchAll(
    /<details[^>]*>\s*<summary><b>([^<]+)<\/b>\s*([^<]*)<\/summary>([\s\S]*?)<\/details>/gi
  )) {
    const name = decode(block[1]);
    if (!name) continue;
    const category = { name, statedCount: decode(block[2]), tools: [] };
    for (const item of block[3].matchAll(
      /<li><b><a href="#([^"]+)"[^>]*>([^<]+)<\/a><\/b>(?:<i>([^<]*)<\/i>)?<\/li>/gi
    )) {
      const toolName = decode(item[2]);
      const slug = slugify(toolName);
      if (!toolName || seen.has(slug)) continue;
      seen.add(slug);
      const anchor = decode(item[1]);
      category.tools.push({
        slug,
        name: toolName,
        summary: decode(item[3] ?? '').slice(0, 220),
        url: detailLinks.get(slug) ?? null,
        upstreamUrl: `${README}#${anchor}`,
      });
    }
    if (category.tools.length) categories.push(category);
  }

  const tools = categories.flatMap((c) => c.tools.map((t) => ({ ...t, category: c.name })));
  return {
    categories: categories.map((c) => ({ name: c.name, statedCount: c.statedCount, toolCount: c.tools.length, tools: c.tools.map((t) => t.slug) })),
    tools,
  };
}

async function main() {
  const idx = process.argv.indexOf('--source');
  const fetchReadme = async () => {
    let last;
    for (let i = 0; i < 3; i++) {
      try {
        const res = await fetch(README, {
          headers: { 'user-agent': UA, accept: 'text/markdown' },
          signal: AbortSignal.timeout(30_000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.text();
      } catch (e) {
        last = e;
        if (i < 2) await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
      }
    }
    throw last;
  };
  const markdown = idx > 0
    ? readFileSync(process.argv[idx + 1], 'utf8')
    : await fetchReadme();
  const { categories, tools } = parseBlueTeamTools(markdown);
  if (!tools.length) throw new Error('no tools parsed — upstream README changed');
  const payload = {
    generatedAt: new Date().toISOString(),
    source: 'BlueTeam-Tools',
    sourceUrl: SOURCE,
    license: 'No project-level licence (all rights reserved). Only tool names, one-line descriptions and public links are mirrored; deep-link upstream for the full article.',
    counts: { categories: categories.length, tools: tools.length, withLinks: tools.filter((t) => t.url).length },
    categories,
    tools,
  };
  writeJsonIfChanged(OUT, payload);
  console.log(`  ✓ ${tools.length} tools / ${categories.length} categories → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`blue-team-tools build failed: ${e.message}`); process.exit(1); });
