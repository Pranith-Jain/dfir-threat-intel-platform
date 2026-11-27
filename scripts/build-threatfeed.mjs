#!/usr/bin/env node
/**
 * Mirror jozeta/ThreatFeed's public feed catalog (MIT).
 *
 * REA confirmed https://jozeta.github.io/ThreatFeed/ is a client-side
 * newsreader whose public `data/feeds.json` lists 181 security feeds across
 * 13 categories. MIT permits a full metadata mirror; no article bodies are
 * fetched — every record links to the upstream feed URL.
 *
 * Output: public/data/threatfeed/index.json
 * Run:    node scripts/build-threatfeed.mjs [--source <feeds.json>]
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'threatfeed', 'index.json');
const REPO = 'https://github.com/jozeta/ThreatFeed';
const FEEDS = 'https://jozeta.github.io/ThreatFeed/data/feeds.json';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const CURATED_FEEDS = [
  { id: 'news', name: 'News', description: 'Important security stories from ThreatFeed, one per story.', file: 'news.xml' },
  { id: 'vulns', name: 'Vulnerabilities', description: 'New CISA KEV entries, critical CVEs, public exploits and Patch Tuesday.', file: 'vulns.xml' },
  { id: 'ransomware', name: 'Ransomware', description: 'Ransomware leak-site victims and ransomware news.', file: 'ransomware.xml' },
  { id: 'npm', name: 'npm advisories', description: 'Reviewed npm security advisories from the GitHub Advisory Database.', file: 'npm.xml' },
];

export function parseThreatFeed(raw) {
  const d = typeof raw === 'string' ? JSON.parse(raw) : raw;
  const feeds = Array.isArray(d?.feeds) ? d.feeds : [];
  const byCategory = new Map();
  for (const f of feeds) {
    if (!f?.id || !f?.name) continue;
    const category = String(f.category ?? 'Uncategorised').slice(0, 80);
    const list = byCategory.get(category) ?? [];
    list.push({
      id: String(f.id).slice(0, 120),
      name: String(f.name).slice(0, 160),
      url: /^https?:\/\//i.test(String(f.url ?? '')) ? String(f.url).slice(0, 1000) : null,
      category,
      tags: Array.isArray(f.tags) ? f.tags.slice(0, 12).map((t) => String(t).slice(0, 40)) : [],
      enabled: f.enabled !== false,
      upstreamUrl: `${REPO}#${encodeURIComponent(String(f.id))}`,
    });
    byCategory.set(category, list);
  }
  const all = [...byCategory.values()].flat();
  const categories = [...byCategory.entries()]
    .map(([name, list]) => ({ name, count: list.length, feeds: list.map((f) => f.id) }))
    .sort((a, b) => b.count - a.count);
  return {
    categories,
    feeds: all,
    retiredFeedIds: Array.isArray(d?.retiredFeedIds) ? d.retiredFeedIds.length : 0,
    version: d?.version ?? null,
    upstreamUpdatedAt: d?.updatedAt ?? null,
  };
}

async function main() {
  const idx = process.argv.indexOf('--source');
  const raw = idx > 0 ? readFileSync(process.argv[idx + 1], 'utf8') : await fetch(FEEDS, {
    headers: { 'user-agent': UA }, signal: AbortSignal.timeout(30_000),
  }).then(async (r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.text(); });
  const parsed = parseThreatFeed(raw);
  if (!parsed.feeds.length) throw new Error('no feeds parsed — upstream shape changed');
  writeJsonIfChanged(OUT, {
    generatedAt: new Date().toISOString(),
    source: 'ThreatFeed',
    sourceUrl: REPO,
    feedUrl: FEEDS,
    license: 'MIT — https://github.com/jozeta/ThreatFeed/blob/main/LICENSE',
    note: 'Feed metadata only. Article bodies are not mirrored; subscribe through the upstream URL.',
    counts: { feeds: parsed.feeds.length, categories: parsed.categories.length, enabled: parsed.feeds.filter((f) => f.enabled).length, retired: parsed.retiredFeedIds },
    ...parsed,
  });
  console.log(`  ✓ ThreatFeed: ${parsed.feeds.length} feeds / ${parsed.categories.length} categories → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`threatfeed build failed: ${e.message}`); process.exit(1); });
