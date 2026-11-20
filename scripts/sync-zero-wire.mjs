#!/usr/bin/env node
/**
 * Mirror the two public Cloudflare Radar Zero Wire JSON feeds into site data.
 *
 * REA capture of https://radar.cloudflare.com/zero-wire (browser scenario,
 * DOM + accessibility + network) confirmed the page is server-rendered and
 * advertises three feed formats via <link rel="alternate">:
 *   - /zero-wire/feed          RSS 2.0
 *   - /zero-wire/feed?format=atom
 *   - /zero-wire/feed?format=json  JSON Feed 1.1
 * The CVE page advertises the same formats at /zero-wire/cves/feed. The JSON
 * variants carry the full briefing content plus an extension object
 * (`_zero_wire` / `_cve`) with structured action, CVSS and source data, so we
 * mirror those verbatim rather than scraping the HTML.
 *
 * Output: public/data/zero-wire/index.json
 * Run:    node scripts/sync-zero-wire.mjs
 */
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'zero-wire');
const BASE = 'https://radar.cloudflare.com/zero-wire';
const FEEDS = {
  briefings: `${BASE}/feed?format=json`,
  cves: `${BASE}/cves/feed?format=json`,
};
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

async function fetchJson(url, attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'application/feed+json, application/json' },
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!data || !Array.isArray(data.items)) throw new Error('not a JSON Feed (missing items)');
      return data;
    } catch (e) {
      last = e;
    }
  }
  throw new Error(`${url}: ${last?.message ?? 'fetch failed'}`);
}

/** Normalise one JSON Feed item into a stable shape for the UI. */
export function normalizeItem(item, kind) {
  const ext = (kind === 'briefings' ? item._zero_wire : item._cve) ?? {};
  const out = {
    id: String(item.id ?? item.url ?? ''),
    url: String(item.url ?? item.id ?? ''),
    title: String(item.title ?? ''),
    summary: String(item.summary ?? ''),
    contentText: String(item.content_text ?? ''),
    published: typeof item.date_published === 'string' ? item.date_published : null,
    modified: typeof item.date_modified === 'string' ? item.date_modified : null,
    tags: Array.isArray(item.tags) ? item.tags.filter((t) => typeof t === 'string') : [],
    image: typeof item.image === 'string' ? item.image : null,
    ext,
  };
  if (kind === 'cves') {
    out.cveId = String(ext.id ?? out.title ?? '').match(/CVE-\d{4}-\d{4,}/)?.[0] ?? '';
    out.severity = String(ext.severity ?? 'UNKNOWN').toUpperCase();
    out.score = typeof ext.score === 'number' ? ext.score : null;
    out.cvssVersion = String(ext.cvss_version ?? '');
  }
  return out;
}

export function summarize(briefings, cves) {
  const bySeverity = {};
  for (const c of cves) bySeverity[c.severity || 'UNKNOWN'] = (bySeverity[c.severity || 'UNKNOWN'] ?? 0) + 1;
  return { briefings: briefings.length, cves: cves.length, bySeverity };
}

async function main() {
  console.log('  fetching Zero Wire JSON feeds');
  const [briefingFeed, cveFeed] = await Promise.all([
    fetchJson(FEEDS.briefings),
    fetchJson(FEEDS.cves),
  ]);
  const briefings = briefingFeed.items.map((i) => normalizeItem(i, 'briefings'));
  const cves = cveFeed.items.map((i) => normalizeItem(i, 'cves'));
  if (!briefings.length || !cves.length) throw new Error('empty feed — upstream format changed');

  const payload = {
    generatedAt: new Date().toISOString(),
    upstream: {
      site: BASE,
      cvesPage: `${BASE}/cves`,
      briefingsFeed: FEEDS.briefings,
      cvesFeed: FEEDS.cves,
      briefingsRss: `${BASE}/feed`,
      cvesRss: `${BASE}/cves/feed`,
      schema: `${BASE}/feed/schema.json`,
    },
    feedTitles: { briefings: briefingFeed.title, cves: cveFeed.title },
    stats: summarize(briefings, cves),
    briefings,
    cves,
  };
  mkdirSync(OUT, { recursive: true });
  writeJsonIfChanged(join(OUT, 'index.json'), payload);
  console.log(`  ✓ ${briefings.length} briefings · ${cves.length} CVEs → ${OUT}/index.json\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`zero-wire sync failed: ${e.message}`); process.exit(1); });
