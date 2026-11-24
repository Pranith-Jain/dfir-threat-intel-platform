#!/usr/bin/env node
/**
 * Mirror vulntracker.io's public 24h "Trending CVEs" board into site data.
 *
 * The board is server-rendered Next.js (robots.txt allows /trending). There is
 * no public JSON endpoint, but the RSC stream embeds the exact table as a
 * JSON `data.items` array with people/posts counts, severity, CVSS and
 * "is_exploited". This is a *social attention* signal (public Bluesky posts,
 * automated CVE feeds excluded), so it belongs beside cvemon/cves.io on the
 * Trending tab — never in the canonical new/exploited CVE feed.
 *
 * Output: public/data/cve-intel/vulntracker-trending.json
 * Run:    node scripts/sync-vulntracker-trending.mjs
 */
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'cve-intel', 'vulntracker-trending.json');
const URL_24H = 'https://vulntracker.io/trending?window=24h';
const SITE = 'https://vulntracker.io';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const MAX_ITEMS = 50;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const RSC_CHUNK_RE = /self\.__next_f\.push\(\[1,("(?:\\.|[^"\\])*")\]\)/g;

/**
 * Pull data.items out of the RSC stream. Balances brackets so a title
 * containing `]` cannot truncate the payload. [] on a format change.
 */
export function extractRscItems(html) {
  if (typeof html !== 'string') return [];
  for (const match of html.matchAll(RSC_CHUNK_RE)) {
    let chunk;
    try {
      chunk = JSON.parse(match[1]);
    } catch {
      continue;
    }
    if (!chunk.includes('"data":') || !chunk.includes('"items":[')) continue;
    const start = chunk.indexOf('[', chunk.indexOf('"items":['));
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let i = start; i < chunk.length; i++) {
      const c = chunk[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (c === '\\') escaped = true;
        else if (c === '"') inString = false;
        continue;
      }
      if (c === '"') inString = true;
      else if (c === '[') depth++;
      else if (c === ']') {
        depth--;
        if (depth === 0) {
          try {
            const parsed = JSON.parse(chunk.slice(start, i + 1));
            return Array.isArray(parsed) ? parsed : [];
          } catch {
            return [];
          }
        }
      }
    }
  }
  return [];
}

const numberOrNull = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const isoOrNull = (v) => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? v : null);
const countOrZero = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);

/** Drop malformed ids, dedupe, cap the board. */
export function normalizeItems(raw, maxItems = MAX_ITEMS) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const items = [];
  for (const row of raw) {
    const id = typeof row?.cve_id === 'string' ? row.cve_id.trim().toUpperCase() : '';
    if (!CVE_RE.test(id) || seen.has(id)) continue;
    const title = typeof row.title === 'string' ? row.title.trim().slice(0, 400) : '';
    if (!title) continue;
    seen.add(id);
    items.push({
      id,
      rank: items.length + 1,
      title,
      severity: typeof row.severity === 'string' ? row.severity.toUpperCase() : 'UNKNOWN',
      cvss: numberOrNull(row.base_score),
      exploited: row.is_exploited === true,
      people: countOrZero(row.people),
      posts: countOrZero(row.posts),
      lastPostedAt: isoOrNull(row.last_posted_at),
      published: isoOrNull(row.published_date),
      url: `${SITE}/cves/${id}`,
    });
    if (items.length >= maxItems) break;
  }
  return items;
}

export function buildDataset(rawItems) {
  const items = normalizeItems(rawItems);
  return {
    generatedAt: new Date().toISOString(),
    window: '24h',
    upstream: {
      site: SITE,
      url: URL_24H,
      attribution: 'Trending is counted from public Bluesky posts. Automated CVE feeds are not counted.',
    },
    count: items.length,
    items,
  };
}

async function fetchHtml(attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(URL_24H, {
        headers: { 'user-agent': UA, accept: 'text/html' },
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
    }
  }
  throw new Error(`${URL_24H}: ${last?.message ?? 'fetch failed'}`);
}

async function main() {
  console.log('  fetching vulntracker.io 24h trending board');
  const html = await fetchHtml();
  const payload = buildDataset(extractRscItems(html));
  if (!payload.count) throw new Error('no trending rows parsed — upstream format changed');
  writeJsonIfChanged(OUT, payload);
  console.log(`  ✓ ${payload.count} trending CVEs → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`vulntracker trending sync failed: ${e.message}`); process.exit(1); });
