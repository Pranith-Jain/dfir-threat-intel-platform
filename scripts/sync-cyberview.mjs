#!/usr/bin/env node
/**
 * Mirror the public data files behind https://xanderhutch.github.io/CyberView/
 * into site data. Five upstream pages are replicated as separate routes in
 * the app (home/globe, vulnerabilities, archive, trends and tabletop); each is
 * a static page whose content is loaded from these JSON files at runtime.
 *
 * REA browser scenarios captured all five rendered pages (DOM + accessibility)
 * and showed the only network reads are these same static data files — there
 * is no private API, key or login. Everything mirrored here is public and
 * rebuilt on the upstream site's own schedule.
 *
 * Output: public/data/cyberview/**  (+ manifest.json)
 * Run:    node scripts/sync-cyberview.mjs
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'cyberview');
const BASE = 'https://xanderhutch.github.io/CyberView';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

/** Static files each replicated page reads. Kept exact so upstream paths stay recognisable. */
const FILES = [
  'data/feed.json',            // home globe: checked events, high-priority subset
  'data/workbench.json',       // vulnerabilities: KEV queue, guides, analyses, hunt pack
  'data/archive/index.json',   // archive: months + totals
  'data/archive/search.json',  // archive: compact search rows
  'data/archive/kev.json',     // archive: KEV table
  'data/trends.json',          // trends: weekly dims, daily counts, grid signals
  'data/tabletop.json',        // tabletop: full exercise script
  'data/cve/index.json',       // vulnerabilities: "All CVEs" lookup metadata
  'data/cve/recent.json',      // vulnerabilities: "All CVEs" last-two-weeks pool
  'data/health.json',          // status strip on the upstream pages
];

async function fetchText(rel, attempts = 2) {
  const url = `${BASE}/${rel}`;
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json,*/*' },
        signal: AbortSignal.timeout(45_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
    }
  }
  throw new Error(`${rel}: ${last?.message ?? 'fetch failed'}`);
}

function existing(rel) {
  const p = join(OUT, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

async function main() {
  console.log(`  fetching ${FILES.length} CyberView data files`);
  const written = [];
  for (const rel of FILES) {
    let body;
    try {
      body = await fetchText(rel);
      JSON.parse(body); // fail fast on HTML error pages
    } catch (e) {
      const cached = existing(rel);
      if (!cached) throw e;
      console.log(`  ! ${rel} unavailable (${e.message}); keeping previous copy`);
      continue;
    }
    const dest = join(OUT, rel);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, `${body.trimEnd()}\n`);
    written.push(rel);
    console.log(`  ✓ ${rel} (${(body.length / 1024).toFixed(0)} KB)`);
  }

  // Monthly archive files are listed by the upstream index; mirror them too.
  const indexPath = join(OUT, 'data', 'archive', 'index.json');
  let months = [];
  if (existsSync(indexPath)) {
    const index = JSON.parse(readFileSync(indexPath, 'utf8'));
    months = (index.months ?? []).map((m) => m.month).filter((m) => /^\d{4}-\d{2}$/.test(m));
  }
  for (const month of months) {
    const rel = `data/archive/${month}.json`;
    let body;
    try {
      body = await fetchText(rel);
      JSON.parse(body);
    } catch (e) {
      if (existing(rel)) { console.log(`  ! ${rel} unavailable; keeping previous copy`); continue; }
      console.log(`  ! ${rel} skipped (${e.message})`);
      continue;
    }
    writeFileSync(join(OUT, 'data', 'archive', `${month}.json`), `${body.trimEnd()}\n`);
    written.push(rel);
    console.log(`  ✓ ${rel}`);
  }

  // JSON Lines history -> a JSON array so the home page can plot every event
  // (lat/lng lives here, not in the compact search file) with a plain fetch.
  try {
    const lines = (await fetchText('data/archive/events.jsonl')).split('\n').filter(Boolean).map((line) => JSON.parse(line));
    if (lines.length) {
      const dest = join(OUT, 'data', 'events.json');
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, `${JSON.stringify(lines)}\n`);
      written.push('data/events.json');
      console.log(`  ✓ data/events.json (${lines.length} events from JSON Lines)`);
    }
  } catch (e) {
    if (!existing('data/events.json')) console.log(`  ! events.jsonl skipped (${e.message})`);
  }

  let stats = {};
  try {
    const feed = JSON.parse(readFileSync(join(OUT, 'data', 'feed.json'), 'utf8'));
    const index = JSON.parse(readFileSync(indexPath, 'utf8'));
    stats = { events: feed.items?.length ?? 0, archiveTotal: index.total ?? 0, kevTotal: index.kev_total ?? 0, months: months.length };
  } catch { /* stats are best-effort */ }

  const manifest = {
    generatedAt: new Date().toISOString(),
    upstream: { site: `${BASE}/`, pages: ['', 'vulnerabilities.html', 'archive.html', 'trends.html', 'tabletop.html'] },
    files: written,
    stats,
  };
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`  ✓ mirrored ${written.length} files → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`cyberview sync failed: ${e.message}`); process.exit(1); });
