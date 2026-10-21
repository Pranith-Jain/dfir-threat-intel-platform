#!/usr/bin/env node
/**
 * Sync the DarkForums IP intelligence dataset.
 *
 * DarkForums (github.com/Ivancastl/darkforums-ip-intel) maps the IP
 * addresses and usernames observed on a cybercrime forum, so an analyst can
 * see which actors share infrastructure and where that infrastructure sits.
 *
 * Two upstream artifacts are used:
 *
 *   darkforums.json  — the raw scrape: `{ postId: { ip, username, hostname } }`
 *                       plus an `error` marker for posts that could not be
 *                       parsed. 41 MB.
 *   ips.db            — the same rows in a SQLite table (312k rows, 16 MB).
 *                       Not used here: reading SQLite from a build script
 *                       needs either a native module or an experimental
 *                       Node flag, and the JSON needs neither.
 *
 * Country attribution comes from DB-IP's free country database, mirrored as
 * CSV so the build needs no MaxMind library and no license key:
 *   https://github.com/sapics/ip-location-db (dbip-country/dbip-country-ipv4.csv)
 *
 * Run by:
 *   1. GitHub Action (.github/workflows/threat-intel-sync.yml)
 *   2. Manual: `node scripts/sync-darkforums-ip.mjs`
 *
 * After sync, run `node scripts/build-darkforums-ip.mjs`.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging');
const OUT = join(STAGING, 'darkforums-ip');
const UA = 'pranithjain-threat-intel-sync/1.0 (+https://pranithjain.qzz.io)';

export const DARKFORUMS = {
  source: 'DarkForums',
  sourceUrl: 'https://github.com/Ivancastl/darkforums-ip-intel',
  description:
    'IP addresses and usernames observed on a cybercrime forum, with country attribution and per-actor infrastructure grouping.',
  license: 'MIT (tool) — underlying forum observations are third-party data',
  geoSource:
    'https://github.com/sapics/ip-location-db — DB-IP country database (CC BY 4.0)',
};

const SOURCES = {
  posts: 'https://raw.githubusercontent.com/Ivancastl/darkforums-ip-intel/main/darkforums.json',
  geo: 'https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv',
};

const FETCH_TIMEOUT_MS = 180_000;
/** The upstream JSON is 41 MB; the geo CSV is 11 MB. */
const MAX_POSTS_BYTES = 64 * 1024 * 1024;
const MAX_GEO_BYTES = 24 * 1024 * 1024;

async function fetchText(url, maxBytes, label) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: 'application/json,text/csv,*/*' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > maxBytes) {
    throw new Error(`${label}: ${text.length} bytes exceeds the ${maxBytes} byte cap`);
  }
  return text;
}

async function main() {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
  console.log('• DarkForums IP intelligence');

  console.log('  · forum observations');
  let posts;
  try {
    const text = await fetchText(SOURCES.posts, MAX_POSTS_BYTES, 'darkforums.json');
    posts = JSON.parse(text);
    writeFileSync(join(OUT, 'posts.json'), text);
    console.log(`  ✓ ${Object.keys(posts).length} post records`);
  } catch (err) {
    console.error(`  ✗ darkforums.json: ${err.message ?? err}`);
    process.exitCode = 1;
  }

  console.log('  · country ranges');
  try {
    const text = await fetchText(SOURCES.geo, MAX_GEO_BYTES, 'dbip-country');
    writeFileSync(join(OUT, 'geo.csv'), text);
    const lines = text.split('\n').filter(Boolean);
    console.log(`  ✓ ${lines.length} country ranges`);
  } catch (err) {
    console.error(`  ✗ country ranges: ${err.message ?? err}`);
    process.exitCode = 1;
  }

  writeFileSync(
    join(OUT, 'source.json'),
    JSON.stringify(
      { ...DARKFORUMS, synced_at: new Date().toISOString(), sources: SOURCES },
      null,
      2
    )
  );
  console.log(`  → ${OUT}\n`);
}

main().catch((err) => {
  console.error(`  ✗ ${err.message ?? err}`);
  process.exit(1);
});
