#!/usr/bin/env node
/**
 * Sync the MBSD CIG Ransomware Information Portal
 * (mbsd.jp/cig-ransomware-portal) into site data.
 *
 * Upstream is a Vite/React SPA that loads its whole dataset as JSON assets:
 *   /ransomware-data.json   one entry per ransomware group: activity flags,
 *                           relationshipdict (bilingual group-to-group notes),
 *                           boxcomment (bilingual profile), rebrandlist,
 *                           firstappearyear
 *   /reference.json         group co-occurrence references ({groups, url})
 *   /update-history.json    dataset changelog ({date, version, events[]})
 *   /nodeLocation.json      affiliate chains (chainNodesLocation arrays)
 *   /assets/ransom-notes-db-*.json   ransom note corpus (content-hash name,
 *                           discovered from index.html)
 *
 * Staging (threat-intel-staging/cig-portal/): verbatim upstream copies.
 * Site data (public/data/cig-portal/):
 *   index.json     slim per-group flags + stats + chains + update history
 *   profiles.json  name -> {profile ja/en, relationships ja/en, rebrands}
 *                  (large; the page lazy-loads it only when a group opens)
 *   reference.json verbatim co-occurrence references
 *
 * Run: node scripts/sync-cig-portal.mjs
 */
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'cig-portal');
const OUT = join(ROOT, 'public', 'data', 'cig-portal');
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const BASE = 'https://www.mbsd.jp/cig-ransomware-portal';

/** Boolean activity flags we surface as first-class filters on the page. */
const FLAG_KEYS = [
  'withintwoweeks',
  'leaksite',
  'hackerforum',
  'telegram',
  'noencryption',
  'shadowsyndigate',
  'precursor',
  'hacktivist',
  'sameaffiliate',
  'isOther',
];

async function fetchBuffer(url) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: '*/*' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`fetch failed: ${url} -> ${res.status} ${res.statusText}`);
  return Buffer.from(await res.arrayBuffer());
}

async function fetchJson(url) {
  return JSON.parse((await fetchBuffer(url)).toString('utf8'));
}

async function main() {
  const problems = [];
  const note = (label, err) => {
    problems.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
    console.error(`[cig] ${label} failed: ${err instanceof Error ? err.message : err}`);
  };

  rmSync(STAGING, { recursive: true, force: true });
  mkdirSync(STAGING, { recursive: true });
  mkdirSync(OUT, { recursive: true });

  // 1. Discover the content-hashed ransom-note DB asset from the shell page.
  let notesDbUrl = null;
  try {
    const shell = (await fetchBuffer(`${BASE}/`)).toString('utf8');
    writeFileSync(join(STAGING, 'index.html'), shell);
    const m = shell.match(/assets\/(ransom-notes-db-[A-Za-z0-9_-]+\.json)/);
    if (m) {
      notesDbUrl = `${BASE}/assets/${m[1]}`;
      // Note corpus is an internal asset for our own enrichment only; keep
      // the raw copy in staging rather than shipping it to public/data.
      writeFileSync(join(STAGING, m[1]), await fetchBuffer(notesDbUrl));
    }
  } catch (err) {
    note('index.html / ransom-notes-db discovery', err);
  }

  // 2. The four data files. Each is isolated so one failure keeps the rest.
  let groups = null;
  let reference = null;
  let updateHistory = null;
  let nodeLocation = null;
  try {
    groups = await fetchJson(`${BASE}/ransomware-data.json`);
    writeFileSync(join(STAGING, 'ransomware-data.json'), JSON.stringify(groups));
  } catch (err) {
    note('ransomware-data.json', err);
  }
  try {
    reference = await fetchJson(`${BASE}/reference.json`);
    writeFileSync(join(STAGING, 'reference.json'), JSON.stringify(reference));
  } catch (err) {
    note('reference.json', err);
  }
  try {
    updateHistory = await fetchJson(`${BASE}/update-history.json`);
    writeFileSync(join(STAGING, 'update-history.json'), JSON.stringify(updateHistory));
  } catch (err) {
    note('update-history.json', err);
  }
  try {
    nodeLocation = await fetchJson(`${BASE}/nodeLocation.json`);
    writeFileSync(join(STAGING, 'nodeLocation.json'), JSON.stringify(nodeLocation));
  } catch (err) {
    note('nodeLocation.json', err);
  }

  if (!groups) {
    throw new Error('ransomware-data.json unavailable - nothing to build');
  }

  // 3. Slim per-group view for index.json; full profiles into profiles.json.
  const slim = [];
  const profiles = {};
  const stats = {
    groups: 0,
    active_within_2w: 0,
    leaksite: 0,
    hackerforum: 0,
    telegram: 0,
    noencryption: 0,
    hacktivist: 0,
    precursor: 0,
    shadowsyndigate: 0,
    sameaffiliate: 0,
    isOther: 0,
    with_rebrandlist: 0,
    with_relationships: 0,
  };
  const firstYears = new Map();
  for (const [name, g] of Object.entries(groups)) {
    if (!g || typeof g !== 'object') continue;
    stats.groups += 1;
    const flags = {};
    for (const k of FLAG_KEYS) flags[k] = g[k] === true;
    for (const k of FLAG_KEYS.slice(1)) if (flags[k]) stats[k] += 1;
    if (flags.withintwoweeks) stats.active_within_2w += 1;
    const rel = g.relationshipdict || {};
    const relationships = Object.entries(rel).map(([other, notePair]) => ({
      group: other,
      ja: notePair?.ja || '',
      en: notePair?.en || '',
    }));
    if (relationships.length) stats.with_relationships += 1;
    const year = typeof g.firstappearyear === 'string' ? g.firstappearyear : null;
    if (year) firstYears.set(year, (firstYears.get(year) || 0) + 1);
    slim.push({
      name,
      flags,
      firstappearyear: year,
      rebrands: Array.isArray(g.rebrandlist) ? g.rebrandlist : [],
      relationships: relationships.map((r) => r.group),
      relationship_count: relationships.length,
    });
    profiles[name] = {
      profile: g.boxcomment || null,
      relationships,
      rebrandlist: Array.isArray(g.rebrandlist) ? g.rebrandlist : [],
    };
  }
  stats.with_rebrandlist = slim.filter((s) => s.rebrands.length > 0).length;
  slim.sort((a, b) => a.name.localeCompare(b.name));

  const latest = Array.isArray(updateHistory) && updateHistory.length ? updateHistory[0] : null;

  const index = {
    generated_at: new Date().toISOString(),
    upstream: {
      portal: `${BASE}/`,
      publisher: 'MBSD (Mitsui Bussan Secure Directions) CIG Ransomware Information Portal',
      dataset_version: latest?.version || null,
      dataset_updated: latest?.date || null,
      notes_db: notesDbUrl,
    },
    sync_problems: problems,
    stats,
    first_appearance_years: [...firstYears.entries()]
      .map(([year, count]) => ({ year, count }))
      .sort((a, b) => b.year.localeCompare(a.year)),
    // Upstream marks a group active when it surfaced within two weeks; that
    // same ordering puts newest first in their UI. Mirror the sort so the
    // default view matches the portal.
    groups: slim,
    chains: nodeLocation?.chainNodesLocation || [],
    update_history: updateHistory || [],
  };
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));
  writeFileSync(join(OUT, 'profiles.json'), JSON.stringify(profiles));
  if (reference) writeFileSync(join(OUT, 'reference.json'), JSON.stringify(reference));

  console.log(
    `[cig] groups=${stats.groups} active2w=${stats.active_within_2w} refs=${reference?.length ?? 'n/a'} ` +
      `chains=${index.chains.length} history=${updateHistory?.length ?? 'n/a'} problems=${problems.length}`
  );
}

main().catch((err) => {
  console.error('[cig] sync failed:', err);
  process.exitCode = 1;
});
