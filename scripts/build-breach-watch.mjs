#!/usr/bin/env node
/**
 * Build the Breach Watch manifest under public/data/breach-watch/.
 *
 * Fetches free, open breach/ransomware data from public trackers and
 * slices it into a slim index + per-breach JSON files for edge serving
 * via ASSETS. No API keys required.
 *
 * Sources (all free, open, no auth):
 *   - ransomware.live   → data.ransomware.live/posts.json        (28k+ claims)
 *   - ransomlook.io     → www.ransomlook.io/api/recent           (100 recent)
 *   - Darkfield         → darkfield.orizon.one/feed.json          (200 recent)
 *   - Darkfield Groups  → darkfield.orizon.one/data/groups.json   (471 groups, aliases)
 *   - RecentBreaches    → recentbreaches.com/api/leaks            (20 recent)
 *   - CTI.FYI           → cti.fyi/api/v1/posts/recent            (50 recent)
 *   - XposedOrNot       → api.xposedornot.com/v1/breaches        (763 breaches)
 *
 * Emits:
 *   public/data/breach-watch/index.json             (slim — breach index)
 *   public/data/breach-watch/breaches/<slug>.json   (1 per breach, full body)
 *
 * Safe to run repeatedly — wipes public/data/breach-watch/ on each run.
 *
 * FILES_LIMIT bounds the emitted body + index count: the Worker Free plan caps
 * static assets at 20,000 per version, and the full 90-day window (2.7k bodies)
 * pushes dist past that. Keep only the most recent breaches so deploys stay
 * under the cap while the index still reflects live feed state.
 */
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'breach-watch');

const SOURCE = 'ransomware.live + ransomlook.io + Darkfield + RecentBreaches.com + CTI.FYI + XposedOrNot';
const LICENSE = 'CC0 — public data from open trackers';

/** Cap on emitted breach bodies + index entries (Free-plan 20k asset cap). */
const FILES_LIMIT = 350;

const NOTORIOUS_GROUPS = new Set([
  'lockbit',
  'clop',
  'blackcat',
  'alphv',
  'ransomhub',
  'akira',
  'qilin',
  'blackbasta',
  'bianlian',
  'play',
  'hive',
  'royal',
  'dragonforce',
  'incransom',
  'snatch',
  '8base',
  'cactus',
  'abyss',
  'medusa',
  'rhysida',
  'mallox',
  'monti',
  'thegentlemen',
  'deadlock',
  'everest',
  'braincipher',
  'shinyhunters',
  'stormous',
]);

function slugify(name) {
  return name
    .toLowerCase()
    .replace(/['']/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 120);
}

function deriveSeverity(groupName, extra) {
  const g = (groupName ?? '').toLowerCase().trim();
  if (NOTORIOUS_GROUPS.has(g)) return 'critical';
  if (extra?.exposedRecords > 1_000_000) return 'critical';
  if (extra?.exposedRecords > 100_000) return 'high';
  if (extra?.passwordRisk === 'plaintext') return 'high';
  return 'high';
}

function deriveCategory(groupName, extra) {
  const g = (groupName ?? '').toLowerCase().trim();
  if (extra?.breachType === 'ComboList') return 'combo_list';
  if (extra?.passwordRisk === 'plaintext') return 'credential_leak';
  if (
    [
      'lockbit',
      'clop',
      'blackcat',
      'alphv',
      'ransomhub',
      'akira',
      'qilin',
      'blackbasta',
      'bianlian',
      'play',
      'hive',
      'royal',
      'dragonforce',
      'incransom',
      'snatch',
      '8base',
      'cactus',
      'abyss',
      'medusa',
      'rhysida',
      'mallox',
      'monti',
      'ransomhouse',
      'thegentlemen',
      'chaos',
      'arcusmedia',
      'coinbasecartel',
      'payoutsking',
      'booba project',
      'pear',
      'ailock',
      'settrac',
      'd1r',
      'titan',
      'blacknevas',
      'cmdorganization',
      'lockbit 3.0',
      'cl0p',
      'alphv/blackcat',
      '8 base',
      'hive_',
      'deadlock',
      'safepay',
      'nova',
      'everest',
      'braincipher',
      'stormous',
      'threeam',
      'anubis',
      'shinyhunters',
      'fulcrumsec',
      'worldleaks',
      'krybit',
      'nightspire',
      'm3rx',
      'genesis',
      'payload',
    ].some((n) => g.includes(n))
  ) {
    return 'ransomware';
  }
  if (extra?.source === 'xposedornot') {
    return extra.breachType === 'ComboList' ? 'combo_list' : 'data_breach';
  }
  return 'data_breach';
}

function ensureDir(p) {
  mkdirSync(p, { recursive: true });
}

function safeIsoOr(raw) {
  if (!raw) return new Date().toISOString();
  const cleaned = raw.replace(' ', 'T').replace(/\.\d+/, '');
  const hasTz = cleaned.endsWith('Z') || /\+\d{2}:\d{2}$/.test(cleaned);
  const d = new Date(hasTz ? cleaned : cleaned + 'Z');
  return Number.isFinite(d.getTime()) ? d.toISOString() : new Date().toISOString();
}

// ── Source fetch functions ──────────────────────────────────────────

async function fetchWithTimeout(url, ms = 15_000) {
  const res = await fetch(url, {
    headers: { 'User-Agent': 'pranithjain.qzz.io build script (free, read-only)' },
    signal: AbortSignal.timeout(ms),
  });
  return res;
}

async function fetchRansomwareLiveBreaches() {
  const res = await fetchWithTimeout('https://data.ransomware.live/posts.json', 30_000);
  if (!res.ok) {
    console.warn(`  ransomware.live returned ${res.status}, skipping`);
    return [];
  }
  const raw = await res.json();
  if (!Array.isArray(raw)) {
    console.warn('  ransomware.live: expected array');
    return [];
  }
  const cutoffMs = Date.now() - 90 * 86_400_000;
  const out = [];
  for (const e of raw) {
    if (!e?.post_title || !e.group_name || !e.discovered) continue;
    const discovered = safeIsoOr(e.discovered);
    if (Date.parse(discovered) < cutoffMs) continue;
    out.push({
      title: e.post_title.trim(),
      group: e.group_name.trim(),
      discovered,
      description: e.description?.trim() || null,
      country: e.country?.trim() || null,
      sector: e.activity?.trim() || null,
      source: 'ransomware.live',
      source_url: 'https://www.ransomware.live/',
    });
    if (out.length >= FILES_LIMIT) break;
  }
  return out;
}

async function fetchRansomlookBreaches() {
  const res = await fetchWithTimeout('https://www.ransomlook.io/api/recent');
  if (!res.ok) {
    console.warn(`  ransomlook.io returned ${res.status}, skipping`);
    return [];
  }
  const raw = await res.json();
  if (!Array.isArray(raw)) {
    console.warn('  ransomlook.io: expected array');
    return [];
  }
  const cutoffMs = Date.now() - 90 * 86_400_000;
  const out = [];
  for (const e of raw) {
    if (!e?.post_title || !e.group_name || !e.discovered) continue;
    const discovered = safeIsoOr(e.discovered);
    if (Date.parse(discovered) < cutoffMs) continue;
    out.push({
      title: e.post_title.trim(),
      group: e.group_name.trim(),
      discovered,
      description: e.description?.trim() || null,
      country: null,
      sector: null,
      source: 'ransomlook.io',
      source_url: e.screen
        ? `https://www.ransomlook.io/${e.screen.replace(/^\//, '')}`
        : 'https://www.ransomlook.io/recent',
    });
    if (out.length >= FILES_LIMIT) break;
  }
  return out;
}

async function fetchDarkfieldBreaches() {
  const res = await fetchWithTimeout('https://darkfield.orizon.one/feed.json');
  if (!res.ok) {
    console.warn(`  Darkfield returned ${res.status}, skipping`);
    return [];
  }
  const raw = await res.json();
  const victims = raw?.victims;
  if (!Array.isArray(victims)) {
    console.warn('  Darkfield: expected .victims array');
    return [];
  }
  const cutoffMs = Date.now() - 90 * 86_400_000;
  const out = [];
  for (const v of victims) {
    if (!v?.victim || !v.group || !v.discovered) continue;
    const discovered = safeIsoOr(v.discovered);
    if (Date.parse(discovered) < cutoffMs) continue;
    out.push({
      title: v.victim.trim(),
      group: v.group.trim(),
      discovered,
      description: v.status ? `Status: ${v.status}` : null,
      country: v.country?.trim() || null,
      sector: v.sector?.trim() || null,
      source: 'Darkfield',
      source_url: v.url || 'https://darkfield.orizon.one',
    });
  }
  return out;
}

async function fetchDarkfieldGroups() {
  const res = await fetchWithTimeout('https://darkfield.orizon.one/data/groups.json', 20_000);
  if (!res.ok) {
    console.warn('  Darkfield groups unavailable, skipping alias enrichment');
    return null;
  }
  const raw = await res.json();
  const groups = raw?.groups;
  if (!Array.isArray(groups)) {
    console.warn('  Darkfield groups: expected .groups array');
    return null;
  }
  const aliasMap = new Map();
  for (const g of groups) {
    if (g.aliases?.length > 0) {
      aliasMap.set((g.slug || g.name || '').toLowerCase(), {
        aliases: g.aliases,
        totalVictims: g.total_victims || 0,
        firstSeen: g.first_seen || null,
        lastSeen: g.last_seen || null,
      });
    }
  }
  return aliasMap;
}

async function fetchRecentBreaches() {
  const res = await fetchWithTimeout('https://recentbreaches.com/api/leaks?limit=20');
  if (!res.ok) {
    console.warn(`  RecentBreaches.com returned ${res.status}, skipping`);
    return [];
  }
  const raw = await res.json();
  const leaks = raw?.leaks;
  if (!Array.isArray(leaks)) {
    console.warn('  RecentBreaches: expected .leaks array');
    return [];
  }
  const out = [];
  for (const l of leaks) {
    if (!l?.victim || !l.group || !l.listed) continue;
    out.push({
      title: l.victim.trim(),
      group: l.group.trim(),
      discovered: safeIsoOr(l.listed),
      description: l.claim || null,
      country: l.country?.trim() || null,
      sector: l.sector?.trim() || null,
      source: 'RecentBreaches.com',
      source_url: l.url || 'https://recentbreaches.com',
    });
  }
  return out;
}

async function fetchCtiFyiBreaches() {
  const res = await fetchWithTimeout('https://cti.fyi/api/v1/posts/recent');
  if (!res.ok) {
    console.warn(`  CTI.FYI returned ${res.status}, skipping`);
    return [];
  }
  const raw = await res.json();
  const results = raw?.results;
  if (!Array.isArray(results)) {
    console.warn('  CTI.FYI: expected .results array');
    return [];
  }
  const cutoffMs = Date.now() - 90 * 86_400_000;
  const out = [];
  for (const r of results) {
    if (!r?.post_title || !r.group_name || !r.discovered) continue;
    const discovered = safeIsoOr(r.discovered);
    if (Date.parse(discovered) < cutoffMs) continue;
    out.push({
      title: r.post_title.trim(),
      group: r.group_name.trim(),
      discovered,
      description: null,
      country: null,
      sector: null,
      source: 'CTI.FYI',
      source_url: r.post_url || 'https://cti.fyi',
    });
    if (out.length >= 200) break;
  }
  return out;
}

async function fetchXposedOrNotBreaches() {
  const res = await fetchWithTimeout('https://api.xposedornot.com/v1/breaches', 20_000);
  if (!res.ok) {
    console.warn(`  XposedOrNot returned ${res.status}, skipping`);
    return [];
  }
  const raw = await res.json();
  const breaches = raw?.exposedBreaches;
  if (!Array.isArray(breaches)) {
    console.warn('  XposedOrNot: expected .exposedBreaches array');
    return [];
  }
  const cutoffMs = Date.now() - 90 * 86_400_000;
  const out = [];
  for (const b of breaches) {
    if (!b?.breachID || !b.addedDate) continue;
    const discovered = safeIsoOr(b.addedDate);
    if (Date.parse(discovered) < cutoffMs) continue;
    out.push({
      title: b.breachID.trim(),
      group: 'Unattributed',
      discovered,
      description: b.exposureDescription?.trim() || null,
      country: null,
      sector: b.industry?.trim() || null,
      source: 'XposedOrNot',
      source_url: b.referenceURL || `https://xposedornot.com/breach/${encodeURIComponent(b.breachID)}`,
      _extra: {
        breachType: b.breachType || 'DataBreach',
        exposedRecords: b.exposedRecords || 0,
        passwordRisk: b.passwordRisk || null,
        domain: b.domain || null,
        exposedData: b.exposedData || [],
        verified: b.verified || false,
        sensitive: b.sensitive || false,
      },
    });
  }
  return out;
}

/** True when the merged row itself carries that index field (retained rows do). */
function row_has(e, k) {
  return Object.prototype.hasOwnProperty.call(e, k);
}

/** Derive JSON.parse(readFileSync(p)) with undefined on missing/corrupt. */
function readJsonSafe(p) {
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return undefined;
  }
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
  console.log('Fetching breach data from free public trackers...');

  const settled = await Promise.allSettled([
    fetchRansomwareLiveBreaches(),
    fetchRansomlookBreaches(),
    fetchDarkfieldBreaches(),
    fetchDarkfieldGroups(),
    fetchRecentBreaches(),
    fetchCtiFyiBreaches(),
    fetchXposedOrNotBreaches(),
  ]);

  const [fromRl, fromRl2, fromDf, dfGroupsMap, fromRb, fromCti, fromXo] = settled.map((r) =>
    r.status === 'fulfilled' ? r.value : []
  );

  const rlCount = fromRl.length || 0;
  const rl2Count = fromRl2.length || 0;
  const dfCount = fromDf.length || 0;
  const rbCount = fromRb.length || 0;
  const ctiCount = fromCti.length || 0;
  const xoCount = fromXo.length || 0;

  console.log(`  ransomware.live:       ${rlCount} entries`);
  console.log(`  ransomlook.io:         ${rl2Count} entries`);
  console.log(`  Darkfield:             ${dfCount} entries`);
  console.log(`  RecentBreaches.com:    ${rbCount} entries`);
  console.log(`  CTI.FYI:               ${ctiCount} entries`);
  console.log(`  XposedOrNot:           ${xoCount} entries`);

  if (rlCount + rl2Count + dfCount + rbCount + ctiCount + xoCount === 0) {
    console.error('No data fetched from any source — cannot build manifest.');
    process.exit(1);
  }

  // Merge: dedupe by (group + normalized-title + day), preferring richer sources
  const seen = new Set();
  const merged = [];
  const sourcePriority = [
    'ransomware.live', // richest (description, country, activity)
    'Darkfield', // sector + country
    'RecentBreaches.com', // sector + country + claim
    'ransomlook.io',
    'CTI.FYI',
    'XposedOrNot', // different data type, rarely overlaps
  ];

  const allSources = [fromRl, fromDf, fromRb, fromRl2, fromCti, fromXo];
  for (const entries of allSources) {
    for (const e of entries) {
      const day = e.discovered.slice(0, 10);
      const normTitle = e.title
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 80);
      const key = `${e.group}|${normTitle}|${day}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(e);
    }
  }

  // Retention: a partially-reachable upstream (flaky network, tracker purging
  // old pages) must never silently shrink the committed dataset — a partial
  // fetch once shipped 164 rows over main's 350 and the live site lost
  // half its breach history. Retain every committed row that is still inside
  // the 90-day window and is not superseded by a fresh fetch, so the emitted
  // index can only grow within the window until the FILES_LIMIT cap forces
  // natural aging-out.
  const prevIndexPath = join(OUT, 'index.json');
  const prevRows = existsSync(prevIndexPath) ? (readJsonSafe(prevIndexPath)?.breachIndex ?? []) : [];
  const freshCount = merged.length;
  if (prevRows.length > 0 && freshCount < Math.floor(prevRows.length * 0.6)) {
    console.warn(
      `build-breach-watch: fresh fetch returned only ${freshCount} of ${prevRows.length} committed rows — upstream(s) partially reachable; retaining committed history`
    );
  }
  const DAY_MS = 86_400_000;
  const cutoff = new Date(Date.now() - 90 * DAY_MS).toISOString().slice(0, 10);
  for (const row of prevRows) {
    if (typeof row.discovered !== 'string' || row.discovered.slice(0, 10) < cutoff) continue; // outside window
    const day = row.discovered.slice(0, 10);
    const normTitle = row.title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 80);
    const key = `${row.group}|${normTitle}|${day}`;
    if (seen.has(key)) continue; // fresh fetch supersedes the committed row
    const bodyPath = join(OUT, 'breaches', `${row.slug}.json`);
    if (!existsSync(bodyPath)) continue; // body lost — row is unreconstructable
    let bodyJson;
    try {
      bodyJson = JSON.stringify(JSON.parse(readFileSync(bodyPath, 'utf8')));
    } catch {
      continue; // corrupt body — skip rather than ship a broken row
    }
    seen.add(key);
    merged.push({ ...row, _retained: true, _bodyJson: bodyJson });
  }

  // Sort newest first, then cap the emitted window so the total static-asset
  // count stays under the Worker Free plan limit (20,000 per version).
  merged.sort((a, b) => b.discovered.localeCompare(a.discovered));
  if (merged.length > FILES_LIMIT) merged.length = FILES_LIMIT;

  console.log(`  merged (deduped):      ${merged.length} entries`);

  // Wipe output dir
  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  ensureDir(join(OUT, 'breaches'));

  // Build index entries + write per-breach bodies
  const breachIndex = [];
  const groupCounts = new Map();
  const categoryCounts = new Map();

  for (const e of merged) {
    const slug = slugify(`${e.group}-${e.title}-${e.discovered.slice(0, 10)}`);

    // Enrich with Darkfield group aliases
    const groupKey = e.group.toLowerCase();
    const darkfieldGroup = dfGroupsMap instanceof Map ? dfGroupsMap.get(groupKey) : null;

    const severity = e._retained && row_has(e, 'severity') ? e.severity : deriveSeverity(e.group, e._extra);
    const category = e._retained && row_has(e, 'category') ? e.category : deriveCategory(e.group, e._extra);

    groupCounts.set(e.group, (groupCounts.get(e.group) || 0) + 1);
    categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);

    const indexEntry = {
      slug,
      title: e.title,
      group: e.group,
      discovered: e.discovered,
      category,
      severity,
      country: e.country,
      sizeBytes: 0,
    };

    const bodyJson = e._retained
      ? e._bodyJson
      : JSON.stringify({
          ...indexEntry,
          description: e.description,
          source_url: e.source_url,
          groupAliases: darkfieldGroup?.aliases || [],
          activity: e.sector,
          references: [`${e.source}`],
        });
    indexEntry.sizeBytes = Buffer.byteLength(bodyJson, 'utf-8');

    writeFileSync(join(OUT, 'breaches', `${slug}.json`), bodyJson);
    breachIndex.push(indexEntry);
  }

  // Build groups list (sorted by count desc)
  const groups = [...groupCounts.entries()]
    .map(([name, count]) => {
      const groupCategory = deriveCategory(name, {});
      return { name, count, topCategory: groupCategory };
    })
    .sort((a, b) => b.count - a.count);

  // Build categories list
  const categories = [...categoryCounts.entries()]
    .map(([key, count]) => ({
      key,
      label: key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
      count,
    }))
    .sort((a, b) => b.count - a.count);

  const index = {
    source: SOURCE,
    license: LICENSE,
    replicatedAt: new Date().toISOString(),
    counts: {
      breaches: breachIndex.length,
      groups: groups.length,
      categories: categories.length,
    },
    lastSyncedAt: new Date().toISOString(),
    categories,
    groups,
    breachIndex,
  };

  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));
  console.log(`\nWrote ${breachIndex.length} breaches, ${groups.length} groups, ${categories.length} categories`);
  console.log(`  -> ${OUT}/`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
