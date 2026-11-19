#!/usr/bin/env node
/**
 * Build the Offsec Harness Index manifest under public/data/oh/.
 *
 * Replicates the machine-readable export of offsecharnesses.ai — 154 tracked
 * open-source offensive-AI agent harnesses, 14 seen in real attacks (9
 * confirmed, 5 observed), 26 actors and 32 primary reports. Each evidence
 * row's `uses` entries carry quoted source lines; each field row carries
 * GitHub facts (stars, licence, last push).
 *
 * Source: https://offsecharnesses.ai/data.json  (robots.txt: Allow: /)
 *        https://offsecharnesses.ai/status.json
 * Site:   https://offsecharnesses.ai/
 * Upstream data: github.com/danielmiessler/substrate/tree/main/Data/Offensive-AI-Harnesses
 *
 * No reuse licence is published, so this replication stores structured
 * metadata plus short factual descriptions and deep-links every harness,
 * source and reference to upstream. No prose blocks or images are vendored.
 *
 * Emits:
 *   public/data/oh/index.json            (slim index + stats + rows)
 *   public/data/oh/harnesses/<slug>.json (full harness records)
 *   public/data/oh/sources.json          (32 primary reports)
 *   public/data/oh/references.json       (72 discovery references)
 *
 * Usage: node scripts/build-oh-manifest.mjs [--source <data.json>] [--status <status.json>]
 * Safe to run repeatedly — wipes public/data/oh/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'oh');
const BASE = 'https://offsecharnesses.ai';
const SOURCE = 'offsecharnesses.ai';
const SOURCE_URL = BASE;
const LICENSE = 'No reuse licence published — structured metadata and deep links only';
const UPSTREAM_DATA = 'https://github.com/danielmiessler/substrate/tree/main/Data/Offensive-AI-Harnesses';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

const args = process.argv.slice(2);
function argValue(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}
const LOCAL_SOURCE = argValue('--source');
const LOCAL_STATUS = argValue('--status');

async function loadJson(path, local) {
  if (local) return JSON.parse(readFileSync(local, 'utf8'));
  const resp = await fetch(`${BASE}${path}`, {
    headers: { 'user-agent': UA, accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!resp.ok) throw new Error(`fetch ${path}: ${resp.status} ${resp.statusText}`);
  return await resp.json();
}

export function slugify(name) {
  return String(name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80);
}

export function slimRow(h) {
  return {
    slug: slugify(h.name),
    name: h.name,
    table: h.table ?? null,
    tier: h.tier ?? null,
    kind: h.kind ?? null,
    description: h.description ?? null,
    repo: h.repo ?? null,
    url: h.url ?? `${BASE}/#h-${slugify(h.name)}`,
    stars: h.stars ?? null,
    license: h.license ?? null,
    lastPush: h.last_push ?? null,
    archived: !!h.archived,
    actors: (h.actors ?? []).map((a) => ({ name: a.name, note: a.note ?? null })),
    useTags: (h.uses ?? []).map((u) => u.tag),
    useBasis: (h.uses ?? []).map((u) => u.basis).filter(Boolean),
    breach: h.breach ?? null,
    keyFigure: h.key_figure ?? null,
    sourceCount: Array.isArray(h.sources) ? h.sources.length : 0,
    incidentCount: Array.isArray(h.incidents) ? h.incidents.length : 0,
  };
}

function fullBody(h) {
  return {
    ...slimRow(h),
    whatItDid: h.what_it_did ?? null,
    note: h.note ?? null,
    uses: Array.isArray(h.uses)
      ? h.uses.map((u) => ({ tag: u.tag, basis: u.basis ?? null, source: u.source ?? null, quote: u.quote ?? null }))
      : [],
    sourceIds: Array.isArray(h.sources) ? h.sources : [],
    incidents: Array.isArray(h.incidents) ? h.incidents : [],
    upstreamUrl: h.url ?? `${BASE}/#h-${slugify(h.name)}`,
  };
}

function countBy(rows, key) {
  const out = {};
  for (const r of rows) {
    const v = r[key] == null || r[key] === '' ? 'null' : String(r[key]);
    out[v] = (out[v] ?? 0) + 1;
  }
  return out;
}

function tallyMulti(rows, key) {
  const out = {};
  for (const r of rows) {
    const arr = Array.isArray(r[key]) ? r[key] : [];
    for (const v of arr) {
      const k = typeof v === 'object' ? v?.name ?? v?.tag : v;
      if (k == null || k === '') continue;
      out[k] = (out[k] ?? 0) + 1;
    }
  }
  return Object.entries(out)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));
}

async function main() {
  const builtAt = new Date().toISOString();
  const data = await loadJson('/data.json', LOCAL_SOURCE);
  if (!Array.isArray(data.harnesses) || data.harnesses.length === 0) {
    throw new Error('no harnesses in upstream export');
  }
  let status = null;
  try {
    status = await loadJson('/status.json', LOCAL_STATUS);
  } catch (e) {
    console.warn(`[oh] status.json unavailable (${e.message}) — deriving counts`);
  }

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'harnesses'), { recursive: true });

  for (const h of data.harnesses) {
    writeFileSync(
      join(OUT, 'harnesses', `${slugify(h.name)}.json`),
      JSON.stringify(
        {
          slug: slugify(h.name),
          source: SOURCE,
          sourceUrl: SOURCE_URL,
          license: LICENSE,
          harness: fullBody(h),
        },
        null,
        2,
      ) + '\n',
    );
  }

  writeFileSync(
    join(OUT, 'sources.json'),
    JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, count: (data.sources ?? []).length, sources: data.sources ?? [] }, null, 2) + '\n',
  );
  writeFileSync(
    join(OUT, 'references.json'),
    JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, count: (data.references ?? []).length, references: data.references ?? [] }, null, 2) + '\n',
  );

  const harnesses = data.harnesses;
  const stats = {
    tracked: harnesses.length,
    evidenceRows: status?.evidence_rows ?? harnesses.filter((h) => h.table === 'evidence').length,
    fieldRows: status?.field_rows ?? harnesses.filter((h) => h.table === 'field').length,
    byTier: countBy(harnesses, 'tier'),
    byTable: countBy(harnesses, 'table'),
    byKind: countBy(harnesses, 'kind'),
    byLicense: countBy(harnesses, 'license'),
    byUseTag: tallyMulti(harnesses, 'uses'),
    actors: tallyMulti(harnesses, 'actors').slice(0, 40),
    sourceCount: (data.sources ?? []).length,
    referenceCount: (data.references ?? []).length,
    breaches: harnesses.filter((h) => h.breach === 'Yes').length,
    withRepo: harnesses.filter((h) => !!h.repo).length,
  };

  writeFileSync(
    join(OUT, 'index.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: SOURCE_URL,
        license: LICENSE,
        builtAt,
        upstreamData: UPSTREAM_DATA,
        evidenceReviewed: status?.evidence_reviewed ?? data.evidence_reviewed ?? null,
        githubFacts: status?.field_generated ?? data.github_facts ?? null,
        tiers: data.tiers ?? {},
        useTags: data.use_tags ?? [],
        related: data.related ?? {},
        counts: {
          tracked: harnesses.length,
          inTheWild: harnesses.filter((h) => h.table === 'evidence').length,
          confirmed: harnesses.filter((h) => h.tier === 'confirmed').length,
          observed: harnesses.filter((h) => h.tier === 'observed').length,
          actors: stats.actors.length,
          sources: stats.sourceCount,
          breaches: stats.breaches,
        },
        stats,
        harnesses: harnesses.map(slimRow),
        webPages: {
          index: SOURCE_URL,
          about: `${SOURCE_URL}/about/`,
          data: `${SOURCE_URL}/data/`,
          upstreamData: UPSTREAM_DATA,
        },
      },
      null,
      2,
    ) + '\n',
  );

  console.log(
    `[oh] tracked=${harnesses.length} evidence=${stats.evidenceRows} field=${stats.fieldRows} sources=${stats.sourceCount} shards=${harnesses.length}`,
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
    console.error(`[oh] build failed: ${e.message}`);
    process.exit(1);
  });
}
