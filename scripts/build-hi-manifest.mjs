#!/usr/bin/env node
/**
 * Build the Hacking Incidents ledger manifest under public/data/hi/.
 *
 * Replicates the machine-readable export of hackingincidents.ai — a sourced
 * ledger of cyberattacks where AI use is stated or credibly suspected
 * (286 published reports, Jan 2023 → Nov 2026). Every incident carries an
 * evidence grade (CONFIRMED / STRONG / SUSPECTED), an autonomy band, zero or
 * more primary sources and an enrichment block (models, harness, countries,
 * sectors).
 *
 * Source: https://hackingincidents.ai/incidents.json  (robots.txt: Allow: /)
 * Site:   https://hackingincidents.ai/
 *
 * No reuse licence is published upstream, so this replication stores only
 * structured metadata/factual summaries and deep-links every record to its
 * incident page and primary sources. No prose/assets are vendored.
 *
 * Emits:
 *   public/data/hi/index.json                (slim — stats, months, rows)
 *   public/data/hi/incidents/<YYYY-MM>.json  (month shards, full records)
 *   public/data/hi/stats.json                (computed stats pass-through)
 *
 * Usage: node scripts/build-hi-manifest.mjs [--source <incidents.json>]
 * `--source` points at a locally downloaded incidents.json (offline mode).
 * Safe to run repeatedly — wipes public/data/hi/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'hi');
const BASE = 'https://hackingincidents.ai';
const SOURCE = 'hackingincidents.ai';
const SOURCE_URL = BASE;
const LICENSE = 'No reuse licence published — structured metadata and deep links only';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

const args = process.argv.slice(2);
const sourceIdx = args.indexOf('--source');
const LOCAL_SOURCE = sourceIdx >= 0 ? args[sourceIdx + 1] : null;

async function loadIncidents() {
  if (LOCAL_SOURCE) return JSON.parse(readFileSync(LOCAL_SOURCE, 'utf8'));
  const resp = await fetch(`${BASE}/incidents.json`, {
    headers: { 'user-agent': UA, accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!resp.ok) throw new Error(`fetch incidents.json: ${resp.status} ${resp.statusText}`);
  return await resp.json();
}

/** Upstream snake_case → manifest camelCase; the index stays small enough to load whole. */
export function slimRow(r) {
  const en = r.enrichment ?? {};
  return {
    id: r.id,
    title: r.title,
    date: r.date,
    year: String(r.date ?? '').slice(0, 4),
    month: String(r.date ?? '').slice(0, 7),
    actor: r.actor ?? null,
    actorType: r.actor_type ?? null,
    nexus: r.nexus ?? null,
    targets: r.targets ?? null,
    aiRole: Array.isArray(r.ai_role) ? r.ai_role : [],
    models: Array.isArray(r.models) ? r.models : [],
    modelBasis: r.model_basis ?? null,
    autonomy: r.autonomy ?? null,
    confidence: String(r.confidence ?? '').toLowerCase(),
    sourceCount: Array.isArray(r.sources) ? r.sources.length : 0,
    primarySourceCount: Array.isArray(r.sources) ? r.sources.filter((s) => s.primary).length : 0,
    modelNamed: en.model_named ?? false,
    harnessUsed: en.harness?.used ?? false,
    harnessNames: Array.isArray(en.harness?.names) ? en.harness.names : [],
    countries: Array.isArray(en.countries) ? en.countries : [],
    sectors: Array.isArray(en.sectors) ? en.sectors : [],
  };
}

export function fullBody(r) {
  return {
    ...slimRow(r),
    outcome: r.outcome ?? null,
    confidenceReason: r.confidence_reason ?? null,
    summary: r.summary ?? '',
    quote: r.quote ?? null,
    singleSourceReason: r.single_source_reason ?? null,
    disclosed: r.disclosed ?? null,
    activity: r.activity ?? null,
    enrichment: r.enrichment ?? null,
    sources: (Array.isArray(r.sources) ? r.sources : []).map((s) => ({
      title: s.title ?? null,
      publisher: s.publisher ?? null,
      url: s.url,
      date: s.date ?? null,
      verifiedOn: s.verified_on ?? null,
      primary: !!s.primary,
      quoteFound: !!s.quote_found,
    })),
    upstreamUrl: `${BASE}/incident/${r.id}/`,
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
    const arr = Array.isArray(r[key]) ? r[key] : r[key] ? [r[key]] : [];
    for (const v of arr) {
      if (v == null || v === '') continue;
      out[v] = (out[v] ?? 0) + 1;
    }
  }
  return out;
}

async function main() {
  const builtAt = new Date().toISOString();
  const dist = await loadIncidents();
  if (!Array.isArray(dist.incidents) || dist.incidents.length === 0) {
    throw new Error('no incidents in upstream export');
  }
  const incidents = dist.incidents;

  // Month shards — keyed by the ledger's own YYYY-MM date.
  const byMonth = new Map();
  for (const r of incidents) {
    const month = String(r.date ?? '').slice(0, 7);
    if (!/^\d{4}-\d{2}$/.test(month)) throw new Error(`bad date for ${r.id}: ${r.date}`);
    if (!byMonth.has(month)) byMonth.set(month, []);
    byMonth.get(month).push(r);
  }

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'incidents'), { recursive: true });

  const months = [...byMonth.keys()].sort();
  for (const month of months) {
    writeFileSync(
      join(OUT, 'incidents', `${month}.json`),
      JSON.stringify(
        {
          month,
          count: byMonth.get(month).length,
          source: SOURCE,
          sourceUrl: SOURCE_URL,
          license: LICENSE,
          incidents: byMonth.get(month).map(fullBody),
        },
        null,
        2,
      ) + '\n',
    );
  }

  const stats = {
    count: incidents.length,
    months: Object.fromEntries(months.map((m) => [m, byMonth.get(m).length])),
    byYear: countBy(incidents.map(withYear), 'year'),
    byConfidence: countBy(incidents.map(lowerConfidence), 'confidence'),
    byAutonomy: countBy(incidents, 'autonomy'),
    byActorType: countBy(incidents, 'actor_type'),
    byRole: tallyMulti(incidents, 'ai_role'),
    byCountry: tallyMulti(incidents.map(withCountries), 'countries'),
    bySector: tallyMulti(incidents.map(withSectors), 'sectors'),
    sources: {
      links: incidents.reduce((n, r) => n + (Array.isArray(r.sources) ? r.sources.length : 0), 0),
      primary: incidents.reduce((n, r) => n + (Array.isArray(r.sources) ? r.sources.filter((s) => s.primary).length : 0), 0),
      uniqueUrls: [...new Set(incidents.flatMap((r) => (r.sources ?? []).map((s) => s.url)))].length,
    },
    namedModels: incidents.filter((r) => r.enrichment?.model_named).length,
    harnessUse: incidents.filter((r) => r.enrichment?.harness?.used).length,
  };
  writeFileSync(
    join(OUT, 'stats.json'),
    JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, stats }, null, 2) + '\n',
  );

  const slim = incidents.map(slimRow);
  slim.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.id < b.id ? 1 : -1));

  writeFileSync(
    join(OUT, 'index.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: SOURCE_URL,
        license: LICENSE,
        builtAt,
        upstreamUpdated: dist.updated ?? null,
        counts: {
          records: incidents.length,
          months: months.length,
          confirmed: incidents.filter((r) => String(r.confidence).toLowerCase() === 'confirmed').length,
          strong: incidents.filter((r) => String(r.confidence).toLowerCase() === 'strong').length,
          suspected: incidents.filter((r) => String(r.confidence).toLowerCase() === 'suspected').length,
          namedModels: stats.namedModels,
          harnessUse: stats.harnessUse,
          sourceLinks: stats.sources.links,
        },
        stats,
        months,
        incidents: slim,
        webPages: {
          ledger: SOURCE_URL,
          incidents: `${SOURCE_URL}/incidents/`,
          analysis: `${SOURCE_URL}/analysis/`,
          data: `${SOURCE_URL}/data/`,
          method: `${SOURCE_URL}/method/`,
        },
      },
      null,
      2,
    ) + '\n',
  );

  console.log(
    `[hi] records=${incidents.length} months=${months.length} confirmed=${(stats.byConfidence.confirmed ?? 0)} shards=${months.length}`,
  );
}

function withYear(r) {
  return { ...r, year: String(r.date ?? '').slice(0, 4) };
}
function lowerConfidence(r) {
  return { ...r, confidence: String(r.confidence ?? '').toLowerCase() };
}
function withCountries(r) {
  return { ...r, countries: Array.isArray(r.enrichment?.countries) ? r.enrichment.countries : [] };
}
function withSectors(r) {
  return { ...r, sectors: Array.isArray(r.enrichment?.sectors) ? r.enrichment.sectors : [] };
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
    console.error(`[hi] build failed: ${e.message}`);
    process.exit(1);
  });
}
