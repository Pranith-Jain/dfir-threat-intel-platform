#!/usr/bin/env node
/**
 * Build the ORCA AI Incident Archive manifest under public/data/orca/.
 *
 * Replicates the machine-readable export of
 * Continuum-AI-Corp/Orca-AI-Incident-Archive (CC BY 4.0): an open database of
 * real-world AI agent security incidents (417 records, 2024-12 → 2026-11).
 *
 * Source: https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive
 *         dist/incidents.json (schema 2) + dist/stats.json
 *
 * The upstream `dist/` export is generated from the YAML frontmatter of
 * each incident record — every record carries at least one clickable primary
 * source. Records whose `kind` is `policy`/`report` are informational moves,
 * not incidents; `real_harm` separates confirmed victims from research demos.
 * English fields only are replicated (the six upstream translations are
 * dropped to keep the manifest lean); each record deep-links its upstream
 * source file for the full translated text.
 *
 * Emits:
 *   public/data/orca/index.json               (slim — stats + months + slim rows)
 *   public/data/orca/incidents/<YYYY-MM>.json (month shards, full English records)
 *   public/data/orca/stats.json               (upstream stats pass-through)
 *
 * Usage:
 *   node scripts/build-orca-manifest.mjs [--source <incidents.json>]
 * `--source` points at a locally downloaded dist/incidents.json (offline
 * mode); otherwise it is fetched from raw.githubusercontent.com.
 *
 * Safe to run repeatedly — wipes public/data/orca/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'orca');

const SOURCE = 'github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive';
const SOURCE_URL = 'https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive';
const RAW_BASE = 'https://raw.githubusercontent.com/Continuum-AI-Corp/Orca-AI-Incident-Archive/main';
const LICENSE = 'CC BY 4.0';
const UPSTREAM_BLOB = `${SOURCE_URL}/blob/main`;

const args = process.argv.slice(2);
const sourceIdx = args.indexOf('--source');
const LOCAL_SOURCE = sourceIdx >= 0 ? args[sourceIdx + 1] : null;

/** Upstream field (snake_case) → manifest field (camelCase). */
function slimRow(r) {
  return {
    id: r.id,
    title: r.title,
    date: r.date,
    dateEnd: r.date_end ?? null,
    month: r.month,
    kind: r.kind,
    types: r.type ?? [],
    severity: r.severity,
    confidence: r.confidence,
    realHarm: r.real_harm ?? null,
    aiInvolvement: r.ai_involvement,
    regions: r.region ?? [],
    landmark: !!r.landmark,
    disputed: !!r.disputed,
    sourceCount: Array.isArray(r.sources) ? r.sources.length : 0,
  };
}

function fullBody(r) {
  return {
    ...slimRow(r),
    datePrecision: r.date_precision,
    dateRaw: r.date_raw ?? null,
    summary: r.summary ?? '',
    sources: (r.sources ?? []).map((s) => ({ url: s.url, label: s.label ?? s.url })),
    upstreamPath: r.path ?? null,
    upstreamUrl: r.path ? `${UPSTREAM_BLOB}/${r.path}` : SOURCE_URL,
  };
}

async function loadJson(relPath) {
  if (LOCAL_SOURCE) {
    return JSON.parse(readFileSync(LOCAL_SOURCE, 'utf8'));
  }
  const resp = await fetch(`${RAW_BASE}/${relPath}`);
  if (!resp.ok) throw new Error(`fetch ${relPath}: ${resp.status} ${resp.statusText}`);
  return await resp.json();
}

async function main() {
  const builtAt = new Date().toISOString().slice(0, 10);

  const dist = await loadJson('dist/incidents.json');
  if (!Array.isArray(dist.incidents) || dist.incidents.length === 0) {
    throw new Error('no incidents in upstream export');
  }
  let stats = null;
  try {
    stats = await loadJson('dist/stats.json');
  } catch {
    console.warn('[orca] stats.json fetch failed — deriving stats locally');
  }

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'incidents'), { recursive: true });

  // ─── 1. Month shards (full English bodies) ─────────────────────────────
  const byMonth = new Map();
  for (const r of dist.incidents) {
    const month = r.month || String(r.id).slice(0, 7);
    if (!/^\d{4}-\d{2}$/.test(month)) throw new Error(`bad month for ${r.id}: ${month}`);
    if (!byMonth.has(month)) byMonth.set(month, []);
    byMonth.get(month).push(r);
  }
  const months = [...byMonth.keys()].sort();
  for (const month of months) {
    const rows = byMonth.get(month);
    writeFileSync(
      join(OUT, 'incidents', `${month}.json`),
      JSON.stringify(
        {
          month,
          count: rows.length,
          source: SOURCE,
          sourceUrl: SOURCE_URL,
          license: LICENSE,
          incidents: rows.map(fullBody),
        },
        null,
        2,
      ) + '\n',
    );
  }

  // ─── 2. Stats (upstream pass-through, with a local fallback) ───────────
  const localStats = {
    version: dist.version,
    count: dist.incidents.length,
    months: Object.fromEntries(months.map((m) => [m, byMonth.get(m).length])),
    by_severity: countBy(dist.incidents, 'severity'),
    by_kind: countBy(dist.incidents, 'kind'),
    by_type: tallyMulti(dist.incidents, 'type'),
    by_confidence: countBy(dist.incidents, 'confidence'),
    by_region: tallyMulti(dist.incidents, 'region'),
    real_harm: {
      true: dist.incidents.filter((r) => r.real_harm === true).length,
      false: dist.incidents.filter((r) => r.real_harm === false).length,
      null: dist.incidents.filter((r) => r.real_harm == null).length,
    },
    ai_involvement: countBy(dist.incidents, 'ai_involvement'),
    sources: {
      links: dist.incidents.reduce((n, r) => n + (Array.isArray(r.sources) ? r.sources.length : 0), 0),
      unique_urls: [...new Set(dist.incidents.flatMap((r) => (r.sources ?? []).map((s) => s.url)))].length,
    },
  };
  writeFileSync(
    join(OUT, 'stats.json'),
    JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, stats: stats ?? localStats }, null, 2) + '\n',
  );

  // ─── 3. Slim index ─────────────────────────────────────────────────────
  const slim = dist.incidents.map(slimRow);
  // Newest first (date desc) — the archive reads chronologically.
  slim.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.id < b.id ? 1 : -1));
  writeFileSync(
    join(OUT, 'index.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: SOURCE_URL,
        license: LICENSE,
        builtAt,
        upstreamVersion: dist.version,
        upstreamSchema: dist.schema_version ?? dist.schema,
        languages: dist.languages ?? ['en'],
        counts: {
          records: dist.incidents.length,
          months: months.length,
          realHarm: dist.incidents.filter((r) => r.real_harm === true).length,
          critical: dist.incidents.filter((r) => r.severity === 'critical').length,
          incidents: dist.incidents.filter((r) => r.kind === 'incident').length,
          disputed: dist.incidents.filter((r) => r.disputed).length,
          landmark: dist.incidents.filter((r) => r.landmark).length,
          sources: (stats ?? localStats).sources?.links ?? null,
        },
        stats: stats ?? localStats,
        months,
        incidents: slim,
      },
      null,
      2,
    ) + '\n',
  );

  console.log(
    `[orca] records=${dist.incidents.length} months=${months.length} real_harm=${(stats ?? localStats).real_harm?.true ?? '?'} shards=${months.length} (upstream ${dist.version})`,
  );
}

function countBy(rows, key) {
  const out = {};
  for (const r of rows) {
    const v = r[key] == null ? 'null' : String(r[key]);
    out[v] = (out[v] ?? 0) + 1;
  }
  return out;
}

function tallyMulti(rows, key) {
  const out = {};
  for (const r of rows) {
    const arr = Array.isArray(r[key]) ? r[key] : [r[key]];
    for (const v of arr) {
      if (v == null) continue;
      out[v] = (out[v] ?? 0) + 1;
    }
  }
  return out;
}

const isMain = (() => {
  if (typeof process === 'undefined' || !process.argv[1]) return false;
  try {
    return resolvePath(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();
if (isMain) {
  main().catch((e) => {
    console.error(`[orca] build failed: ${e.message}`);
    process.exit(1);
  });
}
