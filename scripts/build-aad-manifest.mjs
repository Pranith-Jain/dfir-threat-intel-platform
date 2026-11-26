#!/usr/bin/env node
/**
 * Build the Agentic Attack Detections manifest under public/data/aad/.
 *
 * Mirrors the structured metadata of ThreatDefence/agentic-attack-detections
 * (MIT): detection coverage for agentic attack frameworks (ARTEX, Cairn,
 * PentAGI, HexStrike, ...), the sourced indicator CSV, the consolidated
 * ATT&CK Navigator layer, and the shared behavior / general-intrusion rules.
 *
 * Only factual, publicly served fields are replicated. Detection rules live
 * in the upstream repository; each framework body deep-links there. The
 * manifest is intentionally slim enough to be read through env.ASSETS.
 *
 * Emits:
 *   public/data/aad/index.json               (slim — stats, frameworks, shared rule inventory)
 *   public/data/aad/frameworks/<slug>.json   (per-framework coverage + techniques + indicators)
 *   public/data/aad/indicators/<type>.json   (indicator shards by IOC type)
 *   public/data/aad/attack.json              (ATT&CK layer: technique → rule count)
 *
 * Usage:
 *   node scripts/build-aad-manifest.mjs [--source <repo-dir>]
 * `--source` uses a local checkout instead of the GitHub API/raw endpoints.
 * Safe to run repeatedly — wipes public/data/aad/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'aad');

const SOURCE = 'github.com/ThreatDefence/agentic-attack-detections';
const SOURCE_URL = 'https://github.com/ThreatDefence/agentic-attack-detections';
const RAW_BASE = 'https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main';
const API_TREE = 'https://api.github.com/repos/ThreatDefence/agentic-attack-detections/git/trees/main?recursive=1';
const LICENSE = 'MIT';

const args = process.argv.slice(2);
const sourceIdx = args.indexOf('--source');
const SOURCE_DIR = sourceIdx >= 0 && args[sourceIdx + 1] ? resolvePath(args[sourceIdx + 1]) : null;

function local(rel) {
  if (!SOURCE_DIR) return null;
  const p = join(SOURCE_DIR, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

async function remote(rel) {
  const res = await fetch(`${RAW_BASE}/${rel}`, {
    headers: { 'User-Agent': 'dfir-platform-build' },
  });
  if (!res.ok) throw new Error(`${rel}: HTTP ${res.status}`);
  return res.text();
}

async function read(rel) {
  const cached = local(rel);
  if (cached !== null) return cached;
  return remote(rel);
}

async function tree() {
  // The tree endpoint is only used for the shared rule inventory; in offline
  // mode enumerate the local checkout instead.
  if (SOURCE_DIR) {
    const { readdirSync, statSync } = await import('node:fs');
    const files = [];
    const walk = (dir, prefix = '') => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        const rel = prefix ? `${prefix}/${name}` : name;
        if (statSync(p).isDirectory()) walk(p, rel);
        else files.push(rel);
      }
    };
    walk(SOURCE_DIR);
    return files;
  }
  const res = await fetch(API_TREE, {
    headers: { 'User-Agent': 'dfir-platform-build', Accept: 'application/vnd.github+json' },
  });
  if (!res.ok) throw new Error(`tree API: HTTP ${res.status}`);
  const body = await res.json();
  if (body.truncated) throw new Error('tree API response truncated');
  return (body.tree || []).filter((n) => n.type === 'blob').map((n) => n.path);
}

function writeJson(rel, value) {
  const p = join(OUT, rel);
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, JSON.stringify(value, null, 2) + '\n');
}

const clean = (s) => (s || '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/`/g, '').trim();

// Slice a markdown section by its `## Heading` (upstream links are relative:
// `frameworks/<slug>`, not `/blob/main/frameworks/<slug>`).
function section(md, heading) {
  const lines = md.split('\n');
  const start = lines.findIndex((l) => l.trim() === `## ${heading}`);
  if (start < 0) return [];
  const end = lines.findIndex((l, i) => i > start && /^##\s/.test(l.trim()));
  return lines.slice(start + 1, end < 0 ? undefined : end);
}

const slugFrom = (cell) => (cell || '').match(/frameworks\/([a-z0-9-]+)/)?.[1] || null;

// Coverage table: | [Name](frameworks/slug) | KQL | Analytics | Sigma | Suricata | YARA | Zeek | Indicators |
function parseCoverage(md) {
  const rows = {};
  for (const line of section(md, 'Coverage')) {
    if (!line.startsWith('| [')) continue;
    const cells = line.split('|').map((c) => c.trim()).filter((c, i, a) => i > 0 && i < a.length - 1);
    const slug = slugFrom(cells[0]);
    if (!slug) continue;
    const nums = cells.slice(1).map((c) => (c && /^\d+$/.test(c) ? Number(c) : null));
    rows[slug] = {
      slug,
      name: clean(cells[0]),
      kqlHunts: nums[0] || 0,
      analytics: nums[1] || 0,
      sigma: nums[2] || 0,
      suricata: nums[3] || 0,
      yara: nums[4] || 0,
      indicatorsCovered: nums[6] || 0,
    };
  }
  return rows;
}

// Frameworks table: | [Name](frameworks/slug) | What it is | Seen in |
function parseDescriptions(md) {
  const rows = {};
  for (const line of section(md, 'Frameworks')) {
    if (!line.startsWith('| [')) continue;
    const cells = line.split('|').map((c) => c.trim()).filter((c, i, a) => i > 0 && i < a.length - 1);
    const slug = slugFrom(cells[0]);
    if (!slug) continue;
    rows[slug] = {
      description: clean(cells[1]).slice(0, 500),
      seenIn: clean(cells[2]).slice(0, 300),
    };
  }
  return rows;
}

// Minimal RFC-4180 CSV parser (the upstream CSV quotes commas in context).
function parseCsv(text) {
  const rows = [];
  let field = '', row = [], quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const headers = rows.shift().map((h) => h.trim());
  return rows.filter((r) => r.length === headers.length).map((r) =>
    Object.fromEntries(headers.map((h, i) => [h, r[i].trim()])));
}

function parseLayer(text) {
  const layer = JSON.parse(text);
  return {
    description: layer.description || '',
    maxValue: layer.maxValue ?? layer.gradient?.maxValue ?? 0,
    techniques: (layer.techniques || []).map((t) => ({
      id: t.techniqueID,
      score: t.score ?? 0,
      comment: (t.comment || '').slice(0, 600),
    })),
  };
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      try { results[i] = await fn(items[i], i); }
      catch { results[i] = null; }
    }
  }));
  return results;
}

async function main() {
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });

  const [readme, csv, layerText, files] = await Promise.all([
    read('README.md'),
    read('iocs/indicators.csv'),
    read('generated/attack/agentic-attack-detections.json'),
    tree(),
  ]);

  const coverage = parseCoverage(readme);
  const descriptions = parseDescriptions(readme);
  const attack = parseLayer(layerText);
  const indicators = parseCsv(csv);

  // Shared rule inventory (behaviors/ + general/) from the file list.
  const groupRules = (prefix) => {
    const out = [];
    for (const f of files) {
      if (!f.startsWith(`${prefix}/`) || !/\.(kql|yml|yaml|rules|zeek|yar)$/.test(f)) continue;
      const parts = f.split('/');
      out.push({ path: f, kind: parts[1] || '', name: parts.slice(2).join('/') || parts[1] });
    }
    return out;
  };
  const behaviors = groupRules('behaviors');
  const general = groupRules('general');

  // Indicator shards by type + a per-framework slim pointer.
  const byType = new Map();
  const byFramework = new Map();
  for (const row of indicators) {
    const type = row.type || 'string';
    // Shared indicators name several frameworks in one space-separated cell
    // (e.g. "artex cairn"). Attribute the indicator to each of them; treating
    // the whole cell as a slug produced fake frameworks and broke filtering.
    const frameworkList = (row.framework || '').split(/[\s,]+/).filter(Boolean);
    const item = {
      value: (row.value || '').slice(0, 400),
      confidence: row.confidence || '',
      context: (row.context || '').slice(0, 320),
      actor: row.actor || '',
      source: row.source || '',
      sourceUrl: row.source_url || '',
      reported: row.reported || '',
      framework: frameworkList[0] || 'general',
      frameworks: frameworkList,
    };
    if (!byType.has(type)) byType.set(type, []);
    byType.get(type).push(item);
    const owners = frameworkList.length ? frameworkList : ['general'];
    for (const fw of owners) {
      if (!byFramework.has(fw)) byFramework.set(fw, []);
      byFramework.get(fw).push({ ...item, type });
    }
  }
  const typeNames = [...byType.keys()].sort();
  for (const type of typeNames) {
    writeJson(`indicators/${type}.json`, { type, count: byType.get(type).length, items: byType.get(type) });
  }

  // Framework bodies: coverage counts + description + ATT&CK techniques + indicators.
  const slugs = new Set([...Object.keys(coverage), ...Object.keys(descriptions), ...byFramework.keys()]);
  const orderedSlugs = [...slugs].sort();
  const layerPaths = new Set(files.filter((f) => /^generated\/attack\/[a-z0-9-]+\.json$/.test(f)));
  const frameworkLayers = await mapWithConcurrency(orderedSlugs, 6, async (slug) => {
    const rel = `generated/attack/${slug}.json`;
    return layerPaths.has(rel) ? parseLayer(await read(rel)) : null;
  });
  const frameworks = [];
  for (const [idx, slug] of orderedSlugs.entries()) {
    const c = coverage[slug] || {};
    const d = descriptions[slug] || {};
    const fwIndicators = byFramework.get(slug) || [];
    // Prefer the upstream per-framework ATT&CK layer; fall back to techniques
    // whose consolidated-layer comment names this framework.
    const name = c.name || slug;
    const techniques = frameworkLayers[idx]?.techniques || attack.techniques.filter((t) => {
      const hay = `${t.comment} ${t.id}`.toLowerCase();
      return hay.includes(slug.toLowerCase()) || hay.includes(name.toLowerCase());
    });
    const body = {
      slug,
      name,
      description: d.description || '',
      seenIn: d.seenIn || '',
      counts: {
        kqlHunts: c.kqlHunts || 0,
        analytics: c.analytics || 0,
        sigma: c.sigma || 0,
        suricata: c.suricata || 0,
        yara: c.yara || 0,
        indicators: byFramework.get(slug)?.length || 0,
      },
      techniques,
      indicators: fwIndicators.slice(0, 250),
      indicatorsTruncated: fwIndicators.length > 250,
      upstreamUrl: `${SOURCE_URL}/tree/main/frameworks/${slug}`,
      source: SOURCE,
      license: LICENSE,
    };
    writeJson(`frameworks/${slug}.json`, body);
    frameworks.push({
      slug,
      name,
      description: body.description,
      seenIn: body.seenIn,
      counts: body.counts,
      techniqueCount: techniques.length,
    });
  }

  writeJson('attack.json', {
    source: SOURCE,
    sourceUrl: SOURCE_URL,
    description: attack.description,
    maxValue: attack.maxValue,
    techniques: attack.techniques,
  });

  const index = {
    generatedAt: new Date().toISOString(),
    source: SOURCE,
    sourceUrl: SOURCE_URL,
    license: LICENSE,
    description: 'Detection rules, hunting queries and sourced indicators for agentic attack frameworks, curated by ThreatDefence.',
    stats: {
      frameworks: frameworks.length,
      indicators: indicators.length,
      indicatorTypes: typeNames.length,
      attackTechniques: attack.techniques.length,
      behaviorRules: behaviors.length,
      generalRules: general.length,
    },
    indicatorTypes: typeNames.map((type) => ({ type, count: byType.get(type).length })),
    frameworks,
    shared: {
      behaviors: { count: behaviors.length, rules: behaviors },
      general: { count: general.length, rules: general },
    },
  };
  writeJson('index.json', index);

  console.log(`[aad] ${frameworks.length} frameworks, ${indicators.length} indicators, ${attack.techniques.length} ATT&CK techniques -> ${OUT}`);
}

main().catch((err) => { console.error('[aad] build failed:', err); process.exitCode = 1; });
