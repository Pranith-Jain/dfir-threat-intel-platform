#!/usr/bin/env node
/**
 * Mirror the OWASP GenAI Threat Intelligence Initiative feed.
 *
 * https://aithreatintelfeed.org/ publishes a STIX 2.1 bundle generated from
 * github.com/GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative.
 * The repo has no reuse licence, but the feed is published openly; to stay
 * conservative we mirror factual STIX object metadata (names, descriptions
 * where public, external references, category labels and relationships) and
 * deep-link upstream. No repository code is vendored.
 *
 * Output: public/data/ai-cti-feed/{index.json,actors/**,ttps/**,reports/**}
 * Run:    node scripts/build-ai-cti-feed.mjs [--source <stix.json>]
 */
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'ai-cti-feed');
const FEED = 'https://aithreatintelfeed.org/stix/threat-actors-ai-stix2.1.json';
const REPO = 'https://github.com/GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

export function slugify(s = '') {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 100);
}

const categoryOf = (obj) => {
  const labels = Array.isArray(obj.labels) ? obj.labels.join(' ') : '';
  if (/category-a|owasp-genai-category-a/.test(labels)) return 'A';
  if (/category-b|owasp-genai-category-b/.test(labels)) return 'B';
  const ext = obj.ai_cti_category;
  if (Array.isArray(ext) && ext.length) return ext[0];
  return null;
};

const refsOf = (obj) =>
  (Array.isArray(obj.external_references) ? obj.external_references : [])
    .slice(0, 12)
    .map((r) => ({ source: r.source_name ?? null, id: r.external_id ?? null, url: r.url ?? null }));

/** Pure STIX → slim/bodies transform. */
export function parseAiCti(bundle) {
  const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
  const byId = new Map(objects.map((o) => [o.id, o]));
  const relationships = objects.filter((o) => o.type === 'relationship');
  const linksFor = (id) =>
    relationships
      .filter((r) => r.source_ref === id || r.target_ref === id)
      .slice(0, 20)
      .map((r) => ({
        type: r.relationship_type,
        target: r.source_ref === id ? r.target_ref : r.source_ref,
      }));

  const make = (obj) => ({
    id: obj.id,
    name: obj.name ?? obj.value ?? obj.id,
    description: String(obj.description ?? '').slice(0, 4000),
    category: categoryOf(obj),
    labels: Array.isArray(obj.labels) ? obj.labels.slice(0, 20) : [],
    created: obj.created ?? null,
    modified: obj.modified ?? null,
    refs: refsOf(obj),
    links: linksFor(obj.id),
  });

  const groups = { 'intrusion-set': [], 'attack-pattern': [], malware: [], report: [] };
  for (const o of objects) if (groups[o.type]) groups[o.type].push(o);

  const actors = groups['intrusion-set'].map(make);
  const ttps = groups['attack-pattern'].map(make);
  const malware = groups.malware.map(make);
  const reports = groups.report.map(make);
  const indicators = objects
    .filter((o) => o.type === 'indicator')
    .slice(0, 400)
    .map((o) => ({
      id: o.id,
      name: String(o.name ?? o.id).slice(0, 160),
      category: categoryOf(o),
      labels: Array.isArray(o.labels) ? o.labels.slice(0, 10) : [],
      created: o.created ?? null,
    }));

  return {
    actors,
    ttps,
    malware,
    reports,
    indicators,
    counts: {
      objects: objects.length,
      actors: actors.length,
      techniques: ttps.length,
      malware: malware.length,
      reports: reports.length,
      indicators: indicators.length,
      relationships: relationships.length,
      categoryA: objects.filter((o) => categoryOf(o) === 'A').length,
      categoryB: objects.filter((o) => categoryOf(o) === 'B').length,
    },
    byId,
  };
}

function writeBodies(dir, rows) {
  mkdirSync(dir, { recursive: true });
  for (const r of rows) {
    const slug = slugify(`${r.name}-${r.id.split('--')[1] ?? ''}`);
    writeJsonIfChanged(join(dir, `${slug}.json`), r);
  }
}

async function main() {
  const idx = process.argv.indexOf('--source');
  const bundle = idx > 0
    ? JSON.parse(readFileSync(process.argv[idx + 1], 'utf8'))
    : await fetch(FEED, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(60_000) })
        .then(async (r) => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return r.json();
        });
  const { actors, ttps, malware, reports, indicators, counts } = parseAiCti(bundle);
  if (!counts.objects) throw new Error('no STIX objects parsed');

  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  writeBodies(join(OUT, 'actors'), actors);
  writeBodies(join(OUT, 'ttps'), ttps);
  writeBodies(join(OUT, 'malware'), malware);

  const slim = (rows) =>
    rows.map((r) => ({
      id: r.id,
      slug: slugify(`${r.name}-${r.id.split('--')[1] ?? ''}`),
      name: r.name,
      category: r.category,
      created: r.created,
      labels: r.labels,
      refCount: r.refs.length,
    }));
  writeJsonIfChanged(join(OUT, 'index.json'), {
    generatedAt: new Date().toISOString(),
    source: 'OWASP GenAI Threat Intelligence Initiative',
    sourceUrl: FEED,
    repoUrl: REPO,
    license: 'No project-level licence; factual STIX metadata mirrored with deep links upstream.',
    counts,
    actors: slim(actors),
    techniques: slim(ttps),
    malware: slim(malware),
    reports: slim(reports),
    indicators,
  });
  console.log(`  ✓ AI-CTI feed: ${counts.objects} objects / ${counts.actors} actors / ${counts.techniques} techniques → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`ai-cti-feed build failed: ${e.message}`); process.exit(1); });
