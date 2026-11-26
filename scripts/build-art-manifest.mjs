#!/usr/bin/env node
/**
 * Build the Atomic Red Team manifest under public/data/art/.
 *
 * Mirrors the public test catalog behind https://www.atomicredteam.io (the
 * docs site is a Next.js viewer over redcanaryco/atomic-red-team, MIT). Only
 * structured metadata is stored: technique id/name, test name, GUID, plain
 * description, supported platforms, executor *type* and argument/dependency
 * counts. Raw executor commands are deliberately NOT vendored — each test
 * deep-links its upstream YAML, which is the canonical source for the
 * executable test body. This keeps the platform a detection reference, not a
 * payload host.
 *
 * Emits:
 *   public/data/art/index.json               (slim — stats + technique index)
 *   public/data/art/techniques/<T####>.json  (per-technique test bodies)
 *
 * Usage:
 *   node scripts/build-art-manifest.mjs [--source <repo-dir>] [--limit N]
 * `--source` uses a local checkout; otherwise the GitHub tree API + raw YAML.
 * Safe to run repeatedly — wipes public/data/art/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { load as loadYaml } from 'js-yaml';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'art');

const SOURCE = 'github.com/redcanaryco/atomic-red-team';
const SOURCE_URL = 'https://github.com/redcanaryco/atomic-red-team';
const SITE_URL = 'https://www.atomicredteam.io';
const RAW_BASE = 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master';
const API_TREE = 'https://api.github.com/repos/redcanaryco/atomic-red-team/git/trees/master?recursive=1';
const LICENSE = 'MIT';

const args = process.argv.slice(2);
function argValue(name) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : null;
}
const SOURCE_DIR = argValue('--source') ? resolvePath(argValue('--source')) : null;
const LIMIT = argValue('--limit') ? Number(argValue('--limit')) : null;

function local(rel) {
  if (!SOURCE_DIR) return null;
  const p = join(SOURCE_DIR, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

async function remote(rel) {
  const res = await fetch(`${RAW_BASE}/${rel}`, { headers: { 'User-Agent': 'dfir-platform-build' } });
  if (!res.ok) throw new Error(`${rel}: HTTP ${res.status}`);
  return res.text();
}
async function read(rel) {
  const cached = local(rel);
  return cached !== null ? cached : remote(rel);
}

async function listTechniquePaths() {
  if (SOURCE_DIR) {
    const atomics = join(SOURCE_DIR, 'atomics');
    const paths = [];
    for (const name of readdirSync(atomics)) {
      if (!/^T\d{4}(\.\d{3})?$/.test(name)) continue;
      const file = join(atomics, name, `${name}.yaml`);
      if (statSync(file).isFile()) paths.push(`atomics/${name}/${name}.yaml`);
    }
    return paths.sort();
  }
  const res = await fetch(API_TREE, {
    headers: { 'User-Agent': 'dfir-platform-build', Accept: 'application/vnd.github+json' },
  });
  if (!res.ok) throw new Error(`tree API: HTTP ${res.status}`);
  const body = await res.json();
  if (body.truncated) throw new Error('tree API response truncated');
  return (body.tree || [])
    .map((n) => n.path)
    .filter((p) => /^atomics\/T\d{4}(\.\d{3})?\/T\d{4}(\.\d{3})?\.yaml$/.test(p))
    .sort();
}

function writeJson(rel, value) {
  const p = join(OUT, rel);
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, JSON.stringify(value, null, 2) + '\n');
}

const cap = (s, n) => (s || '').replace(/\r/g, '').trim().slice(0, n);

function normalizeTest(t) {
  const executor = t.executor || {};
  return {
    name: cap(t.name, 200),
    guid: t.auto_generated_guid || '',
    description: cap(t.description, 700),
    platforms: Array.isArray(t.supported_platforms) ? t.supported_platforms : [],
    executor: {
      name: executor.name || '',
      elevationRequired: Boolean(executor.elevation_required),
      hasCleanup: Boolean(executor.cleanup_command),
    },
    inputArguments: Object.keys(t.input_arguments || {}),
    dependencyCount: Array.isArray(t.dependencies) ? t.dependencies.length : 0,
  };
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      try { results[i] = await fn(items[i], i); }
      catch (err) { results[i] = { __error: String(err) }; }
    }
  });
  await Promise.all(workers);
  return results;
}

async function main() {
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });

  let paths = await listTechniquePaths();
  if (LIMIT) paths = paths.slice(0, LIMIT);
  const parsed = await mapWithConcurrency(paths, 6, async (path) => {
    const doc = loadYaml(await read(path));
    if (!doc || !doc.attack_technique) throw new Error(`no attack_technique in ${path}`);
    const id = doc.attack_technique;
    const tests = (doc.atomic_tests || []).map(normalizeTest);
    return {
      id,
      displayName: cap(doc.display_name, 300),
      tests,
      upstreamUrl: `${SOURCE}/blob/master/${path}`,
    };
  });

  const platformCounts = {};
  const executorCounts = {};
  const techniques = [];
  let testCount = 0;
  for (const doc of parsed.filter((d) => d && !d.__error)) {
    testCount += doc.tests.length;
    const platforms = [...new Set(doc.tests.flatMap((t) => t.platforms))];
    const executors = [...new Set(doc.tests.map((t) => t.executor.name).filter(Boolean))];
    for (const p of platforms) platformCounts[p] = (platformCounts[p] || 0) + 1;
    for (const e of executors) executorCounts[e] = (executorCounts[e] || 0) + 1;
    writeJson(`techniques/${doc.id}.json`, doc);
    techniques.push({
      id: doc.id,
      displayName: doc.displayName,
      testCount: doc.tests.length,
      platforms,
      executors,
      subtechnique: doc.id.includes('.'),
      upstreamUrl: doc.upstreamUrl,
    });
  }
  techniques.sort((a, b) => a.id.localeCompare(b.id));

  writeJson('index.json', {
    generatedAt: new Date().toISOString(),
    source: SOURCE,
    sourceUrl: SOURCE_URL,
    siteUrl: SITE_URL,
    license: LICENSE,
    description: 'Atomic Red Team test catalog: ATT&CK technique index with test metadata and upstream deep links.',
    stats: {
      techniques: techniques.length,
      tests: testCount,
      platforms: Object.keys(platformCounts).length,
      executors: Object.keys(executorCounts).length,
      failed: parsed.filter((d) => d && d.__error).length,
    },
    platformCounts: Object.fromEntries(Object.entries(platformCounts).sort((a, b) => b[1] - a[1])),
    executorCounts: Object.fromEntries(Object.entries(executorCounts).sort((a, b) => b[1] - a[1])),
    techniques,
  });

  console.log(`[art] ${techniques.length} techniques, ${testCount} tests -> ${OUT}`);
}

main().catch((err) => { console.error('[art] build failed:', err); process.exitCode = 1; });
