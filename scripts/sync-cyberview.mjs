#!/usr/bin/env node
/**
 * Mirror CyberView from its SOURCE REPO (https://github.com/CyberViewTools/CyberView)
 * into public/data/cyberview/.
 *
 * LICENCE CHANGE (2026-11-22): upstream was relicensed proprietary repo-wide
 * ("Relicense CyberView as proprietary", commit on Nov 22 2026). We keep the
 * already-committed `source/` snapshot and our own re-implemented SPA pages,
 * but this sync NO LONGER copies upstream HTML/JS/CSS into `source/` — do not
 * expand the vendored content. Data files produced by the upstream build are
 * still mirrored from the public feed; no upstream code is added.
 *
 * REA captured the five rendered upstream pages; the repo README explains the
 * split: code lives on `main`, facts live on the `data` branch mounted at
 * ./data, and `node scripts/build.mjs --quarantine` rebuilds site/data/*.json.
 * We clone both branches shallowly, run that exact upstream build, and copy its
 * output. Branch SHAs are recorded in manifest.json so the scheduled workflow
 * can skip the clone entirely when nothing changed upstream.
 *
 * The NVD "All CVEs" files (site/data/cve/*) are produced by a separate hourly
 * upstream workflow and are not part of this repo build, so those two files
 * are still taken from the published Pages site.
 *
 * Output: public/data/cyberview/** (+ manifest.json)
 * Run:    node scripts/sync-cyberview.mjs [--force]
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, cpSync, mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'cyberview');
const REPO = 'CyberViewTools/CyberView';
const API = `https://api.github.com/repos/${REPO}`;
const PAGES = 'https://cyberview.tools';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const FORCE = process.argv.includes('--force');
const FORCE_SOURCE = process.argv.includes('--force-source');

const BUILT_FILES = [
  'data/feed.json',
  'data/feed.xml',
  'data/bundle.json',        // map events + kev + docs (globe upgrade reads this)
  'data/trends.json',
  'data/tabletop.json',
  'data/workbench.json',
  'data/health.json',
  'data/chat.json',
  'data/ops.json',
  'data/archive/index.json',
  'data/archive/search.json',
  'data/archive/kev.json',
  'data/archive/events.jsonl',
];
const PAGES_FILES = [
  'data/cve/index.json',     // separate hourly upstream CVE workflow
  'data/cve/recent.json',
];

function git(args, cwd, timeout = 300_000) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] });
}
async function fetchText(url, attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json,*/*', ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) },
        signal: AbortSignal.timeout(45_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) { last = e; }
  }
  throw new Error(`${url}: ${last?.message ?? 'fetch failed'}`);
}
async function branchSha(branch) {
  try {
    const data = JSON.parse(await fetchText(`${API}/branches/${branch}`));
    return String(data.commit?.sha ?? '');
  } catch (e) {
    console.log(`  ! could not read upstream ${branch} SHA (${e.message})`);
    return '';
  }
}
function previous() {
  try { return JSON.parse(readFileSync(join(OUT, 'manifest.json'), 'utf8')); } catch { return {}; }
}

async function main() {
  const [mainSha, dataSha] = await Promise.all([branchSha('main'), branchSha('data')]);
  const prev = previous();
  if (!FORCE && mainSha && dataSha && prev?.upstream?.mainSha === mainSha && prev?.upstream?.dataSha === dataSha && existsSync(join(OUT, 'data', 'bundle.json'))) {
    console.log(`  ✓ upstream unchanged (main ${mainSha.slice(0, 7)}, data ${dataSha.slice(0, 7)}) — skipping sync\n`);
    return;
  }

  const tmp = mkdtempSync(join(tmpdir(), 'cyberview-sync-'));
  const written = [];
  let builtAt = '';
  try {
    if (mainSha && dataSha) {
      console.log('  cloning upstream (shallow) and running its data build');
      git(['clone', '--depth', '1', '--branch', 'main', `https://github.com/${REPO}.git`, 'repo'], tmp);
      const repo = join(tmp, 'repo');
      git(['fetch', '--depth', '1', 'origin', 'data'], repo);
      execFileSync(process.execPath, ['scripts/data-branch.mjs', 'ensure'], { cwd: repo, encoding: 'utf8', timeout: 120_000 });
      execFileSync(process.execPath, ['scripts/build.mjs', '--quarantine'], { cwd: repo, encoding: 'utf8', timeout: 300_000, stdio: ['ignore', 'pipe', 'pipe'] });
      mkdirSync(OUT, { recursive: true });
      for (const rel of BUILT_FILES) {
        const src = join(repo, 'site', rel);
        if (!existsSync(src)) continue;
        const dest = join(OUT, rel);
        mkdirSync(dirname(dest), { recursive: true });
        cpSync(src, dest);
        written.push(rel);
      }
      try { builtAt = String(JSON.parse(readFileSync(join(repo, 'site', 'data', 'manifest.json'), 'utf8')).built_at ?? ''); } catch { /* optional */ }

      // The upstream repository is proprietary (all rights reserved). Keep
      // the already-committed source/ snapshot as a historical port reference
      // but do NOT copy new upstream HTML/JS/CSS into it.
      if (FORCE_SOURCE) {
        const srcSite = join(repo, 'site');
        const srcOut = join(OUT, 'source');
        mkdirSync(srcOut, { recursive: true });
        for (const entry of readdirSync(srcSite, { withFileTypes: true })) {
          if (entry.name === 'data') continue;
          const from = join(srcSite, entry.name);
          const to = join(srcOut, entry.name);
          try {
            cpSync(from, to, { recursive: entry.isDirectory() });
            written.push(`source/${entry.name}`);
          } catch { /* best effort per entry */ }
        }
      } else {
        console.log('  ! source/ mirroring disabled since the upstream proprietary relicence (--force-source to override)');
      }
    } else {
      console.log('  ! SHA lookup unavailable — falling back to published Pages files');
    }
  } catch (e) {
    console.log(`  ! repo build failed (${e.message}) — keeping previous mirror where available`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  // Files produced by the separate upstream hourly CVE workflow.
  for (const rel of PAGES_FILES) {
    try {
      const body = await fetchText(`${PAGES}/${rel}`);
      JSON.parse(body);
      const dest = join(OUT, rel);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, `${body.trimEnd()}\n`);
      if (!written.includes(rel)) written.push(rel);
    } catch (e) {
      console.log(`  ! ${rel} unavailable (${e.message})${existsSync(join(OUT, rel)) ? ' — keeping previous copy' : ''}`);
    }
  }

  // JSON Lines -> JSON array (the home page plots every event without a map lib).
  const jsonl = join(OUT, 'data', 'archive', 'events.jsonl');
  if (existsSync(jsonl)) {
    const events = readFileSync(jsonl, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
    if (events.length) {
      writeFileSync(join(OUT, 'data', 'events.json'), `${JSON.stringify(events)}\n`);
      written.push('data/events.json');
    }
  }

  // Mirror monthly files listed by the upstream index.
  try {
    const index = JSON.parse(readFileSync(join(OUT, 'data', 'archive', 'index.json'), 'utf8'));
    for (const m of (index.months ?? []).map((x) => x.month).filter((m) => /^\d{4}-\d{2}$/.test(m))) {
      const rel = `data/archive/${m}.json`;
      if (!existsSync(join(OUT, rel))) {
        try {
          const body = await fetchText(`${PAGES}/${rel}`);
          JSON.parse(body);
          writeFileSync(join(OUT, rel), `${body.trimEnd()}\n`);
          written.push(rel);
        } catch { /* month already present in repo build or unavailable */ }
      }
    }
  } catch { /* index optional */ }

  let stats = {};
  try {
    const bundle = JSON.parse(readFileSync(join(OUT, 'data', 'bundle.json'), 'utf8'));
    const index = JSON.parse(readFileSync(join(OUT, 'data', 'archive', 'index.json'), 'utf8'));
    stats = {
      events: bundle.events?.length ?? 0,
      kev: bundle.kev?.length ?? 0,
      archiveTotal: index.total ?? 0,
      docs: Object.keys(bundle.docs ?? {}),
    };
  } catch { /* best effort */ }

  const manifest = {
    generatedAt: new Date().toISOString(),
    upstream: {
      repo: `https://github.com/${REPO}`,
      site: PAGES,
      mainSha,
      dataSha,
      builtAt,
      licence: 'Proprietary (all rights reserved since 2026-11-22). source/ snapshot retained but no longer expanded.',
    },
    files: [...new Set(written)],
    stats,
  };
  writeFileSync(join(OUT, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`  ✓ mirrored ${manifest.files.length} files · ${stats.events ?? 0} map events · SHA ${mainSha.slice(0, 7)}/${dataSha.slice(0, 7)}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`cyberview sync failed: ${e.message}`); process.exit(1); });
