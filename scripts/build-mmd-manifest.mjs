#!/usr/bin/env node
/**
 * Build the MMD toolkit manifest under public/data/mmd/.
 *
 * Catalogs the shared codes & tools collection of the MalwareMustDie (MMD)
 * team — github.com/unixfreaxjp/malwaremustdie — the non-profit malware
 * awareness group's open-share repository (tools moved from Google Code in
 * 2017; 427 commits to date). The repo is organized by implementation
 * language: Autoit, Bash, Clang, HTML, Perl, Python, batch, plus etc/,
 * radare2stuff/, radare2test/, slides/ and wiki/.
 *
 * Data is fetched live from the GitHub API (tree + commits) and raw README;
 * the committed manifest is the deliverable, refreshed by the weekly sync
 * workflow when upstream pushes new commits.
 *
 * Emits:
 *   public/data/mmd/index.json         (slim — counts, categories, slim file list, recent commits)
 *   public/data/mmd/categories/<cat>.json (per-category file listing)
 *   public/data/mmd/commits.json       (recent 30 commits)
 *   public/data/mmd/readme.json        (upstream README body)
 *
 * Usage:
 *   node scripts/build-mmd-manifest.mjs [--tree <tree.json>] [--commits <commits.json>]
 * `--tree`/`--commits` point at locally saved GitHub API responses
 * (offline mode); otherwise live calls are made (unauthenticated, 1+1 calls).
 *
 * Safe to run repeatedly — wipes public/data/mmd/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'mmd');

const SOURCE = 'github.com/unixfreaxjp/malwaremustdie';
const SOURCE_URL = 'https://github.com/unixfreaxjp/malwaremustdie';
const SITE_URL = 'https://unixfreaxjp.github.io/malwaremustdie/';
const RAW_BASE = 'https://raw.githubusercontent.com/unixfreaxjp/malwaremustdie/master';
const API_BASE = 'https://api.github.com/repos/unixfreaxjp/malwaremustdie';
const BRANCH = 'master';
const LICENSE = 'Unlicensed (public share, upstream disclaimer applies)';

// Root entries that are files, not tool categories.
const ROOT_FILES = new Set(['README.md', '_config.yml']);
// Directory display metadata (order = page display order).
const CATEGORY_META = {
  Python: 'Python malware-analysis & automation tooling',
  Bash: 'Shell utilities for log triage, diffing and crawling',
  Perl: 'Perl analysis and network scripts',
  Clang: 'C source projects (e.g. the w3bfukk0r web brute-force tool)',
  Autoit: 'AutoIt Windows utilities (WHOIS lookup tools)',
  batch: 'Windows batch helpers',
  HTML: 'Standalone HTML analysis tools (DGA decoders, sample mailers)',
  etc: 'Miscellaneous supporting resources',
  radare2stuff: 'radare2 scripts and r2-based analysis material',
  radare2test: 'radare2 test material and practice targets',
  slides: 'Conference and awareness slides',
  wiki: 'Wiki-documented case notes and references',
};

const args = process.argv.slice(2);
function argValue(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}
const LOCAL_TREE = argValue('--tree');
const LOCAL_COMMITS = argValue('--commits');

function toolKind(ext, size) {
  if (size === 0) return 'empty';
  if (['sh', 'bash'].includes(ext)) return 'script';
  if (['py'].includes(ext)) return 'script';
  if (['pl', 'pm'].includes(ext)) return 'script';
  if (['au3', 'a3x', 'ini'].includes(ext)) return 'script';
  if (['bat', 'cmd'].includes(ext)) return 'script';
  if (['c', 'h', 'cpp', 'cc'].includes(ext)) return 'source';
  if (['md', 'txt', 'rst'].includes(ext)) return 'doc';
  if (['html', 'htm'].includes(ext)) return 'webtool';
  if (['pdf', 'pptx', 'ppt', 'odp'].includes(ext)) return 'slides';
  if (['gz', 'tar', 'tgz', 'zip'].includes(ext)) return 'archive';
  if (['png', 'jpg', 'jpeg', 'gif', 'svg'].includes(ext)) return 'image';
  if (['exe', 'bin', 'elf', 'dll'].includes(ext)) return 'binary';
  if (['r2', 'r2pipe', 'idc', 'py3'].includes(ext)) return 'r2-script';
  return 'resource';
}

function extOf(path) {
  const base = path.split('/').pop() ?? '';
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i + 1).toLowerCase() : '';
}

async function fetchJson(url) {
  const resp = await fetch(url, {
    headers: { accept: 'application/vnd.github+json', 'user-agent': 'mmd-manifest-builder' },
  });
  if (!resp.ok) throw new Error(`fetch ${url}: ${resp.status} ${resp.statusText}`);
  return await resp.json();
}

function readLocalJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

async function main() {
  const builtAt = new Date().toISOString().slice(0, 10);

  // 1. Repo tree (recursive). 230 blobs across 12 directories.
  const tree = LOCAL_TREE
    ? readLocalJson(LOCAL_TREE)
    : await fetchJson(`${API_BASE}/git/trees/${BRANCH}?recursive=1`);
  if (tree.truncated) throw new Error('GitHub tree response truncated — raise the fetch approach');
  const blobs = (tree.tree ?? []).filter((f) => f.type === 'blob');
  if (blobs.length === 0) throw new Error('no files in GitHub tree');

  // 2. Recent commits (activity feed).
  const commitsRaw = LOCAL_COMMITS
    ? readLocalJson(LOCAL_COMMITS)
    : await fetchJson(`${API_BASE}/commits?per_page=30`);
  const commits = (Array.isArray(commitsRaw) ? commitsRaw : []).map((c) => ({
    sha: String(c.sha ?? '').slice(0, 7),
    date: c.commit?.author?.date ?? null,
    author: c.commit?.author?.name ?? c.author?.login ?? null,
    message: (c.commit?.message ?? '').split('\n')[0].slice(0, 160),
  }));

  // 3. README body (kept from the previous build in offline mode).
  let readme = null;
  try {
    const resp = LOCAL_TREE ? null : await fetch(`${RAW_BASE}/README.md`);
    readme = resp && resp.ok ? await resp.text() : null;
  } catch {
    readme = null;
  }
  if (!readme && existsSync(join(OUT, 'readme.json'))) {
    // offline mode keeps the last committed README rather than dropping it
    try {
      readme = readLocalJson(join(OUT, 'readme.json'))?.body ?? null;
    } catch {
      readme = null;
    }
  }

  // 4. Partition into categories.
  const files = [];
  for (const f of blobs) {
    const path = f.path;
    const top = path.split('/')[0];
    if (ROOT_FILES.has(top)) continue;
    const category = path.includes('/') ? top : '_root';
    files.push({
      path,
      name: path.split('/').pop() ?? path,
      category,
      ext: extOf(path),
      kind: toolKind(extOf(path), f.size ?? 0),
      size: f.size ?? 0,
    });
  }
  files.sort((a, b) => a.path.localeCompare(b.path));

  const categories = [...new Set(files.map((f) => f.category))].sort((a, b) => {
    const order = Object.keys(CATEGORY_META);
    const ia = order.indexOf(a) < 0 ? 99 : order.indexOf(a);
    const ib = order.indexOf(b) < 0 ? 99 : order.indexOf(b);
    return ia - ib || a.localeCompare(b);
  });

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'categories'), { recursive: true });

  // 5. Category shards.
  const catSummary = [];
  for (const cat of categories) {
    const catFiles = files.filter((f) => f.category === cat);
    writeFileSync(
      join(OUT, 'categories', `${cat}.json`),
      JSON.stringify(
        {
          category: cat,
          description: CATEGORY_META[cat] ?? 'MMD shared resources',
          count: catFiles.length,
          totalSize: catFiles.reduce((n, f) => n + f.size, 0),
          source: SOURCE,
          sourceUrl: cat === '_root' ? SOURCE_URL : `${SOURCE_URL}/tree/master/${cat}`,
          license: LICENSE,
          files: catFiles,
        },
        null,
        2,
      ) + '\n',
    );
    catSummary.push({
      category: cat,
      description: CATEGORY_META[cat] ?? 'MMD shared resources',
      count: catFiles.length,
      totalSize: catFiles.reduce((n, f) => n + f.size, 0),
      kinds: countBy(catFiles, 'kind'),
    });
  }

  // 6. Commits + readme.
  writeFileSync(
    join(OUT, 'commits.json'),
    JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, count: commits.length, commits }, null, 2) + '\n',
  );
  writeFileSync(
    join(OUT, 'readme.json'),
    JSON.stringify({ source: SOURCE, sourceUrl: SOURCE_URL, license: LICENSE, builtAt, body: readme ?? '' }, null, 2) + '\n',
  );

  // 7. Slim index.
  writeFileSync(
    join(OUT, 'index.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: SOURCE_URL,
        siteUrl: SITE_URL,
        license: LICENSE,
        builtAt,
        branch: BRANCH,
        about:
          'Open-share collection of codes and tools from the MalwareMustDie (MMD) team — a non-profit malware awareness group of network engineers and security researchers (est. 2012). Analysis tooling, log-triage utilities, radare2 material, slides and case notes, organized by implementation language.',
        counts: {
          files: files.length,
          categories: categories.length,
          scripts: files.filter((f) => f.kind === 'script').length,
          docs: files.filter((f) => f.kind === 'doc').length,
          binaries: files.filter((f) => f.kind === 'binary' || f.kind === 'archive').length,
          totalSize: files.reduce((n, f) => n + f.size, 0),
          commitsTracked: 427,
          recentCommits: commits.length,
        },
        categories: catSummary,
        files,
        recentCommits: commits.slice(0, 15),
        lastCommit: commits[0]?.date ?? null,
      },
      null,
      2,
    ) + '\n',
  );

  console.log(
    `[mmd] files=${files.length} categories=${categories.length} scripts=${files.filter((f) => f.kind === 'script').length} recentCommits=${commits.length} lastCommit=${commits[0]?.date ?? 'n/a'}`,
  );
}

function countBy(rows, key) {
  const out = {};
  for (const r of rows) out[r[key]] = (out[r[key]] ?? 0) + 1;
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
    console.error(`[mmd] build failed: ${e.message}`);
    process.exit(1);
  });
}
