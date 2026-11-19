#!/usr/bin/env node
/**
 * Sync The OSINT Toolbox (github.com/The-Osint-Toolbox, aka CQCore) into a
 * single browsable directory: every public repository plus every external
 * tool link published in their READMEs.
 *
 * Sources (all public, no key):
 *   - https://api.github.com/users/The-Osint-Toolbox
 *   - https://api.github.com/users/The-Osint-Toolbox/repos?per_page=100
 *   - https://raw.githubusercontent.com/<repo>/<default_branch>/README.md
 *
 * The root README's "Quick Links" table supplies the upstream's own category
 * labels. Four links point at repos that were renamed later; ALIASES maps
 * those old slugs to their current names.
 *
 * Output: public/data/osint-toolbox/index.json (+ README.md)
 *
 * Attribution is preserved from the root README: these are the author's
 * curated bookmarks, not recommendations or endorsements, and some resources
 * are paid. Link text and URLs are kept verbatim (entities decoded).
 *
 * Run: node scripts/sync-osint-toolbox.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'osint-toolbox');
const OWNER = 'The-Osint-Toolbox';
const ROOT_REPO = 'The-OSINT-Toolbox';
const API = `https://api.github.com/users/${OWNER}`;
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const TIMEOUT_MS = 30_000;
const concurrency = 8;

const ALIASES = {
  'Data-OSINT': 'Data-Acquisition-OSINT',
  'Company-OSINT': 'Company-Business-OSINT',
  'GitHub-OSINT-Resources': 'GitHub-OSINT-Accounts',
  'OSINT-Practitioners': 'OSINT-Communities-Practitioners',
};

async function fetchText(url, accept = 'text/plain') {
  let lastErr;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      return await res.text();
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(`${url}: ${lastErr?.message ?? 'fetch failed'}`);
}

async function fetchJson(url) {
  return JSON.parse(await fetchText(url, 'application/vnd.github+json'));
}

export function decodeEntities(value) {
  return String(value ?? '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)));
}

function cleanText(value) {
  return decodeEntities(value.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
}

function canonicalUrl(value) {
  try {
    const u = new URL(value);
    for (const key of [...u.searchParams.keys()]) {
      if (key.startsWith('utm_') || key === 'ref' || key === 'source') u.searchParams.delete(key);
    }
    u.hash = '';
    return `${u.origin}${u.pathname.replace(/\/$/, '')}${u.searchParams.size ? `?${u.searchParams}` : ''}`;
  } catch {
    return value.trim();
  }
}

/** Upstream quick-links table -> repo name -> category label. */
export function parseQuickLinks(readme) {
  const labels = new Map();
  const re = /<a\b[^>]*href="https:\/\/github\.com\/(?:The-Osint-Toolbox|cqcore)\/([^"/#?]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  for (const m of readme.matchAll(re)) {
    const repo = ALIASES[m[1]] ?? m[1];
    const label = cleanText(m[2]);
    if (repo && label) labels.set(repo, label);
  }
  return labels;
}

const IMAGE_EXT = /\.(png|jpe?g|gif|svg|webp|ico|bmp)(\?|$)/i;

/** Every distinct external resource linked from a repo README. */
export function extractTools(readme, repoName, category, limit = 400) {
  const seen = new Set();
  const tools = [];
  const re = /<a\b[^>]*href="(https?:\/\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  for (const m of readme.matchAll(re)) {
    if (tools.length >= limit) break;
    const url = cleanText(m[1]);
    const name = cleanText(m[2]);
    if (!url || !name || IMAGE_EXT.test(url)) continue;
    if (/github\.com\/(The-Osint-Toolbox|cqcore)\//i.test(url)) continue;
    if (/cqcore\.uk/i.test(url)) continue;
    const key = canonicalUrl(url).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    tools.push({
      name: name.slice(0, 140),
      url: url.slice(0, 600),
      repo: repoName,
      category,
    });
  }
  return tools;
}

async function mapWithConcurrency(items, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      // eslint-disable-next-line no-await-in-loop
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

export function buildDataset({ profile, repos, readmes, now = new Date().toISOString() }) {
  const labels = parseQuickLinks(readmes[ROOT_REPO] ?? '');
  const allTools = [];
  const repoRows = [];

  for (const repo of repos) {
    const category = labels.get(repo.name) ?? repo.name.replace(/-/g, ' ');
    const tools = extractTools(readmes[repo.name] ?? '', repo.name, category);
    allTools.push(...tools);
    repoRows.push({
      name: repo.name,
      fullName: repo.full_name,
      url: repo.html_url,
      description: repo.description ?? '',
      homepage: repo.homepage || null,
      category,
      stars: repo.stargazers_count ?? 0,
      forks: repo.forks_count ?? 0,
      topics: Array.isArray(repo.topics) ? repo.topics.slice(0, 12) : [],
      createdAt: repo.created_at ?? null,
      pushedAt: repo.pushed_at ?? null,
      defaultBranch: repo.default_branch ?? 'main',
      toolCount: tools.length,
    });
  }

  const categories = [...new Set(repoRows.map((r) => r.category))].sort((a, b) => a.localeCompare(b));
  return {
    generatedAt: now,
    source: {
      name: profile.name || profile.login || OWNER,
      login: profile.login ?? OWNER,
      url: profile.html_url ?? `https://github.com/${OWNER}`,
      api: `${API}/repos`,
      description: profile.description ?? '',
      followers: profile.followers ?? 0,
      publicRepos: profile.public_repos ?? repos.length,
    },
    stats: {
      repos: repoRows.length,
      tools: allTools.length,
      stars: repoRows.reduce((sum, r) => sum + r.stars, 0),
      categories: categories.length,
    },
    categories,
    repos: repoRows.sort((a, b) => a.category.localeCompare(b.category) || b.stars - a.stars),
    tools: allTools.sort((a, b) => a.name.localeCompare(b.name) || a.repo.localeCompare(b.repo)),
  };
}

function writeReadme(dataset) {
  const lines = [
    '# The OSINT Toolbox directory',
    '',
    'Generated by `scripts/sync-osint-toolbox.mjs`. Do not edit by hand.',
    '',
    `- Synced: ${dataset.generatedAt}`,
    `- Upstream: ${dataset.source.url}`,
    `- ${dataset.stats.repos} repositories · ${dataset.stats.tools} external tool links · ${dataset.stats.categories} categories`,
    '',
    'Repository metadata comes from the public GitHub API; tool links are the',
    'external anchors in each repo README, with link text and URLs kept verbatim.',
    'Category labels come from the root README Quick Links table. Links are not',
    'recommendations or endorsements, and some resources are paid — see the',
    'attribution on the page.',
    '',
  ];
  writeFileSync(join(OUT, 'README.md'), lines.join('\n'));
}

async function main() {
  console.log(`  fetching ${OWNER} profile + repositories`);
  const [profile, repos] = await Promise.all([
    fetchJson(API),
    fetchJson(`${API}/repos?per_page=100&sort=full_name&type=public`),
  ]);
  if (!Array.isArray(repos) || repos.length === 0) throw new Error('GitHub returned no repositories');
  console.log(`    ✔ ${repos.length} public repos`);

  const targets = [{ name: ROOT_REPO, full_name: `${OWNER}/${ROOT_REPO}`, default_branch: 'main' }, ...repos];
  const readmeList = await mapWithConcurrency(targets, async (repo) => {
    const branch = repo.default_branch || 'main';
    const url = `https://raw.githubusercontent.com/${repo.full_name}/${branch}/README.md`;
    try {
      return await fetchText(url);
    } catch {
      // A few repos may use readme.md or a different default branch.
      return fetchText(`https://raw.githubusercontent.com/${repo.full_name}/${branch}/readme.md`);
    }
  });
  const readmes = Object.fromEntries(
    targets.map((repo, i) => [repo.name, readmeList[i]]).filter(([, text]) => typeof text === 'string')
  );
  console.log(`    ✔ ${Object.keys(readmes).length} READMEs parsed`);

  const dataset = buildDataset({ profile, repos, readmes });
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(dataset));
  writeReadme(dataset);
  console.log(
    `  ✓ ${dataset.stats.repos} repos · ${dataset.stats.tools} tools · ${dataset.stats.stars.toLocaleString('en-US')} stars`
  );
  console.log(`  → ${OUT}/index.json\n`);
}

const invokedDirectly =
  process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;

if (invokedDirectly) {
  main().catch((err) => {
    console.error(`  ✗ ${err.message ?? err}`);
    process.exit(1);
  });
}
