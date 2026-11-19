#!/usr/bin/env node
/**
 * Sync the Cheyenne earth-observation board documentation into
 * public/data/cheyenne/index.json.
 *
 * Upstream (inspected with REA, 2026-11-19):
 *   https://github.com/MJCruickshank/cheyenne
 *   - README.md            overview, features, install, data sources, limits, credits
 *   - web/catalog.json     23 satellite constellations in 6 operator groups
 *   - docs/screenshots/*    images embedded in the README
 *
 * This is a documentation mirror, not a copy of the desktop app: the page
 * renders upstream's own descriptions, tables and images with attribution.
 * No data or claims are synthesised here.
 *
 * Run: node scripts/sync-cheyenne.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'cheyenne');
const OWNER = 'MJCruickshank';
const REPO = 'cheyenne';
const API = `https://api.github.com/repos/${OWNER}/${REPO}`;
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const TIMEOUT_MS = 30_000;

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

function decode(value) {
  return String(value ?? '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'");
}

function clean(value, keepBold = false) {
  let out = decode(value)
    .replace(/<[^>]+>/g, '')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1')
    .replace(/`([\s\S]*?)`/g, '$1');
  if (!keepBold) out = out.replace(/\*\*/g, '');
  return out.replace(/\s+/g, ' ').trim();
}

/** First link in a markdown cell, plus the cell text without link syntax. */
function cell(value) {
  const raw = String(value ?? '').trim();
  const link = raw.match(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/);
  return {
    text: clean(raw.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '$1')),
    url: link ? link[2] : null,
  };
}

/** Substring of a Markdown heading section, up to the next same/higher heading. */
export function section(readme, heading, level = 2) {
  const marks = '#'.repeat(level);
  const re = new RegExp(`^${marks} ${heading.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}[ \\t]*$`, 'm');
  const start = readme.search(re);
  if (start < 0) return '';
  const from = readme.indexOf('\n', start) + 1;
  const next = readme.slice(from).search(/^#{1,3} /m);
  return next < 0 ? readme.slice(from) : readme.slice(from, from + next);
}

/** Markdown bullets, folding indented continuation lines into the item. */
export function bullets(text, keepBold = false) {
  const out = [];
  for (const line of text.split('\n')) {
    const item = line.match(/^\s*[-*]\s+(.+)$/);
    if (item) {
      out.push(item[1].trim());
    } else if (out.length && /^\s+\S/.test(line) && !/^\s*(\||#|>)/.test(line)) {
      out[out.length - 1] += ` ${line.trim()}`;
    }
  }
  return out.filter(Boolean).map((line) => clean(line, keepBold));
}

/** Pipe table -> array of cell objects keyed by the header row. */
export function table(text) {
  const rows = text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('|'));
  if (rows.length < 2) return [];
  const split = (line) => line.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  const headers = split(rows[0]);
  const out = [];
  for (const row of rows.slice(1)) {
    const cells = split(row);
    if (cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
    const entry = {};
    headers.forEach((h, i) => {
      entry[clean(h).toLowerCase().replace(/\s+/g, '')] = cell(cells[i] ?? '');
    });
    out.push(entry);
  }
  return out;
}

export function featureCards(text) {
  return bullets(text, true).map((line) => {
    const bold = line.match(/^\*\*(.+?)\*\*\s*([\s\S]*)$/);
    if (!bold) return { title: '', body: line };
    return {
      title: clean(bold[1]).replace(/\.$/, ''),
      body: clean(bold[2]),
    };
  });
}

export function extractScreenshots(readme, rawBase) {
  const out = [];
  const re = /!\[([^\]]*)\]\((docs\/screenshots\/[^)]+)\)/g;
  for (const m of readme.matchAll(re)) {
    if (out.some((s) => s.url.endsWith(m[2]))) continue;
    out.push({ alt: clean(m[1]), url: `${rawBase}/${m[2]}` });
  }
  return out;
}

function firstCodeBlock(text) {
  const m = text.match(/```[a-z]*\n([\s\S]*?)```/i);
  return m ? m[1].trim() : '';
}

function prose(text) {
  return text
    .split('\n')
    .filter((l) => l.trim() && !l.trim().startsWith('|') && !l.trim().startsWith('#') && !l.trim().startsWith('<') && !l.trim().startsWith('!'))
    .map((l) => clean(l))
    .join(' ')
    .trim();
}

export function buildDataset({ meta, readme, catalog, now = new Date().toISOString() }) {
  const branch = meta.default_branch || 'main';
  const rawBase = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${branch}`;
  const overview = prose(section(readme, 'Cheyenne', 1).slice(0, 1400));
  const features = featureCards(section(readme, 'Features'));
  const dataSources = table(section(readme, 'Data sources')).map((r) => ({
    data: r.data?.text ?? '',
    source: r.source?.text ?? '',
    url: r.source?.url ?? null,
  }));
  const aisFeeds = table(section(readme, 'AIS: ship tracking')).map((r) => ({
    feed: r.feed?.text ?? '',
    url: r.feed?.url ?? null,
    area: r.area?.text ?? '',
    key: r.key?.text ?? '',
    usage: r.howitisused?.text ?? '',
  }));
  const footprints = table(section(readme, 'What the future footprints mean', 3)).map((r) => ({
    label: r.label?.text ?? '',
    source: r.source?.text ?? '',
    reliability: r.reliability?.text ?? '',
  }));
  const credits = table(section(readme, 'Credits and licences')).map((r) => ({
    component: r.component?.text ?? '',
    url: r.component?.url ?? null,
    licence: r.licence?.text ?? '',
  }));

  const groups = Array.isArray(catalog?.groups) ? catalog.groups : [];
  const fleets = Array.isArray(catalog?.constellations)
    ? catalog.constellations.map((c) => ({
        id: c.id,
        name: c.name,
        group: c.group,
        operator: c.operator ?? '',
        sensor: c.sensor ?? '',
        instrument: c.instrument ?? '',
        gsd: c.gsd ?? '',
        revisit: c.revisit ?? '',
        color: c.color ?? '',
        access: c.access ?? '',
        defaultVisible: c.defaultVisible === true,
      }))
    : [];

  return {
    generatedAt: now,
    source: {
      name: meta.name ?? REPO,
      fullName: meta.full_name ?? `${OWNER}/${REPO}`,
      url: meta.html_url ?? `https://github.com/${OWNER}/${REPO}`,
      description: meta.description ?? '',
      stars: meta.stargazers_count ?? 0,
      forks: meta.forks_count ?? 0,
      pushedAt: meta.pushed_at ?? null,
      license: meta.license?.spdx_id ?? null,
      readmeUrl: `${rawBase}/README.md`,
      catalogUrl: `${rawBase}/web/catalog.json`,
    },
    overview,
    features,
    screenshots: extractScreenshots(readme, rawBase),
    groups,
    fleets,
    dataSources,
    aisFeeds,
    footprints,
    limitations: bullets(section(readme, 'Limitations')),
    credits,
    creditsNote: prose(section(readme, 'Credits and licences')),
    install: {
      requirements: bullets(section(readme, 'Requirements', 3)),
      commands: firstCodeBlock(section(readme, 'Get the code and run it', 3)),
    },
  };
}

function writeReadme(dataset) {
  writeFileSync(
    join(OUT, 'README.md'),
    [
      '# Cheyenne documentation mirror',
      '',
      'Generated by `scripts/sync-cheyenne.mjs`. Do not edit by hand.',
      '',
      `- Synced: ${dataset.generatedAt}`,
      `- Upstream: ${dataset.source.url}`,
      `- ${dataset.fleets.length} satellite fleets in ${dataset.groups.length} groups · ${dataset.screenshots.length} screenshots`,
      '',
      'Descriptions, tables and image links are verbatim from the upstream README;',
      'fleet metadata is verbatim from `web/catalog.json`. Cheyenne is not affiliated',
      'with or endorsed by any of the data providers it lists.',
      '',
    ].join('\n')
  );
}

async function main() {
  console.log(`  fetching ${OWNER}/${REPO} metadata, README and fleet catalog`);
  const [meta, readme, catalog] = await Promise.all([
    fetchJson(API),
    fetchText(`https://raw.githubusercontent.com/${OWNER}/${REPO}/HEAD/README.md`),
    fetchJson(`https://raw.githubusercontent.com/${OWNER}/${REPO}/HEAD/web/catalog.json`),
  ]);
  const dataset = buildDataset({ meta, readme, catalog });
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(dataset, null, 2));
  writeReadme(dataset);
  console.log(
    `  ✓ ${dataset.features.length} features · ${dataset.fleets.length} fleets · ` +
      `${dataset.dataSources.length} data sources · ${dataset.screenshots.length} screenshots`
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
