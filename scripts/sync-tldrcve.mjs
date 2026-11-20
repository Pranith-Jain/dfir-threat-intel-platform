#!/usr/bin/env node
/**
 * Mirror the public surfaces of https://tldrcve.com into site data.
 *
 * REA confirmed the site is server-rendered static HTML (no XHR/API): the
 * homepage, /cves/, /versions/ and each /<slug>/ detail page contain all the
 * content. robots.txt allows all paths. We parse that markup into structured
 * records and link every row/detail back to upstream. No prose is rewritten
 * or invented; missing fields stay null/[].
 *
 * Output: public/data/tldrcve/index.json
 * Run: node scripts/sync-tldrcve.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'tldrcve');
const BASE = 'https://tldrcve.com';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

async function fetchText(url, attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'text/html,*/*' },
        signal: AbortSignal.timeout(25_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
    }
  }
  throw new Error(`${url}: ${last?.message ?? 'fetch failed'}`);
}

export function decodeEntities(s) {
  return String(s ?? '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;|&apos;/gi, "'")
    .replace(/&hellip;/gi, '…')
    .replace(/&middot;/gi, '·')
    .replace(/&mdash;/gi, '—')
    .replace(/&ndash;/gi, '–')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)));
}

export function text(html) {
  return decodeEntities(String(html ?? '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function attr(block, name) {
  return decodeEntities(block.match(new RegExp(`${name}="([^"]*)"`))?.[1] ?? '');
}

/** /cves/ rows. */
export function parseCveList(html) {
  const out = [];
  const blocks = String(html ?? '').match(/<li class="row"[\s\S]*?<\/li>/g) ?? [];
  for (const block of blocks) {
    const slug = block.match(/href="\/([^"/]+)\/"/)?.[1];
    if (!slug) continue;
    out.push({
      slug,
      name: text(block.match(/class="row__name">([\s\S]*?)<\/span>/)?.[1]),
      meta: text(block.match(/class="row__meta">([\s\S]*?)<\/span>/)?.[1]),
      line: text(block.match(/class="row__line">([\s\S]*?)<\/span>/)?.[1]),
      verdict: text(block.match(/class="verdict[^"]*">([\s\S]*?)<\/span>/)?.[1]),
      scareLevel: Number(attr(block, 'data-scare')) || null,
      meterLabel: decodeEntities(block.match(/aria-label="Scare-o-meter: ([^"]+)"/)?.[1] ?? ''),
      disclosed: attr(block, 'data-disclosed') || null,
      url: `${BASE}/${slug}/`,
    });
  }
  return out;
}

/** /versions/ cards. */
export function parseVersions(html) {
  const out = [];
  const blocks = String(html ?? '').match(/<li class="vcard"[\s\S]*?<\/li>/g) ?? [];
  for (const block of blocks) {
    const slug = block.match(/href="\/versions\/([^"/]+)\/"/)?.[1];
    if (!slug) continue;
    const chips = [...block.matchAll(/<span class="vchip"><span>([\s\S]*?)<\/span><b>([\s\S]*?)<\/b><\/span>/g)].map((m) => ({
      line: text(m[1]),
      version: text(m[2]),
    }));
    out.push({
      slug,
      name: text(block.match(/class="vcard__name">([\s\S]*?)<\/span>/)?.[1]),
      meta: text(block.match(/class="vcard__meta">([\s\S]*?)<\/span>/)?.[1]),
      nofix: attr(block, 'data-nofix') === '1',
      chips,
      url: `${BASE}/versions/${slug}/`,
    });
  }
  return out;
}

function parseFolds(html) {
  const blocks = String(html ?? '').match(/<details class="fold"[\s\S]*?<\/details>/g) ?? [];
  return blocks.map((block) => ({
    num: text(block.match(/class="fold__num">([\s\S]*?)<\/span>/)?.[1]),
    title: text(block.match(/class="fold__title">([\s\S]*?)<\/span>/)?.[1]),
    hint: text(block.match(/class="fold__hint">([\s\S]*?)<\/span>/)?.[1]) || null,
    body: text(block.match(/<div class="fold__body">([\s\S]*?)<\/div>/)?.[1]),
    code: [...block.matchAll(/<pre><code>([\s\S]*?)<\/code><\/pre>/g)].map((m) => text(m[1])),
  }));
}

/** One /<slug>/ detail page. */
export function parseDetail(html, slug) {
  const doc = String(html ?? '');
  const main = doc.match(/<main[^>]*>([\s\S]*?)<\/main>/)?.[1] ?? doc;
  const section = (id) => {
    const start = main.search(new RegExp(`aria-labelledby="${id}"`));
    if (start < 0) return '';
    const end = main.indexOf('</section>', start);
    return main.slice(start, end < 0 ? start + 12000 : end);
  };
  const affected = parseFolds(section('h-affected'));
  const actions = parseFolds(section('h-do'));
  const checklist = [...main.matchAll(/<li class="check check--(yes|no)">([\s\S]*?)<\/li>/g)].map((m) => ({
    yes: m[1] === 'yes',
    text: text(m[2].replace(/<span class="visually-hidden">[\s\S]*?<\/span>/, '')),
  }));
  const sources = [...main.matchAll(/<li><a href="([^"]+)"[^>]*>([\s\S]*?)<\/a>(?:\s*<span class="src-date">([\s\S]*?)<\/span>)?<\/li>/g)]
    .map((m) => ({ url: decodeEntities(m[1]), title: text(m[2]), date: text(m[3]) || null }));
  const changes = [...main.matchAll(/<li><time datetime="([^"]+)">([\s\S]*?)<\/time><span>([\s\S]*?)<\/span><\/li>/g)]
    .map((m) => ({ date: m[1], text: text(m[3]) }));
  return {
    slug,
    kicker: text(main.match(/class="kicker">([\s\S]*?)<\/p>/)?.[1]),
    name: text(main.match(/<h1>([\s\S]*?)<\/h1>/)?.[1]),
    verdict: text(main.match(/class="verdict[^"]*">([\s\S]*?)<\/span>/)?.[1]),
    verdictHint: text(main.match(/class="verdict-line"[\s\S]*?<\/span>\s*<span>([\s\S]*?)<\/span>/)?.[1]),
    summary: text(main.match(/class="summary">([\s\S]*?)<\/p>/)?.[1]),
    meterLabel: text(main.match(/class="meter__label">([\s\S]*?)<\/p>/)?.[1]),
    meterHint: text(main.match(/class="meter__hint">([\s\S]*?)<\/p>/)?.[1]),
    checklist,
    affected,
    actions,
    sources,
    changes,
    url: `${BASE}/${slug}/`,
  };
}

async function main() {
  console.log('  fetching tldrcve list + versions');
  const [listHtml, versionsHtml] = await Promise.all([
    fetchText(`${BASE}/cves/`),
    fetchText(`${BASE}/versions/`),
  ]);
  const cves = parseCveList(listHtml);
  const versions = parseVersions(versionsHtml);
  if (cves.length === 0) throw new Error('no CVE rows parsed — upstream markup changed');

  console.log(`  fetching ${cves.length} detail pages`);
  const details = [];
  for (let i = 0; i < cves.length; i += 4) {
    const chunk = cves.slice(i, i + 4);
    const pages = await Promise.all(
      chunk.map((c) => fetchText(c.url).catch(() => null))
    );
    pages.forEach((html, j) => {
      if (html) details.push(parseDetail(html, chunk[j].slug));
    });
  }

  const byVerdict = {};
  for (const c of cves) byVerdict[c.verdict || 'unknown'] = (byVerdict[c.verdict || 'unknown'] ?? 0) + 1;
  const payload = {
    generatedAt: new Date().toISOString(),
    upstream: { site: BASE, list: `${BASE}/cves/`, versions: `${BASE}/versions/`, feed: `${BASE}/feed.xml`, scale: `${BASE}/how-we-rate/` },
    stats: { cves: cves.length, details: details.length, versions: versions.length, byVerdict },
    scale: [
      { level: 1, label: 'Shrug', meaning: 'Real, but not worth losing sleep over.' },
      { level: 2, label: 'Keep an eye on it', meaning: 'Patch on schedule. Watch for news.' },
      { level: 3, label: 'Check today', meaning: "Find out if you're affected. If you are, patch." },
      { level: 4, label: 'Drop everything', meaning: 'Attackers are already on it. Patch now.' },
    ],
    cves: cves.map((c) => ({ ...c, detail: details.find((d) => d.slug === c.slug) ?? null })),
    versions,
  };
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'index.json'), `${JSON.stringify(payload, null, 2)}\n`);
  console.log(`  ✓ ${cves.length} CVEs · ${details.length} details · ${versions.length} version lines → ${OUT}/index.json\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`tldrcve sync failed: ${e.message}`); process.exit(1); });
