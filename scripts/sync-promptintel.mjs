#!/usr/bin/env node
/**
 * Mirror the public IoPC taxonomy (PromptIntel / SecurityBreak) into site data.
 *
 * PromptIntel's API needs `PROMPTINTEL_API_KEY`, but the taxonomy itself is a
 * public, crawlable reference: robots.txt allows `/` for every agent, the
 * taxonomy index lists every domain + technique, and each technique page
 * carries its description, maturity, review dates and the full framework
 * mapping table (OWASP LLM, OWASP Agentic, MITRE ATLAS, Google SAIF, CSA AARM,
 * NIST AI RMF). Mirroring that means the platform can render the taxonomy with
 * no key and no runtime upstream hop.
 *
 * What is mirrored: identifiers, names, one-sentence descriptions, maturity /
 * evidence / review dates and framework mapping rows. No prompt attack text, no
 * agent-threat analysis, no NOVA rules — those stay behind the API. Every entry
 * keeps an upstream `url`, and `license` records the attribution.
 *
 * Output:
 *   public/data/promptintel/index.json          slim index + domains + frameworks
 *   public/data/promptintel/entries/<id>.json   full per-technique body
 *   public/data/promptintel/frameworks.json     framework list (name/version/url)
 *
 * Run:  node scripts/sync-promptintel.mjs
 *       node scripts/sync-promptintel.mjs --source ./promptintel-staging
 */
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'promptintel');
const BASE = 'https://promptintel.securitybreak.io';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
/** Polite crawl: PromptIntel is a small site and we only ask for 37 pages. */
const PACE_MS = 350;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ─── HTML helpers ─────────────────────────────────────────────────────── */

const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', mdash: '—', ndash: '–',
  hellip: '…', rsquo: '’', lsquo: '‘', ldquo: '“', rdquo: '”', middot: '·',
};

export function decodeEntities(text = '') {
  return String(text).replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, code) => {
    if (code[0] === '#') {
      const n = code[1] === 'x' || code[1] === 'X' ? parseInt(code.slice(2), 16) : Number(code.slice(1));
      return Number.isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ENTITIES[code] ?? m;
  });
}

/** Strip tags, decode entities, collapse whitespace. */
export function text(html = '') {
  return decodeEntities(
    String(html)
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
  )
    .replace(/\s+/g, ' ')
    .trim();
}

const heading = (html, tag) => {
  const m = String(html).match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
  return m ? text(m[1]) : '';
};

/** Body slice that stops before the shared footer boilerplate. */
function mainSlice(html) {
  const start = html.search(/<h1[\s>]/i);
  if (start < 0) return '';
  const rest = html.slice(start);
  const cut = rest.search(/<p>\s*PromptIntel is a product by/i);
  return cut > 0 ? rest.slice(0, cut) : rest;
}

/* ─── Parsers ──────────────────────────────────────────────────────────── */

/** `## T1 Instruction & Input Injection` sections with their technique lists. */
export function parseTaxonomyIndex(html) {
  const version = html.match(/Version\s+(\d+\.\d+\.\d+)\./i)?.[1] ?? 'unreleased';
  const domains = [];
  const entries = [];
  // Split on level-2 headings so each block is one domain.
  const blocks = String(html).split(/<h2[^>]*>/i).slice(1);
  for (const raw of blocks) {
    const close = raw.indexOf('</h2>');
    if (close < 0) continue;
    const title = text(raw.slice(0, close));
    const body = raw.slice(close + 5);
    const code = title.match(/^(T\d+)\b/)?.[1];
    if (!code) continue;
    const name = title.replace(/^T\d+\s*/, '').trim();
    const description = text(body.match(/<p[^>]*>([\s\S]*?)<\/p>/i)?.[1] ?? '');
    const domain = { id: code, name, description, techniques: [] };
    for (const m of body.matchAll(/<li>\s*<a href="\/taxonomy\/([^"]+)\/"[^>]*>([\s\S]*?)<\/a>\s*:?\s*([\s\S]*?)<\/li>/gi)) {
      const id = decodeEntities(m[1]).replace(/\/$/, '');
      if (!/^IOPC-[TR]\d/i.test(id)) continue;
      const label = text(m[2]);
      const summary = text(m[3]);
      const entryName = label.replace(/^IOPC-[TR][\d.]+\s*/i, '').trim();
      domain.techniques.push(id);
      entries.push({
        id,
        name: entryName || label,
        domain: code,
        domainName: name,
        summary,
        url: `${BASE}/taxonomy/${id}/`,
      });
    }
    domains.push(domain);
  }
  return { version, domains, entries };
}

/**
 * One technique page: description, "How it differs", status line and the
 * "Mapped to" table. Mapping rows read
 *   `<li>FRAMEWORK: <strong>REF</strong> Name (relationship)</li>`
 */
export function parseEntryPage(html, id) {
  const body = mainSlice(html);
  const title = heading(body, 'h1');
  const name = title.replace(/^IOPC-[TR][\d.]+\s*/i, '').trim();
  const description = text(body.match(/<h1[^>]*>[\s\S]*?<\/h1>\s*<p[^>]*>([\s\S]*?)<\/p>/i)?.[1] ?? '');
  const differs = text(
    body.match(/<h2[^>]*>\s*How it differs\s*<\/h2>\s*<p[^>]*>([\s\S]*?)<\/p>/i)?.[1] ?? ''
  );
  const statusRaw = text(
    body.match(/<h2[^>]*>\s*Status\s*<\/h2>\s*<p[^>]*>([\s\S]*?)<\/p>/i)?.[1] ?? ''
  );
  const maturity = statusRaw.match(/^\s*([a-z_-]+)/i)?.[1]?.toLowerCase() ?? 'unknown';
  const evidence = statusRaw.match(/evidence:\s*([a-z_-]+)/i)?.[1]?.toLowerCase() ?? null;
  const reviewed = statusRaw.match(/reviewed\s+(\d{4}-\d{2}-\d{2})/i)?.[1] ?? null;

  const mappings = [];
  const list = body.match(/<h2[^>]*>\s*Mapped to\s*<\/h2>\s*<ul[^>]*>([\s\S]*?)<\/ul>/i)?.[1] ?? '';
  for (const li of list.matchAll(/<li>([\s\S]*?)<\/li>/gi)) {
    // `FRAMEWORK: <strong>REF</strong> Name (relationship)` — the ref lives in
    // <strong>, so split on that boundary instead of re-reading the flat text.
    const parts = li[1].match(/^([\s\S]*?)<strong[^>]*>([\s\S]*?)<\/strong>([\s\S]*)$/i);
    if (!parts) continue;
    const framework = text(parts[1]).replace(/:\s*$/, '').trim();
    const ref = text(parts[2]);
    const tail = text(parts[3]);
    if (!framework || !ref) continue;
    const rel = tail.match(/\(([a-z_ ]+)\)\s*$/i);
    mappings.push({
      framework,
      ref,
      name: (rel ? tail.slice(0, rel.index) : tail).trim(),
      relationship: rel ? rel[1].trim().toLowerCase() : '',
    });
  }

  return {
    id,
    name,
    description,
    differs,
    maturity,
    evidence,
    reviewed,
    statusLine: statusRaw,
    mappings,
    url: `${BASE}/taxonomy/${id}/`,
  };
}

/** Framework list from /taxonomy/frameworks/. */
export function parseFrameworks(html) {
  const out = [];
  const list = String(html).match(/<h1[^>]*>\s*Framework mappings\s*<\/h1>[\s\S]*?<ul[^>]*>([\s\S]*?)<\/ul>/i)?.[1] ?? '';
  for (const li of list.matchAll(/<li>([\s\S]*?)<\/li>/gi)) {
    const strong = li[1].match(/<strong[^>]*>([\s\S]*?)<\/strong>/i);
    if (!strong) continue;
    const name = text(strong[1]);
    const version = text(li[1]).match(/\(version\s+([^)]+)\)/i)?.[1] ?? null;
    const url = li[1].match(/href="(https?:[^"]+)"/i)?.[1] ?? null;
    out.push({ name, version, url });
  }
  return out;
}

/* ─── Fetch ────────────────────────────────────────────────────────────── */

async function fetchHtml(url, attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml' },
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
      if (i + 1 < attempts) await sleep(1500);
    }
  }
  throw new Error(`${url}: ${last?.message ?? 'fetch failed'}`);
}

const readLocal = (dir, rel) => readFileSync(join(dir, rel), 'utf8');

async function main() {
  const arg = process.argv.indexOf('--source');
  const local = arg > 0 ? process.argv[arg + 1] : null;

  const get = local
    ? async (url) => {
        const rel = url.replace(`${BASE}/`, '').replace(/\/$/, '') || 'index';
        const file = rel === 'index' ? 'taxonomy.html' : `${rel.replace(/\//g, '__')}.html`;
        return readLocal(local, file);
      }
    : async (url) => {
        const html = await fetchHtml(url);
        await sleep(PACE_MS);
        return html;
      };

  console.log(`  ${local ? `reading ${local}` : 'fetching PromptIntel taxonomy'}`);
  const indexHtml = await get(`${BASE}/taxonomy/`);
  const { version, domains, entries } = parseTaxonomyIndex(indexHtml);
  if (!entries.length) throw new Error('no techniques parsed — upstream markup changed');

  const frameworksHtml = await get(`${BASE}/taxonomy/frameworks/`);
  const frameworks = parseFrameworks(frameworksHtml);

  const bodies = [];
  for (const entry of entries) {
    try {
      const page = await get(entry.url);
      bodies.push({ ...parseEntryPage(page, entry.id), domain: entry.domain, domainName: entry.domainName });
    } catch (e) {
      console.warn(`  ! ${entry.id}: ${e.message}`);
      bodies.push({ ...entry, differs: '', maturity: 'unknown', evidence: null, reviewed: null, statusLine: '', mappings: [] });
    }
  }

  const byId = new Map(bodies.map((b) => [b.id, b]));
  const slim = entries.map((e) => {
    const b = byId.get(e.id);
    return {
      ...e,
      summary: e.summary || b?.description || '',
      maturity: b?.maturity ?? 'unknown',
      evidence: b?.evidence ?? null,
      reviewed: b?.reviewed ?? null,
      frameworks: [...new Set((b?.mappings ?? []).map((m) => m.framework))],
      mappingCount: b?.mappings?.length ?? 0,
    };
  });

  // Flat mapping table in the index so `/taxonomy/mappings` and
  // `/taxonomy/translate` answer from ONE asset fetch instead of reading 35
  // per-technique files (the free plan caps an invocation at 50 subrequests).
  const mappingRows = bodies.flatMap((b) =>
    (b.mappings ?? []).map((m) => ({
      entry: b.id,
      name: b.name,
      domain: b.domain ?? b.id.slice(5, 7),
      framework: m.framework,
      ref: m.ref,
      item: m.name,
      relationship: m.relationship,
    }))
  );

  rmSync(join(OUT, 'entries'), { recursive: true, force: true });
  mkdirSync(join(OUT, 'entries'), { recursive: true });

  for (const body of bodies) {
    writeJsonIfChanged(join(OUT, 'entries', `${body.id}.json`), body);
  }

  const index = {
    source: 'PromptIntel',
    sourceUrl: `${BASE}/taxonomy/`,
    license: 'PromptIntel (SecurityBreak). Taxonomy metadata mirrored for reference with attribution; every record deep-links upstream. Prompt attack text, agent-threat analyses and NOVA rules are not mirrored.',
    syncedAt: new Date().toISOString(),
    taxonomyVersion: version,
    counts: {
      domains: domains.length,
      techniques: slim.length,
      frameworks: frameworks.length,
      mappings: slim.reduce((n, e) => n + e.mappingCount, 0),
    },
    frameworks,
    domains: domains.map((d) => ({ ...d, techniques: d.techniques })),
    entries: slim,
    mappings: mappingRows,
  };
  writeJsonIfChanged(join(OUT, 'index.json'), index);
  writeJsonIfChanged(join(OUT, 'frameworks.json'), { taxonomyVersion: version, frameworks });

  console.log(`  ✓ IoPC ${version}: ${slim.length} techniques / ${domains.length} domains / ${frameworks.length} frameworks → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`promptintel sync failed: ${e.message}`); process.exit(1); });
