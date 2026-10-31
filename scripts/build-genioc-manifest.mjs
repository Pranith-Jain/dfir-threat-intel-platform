#!/usr/bin/env node
// Builds public/data/genioc/ from gendigitalinc/ioc (Gen Threat Labs).
//
// Upgrades the existing live malware-iocs route (GitHub contents API,
// type-less flat IoC strings, capped at 200) with a build-time deep
// manifest: every family, classified IoC values (md5/sha1/sha256/domain/
// IP/CIDR/URL), mutexes, filenames, extras inventory, YARA rule names,
// and a cleaned README summary. The page + /api/v1/genioc read this
// instead of hammering the rate-limited GitHub contents API.
//
// Usage:
//   node scripts/build-genioc-manifest.mjs
//   node scripts/build-genioc-manifest.mjs --source /path/to/ioc-clone
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'genioc');
const REPO_TARBALL = 'https://codeload.github.com/gendigitalinc/ioc/tar.gz/refs/heads/master';
const SOURCE_REPO_URL = 'https://github.com/gendigitalinc/ioc';
const SOURCE_LICENSE =
  'Detection Rule License (DRL) 1.1 — https://github.com/SigmaHQ/Detection-Rule-License';

// ─── Source acquisition ─────────────────────────────────────────────

async function acquireSource() {
  const argIdx = process.argv.indexOf('--source');
  const override = argIdx !== -1 ? process.argv[argIdx + 1] : null;
  if (override) {
    if (!existsSync(override)) throw new Error(`--source ${override} does not exist`);
    return override;
  }
  // Download the tarball and untar with the system tar (no deps).
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const tmp = mkdtempSync(join(tmpdir(), 'genioc-'));
  const tarball = join(tmp, 'ioc.tar.gz');
  try {
    const res = await fetch(REPO_TARBALL, {
      headers: { 'user-agent': 'pranithjain-dfir/1.0' },
      signal: AbortSignal.timeout(90_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await writeFile(tarball, Buffer.from(await res.arrayBuffer()));
  } catch (_fetchErr) {
    // Large-tarball fetch can stall behind proxies — fall back to curl.
    execFileSync('curl', ['-sSL', '--connect-timeout', '30', '--max-time', '180', '-o', tarball, REPO_TARBALL], { stdio: 'inherit' });
  }
  execFileSync('tar', ['-xzf', tarball, '-C', tmp]);
  // GitHub tarballs wrap in one root dir — resolve it.
  const entries = await readdir(tmp);
  const root = entries.find((e) => !e.endsWith('.tar.gz'));
  if (!root) throw new Error('tar extraction produced no directory');
  return join(tmp, root);
}

// ─── Classification ─────────────────────────────────────────────────

const RE_MD5 = /^[a-fA-F\d]{32}$/;
const RE_SHA1 = /^[a-fA-F\d]{40}$/;
const RE_SHA256 = /^[a-fA-F\d]{64}$/;
const RE_IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const RE_CIDR = /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const RE_URL = /^https?:\/\//i;
// Loose domain shape (labels + TLD ≥ 2 letters). Over-matching plain
// words is unlikely here: network files rarely carry bare words.
const RE_DOMAIN = /^[a-zA-Z\d](?:[a-zA-Z\d-]*[a-zA-Z\d])?(?:\.[a-zA-Z\d](?:[a-zA-Z\d-]*[a-zA-Z\d])?)*\.[a-zA-Z]{2,}$/;

/** One classified IOC value. */
export function classifyLine(line) {
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  // Strip trailing inline comments ("1.2.3.4 # cobalt").
  const base = t.split(/\s+#\s?/)[0].trim() || t;
  if (RE_SHA256.test(base)) return { type: 'sha256', value: base };
  if (RE_SHA1.test(base)) return { type: 'sha1', value: base };
  if (RE_MD5.test(base)) return { type: 'md5', value: base };
  if (RE_CIDR.test(base)) return { type: 'cidr', value: base };
  if (RE_IPV4.test(base)) return { type: 'ip', value: base };
  if (RE_URL.test(base)) return { type: 'url', value: base };
  if (RE_DOMAIN.test(base)) return { type: 'domain', value: base };
  return { type: 'other', value: t };
}

export function classifyText(text) {
  const out = [];
  for (const line of (text || '').split('\n')) {
    const c = classifyLine(line);
    if (c) out.push(c);
  }
  return out;
}

function dedupeByType(classified) {
  const LIMIT = 4000; // per-type hard cap — extras files can be wallets.csv-scale
  const types = { md5: [], sha1: [], sha256: [], ip: [], domain: [], cidr: [], url: [], other: [] };
  const seen = { md5: new Set(), sha1: new Set(), sha256: new Set(), ip: new Set(), domain: new Set(), cidr: new Set(), url: new Set(), other: new Set() };
  const push = (type, value) => {
    if (seen[type].size >= LIMIT || seen[type].has(value)) return;
    seen[type].add(value);
    types[type].push(value);
  };
  for (const { type, value } of classified) push(type, value);
  return types;
}

// ─── README / YARA helpers ──────────────────────────────────────────

function readmeSummary(md) {
  const links = [...new Set((md.match(/https?:\/\/[^\s)\]]+/g) || []).map((u) => u.replace(/[),.]+$/, '')))]
    .filter((u) => !u.includes('avatars.githubusercontent'))
    .slice(0, 8);
  const cleanLines = [];
  for (const raw of md.split('\n')) {
    const line = raw.replace(/[#*_>`]/g, '').trim();
    if (!line || line.startsWith('!')) continue;
    if (cleanLines.join(' ').length > 600) break;
    cleanLines.push(line);
  }
  return { summary: cleanLines.join(' ').slice(0, 600), links };
}

function extractYara(text) {
  const names = [];
  const re = /\brule\s+([A-Za-z_][\w]*)/g;
  let m;
  while ((m = re.exec(text)) !== null && names.length < 400) names.push(m[1]);
  return names;
}

// ─── Family scan ────────────────────────────────────────────────────

function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'family';
}

const N = (l) => l.trim();

async function scanFamily(familyDir, familyName) {
  const io = {
    domains: [], ips: [], urls: [], cidrs: [], md5: [], sha1: [], sha256: [],
    mutexes: [], filenames: [], other: [],
  };
  let readme = null;
  const extras = [];
  const yara = [];
  let fileCount = 0;

  async function walk(sub, scoped) {
    const entries = await readdir(sub, { withFileTypes: true });
    for (const e of entries) {
      const p = join(sub, e.name);
      if (e.isDirectory()) {
        // Anything below the family root (extras/, payload_tools/, …) is extras.
        await walk(p, true);
        continue;
      }
      if (e.name.endsWith('.md')) {
        if (!scoped) {
          if (e.name === 'README.md') readme = readmeSummary(await readFile(p, 'utf8'));
          continue;
        }
        extras.push({ name: e.name, count: 0, bytes: 0, kind: 'doc' });
        continue;
      }
      if (e.name.endsWith('.py') || e.name.endsWith('.proto')) {
        extras.push({ name: scoped ? e.name : e.name, count: 0, bytes: 0, kind: 'script' });
        continue;
      }
      if (e.name.endsWith('.yar') || e.name.endsWith('.yara')) {
        const raw = await readFile(p, 'utf8');
        yara.push({ name: e.name, rules: extractYara(raw).length, names: extractYara(raw) });
        continue;
      }
      if (!/\.(txt|csv|bin|md5|sha1|sha256)$/i.test(e.name)) continue;
      const raw = await readFile(p, 'utf8').catch(() => null);
      if (raw === null) continue;
      fileCount += 1;
      if (scoped) {
        const lines = raw.split(/\r?\n/).map(N).filter(Boolean);
        // Mutex / filename reference files that live under extras/ still feed
        // the same artefact lists.
        if (/mutex/i.test(e.name)) {
          io.mutexes.push(...lines.slice(0, 500));
          extras.push({ name: e.name, count: lines.length, bytes: raw.length, kind: 'list' });
          continue;
        }
        if (/filename/i.test(e.name)) {
          io.filenames.push(...lines.slice(0, 500));
          extras.push({ name: e.name, count: lines.length, bytes: raw.length, kind: 'list' });
          continue;
        }
        const cls = dedupeByType(classifyText(raw));
        const n = cls.md5.length + cls.sha1.length + cls.sha256.length + cls.ip.length + cls.domain.length + cls.cidr.length + cls.url.length;
        extras.push({
          name: e.name,
          count: lines.length,
          bytes: raw.length,
          kind: n > 0 ? 'list' : 'other',
        });
        if (n > 0) {
          io.md5.push(...cls.md5);
          io.sha1.push(...cls.sha1);
          io.sha256.push(...cls.sha256);
          io.ips.push(...cls.ip);
          io.domains.push(...cls.domain);
          io.urls.push(...cls.url);
        }
        continue;
      }
      if (e.name === 'samples.md5' || e.name === 'md5') {
        io.md5.push(...raw.split(/\r?\n/).map(N).filter((l) => RE_MD5.test(l)));
      } else if (e.name === 'samples.sha1' || e.name === 'sha1') {
        io.sha1.push(...raw.split(/\r?\n/).map(N).filter((l) => RE_SHA1.test(l)));
      } else if (e.name === 'samples.sha256' || e.name === 'sha256') {
        io.sha256.push(...raw.split(/\r?\n/).map(N).filter((l) => RE_SHA256.test(l)));
      } else if (e.name === 'samples.csv') {
        // CSV sample table (sha256,md5,sha1 header) — map columns to lists.
        const rows = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        if (rows.length) {
          const header = rows[0].split(',').map((h) => h.trim().toLowerCase());
          const idxOf = (t) => header.indexOf(t);
          const hasHeader = idxOf('sha256') !== -1 || idxOf('md5') !== -1 || idxOf('sha1') !== -1;
          const cS256 = hasHeader ? idxOf('sha256') : 0;
          const cMd5 = hasHeader ? idxOf('md5') : 1;
          const cSha1 = hasHeader ? idxOf('sha1') : 2;
          for (const row of hasHeader ? rows.slice(1) : rows) {
            const cells = row.split(',').map((c) => c.trim());
            if (cS256 >= 0 && RE_SHA256.test(cells[cS256] || '')) io.sha256.push(cells[cS256]);
            if (cMd5 >= 0 && cells[cMd5] && RE_MD5.test(cells[cMd5])) io.md5.push(cells[cMd5]);
            if (cSha1 >= 0 && cells[cSha1] && RE_SHA1.test(cells[cSha1])) io.sha1.push(cells[cSha1]);
          }
        }
      } else if (e.name === 'network.txt') {
        const cls = dedupeByType(classifyText(raw));
        io.ips.push(...cls.ip);
        io.domains.push(...cls.domain);
        io.urls.push(...cls.url);
        io.cidrs.push(...cls.cidr);
        io.other.push(...cls.other);
      } else if (e.name === 'mutexes.txt') {
        io.mutexes.push(...raw.split(/\r?\n/).map(N).filter(Boolean).slice(0, 500));
      } else if (e.name === 'filenames.txt') {
        io.filenames.push(...raw.split(/\r?\n/).map(N).filter(Boolean).slice(0, 500));
      }
    }
  }
  await walk(familyDir, false);

  io.md5 = [...new Set(io.md5)];
  io.sha1 = [...new Set(io.sha1)];
  io.sha256 = [...new Set(io.sha256)];
  io.ips = [...new Set(io.ips)];
  io.domains = [...new Set(io.domains)];

  const totals = {
    files: fileCount,
    md5: io.md5.length,
    sha1: io.sha1.length,
    sha256: io.sha256.length,
    hashes: io.md5.length + io.sha1.length + io.sha256.length,
    ips: io.ips.length,
    domains: io.domains.length,
    urls: io.urls.length,
    cidrs: io.cidrs.length,
    network: io.ips.length + io.domains.length + io.urls.length + io.cidrs.length + io.other.length,
    mutexes: io.mutexes.length,
    filenames: io.filenames.length,
    extras: extras.length,
    yara: yara.reduce((a, y) => a + y.rules, 0),
  };
  return { name: familyName, io, readme, extras, yara, totals };
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  const src = await acquireSource();
  const dirs = (await readdir(src, { withFileTypes: true })).filter(
    (e) => e.isDirectory() && !e.name.startsWith('.')
  );

  const builtFamilies = [];
  const indexCards = [];

  for (const dirent of dirs) {
    const f = await scanFamily(join(src, dirent.name), dirent.name);
    const { totals, readme } = f;
    if (
      totals.hashes === 0 && totals.network === 0 && totals.mutexes === 0 &&
      totals.filenames === 0 && !readme
    ) {
      continue;
    }
    f.slug = slugify(dirent.name);
    builtFamilies.push(f);
    indexCards.push({
      slug: f.slug,
      name: f.name,
      hashes: totals.hashes,
      network: totals.network,
      mutexes: totals.mutexes,
      filenames: totals.filenames,
      extras: totals.extras,
      yara: totals.yara,
      summary: readme?.summary ? readme.summary.slice(0, 140) : undefined,
    });
  }

  indexCards.sort((a, b) => a.name.localeCompare(b.name));
  builtFamilies.sort((a, b) => a.name.localeCompare(b.name));

  const counts = indexCards.reduce(
    (acc, f) => ({
      families: acc.families + 1,
      hashes: acc.hashes + f.hashes,
      network: acc.network + f.network,
      mutexes: acc.mutexes + f.mutexes,
      filenames: acc.filenames + f.filenames,
      yara: acc.yara + f.yara,
    }),
    { families: 0, hashes: 0, network: 0, mutexes: 0, filenames: 0, yara: 0 }
  );

  await mkdir(join(OUT, 'sections'), { recursive: true });
  await writeFile(
    join(OUT, 'index.json'),
    JSON.stringify({ source: SOURCE_REPO_URL, license: SOURCE_LICENSE, builtAt: new Date().toISOString(), counts, families: indexCards })
  );
  for (const f of builtFamilies) {
    const { name, slug, io, readme, extras, yara, totals } = f;
    await writeFile(join(OUT, 'sections', `${slug}.json`), JSON.stringify({ name, slug, readme, extras, yara, totals, iocs: io }));
  }
  console.log(
    `genioc: built ${builtFamilies.length} families -> public/data/genioc (${counts.hashes} hashes, ${counts.network} network IoCs, ${counts.yara} YARA rules)`
  );
}

main().catch((e) => {
  console.error('build-genioc-manifest failed:', e);
  process.exit(1);
});
