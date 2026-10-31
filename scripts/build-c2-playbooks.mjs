#!/usr/bin/env node
// Builds public/data/c2-playbooks/ from fareedfauzi/MANTIS's curated
// C2 & infrastructure hunting playbook catalog (backend/data/c2_hunting_rules/).
//
// Ports the MANTIS catalog parser (backend/c2_hunting_catalog.py, MIT)
// to a build-time normalizer: markdown engine files (shodan/censys/netlas),
// fingerprint tables (favicon MMH3, urlscan payload SHA-256), and the six
// JSON rule sets (Embee Research, Etugen, OpenHunting, Silent Push,
// Validin, ZoomEye). Entries carry engine + query + a constructed
// external-search URL so analysts go from playbook to platform in one hop.
//
// Source: https://github.com/fareedfauzi/MANTIS (MIT). Attribution kept
// in index.json + the UI.
//
// Usage:
//   node scripts/build-c2-playbooks.mjs
//   node scripts/build-c2-playbooks.mjs --source /path/to/MANTIS/backend/data/c2_hunting_rules
import { writeFile as writeFileAsync, mkdir as mkdirAsync, readFile } from 'node:fs/promises';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'c2-playbooks');
const RAW_BASE =
  'https://raw.githubusercontent.com/fareedfauzi/MANTIS/main/backend/data/c2_hunting_rules';
const SOURCE_REPO_URL = 'https://github.com/fareedfauzi/MANTIS';
const SOURCE_LICENSE = 'MIT (MANTIS, fareedfauzi)';

const MD_FILES = ['shodan_queries.md', 'censys_queries.md', 'netlas_queries.md', 'urlscan_queries.md', 'urlscan_sha256.md', 'favicon_hashes.md'];
const JSON_FILES = ['embeeresearch_rules.json', 'etugen_rules.json', 'openhunting_censys.json', 'silentpush_rules.json', 'validin_rules.json', 'zoomeye_rules.json'];

// ─── Source acquisition ─────────────────────────────────────────────

async function acquireSource() {
  const argIdx = process.argv.indexOf('--source');
  const override = argIdx !== -1 ? process.argv[argIdx + 1] : null;
  if (override) {
    if (!readdirSync(override)) throw new Error('--source not readable');
    return override;
  }
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { execFileSync } = await import('node:child_process');
  const tmp = mkdtempSync(join(tmpdir(), 'c2play-'));
  for (const f of readdirable()) {
    const dest = join(tmp, f);
    try {
      const res = await fetch(`${RAW_BASE}/${f}`, { headers: { 'user-agent': 'pranithjain-dfir/1.0' } });
      if (!res.ok) {
        console.warn(`c2-playbooks: skipped ${f} (HTTP ${res.status})`);
        continue;
      }
      await writeFileAsync(dest, await res.text());
    } catch (_fetchErr) {
      // fetch can stall behind proxies — fall back to curl.
      try {
        execFileSync(
          'curl',
          ['-sSL', '--connect-timeout', '20', '--max-time', '90', '-o', dest, `${RAW_BASE}/${f}`],
          { stdio: 'inherit' }
        );
      } catch (_curlErr) {
        console.warn(`c2-playbooks: skipped ${f} (fetch + curl failed)`);
      }
    }
  }
  return tmp;
}

function readdirable() {
  return [...MD_FILES, ...JSON_FILES];
}

// ─── Ported from MANTIS c2_hunting_catalog.py ────────────────────────

/** _categorize_family — ported verbatim (family + technique heuristics). */
export function categorizeFamily(family = '', tech = '') {
  const f = `${family} ${tech}`.toLowerCase();
  if (/(opendir|open directory|git exposure|bash_history|secrets|backup|trashpile)/.test(f)) return 'Exposed OpenDir / Secrets';
  if (/webshell/.test(f)) return 'Webshell';
  if (/(hacktool|password-cracking|exploit)/.test(f)) return 'Hacktool';
  if (/tunnel/.test(f)) return 'Tunnel / Proxy';
  if (/botnet/.test(f)) return 'Botnet';
  if (/(phish|gophish|evilginx|modlishka)/.test(f)) return 'Phishing Framework';
  if (/(stealer|collector|redline|vidar|raccoon|mars|stealc|lumma|luma|meduza|risepro)/.test(f)) return 'Info Stealer';
  if (/(rat\b|asyncrat|quasar|orcus|dcrat|remcos|njrat|warzone|nanocore|hookbot)/.test(f)) return 'RAT';
  if (/(trojan|banking|icedid|gozi|bokbot|qakbot|trickbot|dridex)/.test(f)) return 'Banking Trojan';
  if (/(ransom|lockbit|blackcat|alphv|ransomhub)/.test(f)) return 'Ransomware';
  if (/(apt|winnti|barium|lazarus|mustang|sandworm|turla|charming)/.test(f)) return 'APT Infrastructure';
  if (/favicon/.test(f)) return 'Favicon Fingerprint';
  return 'C2 Framework';
}

/**
 * _get_external_url — ported verbatim from c2_hunting_catalog.py.
 * Constructs the direct "open this hunt in the platform" URL.
 */
export function externalUrl(engine, query = '') {
  const eng = (engine || '').toLowerCase().trim();
  const q = (query || '').trim();
  if (!q) return '';
  const ipMatch = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(q);
  const isPureIp = /^(?:net:)?(?:ip:)?\s*"?((?:\d{1,3}\.){3}\d{1,3})"?$/.test(q);
  const isPureDomain = /^(?:domain:)?\s*"?([a-zA-Z\d.-]+\.[a-zA-Z]{2,})"?$/.test(q) && !isPureIp;
  const rawIp = ipMatch ? ipMatch[0] : '';
  let clean = q;
  switch (eng) {
    case 'shodan': {
      if (isPureIp && rawIp) return `https://www.shodan.io/host/${rawIp}`;
      clean = q.replace(/\bip:"?([\d.]+)"?/g, 'net:$1').replace(/\basn:"?(?:AS)?(\d+)"?/g, 'asn:AS$1');
      return `https://www.shodan.io/search?query=${encodeURIComponent(clean)}`;
    }
    case 'censys': {
      if (isPureIp && rawIp) return `https://search.censys.io/hosts/${rawIp}`;
      clean = q.replace(/\bip\s*:\s*"([\d.]+)"/g, 'ip: $1');
      return `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(clean)}`;
    }
    case 'fofa':
      return `https://fofa.info/result?qbase64=${Buffer.from(q, 'utf8').toString('base64')}`;
    case 'netlas': {
      clean = q.replace(/\bip:"([\d.]+)"/g, 'ip:$1');
      return `https://app.netlas.io/responses/?q=${encodeURIComponent(clean)}`;
    }
    case 'urlscan': {
      if (isPureIp && rawIp) return `https://urlscan.io/ip/${rawIp}`;
      if (isPureDomain) return `https://urlscan.io/domain/${q.replace(/^domain:\s*"?|"?$/g, '')}`;
      clean = q.replace(/files\.sha256:"?([a-f\d]{64})"?/gi, 'hash:$1');
      return urlscanFragment(clean);
    }
    case 'greynoise':
      if (isPureIp && rawIp) return `https://viz.greynoise.io/ip/${rawIp}`;
      return `https://viz.greynoise.io/query?gnql=${encodeURIComponent(q)}`;
    case 'etugen':
      if (isPureIp && rawIp) return `https://app.etugen.io/trashpile/host/${rawIp}`;
      return `https://app.etugen.io/search?q=${encodeURIComponent(q)}`;
    case 'validin': {
      if (isPureIp && rawIp) return `https://app.validin.com/ip/${rawIp}`;
      if (isPureDomain) return `https://app.validin.com/domain/${q.replace(/^domain:\s*"?|"?$/g, '')}`;
      return `https://app.validin.com/search?q=${encodeURIComponent(q)}`;
    }
    case 'zoomeye':
      if (isPureIp && rawIp) return `https://www.zoomeye.ai/searchResult?q=ip%3D%22${rawIp}%22`;
      return `https://www.zoomeye.ai/searchResult?q=${encodeURIComponent(q)}`;
    default:
      return '';
  }
}
// Python used `urllib.parse.quote(clean_q, safe=':="/+*')`: JS encodeURIComponent always escapes `"`/`/`.
// Reproduce the safe-charset escaping for the urlscan fragment only.
export function urlscanFragment(clean) {
  const safe = ':="/+*';
  let out = '';
  for (const ch of clean) {
    if (/[A-Za-z\d\-_.!~*'()]/.test(ch) || safe.includes(ch)) out += ch;
    else out += encodeURIComponent(ch);
  }
  return `https://urlscan.io/search/#${out}`;
}

// ─── Normalizer ─────────────────────────────────────────────────────

function mkItem({ id, family, category, technique, engine, query, notes, hashValue }) {
  if (!query || !query.trim()) return null;
  const eng = (engine || '').toLowerCase();
  return {
    id,
    family: family || 'Unknown',
    category: category || categorizeFamily(family, technique),
    technique: technique || 'Detection Rule',
    engine: eng,
    query: query.trim(),
    externalUrl: externalUrl(eng, query),
    notes,
    ...(hashValue ? { hash: hashValue } : {}),
  };
}

// 1. favicon_hashes.md → Shodan / FOFA / Netlas favicon queries
function parseFavicon(text, items) {
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const parts = t.split(/\s+/).filter(Boolean);
    if (parts.length < 3 || !/^\d+$/.test(parts[0])) continue;
    const name = parts.slice(1, -1).join(' ');
    const hash = parts[parts.length - 1];
    const queries = {
      shodan: `http.favicon.hash:${hash}`,
      fofa: `icon_hash="${hash}"`,
      netlas: `http.favicon.hash_mmh3:${hash}`,
    };
    for (const [eng, q] of Object.entries(queries)) {
      const it = mkItem({
        id: `fav-${eng}-${hash}`,
        family: name,
        category: categorizeFamily(name, 'Favicon Hash'),
        technique: eng === 'shodan' ? 'Murmur3 Favicon Hash' : eng === 'fofa' ? 'Favicon Icon Hash' : 'Favicon MMH3',
        engine: eng,
        query: q,
        notes: `MMH3 Favicon Hash: ${hash}`,
        hashValue: hash,
      });
      if (it) items.push(it);
    }
  }
}

// 2. urlscan_sha256.md → payload hash hunts
function parseUrlscanSha(text, items) {
  for (const line of text.split('\n')) {
    if (!line.includes('|')) continue;
    const parts = line.split('|').map((s) => s.trim());
    if (parts.length >= 4 && /^\d+$/.test(parts[1]) && /^[a-f\d]{64}$/i.test(parts[3] || '')) {
      const name = parts[2];
      const sha = parts[3].toLowerCase();
      const q = `files.sha256:"${sha}"`;
      const it = mkItem({
        id: `urlscan-sha-${sha.slice(0, 12)}`,
        family: name,
        category: categorizeFamily(name, 'Payload Hash'),
        technique: 'File SHA-256 Hash',
        engine: 'urlscan',
        query: q,
        notes: `Associated Payload SHA256: ${sha}`,
        hashValue: sha,
      });
      if (it) items.push(it);
    }
  }
}

// 3. urlscan_queries.md → community dorks ("1- task.tags:…")
function parseUrlscanDorks(text, items) {
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!/^\d+\s*[-–]/.test(t)) continue;
    const dash = t.search(/[-–]/);
    // MANTIS strips enclosing quotes (ASCII + smart) from the dork.
    const q = t.slice(dash + 1).trim().replace(/^[“”"']+|[“”"']+$/g, '').trim();
    const it = mkItem({
      id: `urlscan-dork-${items.length}`,
      family: 'C2 Threat Feed',
      category: 'C2 Framework',
      technique: 'Community Tag / Dork',
      engine: 'urlscan',
      query: q,
      notes: 'URLScan hunting query for active threat/c2 scans',
    });
    if (it) items.push(it);
  }
}

// 4. shodan/censys/netlas markdown → ## family / ### technique / ```query```
function parseEngineMarkdown(engine, text, items) {
  const sections = text.split(/\n##\s+/);
  for (const sec of sections.slice(1)) {
    const lines = sec.split('\n');
    const secTitle = lines[0].trim();
    if (/(Table of Contents|Platform Syntax|Netlas Featured)/.test(secTitle)) continue;
    let family = secTitle.replace(/^[^\w\s]+/, '').trim() || 'Unknown C2';

    const subs = sec.split(/\n###\s+/);
    for (const sub of subs.slice(1)) {
      let tech = sub.split('\n')[0].trim().replace(/^[^\w\s]+/, '').trim();
      const blocks = [...sub.matchAll(/```(?:bash|shodan|censys|sql|netlas|text)?\s*\n([\s\S]*?)\n```/g)];
      for (const b of blocks) {
        for (const rawLine of b[1].split('\n')) {
          const q = rawLine.trim();
          if (!q || q.startsWith('#') || q.startsWith('curl')) continue;
          const it = mkItem({
            id: `${engine}-${items.length}`,
            family,
            technique: tech || 'Detection Rule',
            engine,
            query: q,
            notes: `${family} -> ${tech}`,
          });
          if (it) items.push(it);
        }
      }
    }
  }
}

// 5. JSON rule sets (Embee, Etugen, OpenHunting, Silent Push, Validin, ZoomEye)
// `fallbackEngine` is used only when an entry itself carries no engine field
// (Embee entries carry their own engine).
function parseJsonRules(file, fallbackEngine, label) {
  const out = [];
  try {
    const arr = JSON.parse(file);
    if (!Array.isArray(arr)) return out;
    for (const e of arr) {
      const eng = (typeof e.engine === 'string' && e.engine ? e.engine : fallbackEngine).toLowerCase();
      const it = mkItem({
        id: e.id || `${label}-${out.length}`,
        family: e.family,
        category: e.category,
        technique: e.technique,
        engine: eng,
        query: e.query || '',
        notes: e.notes,
        hashValue: e.hash_value,
      });
      if (it) out.push(it);
    }
  } catch (_e) {
    console.warn(`c2-playbooks: unparseable ${label}`);
  }
  return out;
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  const dir = await acquireSource();
  let read = async (f) => {
    try {
      return await readFile(join(dir, f), 'utf8');
    } catch (_e) {
      return '';
    }
  };
  const items = [];

  parseFavicon(await read('favicon_hashes.md'), items);
  parseUrlscanSha(await read('urlscan_sha256.md'), items);
  parseUrlscanDorks(await read('urlscan_queries.md'), items);
  parseEngineMarkdown('shodan', await read('shodan_queries.md'), items);
  parseEngineMarkdown('censys', await read('censys_queries.md'), items);
  parseEngineMarkdown('netlas', await read('netlas_queries.md'), items);
  items.push(...parseJsonRules(await read('openhunting_censys.json'), 'censys', 'openhunting'));
  items.push(...parseJsonRules(await read('etugen_rules.json'), 'etugen', 'etugen'));
  items.push(...parseJsonRules(await read('silentpush_rules.json'), 'silentpush', 'silentpush'));
  items.push(...parseJsonRules(await read('validin_rules.json'), 'validin', 'validin'));
  items.push(...parseJsonRules(await read('embeeresearch_rules.json'), 'censys', 'embee'));
  items.push(...parseJsonRules(await read('zoomeye_rules.json'), 'zoomeye', 'zoomeye'));

  // De-dupe by id, drop empties. mkItem already strips empty queries.
  const seen = new Set();
  const entries = items.filter((i) => i && !seen.has(i.id) && seen.add(i.id));

  const engines = {};
  const categories = {};
  const families = {};
  const faviconHashes = [];
  const jarmHashes = [];
  for (const e of entries) {
    engines[e.engine] = (engines[e.engine] || 0) + 1;
    categories[e.category] = (categories[e.category] || 0) + 1;
    families[e.family] = (families[e.family] || 0) + 1;
    if ('hash' in e && e.technique.toLowerCase().includes('favicon')) faviconHashes.push({ family: e.family, hash: e.hash });
    const jm = /jarm[:=\s"]+([a-f\d]{62})/i.exec(e.query);
    if (jm) jarmHashes.push({ family: e.family, hash: jm[1].toLowerCase() });
  }

  const builtAt = new Date().toISOString();
  const enginesList = Object.fromEntries(Object.entries(engines).sort((a, b) => b[1] - a[1]));
  // Section files per engine keep the index slim and lookups fast.
  const byEngine = new Map();
  for (const e of entries) {
    if (!byEngine.has(e.engine)) byEngine.set(e.engine, []);
    byEngine.get(e.engine).push(e);
  }
  await mkdirAsync(join(OUT, 'sections'), { recursive: true });
  await writeFileAsync(
    join(OUT, 'index.json'),
    JSON.stringify({
      source: SOURCE_REPO_URL,
      license: SOURCE_LICENSE,
      portedFrom: 'backend/c2_hunting_catalog.py (MANTIS)',
      builtAt,
      counts: { entries: entries.length, engines: Object.keys(engines).length, categories: Object.keys(categories).length, families: Object.keys(families).length },
      engines: enginesList,
      categories,
      topFamilies: Object.entries(families).sort((a, b) => b[1] - a[1]).slice(0, 30).map(([family, count]) => ({ family, count })),
      faviconHashes,
      jarmHashes: jarmHashes.slice(0, 200),
    })
  );
  for (const [eng, list] of byEngine) {
    await writeFileAsync(join(OUT, `sections/${eng}.json`), JSON.stringify({ engine: eng, count: list.length, entries: list }));
  }
  console.log(`c2-playbooks: built ${entries.length} entries across ${byEngine.size} engines -> public/data/c2-playbooks`);
}

main().catch((e) => {
  console.error('build-c2-playbooks failed:', e);
  process.exit(1);
});
