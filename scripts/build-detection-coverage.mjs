#!/usr/bin/env node
/**
 * Build the CVE -> detection-rule coverage index.
 *
 * The premise: knowing a CVE is exploited is only half the job. The other half
 * is knowing whether the SIEM you actually run has a published rule for it.
 * Every other vuln feed stops at severity; this answers "can I detect it".
 *
 * We already own both halves separately (CISA KEV/EPSS/NVD on one side,
 * rule corpora on the other) but never joined them. This script does the join
 * at build time so the runtime route is a pure lookup.
 *
 * Inputs (all public, no auth required):
 *   detection  SigmaHQ/sigma         tarball  ~9.5 MB
 *   detection  elastic/detection-rules tarball ~62 MB
 *   detection  splunk/security_content tarball ~15 MB
 *   exploit    rapid7 metasploit metadata  ~11 MB
 *   exploit    projectdiscovery nuclei cves.json ~2.2 MB
 *   exploit    exploit-db files_exploits.csv ~10 MB
 *
 * Emits:
 *   public/data/detection-coverage/sources.json   source registry + attribution
 *   public/data/detection-coverage/rules.json     the rule array (CVE-keyed only)
 *   public/data/detection-coverage/stats.json     rollups for the header
 *
 * Rules WITHOUT a CVE reference are dropped. They answer a different question
 * (technique coverage, see library.json) and keeping them here would triple the
 * payload for no gain on the coverage question.
 *
 * Azure-Sentinel is deliberately absent: its tarball is ~690 MB and it is the
 * single largest corpus. Add it here if the build budget ever allows, the
 * extractor already understands KQL.
 *
 * Run:  node scripts/build-detection-coverage.mjs
 * Cache: set DETECTION_COVERAGE_SKIP_FETCH=1 to rebuild from a warm /tmp cache.
 */
import {
  createWriteStream,
  mkdirSync,
  existsSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  statSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'detection-coverage');
const CACHE = join('/tmp', 'detection-coverage-cache');

/**
 * CISA KEV, fetched once so the build can resolve product-level coverage.
 *
 * This duplicates what the route fetches at runtime, which is deliberate: the
 * join has to happen where the rule tokens live, and doing it here keeps a 7 MB
 * product index out of the deployment. The runtime reads the resolved result
 * instead of recomputing it.
 */
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const SKIP_FETCH = process.env.DETECTION_COVERAGE_SKIP_FETCH === '1';

/** CVE-YYYY-NNNN with at least 4 digits, bounded at 19 per the CVE 5.x spec. */
const CVE_RE = /\bCVE-(\d{4})-(\d{4,19})\b/gi;

/** ATT&CK technique ids, sub-technique optional. */
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

/**
 * Rule sources.
 *
 * `license` + `homepage` + `attribution` are NOT optional bookkeeping: Sigma
 * is DRL 1.1, Elastic is Elastic License 2.0, Splunk is CC BY-NC-SA 4.0. All
 * three permit redistribution with attribution, and all three require it. The
 * API surfaces these verbatim in the UI footer, so keep them accurate.
 */
const SOURCES = [
  {
    id: 'sigma',
    label: 'SigmaHQ',
    kind: 'detection',
    format: 'generic signature',
    archive: 'https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz',
    repo: 'SigmaHQ/sigma',
    branch: 'master',
    blobBase: 'https://github.com/SigmaHQ/sigma/blob/master/',
    homepage: 'https://github.com/SigmaHQ/sigma',
    license: 'Detection-Rule-Licence 1.1',
    licenseUrl: 'https://github.com/SigmaHQ/Detection-Rule-License',
    attribution: 'Sigma rules from SigmaHQ/sigma, licensed under the Detection-Rule-Licence 1.1.',
  },
  {
    id: 'elastic',
    label: 'Elastic detection rules',
    kind: 'detection',
    format: 'Elastic Security (TOML)',
    archive: 'https://github.com/elastic/detection-rules/archive/refs/heads/main.tar.gz',
    repo: 'elastic/detection-rules',
    branch: 'main',
    blobBase: 'https://github.com/elastic/detection-rules/blob/main/',
    homepage: 'https://github.com/elastic/detection-rules',
    license: 'Elastic License 2.0',
    licenseUrl: 'https://www.elastic.co/licensing/elastic-license-2-0',
    attribution: 'Elastic detection rules from elastic/detection-rules, licensed under the Elastic License 2.0.',
  },
  {
    id: 'splunk',
    label: 'Splunk Security Content',
    kind: 'detection',
    format: 'Splunk SPL',
    archive: 'https://github.com/splunk/security_content/archive/refs/heads/develop.tar.gz',
    repo: 'splunk/security_content',
    branch: 'develop',
    blobBase: 'https://github.com/splunk/security_content/blob/develop/',
    homepage: 'https://github.com/splunk/security_content',
    license: 'CC BY-NC-SA 4.0',
    licenseUrl: 'https://github.com/splunk/security_content/blob/develop/LICENSE',
    attribution: 'Splunk Security Content from splunk/security_content, licensed under CC BY-NC-SA 4.0.',
  },
  {
    id: 'sentinel',
    label: 'Microsoft Sentinel',
    kind: 'detection',
    format: 'KQL (Analytic Rules)',
    // Not a tarball: the Sentinel repo is ~690 MB, almost all of it Solution
    // pack workbooks and parser samples that contain no CVEs. Pulling the whole
    // thing to read 2,283 analytic rules would be a 690 MB download for a few
    // MB of signal, so we take the git tree and fetch only the rule files.
    archive: 'https://api.github.com/repos/Azure/Azure-Sentinel/git/trees/master?recursive=1',
    blobBase: 'https://github.com/Azure/Azure-Sentinel/blob/master/',
    rawBase: 'https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/',
    homepage: 'https://github.com/Azure/Azure-Sentinel',
    license: 'MIT',
    licenseUrl: 'https://github.com/Azure/Azure-Sentinel/blob/master/LICENSE',
    attribution: 'Microsoft Sentinel analytic rules from Azure/Azure-Sentinel (MIT).',
  },
  {
    id: 'metasploit',
    label: 'Metasploit Framework',
    kind: 'exploit',
    format: 'Rapid7 module metadata',
    archive: 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json',
    repo: 'rapid7/metasploit-framework',
    branch: 'master',
    blobBase: 'https://github.com/rapid7/metasploit-framework/blob/master/',
    homepage: 'https://www.metasploit.com/',
    license: 'BSD-3-Clause',
    licenseUrl: 'https://github.com/rapid7/metasploit-framework/blob/master/LICENSE',
    attribution: 'Metasploit module metadata from Rapid7’s Metasploit Framework (BSD-3-Clause).',
  },
  {
    id: 'nuclei',
    label: 'Nuclei templates',
    kind: 'exploit',
    format: 'ProjectDiscovery template index',
    archive: 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json',
    repo: 'projectdiscovery/nuclei-templates',
    branch: 'main',
    blobBase: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/',
    homepage: 'https://github.com/projectdiscovery/nuclei-templates',
    license: 'MIT',
    licenseUrl: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md',
    attribution: 'Nuclei template index from ProjectDiscovery/nuclei-templates (MIT).',
  },
  {
    id: 'exploitdb',
    label: 'Exploit Database',
    kind: 'exploit',
    format: 'OffSec CSV index',
    archive: 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
    repo: 'exploit-database/exploitdb',
    branch: 'main',
    blobBase: 'https://gitlab.com/exploit-database/exploitdb/-/blob/main/',
    homepage: 'https://gitlab.com/exploit-database/exploitdb',
    license: 'GPL-2.0',
    licenseUrl: 'https://gitlab.com/exploit-database/exploitdb/-/blob/main/LICENSE.md',
    attribution: 'Exploit Database entries from exploit-database/exploitdb, licensed under GPL-2.0.',
  },
];

// ── fetch helpers ────────────────────────────────────────────────────

async function download(url, dest) {
  if (!existsSync(CACHE)) mkdirSync(CACHE, { recursive: true });
  if (!SKIP_FETCH && existsSync(dest) && statSync(dest).size > 0) return dest;

  process.stdout.write(`  ↓ ${url.split('/').slice(-1)[0].slice(0, 48)}\n`);
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  await pipeline(Readable.fromWeb(res.body), createWriteStream(dest));
  return dest;
}

/**
 * Download + extract a GitHub tarball, returning the extracted root dir.
 *
 * `tar` is used rather than a JS gunzip/tar dependency: bsdt ships with macOS
 * and every Linux CI image, and streaming a 62 MB archive through Node would
 * need a tar parser we would otherwise carry for one build step.
 */
function extractArchive(tarball, sourceId) {
  const target = join(CACHE, `${sourceId}-extracted`);
  if (existsSync(target)) return target;

  // GitHub tarballs unpack into a single `<repo>-<branch>/` directory. Name the
  // staging dir deterministically from the source id rather than guessing the
  // upstream directory name from the branch, which differs per source
  // (master vs main vs develop).
  mkdirSync(target, { recursive: true });
  execFileSync('tar', ['-xzf', tarball, '-C', target, '--strip-components', '1'], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });

  const entries = readdirSync(target);
  if (entries.length === 0) throw new Error(`tar extracted nothing for ${tarball}`);
  return target;
}

function walk(dir, out = [], depth = 0) {
  if (depth > 12) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out, depth + 1);
    else out.push(p);
  }
  return out;
}

/** Strip the leading archive directory component (`sigma-master/rules/...`). */
function relPath(rootDir, fullPath) {
  return fullPath.slice(rootDir.length + 1).split('\\').join('/');
}

function cvesIn(text) {
  const out = new Set();
  for (const m of text.matchAll(CVE_RE)) out.add(m[0].toUpperCase());
  return [...out].sort();
}

function attacksIn(text) {
  const out = new Set();
  for (const m of text.matchAll(ATTACK_RE)) out.add(m[0]);
  return [...out].sort();
}

/**
 * Pull a scalar out of front-matter style files without a YAML dependency.
 *
 * Sigma is YAML, Elastic is TOML, Splunk is JSON-with-comments. Parsing three
 * real formats properly means three parsers and three sets of upstream schema
 * drift to chase, for four fields. A regex over the first few KB gets the
 * title/level/date reliably because every one of these formats puts them in a
 * short flat header block.
 */
function scalar(text, key) {
  const re = new RegExp(`^\\s*(?:-\\s*)?${key}\\s*[:=]\\s*["']?([^"'\\r\\n]+?)["']?\\s*$`, 'im');
  const m = text.match(re);
  return m ? m[1].trim() : null;
}

const READ_CAP = 200_000; // bytes of a rule file we bother to inspect

/**
 * Product tokens extracted from a rule, for product-level coverage matching.
 *
 * This is the correction to the first version of this build, which indexed only
 * rules carrying a CVE id. That was 402 of 7,399 detection rules: vendors mostly
 * do NOT tag rules with CVE ids, so dropping the untagged 95% threw away almost
 * all the coverage signal and made the headline number meaningless.
 *
 * A rule is now matched to a product by the product NAME appearing in its title
 * or path, which is how rules are actually written: a Citrix NetScaler rule is
 * named for the product, not the CVE. Tokens shorter than 4 characters and the
 * generic-noise list below are dropped, because a rule called "Citrix" would
 * otherwise match all 400 Citrix CVEs and a rule called "Core" would match
 * everything.
 */
const PRODUCT_TOKEN_MIN = 4;

/**
 * Product names that appear in rule names for reasons unrelated to the product
 * itself. `core` in "core dump" is the motivating case; without this a generic
 * rule name would match a KEV entry whose product is literally "Core".
 */
const GENERIC_PRODUCT_TOKENS = new Set([
  'core',
  'edge',
  'plus',
  'pro',
  'lite',
  'soft',
  'ware',
  'app',
  'apps',
  'server',
  'client',
  'cloud',
  'system',
  'net',
  'open',
  'data',
  'base',
  'hub',
  'node',
  'link',
  'point',
  'center',
  'central',
  'stack',
  'suite',
  'tool',
  'tools',
  'platform',
  'platforms',
  'windows',
  'linux',
  'macos',
  'android',
  'ios',
]);

function productTokens(text) {
  const out = new Set();
  for (const raw of text.toLowerCase().split(/[^a-z0-9]+/)) {
    if (raw.length < PRODUCT_TOKEN_MIN) continue;
    if (GENERIC_PRODUCT_TOKENS.has(raw)) continue;
    out.add(raw);
  }
  return out;
}

// ── extractors ───────────────────────────────────────────────────────

/**
 * Sigma: YAML under rules/**. Only the canonical `rules/` tree counts; the
 * sibling trees (rules-emerging-threats, rules-threat-hunting, deprecated,
 * unsupported) are either vendored copies or explicitly parked, and counting
 * them would double-report the same rule under two ids.
 */
function extractSigma(rootDir, source, rules) {
  const base = join(rootDir, 'rules');
  if (!existsSync(base)) return { scanned: 0, matched: 0 };

  let scanned = 0;
  for (const file of walk(base)) {
    if (!file.endsWith('.yml') && !file.endsWith('.yaml')) continue;
    scanned += 1;
    const rel = relPath(rootDir, file);
    const text = readFileSync(file, 'utf8').slice(0, READ_CAP);
    const title = scalar(text, 'title') ?? rel.split('/').pop();
    rules.push({
      rid: `sigma:${rel}`,
      source: source.id,
      title,
      url: source.blobBase + rel,
      level: (scalar(text, 'level') ?? '').toLowerCase() || null,
      techniques: attacksIn(text),
      cves: cvesIn(text),
      updated: scalar(text, 'date') ?? null,
      products: [...productTokens(`${title} ${rel}`)],
    });
  }
  return { scanned, matched: rules.filter((r) => r.source === source.id).length };
}

/**
 * Elastic: TOML under the rules/ tree. The detection-rules repo also carries
 * helper modules and lib/ scaffolding which never reference a CVE; the
 * `rules/` prefix keeps us on actual analytics.
 */
function extractElastic(rootDir, source, rules) {
  const base = join(rootDir, 'rules');
  if (!existsSync(base)) return { scanned: 0, matched: 0 };

  let scanned = 0;
  for (const file of walk(base)) {
    if (!file.endsWith('.toml')) continue;
    // Upstream parks retired analytics under rules/_deprecated/. A rule there is
    // not published, so counting it would report coverage that does not exist.
    if (file.includes('/_deprecated/')) continue;
    scanned += 1;
    const rel = relPath(rootDir, file);
    const text = readFileSync(file, 'utf8').slice(0, READ_CAP);
    const title = scalar(text, 'name') ?? rel.split('/').pop();
    rules.push({
      rid: `elastic:${rel}`,
      source: source.id,
      title,
      url: source.blobBase + rel,
      level: (scalar(text, 'risk_score') ?? '').toLowerCase() || null,
      techniques: attacksIn(text),
      cves: cvesIn(text),
      updated: scalar(text, 'updated') ?? null,
      products: [...productTokens(`${title} ${rel}`)],
    });
  }
  return { scanned, matched: rules.filter((r) => r.source === source.id).length };
}

/**
 * Splunk: security_content ships a `.yml` analytics stanza per detection, with
 * the SPL itself under `search`. The CVE reference lives in the yml, so that
 * is the file we read — filtering on `.spl` finds nothing.
 */
function extractSplunk(rootDir, source, rules) {
  const base = join(rootDir, 'detections');
  if (!existsSync(base)) return { scanned: 0, matched: 0 };

  let scanned = 0;
  for (const file of walk(base)) {
    if (!file.endsWith('.yml')) continue;
    // `deprecated/` is a parking lot upstream; a rule there is not published.
    if (file.includes('/deprecated/')) continue;
    scanned += 1;
    const rel = relPath(rootDir, file);
    const text = readFileSync(file, 'utf8').slice(0, READ_CAP);
    const title = scalar(text, 'title') ?? rel.split('/').pop();
    rules.push({
      rid: `splunk:${rel}`,
      source: source.id,
      title,
      url: source.blobBase + rel,
      level: null,
      techniques: attacksIn(text),
      cves: cvesIn(text),
      updated: scalar(text, 'last_updated') ?? null,
      products: [...productTokens(`${title} ${rel}`)],
    });
  }
  return { scanned, matched: rules.filter((r) => r.source === source.id).length };
}

/**
 * Microsoft Sentinel.
 *
 * The repo is ~690 MB and only ~2,300 of its files are KQL analytic rules; the
 * rest is Solution workbooks, sample data and CI config that cannot contain a
 * CVE. So: take the git tree (one 14 MB request), filter to the rule
 * directories, then fetch just those files concurrently from raw.githubusercontent.
 *
 * The live content path is `Solutions/<pack>/Analytic Rules/<file>.yaml`.
 * `Deprecated Analytic Rules`, the older `Analytics Rules` spelling, and the
 * Hunting Queries trees are all parked upstream, so they are excluded for the
 * same reason Sigma's `deprecated/` and Elastic's `_deprecated/` are.
 */
async function extractSentinel(source, rules) {
  const res = await fetch(source.archive, { headers: { 'User-Agent': 'pranithjain-dfir/1.0' } });
  if (!res.ok) throw new Error(`sentinel tree -> HTTP ${res.status}`);
  const tree = (await res.json()).tree ?? [];

  const LIVE = /^Solutions\/[^/]+\/Analytic Rules\/.+\.ya?ml$/i;
  const PARKED = /Deprecated|Analytics Rules\/|Hunting/i;
  const paths = tree
    .filter((t) => t.type === 'blob' && LIVE.test(t.path) && !PARKED.test(t.path))
    .map((t) => t.path);

  process.stdout.write(`  · ${paths.length} analytic rules\n`);

  const CONCURRENCY = 24;
  let cursor = 0;
  let scanned = 0;

  const worker = async () => {
    for (;;) {
      const i = cursor++;
      if (i >= paths.length) return;
      const path = paths[i];
      scanned += 1;
      try {
        const r = await fetch(`${source.rawBase}${encodeURI(path).replace(/%2F/g, '/')}`, {
          headers: { 'User-Agent': 'pranithjain-dfir/1.0' },
          signal: AbortSignal.timeout(20_000),
        });
        if (!r.ok) continue;
        const text = (await r.text()).slice(0, READ_CAP);
        const title = scalar(text, 'title') ?? path.split('/').pop();
        rules.push({
          rid: `sentinel:${path}`,
          source: source.id,
          title,
          url: source.blobBase + encodeURI(path).replace(/%2F/g, '/'),
          level: null,
          techniques: attacksIn(text),
          cves: cvesIn(text),
          updated: null,
          products: [...productTokens(`${title} ${path}`)],
        });
      } catch {
        // One 404 or timeout must not abandon the other 2,000 rules.
      }
    }
  };

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return { scanned, matched: rules.filter((r) => r.source === source.id).length };
}

/**
 * Metasploit: one JSON object keyed by module fullname. `references` holds bare
 * `CVE-YYYY-NNNN` strings alongside OSVDB/BID/URL- prefixed ones, which is
 * exactly why the CVE regex rather than a token split is the right extractor.
 */
function extractMetasploit(jsonPath, source, rules) {
  const meta = JSON.parse(readFileSync(jsonPath, 'utf8'));
  const entries = Object.entries(meta);
  for (const [fullname, m] of entries) {
    const refs = Array.isArray(m.references) ? m.references : [];
    const cves = cvesIn(refs.join('\n'));
    if (cves.length === 0) continue;
    rules.push({
      rid: `metasploit:${fullname}`,
      source: source.id,
      title: m.name ?? fullname,
      url: source.blobBase + fullname.split('/').join('/') + '.rb',
      level: m.rank >= 400 ? 'excellent' : m.rank >= 300 ? 'good' : 'normal',
      techniques: [],
      cves,
      updated: m.mod_time ? String(m.mod_time).slice(0, 10) : null,
      products: [...productTokens(`${m.name ?? ''} ${fullname}`)],
    });
  }
  return { scanned: entries.length, matched: rules.filter((r) => r.source === source.id).length };
}

/**
 * Nuclei: NDJSON, not a JSON array — one template object per line, which is
 * how `cves.json` is generated. Parsing it as one array fails at line 2.
 */
function extractNuclei(jsonPath, source, rules) {
  const raw = readFileSync(jsonPath, 'utf8');
  const templates = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      templates.push(JSON.parse(trimmed));
    } catch {
      // A malformed line is upstream's problem, not a reason to lose the other
      // ~11k templates in the file.
    }
  }

  for (const t of templates) {
    const cves = t.ID ? [String(t.ID).toUpperCase()] : [];
    if (cves.length === 0) continue;
    const filePath = t.file_path ?? t.TemplateID;
    const title = t.Info?.Name ?? t.TemplateID ?? t.ID;
    rules.push({
      rid: `nuclei:${t.TemplateID ?? t.ID}`,
      source: source.id,
      title,
      url: filePath ? `${source.blobBase}${filePath}` : null,
      level: (t.Info?.Severity ?? '').toLowerCase() || null,
      techniques: [],
      cves,
      updated: null,
      products: [...productTokens(`${title} ${t.TemplateID ?? ''}`)],
    });
  }
  return { scanned: templates.length, matched: rules.filter((r) => r.source === source.id).length };
}

/**
 * Exploit-DB CSV: RFC4180 with quoted fields containing newlines and commas,
 * so it has to be parsed properly rather than split on ','.
 *
 * The CVE is in `codes` (a `;`-delimited list of CVE/OSVDB ids), NOT in the
 * description — descriptions read like "AIX Calendar Manager ... Buffer
 * Overflow (Metasploit)" and carry no identifier at all. `tags` and `aliases`
 * can also hold them, so all four are scanned.
 */
function extractExploitDb(csvPath, source, rules) {
  const text = readFileSync(csvPath, 'utf8');
  const rows = [];
  let field = '';
  let row = [];
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else quoted = false;
      } else field += ch;
      continue;
    }
    if (ch === '"') quoted = true;
    else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch !== '\r') field += ch;
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }

  const header = rows.shift() ?? [];
  const col = Object.fromEntries(header.map((h, i) => [h.trim().toLowerCase(), i]));

  // Header names have drifted across exploitdb exports; fall back to the
  // canonical column order rather than silently indexing undefined.
  const at = (name, fallback) => {
    const i = col[name];
    return i === undefined ? fallback : i;
  };
  const iId = at('id', 0);
  const iFile = at('file', 1);
  const iDesc = at('description', 2);
  const iDate = at('date_published', 3);
  const iAuthor = at('author', 4);
  const iCodes = at('codes', 11);
  const iTags = at('tags', 12);
  const iAliases = at('aliases', 13);

  let matched = 0;
  for (const r of rows) {
    const haystack = [r[iDesc], r[iFile], r[iCodes], r[iTags], r[iAliases]].join('\n');
    const cves = cvesIn(haystack);
    if (cves.length === 0) continue;
    matched += 1;
    const edbId = r[iId];
    const desc = (r[iDesc] ?? '').split('\n')[0].slice(0, 160);
    rules.push({
      rid: `exploitdb:${edbId}`,
      source: source.id,
      title: desc,
      url: edbId ? `https://www.exploit-db.com/exploits/${edbId}` : null,
      level: null,
      techniques: [],
      cves,
      updated: (r[iDate] ?? '').slice(0, 10) || null,
      author: r[iAuthor] || null,
      products: [...productTokens(`${desc} ${r[iFile] ?? ''}`)],
    });
  }
  return { scanned: rows.length, matched };
}

// ── main ─────────────────────────────────────────────────────────────

console.log('🔨 Building detection coverage index');

if (!existsSync(CACHE)) mkdirSync(CACHE, { recursive: true });
mkdirSync(OUT, { recursive: true });

const rules = [];
const sourceStats = {};

for (const source of SOURCES) {
  const started = Date.now();
  try {
    let stat;
    if (source.id === 'sentinel') {
      stat = await extractSentinel(source, rules);
    } else if (source.kind === 'detection') {
      const tarball = await download(source.archive, join(CACHE, `${source.id}.tar.gz`));
      const rootDir = extractArchive(tarball, source.id);
      if (source.id === 'sigma') stat = extractSigma(rootDir, source, rules);
      else if (source.id === 'elastic') stat = extractElastic(rootDir, source, rules);
      else stat = extractSplunk(rootDir, source, rules);
    } else {
      const file = await download(source.archive, join(CACHE, `${source.id}.dat`));
      if (source.id === 'metasploit') stat = extractMetasploit(file, source, rules);
      else if (source.id === 'nuclei') stat = extractNuclei(file, source, rules);
      else stat = extractExploitDb(file, source, rules);
    }
    sourceStats[source.id] = { ...stat, ok: true };
    console.log(
      `  ✓ ${source.id.padEnd(11)} ${String(stat.matched).padStart(6)} CVE-linked / ${String(stat.scanned).padStart(6)} scanned  (${Date.now() - started}ms)`
    );
  } catch (err) {
    sourceStats[source.id] = { ok: false, error: String(err.message ?? err) };
    console.log(`  ✗ ${source.id.padEnd(11)} ${err.message ?? err}`);
  }
}

// ── dedupe + shape ───────────────────────────────────────────────────

// A rule can reference the same CVE twice (once in the description, once in a
// references block). Normalise the cves array; sort rules by id so the emitted
// file diffs cleanly between builds rather than reshuffling on archive order.
for (const r of rules) r.cves = [...new Set(r.cves)].sort();
rules.sort((a, b) => a.rid.localeCompare(b.rid));

// ── rollups ──────────────────────────────────────────────────────────

const kindBySource = new Map(SOURCES.map((s) => [s.id, s.kind]));

const cveSet = new Set();
const perSource = {};
const kindCount = { detection: 0, exploit: 0 };
for (const r of rules) {
  r.cves.forEach((c) => cveSet.add(c));
  perSource[r.source] = (perSource[r.source] ?? 0) + 1;
  kindCount[kindBySource.get(r.source) ?? 'detection'] += 1;
}

const sourcesOut = SOURCES.map((s) => ({
  id: s.id,
  label: s.label,
  kind: s.kind,
  format: s.format,
  homepage: s.homepage,
  license: s.license,
  licenseUrl: s.licenseUrl,
  attribution: s.attribution,
  accessUrl: s.archive,
  ruleCount: perSource[s.id] ?? 0,
  scanned: sourceStats[s.id]?.scanned ?? 0,
  status: sourceStats[s.id]?.ok ? 'ok' : 'down',
  ...(sourceStats[s.id]?.ok ? {} : { error: sourceStats[s.id]?.error ?? 'unknown' }),
}));

const stats = {
  schemaVersion: 'detection-coverage-stats-v1',
  generatedAt: new Date().toISOString(),
  rules: rules.length,
  detections: kindCount.detection,
  exploits: kindCount.exploit,
  distinctCves: cveSet.size,
  perSource,
};

// ── artifacts ────────────────────────────────────────────────────────

/**
 * Artifacts, shaped by how each is actually read.
 *
 * A single 9.7 MB `rules.json` would have been simpler, and it was the first
 * version. It is wrong: the Worker would have to parse all 35k rule objects to
 * answer a question about one CVE, and the parsed form costs several times the
 * file size in heap. So the rule set is split by access pattern instead.
 *
 *   index.json          4 KB   source registry + rollups
 *   cve-index.json    1.8 MB   CVE -> {d:[rid], e:[rid]}, the hot path for
 *                                summary, gap list and per-CVE lookups. Rule ids
 *                                are bare strings so a rule covering four CVEs
 *                                costs four id references, not four copies.
 *   detections.json   ~150 KB  every detection rule, small enough to hold
 *                                whole. The library and platform views only
 *                                ever touch detection rules, and there are a
 *                                few hundred of them.
 *   exploits/NN.json   ~600 KB  exploit rules, 16 shards keyed by the CVE's FNV-1a
 *                          each  hash. A per-CVE detail lookup reads exactly one
 *                          shard instead of the whole set.
 *
 * The shard count is a power of two so the modulo is a mask, and 16 was picked
 * because it keeps each shard comfortably inside a single cached read while
 * staying small enough that no single shard dominates.
 */
const SHARD_COUNT = 16;

/** FNV-1a 32-bit. Same algorithm the runtime uses so shard paths agree. */
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

const cveIndex = {};
const detections = [];
const exploitShards = Array.from({ length: SHARD_COUNT }, () => []);

for (const r of rules) {
  const isExploit = kindBySource.get(r.source) === 'exploit';
  for (const cve of r.cves) {
    const entry = (cveIndex[cve] ??= { d: [], e: [] });
    entry[isExploit ? 'e' : 'd'].push(r.rid);
  }
  if (isExploit) {
    // Shard on the RULE ID, not on one of its CVEs. A rule can reference
    // several CVEs, and the runtime only knows which shard a rule is in if the
    // shard is a pure function of the rule id itself. Sharding on `cves[0]`
    // would put the rule in one shard while a lookup for its other CVEs
    // computed a different one, and those lookups would silently miss it.
    const shard = fnv1a(r.rid) % SHARD_COUNT;
    exploitShards[shard].push(r);
  } else {
    detections.push(r);
  }
}

/**
 * ATT&CK technique -> detection rule ids.
 *
 * Technique coverage is the other half of the coverage question. A behavioural
 * detection covers a class of activity, not one CVE, so "is this covered" for a
 * technique is a better proxy for real coverage than any per-CVE join.
 */
const techniqueIndex = {};
for (const r of detections) {
  for (const t of r.techniques) {
    (techniqueIndex[t] ??= []).push(r.rid);
  }
}

/**
 * KEV x coverage, resolved at BUILD time.
 *
 * The first version shipped `product-index.json` (token -> rule ids) and made
 * the Worker do the join at request time. That artifact was 7 MB, larger than
 * the rule set it indexed, because most rules mention a dozen product-shaped
 * words. Doing the join here instead collapses it to one row per KEV entry,
 * which is the only thing any caller actually asks for.
 *
 * Two coverage tiers are kept separate because they are NOT equally strong and
 * presenting them as one number is what made the first version of this page
 * misleading:
 *
 *   d  explicit   a rule cites this CVE id. Strong evidence, and rare.
 *   p  inferred   a rule names this CVE's product. Reasonable evidence, and
 *                 common. A Citrix rule is relevant coverage for a Citrix CVE,
 *                 but it may target a different bug entirely.
 *
 * Callers must not collapse these without saying so.
 */
/**
 * Cap on product-inferred rules stored per CVE.
 *
 * Unbounded, a CVE whose product name is common enough ("Windows", "Linux")
 * matched hundreds of rules and the join artifact grew to 7.5 MB — larger than
 * every other artifact combined, to answer a question nobody asks in that much
 * detail. Capped, with the true total kept alongside so the UI can say
 * "showing 25 of 340" instead of silently implying 25 is all of them.
 */
const PRODUCT_MATCH_CAP = 25;

const kevCoverage = {};
let kevFetched = 0;
try {
  const kevRes = await fetch(KEV_URL, {
    headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!kevRes.ok) throw new Error(`HTTP ${kevRes.status}`);
  const kevBody = await kevRes.json();
  const vulns = Array.isArray(kevBody.vulnerabilities) ? kevBody.vulnerabilities : [];
  kevFetched = vulns.length;

  const productIndex = new Map();
  for (const r of detections) {
    for (const token of r.products ?? []) {
      const list = productIndex.get(token);
      if (list) list.push(r.rid);
      else productIndex.set(token, [r.rid]);
    }
  }

  for (const v of vulns) {
    const cveId = String(v.cveID ?? '').toUpperCase();
    if (!cveId) continue;

    const explicit = cveIndex[cveId] ?? { d: [], e: [] };

    // Tokenize vendor_project and product separately. Vendor alone is too
    // coarse (`Cisco` covers dozens of unrelated products), so a rule must
    // match the PRODUCT to count; the vendor is consulted only when the
    // product field is empty.
    const productToks = productTokens(`${v.product ?? ''}`);
    const searchToks = productToks.length > 0 ? productToks : productTokens(`${v.vendorProject ?? ''}`);

    // A rule matched by more than one product token is far less likely to be
    // coincidence. With a single token there is nothing to corroborate, so
    // every hit counts and the cap does the bounding instead.
    const votes = new Map();
    for (const token of searchToks) {
      for (const rid of productIndex.get(token) ?? []) votes.set(rid, (votes.get(rid) ?? 0) + 1);
    }
    const minVotes = searchToks.length > 1 ? 2 : 1;
    const ranked = [...votes.entries()]
      .filter(([, n]) => n >= minVotes)
      // Stable and deterministic: more votes first, then by id, so two builds
      // of the same inputs emit byte-identical output.
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

    kevCoverage[cveId] = {
      d: explicit.d,
      p: ranked.slice(0, PRODUCT_MATCH_CAP).map(([rid]) => rid),
      pTotal: ranked.length,
      e: explicit.e,
    };
  }
} catch (err) {
  // The rule index is still useful without the KEV join; the route falls back to
  // explicit-only coverage. Say so loudly rather than shipping a silent gap.
  console.log(`  ! KEV join skipped: ${err.message ?? err}`);
  kevCoverage.skipped = { reason: String(err.message ?? err) };
}

stats.kevJoined = kevFetched;
stats.kevWithExplicitDetection = Object.values(kevCoverage).filter((k) => k && Array.isArray(k.d) && k.d.length > 0).length;
stats.kevWithProductInference = Object.values(kevCoverage).filter(
  (k) => k && Array.isArray(k.p) && k.p.length > 0 && (!k.d || k.d.length === 0)
).length;

/**
 * How much of the detection corpus actually cites a CVE. Low, and it is the
 * single most important number this build produces: it is why coverage cannot
 * be measured by CVE reference alone, and why the product and technique indexes
 * exist alongside `cve-index.json`.
 */
stats.detectionRulesTotal = detections.length;
stats.detectionRulesCveTagged = detections.filter((r) => r.cves.length > 0).length;
stats.detectionCveLinkRate = detections.length
  ? Number(((stats.detectionRulesCveTagged / detections.length) * 100).toFixed(1))
  : 0;
stats.techniques = Object.keys(techniqueIndex).length;

/**
 * Daily snapshot for the detection-update changelog.
 *
 * Accumulates one row per build rather than keeping every snapshot: a full
 * rule-set snapshot per day would grow the repository without bound, and the
 * only thing the changelog needs to diff against is yesterday's counts. Rule
 * content changes come from the `updated` field on each rule, which is already
 * indexed; what this catches is rules appearing and disappearing upstream, which
 * is what happens when a vendor retires a corpus or renames a tree.
 */
const HISTORY_PATH = join(OUT, 'history.json');
const HISTORY_KEEP = 90;
const today = new Date().toISOString().slice(0, 10);
let history = { schemaVersion: 'detection-coverage-history-v1', points: [] };
if (existsSync(HISTORY_PATH)) {
  try {
    const prior = JSON.parse(readFileSync(HISTORY_PATH, 'utf8'));
    if (Array.isArray(prior.points)) history = prior;
  } catch {
    // A corrupt history file must not stop the build. The changelog restarts
    // from today, which is a visible gap rather than a silent wrong answer.
  }
}
const perSourceCounts = {};
for (const r of detections) perSourceCounts[r.source] = (perSourceCounts[r.source] ?? 0) + 1;
const snapshot = {
  date: today,
  detections: detections.length,
  exploits: kindCount.exploit,
  techniques: Object.keys(techniqueIndex).length,
  cveTagged: stats.detectionRulesCveTagged,
  perSource: perSourceCounts,
};
// Replace today's row rather than appending, so re-running the build on the
// same day is idempotent instead of showing a duplicate.
history.points = [...history.points.filter((p) => p.date !== today), snapshot]
  .sort((a, b) => a.date.localeCompare(b.date))
  .slice(-HISTORY_KEEP);
writeFileSync(HISTORY_PATH, JSON.stringify({ ...history, generatedAt: stats.generatedAt }, null, 2));

writeFileSync(join(OUT, 'index.json'), JSON.stringify({ ...stats, sources: sourcesOut }, null, 2));
writeFileSync(join(OUT, 'cve-index.json'), JSON.stringify(cveIndex));
writeFileSync(join(OUT, 'kev-coverage.json'), JSON.stringify(kevCoverage));
writeFileSync(join(OUT, 'technique-index.json'), JSON.stringify(techniqueIndex));

// Detection rules are sharded BY SOURCE rather than by hash. The library and
// platform views almost always filter by source, so this is the split that lets
// a request load one file instead of all 9,670 rules, and it maps to how an
// analyst thinks about them ("the Sigma rules", "the Sentinel rules").
const detectionDir = join(OUT, 'detections');
mkdirSync(detectionDir, { recursive: true });
const detectionSizes = [];
for (const source of SOURCES) {
  if (source.kind !== 'detection') continue;
  const rows = detections.filter((r) => r.source === source.id);
  const path = join(detectionDir, `${source.id}.json`);
  writeFileSync(path, JSON.stringify(rows));
  detectionSizes.push({ id: source.id, rules: rows.length, kb: Number((statSync(path).size / 1024).toFixed(0)) });
}

const exploitDir = join(OUT, 'exploits');
mkdirSync(exploitDir, { recursive: true });
const shardSizes = [];
for (let i = 0; i < SHARD_COUNT; i += 1) {
  const name = String(i).padStart(2, '0');
  const path = join(exploitDir, `${name}.json`);
  writeFileSync(path, JSON.stringify(exploitShards[i]));
  shardSizes.push(statSync(path).size);
}

const largest = Math.max(...shardSizes);
const bytes = [
  `index.json ${(statSync(join(OUT, 'index.json')).size / 1024).toFixed(0)}KB`,
  `cve-index.json ${(statSync(join(OUT, 'cve-index.json')).size / 1024).toFixed(0)}KB`,
  `kev-coverage.json ${(statSync(join(OUT, 'kev-coverage.json')).size / 1024).toFixed(0)}KB`,
  `technique-index.json ${(statSync(join(OUT, 'technique-index.json')).size / 1024).toFixed(0)}KB`,
  `detections/ ${detectionSizes.map((d) => `${d.id} ${d.kb}KB`).join(', ')}`,
  `exploits/ ${SHARD_COUNT} shards, largest ${(largest / 1024).toFixed(0)}KB`,
].join('\n  ');

console.log(`\n  ${rules.length} rules · ${kindCount.detection} detection / ${kindCount.exploit} exploit`);
console.log(
  `  CVE-tagged detection rules: ${stats.detectionRulesCveTagged}/${stats.detectionRulesTotal} (${stats.detectionCveLinkRate}%)`
);
console.log(`  ${stats.techniques} ATT&CK techniques indexed`);
console.log(
  `  KEV join: ${stats.kevWithExplicitDetection}/${stats.kevJoined} explicit · ${stats.kevWithProductInference} more via product inference\n`
);
console.log(`  ${bytes}\n`);