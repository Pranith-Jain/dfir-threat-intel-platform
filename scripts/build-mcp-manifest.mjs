#!/usr/bin/env node
/**
 * Build the MCP (Model Context Protocol) server manifest.
 *
 * Parses `worker/mcp-server.ts` and emits:
 *   public/mcp-manifest.json           — machine-readable list of every tool
 *   public/mcp/claude-desktop.json     — drop-in Claude Desktop config
 *   public/mcp/cursor.json             — drop-in Cursor config
 *   public/mcp/vscode-mcp.json         — drop-in VS Code (Copilot) config
 *   public/mcp/README.md               — human-readable tool catalog
 *
 * The MCP endpoint is wired in `worker/index.ts` at `/api/mcp`; this
 * manifest is the discoverability surface that lets analysts (and
 * AI agents) find and use those tools without reading the source.
 *
 * Run via:
 *   node scripts/build-mcp-manifest.mjs
 *
 * Wired into the build pipeline via `prebuild`.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const MCP_SRC = join(ROOT, 'worker', 'mcp-server.ts');
const MCP_TOOLS_DIR = join(ROOT, 'worker', 'mcp-tools');
const OUT_DIR = join(ROOT, 'public', 'mcp');
const MANIFEST_PATH = join(ROOT, 'public', 'mcp-manifest.json');

const SERVER_NAME = 'DFIR-ThreatIntel-MCP';
const SERVER_VERSION = '1.0.0';
const ENDPOINT = 'https://pranithjain.qzz.io/api/mcp';
const TRANSPORT = 'streamable-http';

// ── Categories ────────────────────────────────────────────────────────────
const CATEGORY_HINTS = [
  { match: /^(check_ioc|ioc_|correlate_iocs)/, cat: 'ioc' },
  { match: /^(lookup_cve|cve_)/, cat: 'cve' },
  { match: /^(enrich_actor|search_actor)/, cat: 'actor' },
  { match: /^(lookup_domain|lookup_asn|lookup_ip|get_ip|pivot_domain|search_registrant|watch_domain_ct|get_domain_certs|get_domain_history|whois|get_dns|get_wayback|wayback)/, cat: 'domain' },
  { match: /^(analyze_phishing|analyze_url|phish)/, cat: 'phishing' },
  { match: /^(unified_search|search_)/, cat: 'search' },
  { match: /^(get_live_iocs|get_ransomware|get_today_briefing|list_briefings|get_supply|get_global|get_correlated|get_detection_rules|get_mitre|get_relationship|get_blocklists|get_malpedia|search_malpedia|search_triage)/, cat: 'intel' },
  { match: /^(analyze_report|extract_ttps|extract_fivew|extract_iocs|parse_)/, cat: 'analysis' },
  { match: /^(generate_yara|validate_yara|generate_kql|generate_sigma|generate_splunk)/, cat: 'detection' },
  { match: /^(get_breach|check_breach|breach_)/, cat: 'breach' },
  { match: /^(get_geo|get_company|get_ip_geo|geo)/, cat: 'infra' },
  { match: /^(hr_|hudson)/, cat: 'hudson' },
  { match: /^(si_|security_investigator)/, cat: 'si' },
  { match: /^(nhi_)/, cat: 'identity' },
  { match: /^(winreg_)/, cat: 'winreg' },
  { match: /^(sigbase_)/, cat: 'sigbase' },
  { match: /^(passive_dns)/, cat: 'pdns' },
  { match: /^(ioc_watchlist)/, cat: 'watchlist' },
  { match: /^(notebook)/, cat: 'notebook' },
  { match: /^(shiftlog)/, cat: 'shiftlog' },
  { match: /^(promptvault|hypos)/, cat: 'prompts' },
  { match: /^(trace_wallet|wallet|crypto)/, cat: 'crypto' },
  { match: /^(generate_dork|dork|google)/, cat: 'osint' },
  { match: /^(check_exposure|exposure|scan_website|scan_site|get_technologies|builtwith)/, cat: 'exposure' },
  { match: /^(dl_|destroylist)/, cat: 'phishing' },
];

export function categorize(name) {
  for (const h of CATEGORY_HINTS) {
    if (h.match.test(name)) return h.cat;
  }
  return 'other';
}

// ── Parser ────────────────────────────────────────────────────────────────

/**
 * Find the matching `)` for an opening `(` in TypeScript source.
 * Skips strings, template literal interpolations, and comments so
 * apostrophes in comments don't fool the paren counter.
 */
export function findMatchingParen(src, openIdx) {
  let i = openIdx + 1;
  let depth = 1;
  while (i < src.length) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      if (nl < 0) return -1;
      i = nl + 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end < 0) return -1;
      i = end + 2;
      continue;
    }
    if (c === "'" || c === '"') {
      const q = c;
      i++;
      while (i < src.length) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === q) { i++; break; }
        i++;
      }
      continue;
    }
    if (c === '`') {
      i++;
      while (i < src.length) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === '`') { i++; break; }
        if (src[i] === '$' && src[i + 1] === '{') {
          i += 2;
          let d = 1;
          while (i < src.length && d > 0) {
            if (src[i] === '{') d++;
            else if (src[i] === '}') d--;
            if (d > 0) i++;
          }
          i++;
          continue;
        }
        i++;
      }
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

/** Pull all string-literal contents from a block. Comments are skipped. */
export function extractStringLiterals(block) {
  const lits = [];
  let i = 0;
  while (i < block.length) {
    const c = block[i];
    if (c === '/' && block[i + 1] === '/') {
      const nl = block.indexOf('\n', i);
      if (nl < 0) break;
      i = nl + 1;
      continue;
    }
    if (c === '/' && block[i + 1] === '*') {
      const end = block.indexOf('*/', i + 2);
      if (end < 0) break;
      i = end + 2;
      continue;
    }
    if (c === "'" || c === '"') {
      const q = c;
      let j = i + 1;
      while (j < block.length) {
        if (block[j] === '\\') { j += 2; continue; }
        if (block[j] === q) { j++; break; }
        j++;
      }
      lits.push(block.substring(i + 1, j - 1));
      i = j;
      continue;
    }
    i++;
  }
  return lits;
}

export function parseTools(src) {
  const tools = [];
  // Tool registrations were moved out of mcp-server.ts into worker/mcp-tools/*,
  // where each registrar receives the host and calls `h.tools(...)`. Accept the
  // old `this.tools(...)` spelling too, so the parser keeps working for any
  // registration still written directly against the class.
  const re = /(?:this|h)\.tools?\(/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const openIdx = m.index + m[0].length - 1;
    const closeIdx = findMatchingParen(src, openIdx);
    if (closeIdx < 0) continue;
    const block = src.substring(openIdx + 1, closeIdx);
    const lits = extractStringLiterals(block);
    if (lits.length < 2) continue;
    const name = lits[0];
    const description = lits[1];
    if (!/^[a-z_][a-z0-9_]*$/.test(name)) continue;
    tools.push({ name, description });
  }
  return tools;
}

// ── Main ──────────────────────────────────────────────────────────────────

/**
 * Tool registrations no longer live in mcp-server.ts itself — they were split
 * into per-domain registrar modules under worker/mcp-tools/. This derives that
 * module list from the registrar imports in mcp-server.ts, so a newly added
 * registrar is picked up automatically and in the same order init() calls it
 * (which keeps the duplicate-name warning deterministic).
 */
export function toolSourcePaths() {
  const server = readFileSync(MCP_SRC, 'utf8');
  const mods = [
    ...server.matchAll(/import \{ register\w+Tools \} from '\.\/mcp-tools\/([a-z0-9-]+)';/g),
  ].map((m) => m[1]);
  return mods.map((m) => join(MCP_TOOLS_DIR, `${m}.ts`));
}

/** Parse every tool registration across mcp-server.ts + all registrar modules. */
export function parseAllTools() {
  const tools = [];
  // mcp-server.ts is included so any registration added directly to the class
  // is still picked up (it currently contributes none).
  for (const p of [MCP_SRC, ...toolSourcePaths()]) {
    tools.push(...parseTools(readFileSync(p, 'utf8')));
  }
  return tools;
}

function main() {
  const tools = parseAllTools();

  if (tools.length === 0) {
    console.error('No tools parsed from worker/mcp-tools/* - refusing to write an empty manifest.');
    process.exit(1);
  }

  // Deduplicate (warn if source has dupes).
  const seen = new Set();
  const uniq = [];
  for (const t of tools) {
    if (seen.has(t.name)) {
      console.error(`WARN: duplicate tool name "${t.name}" in worker/mcp-tools/* - keeping first only`);
      continue;
    }
    seen.add(t.name);
    uniq.push(t);
  }
  uniq.sort((a, b) => a.name.localeCompare(b.name));

  const manifest = {
    $schema: 'https://modelcontextprotocol.io/schemas/manifest/v1.json',
    name: SERVER_NAME,
    version: SERVER_VERSION,
    description:
      'DFIR + Threat Intel MCP server. ' + uniq.length + ' tools across IOC check, CVE/KEV, actor enrichment, domain/ASN/WHOIS pivots, ransomware + breach monitoring, phishing analysis, supply-chain attacks, YARA/Sigma authoring, MITRE ATT&CK extraction, Hudson Rock infostealer search, passive DNS, IOC watchlists, investigation notebooks, shift handover, prompt vault, and the full SCStelz/security-investigator playbook library (KQL queries, skills, automations, knowledge-base docs).',
    transport: TRANSPORT,
    endpoint: ENDPOINT,
    auth: {
      type: 'api-key',
      header: 'Authorization: Bearer <key>',
      altHeader: 'X-API-Key: <key>',
      note: 'An API key is required to test this MCP. Email hello@pranithjain.qzz.io to request one.',
    },
    capabilities: { tools: { listChanged: false } },
    toolCount: uniq.length,
    generatedAt: stableGeneratedAt(),
    tools: uniq.map((t) => ({
      name: t.name,
      description: t.description,
      category: categorize(t.name),
    })),
  };

  mkdirSync(OUT_DIR, { recursive: true });

  writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log(`+ ${MANIFEST_PATH}  (${uniq.length} tools)`);

  const claudeDesktop = {
    mcpServers: {
      'dfir-threatintel': {
        transport: TRANSPORT,
        url: ENDPOINT,
        headers: { Authorization: 'Bearer <your-api-key>' },
      },
    },
  };
  writeFileSync(join(OUT_DIR, 'claude-desktop.json'), JSON.stringify(claudeDesktop, null, 2) + '\n', 'utf8');

  const cursor = {
    mcpServers: {
      'dfir-threatintel': {
        url: ENDPOINT,
        transport: TRANSPORT,
        headers: { Authorization: 'Bearer <your-api-key>' },
      },
    },
  };
  writeFileSync(join(OUT_DIR, 'cursor.json'), JSON.stringify(cursor, null, 2) + '\n', 'utf8');

  const vscode = {
    servers: {
      'dfir-threatintel': {
        type: 'http',
        url: ENDPOINT,
        headers: { Authorization: 'Bearer <your-api-key>' },
      },
    },
  };
  writeFileSync(join(OUT_DIR, 'vscode-mcp.json'), JSON.stringify(vscode, null, 2) + '\n', 'utf8');

  const grouped = new Map();
  for (const t of uniq) {
    const c = categorize(t.name);
    if (!grouped.has(c)) grouped.set(c, []);
    grouped.get(c).push(t);
  }
  const catOrder = Array.from(grouped.keys()).sort((a, b) => grouped.get(b).length - grouped.get(a).length);
  const md = [
    '# DFIR-ThreatIntel MCP - tool catalog',
    '',
    '**' + uniq.length + ' tools** | live at `' + ENDPOINT + '` (streamable HTTP).',
    '',
    '## Quick start',
    '',
    '1. An API key is required to test this MCP - email `hello@pranithjain.qzz.io` to request one.',
    '2. Drop one of the config snippets in this directory into your MCP client config:',
    '   - **Claude Desktop**: `claude-desktop.json` -> `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\\Claude\\claude_desktop_config.json` (Windows).',
    '   - **Cursor**: `cursor.json` -> `~/.cursor/mcp.json`.',
    '   - **VS Code (Copilot)**: `vscode-mcp.json` -> `.vscode/mcp.json` in your workspace.',
    '3. Replace `<your-api-key>` with a real key.',
    '4. Restart your client. Tools appear as `mcp__dfir-threatintel__<tool_name>`.',
    '',
    '## Tools by category',
    '',
    ...catOrder.flatMap((c) => {
      const items = grouped.get(c);
      return ['### ' + c + ' (' + items.length + ')', '', ...items.map((t) => '- `' + t.name + '` - ' + t.description), ''];
    }),
    '## Machine-readable',
    '',
    'Full manifest with per-tool metadata: `mcp-manifest.json` at the site root.',
  ].join('\n');
  writeFileSync(join(OUT_DIR, 'README.md'), md, 'utf8');
  console.log(`+ ${join(OUT_DIR, 'README.md')}`);
}

/**
 * Deterministic `generatedAt`: the last commit that touched the tool surface
 * (worker/mcp-server.ts) rather than the wall clock. Rebuilding an unchanged
 * tree produces the same manifest byte-for-byte, so auto-sync workflows
 * commit only on real tool changes. Falls back to the wall clock when not
 * in a git repo.
 */
function stableGeneratedAt() {
  try {
    const stamp = execSync('git log -1 --format=%cI -- worker/mcp-server.ts', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (stamp) return stamp;
  } catch {
    // not a git repo — fall through
  }
  return new Date().toISOString();
}

const isMain = (() => {
  if (typeof process === 'undefined' || !process.argv[1]) return false;
  try {
    return fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
})();

if (isMain) {
  main();
}
