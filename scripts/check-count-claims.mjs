#!/usr/bin/env node
/**
 * Guard the platform's scale claims against the registries that produce
 * them.
 *
 * Every number the README, CLAUDE.md, package.json and the UI quote about
 * "how big is this platform" drifted at the same time, because they were
 * all hand-written copies of a value that is computed somewhere else. The
 * worst of them — "135+ tool DFIR toolkit" (actually 98) and "332-tool MCP
 * server" (actually 426) — sat in the first line of the README.
 *
 * This script derives the numbers from their sources of truth and fails when
 * a claim disagrees. Adding a tool now moves the registry, and the next CI
 * run tells you which sentence to update (or, better, that the sentence is
 * generated and should not be hand-written at all).
 *
 * Sources of truth:
 *   MCP tools      scripts/build-mcp-manifest.mjs → parseAllTools()
 *                  (cross-checked against public/mcp-manifest.json)
 *   DFIR tools     src/components/dfir/tool-count.ts → MAIN_TOOL_COUNT
 *                  (itself pinned to tool-sections.ts by tool-count.test.ts)
 *   DFIR routes    src/data/dfir-hubs.ts page entries
 *   DFIR hubs      src/data/dfir-hubs.ts hub entries
 *
 * Run:  node scripts/check-count-claims.mjs
 */
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseAllTools } from './build-mcp-manifest.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const read = (p) => readFileSync(resolve(ROOT, p), 'utf8');
const readJson = (p) => JSON.parse(read(p));

/* ── Derive the numbers ───────────────────────────────────────────────────── */

const mcpTools = parseAllTools().length;
const mcpManifest = readJson('public/mcp-manifest.json');

const toolCountMirror = read('src/components/dfir/tool-count.ts');
const m = /export const MAIN_TOOL_COUNT = (\d+);/.exec(toolCountMirror);
if (!m) throw new Error('could not read MAIN_TOOL_COUNT from src/components/dfir/tool-count.ts');
const dfirTools = Number(m[1]);

const dfirHubs = read('src/data/dfir-hubs.ts');
const dfirHubEntries = (dfirHubs.match(/^\s*\{\s*id: '/gm) ?? []).length;
const dfirPages = (dfirHubs.match(/path: '\/dfir\//g) ?? []).length;
const dfirHubIds = (dfirHubs.match(/^\s{4}id: '/gm) ?? []).length;

const appSrc = read('src/App.tsx');
const appDfirRoutes = (appSrc.match(/path: '\/dfir[^']*',\s*Component:/g) ?? []).length;
const appTotalRoutes = (appSrc.match(/path: '[^']*',\s*Component:/g) ?? []).length;

/**
 * Count the test files across the four trees.
 *
 * `find` rather than a directory walk so the count matches what a reader
 * would type to check it, and so it does not need a glob dependency.
 */
function countTestFiles() {
  const out = execFileSync(
    'find',
    ['src', 'api', 'worker', 'scripts', '-name', '*.test.*', '-not', '-path', '*/node_modules/*'],
    { cwd: ROOT, encoding: 'utf8' }
  );
  return out.split('\n').filter((l) => l.trim()).length;
}

/* ── The claims ────────────────────────────────────────────────────────────── */

/**
 * Each claim is an anchor (a unique substring of the line), the file it
 * lives in, and the number it must contain.
 *
 * Anchors are used instead of line numbers so the guard survives edits
 * elsewhere in the file; the reported line is whatever the anchor is
 * actually on now.
 */
const CLAIMS = [
  // README
  { file: 'README.md', anchor: 'tool DFIR toolkit', group: 'dfirTools', re: /A (\d+)\+ tool DFIR toolkit/ },
  { file: 'README.md', anchor: 'interactive analyst tools', group: 'dfirTools', re: /(\d+)\+ interactive analyst tools/ },
  { file: 'README.md', anchor: 'tool MCP server', group: 'mcpTools', re: /a (\d+)-tool MCP server/ },
  { file: 'README.md', anchor: 'MCP (Model Context Protocol) server', group: 'mcpTools', re: /A (\d+)-tool MCP/ },
  { file: 'README.md', anchor: 'MCP server (', group: 'mcpTools', re: /MCP server \((\d+) tools\)/ },
  { file: 'README.md', anchor: 'Durable Objects | ', group: 'durableObjects', re: /Durable Objects \| (\d+)/ },
  { file: 'README.md', anchor: 'route components', group: 'appTotalRoutes', re: /\((\d+)(\+)? route components\)/ },
  { file: 'README.md', anchor: 'leak-site directory', group: 'ransomwareGroups', re: /(\d+)-group leak-site directory/ },

  // CLAUDE.md
  { file: 'CLAUDE.md', anchor: 'MCP tool inventory', group: 'mcpTools', re: /MCP tool inventory\*\*: (\d+) tools/ },
  { file: 'CLAUDE.md', anchor: 'regenerate `public/mcp-manifest.json`', group: 'mcpTools', re: /\(now (\d+) tools\)/ },

  // package.json
  { file: 'package.json', anchor: 'analyst tools', group: 'dfirTools', re: /(\d+)\+ analyst tools/ },
  { file: 'package.json', anchor: 'MCP tools', group: 'mcpTools', re: /(\d+)(\+)? MCP tools/ },

  // The product's own copy
  { file: 'src/data/dfir-faq.ts', anchor: 'CRUCIBLE is a free', group: 'dfirTools', re: /collection of (\d+)\+ utilities/ },
  { file: 'src/data/radar-faq.ts', anchor: 'tool DFIR surface', group: 'dfirTools', re: /(\d+)\+ tool DFIR surface/ },
  { file: 'src/components/PageToCheckOut.tsx', anchor: 'browser-side security tools', group: 'dfirTools', re: /(\d+)\+ browser-side security tools/ },
  { file: 'src/components/PageToCheckOut.tsx', anchor: 'Browse all', group: 'dfirTools', re: /Browse all (\d+)\+ tools/ },
  { file: 'src/components/sections/Toolkits.tsx', anchor: 'run in your browser', group: 'dfirTools', re: /(\d+)\+ tools that run in your browser/ },
  { file: 'src/components/ToolStructuredData.tsx', anchor: 'collection of', group: 'dfirTools', re: /collection of (\d+)\+ utilities/ },
  { file: 'src/pages/McpCatalog.tsx', anchor: 'tools for AI agents', group: 'mcpTools', re: /(\d+) tools for AI agents/ },
  { file: 'src/pages/McpCatalog.tsx', anchor: 'MCP tools covering', group: 'mcpTools', re: /(\d+) MCP tools covering/ },
  { file: 'src/pages/McpCatalog.tsx', anchor: 'tools across IOC/CVE/actor/YARA', group: 'mcpTools', re: /'(\d+) tools across/ },
  { file: 'api/src/lib/api-docs-html.ts', anchor: 'MCP server (', group: 'mcpTools', re: /MCP server \((\d+) tools\)/ },
  { file: 'scripts/build-llms-full.mjs', anchor: 'MCP server (AI agent tools', group: 'mcpTools', re: /MCP server \(AI agent tools, (\d+) tools\)/ },

  // The surface-level numbers, which were stale for the same reason.
  { file: 'README.md', anchor: 'consensus scoring across', group: 'iocFeeds', re: /across (\d+) feeds/ },
  { file: 'README.md', anchor: 'geo-coded events across', group: 'pulseLayers', re: /across (\d+) layers/ },
  { file: 'README.md', anchor: 'hand-rolled SVG panels', group: 'metricsPanels', re: /(\d+) hand-rolled SVG panels/ },
  { file: 'README.md', anchor: 'SecOps Tools (', group: 'secopsTools', re: /SecOps Tools \((\d+)\)/ },
  { file: 'README.md', anchor: 'test files', group: 'testFiles', re: /across (\d+) test files/ },

  // The product's own copies of the same numbers.
  { file: 'src/data/threatintel-hubs.ts', anchor: 'leak site - status', group: 'ransomwareGroups', re: /profiles \((\d+) groups\)/ },
  { file: 'src/data/threatintel-hubs.ts', anchor: 'tools across 13 providers', group: 'darknetTools', re: /'(\d+) tools across 13 providers/ },
  { file: 'src/data/threatintel-hubs.ts', anchor: 'events across', group: 'pulseLayers', re: /events across (\d+) layers/ },
  { file: 'src/data/threatintel-sections.ts', anchor: 'tools across 13 providers', group: 'darknetTools', re: /'(\d+) tools across 13 providers/ },
  { file: 'src/pages/DarknetIntel.tsx', anchor: 'tools across 13 providers', group: 'darknetTools', re: /description="(\d+) tools across 13 providers/ },
  { file: 'src/pages/threatintel/IocCorrelation.tsx', anchor: 'public IOC feeds', group: 'iocFeeds', re: /Aggregated across (\d+) public IOC feeds/ },
  { file: 'src/data/dfir/tool-topics.ts', anchor: 'curated security tools', group: 'secopsTools', re: /'(\d+) curated security tools/ },
];

/**
 * Some counts come from data files rather than from code. Those are read
 * from the data and compared against the claim.
 */
const DATA_CLAIMS = [
  {
    file: 'README.md',
    anchor: 'leak-site directory',
    re: /(\d+)-group leak-site directory/,
    value: () => readJson('public/data/ransomware-groups/index.json').counts?.groups ?? 0,
  },
];

/* ── Check ────────────────────────────────────────────────────────────────── */

const GROUPS = {
  dfirTools,
  dfirPages,
  dfirHubs,
  dfirHubEntries,
  mcpTools,
  appTotalRoutes,
  appDfirRoutes,
  // The enabled Durable Object bindings, from wrangler.jsonc. A commented-out
  // binding does not count — ThreatDataDO is implemented but deliberately
  // not enabled.
  durableObjects: (read('wrangler.jsonc').match(/^\s*\{ "name": "[A-Z_]+", "class_name"/gm) ?? []).length,
  ransomwareGroups: readJson('public/data/ransomware-groups/index.json').counts?.groups ?? 0,
  // The globe's layer definitions.
  pulseLayers: (
    read('src/pages/threatintel/global-pulse-types.tsx').match(
      /const LAYER_DEFS[^=]*=\s*\{([\s\S]*?)\n\};/
    )?.[1].match(/^\s{2}[a-zA-Z0-9_]+:/gm) ?? []
  ).length,
  // The metrics dashboard's SVG panels.
  metricsPanels: (read('src/pages/threatintel/Metrics.tsx').match(/<ChartCard/g) ?? []).length,
  // The IOC feeds the correlation view aggregates.
  iocFeeds: new Set(
    (read('api/src/routes/ioc-correlation.ts').match(/trackSource\('([^']+)'/g) ?? []).map((m) =>
      m.match(/'([^']+)'/)[1]
    )
  ).size,
  // The darknet MCP tools.
  darknetTools: mcpManifest.tools.filter((t) => t.name.startsWith('dn_')).length,
  // Test files across the four trees.
  testFiles: countTestFiles(),
  // Routable threat-intel pages.
  threatIntelPages: (read('src/data/threatintel-hubs.ts').match(/path: '\/threatintel\//g) ?? []).length,
  // The SecOps tool catalogue.
  secopsTools: (read('src/data/dfir/secops-catalog.ts').match(/^\s{2}\{\s*id:/gm) ?? []).length,
};

const problems = [];
const checked = [];

function checkClaim({ file, anchor, re, group }) {
  const path = resolve(ROOT, file);
  if (!existsSync(path)) {
    problems.push(`${file}: file not found`);
    return;
  }
  const src = read(file);
  const lines = src.split('\n');
  const lineNo = lines.findIndex((l) => l.includes(anchor));
  if (lineNo === -1) {
    problems.push(`${file}: no line contains the anchor "${anchor}" — the claim moved`);
    return;
  }
  const hit = re.exec(lines[lineNo]);
  if (!hit) {
    problems.push(`${file}:${lineNo + 1}: the anchor "${anchor}" no longer matches ${re}`);
    return;
  }
  const claimed = Number(hit[1]);
  const expected = GROUPS[group];
  checked.push({ file, line: lineNo + 1, claimed, expected, group });
  if (claimed !== expected) {
    problems.push(
      `${file}:${lineNo + 1}: says ${claimed} for ${group} — the registry says ${expected}`
    );
  }
}

for (const claim of CLAIMS) checkClaim(claim);

for (const claim of DATA_CLAIMS) {
  const path = resolve(ROOT, claim.file);
  if (!existsSync(path)) continue;
  const lines = read(claim.file).split('\n');
  const lineNo = lines.findIndex((l) => l.includes(claim.anchor));
  if (lineNo === -1) continue;
  const hit = claim.re.exec(lines[lineNo]);
  if (!hit) continue;
  const claimed = Number(hit[1]);
  const expected = claim.value();
  checked.push({ file: claim.file, line: lineNo + 1, claimed, expected, group: 'data' });
  if (claimed !== expected) {
    problems.push(
      `${claim.file}:${lineNo + 1}: says ${claimed} — the data says ${expected}`
    );
  }
}

/* ── Cross-checks between the two MCP sources ─────────────────────────────── */

if (mcpManifest.toolCount !== mcpTools) {
  problems.push(
    `public/mcp-manifest.json says ${mcpManifest.toolCount} tools but the registrar source has ${mcpTools} — the manifest is stale (run: node scripts/build-mcp-manifest.mjs)`
  );
}
if (mcpManifest.tools?.length !== mcpTools) {
  problems.push(
    `public/mcp-manifest.json lists ${mcpManifest.tools?.length ?? 0} tools but toolCount says ${mcpManifest.toolCount}`
  );
}

/* ── Report ───────────────────────────────────────────────────────────────── */

console.log('=== Platform scale claims vs their registries ===\n');
for (const c of checked) {
  const ok = c.claimed === c.expected;
  console.log(
    `  ${ok ? '✓' : '✗'} ${c.file}:${c.line}  ${c.group} = ${c.claimed}${ok ? '' : ` (registry: ${c.expected})`}`
  );
}
console.log('');

if (problems.length > 0) {
  console.error('Stale scale claims — fix the text, or generate it from the registry:\n');
  for (const p of problems) console.error(`  ✗ ${p}`);
  console.error('');
  process.exit(1);
}

console.log(`All ${checked.length} scale claims match their registries.`);
