#!/usr/bin/env node
/**
 * Metadata-only reference entries for two security research projects:
 *   - argonne-citadel/grid-stix (GPL-3.0) — electrical-grid STIX 2.1 ontology
 *   - sresarehumantoo/ARTEX-CC (AGPL-3.0) — MCP bridge for autonomous pentesting
 *
 * Neither project's code, README prose or images are vendored. This emits
 * short original summaries, factual counts, licence identifiers and upstream
 * links, plus the public headings found in each README.
 *
 * Output: public/data/research-projects/index.json
 * Run:    node scripts/build-research-projects.mjs [--source-dir <dir>]
 */
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'research-projects', 'index.json');
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

const PROJECTS = [
  {
    id: 'grid-stix',
    name: 'Grid-STIX',
    repo: 'argonne-citadel/grid-stix',
    url: 'https://github.com/argonne-citadel/grid-stix',
    docUrl: 'https://raw.githubusercontent.com/argonne-citadel/grid-stix/main/README.md',
    license: 'GPL-3.0',
    summary: 'STIX 2.1 ontology for electrical-grid cybersecurity: assets, OT devices, zero-trust components, AMI, supply chain and nuclear safeguards.',
    facts: [
      { label: 'Classes', value: '230+' },
      { label: 'Grid relationships', value: '40+' },
      { label: 'ICS protocols', value: '13 (DNP3, Modbus, IEC 61850/60870, OPC-UA, PROFINET, …)' },
      { label: 'Format', value: 'OWL ontology + STIX 2.1 + generated Python classes' },
    ],
    capabilities: ['zero trust', 'AMI', 'supply chain', 'nuclear safeguards', 'attack patterns', 'STIX 2.1', 'OWL'],
  },
  {
    id: 'artex-cc',
    name: 'ARTEX-CC',
    repo: 'sresarehumantoo/ARTEX-CC',
    url: 'https://github.com/sresarehumantoo/ARTEX-CC',
    docUrl: 'https://raw.githubusercontent.com/sresarehumantoo/ARTEX-CC/main/README.md',
    license: 'AGPL-3.0',
    summary: 'Go bridge exposing an autonomous penetration-testing workflow as 65 MCP tools driven by Claude Code; no separate LLM API key.',
    facts: [
      { label: 'MCP tools', value: '65' },
      { label: 'Language', value: 'Go 1.26+' },
      { label: 'Model', value: 'Brings its own client; ARTEX supplies the hands (asset graph, findings, traffic, reports)' },
      { label: 'Scope', value: 'Authorized pentests, red teaming, CTFs and lab work only' },
    ],
    capabilities: ['MCP', 'asset graph', 'exploration tracking', 'finding management', 'coverage recording', 'traffic capture', 'report generation'],
  },
];

/** Public README headings are factual structure, not vendored prose. */
export function headingsFrom(markdown = '') {
  return [...String(markdown).matchAll(/^#{1,3}\s+(.+)$/gm)]
    .map((m) => m[1].replace(/[*`]/g, '').trim())
    .filter(Boolean)
    .slice(0, 30);
}

async function main() {
  const arg = process.argv.indexOf('--source-dir');
  const dir = arg > 0 ? process.argv[arg + 1] : null;
  const projects = [];
  for (const p of PROJECTS) {
    let headings = [];
    try {
      const md = dir
        ? readFileSync(join(dir, `${p.id}.md`), 'utf8')
        : await fetch(p.docUrl, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(25_000) })
            .then(async (r) => (r.ok ? r.text() : ''));
      headings = headingsFrom(md);
    } catch {
      /* headings are decoration — never fail the build */
    }
    projects.push({
      id: p.id,
      name: p.name,
      repo: p.repo,
      url: p.url,
      license: p.license,
      summary: p.summary,
      facts: p.facts,
      capabilities: p.capabilities,
      headings,
      note: 'No project code, README prose or images are vendored. Metadata and public headings only; deep-link upstream.',
    });
  }
  writeJsonIfChanged(OUT, {
    generatedAt: new Date().toISOString(),
    source: 'Public GitHub project metadata',
    counts: { projects: projects.length },
    projects,
  });
  console.log(`  ✓ research projects: ${projects.length} metadata entries → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`research-projects build failed: ${e.message}`); process.exit(1); });
