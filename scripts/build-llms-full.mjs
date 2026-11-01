#!/usr/bin/env node
/**
 * Build /llms-full.txt - a single concatenated document that gives an
 * LLM the complete picture of the site in one ingestion.
 *
 * The existing /llms.txt (hand-curated) is a 1-page "what is this site"
 * summary aimed at crawl discovery. /llms-full.txt is a much larger file
 * aimed at model ingestion: it contains the full DFIR + threatintel
 * tool catalog with one line per tool, the MCP server manifest summary,
 * and the rest of the static page metadata.
 *
 * Run via:
 *   node scripts/build-llms-full.mjs
 *
 * Wired into the build pipeline via `prebuild`.
 */
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const OUT = join(ROOT, 'public', 'llms-full.txt');

function readIfExists(p) {
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

function extractTools(manifestPath) {
  const raw = readIfExists(manifestPath);
  if (!raw) return [];
  try {
    const m = JSON.parse(raw);
    return m.tools || [];
  } catch {
    return [];
  }
}

function extractHubs(hubsPath) {
  // The threatintel-hubs.ts / dfir-hubs.ts files export an array of
  // { id, label, pages: [{ path, label, desc, ... }] }. We re-parse
  // them lightly - the format is stable TS that JS regex can recover.
  const src = readIfExists(hubsPath);
  if (!src) return [];
  const tools = [];
  // Each tool has `path: '/...'` and `label: '...'` and `desc: '...'`.
  // Walk line-by-line; when we see a path, the next label/desc lines
  // belong to it.
  const lines = src.split('\n');
  let cur = null;
  for (const line of lines) {
    const pathM = /path:\s*'([^']+)'/.exec(line);
    if (pathM) {
      if (cur) tools.push(cur);
      cur = { path: pathM[1], label: null, desc: null };
      continue;
    }
    if (!cur) continue;
    const labelM = /label:\s*'([^']+)'/.exec(line);
    if (labelM && !cur.label) {
      cur.label = labelM[1];
      continue;
    }
    const descM = /desc:\s*'([^']+)'/.exec(line);
    if (descM && !cur.desc) {
      cur.desc = descM[1];
      continue;
    }
  }
  if (cur) tools.push(cur);
  return tools.filter((t) => t.path && t.label);
}

function formatTool(t, section) {
  const desc = t.desc || t.description || '';
  return `- [${t.label || t.name}](https://pranithjain.qzz.io${t.path || ''}) (${section}): ${desc}`;
}

function main() {
  const lines = [];
  lines.push('# pranithjain.qzz.io - full catalog');
  lines.push('');
  lines.push('> LLM-ingestible catalog of every tool, surface, and AI-agent endpoint on pranithjain.qzz.io. ');
  lines.push('> This is a single concatenated document - every section is self-contained. The site has a live ');
  lines.push('> DFIR + Threat Intel platform and an MCP server; the live endpoints are noted in their sections.');
  lines.push('');

  // Hero - matches the homepage opening.
  lines.push('## Overview');
  lines.push('');
  lines.push('Pranith Jain is an Associate Cyber Security Analyst on the Capgemini CERT team (Threat and');
  lines.push(
    'Vulnerability Intelligence group) working AI automation, autonomous workflows, and AI threat intelligence.'
  );
  lines.push('He builds and runs a live, edge-deployed DFIR and threat-intelligence platform at');
  lines.push('https://pranithjain.qzz.io . The platform has three surfaces:');
  lines.push('');
  lines.push('- A personal portfolio (/, /about, /skills, /experience, /projects).');
  lines.push('- A 130+ tool DFIR toolkit (/dfir/*) covering IOC checks, phishing analysis, CVE triage, ');
  lines.push('  Sigma/KQL/SPL/YARA rule conversion, email defense, IAM analysis, and more.');
  lines.push('- A 124+ surface live threat-intelligence platform (/threatintel/*) with ransomware tracking, ');
  lines.push('  IOC correlation, CVE/KEV feeds, actor timelines, breach monitoring, daily briefings, and an ');
  lines.push('  autonomous case-study blog.');
  lines.push('');
  lines.push('The platform is open at the edge - no signup, no API key required for browsing. Sensitive ');
  lines.push('endpoints (admin, write operations) require an API key or admin token issued at /api/v1/admin/keys.');
  lines.push('');

  // DFIR catalog
  lines.push('## DFIR toolkit tools (130+ routes)');
  lines.push('');
  const dfir = extractHubs(join(ROOT, 'src/data/dfir-hubs.ts'));
  for (const t of dfir) lines.push(formatTool(t, 'dfir'));
  lines.push('');

  // Threat intel catalog
  lines.push('## Threat Intel platform surfaces (124+ routes)');
  lines.push('');
  const ti = extractHubs(join(ROOT, 'src/data/threatintel-hubs.ts'));
  for (const t of ti) lines.push(formatTool(t, 'threatintel'));
  lines.push('');

  // MCP server
  lines.push('## MCP server (AI agent tools, 429 tools)');
  lines.push('');
  lines.push('Endpoint: https://pranithjain.qzz.io/api/mcp (streamable HTTP)');
  lines.push('Auth: Authorization: Bearer <api-key> or X-API-Key: <key>');
  lines.push('Manifest: https://pranithjain.qzz.io/mcp-manifest.json');
  lines.push('Drop-in configs: https://pranithjain.qzz.io/mcp/{claude-desktop,cursor,vscode-mcp}.json');
  lines.push('');
  const mcp = extractTools(join(ROOT, 'public/mcp-manifest.json'));
  for (const t of mcp) lines.push(formatTool({ ...t, path: '/mcp' }, `mcp:${t.category}`));
  lines.push('');

  // OpenAPI
  lines.push('## REST API (OpenAPI 3.1)');
  lines.push('');
  lines.push('Spec: https://pranithjain.qzz.io/api/v1/openapi.json');
  lines.push('Browser: https://pranithjain.qzz.io/api/docs (Scalar)');
  lines.push('Health: https://pranithjain.qzz.io/api/v1/health');
  lines.push('Feed status: https://pranithjain.qzz.io/api/v1/feed-status');
  lines.push('');

  // Brief mention of the open-source packages
  lines.push('## Open-source packages published from this codebase');
  lines.push('');
  lines.push('- cti-text-extract - synchronous, dependency-free CTI entity extractor.');
  lines.push('- stix21-builder - STIX 2.1 bundle builder with deterministic UUIDv5 IDs.');
  lines.push('- cti-ioc-enrich - pluggable IOC enrichment framework.');
  lines.push('- telegram-preview-parser - parse Telegram channel previews to structured JSON.');
  lines.push('- deepdarkcti-parser - parse the fastfire/deepdarkCTI markdown index to typed JSON.');
  lines.push('- cti-platform - the threat-intel platform as a standalone app.');
  lines.push('- DFIR-PLATFORM - the DFIR toolkit as a standalone app.');
  lines.push('- cti-stix-connector (Python) - ingests CSV/JSON/MyThreatIntel data into valid STIX 2.1.');
  lines.push('');

  // Status / freshness statement
  lines.push('## Live status');
  lines.push('');
  lines.push('Per-feed freshness: https://pranithjain.qzz.io/status');
  lines.push('Hourly cron-driven refresh; all caches have a 5-15 minute TTL.');
  lines.push('');

  // Build header / version
  lines.push('---');
  lines.push(`Generated at build time. Pull /mcp-manifest.json for the authoritative tool list and `);
  lines.push(`/api/v1/openapi.json for the authoritative API spec.`);
  lines.push('');

  const out = lines.join('\n');
  writeFileSync(OUT, out, 'utf8');
  console.log(`+ ${OUT}  (${(out.length / 1024).toFixed(1)} KB, ${lines.length} lines)`);
}

main();
