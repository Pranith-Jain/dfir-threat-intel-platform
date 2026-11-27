#!/usr/bin/env node
/**
 * Mirror redteam.vip/prtf — the Physical Red Team Framework (CC BY 4.0).
 *
 * REA browser capture confirmed the public page embeds two JS literals:
 * `const T = {…}` (tool catalog) and `const tactics = […]` (9 tactics /
 * 108 techniques with desc, tools, chains and blue-team notes). We parse them
 * as an AST with acorn — never eval upstream JavaScript — and emit structured
 * JSON with attribution and deep links.
 *
 * Output: public/data/prtf/index.json + techniques/<id>.json
 * Run:    node scripts/build-prtf.mjs [--source <page.html>]
 */
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parse } from 'acorn';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'prtf');
const SITE = 'https://redteam.vip/prtf/';
const LICENSE = 'CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/. Attribution: RedTeam.vip, PRTF v1.1.';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

/** AST → plain JSON. Never executes code; unknown node kinds become undefined. */
function astToJson(node) {
  if (!node) return null;
  switch (node.type) {
    case 'Literal':
      return node.value;
    case 'ObjectExpression': {
      const out = {};
      for (const p of node.properties) {
        if (p.type !== 'Property') continue;
        const key = p.key.type === 'Identifier' ? p.key.name : astToJson(p.key);
        out[String(key)] = astToJson(p.value);
      }
      return out;
    }
    case 'ArrayExpression':
      return node.elements.map(astToJson);
    case 'UnaryExpression': {
      const v = astToJson(node.argument);
      if (node.operator === '-') return -v;
      if (node.operator === '+') return +v;
      if (node.operator === '!') return !v;
      return v;
    }
    case 'Identifier':
      return node.name;
    case 'MemberExpression':
      return `${node.object?.name ?? '?'}.${node.property?.name ?? astToJson(node.property)}`;
    default:
      return undefined;
  }
}

/** Extract `const NAME = …;` up to the next `\n};` / `\n];` and parse safely. */
function literal(html, marker, terminator) {
  const start = html.indexOf(marker);
  if (start < 0) throw new Error(`missing ${marker} — upstream layout changed`);
  const end = html.indexOf(terminator, start);
  if (end < 0) throw new Error(`unterminated ${marker}`);
  const src = html.slice(start + marker.length, end + 2);
  const ast = parse(`(${src})`, { ecmaVersion: 'latest' });
  return astToJson(ast.body[0].expression);
}

export function parsePrtf(html) {
  const tools = literal(html, 'const T =', '\n};');
  const tactics = literal(html, 'const tactics =', '\n];');
  if (!Array.isArray(tactics) || !tactics.length) throw new Error('no tactics parsed');

  // Upstream references tools either inline (`[{n,u}]`) or by catalog key
  // (`T.OSINT`, which the AST pass yields as the string "T.OSINT"). Normalise
  // a bare key into a one-item list first: the old `Array.isArray(refs) ? refs
  // : []` guard made the string branch below unreachable, silently dropping
  // every catalog reference.
  const resolveTools = (refs) => {
    const list = Array.isArray(refs) ? refs : typeof refs === 'string' && refs ? [refs] : [];
    return list
      .map((r) => {
        if (typeof r === 'string') {
          const key = r.split('.')[1] ?? r;
          const entry = tools[key];
          return (Array.isArray(entry) ? entry : []).map((t) => ({ name: t?.n, url: t?.u ?? null }));
        }
        if (r && typeof r === 'object' && r.n) return [{ name: r.n, url: r.u ?? null }];
        return [];
      })
      .flat()
      .slice(0, 20);
  };

  const slim = [];
  const bodies = [];
  for (const tac of tactics) {
    for (const sec of tac.sections ?? []) {
      for (const t of sec.techniques ?? []) {
        if (!t?.id) continue;
        const body = {
          id: t.id,
          name: t.name ?? t.id,
          tacticId: tac.id,
          tacticName: tac.name,
          section: sec.label ?? null,
          description: String(t.desc ?? '').slice(0, 6000),
          tools: resolveTools(t.tools),
          chains: (Array.isArray(t.chains) ? t.chains : []).slice(0, 20).map((c) => ({ id: c.id, name: c.name })),
          blue: t.blue ?? null,
          url: `${SITE}#${t.id}`,
        };
        bodies.push(body);
        slim.push({
          id: body.id,
          name: body.name,
          tacticId: tac.id,
          tacticName: tac.name,
          summary: body.description.slice(0, 240),
          toolCount: body.tools.length,
          url: body.url,
        });
      }
    }
  }
  return {
    tactics: (tactics ?? []).map((t) => ({
      id: t.id,
      name: t.name,
      description: String(t.desc ?? '').slice(0, 600),
      count: (t.sections ?? []).reduce((n, s) => n + (s.techniques?.length ?? 0), 0),
    })),
    slim,
    bodies,
  };
}

async function main() {
  const idx = process.argv.indexOf('--source');
  const html = idx > 0
    ? readFileSync(process.argv[idx + 1], 'utf8')
    : await fetch(SITE, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(30_000) })
        .then(async (r) => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return r.text();
        });
  const { tactics, slim, bodies } = parsePrtf(html);
  if (!slim.length) throw new Error('no techniques parsed — upstream layout changed');

  rmSync(join(OUT, 'techniques'), { recursive: true, force: true });
  mkdirSync(join(OUT, 'techniques'), { recursive: true });
  for (const b of bodies) writeJsonIfChanged(join(OUT, 'techniques', `${b.id}.json`), b);

  const index = {
    generatedAt: new Date().toISOString(),
    source: 'PRTF',
    sourceUrl: SITE,
    license: LICENSE,
    version: '1.1',
    counts: { tactics: tactics.length, techniques: slim.length },
    tactics,
    techniques: slim,
  };
  writeJsonIfChanged(join(OUT, 'index.json'), index);
  console.log(`  ✓ PRTF: ${slim.length} techniques / ${tactics.length} tactics → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`prtf build failed: ${e.message}`); process.exit(1); });
