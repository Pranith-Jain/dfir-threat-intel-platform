#!/usr/bin/env node
/**
 * One-off codemod: replace the inline caught-error ternary with `errMessage()`
 * across `worker/`.
 *
 * Same shape as scripts/codemod-err-message.mjs, which did `src/`:
 *   e instanceof Error ? e.message : String(e)   →  errMessage(e)
 *
 * Deliberately NOT applied to `api/src/`: route handlers there must not echo
 * raw error text to clients — `lib/error.ts`'s `safeErrorMessage()` redacts
 * outside dev, and rewriting those sites to a raw helper would strip that
 * guarantee. Test files are left alone here too.
 *
 * Run from the repo root:  node scripts/codemod-worker-err-message.mjs [--write]
 * Report-only by default; pass --write to apply.
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKER = resolve(ROOT, 'worker');
const WRITE = process.argv.includes('--write');

const RE_IDENT = /\b([A-Za-z_$][A-Za-z0-9_$]*) instanceof Error \? \1\.message : String\(\1\)/g;
const RE_LITERAL = /\b([A-Za-z_$][A-Za-z0-9_$]*) instanceof Error \? \1\.message : '([^'\\\n]*)'/g;
const RE_LITERAL_DQ = /\b([A-Za-z_$][A-Za-z0-9_$]*) instanceof Error \? \1\.message : "([^"\\\n]*)"/g;

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const p = resolve(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(p);
  }
  return out;
}

const HELPER = resolve(WORKER, 'lib/err');

function helperImportPath(file) {
  const rel = relative(dirname(file), HELPER).split('\\').join('/');
  return rel.startsWith('.') ? rel : './' + rel;
}

let touchedFiles = 0;
let total = 0;

for (const file of walk(WORKER)) {
  if (file === HELPER + '.ts') continue;
  const before = readFileSync(file, 'utf8');
  let s = before;
  s = s.replace(RE_LITERAL, (_m, id, lit) => `errMessage(${id}, '${lit}')`);
  s = s.replace(RE_LITERAL_DQ, (_m, id, lit) => `errMessage(${id}, "${lit}")`);
  s = s.replace(RE_IDENT, (_m, id) => `errMessage(${id})`);
  if (s === before) continue;

  if (!/from '[^']*lib\/err'/.test(s)) {
    // Anchor on the END of the last top-level import statement, including
    // multi-line blocks (`import {\n  A,\n} from 'x';`). Matching only
    // single-line imports silently skipped every file whose imports all wrap —
    // which is where a large share of these sites live.
    const imports = [...s.matchAll(/^import\s[\s\S]*?;\n/gm)];
    const last = imports[imports.length - 1];
    // No import statement at all (dependency-free modules like lib/cerast.ts):
    // insert after the leading file doc-comment so the module's own header
    // stays at the top.
    if (!last || last.index === undefined) {
      const doc = /^\/\*\*[\s\S]*?\*\/\n/.exec(s);
      const at = doc ? doc[0].length : 0;
      s = s.slice(0, at) + `\nimport { errMessage } from '${helperImportPath(file)}';\n` + s.slice(at);
    } else {
      const at = last.index + last[0].length;
      s = s.slice(0, at) + `import { errMessage } from '${helperImportPath(file)}';\n` + s.slice(at);
    }
  }

  total += (before.match(RE_IDENT) ?? []).length + (before.match(RE_LITERAL) ?? []).length + (before.match(RE_LITERAL_DQ) ?? []).length;
  touchedFiles++;
  if (WRITE) writeFileSync(file, s);
  else console.log(`${relative(ROOT, file)}`);
}

let left = 0;
const leftFiles = [];
for (const file of walk(WORKER)) {
  const n = (readFileSync(file, 'utf8').match(/instanceof Error \?/g) ?? []).length;
  if (n > 0) {
    left += n;
    leftFiles.push([relative(ROOT, file), n]);
  }
}

console.log(`\n${WRITE ? 'rewrote' : 'would rewrite'} ${total} sites across ${touchedFiles} worker files`);
console.log(`${left} non-standard sites remain in worker/: ${leftFiles.map(([f, n]) => `${n} ${f}`).join(', ') || 'none'}`);