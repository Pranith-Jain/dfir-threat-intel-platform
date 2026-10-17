#!/usr/bin/env node
/**
 * One-off codemod: replace the inline caught-error ternary with `errMessage()`.
 *
 * The shape being deleted:
 *   e instanceof Error ? e.message : String(e)      →  errMessage(e)
 *   e instanceof Error ? e.message : 'no data'      →  errMessage(e, 'no data')
 *
 * Scope is deliberately `src/` only:
 *   - `api/src` uses `safeErrorMessage(env, err)`, which REDACTS in production
 *     (returns "upstream error" unless DFIR_DEV_ERRORS=1). Rewriting it to a raw
 *     message helper would leak upstream response text to clients.
 *   - `worker/` has no equivalent helper yet; its 161 sites are a separate pass.
 *
 * Test files are left alone: same churn, no production value.
 *
 * Run from the repo root:  node scripts/codemod-err-message.mjs [--dry-run]
 * Report-only by default; pass --write to apply.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readdirSync, statSync } from 'node:fs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = resolve(ROOT, 'src');
const WRITE = process.argv.includes('--write');

/** `X instanceof Error ? X.message : String(X)` — X is a simple identifier. */
const RE_IDENT = /\b([A-Za-z_$][A-Za-z0-9_$]*) instanceof Error \? \1\.message : String\(\1\)/g;
/** `X instanceof Error ? X.message : 'literal'` — single-quoted, no escapes. */
const RE_LITERAL = /\b([A-Za-z_$][A-Za-z0-9_$]*) instanceof Error \? \1\.message : '([^'\\\n]*)'/g;
/** `X instanceof Error ? X.message : "literal"` — double-quoted, no escapes. */
const RE_LITERAL_DQ = /\b([A-Za-z_$][A-Za-z0-9_$]*) instanceof Error \? \1\.message : "([^"\\\n]*)"/g;

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const p = resolve(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry) && !/__tests__/.test(p)) out.push(p);
  }
  return out;
}

/** Import path from a file under src/ to src/lib/log, plus the depth. */
function logImportPath(file) {
  const rel = relative(dirname(file), resolve(SRC, 'lib/log')).split('\\').join('/');
  return rel.startsWith('.') ? rel : './' + rel;
}

const files = walk(SRC);
let touchedFiles = 0;
let total = 0;
const leftovers = [];

for (const file of files) {
  const before = readFileSync(file, 'utf8');
  let s = before;

  s = s.replace(RE_LITERAL, (_m, id, lit) => `errMessage(${id}, '${lit}')`);
  s = s.replace(RE_LITERAL_DQ, (_m, id, lit) => `errMessage(${id}, "${lit}")`);
  s = s.replace(RE_IDENT, (_m, id) => `errMessage(${id})`);

  if (s === before) continue;

  // The definition site itself must not import itself.
  if (file === resolve(SRC, 'lib/log.ts')) {
    console.error('refusing to touch src/lib/log.ts (definition site)');
    continue;
  }

  const usedFallback = /errMessage\([^)]*,/.test(s);
  const importLine = `import {${usedFallback ? ' errMessage,' : ' errMessage'}} from '${logImportPath(file)}';`;

  if (!/from '[^']*lib\/log'/.test(s)) {
    // Insert after the last top-level import statement, INCLUDING multi-line
    // blocks — a single-line-only anchor silently skips every file whose
    // imports all wrap.
    const imports = [...s.matchAll(/^import\s[\s\S]*?;\n/gm)];
    const last = imports[imports.length - 1];
    // No import statement at all (dependency-free modules): insert after the
    // leading file doc-comment so the module's own header stays on top.
    const at = last ? last.index + last[0].length : (/^\/\*\*[\s\S]*?\*\/\n/.exec(s)?.[0].length ?? 0);
    s = s.slice(0, at) + importLine + '\n' + s.slice(at);
  } else {
    // Merge into an existing `from '.../lib/log'` import when it doesn't
    // already pull errMessage in.
    const m = /import \{([^}]*)\} from '([^']*lib\/log)';/.exec(s);
    if (m && !/\berrMessage\b/.test(m[1])) {
      const names = m[1]
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean);
      names.push('errMessage');
      names.sort();
      s = s.replace(m[0], `import { ${names.join(', ')} } from '${m[2]}';`);
    }
  }

  const count = (before.match(RE_IDENT) ?? []).length + (before.match(RE_LITERAL) ?? []).length + (before.match(RE_LITERAL_DQ) ?? []).length;
  total += count;
  touchedFiles++;
  if (WRITE) writeFileSync(file, s);
  else console.log(`${count}\t${relative(ROOT, file)}`);
}

// What the codemod deliberately did not touch, for the report.
for (const file of walk(SRC)) {
  const s = readFileSync(file, 'utf8');
  const remaining = (s.match(/instanceof Error \?/g) ?? []).length;
  if (remaining > 0) leftovers.push([relative(ROOT, file), remaining]);
}

console.log(`\n${WRITE ? 'rewrote' : 'would rewrite'} ${total} sites across ${touchedFiles} files (src/, tests excluded)`);
console.log(`${leftovers.reduce((a, [, n]) => a + n, 0)} non-standard sites left in src/ across ${leftovers.length} files:`);
for (const [f, n] of leftovers.sort((a, b) => b[1] - a[1]).slice(0, 12)) console.log(`  ${n}\t${f}`);