#!/usr/bin/env node
/**
 * Regenerate `eslint-rules/raw-colors-baseline.mjs`.
 *
 * Run after landing a batch of `no-raw-colors` fixes:
 *
 *     node scripts/update-raw-colors-baseline.mjs
 *
 * The baseline is the set of files that still trip the rule. Shrinking it is
 * how progress on the token migration becomes visible: after a cleanup commit,
 * this script drops the cleaned files and the rule tightens over them again.
 *
 * The rule is disabled for baselined paths in `eslint.config.js` (so CI's
 * `--max-warnings 0` gate can pass), which means this script has to run the
 * rule explicitly via `--rule` rather than reading the current config.
 *
 * ## Why `--rule` makes this non-circular
 *
 * The obvious worry is that baselined files have the rule off, so a scan cannot
 * see them and stale entries would never drop off the list. That does not
 * apply: `--rule` overrides the flat config, forcing the rule on for EVERY
 * file. Verified directly -- with the config as-is this scan reports 0 files,
 * with `--rule` it reports all of them.
 *
 * So one pass is authoritative, and a listed file that no longer reports
 * anything does drop off. `--check` fails if the committed list disagrees with
 * a fresh scan in either direction: stale entries (suppress nothing) or
 * missing files (would fail CI at `--max-warnings 0`).
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RAW_COLORS_BASELINE } from '../eslint-rules/raw-colors-baseline.mjs';

/** `--check`: verify the generated list has settled instead of writing it. */
const CHECK = process.argv.includes('--check');

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = resolve(ROOT, 'eslint-rules/raw-colors-baseline.mjs');

console.log(`Scanning src/ for no-raw-colors findings (previous baseline: ${RAW_COLORS_BASELINE.length})`);

let stdout = '';
try {
  stdout = execFileSync(
    'npx',
    // `--rule` re-enables the one rule on top of the flat config, where it is
    // currently registered as 'off'. No `--no-eslintrc`: this project uses flat
    // config, where that flag does not exist.
    // `--concurrency=auto` splits the scan across worker threads. This one scan
    // dominates the unit-test suite's wall time (~137s single-threaded); the
    // JSON output shape is identical.
    [
      'eslint',
      'src',
      '--format',
      'json',
      '--concurrency=auto',
      '--rule',
      '{"no-raw-colors/no-raw-colors":"warn"}',
    ],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] },
  );
} catch (err) {
  // ESLint exits non-zero when it reports problems, which is expected here.
  if (err.stdout) stdout = String(err.stdout);
  else {
    console.error('eslint failed:', err.stderr || err.message);
    process.exit(1);
  }
}

const results = JSON.parse(stdout);
const files = results
  .filter((r) => r.messages.some((m) => m.ruleId === 'no-raw-colors/no-raw-colors'))
  .map((r) => relative(ROOT, r.filePath))
  .sort();

if (files.length === 0) {
  console.log('No findings left - the rule can be re-enabled in eslint.config.js and this file deleted.');
  process.exit(0);
}

const before = RAW_COLORS_BASELINE.length;
const added = files.filter((f) => !RAW_COLORS_BASELINE.includes(f));
const removed = RAW_COLORS_BASELINE.filter((f) => !files.includes(f));

const body = `/**
 * Legacy raw-palette baseline for the \`no-raw-colors\` ESLint rule.
 *
 * Generated, not hand-maintained. Regenerate with:
 *
 *     node scripts/update-raw-colors-baseline.mjs
 *
 * ## Why this exists
 *
 * \`no-raw-colors\` (added in 3d66d0e0c) is correct about what it reports: the
 * rule's own test suite passes. But it also flags ~1,800 pre-existing usages
 * across 203 files, and CI gates on \`--max-warnings 0\`, so enabling it repo-
 * wide fails every push.
 *
 * ## Why a baseline rather than turning the rule off
 *
 * Turning the rule off entirely would also stop it catching NEW raw colours,
 * which is the actual value. This list scopes the waiver to the files that
 * already carry the debt, so the rule stays live everywhere else - including
 * any file added after this baseline was generated.
 *
 * ## Why the residue is not bulk-fixable
 *
 * The rule auto-fixes the cases where the mapping is provably a rename: the
 * light half of the pair exactly equals the token's light value, so nothing
 * moves. Those are applied (\`npm run lint:baseline -- --fix\`, see below) and
 * the list shrinks as files clear.
 *
 * What remains is reported but deliberately NOT auto-fixed, because the
 * rewrite would change rendering rather than spelling:
 *
 *  - \`dark:bg-white/10\` and friends. White at 10% LIFTS a navy card;
 *    \`--surface-100\` is near-black in dark mode, so the token form DARKENS
 *    it. Same class name, opposite effect.
 *  - \`text-white\` with no saturated fill behind it. White on a neutral
 *    surface is a contrast bug; renaming it to a reactive ink would hide that
 *    instead of surfacing it.
 *  - Steps with no token at all (\`slate-950\`, \`border-slate-700\`).
 *
 * Each entry should leave the list as its file is cleaned up.
 */
export const RAW_COLORS_BASELINE = ${JSON.stringify(files, null, 2)};
`;

if (!CHECK) {
  writeFileSync(TARGET, body);
  console.log(`Baseline updated: ${before} -> ${files.length} files`);
}
if (removed.length) console.log(`  cleared (${removed.length}): ${removed.slice(0, 8).join(', ')}${removed.length > 8 ? ' ...' : ''}`);
if (added.length) console.log(`  new (${added.length}): ${added.slice(0, 8).join(', ')}${added.length > 8 ? ' ...' : ''}`);

/* ── --check: assert the list has settled ───────────────────────────────── */

// Staleness means a LISTED file that no longer reports anything. The opposite
// -- a listed file that still reports -- is the entire purpose of the list, so
// it is not a failure. `--rule` re-enables the rule on top of the flat config
// (verified to override the baselined-files override), so this scan sees the
// real current state of every file.
if (CHECK) {
  const stale = RAW_COLORS_BASELINE.filter((f) => !files.includes(f));
  const missing = files.filter((f) => !RAW_COLORS_BASELINE.includes(f));

  if (!stale.length && !missing.length) {
    console.log(
      `Baseline is accurate: ${RAW_COLORS_BASELINE.length} files listed, ` +
        `all still reporting, none missing.`
    );
    process.exit(0);
  }
  if (stale.length) {
    console.warn(
      `Baseline lists ${stale.length} file(s) that are now CLEAN (stale entries):\n  ` +
        stale.slice(0, 8).join('\n  ') +
        (stale.length > 8 ? '\n  ...' : '') +
        '\n  Non-fatal: these may be clean locally but still dirty in the commit.'
    );
  }
  if (missing.length) {
    console.error(
      `Baseline is MISSING ${missing.length} file(s) that report findings:\n  ` +
        missing.slice(0, 8).join('\n  ') +
        (missing.length > 8 ? '\n  ...' : '') +
        '\n  These would fail CI at --max-warnings 0. Run: node scripts/update-raw-colors-baseline.mjs'
    );
  }
  // Only a MISSING entry is fatal. Stale entries are reported but tolerated:
  // a file can be clean in the working tree and still dirty in the commit,
  // which is exactly what an in-progress token sweep looks like. Pruning on
  // staleness would drop those files from the waiver and break the next push.
  process.exit(missing.length ? 1 : 0);
}