#!/usr/bin/env node
/**
 * Run coverage on the root vitest suite and report the protected-surface
 * coverage (the libs and modules that are the platform's engineering
 * surface, not the page components or generated content).
 *
 * Usage: node scripts/check-coverage.mjs
 *
 * Wired into CI as a separate job. The job fails the build if any
 * protected surface drops below its threshold — this catches regressions
 * in the parts of the codebase that actually carry logic.
 */
import { execSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
// This file is ESM, so the bare `require` identifier does not exist — the
// old `require.resolve(...)` threw a ReferenceError that the catch below
// swallowed, so `coverageAvailable()` always answered false and the
// "protected surfaces" gate silently degraded to a test-file-existence
// check. createRequire gives a real resolver in an ESM module.
const require = createRequire(import.meta.url);

// Protected surfaces: per-module minimum coverage (lines %). Bumping
// any of these is a deliberate decision — easier to ratchet up than
// down. The set is intentionally small; the global threshold in
// vitest.config.ts catches the rest.
// Protected surfaces: per-module minimum coverage (lines %). Bumping
// any of these is a deliberate decision — easier to ratchet up than
// down. The set is intentionally small; the global threshold in
// vitest.config.ts catches the rest.
//
// To add a new entry: write a *.test.ts next to the file first, run
// `npm run test:coverage` to measure, then add the entry with a min
// slightly below the measured value so a regression is caught but
// existing code isn't blocked.
const PROTECTED = [
  { path: 'src/lib/dfir/rule-convert/', min: 70 },
  { path: 'src/lib/dfir/cve-priority.ts', min: 60 },
  { path: 'src/lib/dfir/encode.ts', min: 50 },
  { path: 'src/lib/dfir/decode.ts', min: 50 },
  { path: 'src/lib/dfir/osint-pivots.ts', min: 50 },
  { path: 'src/lib/social-parts.ts', min: 60 },
  { path: 'src/lib/back-link.ts', min: 50 },
];

// Tracked surfaces that don't have tests yet — surfaced in CI output
// as a hint to add coverage. They don't fail the build.
const TRACKED = [
  'src/lib/dfir/ioc-detect.ts',
  'src/lib/dfir/identity-lookup.ts',
  'src/lib/sanitize-html.ts',
  'src/lib/sanitize-url.ts',
  'src/lib/features.ts',
];

function coverageAvailable() {
  try {
    require.resolve('@vitest/coverage-v8', { paths: [ROOT] });
    return true;
  } catch {
    return false;
  }
}

function runCoverage() {
  // The COVERAGE reporter is what matters here, not the test reporter.
  // `--reporter=json` overrides the *test* reporter and writes a test-run
  // dump to coverage-results.json; the per-file line coverage the gate
  // reads comes from the `json-summary` COVERAGE reporter, which writes
  // coverage/coverage-summary.json.
  try {
    execSync(
      'npx vitest run --coverage --coverage.reporter=json-summary --coverage.reportsDirectory=coverage',
      {
        cwd: ROOT,
        stdio: 'inherit',
      }
    );
  } catch (err) {
    console.error('vitest coverage run failed (see output above)');
    process.exit(1);
  }
}

function readSummary() {
  const coveragePath = join(ROOT, 'coverage', 'coverage-summary.json');
  if (!existsSync(coveragePath)) {
    console.error('coverage-summary.json not found at', coveragePath);
    process.exit(1);
  }
  return JSON.parse(readFileSync(coveragePath, 'utf8'));
}

function main() {
  if (!coverageAvailable()) {
    console.log('=== Protected-surface test existence (coverage provider not installed) ===\n');
    let missing = 0;
    for (const target of PROTECTED) {
      const base = target.path.replace(/\/$/, '').replace(/\.ts$/, '');
      const candidates = [
        join(ROOT, base + '.test.ts'),
        join(ROOT, base + '.test.tsx'),
        join(ROOT, base, 'index.test.ts'),
      ];
      const found = candidates.some((p) => existsSync(p));
      const mark = found ? '✓' : '✗';
      if (!found) missing++;
      console.log(`  ${mark} ${target.path}  (${found ? 'has tests' : 'NO tests'})`);
    }
    if (missing > 0) {
      console.error(`\n${missing} protected surface(s) have no test file. Install @vitest/coverage-v8 for full coverage reporting.`);
      process.exit(1);
    }
    console.log('\nAll protected surfaces have at least one test file. Install @vitest/coverage-v8 for line coverage.');
    return;
  }
  runCoverage();
  const summary = readSummary();
  // v8 provider keys: path -> { lines, branches, functions, statements, ... }
  const rows = Object.entries(summary).filter(([k]) => k !== 'total').map(([path, v]) => ({ path, ...v }));

  console.log('\n=== Protected-surface coverage ===\n');
  let failed = 0;
  for (const target of PROTECTED) {
    // Find the row that best matches the prefix.
    const matching = rows.filter((r) => r.path.endsWith(target.path) || r.path.includes(target.path));
    if (matching.length === 0) {
      console.log(`  ${target.path.padEnd(40)} (no coverage data — file may not be exercised yet)`);
      continue;
    }
    const total = matching.reduce((acc, r) => ({
      lines: acc.lines + r.lines.pct,
      statements: acc.statements + r.statements.pct,
    }), { lines: 0, statements: 0 });
    const avgLines = total.lines / matching.length;
    const avgStmts = total.statements / matching.length;
    const ok = avgLines >= target.min;
    if (!ok) failed++;
    const mark = ok ? '\u2713' : '\u2717';
    console.log(`  ${mark} ${target.path.padEnd(40)} lines ${avgLines.toFixed(1)}% (min ${target.min}%)  ·  ${matching.length} file(s)`);
  }

  if (failed > 0) {
    console.error(`\n${failed} protected surface(s) below threshold.`);
    process.exit(1);
  }
  console.log('\nAll protected surfaces meet their coverage thresholds.');
}

main();
