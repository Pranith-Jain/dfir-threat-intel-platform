#!/usr/bin/env node
/**
 * Correctness gates that the daily scan can run cheaply.
 *
 * These complement the grep checks in daily-bug-scan.yml. Each one here exists
 * because it either (a) catches a class of bug a grep cannot see, or (b) is a
 * cheap deterministic signal whose absence is genuinely informative. Checks
 * that produced pure noise on this repo were deliberately left out — see the
 * note at the bottom for the ones that were tried and dropped.
 *
 * Exit codes: 0 all clean, 1 at least one gate failed, 2 scanner error.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const WORKFLOWS = '.github/workflows';

const results = [];
function gate(id, title, fn) {
  try {
    const findings = fn();
    results.push({ id, title, findings });
  } catch (err) {
    results.push({ id, title, error: err.message });
  }
}

function walk(dir, filter) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full, filter));
    else if (filter(entry)) out.push(full);
  }
  return out;
}

// ── G1: dependency manifest / lockfile drift ─────────────────────────────
// A package.json entry with no lockfile counterpart makes `npm ci` fail, which
// takes down every CI job at once. Cheap to check, and it is exactly the kind
// of thing a merge wave introduces.

gate('G1', 'package.json / package-lock.json drift', () => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  const root = lock.packages?.[''] ?? {};
  const locked = { ...(root.dependencies ?? {}), ...(root.devDependencies ?? {}) };
  const declared = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  const missing = Object.keys(declared).filter((n) => !(n in locked));
  return missing.map((n) => `${n} (${declared[n]}) declared in package.json, absent from the lockfile root`);
});

// ── G2: every workflow declares a concurrency group ──────────────────────
// Two overlapping runs of a deploy or sync workflow race each other on the same
// D1/KV state. `concurrency` is the only thing preventing that, and omitting it
// is silent — the workflow still works right up until two runs overlap.

gate('G2', 'workflows missing a concurrency group', () => {
  const out = [];
  for (const f of readdirSync(WORKFLOWS)) {
    if (!f.endsWith('.yml') && !f.endsWith('.yaml')) continue;
    const src = readFileSync(join(WORKFLOWS, f), 'utf8');
    if (!/^concurrency:/m.test(src)) out.push(`${WORKFLOWS}/${f}`);
  }
  return out;
});

// ── G3: deploy/sync workflows pinned to a concurrency group that differs ──
// Catching `group: ${{ github.workflow }}` shared across workflows: two
// unrelated workflows would then cancel each other in progress.

gate('G3', 'workflow concurrency group collides with another workflow', () => {
  const groups = new Map();
  for (const f of readdirSync(WORKFLOWS)) {
    if (!/\.ya?ml$/.test(f)) continue;
    const src = readFileSync(join(WORKFLOWS, f), 'utf8');
    const m = /^concurrency:\s*\n\s*group:\s*(.+)$/m.exec(src);
    if (!m) continue;
    const expr = m[1].trim().replace(/^["']|["']$/g, '');
    // A group that interpolates only github.workflow is per-workflow, fine.
    if (/github\.workflow\s*\}\}?$/.test(expr) && !/github\.ref|ref/.test(expr)) continue;
    const list = groups.get(expr) ?? [];
    list.push(f);
    groups.set(expr, list);
  }
  const out = [];
  for (const [expr, files] of groups) {
    if (files.length > 1) out.push(`group "${expr}" shared by: ${files.join(', ')}`);
  }
  return out;
});

// ── G4: scheduled workflows pinned to a branch ───────────────────────────
// `schedule` runs from the default branch, but a workflow can still be left
// with a `branches:` filter that makes the schedule silently not run.

gate('G4', 'scheduled workflow with a push/pull_request branch filter', () => {
  const out = [];
  for (const f of readdirSync(WORKFLOWS)) {
    if (!/\.ya?ml$/.test(f)) continue;
    const src = readFileSync(join(WORKFLOWS, f), 'utf8');
    if (!/^\s*schedule:/m.test(src)) continue;
    if (/branches:\s*(?!$)/m.test(src) && !/schedule:[\s\S]*?branches:/.test(src)) {
      out.push(`${WORKFLOWS}/${f} has schedule: plus a branch filter`);
    }
  }
  return out;
});

// ── G5: knip config present but not wired into CI ────────────────────────
// An unused static-analysis config is a silent loss of coverage: someone tuned
// knip.json and believed dead code was being caught. This is a one-line check
// that catches a real, easy-to-miss state.

gate('G5', 'knip config present but knip is not run by any workflow', () => {
  if (!existsSync('knip.json') && !existsSync('.knip.json')) return [];
  const wired = readdirSync(WORKFLOWS)
    .filter((f) => /\.ya?ml$/.test(f))
    .some((f) => /\bknip\b/.test(readFileSync(join(WORKFLOWS, f), 'utf8')));
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  const inScripts = Object.values(pkg.scripts ?? {}).some((s) => /\bknip\b/.test(s));
  return wired || inScripts ? [] : ['knip.json exists but no workflow or npm script runs knip'];
});

// ── Report ───────────────────────────────────────────────────────────────

let failed = 0;
for (const r of results) {
  if (r.error) {
    console.log(`✗ [${r.id}] ${r.title} — scanner error: ${r.error}`);
    failed += 1;
    continue;
  }
  if (r.findings.length === 0) {
    console.log(`✅ [${r.id}] ${r.title}`);
  } else {
    console.log(`🔴 [${r.id}] ${r.title} — ${r.findings.length} finding(s)`);
    for (const f of r.findings.slice(0, 12)) console.log(`    ${f}`);
    if (r.findings.length > 12) console.log(`    … and ${r.findings.length - 12} more`);
    failed += 1;
  }
}

/*
 * Checks TRIED AND DELIBERATELY NOT SHIPPED — recorded so they are not
 * re-proposed, and because "we looked at this" is the useful part:
 *
 *   - "fetch() with no timeout"      → 513 raw hits. The codebase sets
 *     `signal: AbortSignal.timeout()` on a multiline init object, so a
 *     single-line grep cannot see it. Refining to multiline-aware parsing
 *     still left 16, and several are self-fetches through service bindings
 *     where a timeout is meaningless. Pure noise; the per-provider adapters
 *     already degrade on timeout.
 *   - "D1 .all() with no LIMIT"      → 118 hits. Real in principle, but the
 *     overwhelming majority are bounded in practice — a WHERE on a unique key,
 *     an aggregate with .first(), or a table with a fixed small row count
 *     (achievements, kill-chain steps). Making this precise needs schema
 *     knowledge a regex does not have: it would have to know which tables grow.
 *     Shipping 118 permanent reds would make the whole report noise and get the
 *     gates ignored, so it is left as a documented manual audit item rather
 *     than a gate. If it comes back, it needs a row-count oracle, not a grep.
 *   - "POST route parses a body with no zod nearby" → 18 hits, and the check
 *     could not tell a hand-rolled but correct validator from a genuinely
 *     unvalidated one (it only looked for the literal token `z.object`). A
 *     check that cannot separate those two is not worth a red daily.
 *   - "SQL string built from c.req.*" → 0 hits. Nothing interpolates a request
 *     value into a statement today. A check that never fires is not evidence;
 *     the retention identifier guard in api/src/lib/retention.ts is the real
 *     control there, and it has unit tests.
 *   - "Math.random() near a secret"  → 0 hits. No non-crypto randomness is
 *     used for tokens.
 *   - "@ts-ignore / @ts-expect-error" → 0. Zero debt. Cheap enough to keep in
 *     mind, but as a standalone gate it is a permanent green.
 *   - "TODO / FIXME / HACK"          → 17, all legitimate prose. Debt tracking
 *     is not a bug scanner's job.
 *
 * WHAT WAS KEPT, and why each is worth a permanent green:
 *   G1 — `npm ci` failing on merge takes down every CI job at once.
 *   G2 — two overlapping deploy/sync runs race on the same D1/KV state.
 *   G3 — a shared concurrency group makes unrelated workflows cancel each other.
 *   G4 — a branch filter that silently stops a schedule from ever running.
 *   G5 — a tuned analysis config that nothing runs is coverage nobody has.
 */

process.exit(failed > 0 ? 1 : 0);