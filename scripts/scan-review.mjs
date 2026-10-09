#!/usr/bin/env node
/**
 * Diff-scoped code-review scanner.
 *
 * WHAT THIS IS FOR: docs/loops/security-review-the-diff.md and
 * docs/loops/pr-self-review.md describe two review loops that are currently run
 * by hand. Both share the same blind spot — they depend on a reviewer (human or
 * agent) actually remembering to check a fixed list of categories on a large
 * diff, where the interesting change is usually a small fraction of the lines.
 * This script mechanises the deterministic subset of that list so the human
 * attention goes to the judgement calls instead of the checklist.
 *
 * SCOPE: only ADDED lines in the diff. Reviewing the whole tree on every PR is
 * what makes review get skipped; a diff scanner has to stay diff-scoped or it
 * just reproduces the daily scanner (scripts/scan-ssrf.mjs, scan-gates.mjs) in
 * a place where its output is not actionable.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: it does not claim to find security bugs.
 * Every check here is a pattern with a known false-positive mode, which is why
 * each finding carries a reason and a category rather than a verdict. The
 * authoritative version of "is this diff safe" is still a reviewer's judgement
 * over categories a regex cannot model — see the "not covered" list at the
 * bottom, which is the honest boundary of this tool.
 *
 * Exit codes: 0 no findings, 1 findings present, 2 scanner error.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

// ── Diff acquisition ─────────────────────────────────────────────────────

/**
 * Resolve the diff to review.
 *
 * `origin/main...HEAD` (three-dot) rather than two-dot: the three-dot form
 * diffs against the merge base, so a branch that has fallen behind main is not
 * reviewed against main's newer changes and produce phantom findings.
 */
function diffRange() {
  const explicit = process.argv.find((a) => a.startsWith('--range='));
  if (explicit) return explicit.slice('--range='.length);
  return 'origin/main...HEAD';
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

let range;
try {
  range = diffRange();
  git(['rev-parse', '--verify', range.split('...')[0]]);
} catch {
  console.error(`scan-review: cannot resolve diff range "${range}" — fetch origin or pass --range=<a>...<b>`);
  process.exit(2);
}

/**
 * Parse a unified diff into per-file added/removed line records.
 *
 * Only '+' and '-' lines are kept, and only additions are reported: a REMOVED
 * line cannot introduce a finding, and counting it would make every security
 * fix look like a new problem.
 */
function parseDiff(text) {
  const files = [];
  let file = null;
  for (const line of text.split('\n')) {
    const hdr = /^\+\+\+ b\/(.+)$/.exec(line);
    if (hdr) {
      file = { path: hdr[1], added: [], removed: 0 };
      files.push(file);
      continue;
    }
    if (!file) continue;
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('@@')) {
      const m = /@@ -\d+(?:,\d+)? \+(\d+)/.exec(line);
      file.lineNo = m ? Number(m[1]) : 1;
      continue;
    }
    if (line.startsWith('+')) {
      file.added.push({ no: file.lineNo ?? 0, text: line.slice(1) });
      file.lineNo = (file.lineNo ?? 0) + 1;
    } else if (line.startsWith('-')) {
      file.removed += 1;
    } else {
      file.lineNo = (file.lineNo ?? 0) + 1;
    }
  }
  return files;
}

let files;
try {
  files = parseDiff(git(['diff', '--unified=0', range]));
} catch (err) {
  console.error(`scan-review: git diff failed: ${err.message}`);
  process.exit(2);
}

// ── Findings ─────────────────────────────────────────────────────────────

const findings = [];
function add(category, severity, file, line, why) {
  findings.push({ category, severity, file, line, why });
}

/** True when the line is a comment, a doc line, or inside a string literal. */
function isProse(text) {
  const t = text.trim();
  return (
    t.startsWith('//') ||
    t.startsWith('*') ||
    t.startsWith('/*') ||
    t.startsWith('#') ||
    t.startsWith('<!--')
  );
}

// ── R1: unguarded secret compare ─────────────────────────────────────────
// The category from scanner E, but diff-scoped: a NEW `===` against a token is
// a review question, whereas the repo-wide grep could not tell a credential
// from a crypto asset symbol.

const TOKEN_IDENT = /\b(?:[A-Za-z_]*_?token|secret|password|api_?key)\b/i;
for (const f of files) {
  if (!/\.(ts|tsx)$/.test(f.path) || f.path.includes('.test.')) continue;
  for (const l of f.added) {
    if (isProse(l.text)) continue;
    const m = /[^=!<>](===|!==|==|!=)\s*([A-Za-z_][\w.]*)/.exec(l.text);
    if (!m) continue;
    if (!TOKEN_IDENT.test(m[2])) continue;
    // safeEqual() is the intended control.
    if (/safeEqual\s*\(/.test(l.text)) continue;
    add(
      'unguarded-secret-compare',
      'high',
      f.path,
      l.no,
      `\`${m[1]}\` against \`${m[2]}\`. If that is a credential or bearer capability, use safeEqual() from api/src/lib/safe-equal.ts — \`===\` leaks the secret a byte at a time. If it is not a secret, say so in the review.`
    );
  }
}

// ── R2: raw secret literal ───────────────────────────────────────────────
// A hardcoded value that looks like a credential. The gitleaks CI step already
// catches committed keys; this catches the subtler case of a plausible-looking
// placeholder that is actually live, and of a default that silently works.

for (const f of files) {
  if (!/\.(ts|tsx|mjs|js)$/.test(f.path) || f.path.includes('.test.')) continue;
  for (const l of f.added) {
    if (isProse(l.text)) continue;
    const m = /(?:TOKEN|SECRET|API_KEY|PASSWORD|PRIVATE_KEY)\w*\s*[:=]\s*['"]([^'"]{16,})['"]/.exec(l.text);
    if (!m) continue;
    const value = m[1];
    if (/^(process\.env|import\.meta\.env|\$|<|\$\{)/.test(value)) continue;
    if (/(example|placeholder|changeme|your-|xxx|test|dummy|fake|redacted)/i.test(value)) continue;
    add(
      'hardcoded-secret-literal',
      'high',
      f.path,
      l.no,
      `A literal assigned to a credential-shaped name. If this is live, it is in git history now and must be rotated regardless of what this review concludes.`
    );
  }
}

// ── R3: CSP widening ─────────────────────────────────────────────────────
// The first category docs/loops/security-review-the-diff.md names, and the one
// most likely to be changed "just to make something work".

for (const f of files) {
  for (const l of f.added) {
    const t = l.text;
    if (/unsafe-inline|unsafe-eval|unsafe-hashes/.test(t) && !/^\s*(\*|\/\/)/.test(t.trim())) {
      add(
        'csp-widening',
        'high',
        f.path,
        l.no,
        `\`${t.trim().slice(0, 60)}\` added to a policy string. CSP directives are not style preferences — each of these removes a layer the other checks depend on.`
      );
    }
    // A wildcard source is only as safe as what it admits. Match the `*`
    // INSIDE the quoted policy string — `script-src *` puts the asterisk before
    // the closing quote, so anchoring on quote-then-asterisk misses it.
    if (/['"][^'"]*\*[^'"]*['"]/.test(t) && /(content-security-policy|script-src|default-src|connect-src|img-src)/i.test(t)) {
      add(
        'csp-widening',
        'high',
        f.path,
        l.no,
        `Wildcard source added to a CSP directive. Confirm this is scoped to a non-executable directive; \`script-src *\` defeats the policy entirely.`
      );
    }
  }
}

// ── R4: HTML injection sink ───────────────────────────────────────────────

for (const f of files) {
  if (!/\.tsx$/.test(f.path)) continue;
  for (const l of f.added) {
    if (!/dangerouslySetInnerHTML/.test(l.text) || isProse(l.text)) continue;
    // A sanitiser on the same line, or a known-safe producer, is the accepted shape.
    if (/DOMPurify|sanitize|renderMarkdown|safeHtml|proseHtml/.test(l.text)) continue;
    add(
      'html-injection-sink',
      'high',
      f.path,
      l.no,
      'dangerouslySetInnerHTML added without a sanitiser on the same line. Confirm the interpolated value came from DOMPurify or renderMarkdown — the scanner cannot trace the expression.'
    );
  }
}

// ── R5: interpolated SQL ─────────────────────────────────────────────────

for (const f of files) {
  if (!/\.ts$/.test(f.path) || !f.path.startsWith('api/')) continue;
  for (const l of f.added) {
    if (isProse(l.text)) continue;
    if (!/\.prepare\(`[^`]*\$\{/.test(l.text)) continue;
    // A bound placeholder in the same statement is the accepted shape.
    if (/\$\{[A-Z][A-Z0-9_]*\}/.test(l.text)) continue;
    if (/\$\{\w*(where|placeholder|clause|fragment|binds?)\w*\}/i.test(l.text)) continue;
    add(
      'interpolated-sql',
      'high',
      f.path,
      l.no,
      'Template-literal SQL added. Confirm every interpolated fragment is either an all-caps constant or built only from fixed literals, with user input reaching the database solely through .bind().'
    );
  }
}

// ── R6: unauthenticated state-changing route ─────────────────────────────

for (const f of files) {
  if (!f.path.startsWith('api/src/routes/') || !/\.ts$/.test(f.path) || f.path.includes('.test.')) continue;
  for (const l of f.added) {
    const m = /\.method\s*[:=]\s*['"]?(post|put|patch|delete)\b/i.exec(l.text) || /\.(post|put|patch|delete)\(\s*['"`]/.exec(l.text);
    if (!m) continue;
    // A gate in the same file is the accepted shape. csrf-guard.ts documents
    // that the same-origin exemption is forgeable, so its presence is a review
    // question rather than a clearance.
    const src = readFileSync(f.path, 'utf8');
    if (/requireAdmin|validateInternalToken|validateApiKey|requireApiKey|csrfGuard/.test(src)) continue;
    add(
      'unguarded-mutation-route',
      'high',
      f.path,
      l.no,
      `New ${m[1].toUpperCase()} route in a file with no auth gate. Either it needs requireAdmin/validateApiKey, or it needs a comment saying why it is intentionally public.`
    );
  }
}

// ── R7: serial await in a loop ───────────────────────────────────────────
// Named in docs/loops/ioc-subrequest-budget.md: Workers cap concurrent
// subrequests (~6, and 50 per invocation on the free plan), so a serial await
// in a loop over N upstreams is a latency and budget problem, not a style one.

for (const f of files) {
  if (!/\.(ts|tsx)$/.test(f.path) || f.path.includes('.test.')) continue;
  const src = existsSync(f.path) ? readFileSync(f.path, 'utf8') : '';
  const lines = src.split('\n');
  for (const l of f.added) {
    if (isProse(l.text)) continue;
    if (!/\bawait\b/.test(l.text)) continue;
    const indent = l.text.length - l.text.trimStart().length;
    // Scan BACKWARD for the enclosing loop. Scanning forward instead would
    // match a loop that comes after the await — e.g. two setup awaits above a
    // `for` — and report a serial await that is not in any loop body at all.
    for (let i = l.no - 2; i >= 0 && i >= l.no - 12; i -= 1) {
      const ctx = lines[i];
      if (!ctx) continue;
      const ctxIndent = ctx.length - ctx.trimStart().length;
      if (!/\b(?:for|while)\s*\(/.test(ctx)) continue;
      // The loop must enclose this line: shallower or equal indentation means
      // the await is after the loop closed, not inside its body.
      if (ctxIndent >= indent) break;
      // concurrentMap is the sanctioned bounded-concurrency helper.
      if (/concurrentMap/.test(src)) break;
      add(
        'serial-await-in-loop',
        'medium',
        f.path,
        l.no,
        'await inside a loop body. In Workers this serialises subrequests and burns wall-clock against the invocation limit; use concurrentMap() from api/src/lib/concurrent-map.ts for bounded concurrency.'
      );
      break;
    }
  }
}

// ── R8: swallowed error ──────────────────────────────────────────────────
// An empty catch hides a failure that a review would otherwise catch. The
// codebase convention is logError(); an empty block is the thing to notice.

// A `catch {}` written entirely on one line has its empty body on that same
// line, so the multi-line body scan below never sees it. Handle that shape
// separately rather than missing the most obvious swallow there is.
const INLINE_EMPTY_CATCH = /\bcatch\s*(\([^)]*\))?\s*\{\s*\}/;
for (const f of files) {
  if (!/\.(ts|tsx)$/.test(f.path)) continue;
  if (f.removed > 0 && !f.added.some((l) => /\bcatch\b/.test(l.text))) continue;
  const src = existsSync(f.path) ? readFileSync(f.path, 'utf8') : '';
  const fileLines = src.split('\n');
  for (const l of f.added) {
    if (isProse(l.text)) continue;
    if (!/\bcatch\b/.test(l.text)) continue;
    if (INLINE_EMPTY_CATCH.test(l.text)) {
      add(
        'swallowed-error',
        'low',
        f.path,
        l.no,
        'Empty catch block with no comment. If the swallow is intentional, the codebase convention is a one-line comment saying why — silence here hides a failure a reviewer would otherwise catch.'
      );
      continue;
    }
    // Read the catch BODY, not just the catch line: an explanatory comment or a
    // return/logError usually sits on the following lines, and a check that only
    // looks at the `catch {` token reports every deliberate error path.
    const body = fileLines.slice(l.no - 1, l.no + 4).join('\n');
    const meaningful = body
      .split('\n')
      .map((s) => s.trim())
      // Strip the catch line itself, then comments and blank lines.
      .slice(1)
      .filter((s) => s.length > 0 && !s.startsWith('//') && !s.startsWith('*') && !s.startsWith('/*'));
    if (meaningful.length === 0) {
      add(
        'swallowed-error',
        'low',
        f.path,
        l.no,
        'Catch block with an empty body and no comment. If the swallow is intentional, the codebase convention is a one-line comment saying why — silence here hides a failure a reviewer would otherwise catch.'
      );
      continue;
    }
    // A body that is only a comment is still an acknowledged swallow, which is
    // the accepted shape; only an unexplained one is worth reporting.
    if (/^\/\//.test(meaningful[0]) && meaningful.length === 1) continue;
  }
}

// ── R9: new console noise ────────────────────────────────────────────────

for (const f of files) {
  if (!/^(api\/src|worker)\//.test(f.path) || f.path.includes('.test.')) continue;
  for (const l of f.added) {
    if (isProse(l.text)) continue;
    if (!/console\.(log|debug|dir)\(/.test(l.text)) continue;
    add(
      'console-noise',
      'low',
      f.path,
      l.no,
      'console.log/debug in api or worker code. Use logError()/log() from api/src/lib/logger.ts so the line is structured and filterable.'
    );
  }
}

// ── R10: debt markers introduced ─────────────────────────────────────────

for (const f of files) {
  if (!/\.(ts|tsx|mjs|js)$/.test(f.path)) continue;
  for (const l of f.added) {
    const m = /\b(TODO|FIXME|HACK|XXX)\b/.exec(l.text);
    if (!m) continue;
    // Skip doc prose that merely names the markers (e.g. this file's own list).
    if (isProse(l.text) && !/@/.test(l.text.slice(0, 2))) continue;
    add(
      'debt-marker',
      'low',
      f.path,
      l.no,
      `\`${m[1]}\` added. Fine if it is a real follow-up, but it should be tracked — the repo's loop docs treat an untracked follow-up as a deferred finding.`
    );
  }
}

// ── R11: changed source with no test ─────────────────────────────────────
// Not "no test file exists" — that is true of most of this repo by design. The
// narrower question: did the diff change a file whose own test file exists but
// was not updated?

const changedPaths = new Set(files.map((f) => f.path));
for (const f of files) {
  if (!/\.(ts|tsx)$/.test(f.path) || f.path.includes('.test.')) continue;
  const base = f.path.replace(/\.(ts|tsx)$/, '');
  const candidates = [
    `${base}.test.ts`,
    `${base}.test.tsx`,
    base.replace(/^src\//, 'src/__tests__/'),
  ].filter((c) => c !== f.path);
  const hasTest = candidates.some((c) => existsSync(c));
  if (!hasTest) continue;
  const testChanged = candidates.some((c) => changedPaths.has(c));
  if (!testChanged) {
    add(
      'test-not-updated',
      'medium',
      f.path,
      0,
      'This file has a test file but the diff did not touch it. If the behaviour changed, the test should change with it.'
    );
  }
}

// ── Report ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.file.localeCompare(b.file));

const addedTotal = files.reduce((n, f) => n + f.added.length, 0);

if (findings.length === 0) {
  console.log(`scan-review: clean — ${files.length} file(s), ${addedTotal} added line(s) reviewed in ${range}`);
  console.log('');
  console.log('Clean means the checked patterns are absent, not that the diff is safe.');
  console.log('The categories below are judgement calls a regex cannot decide — read them yourself:');
  console.log('  · untrusted-input handling (uploads, IOC parsing, EXIF/QR)');
  console.log('  · D1 API-key lifecycle and the public MCP surface');
  console.log('  · whether a new gate is actually load-bearing (csrf-guard exempts same-origin, which is forgeable)');
  console.log('  · whether a fix is correct at its source vs. suppressing a symptom');
  process.exit(0);
}

console.log(`scan-review: ${findings.length} finding(s) in ${range}\n`);
let current = null;
for (const f of findings) {
  const where = f.line > 0 ? `${f.file}:${f.line}` : f.file;
  if (f.category !== current) {
    current = f.category;
    console.log(`── ${current}`);
  }
  console.log(`  [${f.severity}] ${where}`);
  console.log(`      ${f.why}`);
}
console.log('');
console.log('These are patterns, not verdicts. A finding is a reason to look, not');
console.log('proof of a defect — dismiss it in review rather than editing the code to');
console.log('quiet the scanner.');
process.exit(1);