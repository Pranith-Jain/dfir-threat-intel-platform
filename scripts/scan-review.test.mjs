/**
 * Tests for the diff-scoped review scanner (scripts/scan-review.mjs).
 *
 * The scanner is only useful if its findings are right. A scanner that fires on
 * everything trains reviewers to skim past it, which is worse than having no
 * scanner — so the negative cases below matter as much as the positive ones:
 * each one is a shape a careless implementation reports wrongly.
 *
 * Every fixture writes a real file and a real diff, so the tests exercise the
 * same path the tool runs in CI, including the on-disk lookups (concurrentMap
 * detection, test-file existence) that a pure-function test would miss.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, 'scan-review.mjs');

/**
 * Build a throwaway git repo with an added file, then scan the diff.
 * `files` maps repo-relative path → content.
 */
function scanDiff(files, opts = {}) {
  const root = mkdtempSync(join(tmpdir(), 'scan-review-'));
  const run = (cmd, args) =>
    execFileSync(cmd, args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    run('git', ['init', '-q', '-b', 'main']);
    run('git', ['config', 'user.email', 't@example.com']);
    run('git', ['config', 'user.name', 't']);
    writeFileSync(join(root, '.gitignore'), 'node_modules\n');
    writeFileSync(join(root, 'package.json'), '{"name":"x"}\n');
    // Seed support files the scanner consults.
    for (const [p, c] of Object.entries(opts.seed ?? {})) {
      const full = join(root, p);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, c);
    }
    run('git', ['add', '-A']);
    run('git', ['commit', '-qm', 'base']);

    // The "branch" commit adds the files under test.
    for (const [p, c] of Object.entries(files)) {
      const full = join(root, p);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, c);
    }
    run('git', ['add', '-A']);
    run('git', ['commit', '-qm', 'change']);
    run('git', ['branch', '-f', 'base-ref', 'HEAD~1']);

    let stdout = '';
    let code = 0;
    try {
      stdout = execFileSync(process.execPath, [SCANNER, '--range=base-ref...HEAD'], {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      code = err.status;
      stdout = err.stdout ?? '';
    }
    return { code, stdout };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ── Must flag ────────────────────────────────────────────────────────────

test('flags an unguarded compare against a token-shaped name', () => {
  const { code, stdout } = scanDiff({
    'api/src/lib/x.ts': `export function check(a: string, b: string) {\n  return a === b;\n}\n`,
  });
  // `b` is not token-shaped, so this must NOT fire — see the negative test below.
  assert.equal(code, 0);
  assert.match(stdout, /clean/);
});

test('flags === against a token variable', () => {
  const { code, stdout } = scanDiff({
    'api/src/lib/x.ts': `export function check(presented: string) {\n  const token = 'abc';\n  return presented === token;\n}\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /unguarded-secret-compare/);
});

test('does not flag safeEqual', () => {
  const { code } = scanDiff({
    'api/src/lib/x.ts': `export function check(presented: string, token: string) {\n  return safeEqual(presented, token);\n}\n`,
  });
  assert.equal(code, 0);
});

test('flags a CSP wildcard source', () => {
  const { code, stdout } = scanDiff({
    'worker/csp.ts': `const policy = "default-src 'self'";\nconst loose = "script-src *";\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /csp-widening/);
});

test('flags unsafe-inline in a policy', () => {
  const { code, stdout } = scanDiff({
    'worker/csp.ts': `const policy = "script-src 'self' 'unsafe-inline'";\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /csp-widening/);
});

test('flags a hardcoded credential literal but not a placeholder', () => {
  const hit = scanDiff({
    'api/src/lib/x.ts': `const ADMIN_TOKEN = "9f3ka0jsdlfkajs0234";\n`,
  });
  assert.equal(hit.code, 1);
  assert.match(hit.stdout, /hardcoded-secret-literal/);

  const miss = scanDiff({
    'api/src/lib/x.ts': `const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? 'placeholder';\n`,
  });
  assert.equal(miss.code, 0);
});

test('flags an unauthenticated mutation route', () => {
  const { code, stdout } = scanDiff({
    'api/src/routes/thing.ts': `import { Hono } from 'hono';\nexport const r = new Hono();\nr.post('/thing', (c) => c.json({ ok: true }));\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /unguarded-mutation-route/);
});

test('does not flag a mutation route in a file with an auth gate', () => {
  const { code } = scanDiff({
    'api/src/routes/thing.ts': `import { Hono } from 'hono';\nimport { requireAdmin } from '../lib/admin-auth';\nexport const r = new Hono();\nr.post('/thing', (c) => c.json({ ok: true }));\n`,
  });
  assert.equal(code, 0);
});

test('flags interpolated SQL without a bound placeholder', () => {
  const { code, stdout } = scanDiff({
    'api/src/routes/thing.ts': `export async function go(db: D1Database, name: string) {\n  return db.prepare(\`SELECT * FROM t WHERE n = \${name}\`);\n}\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /interpolated-sql/);
});

test('does not flag interpolated SQL using an all-caps constant', () => {
  const { code } = scanDiff({
    'api/src/routes/thing.ts': `const TABLE_NAME = 't';\nexport async function go(db: D1Database) {\n  return db.prepare(\`SELECT * FROM \${TABLE_NAME}\`);\n}\n`,
  });
  assert.equal(code, 0);
});

test('flags dangerouslySetInnerHTML without a sanitiser', () => {
  const { code, stdout } = scanDiff({
    'src/pages/X.tsx': `export function X({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /html-injection-sink/);
});

test('does not flag dangerouslySetInnerHTML fed through DOMPurify', () => {
  const { code } = scanDiff({
    'src/pages/X.tsx': `export function X({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;\n}\n`,
  });
  assert.equal(code, 0);
});

test('flags console.log added under api/ or worker/', () => {
  const { code, stdout } = scanDiff({
    'api/src/lib/x.ts': `export function go() {\n  console.log('here');\n}\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /console-noise/);
});

test('does not flag console.error, which is the sanctioned form', () => {
  const { code } = scanDiff({
    'api/src/lib/x.ts': `export function go() {\n  console.error('failed');\n}\n`,
  });
  assert.equal(code, 0);
});

// ── The loop check's real failure mode ───────────────────────────────────
// The first implementation scanned FORWARD from the await for a `for`, so two
// setup awaits sitting above a loop were reported as serial awaits inside it.

test('does not flag awaits that sit ABOVE a loop', () => {
  const { code, stdout } = scanDiff({
    'api/src/lib/x.ts': `export async function go(mod: M, srcs: S[]) {\n  const a = await loadOne(mod);\n  const b = await loadTwo(mod);\n  const hosts = new Set<string>();\n  for (const s of srcs) {\n    hosts.add(s.host);\n  }\n  return hosts;\n}\n`,
  });
  assert.equal(code, 0, 'setup awaits above a loop are not serial awaits');
  assert.doesNotMatch(stdout, /serial-await-in-loop/);
});

test('flags a genuine await inside a loop body', () => {
  const { code, stdout } = scanDiff({
    'api/src/lib/x.ts': `export async function go(srcs: S[]) {\n  const out = [];\n  for (const s of srcs) {\n    const r = await fetchOne(s);\n    out.push(r);\n  }\n  return out;\n}\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /serial-await-in-loop/);
});

test('stays silent on a loop when concurrentMap is already used', () => {
  const { code, stdout } = scanDiff({
    'api/src/lib/x.ts': `import { concurrentMap } from './concurrent-map';\nexport async function go(srcs: S[]) {\n  const out = [];\n  for (const s of srcs) {\n    const r = await fetchOne(s);\n    out.push(r);\n  }\n  return concurrentMap(srcs, fetchOne);\n}\n`,
  });
  assert.equal(code, 0);
  assert.doesNotMatch(stdout, /serial-await-in-loop/);
});

// ── The swallowed-error check's real failure mode ────────────────────────
// A catch whose body is an explanatory comment on the FOLLOWING line is a
// deliberate, documented swallow. Only an unexplained empty one is a finding.

test('does not flag a catch whose body is an explanatory comment', () => {
  const { code, stdout } = scanDiff({
    'api/src/routes/thing.ts': `export async function go(items: S[]) {\n  const out = new Set<string>();\n  for (const s of items) {\n    try {\n      out.add(new URL(s).host);\n    } catch {\n      // A malformed entry cannot be a valid target anyway.\n    }\n  }\n  return out;\n}\n`,
  });
  assert.equal(code, 0);
  assert.doesNotMatch(stdout, /swallowed-error/);
});

test('flags a genuinely empty catch with no comment', () => {
  const { code, stdout } = scanDiff({
    'api/src/routes/thing.ts': `export async function go(items: S[]) {\n  const out = new Set<string>();\n  for (const s of items) {\n    try {\n      out.add(new URL(s).host);\n    } catch {}\n  }\n  return out;\n}\n`,
  });
  assert.equal(code, 1);
  assert.match(stdout, /swallowed-error/);
});

test('does not flag a catch that logs', () => {
  const { code } = scanDiff({
    'api/src/routes/thing.ts': `export async function go() {\n  try {\n    await work();\n  } catch (e) {\n    logError('work failed', e);\n  }\n}\n`,
  });
  assert.equal(code, 0);
});

// ── Diff scoping ─────────────────────────────────────────────────────────

test('ignores REMOVED lines — a security fix must not read as a new finding', () => {
  const root = mkdtempSync(join(tmpdir(), 'scan-review-del-'));
  const run = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: 'ignore' });
  const write = (rel, content) => {
    const full = join(root, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  };
  try {
    run(['init', '-q', '-b', 'main']);
    run(['config', 'user.email', 't@e.com']);
    run(['config', 'user.name', 't']);
    write('package.json', '{}\n');
    // Base contains exactly the vulnerable code a fix would replace.
    write(
      'api/src/routes/thing.ts',
      `export async function go(c: C) {\n  return 1;\n}\n`
    );
    run(['add', '-A']);
    run(['commit', '-qm', 'base']);
    run(['branch', '-f', 'base-ref', 'HEAD']);

    // The fix ADDES the guarded fetch; the vulnerable bare fetch is never
    // present in the added set, so nothing may be reported for it.
    write(
      'api/src/routes/thing.ts',
      `export async function go(c: C) {\n  const url = c.req.query('url');\n  return pinnedFetchFollow(url);\n}\n`
    );
    run(['add', '-A']);
    run(['commit', '-qm', 'fix']);

    const out = execFileSync(process.execPath, [SCANNER, '--range=base-ref...HEAD'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.match(out, /clean/);
    assert.doesNotMatch(out, /unguarded/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a removed unsafe construct is not reported as an added finding', () => {
  const root = mkdtempSync(join(tmpdir(), 'scan-review-del2-'));
  const run = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: 'ignore' });
  const write = (rel, content) => {
    const full = join(root, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  };
  try {
    run(['init', '-q', '-b', 'main']);
    run(['config', 'user.email', 't@e.com']);
    run(['config', 'user.name', 't']);
    write('package.json', '{}\n');
    write('worker/csp.ts', `const p = "script-src 'self'";\n`);
    run(['add', '-A']);
    run(['commit', '-qm', 'base']);
    run(['branch', '-f', 'base-ref', 'HEAD']);

    // The change REMOVES the permissive policy — the wildcard never appears on
    // an added line, so the widening check must stay quiet.
    write('worker/csp.ts', `const p = "script-src 'none'";\n`);
    run(['add', '-A']);
    run(['commit', '-qm', 'tighten']);

    const out = execFileSync(process.execPath, [SCANNER, '--range=base-ref...HEAD'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.doesNotMatch(out, /csp-widening/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('clean output states what it does not cover', () => {
  const { stdout } = scanDiff({ 'api/src/lib/x.ts': `export const a = 1;\n` });
  assert.match(stdout, /Clean means the checked patterns are absent/);
  assert.match(stdout, /judgement calls a regex cannot decide/);
});

test('an unresolvable range exits 2 rather than reporting false clean', () => {
  const root = mkdtempSync(join(tmpdir(), 'scan-review-bad-'));
  try {
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: root, stdio: 'ignore' });
    let code = 0;
    try {
      execFileSync(process.execPath, [SCANNER, '--range=nope...alsonope'], {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      code = err.status;
    }
    assert.equal(code, 2, 'a bad range is a scanner error, not a clean pass');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});