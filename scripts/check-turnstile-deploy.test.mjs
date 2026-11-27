/** Tests for the Turnstile deploy guard (scripts/check-turnstile-deploy.mjs). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseSecretNames } from './check-turnstile-deploy.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'check-turnstile-deploy.mjs');

function run(names, env = {}) {
  const root = mkdtempSync(join(tmpdir(), 'turnstile-guard-'));
  const file = join(root, 'names.txt');
  writeFileSync(file, names);
  try {
    const res = spawnSync(process.execPath, [SCRIPT, '--secrets-file', file], {
      encoding: 'utf8',
      env: { ...process.env, ALLOW_KEYLESS_WRITES: '', ...env },
    });
    return { status: res.status, out: `${res.stdout}${res.stderr}` };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('parseSecretNames handles plain and table-formatted wrangler output', () => {
  assert.equal(parseSecretNames('TURNSTILE_SECRET\nOTHER_KEY\n').has('TURNSTILE_SECRET'), true);
  assert.equal(
    parseSecretNames('Secret name              Type       Created\n TURNSTILE_SECRET        secret     2026-01-01\n').has(
      'TURNSTILE_SECRET'
    ),
    true
  );
  assert.equal(parseSecretNames('TURNSTILE_SITE_KEY\n').has('TURNSTILE_SECRET'), false);
});

test('passes when the gate secret is present', () => {
  const res = run('TURNSTILE_SECRET\nTURNSTILE_SITE_KEY\n');
  assert.equal(res.status, 0);
  assert.match(res.out, /gate is enabled/);
});

test('fails closed when the gate is off and no acceptance is recorded', () => {
  const res = run('CLOUDFLARE_API_TOKEN\n');
  assert.equal(res.status, 1);
  assert.match(res.out, /::error::/);
  assert.match(res.out, /wrangler secret put TURNSTILE_SECRET/);
});

test('warns but passes when keyless writes were explicitly accepted', () => {
  const res = run('CLOUDFLARE_API_TOKEN\n', { ALLOW_KEYLESS_WRITES: '1' });
  assert.equal(res.status, 0);
  assert.match(res.out, /::warning::/);
  assert.match(res.out, /Accepted via ALLOW_KEYLESS_WRITES=1/);
});
