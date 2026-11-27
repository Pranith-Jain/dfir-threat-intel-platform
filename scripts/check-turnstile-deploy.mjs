#!/usr/bin/env node
/**
 * Deploy-time guard for the Turnstile gate on shared-state writes.
 *
 * `api/src/lib/turnstile.ts` is deliberately opt-in: with no `TURNSTILE_SECRET`
 * on the Worker, keyless mutations on TURNSTILE_PREFIXES are allowed. That is
 * what keeps the public-by-design SPA working, but it means a deploy can ship
 * the *code* for the gate without ever enabling it. This guard makes that
 * posture an explicit, visible decision in the deploy pipeline.
 *
 * It reads only secret NAMES (never values) from `wrangler secret list`:
 *
 *   npx wrangler secret list | node scripts/check-turnstile-deploy.mjs
 *
 * Or, for a local/offline check, pass a file of names:
 *
 *   node scripts/check-turnstile-deploy.mjs --secrets-file /tmp/names.txt
 *
 * Exit codes:
 *   0  TURNSTILE_SECRET is present, or the operator explicitly accepted the
 *      keyless posture with ALLOW_KEYLESS_WRITES=1 (emits ::warning::).
 *   1  gate is off and no explicit acceptance was recorded (::error::).
 */
import { readFileSync } from 'node:fs';

export const SECRET_NAME = 'TURNSTILE_SECRET';

/** Parse secret names out of wrangler's plain or table-formatted output. */
export function parseSecretNames(text) {
  const names = new Set();
  for (const line of String(text ?? '').split('\n')) {
    for (const token of line.trim().split(/\s+/)) {
      if (token === SECRET_NAME) names.add(token);
    }
  }
  return names;
}

function readInput() {
  const idx = process.argv.indexOf('--secrets-file');
  if (idx >= 0) {
    const file = process.argv[idx + 1];
    if (!file) throw new Error('--secrets-file needs a path');
    return readFileSync(file, 'utf8');
  }
  if (process.stdin.isTTY) return '';
  return readFileSync(0, 'utf8');
}

function main() {
  let text;
  try {
    text = readInput();
  } catch (err) {
    console.error(`::error::Turnstile deploy guard could not read secret names: ${err.message}`);
    process.exit(1);
  }

  const names = parseSecretNames(text);
  if (names.has(SECRET_NAME)) {
    console.log(`Turnstile gate is enabled on the deployed Worker (${SECRET_NAME} present).`);
    return;
  }

  const now = new Date().toISOString();
  const accepted = process.env.ALLOW_KEYLESS_WRITES === '1';
  console.log(`Deployed Worker secret names: ${[...names].sort().join(', ') || '(none listed)'}`);
  if (accepted) {
    console.log(
      `::warning::[${now}] ${SECRET_NAME} is not set: keyless mutations on shared-state prefixes remain ungated. ` +
        'Accepted via ALLOW_KEYLESS_WRITES=1. Enable with: npx wrangler secret put TURNSTILE_SECRET'
    );
    return;
  }
  console.error(
    `::error::[${now}] ${SECRET_NAME} is not set on the deployed Worker. ` +
      'Keyless POST/PUT/PATCH/DELETE on TURNSTILE_PREFIXES (estate, SOC playbooks, saved reports, ' +
      'workspaces, watchlists, tool chains, cyberpulse scan, X probe batch, radar scan) are reachable ' +
      'by any non-browser caller — the same-origin headers the auth chain trusts are forgeable by a script.'
  );
  console.error('');
  console.error('Enable the gate:  npx wrangler secret put TURNSTILE_SECRET');
  console.error('  then set TURNSTILE_SITE_KEY and TURNSTILE_HOSTNAMES (see docs/turnstile-bot-gate.md).');
  console.error('');
  console.error('If keyless writes are an accepted, reviewed posture for this deployment, set the');
  console.error('repository variable ALLOW_KEYLESS_WRITES=1 to record that decision and unblock deploys.');
  process.exit(1);
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) main();
