/**
 * Tests for the GitHub access path — the fix for the 2026-10-16 finding that
 * `/api/v1/cve-health` reported `github_api: fail — GitHub API returned 403`.
 *
 * Every `api.github.com` call made from the Worker shares one egress IP pool.
 * Unauthenticated that pool has a 60 req/hour budget that any feature can
 * exhaust, after which GitHub answers 403 to everyone — silently starving
 * whatever the call site feeds (CVE PoC search, supply-chain advisories,
 * GenDigital IOC lists, Maltrail trails, the ATT&CK flow corpus, VOLT).
 *
 * The fix is `api/src/lib/github-api.ts`: one header builder that attaches
 * `Authorization: Bearer <GITHUB_TOKEN>` when the secret is configured, plus
 * rate-limit-aware diagnostics. The risk being pinned here is a regression to
 * the old shape — a bare fetch with an inline UA — which type-checks, passes
 * every unit test, and only shows up as a 403 in production.
 *
 * Static guards on purpose: the failure mode is invisible at runtime until the
 * shared quota is gone, so nothing dynamic catches it reliably.
 *
 * Run: node --test scripts/github-auth-guard.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');

/**
 * Call sites that fetch `api.github.com` directly on the CVE / supply-chain /
 * IOC surfaces — the ones whose failure is a feed-health failure. Each must
 * route through the shared helper so the token, when configured, is actually
 * sent. Files NOT listed here either already carried their own token plumbing
 * before this pass (github-security, depx, malicious-packages,
 * supply-chain-attacks, package-verdict, secret-leaks, github-poc-scraper) or
 * are low-traffic personal-profile enrichment with no `env` in scope
 * (profile-stats, email-osnit-profile).
 */
const AUTHENTICATED_CALL_SITES = [
  'api/src/lib/cve-lookup.ts',
  'api/src/routes/global-pulse/fetchers.ts',
  'api/src/routes/malware-iocs.ts',
  'api/src/routes/maltrail.ts',
  'api/src/routes/maltrail-sync.ts',
  'api/src/routes/volexity-threat-intel.ts',
  'api/src/routes/attack-flow-library.ts',
  'api/src/routes/detection-rules.ts',
  'api/src/routes/actor-enrich.ts',
];

/**
 * Callers of `lookupCve` that must thread `env` through. The fetch itself is in
 * cve-lookup.ts; if these stop passing `env`, the GHSA lookup quietly reverts
 * to anonymous and the guard on the file above would still pass.
 */
const ENV_THREADING_CALL_SITES = [
  { rel: 'api/src/routes/unified-search.ts', expect: /lookupCve\([^;]*\benv\b/ },
  { rel: 'api/src/routes/cve-batch.ts', expect: /lookupCve\([^;]*\benv\b/ },
];

test('health-critical GitHub call sites route through the shared helper', () => {
  for (const rel of AUTHENTICATED_CALL_SITES) {
    const src = read(rel);
    assert.match(
      src,
      /githubHeaders\(/,
      `${rel} must build api.github.com headers with githubHeaders() — an inline UA-only ` +
        `header set runs anonymously and absorbs the shared 60/h egress quota (the 403 that ` +
        `emptied this surface before the 2026-10-16 pass)`
    );
  }
});

test('lookupCve callers thread env so GHSA stays authenticated', () => {
  for (const { rel, expect } of ENV_THREADING_CALL_SITES) {
    assert.match(
      read(rel),
      expect,
      `${rel} must pass env into lookupCve() — dropping it silently downgrades the GHSA ` +
        `advisories lookup back to the shared anonymous quota`
    );
  }
});

test('the shared helper keeps token auth and actionable diagnostics', () => {
  const src = read('api/src/lib/github-api.ts');
  assert.match(src, /Authorization = `Bearer \$\{token\}`/, 'helper must attach the token as a Bearer header');
  assert.match(src, /GITHUB_TOKEN\?: string/, 'helper must read GITHUB_TOKEN from env');
  assert.match(
    src,
    /anonymous egress quota exhausted/,
    'a 403 must explain itself (anonymous quota) rather than surface as a bare status code'
  );
  // A 403 means the shared budget is gone; retrying multiplies the load that
  // caused it. The helper must stay retry-free and let callers degrade.
  assert.ok(!/for\s*\(.*attempts/.test(src), 'helper must not retry rate-limited requests');
});

test('GITHUB_TOKEN is declared optional in Env', () => {
  const src = read('api/src/env.ts');
  assert.match(src, /GITHUB_TOKEN\?: string/, 'Env must declare GITHUB_TOKEN as optional (anonymous still works)');
});

test('the GHSA advisories URL builder is used instead of hand-built query strings', () => {
  // `advisoriesUrl` encodes the params; hand-built strings is how the
  // `cve_id=…&per_page=…` shape gets copy-drifted across call sites.
  for (const rel of ['api/src/lib/cve-lookup.ts', 'api/src/routes/global-pulse/fetchers.ts']) {
    assert.match(read(rel), /advisoriesUrl\(/, `${rel} must build GHSA advisories URLs with advisoriesUrl()`);
  }
});
