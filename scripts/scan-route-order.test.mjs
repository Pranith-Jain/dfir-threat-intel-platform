/** Regression tests for the /api/v1 route-order guard. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gatedExactPaths, scanRouteOrder } from './scan-route-order.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const indexSrc = readFileSync(join(ROOT, 'api/src/index.ts'), 'utf8');
const turnstileSrc = readFileSync(join(ROOT, 'api/src/lib/turnstile.ts'), 'utf8');

const CHAINS = `import { turnstileGuard, TURNSTILE_EXACT_PATHS } from './lib/turnstile';
app.use('/api/v1/*', authenticate('external-only'));
for (const path of TURNSTILE_EXACT_PATHS) { app.use(path, turnstileGuard({ exactPath: path })); }
`;

test('current api/src/index.ts has no pre-auth mutation or dead Turnstile gate', () => {
  assert.deepEqual(scanRouteOrder(indexSrc, turnstileSrc), []);
});

test('detects a mutating route registered before the auth chain', () => {
  const issues = scanRouteOrder(
    `app.post('/api/v1/estate/config', handler);\n${CHAINS}`,
    turnstileSrc
  );
  assert.equal(issues.length, 1);
  assert.match(issues[0], /registered before authenticate/);
});

test('detects a Turnstile-gated route registered before its guard', () => {
  const issues = scanRouteOrder(
    `app.post('/api/v1/radar/scan', handler);\n${CHAINS}`,
    turnstileSrc
  );
  assert.ok(issues.some((i) => i.includes('the gate never runs')));
});

test('detects an unallowlisted router mount before auth', () => {
  const issues = scanRouteOrder(`app.route('/api/v1', shadyRouter);\n${CHAINS}`, turnstileSrc);
  assert.ok(issues.some((i) => i.includes('shadyRouter')));
});

test('gatedExactPaths parses the source list', () => {
  const paths = gatedExactPaths(turnstileSrc);
  assert.ok(paths.includes('/api/v1/radar/scan'));
  assert.ok(paths.includes('/api/v1/copilot/chat'));
});
