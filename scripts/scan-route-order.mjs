#!/usr/bin/env node
/**
 * Route-order guard for the /api/v1 auth + Turnstile chains.
 *
 * Hono composes middleware in registration order: a handler registered BEFORE
 * an `app.use()` never runs that middleware. This scanner fails the build when
 *
 *   1. a mutating /api/v1 route (or a router mount) is registered before
 *      `authenticate('external-only')`, unless it is in the explicit allowlist
 *      of intentionally public mounts; or
 *   2. a route named in `TURNSTILE_EXACT_PATHS` is registered before its guard
 *      loop — the exact bug that left /api/v1/radar/scan ungated.
 *
 * The allowlist is deliberately tiny and carries a reason for each entry: the
 * point is to make a new bypass require a conscious, reviewable decision.
 *
 * Exit codes: 0 clean, 1 violations, 2 scanner error.
 */
import { readFileSync } from 'node:fs';

/** Public router mounts verified to contain only read handlers. */
const PUBLIC_ROUTER_MOUNTS = new Map([
  ['darkwebOsintRouter', 'all handlers in api/src/routes/darkweb-osint.ts are GET reads'],
]);

/** Extract the exact-path gate list from turnstile.ts. */
export function gatedExactPaths(turnstileSrc) {
  const block = /export const TURNSTILE_EXACT_PATHS\s*=\s*\[([\s\S]*?)\]\s*as const/.exec(turnstileSrc);
  if (!block) throw new Error('TURNSTILE_EXACT_PATHS not found');
  return [...block[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
}

/**
 * @param {string} indexSrc  contents of api/src/index.ts
 * @param {string} turnstileSrc  contents of api/src/lib/turnstile.ts
 * @returns {string[]} human-readable violations
 */
export function scanRouteOrder(indexSrc, turnstileSrc) {
  const lines = indexSrc.split('\n');
  const issues = [];
  const lineOf = (needle) => {
    const i = lines.findIndex((l) => l.includes(needle));
    return i < 0 ? null : i + 1;
  };

  const authLine = lineOf("app.use('/api/v1/*', authenticate('external-only'))");
  const guardLine = lineOf('for (const path of TURNSTILE_EXACT_PATHS)');
  if (authLine === null || guardLine === null) {
    return ['could not locate the /api/v1 auth chain or the TURNSTILE_EXACT_PATHS guard in api/src/index.ts'];
  }

  // 1. Mutating routes before the auth chain.
  const methodRe = /\bapp\.(post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]/g;
  for (let i = 0; i < lines.length; i++) {
    if (i + 1 >= authLine) break;
    methodRe.lastIndex = 0;
    const m = methodRe.exec(lines[i]);
    if (!m) continue;
    if (m[2].startsWith('/api/v1/') && !m[2].startsWith('/api/v1/public/')) {
      issues.push(
        `line ${i + 1}: ${m[1].toUpperCase()} ${m[2]} is registered before authenticate('external-only') at line ${authLine}`
      );
    }
  }

  // 2. Router mounts before the auth chain must be explicitly allowlisted.
  const mountRe = /\bapp\.route\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)\s*\)/g;
  for (let i = 0; i < lines.length; i++) {
    if (i + 1 >= authLine) break;
    mountRe.lastIndex = 0;
    const m = mountRe.exec(lines[i]);
    if (!m || !m[1].startsWith('/api/v1')) continue;
    if (!PUBLIC_ROUTER_MOUNTS.has(m[2])) {
      issues.push(
        `line ${i + 1}: router ${m[2]} mounted under ${m[1]} before authenticate() — verify its handlers are read-only and allowlist it with a reason`
      );
    }
  }

  // 3. Exact-path Turnstile gates must precede their handlers.
  for (const path of gatedExactPaths(turnstileSrc)) {
    const re = new RegExp(`\\bapp\\.(get|post|put|patch|delete)\\(\\s*['"\`]${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`);
    for (let i = 0; i < lines.length; i++) {
      const m = re.exec(lines[i]);
      if (!m) continue;
      if (i + 1 < guardLine) {
        issues.push(
          `line ${i + 1}: ${m[1].toUpperCase()} ${path} is registered before its Turnstile gate at line ${guardLine} — the gate never runs`
        );
      }
      break;
    }
  }

  return issues;
}

function main() {
  const root = process.cwd();
  try {
    const indexSrc = readFileSync(`${root}/api/src/index.ts`, 'utf8');
    const turnstileSrc = readFileSync(`${root}/api/src/lib/turnstile.ts`, 'utf8');
    const issues = scanRouteOrder(indexSrc, turnstileSrc);
    if (issues.length) {
      console.error('scan-route-order: FAIL');
      for (const issue of issues) console.error(`  · ${issue}`);
      process.exit(1);
    }
    console.log('scan-route-order: clean (auth chain + Turnstile gates precede their handlers)');
  } catch (err) {
    console.error(`scan-route-order: scanner error — ${err.message}`);
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) main();
