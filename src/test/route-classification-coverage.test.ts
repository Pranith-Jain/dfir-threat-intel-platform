import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Structural guard: every mutating /api/v1 route must be CLASSIFIED.
 *
 * Why this exists
 * ---------------
 * Auth and cost control on this API are enforced by hand-maintained lists:
 *
 *   - `requireAdminMiddleware` mounts + `ADMIN_GATED_PREFIXES`  (lib/auth)
 *   - `AI_STRICT_EXACT` / `AI_STRICT_PREFIXES`                 (lib/ratelimit)
 *   - `ADMIN_STRICT_PREFIX` / `BRIEFINGS_ADMIN`                (lib/ratelimit)
 *
 * Nothing about that arrangement stops a newly-registered POST from quietly
 * landing outside all of them. That is not hypothetical: the 2026-10-10 audit
 * found 29 mutating routes sitting on nothing tighter than the global 30/min
 * bucket, several of which fan out to third-party APIs or drive a paid
 * Browser Rendering binding. A second pass driven by this very guard then
 * found 5 more, plus a sub-path hole in `isAiStrict` that left the DELETE on
 * a resource uncapped while the POST that created it was capped.
 *
 * The lists are unavoidably manual — they encode intent, not structure. What
 * CAN be mechanical is the coverage check: fail the build when a mutating
 * route is unclassified, so drift is caught at commit time instead of by the
 * next audit. Cheap per-row CRUD is a deliberate, listed exemption rather than
 * an oversight — see CHEAP_CRUD_EXEMPT.
 *
 * Runs in the ROOT vitest project (jsdom), not the api one: this reads
 * api/src/index.ts as text, and @cloudflare/vitest-pool-workers sandboxes
 * node:fs to its own package.
 */

const ROOT = resolve(__dirname, '../..');
const read = (p: string) => readFileSync(resolve(ROOT, p), 'utf8');

const indexSrc = read('api/src/index.ts');
const authSrc = read('api/src/lib/auth.ts');
const rlSrc = read('api/src/lib/ratelimit.ts');

/**
 * Route registrations, including sub-routers.
 *
 * `app.route(base, router)` mounts a Hono sub-router whose own paths are
 * relative to `base`. Without expanding those, a route like
 * `POST /api/v1/auth/register` (declared as `auth.post('/register')` in
 * routes/auth.ts) looks unregistered — and the stale-entry check below would
 * then "prove" it should be deleted from AI_STRICT_EXACT. That is exactly the
 * mistake this guard made on its first run, so the expansion is load-bearing,
 * not a nicety.
 */
function parseRoutes(): Array<{ line: number; method: string; path: string }> {
  const out: Array<{ line: number; method: string; path: string }> = [];
  indexSrc.split('\n').forEach((l, i) => {
    const direct = /^\s*app\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]/.exec(l);
    if (direct) out.push({ line: i + 1, method: direct[1].toUpperCase(), path: direct[2] });

    const mounted = /^\s*app\.route\(\s*['"`]([^'"`]+)['"`]\s*,\s*([A-Za-z0-9_]+)\s*\)/.exec(l);
    if (!mounted) return;
    const [, base, varName] = mounted;
    // Routers arrive both as named (`import { xRouter } from './routes/x'`) and
    // default (`import authRoutes from './routes/auth'`) imports.
    const file = new RegExp(
      `import\\s+(?:\\{[^}]*\\b${varName}\\b[^}]*\\}\\s+from\\s+'\\./routes/([^']+)'|` +
        `${varName}\\s+from\\s+'\\./routes/([^']+)')`
    ).exec(indexSrc);
    if (!file) return;
    let src: string;
    try {
      src = read(`api/src/routes/${file[1] ?? file[2]}.ts`);
    } catch {
      return; // directory-style router; the direct list still covers most routes
    }
    for (const sub of src.split('\n')) {
      // Receiver-agnostic on purpose: the exported const a sub-router is
      // imported as is often not the name it declares internally
      // (`import authRoutes from './routes/auth'` → `auth.post(...)`).
      const m = /^\s*\w+\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]/.exec(sub);
      if (m) out.push({ line: 0, method: m[1].toUpperCase(), path: `${base.replace(/\/$/, '')}${m[2]}` });
    }
  });
  return out;
}

/** Pull a `const NAME = [ ... ]` / `new Set(...)` string list. */
function stringList(src: string, name: string): string[] {
  const setRe = new RegExp(`const ${name}[^=]*=\\s*new Set(?:<[^>]*>)?\\(\\[([\\s\\S]*?)\\]\\)`);
  const arrRe = new RegExp(`const ${name}[^=]*=\\s*\\[([\\s\\S]*?)\\];`);
  const m = setRe.exec(src) ?? arrRe.exec(src);
  if (!m?.[1]) return [];
  // Strip `//` line comments before matching quotes. Without this an
  // apostrophe inside a comment ("the caller's payload") reads as the end of
  // a string literal and every following entry silently disappears — which
  // looks exactly like those routes being unclassified.
  //
  // The leading `(^|\s)` keeps `https://` inside a quoted URL intact.
  const body = m[1].replace(/(^|\s)\/\/.*$/gm, '$1');
  return [...body.matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

const AI_STRICT_EXACT = new Set(stringList(rlSrc, 'AI_STRICT_EXACT'));
const AI_STRICT_PREFIXES = stringList(rlSrc, 'AI_STRICT_PREFIXES');
const BRIEFINGS_ADMIN = new Set(stringList(rlSrc, 'BRIEFINGS_ADMIN'));
const ADMIN_STRICT_PREFIX = stringList(rlSrc, 'ADMIN_STRICT_PREFIX')[0] ?? '/api/v1/admin/';
const ADMIN_GATED_PREFIXES = stringList(indexSrc, 'ADMIN_GATED_PREFIXES');
const EXEMPT_PATHS = new Set(stringList(authSrc, 'EXEMPT_PATHS'));

/** Literal `app.use(path, requireAdmin…)` mounts, incl. the `${base}` template. */
function adminMountPrefixes(): string[] {
  const baseM = /const base\s*=\s*['"`]([^'"`]+)['"`]/.exec(indexSrc);
  const base = baseM?.[1] ?? '/api/v1/admin';
  const out: string[] = [];
  for (const l of indexSrc.split('\n')) {
    const m = /^\s*app\.use\(\s*['"`]([^'"`]+)['"`]\s*,\s*requireAdmin/.exec(l);
    if (m) out.push(m[1].replace('${base}', base));
  }
  return out;
}

/**
 * Paths that legitimately live on the global bucket only.
 *
 * Per-row CRUD against an unshared or self-owned store: the global 30/min
 * (120/min keyed) is proportionate, and a stricter bucket would be a UX
 * regression with no security gain. Every entry is a deliberate decision — a
 * new path added here should be argued for, not appended to make a test green.
 */
const CHEAP_CRUD_EXEMPT = [
  '/api/v1/external-resources',
  '/api/v1/watchlist/actors',
  // Second-pass candidates that the guard flagged but that turned out to be
  // pure in-process compute with no upstream fan-out, no AI call and no paid
  // binding — the global bucket is proportionate for them.
  '/api/v1/cti/parse', // validate + JSON.parse of a supplied STIX bundle
  '/api/v1/threat-intel/actor-dna/match', // in-memory match over a static DB
  // Sub-router families (`app.route(...)`) the guard could not see before it
  // learned to expand them. Each loads a manifest from ASSETS or calls the API
  // app in-process via the SELF binding — no upstream fan-out, no paid binding,
  // so the global bucket is proportionate.
  '/api/v1/si/parse',
  '/api/v1/si/mailscope',
  '/api/v1/si/shiftlog',
  '/api/v1/si/hypos',
  '/api/v1/si/promptvault',
  '/api/v1/ai-escape/reports',
  '/api/v1/threat-intel/destroylist/check',
  '/api/v1/cairn/scan',
  '/api/v1/nova/scan',
  '/api/v1/denali/evaluate/activity',
  '/api/v1/nhi/scan',
  '/api/v1/dns/batch',
  '/api/v1/file/triage-static',
  '/api/v1/net-analytics/beacon',
  '/api/v1/net-analytics/dns-tunnel',
  '/api/v1/observables/extract',
  '/api/v1/procedures/jobs',
  '/api/v1/rules/sigma/convert',
  // Session-authenticated multi-tenant + profile writes. Not free (they hit
  // D1 and carry a session cookie) but self-scoped, so the global bucket is
  // proportionate; `requireUser` in routes/orgs.ts is the real gate.
  '/api/v1/orgs',
  '/api/v1/leaderboard',
];

const isMutating = (m: string) => m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE';

function classified(path: string, adminPrefixes: string[]): boolean {
  if (EXEMPT_PATHS.has(path)) return true;
  if (ADMIN_STRICT_PREFIX && path.startsWith(ADMIN_STRICT_PREFIX)) return true;
  if (BRIEFINGS_ADMIN.has(path)) return true;
  if (ADMIN_GATED_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`))) return true;
  if (
    adminPrefixes.some((p) => {
      const q = p.replace(/\*$/, '');
      return path === q || path.startsWith(`${q}/`);
    })
  ) {
    return true;
  }
  if (AI_STRICT_EXACT.has(path)) return true;
  // Mirrors isAiStrict(): an exact entry also covers its sub-paths, so
  // `DELETE /api/v1/campaigns/:id` is classified by `/api/v1/campaigns`.
  for (const p of AI_STRICT_EXACT) {
    if (path.startsWith(`${p}/`)) return true;
  }
  if (AI_STRICT_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`))) return true;
  if (CHEAP_CRUD_EXEMPT.some((p) => path === p || path.startsWith(`${p}/`))) return true;
  return false;
}

describe('API route classification (auth + cost control coverage)', () => {
  const adminPrefixes = adminMountPrefixes();
  const routes = parseRoutes();

  it('parses the route table at all (guards the checks below)', () => {
    // If a refactor changes the registration style, every assertion below would
    // silently pass on an empty list. This makes that failure loud.
    expect(routes.length).toBeGreaterThan(400);
    expect(AI_STRICT_EXACT.size).toBeGreaterThan(20);
    expect(ADMIN_GATED_PREFIXES.length).toBeGreaterThan(5);
    expect(EXEMPT_PATHS.size).toBeGreaterThan(20);
  });

  it('classifies every mutating /api/v1 route', () => {
    const unclassified = routes
      .filter((r) => isMutating(r.method) && r.path.startsWith('/api/v1/'))
      .filter((r) => !classified(r.path, adminPrefixes))
      .map((r) => `  index.ts:${r.line}  ${r.method} ${r.path}`);

    expect(
      unclassified,
      `Unclassified mutating routes — give each one an admin gate, an AI/rate-limit\n` +
        `bucket, or (if it is cheap per-row CRUD) an entry in CHEAP_CRUD_EXEMPT:\n${unclassified.join('\n')}`
    ).toEqual([]);
  });

  it('has no stale entries in AI_STRICT_EXACT', () => {
    // A path that no longer exists protects nothing while still looking like
    // coverage — the most likely way these lists rot, and how
    // `/api/v1/ti-dashboard/build` and `/api/v1/auth/register` were found.
    const routesByPath = new Set(routes.map((r) => r.path));
    const orphans = [...AI_STRICT_EXACT].filter((p) => {
      if (routesByPath.has(p) || p.startsWith('/api/v1/taxii2')) return false;
      // isAiStrict treats an exact entry as covering its own sub-paths
      // (`pathname.startsWith(`${p}/`)`) — mirror that contract here, or an
      // entry whose handler lives below its collection root reads as stale
      // (ti-mindmap mounts POSTs at `/ti-mindmap/analyze|assistant`).
      for (const r of routesByPath) {
        if (r.startsWith(`${p}/`)) return false;
      }
      return true;
    });
    expect(orphans, `AI_STRICT_EXACT entries with no matching route: ${orphans.join(', ')}`).toEqual([]);
  });

  it('keeps the cheap-CRUD exemption list free of costly paths', () => {
    // The exemption is the one place a costly endpoint could slip through
    // unnoticed, so it must stay narrow and obvious.
    for (const p of CHEAP_CRUD_EXEMPT) {
      expect(AI_STRICT_EXACT.has(p), `${p} is both cheap-CRUD exempt and AI-strict`).toBe(false);
      expect(ADMIN_GATED_PREFIXES.includes(p), `${p} is both cheap-CRUD exempt and admin-gated`).toBe(false);
    }
  });
});
