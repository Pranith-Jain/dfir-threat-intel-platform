import { describe, it, expect } from 'vitest';
import { rateLimit } from '../../src/lib/ratelimit';

/**
 * 2026-10-10 endpoint audit — coverage for the writes that were reachable with
 * no bucket tighter than the global 30/min (120/min keyed).
 *
 * Why this file exists
 * --------------------
 * `AI_STRICT_EXACT` / `AI_STRICT_PREFIXES` are hand-maintained string lists, so
 * nothing structurally stops a newly-registered mutating route from silently
 * landing outside them. The endpoint audit found 29 such routes; these tests
 * pin the ones that were fixed so a later refactor that drops a name from the
 * list fails loudly instead of quietly restoring an unbounded endpoint.
 *
 * What is asserted is only the *tighter* bucket: with the global counter at 29
 * (one below the 30/min limit) an endpoint on the strict bucket still refuses
 * the call once its own 10/min counter is exhausted. That isolates the strict
 * bucket from the global one — otherwise a test would pass for the wrong reason.
 */

/** Seed the global per-IP counter in the Cache API (mirrors ratelimit.test.ts). */
async function seedGlobal(ip: string, count: number): Promise<void> {
  const bucket = Math.floor(Date.now() / 1000 / 60);
  const key = new Request(`https://rl.internal/u/${bucket}/${encodeURIComponent(ip)}`);
  await caches.default.put(key, new Response(String(count), { headers: { 'cache-control': 'max-age=60' } }));
}

/**
 * Seed the strict (ai-costly) bucket. The DO counter path is unavailable in the
 * test isolate, so this mirrors the per-colo Cache fallback the limiter takes
 * when `atomicStrictIncr` returns null — i.e. exactly the branch under test.
 */
async function seedStrict(ip: string, count: number): Promise<void> {
  const bucket = Math.floor(Date.now() / 1000 / 60);
  const key = new Request(`https://rl.internal/c/${bucket}/${encodeURIComponent(ip)}`);
  await caches.default.put(key, new Response(String(count), { headers: { 'cache-control': 'max-age=60' } }));
}

function makeCtx(url: string, method: string, ip: string) {
  const pending: Promise<unknown>[] = [];
  const ctx = {
    req: {
      url,
      method,
      header: (name: string) => (name.toLowerCase() === 'cf-connecting-ip' ? ip : undefined),
    },
    env: {},
    executionCtx: { waitUntil: (p: Promise<unknown>) => pending.push(p) },
    json: (body: unknown, status?: number, headers?: Record<string, string>) =>
      new Response(JSON.stringify(body), {
        status: status ?? 200,
        headers: { 'content-type': 'application/json', ...(headers ?? {}) },
      }),
  } as unknown as Parameters<typeof rateLimit>[0] & {
    executionCtx: { waitUntil: (p: Promise<unknown>) => void };
  };
  return { ctx, pending };
}

/** Run the limiter and settle any background cache writes. */
async function run(url: string, method: string, ip: string) {
  const { ctx, pending } = makeCtx(url, method, ip);
  let nextCalled = false;
  const res = await rateLimit(ctx, async () => {
    nextCalled = true;
  });
  await Promise.allSettled(pending);
  return { res: res as Response | undefined, nextCalled };
}

/**
 * Every path here was on the global bucket only at audit time. Grouped to match
 * the categories in the AI_STRICT_EXACT comment so the two stay legible
 * together when the list is next audited.
 */
const AUDITED_WRITES: Array<{ path: string; group: string }> = [
  // Outbound-fetch relays — caller controls the target.
  { path: '/api/v1/phishing/fetch-page', group: 'fetch relay' },
  { path: '/api/v1/infra-search', group: 'fetch relay' },
  { path: '/api/v1/open-dir/scan', group: 'fetch relay' },
  { path: '/api/v1/mcp/proxy', group: 'fetch relay' },
  { path: '/api/v1/intodns/debug-email', group: 'fetch relay' },
  { path: '/api/v1/osv/scan', group: 'fetch relay' },
  { path: '/api/v1/bloom/check', group: 'fetch relay' },
  { path: '/api/v1/fortibleed/batch', group: 'fetch relay' },
  { path: '/api/v1/stealer/parse', group: 'fetch relay' },
  { path: '/api/v1/si/enrich-ip-stix-batch', group: 'fetch relay' },
  // CPU / correlation work.
  { path: '/api/v1/report-analyzer/render', group: 'cpu' },
  { path: '/api/v1/cti/render/graph', group: 'cpu' },
  { path: '/api/v1/attack-chain/reconstruct', group: 'cpu' },
  { path: '/api/v1/threat-intel/campaign/analyze', group: 'cpu' },
  { path: '/api/v1/threat-intel/correlate', group: 'cpu' },
  { path: '/api/v1/ssvc/triage', group: 'cpu' },
  { path: '/api/v1/analytics-report', group: 'cpu' },
  // Server-side work amplifiers.
  { path: '/api/v1/automation/run', group: 'amplifier' },
  { path: '/api/v1/intel-bundle', group: 'amplifier' },
  { path: '/api/v1/intel-bundle/build', group: 'amplifier' },
  { path: '/api/v1/cyberpulse/scan', group: 'amplifier' },
  // Global-shared D1 writes.
  { path: '/api/v1/campaigns', group: 'shared write' },
  { path: '/api/v1/watchlist/digest', group: 'shared write' },
  { path: '/api/v1/cti/exposure', group: 'shared write' },
  { path: '/api/v1/yara/generate', group: 'shared write' },
  { path: '/api/v1/yara/validate', group: 'shared write' },
];

/** Prefix families added by the same audit. */
const AUDITED_PREFIX_MEMBERS = [
  '/api/v1/soc/playbooks',
  '/api/v1/soc/playbooks/abc123',
  '/api/v1/soc/playbooks/abc123/execute',
];

describe('rate limiter — 2026-10-10 audit coverage', () => {
  // Distinct IP per case so a seeded bucket from one case cannot leak into the
  // next (the Cache API is per-isolate and these run in the same one).
  let seq = 0;
  const nextIp = () => `198.51.100.${200 + seq++}`;

  it.each(AUDITED_WRITES)('applies the strict bucket to $path ($group)', async ({ path }) => {
    const ip = nextIp();
    // Global counter one below its limit: if the endpoint were only on the
    // global bucket this call would be ALLOWED, so a pass here cannot be
    // explained by the global limit.
    await seedGlobal(ip, 29);
    await seedStrict(ip, 10); // AI_STRICT_LIMIT

    const { res, nextCalled } = await run(`https://api.example.com${path}`, 'POST', ip);
    expect(nextCalled).toBe(false);
    expect(res?.status).toBe(429);
    const body = (await res!.json()) as Record<string, unknown>;
    expect(body.scope).toBe('ai-costly');
    expect(body.limit).toBe(10);
  });

  it.each(AUDITED_PREFIX_MEMBERS)('applies the strict bucket to the prefix member %s', async (path) => {
    const ip = nextIp();
    await seedGlobal(ip, 29);
    await seedStrict(ip, 10);

    const method = path.endsWith('/execute') || path === '/api/v1/soc/playbooks' ? 'POST' : 'POST';
    const { res, nextCalled } = await run(`https://api.example.com${path}`, method, ip);
    expect(nextCalled).toBe(false);
    expect(res?.status).toBe(429);
  });

  it('still admits these endpoints when BOTH counters are under the limit', async () => {
    // Guards against "fixing" the audit by blanket-denying: the strict bucket
    // must throttle, not block.
    const ip = nextIp();
    await seedGlobal(ip, 0);
    await seedStrict(ip, 0);
    const { res, nextCalled } = await run('https://api.example.com/api/v1/infra-search', 'POST', ip);
    expect(nextCalled).toBe(true);
    expect(res).toBeUndefined();
  });

  it('does not apply the strict bucket to GETs of the same paths', async () => {
    // isAiStrict() is method-scoped so parallel SPA tab loads are unaffected.
    const ip = nextIp();
    await seedGlobal(ip, 0);
    await seedStrict(ip, 10);
    const { nextCalled } = await run('https://api.example.com/api/v1/soc/playbooks', 'GET', ip);
    expect(nextCalled).toBe(true);
  });

  it('leaves cheap CRUD on the global bucket (no over-tightening)', async () => {
    // Plain per-row CRUD was deliberately NOT moved: 30/min is proportionate,
    // and a stricter bucket would be a UX regression with no security gain.
    const ip = nextIp();
    await seedGlobal(ip, 29);
    await seedStrict(ip, 10);
    const { nextCalled } = await run('https://api.example.com/api/v1/external-resources', 'POST', ip);
    expect(nextCalled).toBe(true);
  });
});
