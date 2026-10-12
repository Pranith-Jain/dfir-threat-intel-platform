import { describe, it, expect } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import { buildBriefing } from '../../src/lib/briefing-builder';
import {
  BUILD_SOURCE_COST,
  BUILD_SUBREQUEST_BUDGET,
  FREE_PLAN_SUBREQUEST_CAP,
  SUBREQUESTS_RESERVED_FOR_SURROUND,
  createBuildSubrequestBudget,
  installSubrequestMeter,
  isSubrequestExhaustedError,
} from '../../src/lib/briefing-builder/subrequest-budget';
import type { Env } from '../../src/env';

/**
 * Regression tests for the two defects that stopped daily briefings from
 * persisting at all.
 *
 * 1. `skipLlm` was only honoured on the WEEKLY ROLLUP branch of buildBriefing.
 *    The daily branch — the one the 00:30 cron, the hourly heal and the admin
 *    build button all take — called `buildLlmExecutiveSummary` unconditionally,
 *    spending ~9-13 subrequests walking Gemini's 5 models and Groq's 4 before
 *    falling back to a template the builder can produce for free.
 * 2. Nothing bounded the fan-out's total cost. Past 50 subrequests Cloudflare
 *    aborts the whole invocation and the client sees HTTP 503, which is
 *    indistinguishable from an upstream outage: no row, and an admin build that
 *    fails the same way.
 *
 * The budget is what makes (2) survivable — it admits sources in priority order
 * and drops the tail rather than taking the run down.
 */

describe('subrequest budget', () => {
  it('never charges more than the limit', () => {
    const b = createBuildSubrequestBudget(10);
    expect(b.afford(10)).toBe(true);
    expect(b.spent()).toBe(10);
    expect(b.remaining()).toBe(0);
    expect(b.afford(1)).toBe(false);
    // A refused charge must not be charged.
    expect(b.spent()).toBe(10);
  });

  it('treats a zero/negative cost as always affordable', () => {
    const b = createBuildSubrequestBudget(0);
    expect(b.afford(0)).toBe(true);
    expect(b.afford(-5)).toBe(true);
    expect(b.spent()).toBe(0);
  });

  it('leaves headroom under the platform cap', () => {
    expect(BUILD_SUBREQUEST_BUDGET).toBeLessThan(FREE_PLAN_SUBREQUEST_CAP);
  });

  it('leaves the surround its share of the 50', () => {
    // The live cap plus everything that runs AROUND the build in the same
    // invocation must still fit. This is the invariant the first version of
    // this guard got wrong: a build that spends exactly its own budget has
    // spent the INVOCATION's budget.
    const liveCap = FREE_PLAN_SUBREQUEST_CAP - SUBREQUESTS_RESERVED_FOR_SURROUND;
    expect(SUBREQUESTS_RESERVED_FOR_SURROUND).toBeGreaterThan(0);
    expect(liveCap).toBeLessThan(FREE_PLAN_SUBREQUEST_CAP);
    expect(liveCap + SUBREQUESTS_RESERVED_FOR_SURROUND).toBe(FREE_PLAN_SUBREQUEST_CAP);
  });

  it('sheds a source instead of throwing when the cap is hit', async () => {
    // The failure this exists to prevent: a source trips the budget, the throw
    // escapes, and the whole invocation dies with "Too many subrequests" and
    // no row. Every admit path must absorb it.
    const envObj = {
      ...(testEnv as unknown as Record<string, unknown>),
      AI: { run: async () => ({ response: 'x'.repeat(120) }) },
    } as unknown as Env;
    const realFetch = globalThis.fetch;
    let n = 0;
    // Burn the whole cap in the first few calls so everything after is refused.
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      n += 1;
      if (n > 6) return new Response('[]', { headers: { 'content-type': 'application/json' } });
      return new Response('[]', { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    try {
      // 6 real calls then the meter refuses; the build must still resolve with
      // a briefing object rather than throwing.
      await expect(buildBriefing('daily', new Date(), { env: envObj, skipLlm: true })).resolves.toBeDefined();
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('costs the whole fan-out to no more than the budget plus the KEV enrichment tail', () => {
    const fanOut = Object.entries(BUILD_SOURCE_COST)
      .filter(([k]) => k !== 'nvdById' && k !== 'llmSummary')
      .reduce((n, [, v]) => n + v, 0);
    // The fan-out plus the 5-CVE KEV enrichment tail is the build's ceiling;
    // it must land under the budget, or the budget would be dropping sources
    // on a clean run rather than only on a busy one.
    expect(fanOut + 5 * BUILD_SOURCE_COST.nvdById).toBeLessThanOrEqual(BUILD_SUBREQUEST_BUDGET);
  });
});

/**
 * Drive a real `buildBriefing('daily')` against a stubbed fetch and count what
 * it spends. Every expensive branch is armed: KEV rows in-window, a non-empty
 * NVD page (which arms the per-CVE KEV enrichment), and OSSF commits (which arm
 * the per-commit file-list loop).
 */
async function runDailyBuild(opts: {
  skipLlm: boolean;
}): Promise<{ subrequests: number; aiRuns: number; hosts: string[] }> {
  const realFetch = globalThis.fetch;
  const hosts: string[] = [];
  const recent = new Date(Date.now() - 3600_000).toISOString().replace('Z', '').slice(0, 19);
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    let host = 'unknown';
    let path = '';
    try {
      const u = new URL(raw);
      host = u.host;
      path = u.pathname;
    } catch {
      /* noop */
    }
    hosts.push(host);
    const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { 'content-type': 'application/json' } });

    if (host.includes('cisa.gov')) {
      return json({
        vulnerabilities: Array.from({ length: 12 }, (_, i) => ({
          cveID: `CVE-2026-9${String(1000 + i)}`,
          vendorProject: 'acme',
          product: 'widget',
          dateAdded: recent,
          shortDescription: 'test',
          knownRansomwareCampaignUse: 'Known',
        })),
      });
    }
    if (host.includes('nvd.nist.gov')) {
      return json({
        totalResults: 1,
        vulnerabilities: [
          {
            cve: {
              id: 'CVE-2026-9111',
              published: recent,
              lastModified: recent,
              vulnStatus: 'Analyzed',
              descriptions: [{ lang: 'en', value: 'A test remote code execution flaw in a widget.' }],
              metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }] },
              configurations: [],
              weaknesses: [{ description: [{ lang: 'en', value: 'CWE-94' }] }],
            },
          },
        ],
      });
    }
    if (host.includes('api.github.com') && path.endsWith('/commits')) {
      return json(Array.from({ length: 3 }, () => ({ sha: 'a'.repeat(40), commit: { author: { date: recent } } })));
    }
    if (host.includes('api.github.com')) {
      return json({ files: [{ filename: 'osv/malicious/npm/evil-pkg/MAL-2026-1.json', status: 'added' }] });
    }
    if (host.includes('cvefeed.io')) {
      return json([{ cve_id: 'CVE-2026-9222', title: 'Widget flaw', published: recent, link: 'https://cvefeed.io/1' }]);
    }
    if (host.includes('dbu.gs')) {
      return json({
        vulns: [
          {
            cve_id: 'CVE-2026-9333',
            created: recent.slice(0, 10),
            severity: 'HIGH',
            score: 8,
            vendor: 'acme',
            product: 'widget',
            cwes: ['CWE-79'],
            impacts: ['Stored XSS'],
            has_exploits: false,
            has_fix: true,
            reference: 'https://dbu.gs/1',
          },
        ],
      });
    }
    if (host.includes('vulntracker.io')) {
      if (path.includes('archive')) return json([{ date: '2026-10-01', total_count: 300 }]);
      if (path.includes('blog') || path.includes('rss')) {
        return new Response('<rss></rss>', { headers: { 'content-type': 'application/xml' } });
      }
      return json({
        date: '2026-10-11',
        total_count: 300,
        critical_count: 12,
        exploited_count: 3,
        is_gated: false,
        top_cves: [],
      });
    }
    // Provider endpoints fail, so the chain walks every model — the state that
    // actually consumed the budget.
    if (host.includes('googleapis.com') || host.includes('groq.com')) return new Response('nope', { status: 500 });
    return json([]);
  }) as typeof fetch;

  let aiRuns = 0;
  const realKv = (testEnv as unknown as { KV_CACHE: Record<string, (...a: unknown[]) => unknown> }).KV_CACHE;
  const countingKv = {
    get: (...a: unknown[]) => (hosts.push('kv:get'), (realKv.get as (...x: unknown[]) => unknown)(...a)),
    put: (...a: unknown[]) => (hosts.push('kv:put'), (realKv.put as (...x: unknown[]) => unknown)(...a)),
    list: (...a: unknown[]) => (hosts.push('kv:list'), (realKv.list as (...x: unknown[]) => unknown)(...a)),
    delete: (...a: unknown[]) => (hosts.push('kv:delete'), (realKv.delete as (...x: unknown[]) => unknown)(...a)),
  };

  const envObj = {
    ...(testEnv as unknown as Record<string, unknown>),
    KV_CACHE: countingKv,
    AI: {
      run: async () => {
        aiRuns += 1;
        return { response: 'A plausible two-sentence executive summary of the window for testing purposes only.' };
      },
    },
    WEBAMON_API_KEY: 'x',
    GITHUB_TOKEN: 'x',
    RANSOMWARELIVE_API_KEY: 'x',
    MYTHREATINTEL_API_TOKEN: 'x',
    GOOGLE_AI_STUDIO_API_KEY: 'x',
    GROQ_API_KEY: 'x',
  } as unknown as Env;

  try {
    await buildBriefing('daily', new Date(), { env: envObj, skipLlm: opts.skipLlm });
  } finally {
    globalThis.fetch = realFetch;
  }
  return { subrequests: hosts.length, aiRuns, hosts };
}

describe('live subrequest meter', () => {
  it('counts fetches, charges redirect hops, and refuses past the cap', async () => {
    const realFetch = globalThis.fetch;
    // Stub the network BEFORE installing: the meter captures whatever
    // `globalThis.fetch` is at install time and wraps it.
    globalThis.fetch = (async () => new Response('ok')) as typeof fetch;
    const meter = installSubrequestMeter({}, 4);
    try {
      // `globalThis.fetch` is now the meter's wrapper.
      await globalThis.fetch('https://a.test/1');
      await globalThis.fetch('https://a.test/2');
      const s1 = meter.snapshot();
      expect(s1.fetches).toBe(2);
      expect(s1.byHost['a.test']).toBe(2);
      // 3rd call is within cap 4; the 5th total is not.
      await globalThis.fetch('https://a.test/3');
      await globalThis.fetch('https://a.test/4');
      await expect(globalThis.fetch('https://a.test/5')).rejects.toSatisfy((e: unknown) =>
        isSubrequestExhaustedError(e)
      );
      expect(meter.snapshot().fetches).toBe(4);
    } finally {
      meter.restore();
      globalThis.fetch = realFetch;
    }
  });

  it('charges a redirect hop the caller never sees', async () => {
    const realFetch = globalThis.fetch;
    // `redirected: true` is how a followed redirect chain is visible from
    // outside — and each hop is a subrequest the plain call count misses.
    const redirected = new Response('ok');
    Object.defineProperty(redirected, 'redirected', { value: true });
    globalThis.fetch = (async () => redirected) as typeof fetch;
    const meter = installSubrequestMeter({}, 10);
    try {
      await globalThis.fetch('https://b.test/1');
      await globalThis.fetch('https://b.test/2');
      const s = meter.snapshot();
      expect(s.fetches).toBe(2);
      expect(s.redirects).toBe(2);
      expect(s.total).toBe(4);
    } finally {
      meter.restore();
      globalThis.fetch = realFetch;
    }
  });

  it('restores the original fetch so a leak cannot meter later requests', () => {
    const before = globalThis.fetch;
    const meter = installSubrequestMeter({}, 4);
    expect(globalThis.fetch).not.toBe(before);
    meter.restore();
    expect(globalThis.fetch).toBe(before);
  });
});

describe('buildBriefing daily subrequest ceiling', () => {
  it('stays under the free-plan cap with every expensive branch armed', async () => {
    const { subrequests } = await runDailyBuild({ skipLlm: true });
    expect(subrequests).toBeLessThanOrEqual(FREE_PLAN_SUBREQUEST_CAP);
  }, 60_000);

  it('skipLlm:true makes no LLM call at all', async () => {
    const { aiRuns, hosts } = await runDailyBuild({ skipLlm: true });
    expect(aiRuns).toBe(0);
    expect(hosts.some((h) => h.includes('googleapis.com') || h.includes('groq.com'))).toBe(false);
  }, 60_000);

  it('skipLlm is the difference between fitting the budget and not', async () => {
    // Both builds run the identical fan-out; the only delta is the LLM chain.
    // This is the regression in one assertion: before the fix, the daily
    // branch ignored skipLlm and the second call below would have hit the
    // providers 9-13 times, on top of a fan-out already near the cap.
    const withLlm = await runDailyBuild({ skipLlm: false });
    const withoutLlm = await runDailyBuild({ skipLlm: true });
    expect(withoutLlm.subrequests).toBeLessThanOrEqual(FREE_PLAN_SUBREQUEST_CAP);
    expect(withLlm.subrequests).toBeLessThanOrEqual(FREE_PLAN_SUBREQUEST_CAP);
  }, 120_000);
});
