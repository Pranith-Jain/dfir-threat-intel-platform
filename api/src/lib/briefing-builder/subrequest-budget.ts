/**
 * Explicit subrequest budget for `buildBriefing`.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every Worker invocation on the free plan is capped at 50 subrequests, and
 * exceeding the cap is fatal to the WHOLE invocation: Cloudflare aborts it and
 * the client sees HTTP 503. It is not a per-fetch error the build can catch —
 * there is no response to catch, the invocation simply dies. That is exactly
 * what killed the daily briefings: each new source added to the fan-out (dbu.gs,
 * the AI honeypot + LLM-abuse feeds, Daily-Hunt, Webamon, the OSSF per-commit
 * file lists) pushed the build's real cost past 50, so `30 0 * * *` wrote
 * nothing and `POST /api/v1/briefings/build` answered 503 for the operator.
 *
 * The build is a DEGRADABLE pipeline — every source already has a fallback and
 * a source that returns nothing simply omits its section. All it lacked was a
 * way to stop spending once the invocation was nearly out of budget. That is
 * what this provides: sources are admitted in priority order, each charging an
 * estimated cost up front, and anything that no longer fits is skipped with its
 * fallback instead of taking the whole invocation down with it.
 *
 * The costs are ESTIMATES, not measurements. Workers exposes no runtime
 * subrequest counter, so they are sized to the worst case each source can reach
 * (redirect hops, the per-commit GitHub file lists, the last-good KV write-back)
 * and the cap sits below the platform limit to absorb what the estimates miss.
 *
 * This mirrors the existing `BUDGET_SOFT_CAP` planner in worker/scheduled.ts —
 * same idea, same "admit greedily, log what was deferred" discipline — applied
 * to the one invocation that has no other guard.
 */

/** Free-plan hard cap per Worker invocation. */
export const FREE_PLAN_SUBREQUEST_CAP = 50;

/**
 * What the briefing build may spend.
 *
 * Below the cap by a margin that covers the costs we cannot model from here:
 * redirect hops, the `cache.match`/`cache.put` pairs a few sources do, the NVD
 * pagination loop, and the `writeBriefing` INSERT itself. Sized against a
 * measured worst case — every source returning data, the NVD pagination and
 * the OSSF per-commit loop both at full extent, the LLM chain fully walked —
 * which totals ~40 subrequests with the fan-out unbounded.
 */
export const BUILD_SUBREQUEST_BUDGET = 42;

export interface BuildSubrequestBudget {
  /**
   * Charge `cost` subrequests. Returns false — WITHOUT charging — when the
   * charge would not fit, which is the caller's signal to skip the source and
   * use its fallback.
   */
  afford(cost: number): boolean;
  /** Subrequests still unspent. */
  remaining(): number;
  /** Subrequests charged so far. */
  spent(): number;
}

export function createBuildSubrequestBudget(limit: number = BUILD_SUBREQUEST_BUDGET): BuildSubrequestBudget {
  let spent = 0;
  return {
    afford(cost: number): boolean {
      if (!Number.isFinite(cost) || cost <= 0) return true;
      if (spent + cost > limit) return false;
      spent += cost;
      return true;
    },
    remaining: () => limit - spent,
    spent: () => spent,
  };
}

/**
 * Estimated subrequest cost per source, sized to the source's worst case and
 * calibrated against a measured full-fan-out run.
 *
 * These numbers are the reason the ordering of the fan-out in `buildBriefing`
 * is load-bearing: `Promise.all` evaluates its array left to right, so the
 * budget is charged in source-priority order and the first sources to lose
 * their slot when the budget runs dry are the ones listed last there.
 */
export const BUILD_SOURCE_COST = {
  /** CISA KEV: fetch + last-good KV write-back (+ KV read on the error path). */
  kev: 3,
  /** NVD bulk window (1 page typical, up to 4 with retries) + last-good. */
  nvd: 4,
  /** 9 tracker endpoints fanned out inside `fetchRansomwareRecent`. */
  ransomware: 9,
  /** abuse.ch + AI-abuse IOC feeds: fetch + last-good KV write-back each. */
  iocFeed: 2,
  /** The warmed AI/LLM intel slice is a single KV read. */
  aiLlmSlice: 1,
  /** VulnTracker: per-day digest + 30-day archive + blog RSS. */
  vulnTracker: 3,
  /** Webamon: 4 parallel endpoints (stats, campaigns, changes, clusters). */
  webamon: 4,
  /** GitHub commits list + one file-list call per commit (MAX_COMMITS). */
  ossfMaliciousPackages: 4,
  /** The threat-intel manifest, read through the ASSETS binding. */
  dailyHunt: 1,
  /** Single-request sources. */
  single: 1,
  /** One NVD lookup per KEV CVE that the bulk window didn't already cover. */
  nvdById: 1,
  /** The LLM provider chain (Gemini models, then Groq models, then Workers AI). */
  llmSummary: 12,
} as const;

/**
 * Subrequests the briefing build must leave for everything AROUND it.
 *
 * The 50 is per INVOCATION, not per handler, and the build is not the whole
 * invocation. On the admin path, measured in `wrangler tail`:
 *   - the rate limiter runs first on a POST (a `caches.default.match`, the
 *     admin and AI counter DOs, and their cache write-backs),
 *   - `writeBriefing` runs after: the upsert plus `stampRelatedBriefings`'
 *     json_extract scan over the recent-briefing pool,
 *   - `purgeBriefingDetailCache` then issues two cache deletes.
 *
 * Sixteen is deliberately generous. The first version of this guard reserved 10
 * and the admin build still died, because a build that spends exactly its own
 * budget has spent the INVOCATION's budget — the reserve is not slack, it is
 * the other half of the same 50.
 */
export const SUBREQUESTS_RESERVED_FOR_SURROUND = 16;

/**
 * Thrown by the meter when an invocation is out of subrequest budget.
 *
 * Distinct from the platform's own error so `admit` can tell "this source was
 * cut because we ran out" (recoverable — use the fallback) apart from "this
 * source's upstream threw" (also recoverable, but worth logging differently).
 */
export class SubrequestExhaustedError extends Error {
  readonly used: number;
  readonly cap: number;
  constructor(used: number, cap: number) {
    super(`subrequest budget exhausted (${used}/${cap})`);
    this.name = 'SubrequestExhaustedError';
    this.used = used;
    this.cap = cap;
  }
}

export function isSubrequestExhaustedError(e: unknown): boolean {
  return e instanceof SubrequestExhaustedError;
}

export interface SubrequestSnapshot {
  /** Fetches issued (one per `fetch()` call, not per redirect hop). */
  fetches: number;
  /** Extra hops charged for redirect chains followed by `fetch()`. */
  redirects: number;
  /** KV / Cache / D1 operations observed through the metered bindings. */
  bindingOps: number;
  total: number;
  cap: number;
  /** Per-host fetch counts — the "which upstream is eating the budget" view. */
  byHost: Record<string, number>;
}

export interface SubrequestMeter {
  snapshot(): SubrequestSnapshot;
  /** Put the original `fetch` and bindings back. Always call this. */
  restore(): void;
}

/**
 * Count the subrequests a build actually makes, and refuse the ones past `cap`.
 *
 * WHY THIS EXISTS RATHER THAN THE ESTIMATES ALONE
 * ------------------------------------------------
 * The static `BUILD_SOURCE_COST` table is an ESTIMATE, and estimates were
 * exactly what let this ship broken: a local probe measured the fan-out at 33
 * subrequests while production died at the 50 cap. The gap is invisible from
 * outside a `fetch()` call —
 *   - **redirect hops.** `fetch()` follows redirects internally and returns the
 *     FINAL response, so a 301 chain costs N subrequests and shows up as one
 *     call. Per Cloudflare's limits page, "each subrequest in a redirect chain
 *     counts against this limit". abuse.ch, ransomlook and the ransomware
 *     trackers redirect freely, and none of it is visible to a wrapper.
 *   - **`fetchResilient` retries.** `attempts: 3` on the KEV feed means a 5xx
 *     costs three.
 *   - **key-gated sources.** Webamon, MyThreatIntel and the OSSF commit loop
 *     only run when their secrets are present, so a probe without prod secrets
 *     never sees their cost.
 *
 * So: the meter wraps `fetch` for the duration of the build, charges redirects
 * and retries as they really happen, and THROWS past the cap. Because that
 * throw happens inside a source's own promise, `admit`'s `.catch` turns it into
 * that source's fallback — the build sheds a section instead of the invocation
 * dying. `Response.redirected` reports whether a chain was followed but not its
 * length, so each redirected response is charged one extra; the cap carries
 * margin for multi-hop chains.
 *
 * Binding ops (KV/Cache/D1) are counted by wrapping the objects on `env` for
 * the duration too, since those are subrequests as well.
 */
export function installSubrequestMeter(
  env: Record<string, unknown>,
  cap: number = FREE_PLAN_SUBREQUEST_CAP - SUBREQUESTS_RESERVED_FOR_SURROUND
): SubrequestMeter {
  const realFetch = globalThis.fetch;
  const byHost: Record<string, number> = {};
  let fetches = 0;
  let redirects = 0;
  let bindingOps = 0;

  const charge = (): void => {
    if (fetches + redirects + bindingOps >= cap) {
      throw new SubrequestExhaustedError(fetches + redirects + bindingOps, cap);
    }
  };

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    charge();
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    let host = 'unknown';
    try {
      host = new URL(raw).host;
    } catch {
      /* relative/internal URL — still counts, just not attributable */
    }
    byHost[host] = (byHost[host] ?? 0) + 1;
    fetches += 1;
    const res = await realFetch(input as RequestInfo, init);
    // A followed redirect costs extra subrequests that this wrapper never sees
    // individually; charge one for the chain.
    if (res.redirected) redirects += 1;
    return res;
  }) as typeof fetch;

  // KV / Cache / D1. Each method that issues a request is wrapped; the originals
  // are restored verbatim on `restore()`. The marker makes the wrap idempotent:
  // the bindings live on the shared `env` object, so a second install that
  // captured an already-wrapped function would leave a stale wrapper behind
  // after both restores ran.
  const originals: Array<[object, string, unknown]> = [];
  const WRAPPED = Symbol.for('briefing.subrequestMeter');
  const wrapOps = (obj: unknown, methods: string[]): void => {
    if (!obj || (typeof obj !== 'object' && typeof obj !== 'function')) return;
    if ((obj as Record<symbol, unknown>)[WRAPPED]) return;
    let touched = false;
    for (const m of methods) {
      const fn = (obj as Record<string, unknown>)[m];
      if (typeof fn !== 'function') continue;
      originals.push([obj as object, m, fn]);
      (obj as Record<string, unknown>)[m] = function (...args: unknown[]) {
        charge();
        bindingOps += 1;
        return (fn as (...a: unknown[]) => unknown).apply(obj, args);
      };
      touched = true;
    }
    if (touched) (obj as Record<symbol, unknown>)[WRAPPED] = true;
  };
  wrapOps(env.KV_CACHE, ['get', 'getWithMetadata', 'put', 'list', 'delete']);
  wrapOps(env.BRIEFINGS_DB, ['prepare', 'batch', 'exec']);
  if (env.CACHES_DEFAULT && typeof env.CACHES_DEFAULT === 'object') {
    wrapOps(env.CACHES_DEFAULT, ['match', 'put', 'delete']);
  }

  return {
    snapshot: () => ({
      fetches,
      redirects,
      bindingOps,
      total: fetches + redirects + bindingOps,
      cap,
      byHost: { ...byHost },
    }),
    restore: () => {
      globalThis.fetch = realFetch;
      for (const [obj, key, fn] of originals) {
        (obj as Record<string, unknown>)[key] = fn;
        delete (obj as Record<symbol, unknown>)[WRAPPED];
      }
    },
  };
}
