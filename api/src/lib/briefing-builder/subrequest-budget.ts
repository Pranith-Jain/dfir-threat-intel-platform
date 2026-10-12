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
