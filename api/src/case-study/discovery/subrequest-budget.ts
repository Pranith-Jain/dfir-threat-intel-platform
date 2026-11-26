/**
 * Counted subrequest budget for one discovery invocation.
 *
 * The Workers Free plan allows 50 subrequests per invocation, and discovery
 * shares that ceiling with candidate persistence and dedup writes. Before this
 * existed, `discoverCves` alone spent ~53 (1 KEV fetch + 26 NVD lookups + 26
 * NVD HEAD probes), exhausting the account before the later runners fetched
 * anything. Each runner swallowed the resulting "Too many subrequests" in its
 * own catch, so the admin saw a quiet all-CVE queue rather than a failure.
 *
 * Only the two heavy runners (`cve`, `trends`) spend through the budget today;
 * the seam is generic so a runner can opt in as its fan-out grows. The
 * orchestrator reads `wasStarved(name)` after every batch — runners must not
 * be trusted to report it themselves, because their defensive catches turn a
 * thrown budget error into an empty candidate list.
 */

/** Runner allowance. The headroom is for persistence, dedup and SELF calls. */
export const DISCOVERY_SUBREQUEST_LIMIT = 38;

export class SubrequestExhaustedError extends Error {
  constructor(readonly runner: string) {
    super(`subrequest budget exhausted for ${runner}`);
    this.name = 'SubrequestExhaustedError';
  }
}

export interface SubrequestBudget {
  /** Spend `n` units for `runner`, or throw without spending them. */
  spend(runner: string, n?: number): void;
  /** Units consumed so far. */
  used(): number;
  /** Units still available to runners. */
  remaining(): number;
  /** True once this runner was denied at least one spend. */
  wasStarved(runner: string): boolean;
  /** Names of every starved runner, in first-starved order. */
  starvedNames(): string[];
}

export function createSubrequestBudget(limit = DISCOVERY_SUBREQUEST_LIMIT): SubrequestBudget {
  let usedUnits = 0;
  const starved = new Set<string>();
  return {
    spend(runner, n = 1) {
      if (usedUnits + n > limit) {
        starved.add(runner);
        throw new SubrequestExhaustedError(runner);
      }
      usedUnits += n;
    },
    used: () => usedUnits,
    remaining: () => Math.max(0, limit - usedUnits),
    wasStarved: (runner) => starved.has(runner),
    starvedNames: () => [...starved],
  };
}
