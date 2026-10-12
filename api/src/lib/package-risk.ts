/**
 * Composite package risk score.
 *
 * `package-verdict` answers a binary question — malicious or not — which is
 * correct for what it is and useless for triage. A package with one unfixed
 * path-traversal advisory and a package with a trojanised maintainer release are
 * both `clean`/`malicious`, and they should never be on the same page of a
 * queue.
 *
 * This module produces a 0-100 score with a stated component breakdown, so a
 * number can be argued with rather than just obeyed.
 *
 * Design constraints that shaped the weights:
 *
 *  - **Malicious dominates.** A package confirmed in the OpenSSF malicious
 *    registry is not "severe", it is a different category. It gets a floor,
 *    not a bonus, so no amount of other signals can drag it down.
 *
 *  - **Missing fix outranks severity.** An unpatched critical is the thing you
 *    must act on today; a patched critical is a thing you must plan for.
 *
 *  - **Unscored is not zero.** A package OSV has never seen gets an explicit
 *    "unknown" component rather than a zero that reads as "safe".
 *
 *  - **Age decays.** An unpatched advisory from four years ago is less urgent
 *    than one from last week, because there has been four years to notice it
 *    and the environment has usually moved.
 *
 * Every weight below is commented with what it is trying to capture. A risk
 * score whose constants nobody can justify is a number nobody should trust.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

/** Highest CVSS base score in each severity band (CVSS v3.x ranges). */
const CVSS_BAND: Array<{ band: Exclude<Severity, 'unknown'>; min: number }> = [
  { band: 'critical', min: 9 },
  { band: 'high', min: 7 },
  { band: 'medium', min: 4 },
  { band: 'low', min: 0.1 },
];

export function cvssBand(score: number | null | undefined): Severity {
  if (score == null || !Number.isFinite(score)) return 'unknown';
  return CVSS_BAND.find((b) => score >= b.min)?.band ?? 'none';
}

export interface RiskInput {
  /** True when the package is in the OpenSSF malicious-packages registry. */
  malicious?: boolean;
  /** Highest CVSS across the package's advisories. */
  cvss?: number | null;
  /** Highest EPSS across the CVEs its advisories map to, 0-1. */
  epss?: number | null;
  /** Any mapped CVE is on the CISA KEV list. */
  kev?: boolean;
  /** At least one advisory has no fixed version available. */
  hasUnfixedAdvisory?: boolean;
  /** Days since the newest advisory was published. */
  newestAdvisoryAgeDays?: number | null;
  /** Advisory count, used only for a small "how much is known" nudge. */
  advisoryCount?: number;
}

export interface RiskComponent {
  key: string;
  /** Points this component contributed, before weighting. */
  points: number;
  /** What that points value is worth out of 100. */
  weight: number;
  detail: string;
}

export interface RiskAssessment {
  /** 0-100. Higher is worse. */
  score: number;
  band: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
  verdict: 'malicious' | 'act-now' | 'schedule' | 'monitor' | 'clean' | 'unknown';
  components: RiskComponent[];
  /** One-line rationale for the top contributing factor. */
  rationale: string;
  /** Stated so a consumer cannot present the number without its caveats. */
  caveat: string;
}

/**
 * Component weights. Sum to 100.
 *
 * malicious 40 / exploitability 25 / unfixed 20 / kev 10 / volume 5.
 */
const WEIGHTS = {
  malicious: 40,
  exploitability: 25,
  unfixed: 20,
  kev: 10,
  volume: 5,
} as const;

/** Advisory age at which the urgency weight has halved. */
const DECAY_HALF_LIFE_DAYS = 180;

/**
 * Exponential decay on urgency by advisory age.
 *
 * A half-life rather than a linear ramp because the difference between "1 day
 * old" and "30 days old" matters far more than the difference between "300 days
 * old" and "329 days old". A linear scale would still be near-full weight at a
 * year, which is not how unpatched-advisory risk behaves.
 */
function ageDecay(ageDays: number | null | undefined): number {
  if (ageDays == null || !Number.isFinite(ageDays) || ageDays < 0) return 1;
  return Math.pow(0.5, ageDays / DECAY_HALF_LIFE_DAYS);
}

export function assessPackageRisk(input: RiskInput): RiskAssessment {
  const components: RiskComponent[] = [];

  // ── malicious ─────────────────────────────────────────────────────
  if (input.malicious) {
    components.push({
      key: 'malicious',
      points: 1,
      weight: WEIGHTS.malicious,
      detail: 'Package is listed in the OpenSSF malicious-packages registry',
    });
  } else {
    components.push({
      key: 'malicious',
      points: 0,
      weight: WEIGHTS.malicious,
      detail: 'Not in the OpenSSF malicious-packages registry',
    });
  }

  // ── exploitability: CVSS and EPSS folded together ─────────────────
  // Both describe "how bad and how likely", and taking the max of the two
  // normalised values rather than a weighted blend stops a high CVSS with no
  // EPSS data from being diluted into invisibility by the absence of data.
  const decay = ageDecay(input.newestAdvisoryAgeDays);
  const cvssNorm = input.cvss != null && Number.isFinite(input.cvss) ? Math.min(1, input.cvss / 10) : null;
  const epssNorm = input.epss != null && Number.isFinite(input.epss) ? Math.min(1, Math.max(0, input.epss)) : null;
  const observed = cvssNorm ?? epssNorm;
  const exploitability = observed == null ? null : Math.max(cvssNorm ?? 0, epssNorm ?? 0) * decay;

  components.push({
    key: 'exploitability',
    points: exploitability == null ? 0 : Number(exploitability.toFixed(3)),
    weight: WEIGHTS.exploitability,
    detail:
      exploitability == null
        ? 'No CVSS or EPSS data — scored as unknown, not as zero'
        : `CVSS ${input.cvss ?? 'n/a'}, EPSS ${input.epss == null ? 'n/a' : `${(input.epss * 100).toFixed(1)}%`}` +
          (decay < 1 ? `, decayed x${decay.toFixed(2)} for age` : ''),
  });

  // ── unfixed ──────────────────────────────────────────────────────
  const unfixed = input.hasUnfixedAdvisory === true;
  components.push({
    key: 'unfixed',
    points: unfixed ? 1 : 0,
    weight: WEIGHTS.unfixed,
    detail: unfixed ? 'At least one advisory has no fixed version' : 'All advisories have a fixed version',
  });

  // ── KEV ──────────────────────────────────────────────────────────
  components.push({
    key: 'kev',
    points: input.kev ? 1 : 0,
    weight: WEIGHTS.kev,
    detail: input.kev ? 'A mapped CVE is on the CISA KEV list' : 'No mapped CVE is on the CISA KEV list',
  });

  // ── volume ───────────────────────────────────────────────────────
  // Small by design. "Lots of advisories" is weak evidence on its own — a
  // popular package has more advisories because more people look at it — so
  // this is capped low enough that it can never flip a verdict on its own.
  const count = Math.max(0, Math.min(10, input.advisoryCount ?? 0));
  components.push({
    key: 'volume',
    points: Number((count / 10).toFixed(2)),
    weight: WEIGHTS.volume,
    detail: `${input.advisoryCount ?? 0} advisories on record`,
  });

  const raw = components.reduce((sum, c) => sum + c.points * c.weight, 0);
  // A confirmed-malicious package cannot be argued down by weak other signals.
  // The floor is 85, not 100: the score should still be able to express "how
  // bad, specifically", but nothing else may push it into the ordinary range.
  const score = input.malicious ? Math.max(85, Math.min(100, raw)) : Math.min(100, Number(raw.toFixed(1)));

  const band: RiskAssessment['band'] = input.malicious
    ? 'critical'
    : score >= 70
      ? 'critical'
      : score >= 45
        ? 'high'
        : score >= 20
          ? 'medium'
          : score > 0
            ? 'low'
            : 'informational';

  const anySignal =
    input.malicious === true ||
    unfixed ||
    input.kev === true ||
    exploitability != null ||
    (input.advisoryCount ?? 0) > 0;

  // Severity bands gate the escalation, because the weighted score alone is too
  // blunt at the top end: an unpatched CVSS 9.8 lands around 44 points, which
  // on score alone would read as "monitor". It is not. An unpatched critical
  // with no known exploitability data is the case most worth surfacing, because
  // the absence of an EPSS record is exactly when you least want to assume.
  const severity = cvssBand(input.cvss);
  const severeAndUnfixed = unfixed && (severity === 'critical' || severity === 'high');

  const verdict: RiskAssessment['verdict'] = input.malicious
    ? 'malicious'
    : !anySignal
      ? 'unknown'
      : input.kev || severeAndUnfixed || score >= 70
        ? 'act-now'
        : unfixed && score >= 45
          ? 'schedule'
          : score >= 20 || (input.advisoryCount ?? 0) > 0
            ? 'monitor'
            : 'clean';

  const top = [...components].sort((a, b) => b.points * b.weight - a.points * a.weight)[0];

  return {
    score,
    band,
    verdict,
    components,
    rationale: top && top.points > 0 ? top.detail : 'No risk signals found for this package',
    caveat:
      'Composite of OpenSSF malicious-registry membership, CVSS, EPSS, fix availability, CISA KEV membership and advisory volume. It is a triage aid, not a vulnerability count: a package with no advisories is not thereby safe, only unexamined.',
  };
}

/**
 * SLA recommendation, derived from the verdict.
 *
 * Separate from the score so the urgency language ("patch in 7 days") is written
 * once and cannot drift from the number that produced it.
 */
export function remediationSla(verdict: RiskAssessment['verdict']): { window: string; action: string } {
  switch (verdict) {
    case 'malicious':
      return {
        window: 'immediate',
        action: 'Remove or pin to a known-good version. Assume the installed copy is compromised until verified.',
      };
    case 'act-now':
      return { window: '7 days', action: 'Patch or isolate. A mapped CVE is confirmed exploited in the wild.' };
    case 'schedule':
      return { window: '30 days', action: 'Schedule a fix. Unpatched advisory above the schedule threshold.' };
    case 'monitor':
      return { window: 'next maintenance', action: 'Track for a fix. No exploitation signal.' };
    case 'unknown':
      return {
        window: 'n/a',
        action: 'No advisory data. Verify the package is real and not a typosquat before trusting it.',
      };
    case 'clean':
    default:
      return { window: 'none', action: 'No action indicated by available data.' };
  }
}
