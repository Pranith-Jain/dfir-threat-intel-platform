import type { DedupRecord } from './types';

const DAY_MS = 24 * 3600 * 1000;
const FOURTEEN_DAYS = 14 * DAY_MS;
const NINETY_DAYS = 90 * DAY_MS;

export function recencyScore(eventIso: string, now: Date): number {
  const age = now.getTime() - new Date(eventIso).getTime();
  if (age <= DAY_MS) return 1.0;
  if (age >= FOURTEEN_DAYS) return 0;
  return 1 - (age - DAY_MS) / (FOURTEEN_DAYS - DAY_MS);
}

export interface SeverityInput {
  cvss?: number;
  kev?: boolean;
  victims?: number;
  /**
   * Distinct independent sources describing the same event (threat-pulse
   * `source_count`, multi-outlet coverage). Scored on the same scale as
   * `victims` — the semantic is identical ("how much independent signal is
   * there"), the alias keeps call sites honest about what the number is.
   */
  mentions?: number;
}

/** A numeric input that is actually usable. `undefined` and `NaN` both mean
 *  "no signal" — reading a field name the upstream API does not return
 *  produces NaN, and a NaN severity used to propagate through finalScore
 *  into the candidate queue where it broke score ordering silently. */
function finiteNumber(n: unknown): n is number {
  return typeof n === 'number' && Number.isFinite(n);
}

export function severityScore(input: SeverityInput): number {
  if (input.kev) return 1.0;
  if (finiteNumber(input.cvss)) return Math.min(1, Math.max(0, input.cvss / 10));
  const n = finiteNumber(input.victims) ? input.victims : input.mentions;
  if (finiteNumber(n)) return Math.min(1, Math.max(0, n / 5));
  return 0.3;
}

// ── Text-derived severity ────────────────────────────────────────────────

/**
 * Severity for candidates whose only signal is prose (RSS titles, advisories
 * without a CVSS, underground claims).
 *
 * Before this existed every RSS-backed runner passed `severityScore({})` and
 * got the flat 0.3 floor, while the CVE runner passed cvss/kev (-> 1.0) and
 * the leak runners passed victim counts (-> 1.0). With severity weighted 0.30
 * in the final score, that meant ONLY CVEs and leak rows could ever outrank
 * the floor: a multi-outlet story about an actively exploited appliance lost
 * to a CVSS 5 CVE that merely had a number attached. The queue read as
 * "CVEs and leaks first, everything else filler" — which was true.
 *
 * The tiers encode the exploitation/impact ladder defenders actually triage
 * by (CISA KEV > in-the-wild exploitation > ransomware/credential economy >
 * critical/APT campaigns > patch noise). The highest matching tier wins;
 * signals do not stack, because stacking rewards keyword-stuffed titles.
 */
const SEVERITY_TEXT_TIERS: Array<{ tier: number; re: RegExp }> = [
  // 1.0 — confirmed exploitation. The strongest thing a headline can say.
  { tier: 1.0, re: /\bactively exploit(ed|ing|ation)?\b/i },
  { tier: 1.0, re: /\bexploited in the wild\b/i },
  { tier: 1.0, re: /\bknown exploited vulnerab/i },
  { tier: 1.0, re: /\bcisa (adds|added|lists|listed)\b/i },
  // 0.9 — weaponisation and the criminal economy in motion.
  { tier: 0.9, re: /\bzero-?day\b[\s\S]{0,80}\bexploit/i },
  { tier: 0.9, re: /\bexploit\b[\s\S]{0,80}\bzero-?day\b/i },
  { tier: 0.9, re: /\bransomware (attack|gang|group|operators?|campaign)\b/i },
  { tier: 0.9, re: /\b(takedown|arrest(ed|s)?|charged|seized|seizes)\b/i },
  { tier: 0.9, re: /\bsupply[- ]chain\b[\s\S]{0,80}\b(backdoor|compromise|implant)\b/i },
  // 0.8 — data exposure and the credential economy.
  {
    tier: 0.8,
    re: /\b\d[\d,.]*\+?\s*(million|billion)?\s*(records|rows|accounts|users|credentials|emails|victims)\b/i,
  },
  { tier: 0.8, re: /\b(leak(ed|ing|s)?)\b[\s\S]{0,60}\b\d[\d,.]*\b/i },
  { tier: 0.8, re: /\bstolen (data|credentials|database)\b/i },
  { tier: 0.8, re: /\baccess (broker|sales?|listing)\b/i },
  { tier: 0.8, re: /\bdata (breach|exposure|dump)\b/i },
  // 0.7 — critical severity and attributed campaigns.
  { tier: 0.7, re: /\bcritical(ly)?\b/i },
  { tier: 0.7, re: /\bAPT\b/ },
  { tier: 0.7, re: /\bthreat (actor|group)s?\b/i },
  { tier: 0.7, re: /\b(new|novel) (backdoor|implant|stealer|botnet|rat|loader)\b/i },
  { tier: 0.7, re: /\battribut(e|es|ed|ing|ion)\b/i },
  { tier: 0.7, re: /\bcve-\d{4}-\d{4,7}\b/i },
  // 0.55 — routine security-reporting signals above the floor.
  { tier: 0.55, re: /\b(malware|phishing|infostealer|stealer|botnet|ransomware)\b/i },
  { tier: 0.55, re: /\b(patches?|patched|advisory|vulnerab|exploit)\b/i },
];

/** Highest matching tier, else the 0.3 "no structured signal" floor. */
export function severityFromText(text: string): number {
  if (!text) return 0.3;
  for (const { tier, re } of SEVERITY_TEXT_TIERS) {
    if (re.test(text)) return tier;
  }
  return 0.3;
}

export function noveltyScore(prev: DedupRecord | null, now: Date): number {
  if (!prev) return 1.0;
  const age = now.getTime() - new Date(prev.lastSeenAt).getTime();
  if (age <= 0) return 0; // Future or same-instant timestamp → fully penalized
  if (age >= NINETY_DAYS) return 1.0;
  // Exponential decay: items seen today get ~0, items seen a week ago get ~0.3
  // This strongly penalizes recently seen content to prevent repetition.
  const normalizedAge = age / NINETY_DAYS;
  return Math.max(0, Math.pow(normalizedAge, 0.5));
}

export interface FinalScoreInput {
  recency: number;
  severity: number;
  novelty: number;
  sourceWeight: number; // 0..1
}

export function finalScore({ recency, severity, novelty, sourceWeight }: FinalScoreInput): number {
  // Non-finite components (a NaN from a drifted field mapping, an undefined
  // recency) count as zero rather than poisoning the whole weighted sum: a
  // NaN score is unorderable and silently corrupts queue selection.
  const r = Number.isFinite(recency) ? recency : 0;
  const s = Number.isFinite(severity) ? severity : 0;
  const n = Number.isFinite(novelty) ? novelty : 0;
  const w = Number.isFinite(sourceWeight) ? sourceWeight : 0;
  // Novelty weight increased from 0.25 to 0.35 to strongly penalize
  // recently seen items and prevent repetition in discovery.
  const weighted = 0.25 * r + 0.3 * s + 0.35 * n + 0.1 * w;
  return Number(weighted.toFixed(4));
}

export interface TrendingAwareScoreInput extends FinalScoreInput {
  trending?: number;
}

export function finalScoreWithTrending({
  recency,
  severity,
  novelty,
  sourceWeight,
  trending,
}: TrendingAwareScoreInput): number {
  if (typeof trending !== 'number' || !Number.isFinite(trending)) {
    return finalScore({ recency, severity, novelty, sourceWeight });
  }
  const r = Number.isFinite(recency) ? recency : 0;
  const s = Number.isFinite(severity) ? severity : 0;
  const n = Number.isFinite(novelty) ? novelty : 0;
  const w = Number.isFinite(sourceWeight) ? sourceWeight : 0;
  // Novelty weight increased to strongly penalize recently seen items
  const weighted = 0.2 * r + 0.2 * s + 0.3 * n + 0.1 * w + 0.2 * trending;
  return Number(weighted.toFixed(4));
}
