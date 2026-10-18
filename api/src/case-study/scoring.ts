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
  if (finiteNumber(input.victims)) return Math.min(1, Math.max(0, input.victims / 5));
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
