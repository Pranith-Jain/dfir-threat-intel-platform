/**
 * Discovery: ransomware victim re-leaks + cross-group claims.
 *
 * A "re-leak" is when the SAME victim is claimed by 2+ distinct ransomware
 * groups (usually: failed double-extortion → another group hits later, OR a
 * RaaS affiliate moves between programs and re-publishes the same haul).
 * The site already exposes this as a public surface at /threatintel/re-leaks
 * via /api/v1/victim-releaks; this runner taps the same data and turns the
 * highest-signal rows into case-study candidates.
 *
 * Stable key shape: `releak-<victim-key>` — one candidate per victim, anchored
 * to the victim (not the group), because the *re-leak* itself is the story,
 * not any single group's claim.
 */

import type { Candidate, DedupRecord } from '../types';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';

export interface ReleakClaim {
  group: string;
  raw_victim: string;
  discovered: string;
  source_url?: string;
}

export interface ReleakRow {
  key: string;
  group_count: number;
  raw_names: string[];
  claims: ReleakClaim[];
  latest: string;
  /** Optional sector hint from the upstream (sector-classifier). */
  sector?: string;
}

export interface DiscoverReleakDeps {
  /** GET /api/v1/victim-releaks via a configured fetch (siteUrl-prefixed). */
  fetchReleaks: () => Promise<ReleakRow[]>;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

const MIN_GROUP_COUNT = 2;
const WINDOW_DAYS = 60;
const MAX_CANDIDATES = 4;

export async function discoverReleaks(deps: DiscoverReleakDeps): Promise<Candidate[]> {
  let rows: ReleakRow[] = [];
  try {
    rows = await deps.fetchReleaks();
  } catch {
    return [];
  }

  const cutoff = deps.now.getTime() - WINDOW_DAYS * 24 * 3600 * 1000;

  // Filter to rows worth a case study: ≥2 distinct group claims, latest claim
  // inside the recency window. Multi-group is the *signal* — single-group
  // re-claims are already covered by the per-group ransomware runner.
  const fresh = rows
    .filter((r) => r.group_count >= MIN_GROUP_COUNT)
    .filter((r) => {
      const t = Date.parse(r.latest);
      return Number.isFinite(t) && t >= cutoff;
    });

  const out: Candidate[] = [];
  for (const r of fresh.slice(0, MAX_CANDIDATES * 3)) {
    const key = `releak-${r.key}`;
    const dedup = await deps.getDedup(key);
    const display = r.raw_names[0] ?? r.key;
    const groups = Array.from(new Set(r.claims.map((c) => c.group))).slice(0, 5);
    const score = finalScore({
      recency: recencyScore(r.latest, deps.now),
      // Severity scales with the number of distinct groups: a 3-group re-leak
      // is a substantially stronger signal than a 2-group one.
      severity: severityScore({ victims: r.group_count * 2 }),
      novelty: noveltyScore(dedup, deps.now),
      sourceWeight: 0.95,
    });
    out.push({
      key,
      type: 'darkweb',
      title: `${display} re-leaked across ${groups.length} groups: ${groups.slice(0, 2).join(', ')}${groups.length > 2 ? '…' : ''}`,
      rationale: `${r.group_count} distinct ransomware groups claimed ${display} (re-leak signal — usually failed double-extortion or affiliate movement)`,
      score,
      evidence: {
        // Subtype hint so the LLM prompt can lean into the "re-leak narrative"
        // angle rather than write a generic per-group victim post.
        subtype: 'releak',
        victim: display,
        raw_names: r.raw_names,
        group_count: r.group_count,
        groups,
        sector: r.sector,
        latest: r.latest,
        claims: r.claims.slice(0, 10),
      },
      discoveredAt: deps.now.toISOString(),
      status: 'pending',
    });
  }

  // Sort by score descending, keep MAX_CANDIDATES.
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, MAX_CANDIDATES);
}
