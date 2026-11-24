import type { Candidate } from '../types';

/** Deterministic PRNG (mulberry32). Same seed → same stream. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** FNV-1a hash of the UTC YYYY-MM-DD — stable within a day, varies across days. */
export function dateSeed(now: Date): number {
  const ymd = now.toISOString().slice(0, 10);
  let h = 2166136261;
  for (let i = 0; i < ymd.length; i += 1) {
    h ^= ymd.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * Pick up to `k` candidates, weighted by score, WITHOUT replacement.
 * The single highest-scored candidate is always included (a genuinely
 * critical item never gets sampled out); the remaining slots are
 * weighted-random so a thin, stable feed pool stops emitting the exact
 * same top-N every run. `rand` is injected so callers control the seed.
 */
export function weightedSampleByScore(cands: Candidate[], k: number, rand: () => number): Candidate[] {
  if (k <= 0) return [];
  if (cands.length <= k) return [...cands].sort((a, b) => b.score - a.score);
  const pool = [...cands].sort((a, b) => b.score - a.score);
  // pool.length > k >= 1, so shift() is always defined here
  const top = pool.shift()!;
  const chosen: Candidate[] = [top]; // guarantee top item
  while (chosen.length < k && pool.length > 0) {
    const total = pool.reduce((s, x) => s + Math.max(x.score, 0.01), 0);
    let r = rand() * total;
    let idx = 0;
    for (; idx < pool.length; idx += 1) {
      r -= Math.max(pool[idx]!.score, 0.01);
      if (r <= 0) break;
    }
    if (idx >= pool.length) idx = pool.length - 1;
    const picked = pool.splice(idx, 1)[0]!;
    chosen.push(picked);
  }
  return chosen;
}

/**
 * Order candidates round-robin by topic, optionally capped at `limit`.
 *
 * Types are ranked by their best candidate, items within a type stay
 * score-ordered, and the output takes one item from each type per round.
 * The round-robin preserves relative quality (the global top item is still
 * first) while guaranteeing every represented topic appears before any
 * topic repeats. `limit` is applied DURING the interleave — a plain
 * `slice()` after a global score sort would hand every slot to the
 * highest-scoring type (in practice, KEV CVEs) and undo the diversity.
 *
 * Shared by the discovery orchestrator (final daily cap) and the admin
 * pending list (display order).
 */
export function interleaveByType(cands: Candidate[], limit?: number): Candidate[] {
  const cap = limit === undefined ? Number.POSITIVE_INFINITY : Math.max(0, Math.floor(limit));
  if (cap === 0) return [];

  const byType = new Map<Candidate['type'], Candidate[]>();
  for (const c of cands) {
    const list = byType.get(c.type);
    if (list) list.push(c);
    else byType.set(c.type, [c]);
  }
  const groups = [...byType.values()];
  for (const g of groups) g.sort((a, b) => b.score - a.score);
  groups.sort((a, b) => (b[0]?.score ?? 0) - (a[0]?.score ?? 0));

  const out: Candidate[] = [];
  const max = groups.reduce((m, g) => Math.max(m, g.length), 0);
  outer: for (let i = 0; i < max; i++) {
    for (const g of groups) {
      const item = g[i];
      if (!item) continue;
      if (out.length >= cap) break outer;
      out.push(item);
    }
  }
  return out;
}
