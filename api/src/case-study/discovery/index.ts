import type { Candidate } from '../types';
import { candidateUsesBlockedSource } from '../source-blocklist';

export interface RunDiscoveryDeps {
  /** Topic name → runner. Generic so new topics (breach, scam, aisec,
   *  intel, …) slot in without changing the orchestrator. */
  runners: Record<string, () => Promise<Candidate[]>>;
  putCandidate: (c: Candidate) => Promise<void>;
  /** Mark all kept stable-keys "seen" in ONE batched read+write. */
  commitDedup: (keys: string[], now: Date) => Promise<void>;
  now: Date;
  /**
   * Max candidates kept *per topic* (default 3). Selection is per-topic, not
   * a global top-N — a global slice let the highest-scoring topic (usually
   * `actor`) crowd every other topic out of the queue. Per-topic selection
   * guarantees every topic that produced candidates is represented.
   */
  perTopic?: number;
  /**
   * Optional overall cap applied AFTER per-topic selection. Unset = no extra
   * cap (the per-topic limits already bound the total to perTopic × topics).
   */
  limit?: number;
  /**
   * Hard novelty gate. Returns true if a candidate key was already
   * surfaced/published recently and must NOT be re-suggested yet.
   *
   * The candidate is passed alongside its key because some gates are properties
   * of the candidate rather than of its history — e.g. a fresh CISA-KEV
   * addition is "suppressed" because the KEV auto-publish job owns it for the
   * next 48h, not because it was seen before.
   */
  isSuppressed?: (key: string, candidate: Candidate) => boolean;
  /**
   * Per-topic selector. Default = strict top-N by score.
   */
  selectPerTopic?: (cands: Candidate[], k: number, topic: string) => Candidate[];
  /**
   * Per-topic override for `perTopic`.
   */
  perTopicOverride?: Record<string, number>;
  /**
   * Daily floor. When the strict pass keeps fewer than this many candidates,
   * the top-up below refills from the runners' already-fetched pool. Unset =
   * no floor (previous behaviour).
   *
   * A floor rather than a bigger `perTopic`: the queue was coming back with
   * 2-3 items because the anti-repetition gate suppressed everything the
   * runners returned, not because the per-topic budget was full. Raising the
   * budget alone changes nothing when the gate is what emptied the pool.
   */
  minKept?: number;
  /**
   * Gate for the top-up pass: may this *suppressed* candidate be re-offered to
   * reach the floor? The caller owns the policy (in run.ts it means "never
   * republish; allow items whose last surfacing is older than N days"), which
   * is why it is injected rather than a window constant here.
   */
  admitSuppressed?: (c: Candidate) => boolean;
  /**
   * In-place ordering for the top-up pool. Default = score desc; run.ts sorts
   * by how long ago each key was last surfaced instead, so the floor is filled
   * with genuinely stale items rather than the strict pass's runners-up.
   */
  rankTopUp?: (pool: Candidate[]) => void;
}

export interface RunDiscoveryResult {
  total: number;
  kept: number;
  /** Candidates dropped by the hard novelty gate (anti-repetition). */
  suppressed: number;
  /** Candidates dropped because they came from a barred source. */
  blocked: number;
  /**
   * Of `kept`, how many came from the top-up pass (i.e. were suppressed by the
   * strict gate and re-admitted to reach `minKept`). 0 = the day was not thin.
   * Logged so "the queue is thin again" is distinguishable from "the floor is
   * being carried by re-surfaced items every day".
   */
  filledFromSuppressed: number;
  /** Candidates dropped by cross-runner URL dedup. */
  deduped: number;
  ids: string[];
  /** Kept count per topic — recomputed AFTER URL dedup + global cap so
   *  the admin sees the real topic mix, not the pre-dedup selection. */
  byTopic: Record<string, number>;
  /** Per-topic counts BEFORE URL dedup and global cap. Useful for
   *  diagnosing a runner that gets cannibalised by another runner that
   *  surfaces the same article (e.g. intel + news on the same CVE writeup).
   *  If selected >> kept for a topic, split that topic into sub-topics
   *  or lower its perTopic budget. */
  byTopicSelected: Record<string, number>;
}

export async function runDiscovery(deps: RunDiscoveryDeps): Promise<RunDiscoveryResult> {
  const perTopic = deps.perTopic ?? 3;
  const isSuppressed = deps.isSuppressed ?? (() => false);
  // Pre-dedup per-topic counts — see RunDiscoveryResult.byTopicSelected.
  const byTopicSelected: Record<string, number> = {};
  let total = 0;
  let suppressed = 0;
  let blocked = 0;
  let selected: Candidate[] = [];
  // Per-topic bags of everything each runner returned, kept so the top-up pass
  // can refill from candidates already in memory. Calling the runners again for
  // the floor would pay their subrequests twice.
  const bags: Record<string, { suppressed: Candidate[] }> = {};
  const entries = Object.entries(deps.runners);

  // Run up to 4 runners in parallel per batch to stay within subrequest
  // budget while reducing wall-clock time vs sequential iteration.
  const BATCH_SIZE = 4;
  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(async ([name, runner]) => {
        const t0 = performance.now();
        try {
          const out = await runner();
          return { name, cands: out, error: null, ms: Math.round(performance.now() - t0) };
        } catch (err) {
          return { name, cands: [] as Candidate[], error: err, ms: Math.round(performance.now() - t0) };
        }
      })
    );
    for (const { name, cands, error } of batchResults) {
      if (error) {
        byTopicSelected[name] = 0;
        bags[name] = { suppressed: [] };
        continue;
      }
      total += cands.length;
      // Barred sources never enter the queue (see source-blocklist.ts). Applied
      // here, at the boundary, so no runner can surface one by accident.
      const allowed = cands.filter((c) => {
        if (candidateUsesBlockedSource(c)) {
          blocked += 1;
          return false;
        }
        return true;
      });
      // Drop already-surfaced keys BEFORE selection so a fresher,
      // lower-scored candidate can take the slot instead of the same
      // recurring story.
      const gateSuppressed = allowed.filter((c) => isSuppressed(c.key, c));
      suppressed += gateSuppressed.length;
      const fresh = allowed.filter((c) => !isSuppressed(c.key, c));
      bags[name] = { suppressed: gateSuppressed };
      const topicPerTopic = deps.perTopicOverride?.[name] ?? perTopic;
      const select =
        deps.selectPerTopic ?? ((cs: Candidate[], k: number) => [...cs].sort((a, b) => b.score - a.score).slice(0, k));
      const top = select(fresh, topicPerTopic, name);
      byTopicSelected[name] = top.length;
      selected.push(...top);
    }
  }

  // Cross-runner URL dedup: same article discovered by two different runners
  // (e.g. intel + news) produces different stable-keys but the same evidence.url.
  // Keep only the highest-scored candidate per URL so we don't waste LLM
  // generation on duplicate content with different labels.
  // Expanded to check evidence.urls[] (cve, actor), evidence.sources[]
  // (agentic-trends, briefing, platform-data), and evidence.cveId (construct NVD
  // URL) so CVE runners dedup against RSS/article runners that cite the same CVE.
  // URL normalization normalizes trailing slashes, drops fragments, lowercases
  // hosts, and strips tracking params so near-duplicates are caught.
  const seenUrl = new Set<string>();
  let deduped = 0;

  function normalizeUrl(raw: string): string {
    try {
      const u = new URL(raw);
      u.hash = '';
      u.hostname = u.hostname.toLowerCase().replace(/^www\./, '');
      u.pathname = u.pathname.replace(/\/+$/, '') || '/';
      u.searchParams.delete('utm_source');
      u.searchParams.delete('utm_medium');
      u.searchParams.delete('utm_campaign');
      u.searchParams.delete('utm_term');
      u.searchParams.delete('utm_content');
      u.searchParams.delete('fbclid');
      u.searchParams.delete('gclid');
      // Rebuild without tracking params.
      const qs = u.searchParams.toString();
      u.search = qs ? `?${qs}` : '';
      return u.toString();
    } catch {
      return raw;
    }
  }

  function pushEvidenceUrls(ev: Record<string, unknown>, into: Set<string>): void {
    const push = (u: unknown) => {
      if (typeof u === 'string' && /^https?:\/\//.test(u)) into.add(normalizeUrl(u));
    };
    push(ev.url);
    if (Array.isArray(ev.urls)) ev.urls.forEach(push);
    if (Array.isArray(ev.sources)) ev.sources.forEach(push);
    push(ev.sourceUrl);
    if (typeof ev.cveId === 'string') {
      into.add(normalizeUrl(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(ev.cveId)}`));
    }
  }

  /** URL-dedup one candidate list against the shared `seenUrl` set. */
  const dropUrlDuplicates = (cands: Candidate[]): Candidate[] =>
    cands.filter((c) => {
      const urls = new Set<string>();
      pushEvidenceUrls(c.evidence ?? {}, urls);
      // If the candidate has no evidence URLs at all it's not dedupable — keep it.
      if (urls.size === 0) return true;
      // If ANY URL was already seen, drop this candidate as a duplicate.
      for (const u of urls) {
        if (seenUrl.has(u)) {
          deduped += 1;
          return false;
        }
      }
      // Mark ALL candidate URLs as seen so future candidates with any overlap
      // are dropped regardless of which field the URL lives in.
      for (const u of urls) seenUrl.add(u);
      return true;
    });

  selected = dropUrlDuplicates(selected);

  // Sort by score for the optional global cap.
  selected.sort((a, b) => b.score - a.score);
  let kept = typeof deps.limit === 'number' ? selected.slice(0, deps.limit) : selected;

  // ── Daily floor ────────────────────────────────────────────────────────
  // The queue used to come back with 2-3 items on a normal day: the runners
  // found plenty, the anti-repetition gate suppressed most of it, and nothing
  // refilled the gap. When the strict pass lands under `minKept`, refill from
  // the pool the runners ALREADY returned — no extra fetches — using the
  // caller's relaxation policy (`admitSuppressed`, which never admits an
  // already-published key) and round-robin across topics so the top-up cannot
  // arrive as a wall of one type.
  let filledFromSuppressed = 0;
  const minKept = deps.minKept ?? 0;
  if (minKept > 0 && kept.length < minKept && deps.admitSuppressed) {
    const tookKeys = new Set(kept.map((c) => c.key));
    const pools = Object.entries(bags)
      .map(([topic, bag]) => ({
        topic,
        pool: bag.suppressed.filter((c) => !tookKeys.has(c.key) && deps.admitSuppressed!(c)),
      }))
      .filter((p) => p.pool.length > 0);
    for (const p of pools) (deps.rankTopUp ?? ((pool: Candidate[]) => pool.sort((a, b) => b.score - a.score)))(p.pool);

    const extras: Candidate[] = [];
    const shortfall = minKept - kept.length;
    let progressed = true;
    while (extras.length < shortfall && progressed) {
      progressed = false;
      for (const { pool } of pools) {
        if (extras.length >= shortfall) break;
        const next = pool.shift();
        if (!next) continue;
        // Route through the URL dedup so a top-up cannot resurrect the same
        // article a kept candidate already covers.
        if (dropUrlDuplicates([next]).length === 0) {
          progressed = true;
          continue;
        }
        extras.push(next);
        tookKeys.add(next.key);
        progressed = true;
      }
    }
    if (extras.length > 0) {
      kept = [...kept, ...extras];
      filledFromSuppressed = extras.length;
    }
  }

  // Recompute byTopic from the *actual* kept candidates so the admin sees
  // the real topic mix. `byTopicSelected` would over-count topics whose
  // candidates were dropped by URL dedup or the global cap. The candidate
  // .type (CaseStudyType) is the canonical topic key — runner names are
  // 1:1 with types in run.ts (discoverOsint → 'osint', discoverTools →
  // 'tool', …), so re-aggregating by type gives the same shape the
  // orchestrator used to populate byTopicSelected.
  const byTopic: Record<string, number> = {};
  for (const c of kept) {
    byTopic[c.type] = (byTopic[c.type] ?? 0) + 1;
  }
  // Zero-fill topics that produced no kept candidates so the admin can
  // still see they ran.
  for (const name of Object.keys(byTopicSelected)) {
    if (!(name in byTopic)) byTopic[name] = 0;
  }

  await Promise.all(kept.map((c) => deps.putCandidate(c)));
  // One read+write for the whole dedup map instead of one per kept candidate.
  await deps.commitDedup(
    kept.map((c) => c.key),
    deps.now
  );
  return {
    total,
    kept: kept.length,
    suppressed,
    deduped,
    blocked,
    filledFromSuppressed,
    ids: kept.map((c) => c.key),
    byTopic,
    byTopicSelected,
  };
}
