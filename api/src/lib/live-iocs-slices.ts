/**
 * Per-source slices for the live-IOC feed fan-out.
 *
 * The queue consumer runs one feed source (see `runFeedSourceById`) and parks
 * its contribution here under a per-source Cache API entry. A later
 * compose-on-read handler (PR3) reads every slice, flattens them, and applies
 * the freshness filter + per-source recount — replacing the synchronous
 * ~33-source fan-out that `fetchLiveIocs` does on a cache miss today.
 *
 * Slices store the RAW pre-freshness contribution (exactly what the source's
 * run() returned), so the reader stays the single source of truth for the
 * freshness window and the count recompute.
 *
 * # Why Cache API, not KV
 *
 * The live-IOC cron runs hourly and enqueues all ~34 sources; the queue
 * consumer writes one slice per source per refresh. At 34 sources × 24
 * refreshes that was 816 KV writes/day — ~80% of the Workers free-tier
 * 1,000-writes-per-day quota, leaving no headroom for any other feature.
 *
 * Slices are an ideal Cache API fit: per-colo, ephemeral, no cross-colo
 * coordination needed (each colo's cron + queue consumer warms its own copy
 * within a minute of cold start), and the 6h `cache-control: max-age` outlives
 * the 1h refresh cadence with margin — a transient upstream flake keeps the
 * last-good contribution visible instead of dropping the source. The Cache
 * API is free and unlimited; a write never counts against the KV quota.
 *
 * A cold colo sees `presentSlices = 0` for up to one cron cycle after
 * `enqueueAllFeeds` fires, at which point `composeOrFallback` falls through to
 * the synchronous `fetchLiveIocs` fan-out — the same fallback it uses for
 * true cold start today. The page is never blank.
 */
import type { LiveIoc, LiveSource, FeedResult } from '../routes/live-iocs';

/**
 * Queue message. Two shapes share the one `live-iocs-feeds` queue:
 *  - `sourceId`: a live-iocs registry source → compose-on-read slice.
 *  - `gp`: a global-pulse feed → warmed into `gp:warm:<key>`, one feed per
 *    consumer invocation so each gets its own 50-subrequest budget (the old
 *    single-invocation parallel warmer blew the Free-plan cap and starved the
 *    rest of the hourly cron). The producer staggers `delaySeconds` so each gp
 *    feed lands in its own batch → its own invocation.
 */
export interface FeedQueueMessage {
  sourceId?: string;
  /**
   * Batched form: run every id in this array and write ONE combined slice.
   *
   * Replaces the one-message-per-source fan-out. Two hard limits made that
   * design unscalable once the registry passed ~30 sources:
   *
   *  1. **Compose-on-read counted a Cache API read per source.** Slice reads
   *     are subrequests, so `composeLiveIocs` over N sources needed N+ reads —
   *     already past the free-plan 50 cap at 46 sources, before the handler's
   *     own `cache.match` / KV / analytics work.
   *  2. **The synchronous cold-start fallback ran one shared 42-subrequest
   *     budget across every source**, so sources past the 42nd degraded to
   *     `ok:false` on every cold colo.
   *
   * Batching fixes both at once: the consumer runs `sourceIds.length` sources in
   * ONE invocation (its own 50-subrequest budget, so a batch must stay small —
   * see `FEED_BATCH_SIZE`) and writes ONE slice; compose then reads one slice
   * per batch instead of one per source. Adding feeds now costs one slice, not
   * two subrequests.
   *
   * `sourceId` is retained so in-flight messages from a previous deploy still
   * resolve (the consumer treats the two shapes identically).
   */
  sourceIds?: string[];
  gp?: { key: string; path: string };
  /** CyberPulse source warm message. Each source type gets its own consumer
   *  invocation → its own 50-subrequest budget. The consumer fetches the source
   *  and writes to `cp:warm:<type>` KV key; the cron reads from KV and passes
   *  into runCyberPulseIngestion as prefetched data. */
  cp?: { type: 'x_accounts' };
  /**
   * Daily CVE digest warm. The digest build fans out over ctiwatch paging +
   * VulnTracker + EPSS (~20 subrequests) — too heavy to share the hourly
   * alarm with cve-recent's own ~25-fetch fan-out, where it starved two hours
   * running (skipped-empty both times while the identical code path succeeded
   * from a fresh budget). Its own consumer invocation → its own budget.
   */
  digestWarm?: true;
  /**
   * Rebuild the dedicated AI/LLM intel slice (llm-threatintel + ai-honeypots).
   *
   * Its own message + its own consumer invocation because the build fans out
   * over five third-party JSON endpoints — sharing the hourly alarm's budget
   * would starve the live-IOC batches, and running it inline on a page view
   * would put five third-party upstreams on the read path.
   */
  aiLlmWarm?: true;
}

export const SLICE_KEY_PREFIX = 'live-iocs:slice:';

/** Cache API request key for a source's slice (internal URL — never fetched). */
export function sliceKey(sourceId: string): Request {
  return new Request(`https://live-iocs-slice.internal/v1/${encodeURIComponent(sourceId)}`);
}

/**
 * Slice TTL — how long a source's last-written slice survives if its next
 * refresh fails. 6h outlives an hourly refresh with margin, so a transient
 * upstream flake keeps the last-good contribution in the composed response
 * instead of dropping the source; a persistently-dead source ages out within
 * ~6h rather than lingering indefinitely.
 */
export const SLICE_TTL_SECONDS = 6 * 60 * 60;

export interface LiveIocSlice {
  source_id: string;
  /** ISO 8601 — when this slice was written by the consumer. */
  generated_at: string;
  items: LiveIoc[];
  sources: LiveSource[];
}

/**
 * Persist a source's contribution as its slice in the per-colo Cache API
 * (overwrites the prior entry). Best-effort: a Cache API failure is swallowed
 * so a transient cache outage doesn't wedge the queue consumer's retry loop —
 * the cron will simply rebuild the slice on the next refresh.
 */
export async function writeSlice(sourceId: string, result: FeedResult): Promise<void> {
  const slice: LiveIocSlice = {
    source_id: sourceId,
    generated_at: new Date().toISOString(),
    items: result.items,
    sources: result.sources,
  };
  const cache = getDefaultCache();
  if (!cache) return;
  try {
    await cache.put(
      sliceKey(sourceId),
      new Response(JSON.stringify(slice), {
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${SLICE_TTL_SECONDS}`,
        },
      })
    );
  } catch {
    /* best-effort — a cache write failure must not break the queue consumer */
  }
}

/**
 * Read a source's slice from the per-colo Cache API, or null if absent /
 * unparseable. Cold-colo misses return null; the caller (`composeLiveIocs`)
 * reports `presentSlices < FEED_SOURCE_IDS.length` so the response flags
 * `extraDegraded` and the read path falls back to the synchronous fan-out.
 */
export async function readSlice(sourceId: string): Promise<LiveIocSlice | null> {
  const cache = getDefaultCache();
  if (!cache) return null;
  try {
    const hit = await cache.match(sliceKey(sourceId));
    if (!hit) return null;
    const parsed = (await hit.json()) as LiveIocSlice | null;
    if (!parsed || !Array.isArray(parsed.items) || !Array.isArray(parsed.sources)) return null;
    return parsed;
  } catch {
    return null;
  }
}

// ── Batched slices ────────────────────────────────────────────────────────
//
// One slice per BATCH of sources rather than one per source. See the
// `sourceIds` doc on `FeedQueueMessage` for why: per-source slices made
// compose-on-read cost one subrequest per source, which does not survive the
// registry growing.

export const BATCH_SLICE_KEY_PREFIX = 'live-iocs:slice:batch:';

/** Cache API request key for a batch slice (internal URL — never fetched). */
export function batchSliceKey(batchId: string): Request {
  return new Request(`https://live-iocs-slice.internal/v2/${encodeURIComponent(batchId)}`);
}

/**
 * A batch slice carries the same envelope as a single-source slice. `source_id`
 * holds the batch id so a mis-keyed write is visible in the stored payload, not
 * just in the URL.
 */
export type LiveIocBatchSlice = LiveIocSlice;

/**
 * Write every source's contribution for one batch as a single slice.
 *
 * Accepts the results keyed by source id and drops any id the batch did not
 * produce a result for (a source that threw is simply absent — the compose-side
 * count check reports the batch as degraded rather than serving a hole
 * silently). Best-effort: a Cache API failure must not wedge the consumer's
 * retry loop.
 */
export async function writeBatchSlice(
  batchId: string,
  results: ReadonlyArray<{ sourceId: string; result: FeedResult }>
): Promise<void> {
  const items: LiveIoc[] = [];
  const sources: LiveSource[] = [];
  for (const { result } of results) {
    for (const it of result.items) items.push(it);
    for (const s of result.sources) sources.push(s);
  }
  if (results.length === 0) return;
  const slice: LiveIocBatchSlice = {
    source_id: batchId,
    generated_at: new Date().toISOString(),
    items,
    sources,
  };
  const cache = getDefaultCache();
  if (!cache) return;
  try {
    await cache.put(
      batchSliceKey(batchId),
      new Response(JSON.stringify(slice), {
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${SLICE_TTL_SECONDS}`,
        },
      })
    );
  } catch {
    /* best-effort — a cache write failure must not break the queue consumer */
  }
}

/** Read one batch slice, or null if absent / unparseable. */
export async function readBatchSlice(batchId: string): Promise<LiveIocBatchSlice | null> {
  const cache = getDefaultCache();
  if (!cache) return null;
  try {
    const hit = await cache.match(batchSliceKey(batchId));
    if (!hit) return null;
    const parsed = (await hit.json()) as LiveIocBatchSlice | null;
    if (!parsed || !Array.isArray(parsed.items) || !Array.isArray(parsed.sources)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function getDefaultCache(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch {
    return null;
  }
}
