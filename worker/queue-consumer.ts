/**
 * Live-IOC feed queue consumer.
 *
 * Each message names one feed source. The consumer runs that source via the
 * registry (`runFeedSourceById`) and parks its contribution in a per-source KV
 * slice (`live-iocs:slice:<id>`). This is the producer side of the
 * compose-on-read model: the read path (PR3) stitches the slices together
 * instead of doing the synchronous ~33-source fan-out on a cache miss.
 *
 * PR2 ships this dormant — nothing enqueues yet; PR3 wires the producer
 * (cron + cold-cache) and flips the read path.
 */
import type { Env } from './env';
import type { Env as ApiEnv } from '../api/src/env';
import apiApp from '../api/src/index';
import { runFeedSourceById, feedBatchId, type FeedDeps, type FeedResult } from '../api/src/routes/live-iocs';
import { writeBatchSlice, type FeedQueueMessage } from '../api/src/lib/live-iocs-slices';
import { buildAiLlmIntel } from '../api/src/lib/ai-llm-intel';
import { writeAiLlmSlice } from '../api/src/routes/ai-llm-intel';
import { gpWarmKey } from '../api/src/routes/global-pulse';
import { warmCveDigestCache } from '../api/src/routes/cve-digest';
import { concurrentMap } from '../api/src/lib/concurrent-map';
import { signInternalToken } from '../api/src/lib/internal-token';
import { fetchXAccountPosts, X_ACCOUNTS } from '../api/src/routes/cyberpulse-ingest';

// `gp:warm:<key>` slice TTL — 180 min. Covers the 60m enqueue gate + one
// missed hourly cycle + queue drain; worst-case slice age ~2h, still within
// TTL so layers don't go dark at 2h → fallback to last-good (which looked like "8h old").
const GP_WARM_TTL_SECONDS = 180 * 60;

/**
 * Refresh a KV key's TTL without paying for a content write.
 *
 * The write-on-change guard below compares the fetched body against what is
 * stored and skips the `put` when they are byte-identical — correct, because
 * KV `expirationTtl` is measured from the `put`. Which means a feed that stops
 * changing also stops having its TTL extended, so the slice expires TTL-hours
 * after the last *content change* rather than after the last successful warm,
 * even though the producer keeps running and logging success. A quiet feed
 * then goes dark and the layer drops out of the map.
 *
 * So: still skip the write most of the time, but force a refresh once the key
 * is two-thirds of the way through its TTL. That costs at most one extra write
 * per key per TTL window — negligible against the 1k/day write budget — and
 * bounds worst-case slice age to TTL/3 past the last real write.
 *
 * The marker lives in the Cache API, which is per-colo and unmetered against
 * the KV write quota; same approach as api/src/lib/lastgood-debounce.ts.
 */
async function shouldRefreshWarmKey(key: string, ttlSeconds: number): Promise<boolean> {
  const marker = `https://warm-ttl-refresh.internal/v1/${key}`;
  try {
    const hit = await caches.default.match(marker);
    if (!hit) {
      await caches.default.put(
        marker,
        new Response('1', {
          headers: { 'cache-control': `max-age=${Math.floor(ttlSeconds / 3)}` },
        })
      );
      return true;
    }
    return false;
  } catch {
    // Marker unavailable — fall back to refreshing, since an unnecessary
    // write is far cheaper than an expired slice.
    return true;
  }
}

// Within-batch fan-out bound. The relevant runtime limit is ~6 simultaneously
// OPEN outbound connections (not a total-subrequest cap). Several sources fan
// out beyond a single fetch — andreafortuna does fetch + KV get/put, and the
// cached malwarebazaar/phishing helpers do fetch + KV — so 4 leaves headroom
// under that limit for those secondary subrequests. (max_concurrency in
// wrangler.jsonc separately bounds parallel batch invocations.)
const BATCH_CONCURRENCY = 4;

export async function handleQueue(
  batch: MessageBatch<FeedQueueMessage>,
  env: Env,
  ctx: ExecutionContext
): Promise<void> {
  const kv = env.KV_CACHE;
  if (!kv) {
    // No KV → nowhere to write slices. Ack everything so a misconfigured env
    // doesn't wedge the queue in an endless retry loop; the startup binding
    // validator already surfaces a missing KV_CACHE.
    for (const msg of batch.messages) msg.ack();
    console.error(JSON.stringify({ job: 'live-iocs-slice', status: 'no_kv', acked: batch.messages.length }));
    return;
  }

  const deps: FeedDeps = { executionCtx: ctx, kv, env: env as unknown as ApiEnv };

  await concurrentMap(
    batch.messages,
    async (msg) => {
      // Extract inside the try: a malformed body (null at runtime) must not
      // throw out of the per-message task — that would reject concurrentMap and
      // bubble out of handleQueue, retrying the WHOLE batch (re-running already
      // -acked messages). Keep failures scoped to their own message.
      let sourceId = '';
      try {
        // ── global-pulse feed warm (gp:warm:<key>) ───────────────────────
        // One feed per message → its own consumer invocation → its own
        // 50-subrequest budget. apiApp.fetch is IN-PROCESS (no network
        // self-fetch, which would loop back and fail). Each message writes its
        // OWN KV key, so there is no read-modify-write race across messages.
        const gp = msg.body?.gp;
        if (gp && typeof gp.key === 'string' && typeof gp.path === 'string') {
          const tokenSecret = env.INTERNAL_TOKEN_SECRET;
          if (!tokenSecret) {
            console.error(JSON.stringify({ job: 'gp-warm-slice', error: 'INTERNAL_TOKEN_SECRET not configured' }));
            return;
          }
          const token = await signInternalToken('queue-consumer', tokenSecret);
          const res = await apiApp.fetch(
            new Request(`https://gp-warm.internal${gp.path}`, {
              headers: { 'x-internal-token': token },
            }),
            env as unknown as ApiEnv as never,
            ctx
          );
          if (res.ok) {
            const body = await res.text();
            // Write-on-change: most feeds return byte-identical JSON hour over
            // hour, and KV writes are the scarce free-plan quota (1k/day vs
            // 100k reads). One cheap read per warm saves the write whenever
            // the feed hasn't moved.
            const key = gpWarmKey(gp.key);
            if ((await kv.get(key)) !== body || (await shouldRefreshWarmKey(key, GP_WARM_TTL_SECONDS))) {
              await kv.put(key, body, { expirationTtl: GP_WARM_TTL_SECONDS });
            }
          } else {
            // Transient upstream failure (5xx/429) → retry with backoff
            // instead of acking an empty warm window; the layer would stay
            // dark until the next hourly enqueue otherwise. 4xx = permanent
            // (bad path/key) — retrying can't fix it, ack to skip DLQ noise.
            console.error(
              JSON.stringify({
                job: 'gp-warm-slice',
                key: gp.key,
                path: gp.path,
                status: res.status,
                error: 'warm fetch not ok',
              })
            );
            if (res.status >= 500 || res.status === 429) {
              msg.retry({ delaySeconds: 60 });
              return;
            }
          }
          msg.ack();
          return;
        }

        // ── Daily CVE digest warm ────────────────────────────────────────
        // Calls warmCveDigestCache in-process (no HTTP round-trip needed —
        // unlike gp slices there is no per-feed path to self-fetch; the
        // builder writes its own cache + KV keys). Own invocation → own
        // 50-subrequest budget, which the hourly alarm could not spare.
        // Retry on !ok (transient upstream); the queue DLQ bounds a hard-down
        // upstream so this cannot spin forever.
        if (msg.body?.digestWarm === true) {
          try {
            const warm = await warmCveDigestCache(env as unknown as ApiEnv);
            console.log(JSON.stringify({ job: 'cve-digest-warm', count: warm.count, ok: warm.ok }));
            if (!warm.ok) {
              msg.retry({ delaySeconds: 300 });
              return;
            }
          } catch (e) {
            console.error(
              JSON.stringify({ job: 'cve-digest-warm', error: e instanceof Error ? e.message : String(e) })
            );
            msg.retry({ delaySeconds: 300 });
            return;
          }
          msg.ack();
          return;
        }

        // ── Dedicated AI / LLM intel slice warm ──────────────────────────
        // Rebuilds the AI/LLM intel payload (llm-threatintel iocs/actors/
        // posts/blog + ai-honeypots) and parks it in the Cache API slice the
        // read path serves. Its own message → own 50-subrequest budget; the
        // build fans over 5 third-party upstreams, so sharing the hourly alarm
        // would starve the live-IOC batches. The two indicator sets are ALSO
        // live-IOC sources, so this is additive: the stream shows the
        // addresses, this carries the campaign narrative.
        if (msg.body?.aiLlmWarm === true) {
          try {
            const payload = await buildAiLlmIntel();
            if (!payload.sources.some((s) => s.ok)) {
              // Nothing usable upstream — retry rather than parking an empty
              // slice that would read as "no AI/LLM intel exists" for 6h.
              console.error(JSON.stringify({ job: 'ai-llm-warm', status: 'all-sources-down' }));
              msg.retry({ delaySeconds: 300 });
              return;
            }
            await writeAiLlmSlice(payload);
            console.log(
              JSON.stringify({
                job: 'ai-llm-warm',
                ok: true,
                degraded: !!payload.degraded,
                actors: payload.stats.actors,
                iocs: payload.stats.iocs,
                posts: payload.stats.posts,
              })
            );
            msg.ack();
            return;
          } catch (e) {
            console.error(JSON.stringify({ job: 'ai-llm-warm', error: e instanceof Error ? e.message : String(e) }));
            msg.retry({ delaySeconds: 300 });
            return;
          }
        }

        // ── CyberPulse source warm (cp:warm:<type>) ──────────────────────
        // Each source type gets its own consumer invocation → its own
        // 50-subrequest budget. The fetcher is called IN-PROCESS (no HTTP
        // self-fetch). Result is written to `cp:warm:<type>` KV with a 150 min
        // TTL — long enough to survive the skip-when-fresh enqueue gate.
        const CP_WARM_TTL_SECONDS = 150 * 60;
        const cp = msg.body?.cp;
        if (cp && typeof cp.type === 'string') {
          try {
            let posts: unknown[] = [];
            if (cp.type === 'x_accounts') {
              posts = await fetchXAccountPosts(env as unknown as ApiEnv, X_ACCOUNTS, 1);
            } else {
              msg.ack();
              return;
            }
            const key = `cp:warm:${cp.type}`;
            const raw = JSON.stringify(posts);
            if ((await kv.get(key)) !== raw || (await shouldRefreshWarmKey(key, CP_WARM_TTL_SECONDS))) {
              await kv.put(key, raw, {
                expirationTtl: CP_WARM_TTL_SECONDS,
              });
            }
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'cp-warm-slice',
                type: cp.type,
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
            // Transient fetcher failure → retry (see gp-warm rationale).
            msg.retry({ delaySeconds: 60 });
            return;
          }
          msg.ack();
          return;
        }

        // Runtime-guard the body (a cross-version producer could send a
        // malformed shape) — the generic already types it, so no cast needed.
        // Accept BOTH the batched (`sourceIds`) and legacy single (`sourceId`)
        // shapes: a message enqueued by a previous deploy can still be in flight
        // across a rolling update.
        const batchIds: string[] = Array.isArray(msg.body?.sourceIds)
          ? msg.body.sourceIds.filter((s): s is string => typeof s === 'string')
          : [];
        sourceId =
          typeof msg.body?.sourceId === 'string' && msg.body.sourceId ? msg.body.sourceId : batchIds.join(',') || '';
        if (!batchIds.length && !sourceId) {
          // Ack (no retry — a malformed body won't parse on redelivery) but log
          // so a burst of bad messages is observable.
          msg.ack();
          return;
        }
        // A batch runs every source against its own invocation's 50-subrequest
        // budget, then parks them all in ONE slice — so adding a feed costs one
        // cache write instead of one subrequest in compose. See
        // `FeedQueueMessage.sourceIds`.
        const targets = batchIds.length ? batchIds : [sourceId];
        const results: Array<{ sourceId: string; result: FeedResult }> = [];
        for (const id of targets) {
          const result = await runFeedSourceById(id, deps);
          // Unknown source id — a stale/poison id from an older registry. Skip it
          // rather than failing the batch, which would retry work that can never
          // succeed and eventually DLQ the whole batch.
          if (result) results.push({ sourceId: id, result });
        }
        if (!results.length) {
          msg.ack();
          return;
        }
        // writeSlice persists to the per-colo Cache API (free, not counted
        // against the KV write quota) — see live-iocs-slices.ts doc for the
        // budget reasoning. `kv` stays in the deps for sources that need it
        // (e.g. andreafortuna's last-good mirror), but the slice itself does
        // not touch KV.
        await writeBatchSlice(feedBatchId(targets), results);
        msg.ack();
      } catch (e) {
        // Transient (KV write / unexpected) — let the queue retry, then DLQ.
        console.error(
          JSON.stringify({
            job: 'live-iocs-slice',
            sourceId: sourceId || null,
            status: 'failed',
            error: e instanceof Error ? e.message : String(e),
          })
        );
        msg.retry();
      }
    },
    BATCH_CONCURRENCY
  );
}
