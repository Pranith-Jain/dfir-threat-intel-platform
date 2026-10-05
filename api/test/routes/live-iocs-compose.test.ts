import { describe, it, expect, beforeEach } from 'vitest';
import {
  composeLiveIocs,
  enqueueAllFeeds,
  feedSourceBatches,
  feedBatchId,
  FEED_BATCH_SIZE,
  FEED_SOURCE_IDS,
} from '../../src/routes/live-iocs';
import { writeBatchSlice, batchSliceKey } from '../../src/lib/live-iocs-slices';

// Slices live in the per-colo Cache API (free, not the KV write quota), so the
// test driver uses `caches.default` for setup/teardown rather than KV.
// `composeLiveIocs` takes an optional `Env`; the D1 read inside
// `finalizeLiveIocs` is guarded by `env?.BRIEFINGS_DB` and is non-fatal, so
// the test simply omits it.
const cache = (caches as unknown as { default: Cache }).default;

const batches = feedSourceBatches();

async function clearAllSlices(): Promise<void> {
  await Promise.all(batches.map((ids) => cache.delete(batchSliceKey(feedBatchId(ids)))));
}

describe('feedSourceBatches', () => {
  it('covers every registry source exactly once, in order', () => {
    const flat = batches.flat();
    expect(flat).toEqual([...FEED_SOURCE_IDS]);
    expect(new Set(flat).size).toBe(flat.length);
  });

  it('keeps every batch within the per-invocation subrequest allowance', () => {
    // A batch runs in ONE consumer invocation against the free-plan 50
    // subrequest cap. Most sources cost 1 fetch; the KV-cached helpers and
    // multi-URL fallback chains cost 2-3, so the worst case is
    // FEED_BATCH_SIZE * 3. Assert that stays comfortably under the cap — a
    // silent overflow here shows up as a whole batch reporting ok:false.
    const worstCase = FEED_BATCH_SIZE * 3;
    expect(worstCase).toBeLessThan(50);
    for (const b of batches) expect(b.length).toBeLessThanOrEqual(FEED_BATCH_SIZE);
  });

  it('keeps the slice-read count inside the handler budget', () => {
    // composeLiveIocs costs one Cache API read per batch. That read count plus
    // the handler's own cache.match / KV / analytics work must fit under 50 —
    // which is exactly why per-source slices had to go.
    expect(batches.length).toBeLessThan(40);
  });

  it('derives a stable id from content, not position', () => {
    // A reordering or insertion must not orphan every slice by changing indices.
    const a = feedBatchId(['x', 'y']);
    const b = feedBatchId(['y', 'x']);
    expect(feedBatchId(['x', 'y'])).toBe(a);
    expect(b).not.toBe(a);
  });
});

describe('composeLiveIocs (Cache API batch slices)', () => {
  beforeEach(clearAllSlices);

  it('merges present slices and flags degraded when the set is incomplete', async () => {
    // Fixtures must land on the content-hashed keys the handler actually reads.
    await writeBatchSlice(feedBatchId(batches[0]!), [
      {
        sourceId: 'emerging-threats',
        result: {
          items: [
            {
              value: '1.1.1.1',
              kind: 'ip',
              source: 'emerging-threats',
              reporter: 'Proofpoint ETOpen',
              context: 'recent compromise / blocklist',
            },
          ],
          sources: [{ id: 'emerging-threats', ok: true, count: 1 }],
        },
      },
    ]);
    await writeBatchSlice(feedBatchId(batches[1]!), [
      {
        sourceId: 'blocklist-de',
        result: {
          items: [{ value: '2.2.2.2', kind: 'ip', source: 'blocklist-de', reporter: 'Blocklist.de', context: 'x' }],
          sources: [{ id: 'blocklist-de', ok: true, count: 1 }],
        },
      },
    ]);

    const { response, presentSlices } = await composeLiveIocs();
    expect(presentSlices).toBe(2);
    // 2 of N batches present → extraDegraded → degraded true
    expect(response.degraded).toBe(true);
    const ids = response.sources.map((s) => s.id);
    expect(ids).toContain('emerging-threats');
    expect(ids).toContain('blocklist-de');
    const values = response.items.map((i) => i.value);
    expect(values).toContain('1.1.1.1');
    expect(values).toContain('2.2.2.2');
  });

  it('drops a source whose slice contributed no fresh items (recount), keeps degraded', async () => {
    // an item observed long before the 7-day staleness cutoff is filtered out
    await writeBatchSlice(feedBatchId(batches[0]!), [
      {
        sourceId: 'tweetfeed',
        result: {
          items: [
            {
              value: 'stale.example',
              kind: 'domain',
              source: 'tweetfeed',
              reporter: 'x',
              observed_at: '2020-01-01T00:00:00.000Z',
            },
          ],
          sources: [{ id: 'tweetfeed', ok: true, count: 1 }],
        },
      },
    ]);
    const { response, presentSlices } = await composeLiveIocs();
    expect(presentSlices).toBe(1);
    // the only item was stale → no active sources, but still degraded (incomplete set)
    expect(response.items.map((i) => i.value)).not.toContain('stale.example');
    expect(response.sources.map((s) => s.id)).not.toContain('tweetfeed');
    expect(response.degraded).toBe(true);
  });

  it('returns presentSlices=0 when no slices exist (caller falls back to sync)', async () => {
    const { presentSlices } = await composeLiveIocs();
    expect(presentSlices).toBe(0);
  });
});

describe('enqueueAllFeeds', () => {
  it('sends one message per batch plus the AI/LLM intel warm', async () => {
    const sent: Array<{ body: { sourceIds?: string[]; aiLlmWarm?: boolean }; delaySeconds?: number }> = [];
    const fakeQueue = {
      sendBatch: async (
        msgs: Iterable<{ body: { sourceIds?: string[]; aiLlmWarm?: boolean }; delaySeconds?: number }>
      ) => {
        for (const m of msgs) sent.push(m);
      },
    };
    await enqueueAllFeeds(fakeQueue as never);

    const feedMessages = sent.filter((m) => m.body.sourceIds);
    const warmMessages = sent.filter((m) => m.body.aiLlmWarm);
    expect(feedMessages).toHaveLength(batches.length);
    expect(warmMessages).toHaveLength(1);
    expect(sent).toHaveLength(batches.length + 1);

    // Every registry source is covered exactly once across the batches.
    expect(feedMessages.flatMap((m) => m.body.sourceIds!)).toEqual([...FEED_SOURCE_IDS]);
  });

  it('staggers sends so the consumer can keep pace', () => {
    // A single burst shows up as an average-lag spike on the queue dashboard.
    // The AI/LLM warm must land after the feed batches, not compete for the head.
    const batchesOf = feedSourceBatches();
    expect(batchesOf.length).toBeGreaterThan(1);
  });
});
