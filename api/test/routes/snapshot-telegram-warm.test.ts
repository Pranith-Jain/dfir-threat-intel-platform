import { describe, it, expect, beforeEach } from 'vitest';
import { readWarmTelegram } from '../../src/routes/snapshot';
import type { TelegramFeedResponse } from '../../src/routes/telegram-feed';

// Regression test for the "Cybersec Telegram firehose — 0 posts · 0 channels
// live" bug: warming migrated to per-feed KV slices (`gp:warm:telegram`, written
// by worker/queue-consumer.ts), but snapshot kept reading the dead legacy single
// `gp:warm` blob and expecting `.telegram` nested inside it. The slice held 487
// items; snapshot read the wrong key and surfaced nothing.

const feed: TelegramFeedResponse = {
  generated_at: '2026-06-10T18:00:00.000Z',
  channels: [{ handle: 'vxunderground', name: 'vx-underground', topic: 'malware', ok: true, count: 3 }],
  items: [
    {
      channel_handle: 'vxunderground',
      channel_name: 'vx-underground',
      channel_topic: 'malware',
      channel_blurb: '',
      permalink: 'https://t.me/vxunderground/1',
      datetime: '2026-06-10T17:00:00.000Z',
      text: 'sample',
    },
  ],
  warnings: [],
};

// Minimal KV: like Workers KV, a bare `get(key)` returns the stored TEXT and
// `get(key, 'json')` parses it. The batched form is included because
// readWarmSlices falls back to one `get(keys[], 'json')`.
function kvWith(map: Record<string, unknown>): KVNamespace {
  return {
    get: async (key: string | string[], type?: 'json' | 'text') => {
      if (Array.isArray(key)) {
        const out = new Map<string, unknown>();
        for (const k of key) {
          const v = map[k];
          if (v !== undefined) out.set(k, type === 'json' ? v : JSON.stringify(v));
        }
        return out;
      }
      if (!(key in map)) return null;
      const v = map[key];
      return type === 'json' ? v : typeof v === 'string' ? v : JSON.stringify(v);
    },
  } as unknown as KVNamespace;
}

describe('readWarmTelegram', () => {
  // readWarmTelegram now shadows its store read in caches.default (per-colo L1
  // so the snapshot aggregator doesn't burn a store read on every request).
  // Clear the shadow between cases so tests don't leak state.
  beforeEach(async () => {
    try {
      await (caches as unknown as { default: Cache }).default.delete(
        new Request('https://gp-warm-telegram-shadow.internal/v1')
      );
    } catch {
      /* miniflare caches.default may be unavailable in some envs */
    }
  });
  it('reads the per-feed warm slice (the key the warmer actually writes)', async () => {
    const r = await readWarmTelegram({ KV_CACHE: kvWith({ 'gp:warm:telegram': feed }) });
    expect(r?.items.length).toBe(1);
    expect(r?.channels.length).toBe(1);
  });

  it('does NOT read the dead legacy gp:warm blob (this was the bug)', async () => {
    // Legacy single-blob shape with telegram nested — must be ignored now.
    const r = await readWarmTelegram({ KV_CACHE: kvWith({ 'gp:warm': { telegram: feed } }) });
    expect(r).toBeNull();
  });

  it('returns null when the slice is empty or the store is unavailable', async () => {
    expect(
      await readWarmTelegram({ KV_CACHE: kvWith({ 'gp:warm:telegram': { items: [], channels: [] } }) })
    ).toBeNull();
    expect(await readWarmTelegram({})).toBeNull();
  });
});
