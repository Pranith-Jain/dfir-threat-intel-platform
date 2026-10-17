/**
 * /api/v1/stealer-forum-intel — degraded-cache behaviour.
 *
 * The chatter counters read the per-colo Cache-API entries that the
 * telegram-feed and reddit-feed producers write. Measured 2026-10-16: on a
 * cold colo both reads miss, every counter is 0 — and because the deepdarkCTI
 * forum rows are non-empty that zero-chatter payload was still cached for the
 * full 30 minutes. Readers saw "0 matches", which reads as "no stealer chatter
 * exists", while the underlying feeds actually held matches.
 *
 * Pinned here:
 *  - a build with both sources present reports real counts and no warning;
 *  - a build with a source missing says so (`warnings`) and gets the short
 *    degraded TTL + `x-si-stale`, so it self-heals instead of pinning zeros.
 */
import { SELF, env } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { STEALER_FORUM_INTEL_CACHE_KEY } from '../../src/routes/stealer-forum-intel';
import { TELEGRAM_FEED_CACHE_KEY, getTelegramFeedCacheKey } from '../../src/routes/telegram-feed';
import { REDDIT_FEED_CACHE_KEY } from '../../src/routes/reddit-feed';
import type { Env } from '../../src/env';

const cache = (caches as unknown as { default: Cache }).default;

interface IntelBody {
  chatter: { telegram: { matches: number; samples: Array<{ keyword: string }> }; reddit: { matches: number } };
  warnings: string[];
}

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return (input as Request).url;
}

async function seed(cacheKey: string | Request, body: unknown): Promise<void> {
  await cache.put(
    typeof cacheKey === 'string' ? new Request(cacheKey) : cacheKey,
    new Response(JSON.stringify(body), {
      headers: {
        'content-type': 'application/json',
        // Required: workerd's Cache API put() silently no-ops for responses
        // without an explicit cache-control header (verified against this
        // runtime: put-without-cc → match miss, put-with-cc → hit).
        'cache-control': 'public, max-age=3600',
      },
    })
  );
}

beforeEach(async () => {
  vi.restoreAllMocks();
  // Cold-colo simulation: nothing in the Cache API, and deepdarkCTI's upstream
  // fan-out fails fast so the forums list is empty and deterministic.
  const tgKey = await getTelegramFeedCacheKey(env as unknown as Env);
  await Promise.all([
    cache.delete(new Request(STEALER_FORUM_INTEL_CACHE_KEY)),
    cache.delete(tgKey),
    cache.delete(new Request(TELEGRAM_FEED_CACHE_KEY)),
    cache.delete(new Request(REDDIT_FEED_CACHE_KEY)),
  ]);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = urlOf(input);
    if (url.includes('stealer-forum-intel') || url.includes('.internal/')) return fetch(input, init);
    return new Response('upstream disabled in test', { status: 404 });
  });
});

describe('GET /api/v1/stealer-forum-intel (chatter counters)', () => {
  it('counts real matches and caches for the full TTL when both feeds are present', async () => {
    const tgKey = await getTelegramFeedCacheKey(env as unknown as Env);
    await seed(tgKey, {
      items: [
        {
          channel_name: 'stealer-chan',
          permalink: 'https://t.me/stealer_chan/1',
          datetime: '2026-10-15T10:00:00Z',
          text: 'fresh combolist dump available',
        },
        { channel_name: 'other', permalink: 'https://t.me/other/9', text: 'nothing relevant here' },
      ],
    });
    await seed(REDDIT_FEED_CACHE_KEY, {
      items: [
        {
          sub_label: 'r/cybersecurity',
          link: 'https://reddit.com/r/cybersecurity/1',
          pub_date: '2026-10-15T09:00:00Z',
          title: 'cloud logs for sale, cheap',
        },
      ],
    });

    const r = await SELF.fetch('https://x/api/v1/stealer-forum-intel');
    expect(r.status).toBe(200);
    const body = (await r.json()) as IntelBody;

    expect(body.chatter.telegram.matches).toBe(1);
    expect(body.chatter.telegram.samples[0]?.keyword).toBe('combolist');
    expect(body.chatter.reddit.matches).toBe(1);
    expect(body.warnings.some((w) => w.startsWith('chatter-source-missing'))).toBe(false);
    expect(r.headers.get('cache-control')).toContain('max-age=1800');
    expect(r.headers.get('x-si-stale')).toBeNull();
  });

  it('flags missing sources and shortens the TTL so zeros self-heal', async () => {
    const r = await SELF.fetch('https://x/api/v1/stealer-forum-intel');
    expect(r.status).toBe(200);
    const body = (await r.json()) as IntelBody;

    expect(body.warnings.some((w) => w.startsWith('chatter-source-missing:telegram'))).toBe(true);
    expect(body.warnings.some((w) => w.startsWith('chatter-source-missing:reddit'))).toBe(true);
    expect(r.headers.get('x-si-stale')).toBe('chatter-source-missing');
    // Degraded builds must NOT be pinned for the full 30-minute window. With
    // empty forums the handler uses no-store; with forums present it would use
    // the 5-minute degraded TTL — either way the answer is "do not hold this".
    const cacheControl = r.headers.get('cache-control') ?? '';
    expect(cacheControl).toMatch(/no-store|max-age=300/);
    expect(cacheControl).not.toContain('max-age=1800');
  });

  it('flags only the source that is actually missing', async () => {
    const tgKey = await getTelegramFeedCacheKey(env as unknown as Env);
    await seed(tgKey, {
      items: [{ channel_name: 'stealer-chan', permalink: 'https://t.me/s/2', text: 'stealer logs bulk' }],
    });

    const r = await SELF.fetch('https://x/api/v1/stealer-forum-intel');
    const body = (await r.json()) as IntelBody;
    expect(body.chatter.telegram.matches).toBe(1);
    expect(body.warnings.some((w) => w.startsWith('chatter-source-missing:telegram'))).toBe(false);
    expect(body.warnings.some((w) => w.startsWith('chatter-source-missing:reddit'))).toBe(true);
  });
});
