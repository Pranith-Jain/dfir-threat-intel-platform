/**
 * /api/v1/x-tweets — guest-timeline staleness and the TweetFeed rescue.
 *
 * Measured 2026-10-17: X's anonymous guest-token timeline serves a frozen
 * snapshot (three active accounts returned 99-100 tweets, none within 7 days,
 * newest ~1 year old), so the endpoint's freshness filter always emptied and
 * callers got a bare `items: []` — indistinguishable from a quiet account.
 *
 * Two behaviours are pinned:
 *  - a handle the TweetFeed firehose covers gets fresh firehose items instead
 *    (mapped into the same item shape, `source: 'tweetfeed'`);
 *  - a handle outside the firehose still returns empty, but says WHY
 *    (`stale_guest_timeline` + `newest_available_at`) and carries the
 *    `x-si-stale` header with a short client window.
 */
import { SELF, env } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const cache = (caches as unknown as { default: Cache }).default;
const kv = env.KV_CACHE as unknown as { delete(key: string): Promise<void> };

const IN_FEED = 'vxunderground';
const NOT_IN_FEED = 'quiet_handle';
const STATUS_ID = '1111111111111111111';

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return (input as Request).url;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** Minimal UserTweets payload with ONE tweet far outside any recent window. */
function frozenTimeline(): Response {
  return json({
    data: {
      user: {
        result: {
          __typename: 'User',
          timeline_v2: {
            timeline: {
              instructions: [
                {
                  type: 'TimelineAddEntries',
                  entries: [
                    {
                      entryId: 'tweet-1',
                      content: {
                        itemContent: {
                          itemType: 'TimelineTweet',
                          tweet_results: {
                            result: {
                              __typename: 'Tweet',
                              legacy: {
                                id_str: '1',
                                full_text: 'ancient tweet',
                                created_at: 'Mon Oct 04 17:25:26 +0000 2021',
                                favorite_count: 1,
                                retweet_count: 1,
                                reply_count: 0,
                                quote_count: 0,
                              },
                            },
                          },
                        },
                      },
                    },
                  ],
                },
              ],
            },
          },
        },
      },
    },
  });
}

beforeEach(async () => {
  vi.restoreAllMocks();
  await Promise.all([
    cache.delete(new Request('https://twitter-guest-token-cache.internal/v1')),
    kv.delete('tw:guest_token'),
    ...['vxunderground', 'quiet_handle'].flatMap((h) => [
      cache.delete(new Request(`https://x-userid-cache.internal/v1?h=${h}`)),
      cache.delete(new Request(`https://tw-tweets-cache.internal/v3?h=${h}&d=7&p=0`)),
    ]),
  ]);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = urlOf(input);
    if (url.includes('guest/activate.json')) return json({ guest_token: 'gt-test' });
    if (url.includes('UserByScreenName')) {
      return json({
        data: {
          user: {
            result: {
              rest_id: '123456',
              is_blue_verified: false,
              legacy: { name: 'Test Account', description: 'bio', followers_count: 10 },
            },
          },
        },
      });
    }
    if (url.includes('UserTweets')) return frozenTimeline();
    if (url.includes('TweetFeed/master/today.csv')) {
      // One fresh row for the covered handle — timestamp inside the window.
      const ts = new Date(Date.now() - 3600_000).toISOString().slice(0, 19).replace('T', ' ');
      return new Response(`${ts},${IN_FEED},sha256,deadbeef,#malware,https://x.com/${IN_FEED}/status/${STATUS_ID}\n`, {
        status: 200,
        headers: { 'content-type': 'text/csv' },
      });
    }
    if (url.includes('TweetFeed/master/week.csv')) return new Response('', { status: 200 });
    if (url.includes('api.fxtwitter.com/2/status/')) {
      const now = Math.floor(Date.now() / 1000);
      return json({
        code: 200,
        status: {
          id: STATUS_ID,
          url: `https://x.com/${IN_FEED}/status/${STATUS_ID}`,
          text: 'fresh IOC tweet from the firehose',
          created_at: 'Fri Oct 16 10:00:00 +0000 2026',
          created_timestamp: now - 3600,
          author: { screen_name: IN_FEED, name: 'vx' },
          replies: 0,
          retweets: 2,
          likes: 3,
          views: 4,
          media: { all: [] },
        },
      });
    }
    return new Response('not mocked: ' + url, { status: 404 });
  });
});

describe('GET /api/v1/x-tweets', () => {
  it('rescues an in-firehose handle with fresh TweetFeed items', async () => {
    const r = await SELF.fetch(`https://x/api/v1/x-tweets?handle=${IN_FEED}&count=5`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      items: Array<{ id: string; text: string; author: { screen_name: string }; url: string }>;
      source?: string;
      stale_guest_timeline?: boolean;
      upstream_error?: string;
    };

    expect(body.items).toHaveLength(1);
    expect(body.source).toBe('tweetfeed');
    expect(body.stale_guest_timeline).toBe(false);
    expect(body.upstream_error).toBeUndefined();
    expect(body.items[0]?.text).toContain('fresh IOC tweet');
    expect(body.items[0]?.author.screen_name).toBe(IN_FEED);
    expect(r.headers.get('x-si-stale')).toBeNull();
    expect(r.headers.get('cache-control')).toContain('max-age=900');
  });

  it('reports the frozen guest timeline instead of implying a quiet account', async () => {
    const r = await SELF.fetch(`https://x/api/v1/x-tweets?handle=${NOT_IN_FEED}&count=5`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      items: unknown[];
      stale_guest_timeline?: boolean;
      newest_available_at?: string;
      upstream_error?: string;
    };

    expect(body.items).toHaveLength(0);
    expect(body.stale_guest_timeline).toBe(true);
    expect(body.newest_available_at).toBe('2021-10-04T17:25:26.000Z');
    expect(body.upstream_error).toContain('out-of-window');
    expect(r.headers.get('x-si-stale')).toBe('guest-timeline-stale');
    expect(r.headers.get('cache-control')).toContain('max-age=300');
  });
});
