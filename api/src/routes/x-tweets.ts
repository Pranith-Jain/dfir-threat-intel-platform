import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, badGateway, tooManyRequests } from '../lib/api-error';
import {
  fetchUserTimeline,
  TwitterRateLimited,
  type TwitterTimelineItem,
  type TwitterTimelineResponse,
} from '../lib/twitter-graphql';
import { fetchXLive } from './x-live';

/**
 * X (Twitter) tweets — anonymous path (highlights, not chronological).
 *
 *   GET /api/v1/x-tweets?handle=briankrebs[&count=20]
 *
 * Stale-fallback uses caches.default (no KV quota). User-initiated view
 * calls (count >= 15) warm the cache; probe calls (count=5) skip it to
 * keep the write storm down.
 *
 * Since 2026-10-17 X's guest timeline only serves frozen snapshots, so an
 * empty in-window result is rescued from the TweetFeed firehose (which is
 * fresh) whenever the handle is covered by it — see `tweetFeedFallback`
 * below. Handles outside the firehose get an explicit
 * `stale_guest_timeline` marker instead of a bare empty list.
 */

const HANDLE_RE = /^[A-Za-z0-9_]{1,15}$/;
const STALE_CACHE_TTL_SECONDS = 7 * 24 * 3600;

function staleCacheKey(handle: string): Request {
  return new Request(`https://x-tweets-stale.internal/v1?h=${handle.toLowerCase()}`);
}

/**
 * TweetFeed rescue for the dead guest timeline.
 *
 * X's anonymous guest-token timeline now serves a frozen snapshot: measured
 * 2026-10-17, briankrebs / vxunderground / malwrhunterteam each returned
 * 99-100 tweets with every single one outside the 7-day window (newest ~1
 * year old). The guest timeline therefore can never satisfy this endpoint's
 * freshness filter, and callers saw a bare `items: []` — indistinguishable
 * from a quiet account (same silent-zero class as the RSS feeds that shipped
 * blank for months).
 *
 * The TweetFeed firehose that /api/v1/x-live already tracks *is* fresh
 * (updated continuously; verified 2026-10-17) and covers exactly the
 * IOC-tweeting accounts this endpoint exists for. When the guest timeline
 * comes back empty in-window, serve those accounts' recent firehose items
 * instead, mapped into the same item shape so the response contract does not
 * change. Handles outside the firehose stay empty, but the response now says
 * why (`stale_guest_timeline` + `newest_available_at`) rather than implying
 * the account went quiet.
 *
 * Cost when the handle is not in the firehose: two edge-cached CSV fetches
 * (10min/1h TTL) and zero fxtwitter lookups.
 */
async function tweetFeedFallback(handle: string, sinceDays: number, count: number): Promise<TwitterTimelineItem[]> {
  try {
    const fresh = await fetchXLive({
      handleFilter: handle,
      // The firehose only spans 7 days (today.csv + week.csv).
      sinceHours: Math.min(sinceDays * 24, 168),
      limit: Math.min(count, 12),
    });
    return fresh.items
      .filter((t) => (t.author?.screen_name ?? '').toLowerCase() === handle.toLowerCase())
      .map((t): TwitterTimelineItem => ({
        id: t.id,
        url: t.url,
        text: t.text,
        created_at: t.created_at,
        created_at_ms: t.created_at_ms,
        author: { screen_name: t.author.screen_name, name: t.author.name, avatar_url: t.author.avatar_url },
        retweet_count: t.retweets,
        favorite_count: t.likes,
        view_count: t.views,
        media: t.media.map((m) => ({ type: m.type, url: m.url })),
        is_retweet: false,
        is_reply: false,
        is_quote: false,
        is_pinned: false,
      }));
  } catch (e) {
    logError('xTweetsHandler tweetfeed fallback failed', e);
    return [];
  }
}

export async function xTweetsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const handleRaw = (c.req.query('handle') ?? '').trim().replace(/^@/, '');
  if (!HANDLE_RE.test(handleRaw)) {
    return badRequest(c, 'invalid handle (1-15 chars, A-Za-z0-9_)');
  }
  const countRaw = Number(c.req.query('count') ?? '40');
  const count = Number.isFinite(countRaw) ? Math.max(5, Math.min(40, Math.floor(countRaw))) : 40;
  const sinceDaysRaw = Number(c.req.query('since_days') ?? '7');
  const sinceDays = Number.isFinite(sinceDaysRaw) ? Math.max(1, Math.min(90, Math.floor(sinceDaysRaw))) : 7;
  const includePinned = c.req.query('include_pinned') === '1';

  const edgeCache = (caches as unknown as { default: Cache }).default;
  const staleKey = staleCacheKey(handleRaw);

  try {
    let body = await fetchUserTimeline(c.env, handleRaw, { count, sinceDays, includePinned });

    // Guest timeline came back empty in-window → rescue from the firehose
    // whenever the handle is covered by it (see tweetFeedFallback above).
    if (body.items.length === 0) {
      const rescued = await tweetFeedFallback(handleRaw, sinceDays, count);
      if (rescued.length > 0) {
        body = {
          ...body,
          items: rescued,
          source: 'tweetfeed',
          stale_guest_timeline: false,
          upstream_error: undefined,
        };
      }
    }

    if (body.source === 'tweetfeed') {
      // Firehose-sourced items are fresher than the 15-minute client window,
      // but the 7-day stale slot is for the GraphQL path only — pinning
      // firehose data there would freeze a much shorter-lived dataset.
      return c.json(body, 200, { 'cache-control': 'public, max-age=900, s-maxage=900' });
    }

    if (body.stale_guest_timeline) {
      // Upstream is serving a frozen snapshot; say so instead of implying the
      // account is quiet, and keep the client window short so a recovery (or
      // a fix) is visible within minutes.
      return c.json(body, 200, {
        'cache-control': 'public, max-age=300',
        'x-si-stale': 'guest-timeline-stale',
      });
    }

    if (!body.cached && body.items.length > 0 && count >= 15) {
      const cacheable = new Response(JSON.stringify(body), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${STALE_CACHE_TTL_SECONDS}, s-maxage=${STALE_CACHE_TTL_SECONDS}`,
        },
      });
      c.executionCtx.waitUntil(edgeCache.put(staleKey, cacheable).catch(() => undefined));
    }
    return c.json(body, 200, { 'cache-control': 'public, max-age=900, s-maxage=1800' });
  } catch (err) {
    logError('xTweetsHandler failed', err);
    // Transient failure — try the Cache API stale entry. Better an old
    // payload than a hard error.
    try {
      const stale = await edgeCache.match(staleKey);
      if (stale) {
        const parsed = (await stale.json()) as TwitterTimelineResponse;
        return c.json({ ...parsed, stale: true, upstream_error: 'transient' }, 200, {
          'cache-control': 'public, max-age=300',
        });
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* fall through */
    }
    if (err instanceof TwitterRateLimited) {
      return tooManyRequests(c, 'rate-limited', { windowSeconds: 60 });
    }
    return badGateway(c, 'upstream error');
  }
}
