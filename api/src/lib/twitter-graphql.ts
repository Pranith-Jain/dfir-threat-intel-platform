import type { Env } from '../env';

/**
 * Anonymous Twitter / X access via the public guest-token GraphQL path.
 *
 * This is the same mechanism Nitter used before its maintainers stepped
 * away. Twitter's web app loads a hardcoded "anonymous bearer" token and
 * exchanges it for a short-lived `guest_token`; the pair authenticates
 * the GraphQL endpoints that return user profiles and timelines without
 * a logged-in account.
 *
 * Verified working against api.twitter.com on 2026-05-24:
 *   - POST  /1.1/guest/activate.json                   → guest_token
 *   - GET   /graphql/<qid>/UserByScreenName           → user_id (rest_id)
 *   - GET   /graphql/<qid>/UserTweets                  → timeline
 *
 * Rate-limit model is per-IP. Cloudflare Workers share egress IPs, so the
 * heavy lifting is caching: a single fresh guest_token typically serves
 * hundreds of UserTweets calls before Twitter rotates the token's quota.
 *
 * Caching layers (highest hit-rate to lowest):
 *   KV  `tw:userid:<screen_name>`        7d   — user IDs never change.
 *   KV  `tw:guest_token`                 2h   — guest tokens last ~3h.
 *   CF  `https://tw-tweets-cache/<handle>` 30min — parsed timeline.
 *
 * Failure modes:
 *   - 401 on UserTweets → guest_token revoked; clear KV, retry once.
 *   - 429 from activate → upstream rate-limited; surface to caller.
 *   - 5xx from GraphQL  → upstream blip; serve stale cache when available.
 */

// Public anonymous bearer used by Twitter's own embedded widgets. NOT a
// secret — visible in every X.com page load. Same value Nitter used.
const ANON_BEARER =
  'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA';

const GUEST_ACTIVATE_URL = 'https://api.twitter.com/1.1/guest/activate.json';
const USER_BY_SN_QID = 'G3KGOASz96M-Qu0nwmGXNg';
const USER_TWEETS_QID = 'V7H0Ap3_Hh2FyS75OCDO3Q';

const KV_GUEST_TOKEN_KEY = 'tw:guest_token';
const KV_GUEST_TOKEN_TTL = 2 * 3600;
// user_id lookup TTL — cached in caches.default (no KV quota).
const KV_USERID_TTL = 7 * 24 * 3600;
const CACHE_TWEETS_TTL = 30 * 60;
/**
 * TTL for a window-empty-but-upstream-has-data build (guest timeline serving
 * only old snapshots). Short so the degraded state is visible and self-heals
 * on the next request instead of being pinned for the full window.
 */
const DEGRADED_TWEETS_TTL = 5 * 60;
const FETCH_TIMEOUT_MS = 15_000;
const MAX_TWEETS_PER_CALL = 40;

const SCREEN_NAME_RE = /^[A-Za-z0-9_]{1,15}$/;

const FEATURES_USER_BY_SN = {
  hidden_profile_likes_enabled: true,
  hidden_profile_subscriptions_enabled: true,
  responsive_web_graphql_exclude_directive_enabled: true,
  verified_phone_label_enabled: false,
  subscriptions_verification_info_is_identity_verified_enabled: true,
  subscriptions_verification_info_verified_since_enabled: true,
  highlights_tweets_tab_ui_enabled: true,
  responsive_web_twitter_article_notes_tab_enabled: false,
  creator_subscriptions_tweet_preview_api_enabled: true,
  responsive_web_graphql_skip_user_profile_image_extensions_enabled: false,
  responsive_web_graphql_timeline_navigation_enabled: true,
};

const FEATURES_USER_TWEETS = {
  rweb_lists_timeline_redesign_enabled: true,
  responsive_web_graphql_exclude_directive_enabled: true,
  verified_phone_label_enabled: false,
  creator_subscriptions_tweet_preview_api_enabled: true,
  responsive_web_graphql_timeline_navigation_enabled: true,
  responsive_web_graphql_skip_user_profile_image_extensions_enabled: false,
  tweetypie_unmention_optimization_enabled: true,
  responsive_web_edit_tweet_api_enabled: true,
  graphql_is_translatable_rweb_tweet_is_translatable_enabled: true,
  view_counts_everywhere_api_enabled: true,
  longform_notetweets_consumption_enabled: true,
  responsive_web_twitter_article_tweet_consumption_enabled: false,
  tweet_awards_web_tipping_enabled: false,
  freedom_of_speech_not_reach_fetch_enabled: true,
  standardized_nudges_misinfo: true,
  tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: true,
  longform_notetweets_rich_text_read_enabled: true,
  longform_notetweets_inline_media_enabled: true,
  responsive_web_media_download_video_enabled: false,
  responsive_web_enhance_cards_enabled: false,
};

export interface TwitterTimelineItem {
  id: string;
  url: string;
  text: string;
  created_at: string;
  /** Parsed ISO timestamp (UTC). Empty when X's raw `created_at` is missing/garbled. */
  created_at_ms: number;
  author: { screen_name: string; name: string; avatar_url?: string; verified?: boolean };
  reply_count?: number;
  retweet_count?: number;
  favorite_count?: number;
  quote_count?: number;
  view_count?: number;
  media: Array<{ type: 'photo' | 'video' | 'gif'; url: string }>;
  is_retweet: boolean;
  is_reply: boolean;
  is_quote: boolean;
  is_pinned: boolean;
}

export interface TwitterTimelineResponse {
  handle: string;
  user_id: string;
  display_name: string;
  bio?: string;
  followers_count?: number;
  items: TwitterTimelineItem[];
  generated_at: string;
  cached: boolean;
  /** Set when this response came from a stale cache because upstream failed. */
  stale?: boolean;
  /** Set when the underlying call returned a known error worth surfacing. */
  upstream_error?: string;
  /**
   * Which upstream produced `items`. `graphql` is X's anonymous guest
   * timeline; `tweetfeed` is the TweetFeed firehose fallback used when the
   * guest timeline yields nothing in-window (see x-tweets.ts).
   */
  source?: 'graphql' | 'tweetfeed';
  /**
   * True when the guest timeline returned items but every one fell outside the
   * freshness window — i.e. X served a frozen snapshot rather than a live
   * timeline. Without this the caller sees `items: []` and cannot tell "quiet
   * account" apart from "upstream is stale" (measured 2026-10-17: three active
   * accounts returned 99-100 tweets each, none within 7 days, newest ~1 year
   * old).
   */
  stale_guest_timeline?: boolean;
  /** Newest tweet date the upstream offered (ISO). Present when stale. */
  newest_available_at?: string;
}

export class TwitterRateLimited extends Error {
  constructor(public retryAfter?: string) {
    super(`Twitter rate-limited${retryAfter ? ` (retry-after ${retryAfter})` : ''}`);
    this.name = 'TwitterRateLimited';
  }
}

// Per-colo Cache-API shadow for the shared guest token. activateGuestToken
// runs on every GraphQL timeline fetch; the shadow collapses repeats to ~1 KV
// read per colo per window. 10min — comfortably shorter than the KV TTL and
// than Twitter's guest-token lifetime, so a revoked token self-heals fast.
const GUEST_TOKEN_SHADOW_TTL = 600;
const GUEST_TOKEN_SHADOW_REQ = new Request('https://twitter-guest-token-cache.internal/v1');

async function activateGuestToken(env: Env): Promise<string> {
  const kv = env.KV_CACHE;
  // L1: per-colo Cache-API shadow (free) before the KV read.
  try {
    const hit = await (caches as unknown as { default: Cache }).default.match(GUEST_TOKEN_SHADOW_REQ);
    if (hit) return await hit.text();
  } catch {
    /* fall through */
  }
  if (kv) {
    const cached = await kv.get(KV_GUEST_TOKEN_KEY);
    if (cached) {
      try {
        await (caches as unknown as { default: Cache }).default.put(
          GUEST_TOKEN_SHADOW_REQ,
          new Response(cached, { headers: { 'cache-control': `max-age=${GUEST_TOKEN_SHADOW_TTL}` } })
        );
      } catch {
        /* best-effort shadow */
      }
      return cached;
    }
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  const res = await fetch(GUEST_ACTIVATE_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ANON_BEARER}`,
      // Twitter's own widget UA. Some endpoints reject obvious bot UAs.
      'user-agent':
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    },
    signal: ctrl.signal,
  });
  clearTimeout(timer);
  if (res.status === 429) {
    throw new TwitterRateLimited(res.headers.get('retry-after') ?? undefined);
  }
  if (!res.ok) throw new Error(`guest_activate HTTP ${res.status}`);
  const json = (await res.json()) as { guest_token?: string };
  const token = json.guest_token;
  if (!token) throw new Error('guest_activate returned no token');
  if (kv) {
    await kv.put(KV_GUEST_TOKEN_KEY, token, { expirationTtl: KV_GUEST_TOKEN_TTL });
  }
  // Write-through the shadow (also replaces a stale cached token after refresh).
  try {
    await (caches as unknown as { default: Cache }).default.put(
      GUEST_TOKEN_SHADOW_REQ,
      new Response(token, { headers: { 'cache-control': `max-age=${GUEST_TOKEN_SHADOW_TTL}` } })
    );
  } catch {
    /* best-effort shadow */
  }
  return token;
}

async function clearGuestToken(env: Env): Promise<void> {
  // Purge both layers so a known-bad token isn't served from the shadow.
  try {
    await (caches as unknown as { default: Cache }).default.delete(GUEST_TOKEN_SHADOW_REQ);
  } catch {
    /* swallow */
  }
  if (env.KV_CACHE) {
    try {
      await env.KV_CACHE.delete(KV_GUEST_TOKEN_KEY);
    } catch {
      /* swallow */
    }
  }
}

async function graphqlGet<T>(
  env: Env,
  guestToken: string,
  url: string
): Promise<{ data: T; status: number; statusText: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${ANON_BEARER}`,
      'x-guest-token': guestToken,
      'x-twitter-active-user': 'yes',
      'x-twitter-client-language': 'en',
      'user-agent':
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      Accept: 'application/json',
    },
    signal: ctrl.signal,
  });
  clearTimeout(timer);
  if (res.status === 429) {
    throw new TwitterRateLimited(res.headers.get('retry-after') ?? undefined);
  }
  if (res.status === 401 || res.status === 403) {
    // Guest token rotated or revoked; caller should clear + retry once.
    await clearGuestToken(env);
    throw new Error(`graphql ${res.status} ${res.statusText} (guest token cleared)`);
  }
  if (!res.ok) throw new Error(`graphql HTTP ${res.status}`);
  const json = (await res.json()) as T;
  return { data: json, status: res.status, statusText: res.statusText };
}

async function resolveUserId(
  env: Env,
  screenName: string
): Promise<{ id: string; name: string; bio: string; followers: number; verified: boolean; avatar?: string }> {
  // user_id lookup cached in caches.default (no KV quota). Switched
  // from KV on 2026-05-24 to drop per-handle KV reads from the
  // probe-and-hide sweep.
  const edgeCache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(`https://x-userid-cache.internal/v1?h=${screenName.toLowerCase()}`);
  try {
    const hit = await edgeCache.match(cacheReq);
    if (hit) {
      return (await hit.json()) as Awaited<ReturnType<typeof resolveUserId>>;
    }
  } catch {
    /* fall through */
  }
  const token = await activateGuestToken(env);
  const variables = encodeURIComponent(JSON.stringify({ screen_name: screenName, withSafetyModeUserFields: true }));
  const features = encodeURIComponent(JSON.stringify(FEATURES_USER_BY_SN));
  const url = `https://api.twitter.com/graphql/${USER_BY_SN_QID}/UserByScreenName?variables=${variables}&features=${features}`;
  const { data } = await graphqlGet<{
    data?: { user?: { result?: Record<string, unknown> } };
  }>(env, token, url);
  const result = data.data?.user?.result;
  if (!result) throw new Error('UserByScreenName returned no result');
  // `rest_id` is the numeric user ID at the top level of `result`.
  const rest = result as Record<string, unknown>;
  const restId = typeof rest.rest_id === 'string' ? rest.rest_id : null;
  // Some payloads put rest_id only inside `id` (base64-encoded). Decode if needed.
  let userId = restId ?? '';
  if (!userId && typeof rest.id === 'string') {
    try {
      const decoded = atob(rest.id);
      const m = decoded.match(/User:(\d+)/);
      if (m) userId = m[1]!;
    } catch {
      /* fall through */
    }
  }
  if (!userId) throw new Error('UserByScreenName could not resolve rest_id');

  const legacy = (rest.legacy ?? {}) as Record<string, unknown>;
  const name = typeof legacy.name === 'string' ? legacy.name : screenName;
  const bio = typeof legacy.description === 'string' ? legacy.description : '';
  const followers = typeof legacy.followers_count === 'number' ? legacy.followers_count : 0;
  const verified = rest.is_blue_verified === true || legacy.verified === true;
  const avatar = typeof legacy.profile_image_url_https === 'string' ? legacy.profile_image_url_https : undefined;

  const record = { id: userId, name, bio, followers, verified, avatar };
  try {
    const cacheable = new Response(JSON.stringify(record), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${KV_USERID_TTL}, s-maxage=${KV_USERID_TTL}`,
      },
    });
    await edgeCache.put(cacheReq, cacheable);
  } catch {
    /* swallow */
  }
  return record;
}

/**
 * Parse the deeply-nested UserTweets timeline into clean items. Twitter's
 * GraphQL response is a mess of `instructions` → `entries` →
 * `itemContent` → `tweet_results` → `result` → `legacy`. We only keep
 * normal tweets + retweets (no cursors, ads, or "who to follow" entries).
 */
function parseTimeline(raw: unknown, screenName: string): TwitterTimelineItem[] {
  const root = raw as Record<string, unknown>;
  const timeline = ((root.data as Record<string, unknown>)?.user as Record<string, unknown>)?.result as
    Record<string, unknown> | undefined;
  const v2 = (timeline?.timeline_v2 as Record<string, unknown>)?.timeline as Record<string, unknown> | undefined;
  const instructions = (v2?.instructions as unknown[]) ?? [];
  const items: TwitterTimelineItem[] = [];

  function pushFromTweetResult(tr: unknown, isRetweet: boolean, isPinned: boolean): void {
    if (!tr || typeof tr !== 'object') return;
    const res = (tr as Record<string, unknown>).result as Record<string, unknown> | undefined;
    if (!res) return;
    const core = res.core as Record<string, unknown> | undefined;
    const author = ((core?.user_results as Record<string, unknown>)?.result as Record<string, unknown>)?.legacy as
      Record<string, unknown> | undefined;
    const legacy = res.legacy as Record<string, unknown> | undefined;
    if (!legacy) return;
    const id = typeof legacy.id_str === 'string' ? legacy.id_str : '';
    const text = typeof legacy.full_text === 'string' ? legacy.full_text : '';
    const createdAt = typeof legacy.created_at === 'string' ? legacy.created_at : '';
    const createdMs = createdAt ? Date.parse(createdAt) : NaN;
    const isReply = !!legacy.in_reply_to_screen_name && legacy.in_reply_to_screen_name !== screenName;
    const isQuote = legacy.is_quote_status === true;
    const authorSn = typeof author?.screen_name === 'string' ? author.screen_name : screenName;
    const authorName = typeof author?.name === 'string' ? author.name : authorSn;
    const authorAvatar =
      typeof author?.profile_image_url_https === 'string' ? author.profile_image_url_https : undefined;
    const authorVerified = author?.verified === true;
    const entities = (legacy.entities ?? {}) as Record<string, unknown>;
    const extEntities = (legacy.extended_entities ?? entities) as Record<string, unknown>;
    const mediaRaw = ((extEntities.media as unknown[]) ?? []).filter(
      (m): m is Record<string, unknown> => !!m && typeof m === 'object'
    );
    const media: TwitterTimelineItem['media'] = mediaRaw
      .map((m): TwitterTimelineItem['media'][number] => {
        const t = m.type as string | undefined;
        const type: 'photo' | 'video' | 'gif' = t === 'video' ? 'video' : t === 'animated_gif' ? 'gif' : 'photo';
        return {
          type,
          url: typeof m.media_url_https === 'string' ? (m.media_url_https as string) : '',
        };
      })
      .filter((m) => m.url);

    items.push({
      id,
      url: `https://x.com/${authorSn}/status/${id}`,
      text,
      created_at: createdAt,
      created_at_ms: Number.isFinite(createdMs) ? createdMs : 0,
      author: { screen_name: authorSn, name: authorName, avatar_url: authorAvatar, verified: authorVerified },
      reply_count: typeof legacy.reply_count === 'number' ? legacy.reply_count : undefined,
      retweet_count: typeof legacy.retweet_count === 'number' ? legacy.retweet_count : undefined,
      favorite_count: typeof legacy.favorite_count === 'number' ? legacy.favorite_count : undefined,
      quote_count: typeof legacy.quote_count === 'number' ? legacy.quote_count : undefined,
      view_count: undefined,
      media,
      is_retweet: isRetweet,
      is_reply: isReply,
      is_quote: isQuote,
      is_pinned: isPinned,
    });
  }

  function isPinnedFromContext(itemContent: Record<string, unknown> | undefined): boolean {
    if (!itemContent) return false;
    const ctx = itemContent.socialContext as Record<string, unknown> | undefined;
    if (!ctx) return false;
    // socialContext.contextType === 'Pin' OR socialContext.text === 'Pinned'
    return ctx.contextType === 'Pin' || ctx.text === 'Pinned';
  }

  for (const ins of instructions) {
    if (!ins || typeof ins !== 'object') continue;
    const insRec = ins as Record<string, unknown>;
    // Single-entry pins (TimelinePinEntry instruction)
    if (insRec.entry) {
      const entry = insRec.entry as Record<string, unknown>;
      const content = entry.content as Record<string, unknown> | undefined;
      const itemContent = content?.itemContent as Record<string, unknown> | undefined;
      if (itemContent && itemContent.itemType === 'TimelineTweet') {
        pushFromTweetResult(itemContent.tweet_results, false, true);
      }
    }
    // TimelineAddEntries — the bulk feed
    if (insRec.type === 'TimelineAddEntries' && Array.isArray(insRec.entries)) {
      for (const entry of insRec.entries as unknown[]) {
        if (!entry || typeof entry !== 'object') continue;
        const entryRec = entry as Record<string, unknown>;
        if (typeof entryRec.entryId === 'string' && entryRec.entryId.startsWith('cursor-')) continue;
        const content = entryRec.content as Record<string, unknown> | undefined;
        if (!content) continue;
        const itemContent = content.itemContent as Record<string, unknown> | undefined;
        if (itemContent && itemContent.itemType === 'TimelineTweet') {
          const tweetResults = itemContent.tweet_results as Record<string, unknown> | undefined;
          const result = tweetResults?.result as Record<string, unknown> | undefined;
          const legacy = result?.legacy as Record<string, unknown> | undefined;
          const isRt = !!legacy?.retweeted_status_result;
          const isPinned = isPinnedFromContext(itemContent);
          pushFromTweetResult(tweetResults, isRt, isPinned);
        }
        // Conversation modules (threaded replies). Skip — we want top-level tweets.
      }
    }
  }

  // Dedupe by ID — pins sometimes appear twice.
  const seen = new Set<string>();
  return items.filter((it) => {
    if (!it.id || seen.has(it.id)) return false;
    seen.add(it.id);
    return true;
  });
}

export async function fetchUserTimeline(
  env: Env,
  screenName: string,
  options: { count?: number; sinceDays?: number; includePinned?: boolean } = {}
): Promise<TwitterTimelineResponse> {
  if (!SCREEN_NAME_RE.test(screenName)) {
    throw new Error(`invalid screen_name: ${screenName}`);
  }
  const lower = screenName.toLowerCase();

  const sinceDays = options.sinceDays ?? 7;
  const includePinned = options.includePinned === true;
  const edgeCache = (caches as unknown as { default: Cache }).default;
  // v2 cache key includes sinceDays + includePinned so the freshness
  // filter doesn't mix with stale "all-time" caches. v1 keys are
  // implicitly evicted.
  const cacheKey = new Request(
    `https://tw-tweets-cache.internal/v3?h=${lower}&d=${sinceDays}&p=${includePinned ? 1 : 0}`
  );
  const cached = await edgeCache.match(cacheKey);
  if (cached) {
    try {
      const body = (await cached.json()) as TwitterTimelineResponse;
      return { ...body, cached: true };
    } catch {
      /* fall through to live fetch */
    }
  }

  let userInfo;
  let userTweetsResp: unknown;
  let lastError: string | undefined;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      userInfo = await resolveUserId(env, lower);
      const token = await activateGuestToken(env);
      const variables = encodeURIComponent(
        JSON.stringify({
          userId: userInfo.id,
          count: Math.min(options.count ?? 20, MAX_TWEETS_PER_CALL),
          includePromotedContent: false,
          withVoice: true,
          withV2Timeline: true,
        })
      );
      const features = encodeURIComponent(JSON.stringify(FEATURES_USER_TWEETS));
      const url = `https://api.twitter.com/graphql/${USER_TWEETS_QID}/UserTweets?variables=${variables}&features=${features}`;
      const { data } = await graphqlGet<unknown>(env, token, url);
      userTweetsResp = data;
      break;
    } catch (e) {
      lastError = (e as Error).message;
      if (e instanceof TwitterRateLimited) throw e;
      // 401/403/etc — guest token was cleared, retry once.
      if (attempt === 0) continue;
      throw e;
    }
  }

  if (!userInfo) throw new Error(lastError ?? 'user lookup failed');
  if (userTweetsResp === undefined) throw new Error(lastError ?? 'UserTweets call failed');

  const allItems = parseTimeline(userTweetsResp, lower);

  // Freshness filter: drop tweets older than `sinceDays` (default 7).
  // X's timeline often leads with a multi-year-old PINNED tweet for
  // dormant accounts — filtering by window hides those. Pinned tweets
  // within-window are surfaced normally (with the is_pinned flag); pinned
  // tweets older than window can be included via includePinned=true.
  // (sinceDays + includePinned already declared above for cache key.)
  const cutoffMs = Date.now() - sinceDays * 86_400_000;
  const items = allItems
    .filter((it) => {
      if (it.created_at_ms === 0) return false; // unparseable date — drop conservatively
      if (it.created_at_ms >= cutoffMs) return true;
      // Out of window. Keep only if it's a pinned tweet AND caller opted in.
      return includePinned && it.is_pinned;
    })
    // Newest-first so the FE doesn't have to re-sort
    .sort((a, b) => b.created_at_ms - a.created_at_ms);

  // Distinguish "account posted nothing in-window" from "upstream served a
  // frozen snapshot". X's guest-token timeline has been observed returning
  // 99-100 tweets for active accounts with every single one outside the
  // freshness window (newest ~1 year old, 2026-10-17). A bare `items: []`
  // read as "quiet account" and hid that. Surface the distinction, and cache
  // the degraded build for minutes rather than the full half hour so a fix
  // on X's side shows up quickly.
  const newestParsedMs = allItems.reduce((m, it) => Math.max(m, it.created_at_ms), 0);
  const staleGuestTimeline = items.length === 0 && allItems.length > 0;

  const body: TwitterTimelineResponse = {
    handle: lower,
    user_id: userInfo.id,
    display_name: userInfo.name,
    bio: userInfo.bio,
    followers_count: userInfo.followers,
    items,
    generated_at: new Date().toISOString(),
    cached: false,
    ...(staleGuestTimeline
      ? {
          stale_guest_timeline: true,
          newest_available_at: newestParsedMs ? new Date(newestParsedMs).toISOString() : undefined,
          upstream_error: `guest timeline returned only out-of-window tweets (${allItems.length} parsed, 0 within ${sinceDays}d)`,
        }
      : {}),
  };

  // Cache successful responses; failures are NOT cached so the next visit retries.
  try {
    const ttl = staleGuestTimeline ? DEGRADED_TWEETS_TTL : CACHE_TWEETS_TTL;
    const cacheable = new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${ttl}, s-maxage=${ttl}`,
      },
    });
    await edgeCache.put(cacheKey, cacheable);
  } catch {
    /* swallow */
  }
  return body;
}
