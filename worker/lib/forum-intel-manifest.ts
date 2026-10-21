/**
 * Leak-intel manifest loader.
 *
 * Reads the static JSON manifests shipped in /public/data/threat-intel/ for
 * the two verticals that carry bulk dark-web reference data:
 *
 *   - LeakScope        breach / dark-forum leak thread metadata (11.8k rows)
 *   - DarkForums IP    forum IP/actor observations with country attribution
 *   - Actor forums     MyBB account directory (324k actors, sharded)
 *
 * Named `leak-intel` rather than folded into `osint-manifest.ts` (which
 * holds the OSINT Framework portal catalog) or `threat-intel-manifest.ts`
 * (which holds the CVE/IOC family) because these two have a different
 * shape: their indexes are large (3.9 MB and 316 KB) and are read for
 * search and filtering rather than for a single body lookup.
 *
 * ## Memory
 *
 * The LeakScope index is held in memory after the first read — it is one
 * JSON document and the alternative (re-parsing 3.9 MB per request) is
 * worse. The DarkForums actor directory (8.3 MB, 38k actors) is read on
 * demand and held for a bounded time, because only the actor endpoints need
 * it.
 *
 * IMPORTANT: none of these manifests carry a URL to a leak, a dump, or a
 * dark-forum thread. The LeakScope upstream strips URL columns before
 * display and this sync strips them before writing, so the metadata index
 * says *what was exposed* and never *where to get it*.
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

const DATA_PREFIX = '/data/threat-intel';
const HOST = 'https://leak-intel.local';

/* ─── LeakScope ───────────────────────────────────────────────────────────── */

export interface LeakScopeEntry {
  /** Thread id as published by the source forum. */
  tid: string;
  /** Which index the thread came from. */
  source: 'breach' | 'darkforum';
  /** Thread prefix / board tag, when the forum has one. */
  prefix?: string | null;
  title: string;
  author: string;
  /** ISO publish timestamp, or null when the source format was unparseable. */
  published_at?: string | null;
  /** The raw source string, kept only when it could not be parsed. */
  published_raw?: string;
  replies: number;
  views: number;
  pages: number;
  attachments: number;
  last_post_at?: string | null;
  last_post_raw?: string;
  last_post_by: string;
  status: string;
  captured_at?: string | null;
  [key: string]: unknown;
}

export interface LeakScopeIndex {
  schemaVersion: string;
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  counts: {
    total: number;
    breach: number;
    darkforum: number;
    authors: number;
    prefixes: number;
    with_ransomware_note: number;
  };
  entries: LeakScopeEntry[];
}

let cachedLeakScopeIndex: LeakScopeIndex | null = null;
let cachedLeakScopeIndexAt = 0;

export async function loadLeakScopeIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<LeakScopeIndex> {
  if (cachedLeakScopeIndex && !opts.forceRefresh) return cachedLeakScopeIndex;
  const idx = await fetchJsonAsset<LeakScopeIndex>(assets, `${DATA_PREFIX}/leakscope/index.json`, HOST);
  if (!idx) {
    throw new Error(
      `LeakScope manifest not found at ${DATA_PREFIX}/leakscope/index.json — ` +
        'did the build run? Run `node scripts/sync-leakscope.mjs && node scripts/build-leakscope.mjs`.'
    );
  }
  cachedLeakScopeIndex = idx;
  cachedLeakScopeIndexAt = Date.now();
  return idx;
}

/* ─── DarkForums IP intelligence ──────────────────────────────────────────── */

export interface DarkforumsCountry {
  iso: string;
  name: string;
  lat: number;
  lon: number;
  observations: number;
  actors: number;
  unique_ips: number;
}

export interface DarkforumsActor {
  username: string;
  ip_count: number;
  country_count: number;
  countries: Array<{ iso: string; count: number }>;
  ips: Array<{ ip: string; iso: string }>;
  ips_truncated: boolean;
}

export interface DarkforumsIndex {
  schemaVersion: string;
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  geoSource: string;
  syncedAt: string;
  counts: {
    observations: number;
    unique_ips: number;
    actors: number;
    countries: number;
    unattributed: number;
    skipped_posts: number;
  };
  countries: DarkforumsCountry[];
  top_actors: DarkforumsActor[];
}

export interface DarkforumsCountryBody {
  iso: string;
  name: string;
  lat: number;
  lon: number;
  /** Total observations in this country (before the per-country point cap). */
  total: number;
  /** Points actually present in this file. */
  shown: number;
  /** True when `total` exceeds `shown`. */
  truncated: boolean;
  actors: number;
  points: Array<{ ip: string; username: string; lat: number; lon: number }>;
}

let cachedDarkforumsIndex: DarkforumsIndex | null = null;
let cachedDarkforumsIndexAt = 0;

export async function loadDarkforumsIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<DarkforumsIndex> {
  if (cachedDarkforumsIndex && !opts.forceRefresh) return cachedDarkforumsIndex;
  const idx = await fetchJsonAsset<DarkforumsIndex>(assets, `${DATA_PREFIX}/darkforums-ip/index.json`, HOST);
  if (!idx) {
    throw new Error(
      `DarkForums IP manifest not found at ${DATA_PREFIX}/darkforums-ip/index.json — ` +
        'did the build run? Run `node scripts/sync-darkforums-ip.mjs && node scripts/build-darkforums-ip.mjs`.'
    );
  }
  cachedDarkforumsIndex = idx;
  cachedDarkforumsIndexAt = Date.now();
  return idx;
}

const darkforumsCountryCache: BodyCache<DarkforumsCountryBody> = { map: new Map(), hits: 0, misses: 0 };
const MAX_COUNTRY_CACHE = 24;

export async function loadDarkforumsCountry(assets: Fetcher, iso: string): Promise<DarkforumsCountryBody | null> {
  const key = iso.toUpperCase();
  if (!/^[A-Z]{2}$/.test(key)) return null;
  const hit = trackHit(darkforumsCountryCache, key);
  if (hit) return hit;
  const body = await fetchJsonAsset<DarkforumsCountryBody>(
    assets,
    `${DATA_PREFIX}/darkforums-ip/geo/${key}.json`,
    HOST
  );
  if (!body) return null;
  return recordHit(darkforumsCountryCache, key, body, MAX_COUNTRY_CACHE);
}

/**
 * The actor directory.
 *
 * 8.3 MB parsed into ~40k objects is roughly 20 MB of heap, which is real
 * against the Worker's 128 MB cap. It is therefore read on demand and held
 * for a bounded time — the endpoints that need it need all of it, so
 * holding several copies would be pure waste.
 */
let cachedDarkforumsActors: { actors: DarkforumsActor[] } | null = null;
let cachedDarkforumsActorsAt = 0;
const ACTOR_TTL_MS = 6 * 3600 * 1000;

export async function loadDarkforumsActors(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<{ actors: DarkforumsActor[] }> {
  if (cachedDarkforumsActors && !opts.forceRefresh && Date.now() - cachedDarkforumsActorsAt < ACTOR_TTL_MS) {
    return cachedDarkforumsActors;
  }
  const body = await fetchJsonAsset<{ actors: DarkforumsActor[] }>(
    assets,
    `${DATA_PREFIX}/darkforums-ip/actors.json`,
    HOST
  );
  if (!body) {
    throw new Error(
      `DarkForums actor directory not found at ${DATA_PREFIX}/darkforums-ip/actors.json — ` +
        'did the build run? Run `node scripts/sync-darkforums-ip.mjs && node scripts/build-darkforums-ip.mjs`.'
    );
  }
  cachedDarkforumsActors = body;
  cachedDarkforumsActorsAt = Date.now();
  return body;
}

/* ─── Forum actor directory (Actores Maliciosos) ─────────────────────────── */

export interface ForumActor {
  uid: string;
  username: string;
  usergroup?: string;
  display_group?: string;
  title?: string;
  posts?: number;
  threads?: number;
  reputation?: number;
  registered_at?: string;
  last_active_at?: string;
  last_post_at?: string;
  registration_ip?: string;
  last_ip?: string;
  website?: string;
  timezone?: string;
  warning_points?: number;
}

export interface ForumActorIndex {
  schemaVersion: string;
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  /** The salt for the email-hash lookup table. Published, not secret. */
  email_salt: string;
  counts: {
    accounts: number;
    actors: number;
    with_email: number;
    with_ip: number;
    actor_shards: number;
    email_shards: number;
    misaligned_dropped: number;
  };
  actor_shards: Array<{ shard: string; actors: number }>;
  /** The columns that were deliberately never copied out of the source. */
  excluded_columns: string[];
}

export interface ForumActorShard {
  shard: string;
  actors: ForumActor[];
}

let cachedForumActorIndex: ForumActorIndex | null = null;
let cachedForumActorIndexAt = 0;

export async function loadForumActorIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<ForumActorIndex> {
  if (cachedForumActorIndex && !opts.forceRefresh) return cachedForumActorIndex;
  const idx = await fetchJsonAsset<ForumActorIndex>(assets, `${DATA_PREFIX}/actor-forums/index.json`, HOST);
  if (!idx) {
    throw new Error(
      `Forum actor manifest not found at ${DATA_PREFIX}/actor-forums/index.json — ` +
        'did the build run? Run `node scripts/sync-actor-forums.mjs && node scripts/build-actor-forums.mjs`.'
    );
  }
  cachedForumActorIndex = idx;
  cachedForumActorIndexAt = Date.now();
  return idx;
}

const forumActorShardCache: BodyCache<ForumActorShard> = { map: new Map(), hits: 0, misses: 0 };
const MAX_ACTOR_SHARD_CACHE = 8;

/**
 * The shard a username belongs to.
 *
 * One shard per starting character, so a prefix lookup — "I have this
 * handle" — loads exactly one file instead of a 60 MB index.
 */
export function forumActorShard(username: string): string {
  const first = username.trim().toLowerCase().charAt(0);
  if (first >= 'a' && first <= 'z') return first;
  if (first >= '0' && first <= '9') return first;
  return '_';
}

export async function loadForumActorShard(assets: Fetcher, shard: string): Promise<ForumActorShard | null> {
  const key = shard.toLowerCase();
  if (!/^[a-z0-9_]$/.test(key)) return null;
  const hit = trackHit(forumActorShardCache, key);
  if (hit) return hit;
  const body = await fetchJsonAsset<ForumActorShard>(assets, `${DATA_PREFIX}/actor-forums/actors/${key}.json`, HOST);
  if (!body) return null;
  return recordHit(forumActorShardCache, key, body, MAX_ACTOR_SHARD_CACHE);
}

/**
 * The email-hash lookup table, one shard per hash prefix.
 *
 * The shipped table holds salted SHA-256 hashes, not addresses, so an
 * exact-match search works without the plaintext corpus being replicated.
 * Each entry carries the uid and the username, so a hash hit resolves to a
 * full actor record by loading exactly one username shard.
 */
export async function loadForumEmailShard(
  assets: Fetcher,
  shard: string
): Promise<Record<string, { uid: string; username: string }> | null> {
  const key = shard.toLowerCase();
  if (!/^[0-9a-f]{2}$/.test(key)) return null;
  try {
    return await fetchJsonAsset<Record<string, { uid: string; username: string }>>(
      assets,
      `${DATA_PREFIX}/actor-forums/emails/${key}.json`,
      HOST
    );
  } catch {
    return null;
  }
}

/* ─── Cache bookkeeping ───────────────────────────────────────────────────── */

/** Hit/miss counters, surfaced by the manifest cache stats endpoint. */
export function leakIntelCacheStats(): {
  leakscope: { loaded: boolean; entries: number; at: number };
  darkforums: { loaded: boolean; countries: number; at: number };
  darkforumsActors: { loaded: boolean; actors: number; at: number };
  darkforumsCountries: { hits: number; misses: number };
  forumActors: { loaded: boolean; actors: number; at: number };
  forumActorShards: { hits: number; misses: number };
} {
  return {
    leakscope: {
      loaded: !!cachedLeakScopeIndex,
      entries: cachedLeakScopeIndex?.entries.length ?? 0,
      at: cachedLeakScopeIndexAt,
    },
    darkforums: {
      loaded: !!cachedDarkforumsIndex,
      countries: cachedDarkforumsIndex?.countries.length ?? 0,
      at: cachedDarkforumsIndexAt,
    },
    darkforumsActors: {
      loaded: !!cachedDarkforumsActors,
      actors: cachedDarkforumsActors?.actors.length ?? 0,
      at: cachedDarkforumsActorsAt,
    },
    darkforumsCountries: {
      hits: darkforumsCountryCache.hits,
      misses: darkforumsCountryCache.misses,
    },
    forumActors: {
      loaded: !!cachedForumActorIndex,
      actors: cachedForumActorIndex?.counts.actors ?? 0,
      at: cachedForumActorIndexAt,
    },
    forumActorShards: {
      hits: forumActorShardCache.hits,
      misses: forumActorShardCache.misses,
    },
  };
}

/** Drop every cached manifest. Used by tests and by the cache-clear path. */
export function clearLeakIntelCaches(): void {
  cachedLeakScopeIndex = null;
  cachedLeakScopeIndexAt = 0;
  cachedDarkforumsIndex = null;
  cachedDarkforumsIndexAt = 0;
  cachedDarkforumsActors = null;
  cachedDarkforumsActorsAt = 0;
  darkforumsCountryCache.map.clear();
  darkforumsCountryCache.hits = 0;
  darkforumsCountryCache.misses = 0;
  cachedForumActorIndex = null;
  cachedForumActorIndexAt = 0;
  forumActorShardCache.map.clear();
  forumActorShardCache.hits = 0;
  forumActorShardCache.misses = 0;
}
