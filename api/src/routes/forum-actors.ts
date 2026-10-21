/**
 * Forum actor directory routes.
 *
 *   GET /api/v1/threat-intel/forum-actors?q=<handle|email>
 *   GET /api/v1/threat-intel/forum-actors/stats
 *
 * Ported from Actores Maliciosos Search (github.com/Ivancastl/actores-maliciosos-search):
 * search the accounts of actors on compromised forums.
 *
 * ## What this surface does and does not expose
 *
 * The upstream tool returns the full MyBB row for an account, which includes
 * the password hash, the salt and the session key. **None of that is
 * replicated here.** The build copies the profile fields an analyst
 * actually pivots on — handle, activity, registration and last-seen IPs,
 * dates — and drops credential material and private per-user state
 * entirely. See `scripts/build-actor-forums.mjs` for the exact exclusion
 * list, which is also published in the manifest so it can be audited.
 *
 * Email addresses are searched through a salted hash rather than a
 * plaintext corpus: the query is hashed with the manifest's published salt
 * and looked up. The capability matches the upstream tool's; the plaintext
 * addresses are not replicated here.
 *
 * ## Cost
 *
 * The directory holds 324k actors and is sharded by the first character of
 * the username, so a handle search reads exactly one shard. An email
 * search reads exactly one of 256 hash shards. Both are single asset
 * reads — no upstream fetch, no Worker CPU.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { respondError } from '../lib/api-error';
import {
  forumActorShard,
  loadForumActorIndex,
  loadForumActorShard,
  loadForumEmailShard,
} from '../lib/forum-intel-manifest';

const CACHE_TTL_SECONDS = 30 * 60;
const MAX_RESULTS = 50;

/**
 * Salted SHA-256 of a lowercased email, truncated to 128 bits.
 *
 * Must match `hashEmail` in scripts/build-actor-forums.mjs exactly — the
 * two are the same function on either side of the build, and a divergence
 * would make every email search silently return nothing.
 */
async function hashEmail(email: string, salt: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}:${email.trim().toLowerCase()}`));
  // Truncated to the same 32 hex characters the build wrote.
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32);
}

export interface ForumActorHit {
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

export async function forumActorsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const url = new URL(c.req.url);
  const q = (url.searchParams.get('q') ?? '').trim();
  if (!q) {
    return respondError(
      c,
      'missing_query',
      'Pass a username or an email address as ?q=… (at least two characters).',
      400
    );
  }
  if (q.length < 2) {
    return respondError(c, 'query_too_short', 'Use at least two characters.', 400);
  }

  const limitRaw = Number.parseInt(url.searchParams.get('limit') ?? '25', 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, MAX_RESULTS)) : 25;

  try {
    const index = await loadForumActorIndex(c.env.ASSETS);

    // An email query goes through the hash table; a handle query goes
    // through the username shard.
    const looksLikeEmail = q.includes('@');
    const hits: ForumActorHit[] = [];
    let mode: 'email' | 'username' = 'username';
    let note: string | undefined;

    if (looksLikeEmail) {
      mode = 'email';
      const hash = await hashEmail(q, index.email_salt);
      const shard = hash.slice(0, 2);
      const table = await loadForumEmailShard(c.env.ASSETS, shard);
      const entry = table?.[hash];
      if (entry) {
        // The hash table carries the username, so the actor record is
        // resolved by loading exactly ONE username shard.
        const body = await loadForumActorShard(c.env.ASSETS, forumActorShard(entry.username));
        const found = body?.actors.find((a) => a.uid === entry.uid);
        if (found) hits.push(found as ForumActorHit);
      }
    } else {
      const shard = forumActorShard(q);
      const body = await loadForumActorShard(c.env.ASSETS, shard);
      const actors = body?.actors ?? [];
      const needle = q.toLowerCase();
      // Prefix first, then substring: a prefix match is what "I have this
      // handle" means, and the substring pass catches the rest.
      const prefix = actors.filter((a) => a.username.toLowerCase().startsWith(needle));
      const contains = actors.filter((a) => !prefix.includes(a) && a.username.toLowerCase().includes(needle));
      hits.push(...([...prefix, ...contains].slice(0, limit) as ForumActorHit[]));
    }

    return c.json(
      {
        generated_at: new Date().toISOString(),
        query: q,
        mode,
        total: hits.length,
        matches: hits,
        ...(note ? { note } : {}),
      },
      200,
      {
        'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
      }
    );
  } catch (e) {
    logError('forum-actors handler failed', e);
    return respondError(c, 'forum_actors_unavailable', e instanceof Error ? e.message : String(e), 503);
  }
}

export async function forumActorsStatsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const index = await loadForumActorIndex(c.env.ASSETS);
    return c.json(
      {
        generated_at: new Date().toISOString(),
        source: index.source,
        source_url: index.sourceUrl,
        license: index.license,
        synced_at: index.syncedAt,
        counts: index.counts,
        actor_shards: index.actor_shards,
        excluded_columns: index.excluded_columns,
        note:
          'Password hashes, salts, session keys and private per-user state are not copied out of the ' +
          'source database. The excluded column list is published here so the omission can be audited.',
      },
      200,
      {
        'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
      }
    );
  } catch (e) {
    logError('forum-actors stats failed', e);
    return respondError(c, 'forum_actors_unavailable', e instanceof Error ? e.message : String(e), 503);
  }
}
