import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { githubHeaders } from '../lib/github-api';
import { badRequest, notFound, internalError, badGateway } from '../lib/api-error';
import { kvBackedGet } from '../lib/route-cache';
import { kvBulkGetText } from '../lib/safe-catch';
import { ACTOR_ALIASES } from '../data/threat-actor-aliases';

/**
 * Maltrail → skeleton actor sync.
 *
 * Hokage-Intel pattern: when stamparm/maltrail has `apt_<name>.txt` files
 * for actors we don't know about, we auto-create a skeleton actor profile
 * so the IOCs always have a home. Later MITRE/Malpedia enrichment fleshes
 * out the profile in place.
 *
 * Storage:
 *   skeleton-actor:{slug}   → JSON SkeletonActor record
 *   skeleton-actor:index    → JSON array of slugs (used for fast listing
 *                             without a costly KV list call)
 *
 * Match rules:
 *   - Filename `apt_<token>(_<more>)?.txt` (e.g. `apt_lazarus.txt`,
 *     `apt_apt28.txt`, `apt_gold_dragon.txt`).
 *   - Token is normalised (lowercase, hyphens collapsed) and compared
 *     against ACTOR_ALIASES canonical + alias slugs (also normalised).
 *   - Any matched filename is recorded against the matching actor — even
 *     if no skeleton is written — so callers can see coverage.
 *
 * Concurrency:
 *   - Endpoint is idempotent. Re-running just updates `last_seen`.
 *   - Hard cap of MAX_SKELETONS per run prevents a runaway loop if the
 *     maltrail repo ever grows pathologically.
 */

const MALTRAIL_API = 'https://api.github.com/repos/stamparm/maltrail/contents/trails/static/malware';
const SKELETON_KEY_PREFIX = 'skeleton-actor:';
const SKELETON_INDEX_KEY = 'skeleton-actor:index';
/** Per-colo Cache-API shadow TTL for single-skeleton reads (matches the 300s response max-age). */
const SKELETON_SHADOW_TTL_SECONDS = 300;
// Bounds total KV writes per invocation. Each create is 1 put; each update is
// 1 get + 1 put. With the index read + list fetch, capping combined work at 15
// keeps worst-case subrequests (~33) well under the Free-plan 50/invocation cap.
// A large maltrail repo syncs incrementally across cron runs.
const MAX_SKELETONS_PER_RUN = 15;
const APT_FILE_RE = /^apt_([a-z0-9._-]+)\.txt$/i;

export interface SkeletonActor {
  slug: string;
  canonical_name: string;
  source_dataset: 'maltrail';
  maltrail_file: string;
  ioc_size_bytes?: number;
  discovered_at: string;
  last_seen: string;
  description: string;
}

function slugifyToken(token: string): string {
  return token
    .toLowerCase()
    .replace(/\.txt$/i, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function prettyName(slug: string): string {
  if (/^apt-?\d+/i.test(slug)) {
    return slug.toUpperCase().replace(/-/g, '');
  }
  return slug
    .split('-')
    .map((p) => (p.length === 0 ? p : p[0]!.toUpperCase() + p.slice(1)))
    .join(' ');
}

/** Build a lookup of every actor slug + alias slug, lowercased. */
const KNOWN_ACTOR_SLUGS = (() => {
  const out = new Set<string>();
  for (const a of ACTOR_ALIASES) {
    out.add(a.slug.toLowerCase());
    for (const alias of a.aliases) {
      out.add(slugifyToken(alias));
    }
    out.add(slugifyToken(a.canonical));
  }
  return out;
})();

async function readSkeletonIndex(kv: KVNamespace): Promise<string[]> {
  try {
    const raw = await kv.get(SKELETON_INDEX_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as string[];
    return Array.isArray(parsed) ? parsed : [];
  } catch (_catchErr) {
    logError('readSkeletonIndex failed', _catchErr);
    return [];
  }
}

async function writeSkeletonIndex(kv: KVNamespace, slugs: string[]): Promise<void> {
  await kv.put(SKELETON_INDEX_KEY, JSON.stringify(slugs));
}

export async function maltrailSyncHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const kv = c.env.KV_CACHE;
  if (!kv) return internalError(c, 'KV not configured');

  let files: Array<{ name: string; size?: number; type?: string }>;
  try {
    const res = await fetch(MALTRAIL_API, {
      headers: githubHeaders(c.env, { accept: 'application/vnd.github.v3+json' }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      return badGateway(c, `github contents API: ${res.status}`);
    }
    files = (await res.json()) as Array<{ name: string; size?: number; type?: string }>;
  } catch (err) {
    logError('maltrailSyncHandler failed', err);
    return badGateway(c, `maltrail list fetch: ${(err as Error).message}`);
  }

  const aptFiles = (Array.isArray(files) ? files : []).filter((f) => f.type === 'file' && APT_FILE_RE.test(f.name));

  const now = new Date().toISOString();
  const matched: Array<{ file: string; actor: string }> = [];
  const created: SkeletonActor[] = [];
  const updated: string[] = [];
  const skipped: string[] = [];

  // Read existing skeleton index up-front so we can detect updates vs. creates.
  const existingSlugs = new Set(await readSkeletonIndex(kv));
  const finalSlugs = new Set(existingSlugs);

  for (const f of aptFiles) {
    // Count BOTH creates and updates — each one costs a KV write (updates also
    // a read). The old guard only counted creates, so an all-updates run could
    // still fire hundreds of subrequests.
    if (created.length + updated.length >= MAX_SKELETONS_PER_RUN) {
      skipped.push(f.name);
      continue;
    }
    const m = APT_FILE_RE.exec(f.name);
    const token = m?.[1] ?? '';
    if (!token) {
      skipped.push(f.name);
      continue;
    }
    const slug = slugifyToken(token);
    if (KNOWN_ACTOR_SLUGS.has(slug)) {
      matched.push({ file: f.name, actor: slug });
      continue;
    }

    const isUpdate = existingSlugs.has(slug);
    const record: SkeletonActor = {
      slug,
      canonical_name: prettyName(slug),
      source_dataset: 'maltrail',
      maltrail_file: f.name,
      ioc_size_bytes: typeof f.size === 'number' ? f.size : undefined,
      discovered_at: isUpdate ? '' /* preserved below */ : now,
      last_seen: now,
      description:
        'Skeleton profile — auto-created from a stamparm/maltrail apt_*.txt file with no canonical actor match. ' +
        'Refresh later after MITRE/Malpedia ingestion to enrich.',
    };

    if (isUpdate) {
      try {
        const prev = await kv.get(`${SKELETON_KEY_PREFIX}${slug}`);
        if (prev) {
          const prevRec = JSON.parse(prev) as SkeletonActor;
          record.discovered_at = prevRec.discovered_at || now;
        } else {
          record.discovered_at = now;
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        record.discovered_at = now;
      }
      updated.push(slug);
    } else {
      finalSlugs.add(slug);
      created.push(record);
    }

    await kv.put(`${SKELETON_KEY_PREFIX}${slug}`, JSON.stringify(record));
  }

  // Persist the updated index whenever we added or pruned anything.
  if (created.length > 0) {
    await writeSkeletonIndex(kv, [...finalSlugs].sort());
  }

  return c.json(
    {
      ok: true,
      total_files_scanned: aptFiles.length,
      matched_count: matched.length,
      created_count: created.length,
      updated_count: updated.length,
      skipped_count: skipped.length,
      matched: matched.slice(0, 50),
      created,
      updated,
      generated_at: now,
    },
    200,
    { 'cache-control': 'no-store' }
  );
}

const SKELETON_LIST_CACHE_KEY = 'https://skeleton-actors-cache.internal/v1-list';

export async function listSkeletonActorsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const kv = c.env.KV_CACHE;
  if (!kv) return c.json({ items: [], count: 0, error: 'KV not configured' });

  // Per-colo Cache API front: this handler does an index read + one KV get per
  // slug (N+1). The list is rebuilt by the maltrail-sync cron/admin job, so a
  // 300s cache (matching the response max-age) avoids the N+1 on every request.
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(SKELETON_LIST_CACHE_KEY);
  try {
    const hit = await cache.match(cacheReq);
    if (hit) return new Response(hit.body, hit);
  } catch (_catchErr) {
    logError('listSkeletonActorsHandler failed', _catchErr);
    /* fall through to a fresh build */
  }

  const slugs = await readSkeletonIndex(kv);
  if (slugs.length === 0) {
    return c.json({ items: [], count: 0, generated_at: new Date().toISOString() }, 200, {
      'cache-control': 'public, max-age=300',
    });
  }

  // Cap the per-slug fan-out at MAX_READS. KV bulk reads make this a single
  // subrequest (was one get per slug), so the cap is no longer needed for the
  // Free-plan 50-subrequest budget — it's retained as a response-size policy
  // and can now be raised. The Cache API front keeps this off the hot path.
  const MAX_READS = 45;
  const slice = slugs.slice(0, MAX_READS);
  const values = await kvBulkGetText(
    kv,
    slice.map((slug) => `${SKELETON_KEY_PREFIX}${slug}`)
  );
  const records = slice.map((slug) => {
    try {
      const raw = values.get(`${SKELETON_KEY_PREFIX}${slug}`) ?? null;
      return raw ? (JSON.parse(raw) as SkeletonActor) : null;
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      return null;
    }
  });

  const items = records.filter((r): r is SkeletonActor => r !== null);
  const response = c.json(
    {
      items,
      count: items.length,
      total: slugs.length,
      truncated: slugs.length > MAX_READS,
      generated_at: new Date().toISOString(),
    },
    200,
    { 'cache-control': 'public, max-age=300' }
  );
  c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  return response;
}

const SLUG_PARAM_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

export async function getSkeletonActorHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const kv = c.env.KV_CACHE;
  if (!kv) return internalError(c, 'KV not configured');
  const slug = (c.req.param('slug') ?? '').toLowerCase();
  if (!SLUG_PARAM_RE.test(slug)) return badRequest(c, 'invalid slug');
  // L1-first: skeleton records only change on an admin-triggered sync, so the
  // per-colo Cache-API shadow (5 min — matching the response max-age) turns
  // repeat profile views into free cache hits instead of one KV read each.
  const backed = await kvBackedGet<unknown>(kv, `${SKELETON_KEY_PREFIX}${slug}`, SKELETON_SHADOW_TTL_SECONDS);
  if (!backed.value) return notFound(c, 'skeleton not found');
  return c.json(backed.value, 200, { 'cache-control': 'public, max-age=300' });
}
