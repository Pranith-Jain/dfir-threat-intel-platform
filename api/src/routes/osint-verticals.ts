/**
 * OSINT vertical routes — LeakScope and DarkForums IP intelligence.
 *
 * Both verticals ship a bulk dataset as a static manifest under
 * /public/data/threat-intel/. The Worker reads the manifest from the ASSETS
 * binding and does the search, filtering and pagination itself, rather than
 * shipping the whole file to the browser.
 *
 * That split is not an optimization, it is the point:
 *
 *   - LeakScope's index is 11.8k rows / 3.9 MB. The page needs to search
 *     across all of them on every keystroke; a client-side index would mean
 *     a 3.9 MB download before the first character is typed.
 *   - DarkForums' actor directory is 38k actors / 8.3 MB, and only the
 *     actor endpoints need it. The country map loads one country file at a
 *     time.
 *
 * ## What LeakScope does and does not expose
 *
 * The upstream index carries thread metadata only — title, author, dates,
 * engagement counts — with every URL column stripped before it is written.
 * There is no link to a leak from these routes, by construction.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { notFound, respondError } from '../lib/api-error';
import {
  loadDarkforumsActors,
  loadDarkforumsCountry,
  loadDarkforumsIndex,
  loadLeakScopeIndex,
  type DarkforumsActor,
  type LeakScopeEntry,
} from '../lib/forum-intel-manifest';

const CACHE_TTL_SECONDS = 15 * 60;

/* ─── LeakScope ───────────────────────────────────────────────────────────── */

export interface LeakScopeRow {
  tid: string;
  source: string;
  prefix: string | null;
  title: string;
  author: string;
  published_at: string | null;
  replies: number;
  views: number;
  pages: number;
  attachments: number;
  last_post_at: string | null;
  last_post_by: string;
  status: string;
}

export interface LeakScopeResponse {
  generated_at: string;
  source: string;
  source_url: string;
  license: string;
  synced_at: string;
  counts: Record<string, number>;
  total: number;
  page: number;
  limit: number;
  pages: number;
  entries: LeakScopeRow[];
}

const NUMERIC_SORTS = new Set(['views', 'replies', 'pages', 'attachments', 'published_at', 'title', 'author']);

/**
 * Search, filter, sort and paginate the leak index.
 *
 * The query is a case-insensitive substring match across the fields an
 * analyst would actually search by — title, author and prefix — rather than
 * a blind match over every key. Matching on `status` would surface a page
 * of threads whose only hit was the word "new".
 */
function filterEntries(
  entries: LeakScopeEntry[],
  opts: { q: string; source: string; sort: string; dir: 'asc' | 'desc' }
): LeakScopeEntry[] {
  const q = opts.q.trim().toLowerCase();
  let rows = entries;

  if (opts.source === 'breach' || opts.source === 'darkforum') {
    rows = rows.filter((e) => e.source === opts.source);
  }

  if (q) {
    rows = rows.filter((e) => {
      const haystack = `${e.title ?? ''} ${e.author ?? ''} ${e.prefix ?? ''}`.toLowerCase();
      return haystack.includes(q);
    });
  }

  const sort = NUMERIC_SORTS.has(opts.sort) ? opts.sort : 'published_at';
  const dir = opts.dir === 'asc' ? 1 : -1;

  return [...rows].sort((a, b) => {
    let av: number | string;
    let bv: number | string;
    switch (sort) {
      case 'views':
        av = a.views ?? 0;
        bv = b.views ?? 0;
        break;
      case 'replies':
        av = a.replies ?? 0;
        bv = b.replies ?? 0;
        break;
      case 'pages':
        av = a.pages ?? 0;
        bv = b.pages ?? 0;
        break;
      case 'attachments':
        av = a.attachments ?? 0;
        bv = b.attachments ?? 0;
        break;
      case 'published_at':
        av = a.published_at ?? '';
        bv = b.published_at ?? '';
        break;
      case 'title':
        av = (a.title ?? '').toLowerCase();
        bv = (b.title ?? '').toLowerCase();
        break;
      case 'author':
        av = (a.author ?? '').toLowerCase();
        bv = (b.author ?? '').toLowerCase();
        break;
      default:
        av = a.published_at ?? '';
        bv = b.published_at ?? '';
    }
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    // Stable tiebreak so pagination does not shuffle equal rows.
    return (a.tid ?? '').localeCompare(b.tid ?? '');
  });
}

export async function leakScopeHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const url = new URL(c.req.url);
  const q = url.searchParams.get('q') ?? '';
  const source = url.searchParams.get('source') ?? '';
  const sort = url.searchParams.get('sort') ?? 'published_at';
  const dir = (url.searchParams.get('dir') ?? 'desc') === 'asc' ? 'asc' : 'desc';

  const pageRaw = Number.parseInt(url.searchParams.get('page') ?? '1', 10);
  const page = Number.isFinite(pageRaw) ? Math.max(1, pageRaw) : 1;
  const limitRaw = Number.parseInt(url.searchParams.get('limit') ?? '50', 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, 200)) : 50;

  try {
    const index = await loadLeakScopeIndex(c.env.ASSETS);
    const filtered = filterEntries(index.entries, { q, source, sort, dir });
    const pages = Math.max(1, Math.ceil(filtered.length / limit));
    const pageClamped = Math.min(page, pages);
    const slice = filtered.slice((pageClamped - 1) * limit, pageClamped * limit);

    const body: LeakScopeResponse = {
      generated_at: new Date().toISOString(),
      source: index.source,
      source_url: index.sourceUrl,
      license: index.license,
      synced_at: index.syncedAt,
      counts: index.counts,
      total: filtered.length,
      page: pageClamped,
      limit,
      pages,
      entries: slice.map((e) => ({
        tid: e.tid,
        source: e.source,
        prefix: e.prefix ?? null,
        title: e.title,
        author: e.author,
        published_at: e.published_at ?? null,
        replies: e.replies ?? 0,
        views: e.views ?? 0,
        pages: e.pages ?? 0,
        attachments: e.attachments ?? 0,
        last_post_at: e.last_post_at ?? null,
        last_post_by: e.last_post_by ?? '',
        status: e.status ?? '',
      })),
    };

    return c.json(body, 200, {
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
    });
  } catch (e) {
    logError('leakscope handler failed', e);
    return respondError(c, 'leakscope_unavailable', e instanceof Error ? e.message : String(e), 503);
  }
}

/* ─── DarkForums IP intelligence ──────────────────────────────────────────── */

export interface DarkforumsIndexResponse {
  generated_at: string;
  source: string;
  source_url: string;
  license: string;
  geo_source: string;
  synced_at: string;
  counts: Record<string, number>;
  countries: unknown[];
  top_actors: DarkforumsActor[];
}

export async function darkforumsIpHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const index = await loadDarkforumsIndex(c.env.ASSETS);
    const body: DarkforumsIndexResponse = {
      generated_at: new Date().toISOString(),
      source: index.source,
      source_url: index.sourceUrl,
      license: index.license,
      geo_source: index.geoSource,
      synced_at: index.syncedAt,
      counts: index.counts,
      countries: index.countries,
      top_actors: index.top_actors,
    };
    return c.json(body, 200, {
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
    });
  } catch (e) {
    logError('darkforums-ip handler failed', e);
    return respondError(c, 'darkforums_unavailable', e instanceof Error ? e.message : String(e), 503);
  }
}

export async function darkforumsCountryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const iso = (c.req.param('iso') ?? '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(iso)) {
    return respondError(c, 'invalid_country', `Expected a two-letter ISO country code, got "${iso}".`, 400);
  }
  try {
    const body = await loadDarkforumsCountry(c.env.ASSETS, iso);
    if (!body) return notFound(c, `No DarkForums observations attributed to ${iso}.`);
    return c.json(body, 200, {
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
    });
  } catch (e) {
    logError('darkforums-country handler failed', e);
    return respondError(c, 'darkforums_unavailable', e instanceof Error ? e.message : String(e), 503);
  }
}

export interface DarkforumsActorResponse {
  generated_at: string;
  query: string;
  total: number;
  matches: DarkforumsActor[];
}

/**
 * Search the actor directory.
 *
 * Substring match, case-insensitive, ranked by how much infrastructure the
 * actor has — an analyst looking up a username wants the account with the
 * most IPs, not the alphabetically first one.
 */
export async function darkforumsActorsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const url = new URL(c.req.url);
  const q = (url.searchParams.get('q') ?? '').trim().toLowerCase();
  const limitRaw = Number.parseInt(url.searchParams.get('limit') ?? '30', 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, 100)) : 30;

  try {
    const { actors } = await loadDarkforumsActors(c.env.ASSETS);
    const matches = q
      ? actors.filter((a) => a.username.toLowerCase().includes(q)).slice(0, limit)
      : actors.slice(0, limit);

    const body: DarkforumsActorResponse = {
      generated_at: new Date().toISOString(),
      query: q,
      total: q ? actors.filter((a) => a.username.toLowerCase().includes(q)).length : actors.length,
      matches,
    };
    return c.json(body, 200, {
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
    });
  } catch (e) {
    logError('darkforums-actors handler failed', e);
    return respondError(c, 'darkforums_unavailable', e instanceof Error ? e.message : String(e), 503);
  }
}
