/**
 * Newly-registered domain monitor.
 *
 *   GET    /api/v1/threat-intel/domain-monitor?q=banco&days=3
 *   GET    /api/v1/threat-intel/domain-monitor/watchlist
 *   POST   /api/v1/threat-intel/domain-monitor/watchlist
 *   DELETE /api/v1/threat-intel/domain-monitor/watchlist/:id
 *   GET    /api/v1/threat-intel/domain-monitor/watchlist/:id/matches
 *
 * Ported from DominiosINT (github.com/Ivancastl/dominiosint): fetch the
 * daily list of newly registered domains, filter it by keyword.
 *
 * ## Why a watchlist and not just a search box
 *
 * The upstream tool is a one-shot search — you type a word, it filters the
 * last N days, you read the result. That is useful, but it only finds
 * things someone was already looking for at that moment. The watchlist is
 * the difference between *looking* and *being told*: a registered keyword
 * is checked on every daily sweep, and the matches are recorded so the
 * same finding is not reported twice.
 *
 * ## Access
 *
 * The GET routes are public reads. The write routes are admin-gated by the
 * global POST/DELETE middleware (see api/src/index.ts) — a watchlist is
 * shared state, and one anonymous visitor adding 5,000 keywords would be a
 * denial of service on the daily sweep.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { notFound, respondError, serviceUnavailable } from '../lib/api-error';
import { safeJsonBody } from '../lib/safe-body';
import { isoDaysAgo, matchDomains, prepareKeywords, MAX_LOOKBACK_DAYS } from '../lib/domain-monitor';

const CACHE_TTL_SECONDS = 30 * 60;

interface DomainWatchRow {
  id: string;
  keyword: string;
  normalized: string;
  note: string | null;
  enabled: number;
  created_at: string;
  last_checked_at: string | null;
  match_count: number;
}

/* ─── Search ──────────────────────────────────────────────────────────────── */

export async function domainMonitorSearchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const url = new URL(c.req.url);
  const q = (url.searchParams.get('q') ?? '').trim();
  const daysRaw = Number.parseInt(url.searchParams.get('days') ?? '3', 10);
  const days = Number.isFinite(daysRaw) ? Math.max(1, Math.min(daysRaw, MAX_LOOKBACK_DAYS)) : 3;

  if (!q) {
    return respondError(
      c,
      'missing_keyword',
      'Pass the keyword to look for as ?q=banco (comma-separated for several).',
      400
    );
  }

  const keywords = q
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const prepared = prepareKeywords(keywords);
  if (prepared.length === 0) {
    return respondError(
      c,
      'keyword_too_short',
      'Each keyword must be at least 3 characters once accents are stripped.',
      400
    );
  }

  try {
    const window = Array.from({ length: days }, (_, i) => isoDaysAgo(i));
    const results = await Promise.all(
      window.map(async (date) => {
        const res = await fetch(`https://raw.githubusercontent.com/ccas10ca-prog/domain/main/dominios/${date}.txt`, {
          headers: { 'user-agent': 'pranithjain-dfir/1.0 (+https://pranithjain.qzz.io)' },
          signal: AbortSignal.timeout(15_000),
          cf: { cacheTtl: 3600, cacheEverything: true },
        } as RequestInit);
        if (!res.ok) return { date, domains: [] as string[], total: 0, ok: false };
        const text = await res.text();
        const domains = text
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l && l.includes('.'));
        return { date, domains: matchDomains(text, prepared), total: domains.length, ok: true };
      })
    );

    const daysOut = results
      .filter((r) => r.ok)
      .map((r) => ({ date: r.date, domains: r.domains, total_domains: r.total }));
    const total = daysOut.reduce((sum, d) => sum + d.domains.length, 0);

    return c.json(
      {
        generated_at: new Date().toISOString(),
        keywords: prepared,
        window,
        days: daysOut,
        total,
        source: 'ccas10ca-prog/domain — daily newly-registered domain lists',
      },
      200,
      {
        'cache-control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 2}`,
      }
    );
  } catch (e) {
    logError('domain-monitor search failed', e);
    return respondError(c, 'domain_monitor_failed', e instanceof Error ? e.message : String(e), 502);
  }
}

/* ─── Watchlist ───────────────────────────────────────────────────────────── */

export async function domainWatchlistListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  try {
    const { results } = await db
      .prepare(
        `SELECT id, keyword, normalized, note, enabled, created_at, last_checked_at, match_count
         FROM domain_watchlist ORDER BY created_at DESC LIMIT 200`
      )
      .all<DomainWatchRow>();
    return c.json(
      {
        generated_at: new Date().toISOString(),
        count: results.length,
        watches: results.map((r) => ({ ...r, enabled: r.enabled === 1 })),
      },
      200,
      { 'cache-control': 'no-store' }
    );
  } catch (e) {
    logError('domain-watchlist list failed', e);
    return respondError(c, 'watchlist_unavailable', e instanceof Error ? e.message : String(e), 500);
  }
}

export async function domainWatchlistCreateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const parsed = await safeJsonBody<{ keyword?: string; note?: string }>(c, { maxBytes: 4096 });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;
  if (!body) {
    return respondError(c, 'invalid_body', 'Expected a JSON body with a `keyword`.', 400);
  }
  const keyword = (body.keyword ?? '').trim();
  if (!keyword) {
    return respondError(c, 'missing_keyword', 'A keyword is required.', 400);
  }
  if (keyword.length > 120) {
    return respondError(c, 'keyword_too_long', 'Keep the keyword under 120 characters.', 400);
  }

  const normalized = prepareKeywords([keyword])[0];
  if (!normalized) {
    return respondError(
      c,
      'keyword_too_short',
      'The keyword must be at least 3 characters once accents are stripped.',
      400
    );
  }

  const id = `dw_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const now = new Date().toISOString();
  try {
    await db
      .prepare(
        `INSERT INTO domain_watchlist (id, keyword, normalized, note, enabled, created_at, match_count)
         VALUES (?, ?, ?, ?, 1, ?, 0)`
      )
      .bind(id, keyword, normalized, body.note?.trim() ?? null, now)
      .run();
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (message.includes('UNIQUE')) {
      return respondError(c, 'duplicate_keyword', 'That keyword is already being watched.', 409);
    }
    logError('domain-watchlist create failed', e);
    return respondError(c, 'watchlist_unavailable', message, 500);
  }

  return c.json(
    { id, keyword, normalized, note: body.note?.trim() ?? null, enabled: true, created_at: now, match_count: 0 },
    201,
    {
      'cache-control': 'no-store',
    }
  );
}

export async function domainWatchlistDeleteHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('id') ?? '';
  try {
    await db.prepare('DELETE FROM domain_watch_matches WHERE watch_id = ?').bind(id).run();
    const res = await db.prepare('DELETE FROM domain_watchlist WHERE id = ?').bind(id).run();
    const changes = (res.meta as { changes?: number } | undefined)?.changes ?? 0;
    if (!changes) return notFound(c, `No watch with id ${id}.`);
    return c.json({ deleted: true, id }, 200, { 'cache-control': 'no-store' });
  } catch (e) {
    logError('domain-watchlist delete failed', e);
    return respondError(c, 'watchlist_unavailable', e instanceof Error ? e.message : String(e), 500);
  }
}

export async function domainWatchlistMatchesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('id') ?? '';
  const limitRaw = Number.parseInt(c.req.query('limit') ?? '100', 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, 500)) : 100;
  try {
    const { results } = await db
      .prepare(
        `SELECT id, domain, registered_on, detected_at, matched_keyword
         FROM domain_watch_matches WHERE watch_id = ? ORDER BY detected_at DESC LIMIT ?`
      )
      .bind(id, limit)
      .all<{
        id: string;
        domain: string;
        registered_on: string;
        detected_at: string;
        matched_keyword: string;
      }>();
    return c.json(
      { generated_at: new Date().toISOString(), watch_id: id, count: results.length, matches: results },
      200,
      { 'cache-control': 'no-store' }
    );
  } catch (e) {
    logError('domain-watchlist matches failed', e);
    return respondError(c, 'watchlist_unavailable', e instanceof Error ? e.message : String(e), 500);
  }
}
