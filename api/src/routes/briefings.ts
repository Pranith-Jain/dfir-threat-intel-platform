import type { Context } from 'hono';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import {
  BRIEFING_MAX_AGE_DAYS,
  buildBriefing,
  findRelatedBriefings,
  listBriefings,
  readBriefing,
  sweepOldBriefings,
  writeBriefing,
  type Briefing,
  type BriefingType,
} from '../lib/briefing-builder';
import { buildIocDump } from '../lib/briefing-builder/aggregate';
import { extractBriefingTags } from '../lib/briefing-tags';
import { requireAdmin as requireSharedAdmin, safeEqual } from '../lib/admin-auth';
import { badRequest, notFound, internalError, serviceUnavailable } from '../lib/api-error';

/**
 * Walk every finding in the briefing and attach auto-extracted tags
 * (CVE IDs, known ransomware actors, heuristic sector). Lazy — applied on
 * read so existing DB-stored briefings get tags without a backfill.
 */
function enrichBriefingWithTags(b: Briefing): Briefing {
  // Landscape reports have a different structure — skip enrichment for them.
  if (b.type === 'landscape') return b;
  const sections = b.sections.map((s) => ({
    ...s,
    findings: s.findings.map((f) => {
      const blob = `${f.title} ${f.description} ${f.vendor ?? ''} ${f.product ?? ''}`;
      return { ...f, tags: extractBriefingTags(blob) };
    }),
  }));
  return { ...b, sections } as Briefing;
}

/**
 * Derive `ioc_dump` from the (possibly already-capped) `iocs` buckets on any
 * pre-deploy briefing that lacks the field. The pre-deploy cap was 30 per
 * type, so old briefings can carry up to 120 entries; the dump preserves
 * that breakdown with the same line format as the in-builder version.
 *
 * New briefings always carry the field, so this is a no-op for them.
 */
function ensureIocDump(b: Briefing): Briefing {
  if (b.type === 'landscape') return b;
  if (b.ioc_dump && b.ioc_dump.count > 0) return b;
  if (!b.iocs) return b;
  const total = b.iocs.urls.length + b.iocs.domains.length + b.iocs.ipv4s.length + b.iocs.hashes.length;
  if (total === 0) return b;
  const dump = buildIocDump(b.iocs, b.stats?.iocs ?? total);
  return dump ? { ...b, ioc_dump: dump } : b;
}

function dbOrError(c: Context<{ Bindings: Env }>): D1Database | null {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return null;
  return db;
}

/**
 * Edge-cache key for briefing reads.
 *
 * `caches.default` stores the whole Response (headers included). Keying on the
 * raw request URL means a Response cached by older code sticks around for its
 * original max-age no matter what — that's why a 26-row D1 still showed 1
 * briefing for hours after the restore. Keying on a *versioned* synthetic URL
 * makes every cached entry disposable: bump BRIEFINGS_CACHE_VERSION and every
 * stale briefing entry is abandoned on the next request (cache miss -> fresh
 * D1 read). Also lets the cron bust the list after writing a briefing.
 */
const BRIEFINGS_CACHE_VERSION = 'v2';

function briefingsCacheKey(c: Context<{ Bindings: Env }>): Request {
  const u = new URL(c.req.url);
  // Only include known-safe query parameters in cache key to prevent
  // poisoning via arbitrary query strings.
  const safeParams = new URLSearchParams();
  const type = u.searchParams.get('type');
  if (type === 'daily' || type === 'weekly' || type === 'landscape') safeParams.set('type', type);
  const limit = u.searchParams.get('limit');
  if (limit) safeParams.set('limit', limit);
  // `offset` MUST be in the key — otherwise every page collapsed onto one
  // cached entry and page 2 served page 1.
  const offset = u.searchParams.get('offset');
  if (offset) safeParams.set('offset', offset);
  const sq = safeParams.toString();
  return new Request(`https://briefings-cache.internal/${BRIEFINGS_CACHE_VERSION}${u.pathname}${sq ? '?' + sq : ''}`, {
    method: 'GET',
  });
}

// Short TTL: a restore or the daily cron should surface within minutes, not
// hours. SWR keeps it cheap (one revalidation per window, stale served free).
const BRIEFINGS_CC = 'public, max-age=300, s-maxage=300, stale-while-revalidate=600';

/** True when the request carries a VALID operator admin token. */
function isAdminRequest(c: Context<{ Bindings: Env }>): boolean {
  return 'ok' in requireSharedAdmin(c);
}

/**
 * Purge the edge-cached detail + print entries for one slug, so a rebuild or
 * delete is reflected immediately on the public page (otherwise the deleted/
 * stale body lingers for up to the 5m TTL + 10m stale-while-revalidate). The
 * paginated /list keys can't be enumerated to purge; admin reads bypass the
 * cache (isAdminRequest) and the public list self-corrects within the TTL.
 */
async function purgeBriefingDetailCache(slug: string): Promise<void> {
  const cache = caches.default;
  const base = `https://briefings-cache.internal/${BRIEFINGS_CACHE_VERSION}/api/v1/briefings/${slug}`;
  await cache.delete(new Request(base, { method: 'GET' }));
  await cache.delete(new Request(`${base}/print`, { method: 'GET' }));
}

export async function listBriefingsHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  try {
    const typeRaw = c.req.query('type');
    const type = typeRaw === 'daily' || typeRaw === 'weekly' || typeRaw === 'landscape' ? typeRaw : undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(Math.max(parseInt(limitRaw, 10) || 20, 1), 100) : 20;
    const offsetRaw = c.req.query('offset');
    const offset = offsetRaw ? Math.max(parseInt(offsetRaw, 10) || 0, 0) : 0;
    const qRaw = c.req.query('q');
    const q = qRaw ? qRaw.trim().slice(0, 100) : undefined;

    // Admin reads bypass the edge cache so the operator sees the live D1 state
    // immediately after a build/delete/prune (a cached list otherwise still
    // shows a just-deleted row, which is what made delete look like it failed).
    const skipCache = !!q || isAdminRequest(c);
    const cache = caches.default;
    const key = briefingsCacheKey(c);
    // Search bypasses the per-PoP cache (unbounded query cardinality); the
    // paginated non-search list is cached per (type, limit, offset).
    const cached = skipCache ? null : await cache.match(key);
    if (cached) return new Response(cached.body, cached);

    const { items, total } = await listBriefings(db, { type, q, limit, offset });
    const res = c.json({ items, total }, 200, {
      'cache-control': skipCache ? 'no-store' : BRIEFINGS_CC,
      'last-modified': new Date().toUTCString(),
    });
    if (!skipCache) c.executionCtx.waitUntil(cache.put(key, res.clone()));
    return res;
  } catch (err) {
    logError('listBriefingsHandler error', err);
    return internalError(c, err);
  }
}

export async function getBriefingHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const slug = c.req.param('slug');
  if (!slug || !/^[a-z0-9-]+$/i.test(slug)) {
    return badRequest(c, 'invalid slug');
  }
  const cache = caches.default;
  const key = briefingsCacheKey(c);
  const cached = await cache.match(key);
  if (cached) return new Response(cached.body, cached);
  const briefing = await readBriefing(db, slug);
  if (!briefing) return notFound(c);
  const res = c.json(ensureIocDump(enrichBriefingWithTags(briefing)), 200, {
    'cache-control': BRIEFINGS_CC,
    'last-modified': new Date().toUTCString(),
  });
  c.executionCtx.waitUntil(cache.put(key, res.clone()));
  return res;
}

export async function todayBriefingHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const cache = caches.default;
  const key = briefingsCacheKey(c);
  const cached = await cache.match(key);
  if (cached) return new Response(cached.body, cached);
  // "today's" briefing covers the previous calendar day (latest fully-closed window)
  const now = new Date();
  const yesterday = new Date(now.getTime() - 86400_000);
  const slug = `daily-${yesterday.toISOString().slice(0, 10)}`;
  const briefing = await readBriefing(db, slug);
  if (!briefing) return notFound(c, 'not yet generated');
  const res = c.json(ensureIocDump(enrichBriefingWithTags(briefing)), 200, {
    'cache-control': BRIEFINGS_CC,
    'last-modified': new Date().toUTCString(),
  });
  c.executionCtx.waitUntil(cache.put(key, res.clone()));
  return res;
}

type AdminCtx = Context<{ Bindings: Env }>;

/**
 * GET /api/v1/briefings/related?slug=…&limit=…
 *
 * Case-triage linkage on demand: finds prior briefings related to the given
 * one by normalized-IOC overlap (with the shared-tactic-keyword fallback),
 * ranked by match count then severity then recency. Computed live from the
 * briefings table (json_extract over the slim fields — never full bodies),
 * so it stays fresh regardless of when the stored stamp was written.
 */
export async function briefingsRelatedHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const slugRaw = c.req.query('slug')?.trim();
  if (!slugRaw) return badRequest(c, 'missing slug');
  if (!/^[a-z0-9-]+$/i.test(slugRaw)) return badRequest(c, 'invalid slug');
  const limitRaw = c.req.query('limit');
  const limit = limitRaw ? Math.min(Math.max(parseInt(limitRaw, 10) || 5, 1), 20) : 5;
  try {
    const briefing = await readBriefing(db, slugRaw);
    if (!briefing) return notFound(c);
    const related_briefings = await findRelatedBriefings(db, briefing, { limit });
    return c.json({ slug: briefing.slug, count: related_briefings.length, related_briefings });
  } catch (err) {
    logError('briefings-related', err instanceof Error ? err : new Error(String(err)));
    return internalError(c, 'failed to compute related briefings');
  }
}

/**
 * Admin gate for briefing mutations (build / backfill / sweep).
 *
 * Primary token is the shared operator `ADMIN_TOKEN` — the SAME token the
 * whole /admin UI logs in with (lib/admin-auth: "one token, all admin
 * surfaces"). This is what was broken: briefings used to require a SEPARATE
 * `BRIEFINGS_ADMIN_TOKEN`, so the admin panel's token always 401'd here.
 *
 * A dedicated `BRIEFINGS_ADMIN_TOKEN`, if still configured, is also accepted
 * for back-compat with any standalone backfill scripts/curls. Either token
 * authorizes the request.
 */
function requireAdmin(c: AdminCtx): { error: Response } | { ok: true } {
  const shared = requireSharedAdmin(c);
  if ('ok' in shared) return shared;
  const legacy = c.env.BRIEFINGS_ADMIN_TOKEN;
  if (legacy) {
    const bearer = /^Bearer\s+(.+)$/i.exec(c.req.header('authorization') ?? '')?.[1];
    const token = bearer || c.req.header('x-admin-token') || '';
    if (token && safeEqual(token, legacy)) return { ok: true };
  }
  // Neither token matched — surface the shared gate's 401/403 response.
  return shared;
}

/**
 * Trigger an on-demand briefing build. Authenticated via Authorization: Bearer header.
 * Set BRIEFINGS_ADMIN_TOKEN as a Worker secret. If unset, this handler is disabled.
 */
export async function buildBriefingHandler(c: AdminCtx) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const auth = requireAdmin(c);
  if ('error' in auth) return auth.error;

  const typeRaw = c.req.query('type');
  if (typeRaw !== 'daily' && typeRaw !== 'weekly' && typeRaw !== 'landscape') {
    return badRequest(c, 'type must be daily, weekly, or landscape');
  }

  try {
    if (typeRaw === 'landscape') {
      const { buildLandscapeReport, writeLandscapeReport } = await import('../lib/landscape-builder');
      const report = await buildLandscapeReport(new Date(), { env: c.env });
      const result = await writeLandscapeReport(db, report);
      await purgeBriefingDetailCache(report.slug);
      return c.json(
        {
          ok: result.written,
          slug: report.slug,
          reason: result.reason,
          stats: report.stats,
        },
        200
      );
    }
    // skipLlm: this endpoint exists to get a briefing ON DISK. The LLM summary
    // is cosmetic (buildLlmExecutiveSummary already falls back to a template),
    // and with the providers degraded it burns ~13 subrequests and a long
    // chain of timeouts before giving up — which is how a manual recovery
    // could fail with "Exceeded CPU Limit" while never writing a row. Persist
    // the briefing first; enrich later if desired.
    const briefing = await buildBriefing(typeRaw as BriefingType, undefined, {
      nvdApiKey: c.env.NVD_API_KEY,
      env: c.env,
      skipLlm: true,
    });
    const result = await writeBriefing(db, briefing);
    await purgeBriefingDetailCache(briefing.slug);
    return c.json(
      { ok: true, slug: briefing.slug, stats: briefing.stats, written: result.written, reason: result.reason },
      200
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error ? err.stack?.split('\n').slice(0, 3).join(' | ') : '';
    logError('briefing build failed', new Error(msg + ' ' + stack));
    return c.json(
      {
        error: `briefing build failed: ${msg}`,
        type: typeRaw,
      },
      500
    );
  }
}

/**
 * Admin backfill — generate the past N daily briefings + last M weekly briefings.
 * Useful on first deploy to populate the list page.
 *
 * POST /api/v1/briefings/backfill?days=14&weeks=3
 *   Authorization: Bearer <BRIEFINGS_ADMIN_TOKEN>
 *
 * Per-iteration failures are tracked and reported. Status is:
 *   200 if everything wrote/skipped cleanly,
 *   207 if some iterations failed (the response lists which),
 *   500 if absolutely nothing succeeded.
 */
export async function backfillBriefingsHandler(c: AdminCtx) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const auth = requireAdmin(c);
  if ('error' in auth) return auth.error;

  const days = Math.min(Math.max(parseInt(c.req.query('days') ?? '14', 10) || 14, 0), 21);
  const weeks = Math.min(Math.max(parseInt(c.req.query('weeks') ?? '3', 10) || 3, 0), 4);
  // Default: skip if a briefing already exists (preserve fresh cron-generated
  // ones). Pass ?force=1 to overwrite — useful after a builder change.
  const force = c.req.query('force') === '1';

  const writtenDaily: string[] = [];
  const skippedDaily: string[] = [];
  const writtenWeekly: string[] = [];
  const skippedWeekly: string[] = [];
  const failures: Array<{ kind: 'daily' | 'weekly'; offset: number; error: string }> = [];

  for (let i = 0; i < days; i += 1) {
    const anchor = new Date(Date.now() - i * 86400_000);
    try {
      const briefing = await buildBriefing('daily', anchor, {
        nvdApiKey: c.env.NVD_API_KEY,
        env: c.env,
        skipLlm: true,
      });
      const result = await writeBriefing(db, briefing, { skipIfExists: !force });
      (result.written ? writtenDaily : skippedDaily).push(briefing.slug);
    } catch (err) {
      logError('backfill daily failed:', err);
      failures.push({ kind: 'daily', offset: i, error: 'build failed' });
    }
  }

  for (let i = 0; i < weeks; i += 1) {
    const anchor = new Date(Date.now() - i * 7 * 86400_000);
    try {
      const briefing = await buildBriefing('weekly', anchor, {
        nvdApiKey: c.env.NVD_API_KEY,
        env: c.env,
        skipLlm: true,
      });
      const result = await writeBriefing(db, briefing, { skipIfExists: !force });
      (result.written ? writtenWeekly : skippedWeekly).push(briefing.slug);
    } catch (err) {
      logError('backfill weekly failed:', err);
      failures.push({ kind: 'weekly', offset: i, error: 'build failed' });
    }
  }

  const totalAttempted = days + weeks;
  const totalSucceeded = writtenDaily.length + skippedDaily.length + writtenWeekly.length + skippedWeekly.length;
  const status: 200 | 207 | 500 = totalSucceeded === 0 && totalAttempted > 0 ? 500 : failures.length > 0 ? 207 : 200;

  return c.json(
    {
      ok: failures.length === 0,
      force,
      daily: writtenDaily,
      daily_skipped: skippedDaily,
      weekly: writtenWeekly,
      weekly_skipped: skippedWeekly,
      failures,
    },
    status
  );
}

/**
 * Admin sweep — delete briefings older than maxAgeDays (default matches the
 * BRIEFING_MAX_AGE_DAYS retention ceiling). Operators can pass a smaller
 * value to force-prune (e.g. `?max_age_days=7`); larger values are clamped
 * to the ceiling so the sweep can never extend retention beyond policy.
 */
/**
 * GET /api/v1/briefings/for-actor/:slug — returns findings tagged with the given
 * actor across recent briefings. Useful for generating actor-specific intelligence
 * summaries without rebuilding the entire briefing pipeline.
 */
/**
 * GET /api/v1/briefings/:slug/print — returns a printable HTML version of the
 * briefing. Designed for "Print to PDF" from the browser or curl-to-file usage.
 */
export async function briefingPrintHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');

  const slug = c.req.param('slug');
  if (!slug || !/^[a-z0-9-]+$/i.test(slug)) {
    return badRequest(c, 'invalid slug');
  }

  const briefing = await readBriefing(db, slug);
  if (!briefing) return notFound(c);

  const b = briefing as unknown as Record<string, unknown>;
  const sections = (b.sections as Array<Record<string, unknown>>) ?? [];
  const stats = (b.stats as Record<string, unknown>) ?? {};

  // Build findings per severity for HTML table
  const severityLabels: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    none: 'Info',
  };

  // HTML-escape all interpolated values. Briefing finding titles/descriptions
  // are sourced from external feeds (CVE aggregators, ransomware trackers) and
  // this route returns text/html under the API CSP — without escaping, feed
  // content containing markup is stored XSS. Numbers are coerced before output.
  const esc = (v: unknown): string =>
    (v == null ? '' : String(v)).replace(
      /[&<>"']/g,
      (ch) => (({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }) as Record<string, string>)[ch]!
    );
  const num = (v: unknown): number => (Number.isFinite(Number(v)) ? Number(v) : 0);

  let sectionsHtml = '';
  for (const section of sections) {
    const findings = (section.findings as Array<Record<string, unknown>>) ?? [];
    if (findings.length === 0) continue;

    const rows = findings
      .map((f: Record<string, unknown>) => {
        const sev = (f.severity as string) ?? 'none';
        const label = severityLabels[sev] ?? 'Info';
        return `<tr>
        <td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font-size:13px">${esc(f.title)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280">${esc(f.description)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #e5e7eb"><span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:600;background:${sev === 'critical' ? '#fef2f2' : '#fffbeb'}">${esc(label)}</span></td>
      </tr>`;
      })
      .join('');

    sectionsHtml += `<h2 style="font-size:16px;margin:16px 0 8px;border-bottom:2px solid #111827;padding-bottom:4px">${esc(section.title)}</h2>
    <table style="width:100%;border-collapse:collapse">${rows}</table>`;
  }

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(b.title ?? slug)}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:system-ui,-apple-system,sans-serif;color:#111;padding:40px;max-width:900px;margin:0 auto;line-height:1.5}
  h1{font-size:24px;margin-bottom:4px}
  .meta{color:#6b7280;font-size:14px;margin-bottom:24px}
  .stats{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
  .stat{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;text-align:center}
  .stat-num{font-size:20px;font-weight:700}
  .stat-label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280}
  table{width:100%;border-collapse:collapse;margin-bottom:16px}
  th{text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;border-bottom:2px solid #e5e7eb}
  @media print{body{padding:20px} .no-print{display:none}}
</style></head><body>
  <h1>${esc(b.title)}</h1>
  <div class="meta">${esc(b.date_range)} &middot; ${esc(b.type)} briefing</div>
  <div class="stats">
    <div class="stat"><div class="stat-num">${num(stats.findings)}</div><div class="stat-label">Findings</div></div>
    <div class="stat"><div class="stat-num">${num(stats.cves)}</div><div class="stat-label">CVEs</div></div>
    <div class="stat"><div class="stat-num">${num(stats.iocs)}</div><div class="stat-label">IOCs</div></div>
    <div class="stat"><div class="stat-num">${num(stats.kevs)}</div><div class="stat-label">KEVs</div></div>
  </div>
  <p style="margin:0 0 24px;font-size:13px">
    <a href="/api/v1/briefings/${esc(slug)}/iocs.txt" style="color:#2563eb;text-decoration:underline">Download IOC dump (.txt)</a>
  </p>
  ${sectionsHtml}
  <p style="margin-top:32px;font-size:11px;color:#9ca3af;text-align:center">Generated by DFIR Threat Intel Platform</p>
</body></html>`;

  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
  });
}

export async function briefingsForActorHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');

  const actorSlug = c.req.param('slug')?.toLowerCase();
  if (!actorSlug || !/^[a-z0-9-]+$/.test(actorSlug)) {
    return badRequest(c, 'invalid actor slug');
  }

  const cache = caches.default;
  // Version the key so a new briefing for this actor isn't pinned for an hour
  // (the list/slug keys are versioned via BRIEFINGS_CACHE_VERSION; this one
  // wasn't).
  const cacheKey = new Request(`https://briefings-cache.internal/${BRIEFINGS_CACHE_VERSION}/for-actor/${actorSlug}`);
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const { items } = await listBriefings(db, { limit: 14 });

  // Parallelize the 14 reads (was a serial await-in-loop on the hot path) and
  // track read failures so a corrupt/blipped row never silently shrinks the
  // page AND gets pinned in cache as an under-count for an hour.
  let degraded = false;
  const settled = await Promise.all(
    items.map(async (b) => {
      try {
        const full = await readBriefing(db, b.slug);
        return full ? { b, full } : null;
      } catch (_catchErr) {
        logError('briefingsForActorHandler failed', _catchErr);
        degraded = true;
        return null;
      }
    })
  );

  const results: Array<{
    slug: string;
    title: string;
    date_range: string;
    findings: Array<{ section: string; finding: Record<string, unknown> }>;
  }> = [];

  for (const row of settled) {
    if (!row) continue;
    const { b, full } = row;
    const enriched = ensureIocDump(enrichBriefingWithTags(full));
    const matched: Array<{ section: string; finding: Record<string, unknown> }> = [];
    for (const section of enriched.sections) {
      for (const finding of section.findings) {
        const f = finding as unknown as Record<string, unknown>;
        const tags = f.tags as { actors?: Array<{ slug: string }> } | undefined;
        if (tags?.actors?.some((a) => a.slug === actorSlug)) {
          matched.push({ section: section.title, finding: f });
        }
      }
    }
    if (matched.length > 0) {
      results.push({
        slug: b.slug,
        title: ((full as unknown as Record<string, unknown>).title as string) ?? '',
        date_range: ((full as unknown as Record<string, unknown>).date_range as string) ?? '',
        findings: matched,
      });
    }
  }

  const total_findings = results.reduce((s, r) => s + r.findings.length, 0);
  const res = c.json({ actor: actorSlug, briefings: results, total_findings }, 200, {
    // Don't pin a partial result for an hour when a read failed.
    'cache-control': degraded ? 'no-store' : 'public, max-age=3600',
  });
  if (!degraded) c.executionCtx.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}

export async function sweepBriefingsHandler(c: AdminCtx) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const auth = requireAdmin(c);
  if ('error' in auth) return auth.error;

  const maxAgeRaw = c.req.query('max_age_days');
  const requested = maxAgeRaw ? Math.max(parseInt(maxAgeRaw, 10) || BRIEFING_MAX_AGE_DAYS, 1) : BRIEFING_MAX_AGE_DAYS;
  const maxAge = Math.min(requested, BRIEFING_MAX_AGE_DAYS);

  try {
    const result = await sweepOldBriefings(db, maxAge);
    return c.json({ ok: true, max_age_days: maxAge, ...result }, 200);
  } catch (err) {
    logError('sweep failed:', err);
    return c.json(
      {
        error: 'sweep failed',
        max_age_days: maxAge,
      },
      500
    );
  }
}

/**
 * Admin delete — remove a single briefing by slug.
 *
 * POST /api/v1/briefings/delete?slug=daily-2026-06-04
 *   Authorization: Bearer <ADMIN_TOKEN>
 *
 * Used by the admin Briefings tab to drop a junk / empty row. The edge cache
 * for the slug (max-age 5m) may still serve the old body briefly; that's
 * acceptable for an operator action.
 */
export async function deleteBriefingHandler(c: AdminCtx) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const auth = requireAdmin(c);
  if ('error' in auth) return auth.error;

  const slug = c.req.query('slug');
  if (!slug || !/^[a-z0-9-]+$/i.test(slug)) {
    return badRequest(c, 'invalid or missing slug');
  }
  try {
    // Idempotent: report whether the row existed, but ALWAYS return 200 — a
    // delete of an already-gone row (e.g. a double-click, or a re-click while a
    // stale cached list still showed it) must not surface as an error. The old
    // `res.meta.changes` gate returned 404 even on a successful delete.
    const existed = await db.prepare('SELECT 1 FROM briefings WHERE slug = ?').bind(slug).first();
    await db.prepare('DELETE FROM briefings WHERE slug = ?').bind(slug).run();
    await purgeBriefingDetailCache(slug);
    return c.json({ ok: true, slug, deleted: !!existed }, 200);
  } catch (err) {
    logError('delete briefing failed:', err);
    return internalError(c, 'delete failed');
  }
}

/**
 * Admin prune — delete every daily/weekly briefing whose stats show 0 findings
 * AND 0 IOCs (the "empty" rows a budget-starved heal used to ship).
 *
 * POST /api/v1/briefings/prune-empty
 *   Authorization: Bearer <ADMIN_TOKEN>
 *
 * Scoped to daily/weekly and to rows that EXPLICITLY carry findings=0 AND
 * iocs=0 — landscape reports (different stats shape, no findings/iocs keys)
 * have json_extract → NULL, so `= 0` is false and they're never touched.
 */
export async function pruneEmptyBriefingsHandler(c: AdminCtx) {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const auth = requireAdmin(c);
  if ('error' in auth) return auth.error;

  try {
    const found = await db
      .prepare("SELECT slug FROM briefings WHERE type IN (?, ?) AND json_extract(stats_json,'$.findings') = 0")
      .bind('daily', 'weekly')
      .all<{ slug: string }>();
    const slugs = (found.results ?? []).map((r) => r.slug);
    if (slugs.length > 0) {
      await db
        .prepare("DELETE FROM briefings WHERE type IN (?, ?) AND json_extract(stats_json,'$.findings') = 0")
        .bind('daily', 'weekly')
        .run();
      await Promise.all(slugs.map((s) => purgeBriefingDetailCache(s)));
    }
    return c.json({ ok: true, deleted: slugs }, 200);
  } catch (err) {
    logError('prune-empty failed:', err);
    return internalError(c, err);
  }
}

/**
 * GET /api/v1/briefings/:slug/iocs.txt — stream the IOC dump as plain text.
 *
 * The brief page links to this URL with `download`, so a click saves a
 * `<slug>.txt` file containing the full deduped IOC list. Mirrors the
 * ioc_dump.content field embedded in the JSON payload, but as a real
 * text/plain file with the right Content-Disposition.
 *
 * 404 when the briefing doesn't exist OR has no IOC dump (an empty brief
 * shouldn't 500 just because the file would be empty). 1h edge-cache so
 * repeated clicks during a debrief don't re-hit D1.
 */
export async function briefingIocsTxtHandler(c: Context<{ Bindings: Env }>) {
  const db = dbOrError(c);
  if (!db) return serviceUnavailable(c, 'briefings database not bound');
  const slug = c.req.param('slug');
  if (!slug || !/^[a-z0-9-]+$/i.test(slug)) {
    return badRequest(c, 'invalid slug');
  }
  const cache = caches.default;
  const key = briefingsCacheKey(c);
  const cached = await cache.match(key);
  if (cached) return new Response(cached.body, cached);
  const briefing = await readBriefing(db, slug);
  if (!briefing) return notFound(c);
  // Backward-compat: pre-deploy briefings (and the current weekly) lack the
  // ioc_dump field. Derive it on-read from the existing iocs buckets so the
  // .txt endpoint is useful for the whole list, not only newly-built briefs.
  const hydrated = ensureIocDump(briefing);
  const dump = hydrated.ioc_dump;
  if (!dump || dump.count === 0) {
    return notFound(c, 'this briefing has no in-window IOCs');
  }
  const filename = `${slug}-iocs.txt`;
  const body = `# ${briefing.title}\n# generated_at: ${briefing.generated_at}\n# count: ${dump.count} unique indicators\n\n${dump.content}\n`;
  const res = new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': BRIEFINGS_CC,
    },
  });
  c.executionCtx.waitUntil(cache.put(key, res.clone()));
  return res;
}
