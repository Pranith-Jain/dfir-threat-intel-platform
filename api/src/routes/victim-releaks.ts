import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { normalizeVictim } from '../lib/victim-normalize';
import { classifySector } from '../lib/sector-classifier';
import { optypeForGroup, type OpType } from '../lib/ransomware-optype';
import { fetchMtiSource, type MtiRansomwareClaim } from '../lib/mythreatintel-api';
import { readLastGood, writeLastGood } from '../lib/lastgood';

/**
 * Victim re-leak detection.
 *
 * Fetches the full per-group post history from Ransomlook for the top-N
 * most-recently-active groups, normalizes victim names, and surfaces
 * victims that appear under 2+ distinct groups. Re-leaks are high-signal:
 *   - usually mean failed double-extortion (group A couldn't monetize, so
 *     the victim hits another group's leak site later)
 *   - or affiliate dispute (RaaS affiliate moves between programs and
 *     re-publishes the same haul)
 *
 * Cached 6h — heavy upstream cost (8 per-group fetches), and re-leaks
 * change on the order of days.
 */

export const VICTIM_RELEAKS_CACHE_KEY = 'https://victim-releaks-cache.internal/v1';
const CACHE_TTL_SECONDS = 6 * 60 * 60;
// Cross-colo last-good fallback: the per-group fan-out is heavy and occasionally
// throws (CPU/time budget) or comes back empty; we serve the last good payload
// any colo produced rather than 500 / a blank page. 7-day window.
const LASTGOOD_KEY = 'victim-releaks';
const LASTGOOD_TTL_SECONDS = 7 * 24 * 60 * 60;
const FETCH_TIMEOUT_MS = 20_000;
const TOP_GROUPS = 8;
const WINDOW_DAYS = 365; // only consider posts within last 12 months — older matches are stale

interface RansomlookGroupPost {
  post_title?: string;
  discovered?: string;
  description?: string;
  link?: string | null;
}

interface VictimClaim {
  group: string;
  raw_victim: string;
  discovered: string; // ISO
  source_url?: string;
}

interface ReleakRow {
  /** Stable comparison key (lowercased alphanumeric). */
  key: string;
  /** Distinct group count for this victim — sort axis. */
  group_count: number;
  /** Original victim strings observed (deduped). */
  raw_names: string[];
  /** Claims ordered newest-first. */
  claims: VictimClaim[];
  /** Most-recent claim ISO timestamp (sort tiebreaker). */
  latest: string;
}

interface SectorCount {
  sector: string;
  count: number;
}
interface OptypeCount {
  optype: OpType;
  count: number;
}
interface GroupPair {
  /** Alphabetically-ordered group slugs. */
  a: string;
  b: string;
  count: number;
}
interface TimelineBucket {
  /** Month bucket, YYYY-MM. */
  period: string;
  count: number;
}

export interface VictimReleaksResponse {
  generated_at: string;
  window_days: number;
  groups_scanned: number;
  victims_scanned: number;
  releaks: ReleakRow[];
  /** Re-leak victims by heuristic sector (classifier is best-effort). */
  by_sector: SectorCount[];
  /** Re-leak participation by group operation-type (curated lookup). */
  by_optype: OptypeCount[];
  /** Top group↔group re-claim pairs. */
  group_pairs: GroupPair[];
  /** Re-leak claim volume bucketed by month over the window. */
  timeline: TimelineBucket[];
  /** Groups in the "active" list whose per-group fetch failed. */
  warnings: Array<{ slug: string; reason: string }>;
  /** Set when this payload is a cross-colo last-good fallback, not a live run. */
  stale?: boolean;
}

/** Valid empty envelope used when a live run fails and there's no last-good. */
function emptyReleaksResponse(reason: string): VictimReleaksResponse {
  return {
    generated_at: new Date().toISOString(),
    window_days: WINDOW_DAYS,
    groups_scanned: 0,
    victims_scanned: 0,
    releaks: [],
    by_sector: [],
    by_optype: [],
    group_pairs: [],
    timeline: [],
    warnings: [{ slug: '*', reason }],
  };
}

async function fetchJson<T>(url: string, timeoutMs: number = FETCH_TIMEOUT_MS): Promise<T | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { Accept: 'application/json', 'User-Agent': 'pranithjain.qzz.io DFIR toolkit (free, read-only)' },
      cf: { cacheTtl: 1800, cacheEverything: true },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch (_catchErr) {
    logError('fetchJson failed', _catchErr);
    return null;
  }
}

function toIsoDate(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const cleaned = s.replace(' ', 'T').replace(/\.\d+$/, '') + 'Z';
  const d = new Date(cleaned);
  return Number.isFinite(d.getTime()) ? d.toISOString() : undefined;
}

export async function fetchVictimReleaks(env?: Env, opts: { timeoutMs?: number } = {}): Promise<VictimReleaksResponse> {
  const timeoutMs = opts.timeoutMs ?? FETCH_TIMEOUT_MS;
  const recent = await fetchJson<Array<{ group_name?: string }>>('https://www.ransomlook.io/api/recent', timeoutMs);
  if (!recent) {
    return {
      generated_at: new Date().toISOString(),
      window_days: WINDOW_DAYS,
      groups_scanned: 0,
      victims_scanned: 0,
      releaks: [],
      by_sector: [],
      by_optype: [],
      group_pairs: [],
      timeline: [],
      warnings: [{ slug: '*', reason: 'ransomlook /api/recent unreachable' }],
    };
  }

  const count = new Map<string, number>();
  for (const e of recent) {
    const g = e.group_name?.trim().toLowerCase();
    if (!g) continue;
    count.set(g, (count.get(g) ?? 0) + 1);
  }
  const topGroups = [...count.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_GROUPS)
    .map(([slug]) => slug);

  // ISO cutoff: only consider claims within WINDOW_DAYS
  const cutoffIso = new Date(Date.now() - WINDOW_DAYS * 86400_000).toISOString();

  const [fetches, mtiClaims] = await Promise.all([
    Promise.all(
      topGroups.map(async (slug) => {
        const data = await fetchJson<[unknown, RansomlookGroupPost[]]>(
          `https://www.ransomlook.io/api/group/${encodeURIComponent(slug)}`,
          timeoutMs
        );
        return { slug, data };
      })
    ),
    // MyThreatIntel ransomware victim claims — an independent source, so a
    // victim that MTI attributes to a different gang than Ransomlook does
    // surfaces as a cross-source re-leak. Skipped (→ []) when no env/token.
    env
      ? fetchMtiSource(env, 'ransomware', { limit: 500 })
          .then((r) => (r.ok ? (r.items as MtiRansomwareClaim[]) : []))
          .catch(() => [] as MtiRansomwareClaim[])
      : Promise.resolve([] as MtiRansomwareClaim[]),
  ]);

  const warnings: VictimReleaksResponse['warnings'] = [];
  const byKey = new Map<string, { rawNames: Set<string>; claims: VictimClaim[]; groups: Set<string> }>();
  let victimsScanned = 0;
  let groupsScanned = 0;

  for (const { slug, data } of fetches) {
    if (!data || !Array.isArray(data) || data.length < 2) {
      warnings.push({ slug, reason: 'per-group fetch failed or malformed' });
      continue;
    }
    groupsScanned += 1;
    const posts = data[1];
    if (!Array.isArray(posts)) continue;

    for (const p of posts) {
      const raw = p.post_title?.trim();
      if (!raw) continue;
      const iso = toIsoDate(p.discovered);
      if (!iso || iso < cutoffIso) continue;
      const key = normalizeVictim(raw);
      // Reject keys that are too short to be meaningful (e.g. masked names like "***" → "").
      if (key.length < 3) continue;
      victimsScanned += 1;
      const sourceUrl = p.link ? `https://www.ransomlook.io${p.link.startsWith('/') ? '' : '/'}${p.link}` : undefined;
      const claim: VictimClaim = {
        group: slug,
        raw_victim: raw,
        discovered: iso,
        source_url: sourceUrl,
      };
      const existing = byKey.get(key);
      if (existing) {
        existing.rawNames.add(raw);
        existing.claims.push(claim);
        existing.groups.add(slug);
      } else {
        byKey.set(key, {
          rawNames: new Set([raw]),
          claims: [claim],
          groups: new Set([slug]),
        });
      }
    }
  }

  // ── MyThreatIntel victims into the same byKey map ──────────────────────
  // Feeding MTI claims here lets a victim seen on a Ransomlook group AND
  // attributed to a different gang by MTI cross-match into a re-leak.
  for (const e of mtiClaims) {
    const raw = e.victim?.trim();
    const gang = e.gang?.trim().toLowerCase();
    if (!raw || !gang || !e.date) continue;
    const iso = toIsoDate(e.date);
    if (!iso || iso < cutoffIso) continue;
    const key = normalizeVictim(raw);
    if (key.length < 3) continue;
    victimsScanned += 1;
    const claim: VictimClaim = {
      group: gang,
      raw_victim: raw,
      discovered: iso,
      source_url: 'https://mythreatintel.com/',
    };
    const existing = byKey.get(key);
    if (existing) {
      existing.rawNames.add(raw);
      existing.claims.push(claim);
      existing.groups.add(gang);
    } else {
      byKey.set(key, { rawNames: new Set([raw]), claims: [claim], groups: new Set([gang]) });
    }
  }

  const releaks: ReleakRow[] = [];
  for (const [key, agg] of byKey) {
    if (agg.groups.size < 2) continue;
    const claims = [...agg.claims].sort((a, b) => b.discovered.localeCompare(a.discovered));
    releaks.push({
      key,
      group_count: agg.groups.size,
      raw_names: [...agg.rawNames],
      claims,
      latest: claims[0]?.discovered ?? '',
    });
  }
  releaks.sort((a, b) => {
    if (b.group_count !== a.group_count) return b.group_count - a.group_count;
    return b.latest.localeCompare(a.latest);
  });

  // ── Trend aggregates (the page leads with these, not raw victim rows) ──
  const sectorTally = new Map<string, number>();
  const optypeTally = new Map<OpType, number>();
  const pairTally = new Map<string, number>();
  const monthTally = new Map<string, number>();

  for (const r of releaks) {
    // Sector: classify on the most-complete raw name (heuristic, name-only).
    const sector = classifySector(r.raw_names[0] ?? r.key);
    sectorTally.set(sector, (sectorTally.get(sector) ?? 0) + 1);

    // Op-type: count each distinct participating group once per victim.
    const distinctGroups = [...new Set(r.claims.map((c) => c.group))].sort();
    for (const g of distinctGroups) {
      const ot = optypeForGroup(g);
      optypeTally.set(ot, (optypeTally.get(ot) ?? 0) + 1);
    }

    // Group pairs: all unordered distinct-group pairs for this victim.
    for (let i = 0; i < distinctGroups.length; i++) {
      for (let j = i + 1; j < distinctGroups.length; j++) {
        const key = `${distinctGroups[i]}${distinctGroups[j]}`;
        pairTally.set(key, (pairTally.get(key) ?? 0) + 1);
      }
    }

    // Timeline: every re-leak claim, bucketed by month.
    for (const c of r.claims) {
      const period = c.discovered.slice(0, 7); // YYYY-MM
      if (period.length === 7) monthTally.set(period, (monthTally.get(period) ?? 0) + 1);
    }
  }

  const by_sector: SectorCount[] = [...sectorTally.entries()]
    .map(([sector, count]) => ({ sector, count }))
    .sort((a, b) => b.count - a.count);
  const by_optype: OptypeCount[] = [...optypeTally.entries()]
    .map(([optype, count]) => ({ optype, count }))
    .sort((a, b) => b.count - a.count);
  const group_pairs: GroupPair[] = [...pairTally.entries()]
    .map(([k, count]) => {
      const [a, b] = k.split('');
      return { a: a ?? '', b: b ?? '', count };
    })
    .sort((x, y) => y.count - x.count)
    .slice(0, 15);
  const timeline: TimelineBucket[] = [...monthTally.entries()]
    .map(([period, count]) => ({ period, count }))
    .sort((a, b) => a.period.localeCompare(b.period));

  return {
    generated_at: new Date().toISOString(),
    window_days: WINDOW_DAYS,
    groups_scanned: groupsScanned,
    victims_scanned: victimsScanned,
    releaks,
    by_sector,
    by_optype,
    group_pairs,
    timeline,
    warnings,
  };
}

// The request-path cold compute is bounded well under Cloudflare's request
// duration ceiling. The full-quality 20s fan-out runs only in the cron
// (refreshVictimReleaksCache), which has a far larger budget; on the request
// path we'd rather drop a slow group (→ warning) than risk a runtime abort.
const COLD_FETCH_TIMEOUT_MS = 12_000;

/**
 * Cron entry point: run the full (slow) aggregation off the request path and
 * force-refresh the global last-good. The hourly cron calls this so the handler
 * never has to do the 8-group fan-out while a user is waiting. Returns the body
 * for logging; throws are the caller's to catch.
 */
export async function refreshVictimReleaksCache(env: Env): Promise<VictimReleaksResponse> {
  const body = await fetchVictimReleaks(env);
  if (body.releaks.length > 0) {
    // skipIfUnchanged: the 6h refresh usually rebuilds the same list; do not
    // spend a KV write (the scarce free-plan quota) on byte-identical bytes.
    await writeLastGood(env, LASTGOOD_KEY, body, {
      ttlSeconds: LASTGOOD_TTL_SECONDS,
      force: true,
      skipIfUnchanged: true,
    });
  }
  return body;
}

export async function victimReleaksHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const json = (body: unknown, cacheControl: string): Response =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': cacheControl },
    });

  // ── Normal path: serve the cron-warmed global copy ───────────────────────
  const lg = await readLastGood<VictimReleaksResponse>(c.env, LASTGOOD_KEY);
  if (lg && lg.releaks.length > 0) {
    return json(lg, `public, max-age=${CACHE_TTL_SECONDS}`);
  }

  // ── Cold path: no warmed copy yet (fresh deploy, before the first cron) ──
  // Use a bounded live compute. Any failure → empty 200, never 500.
  try {
    const body = await fetchVictimReleaks(c.env, { timeoutMs: COLD_FETCH_TIMEOUT_MS });
    if (body.releaks.length > 0) {
      c.executionCtx.waitUntil(writeLastGood(c.env, LASTGOOD_KEY, body, { ttlSeconds: LASTGOOD_TTL_SECONDS }));
      return json(body, `public, max-age=${CACHE_TTL_SECONDS}`);
    }
    return json(body, 'no-store');
  } catch (err) {
    logError('victimReleaksHandler failed', err);
    return json(emptyReleaksResponse(err instanceof Error ? err.message : 'live run failed'), 'no-store');
  }
}
