import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, badGateway } from '../lib/api-error';

/**
 * Maltrail's committed IOC files live under `data/` on the `master` branch.
 *
 * These two constants pointed at `trails/static/malware`, a path that has
 * never existed in stamparm/maltrail (`git log` on that path upstream returns
 * zero commits). Every request 404'd, `maltrailListHandler` surfaced it as a
 * 502, and `/threatintel/malware/maltrail` rendered a raw error for every
 * visitor. Nothing tested it, so it rotted silently.
 *
 * Note the contents are NOT per-actor trails: upstream ships generic malware
 * lists (drop.txt, mass_scanner.txt, ua.txt, whitelist.txt, cdn_ranges.txt,
 * worst_asns.txt, ...). `parseActorFromFilename` still derives a label from
 * the filename, which for these reads as a list name rather than a threat
 * actor — see the note on that function.
 */
const MALTRAIL_RAW = 'https://raw.githubusercontent.com/stamparm/maltrail/master/data';
const MALTRAIL_API = 'https://api.github.com/repos/stamparm/maltrail/contents/data';

interface MaltrailTrailFile {
  name: string;
  path: string;
  size: number;
  actors: string[];
}

/**
 * Human label for a Maltrail list file.
 *
 * This originally parsed `<actor>_<sub>.txt` per-actor trails, but upstream
 * ships generic lists (drop, mass_scanner, ua, whitelist, ...), so the
 * "actor" it derives is really the list name. Kept as `actors[]` because the
 * response shape and the page's type both depend on it; the values are list
 * labels, not threat-actor names.
 */
function parseActorFromFilename(name: string): string[] {
  const base = name.replace(/\.txt$/i, '');
  const parts = base.split(/[_\s]+/);
  const actor = parts.map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase()).join(' ');
  return [actor.trim()];
}

/**
 * Classify a single IOC line from a Maltrail trail file.
 */
function classifyIoc(line: string): 'ipv4' | 'domain' | 'url' | 'hash' | 'unknown' {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) return 'unknown';
  const ipv4Re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipv4Re.test(trimmed)) return 'ipv4';
  const domainRe = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (domainRe.test(trimmed)) return 'domain';
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return 'url';
  const hashRe = /^[a-fA-F0-9]{32,128}$/;
  if (hashRe.test(trimmed)) return 'hash';
  return 'unknown';
}

const MALTRAIL_LIST_TTL = 7200;
const MALTRAIL_LIST_CACHE_KEY = new Request('https://maltrail-list.internal/v1');

export async function maltrailListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  // Provider list is public, never-mutated GitHub data — perfect fit
  // for caches.default. Moved off KV 2026-05-24 to drop the per-visit
  // KV read (and the stale-fallback read on errors).
  const edgeCache = (caches as unknown as { default: Cache }).default;
  try {
    const cached = await edgeCache.match(MALTRAIL_LIST_CACHE_KEY);
    if (cached) {
      return c.json((await cached.json()) as Record<string, unknown>, 200, {
        'cache-control': 'public, max-age=3600',
      });
    }

    const res = await fetch(MALTRAIL_API, {
      headers: { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'pranithjain.qzz.io' },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      // No stale entry to serve (the only way to get one is a prior
      // success). Surface the upstream error.
      return badGateway(c, `github: ${res.status}`);
    }

    const files = (await res.json()) as Array<{ name: string; path: string; size: number; type: string }>;
    const trailFiles: MaltrailTrailFile[] = (Array.isArray(files) ? files : [])
      .filter((f) => f.type === 'file' && f.name.endsWith('.txt'))
      .map((f) => ({
        name: f.name,
        path: f.path,
        size: f.size,
        actors: parseActorFromFilename(f.name),
      }));

    const body = { ok: true, total: trailFiles.length, files: trailFiles };
    const cacheable = new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${MALTRAIL_LIST_TTL}, s-maxage=${MALTRAIL_LIST_TTL}`,
      },
    });
    c.executionCtx.waitUntil(edgeCache.put(MALTRAIL_LIST_CACHE_KEY, cacheable).catch(() => undefined));
    return c.json(body, 200, { 'cache-control': 'public, max-age=3600' });
  } catch (err) {
    logError('handler failed', err);
    return badGateway(c, err instanceof Error ? err.message : String(err));
  }
}

export async function maltrailFetchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const trail = c.req.query('trail');
  if (!trail || !trail.trim()) {
    return badRequest(c, 'missing query param trail (e.g. ?trail=apt_lazarus.txt)');
  }

  const filename = trail.trim();
  const url = `${MALTRAIL_RAW}/${encodeURIComponent(filename)}`;

  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'pranithjain.qzz.io' },
      signal: AbortSignal.timeout(20_000),
    });
    if (res.status === 404) {
      return notFound(c, 'trail file not found');
    }
    if (!res.ok) {
      return badGateway(c, `maltrail: ${res.status}`);
    }

    const text = await res.text();
    const lines = text.split('\n');
    const iocs = lines.map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && !l.startsWith('//'));

    const byType: Record<string, number> = {};
    const iocList: Array<{ value: string; type: string }> = [];
    for (const ioc of iocs) {
      const t = classifyIoc(ioc);
      if (t !== 'unknown') {
        byType[t] = (byType[t] ?? 0) + 1;
        iocList.push({ value: ioc, type: t });
      }
    }

    return c.json(
      {
        ok: true,
        filename,
        actors: parseActorFromFilename(filename),
        total_iocs: iocList.length,
        by_type: byType,
        iocs: iocList.slice(0, 5000),
        truncated: iocList.length > 5000,
      },
      200,
      { 'cache-control': 'public, max-age=3600' }
    );
  } catch (err) {
    logError('handler failed', err);
    return badGateway(c, err instanceof Error ? err.message : String(err));
  }
}
