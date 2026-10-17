import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { fetchResilient } from '../lib/fetch-resilient';
import { safeIso } from '../lib/safe-date';
import { CYBERCRIME_SOURCES, type CybercrimeSource } from '../lib/cybercrime-sources';
import { unwrapBingNewsLink } from '../lib/rss-parser';
import { readLastGood, writeLastGood } from '../lib/lastgood';
import { fetchAFDatamarkets } from '../lib/andreafortuna-feeds';

/**
 * Cyber fraud + cyber crime aggregator for /threatintel/cyber-crime.
 *
 * Pulls RSS/Atom from a curated set of law-enforcement / crypto-crime /
 * fraud-research / news sources, applies optional per-source keyword
 * filters (cyber/crypto/fraud/etc.), dedupes by URL, and surfaces the
 * combined stream via round-robin selection so no single high-volume
 * source dominates the visible top of the page.
 *
 * Pattern mirrors routes/writeups.ts — same RSS+Atom parser, same
 * round-robin selector. Kept separate because the source list, filter
 * logic, and UI surface are distinct.
 *
 * Cache: 30 minutes server-side (news cycle ≈ 30 min between major
 * cybercrime stories; faster than writeups which run hourly).
 */

export const CYBERCRIME_CACHE_KEY = 'https://cybercrime-cache.internal/v2-500';
const CACHE_TTL_SECONDS = 1800;
const FETCH_TIMEOUT_MS = 12_000;
// 2026-05-23: was 120 (15 per source). Bumped to 500 / 60 per source so
// the page aligns with the rest of the live-feed surfaces.
const MAX_ITEMS = 500;
const MAX_PER_SOURCE = 60;
const AF_DATAMARKETS_LASTGOOD_KEY = 'cybercrime/af-datamarkets-lastgood/v1';
const LASTGOOD_TTL_SECONDS = 24 * 60 * 60;

export interface CybercrimeItem {
  title: string;
  url: string;
  source: string;
  category: CybercrimeSource['category'];
  /** ISO 8601 publish date when known. */
  published?: string;
  description?: string;
  tags?: string[];
}

export interface CybercrimeResponse {
  generated_at: string;
  sources: Array<{
    label: string;
    category: string;
    ok: boolean;
    count: number;
    filtered_out?: number;
    error?: string;
    stale?: boolean;
  }>;
  total: number;
  items: CybercrimeItem[];
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetchResilient(
      url,
      {
        headers: {
          'user-agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-cybercrime/1.0 Safari/537.36',
          accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
        },
        cf: { cacheTtl: 1800, cacheEverything: true },
      } as RequestInit,
      { attempts: 3, timeoutMs: FETCH_TIMEOUT_MS }
    );
    if (!res.ok) return null;
    return await res.text();
  } catch (_catchErr) {
    logError('fetchText failed', _catchErr);
    return null;
  }
}

function unwrap(s: string | undefined): string {
  if (!s) return '';
  let out = s.trim();
  const m = /^<!\[CDATA\[([\s\S]*?)\]\]>$/.exec(out);
  if (m) out = m[1] ?? '';
  out = out
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, code) => {
      const n = parseInt(code, 10);
      return Number.isFinite(n) ? String.fromCodePoint(n) : _;
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (_, code) => {
      const n = parseInt(code, 16);
      return Number.isFinite(n) ? String.fromCodePoint(n) : _;
    });
  return out;
}

function htmlToText(html: string, max = 280): string {
  let t = html
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
  if (t.length > max) t = t.slice(0, max).trimEnd() + '…';
  return t;
}

function parseFeed(body: string, src: CybercrimeSource): CybercrimeItem[] {
  const isAtom = /<feed\b[^>]*xmlns=["'][^"']*Atom/i.test(body) || /<entry\b/i.test(body);
  return isAtom ? parseAtom(body, src) : parseRss(body, src);
}

function parseRss(body: string, src: CybercrimeSource): CybercrimeItem[] {
  const out: CybercrimeItem[] = [];
  const itemRe = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRe.exec(body))) {
    const block = m[1];
    if (!block) continue;
    const title = unwrap(/<title>([\s\S]*?)<\/title>/i.exec(block)?.[1]);
    // Entity-decode first (Bing click URLs carry `&amp;`), then resolve the
    // redirector — several sources are Bing News mirrors.
    const link = unwrapBingNewsLink(unwrap(/<link>([\s\S]*?)<\/link>/i.exec(block)?.[1]));
    const pubDate = unwrap(/<pubDate>([\s\S]*?)<\/pubDate>/i.exec(block)?.[1]);
    const description = unwrap(/<description>([\s\S]*?)<\/description>/i.exec(block)?.[1]);
    const tags = Array.from(block.matchAll(/<category[^>]*>([\s\S]*?)<\/category>/gi))
      .map((c) => unwrap(c[1]).trim())
      .filter(Boolean);
    if (!title || !link) continue;
    out.push({
      title: title.trim(),
      url: link.trim(),
      source: src.label,
      category: src.category,
      published: safeIso(pubDate),
      description: description ? htmlToText(description) : undefined,
      tags: tags.length > 0 ? tags : undefined,
    });
  }
  return out;
}

function parseAtom(body: string, src: CybercrimeSource): CybercrimeItem[] {
  const out: CybercrimeItem[] = [];
  const entryRe = /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi;
  let m: RegExpExecArray | null;
  while ((m = entryRe.exec(body))) {
    const block = m[1];
    if (!block) continue;
    const title = unwrap(/<title(?:\s[^>]*)?>([\s\S]*?)<\/title>/i.exec(block)?.[1]);
    const link =
      /<link\s+[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i.exec(block)?.[1] ??
      /<link\s+[^>]*href=["']([^"']+)["'][^>]*rel=["']alternate["']/i.exec(block)?.[1] ??
      /<link\s+[^>]*href=["']([^"']+)["']/i.exec(block)?.[1];
    const published = unwrap(/<published>([\s\S]*?)<\/published>/i.exec(block)?.[1]);
    const updated = unwrap(/<updated>([\s\S]*?)<\/updated>/i.exec(block)?.[1]);
    const summary = unwrap(/<summary(?:\s[^>]*)?>([\s\S]*?)<\/summary>/i.exec(block)?.[1]);
    if (!title || !link) continue;
    out.push({
      title: title.trim(),
      url: link.trim(),
      source: src.label,
      category: src.category,
      published: safeIso(published || updated),
      description: summary ? htmlToText(summary) : undefined,
    });
  }
  return out;
}

function applyFilter(items: CybercrimeItem[], keywords?: string[]): { kept: CybercrimeItem[]; dropped: number } {
  if (!keywords || keywords.length === 0) return { kept: items, dropped: 0 };
  const lower = keywords.map((k) => k.toLowerCase());
  const kept: CybercrimeItem[] = [];
  let dropped = 0;
  for (const it of items) {
    const hay = `${it.title} ${it.description ?? ''} ${(it.tags ?? []).join(' ')}`.toLowerCase();
    if (lower.some((k) => hay.includes(k))) kept.push(it);
    else dropped++;
  }
  return { kept, dropped };
}

function cmpByPublished(a: CybercrimeItem, b: CybercrimeItem): number {
  if (a.published && b.published) return b.published.localeCompare(a.published);
  if (a.published) return -1;
  if (b.published) return 1;
  return 0;
}

/**
 * Same round-robin selector as writeups.ts. Each pass picks the newest
 * head from each non-drained source so no single chatty feed dominates.
 */
function roundRobinBySource(items: CybercrimeItem[], maxItems: number): CybercrimeItem[] {
  const sorted = [...items].sort(cmpByPublished);
  const bySource = new Map<string, CybercrimeItem[]>();
  for (const it of sorted) {
    const bucket = bySource.get(it.source) ?? [];
    bucket.push(it);
    bySource.set(it.source, bucket);
  }
  const visible: CybercrimeItem[] = [];
  let exhausted = false;
  while (visible.length < maxItems && !exhausted) {
    let picked = false;
    const heads: Array<{ source: string; head: CybercrimeItem }> = [];
    for (const [source, bucket] of bySource) {
      const head = bucket[0];
      if (head) heads.push({ source, head });
    }
    heads.sort((a, b) => cmpByPublished(a.head, b.head));
    for (const { source } of heads) {
      if (visible.length >= maxItems) break;
      const bucket = bySource.get(source);
      if (!bucket || bucket.length === 0) continue;
      const next = bucket.shift();
      if (next) {
        visible.push(next);
        picked = true;
      }
    }
    if (!picked) exhausted = true;
  }
  return visible;
}

export async function fetchCybercrime(
  executionCtx?: { waitUntil: (p: Promise<unknown>) => void },
  kv?: KVNamespace
): Promise<CybercrimeResponse> {
  const sourceMeta: CybercrimeResponse['sources'] = [];
  const all: CybercrimeItem[] = [];

  const [results, afItemsRaw] = await Promise.all([
    Promise.all(
      CYBERCRIME_SOURCES.map(async (src) => {
        try {
          const body = await fetchText(src.url);
          if (!body) return { src, ok: false, items: [] as CybercrimeItem[], dropped: 0, error: 'fetch failed' };
          // parseFeed/applyFilter run regexes over untrusted upstream XML;
          // a malformed feed must degrade this one source, not 500 the
          // whole endpoint by rejecting the surrounding Promise.all.
          const parsed = parseFeed(body, src);
          parsed.sort(cmpByPublished);
          const { kept, dropped } = applyFilter(parsed, src.filterKeywords);
          return { src, ok: kept.length > 0, items: kept.slice(0, MAX_PER_SOURCE), dropped };
        } catch (_catchErr) {
          logError('fetchCybercrime failed', _catchErr);
          return { src, ok: false, items: [] as CybercrimeItem[], dropped: 0, error: 'parse failed' };
        }
      })
    ),
    // parseDatamarkets can throw on malformed upstream — keep it from
    // taking the whole aggregate down.
    fetchAFDatamarkets().catch(() => [] as CybercrimeItem[]),
  ]);

  for (const r of results) {
    sourceMeta.push({
      label: r.src.label,
      category: r.src.category,
      ok: r.ok,
      count: r.items.length,
      ...(r.dropped > 0 ? { filtered_out: r.dropped } : {}),
      ...((!r.ok && 'error' in r ? { error: r.error } : {}) as object),
    });
    for (const it of r.items) all.push(it);
  }

  // ─── Andrea Fortuna Datamarkets (underground forum threads) ─────────────
  let afItems = afItemsRaw;
  let afOk = afItems.length > 0;
  let afStale = false;

  if (afOk && kv) {
    executionCtx?.waitUntil(
      writeLastGood(
        { KV_CACHE: kv },
        AF_DATAMARKETS_LASTGOOD_KEY,
        { items: afItems, refreshed_at: new Date().toISOString() },
        { ttlSeconds: LASTGOOD_TTL_SECONDS, keyPrefix: '' }
      )
    );
  } else if (!afOk && kv) {
    try {
      const parsed = await readLastGood<{ items: typeof afItems }>({ KV_CACHE: kv }, AF_DATAMARKETS_LASTGOOD_KEY, {
        keyPrefix: '',
      });
      if (parsed && Array.isArray(parsed.items) && parsed.items.length > 0) {
        afItems = parsed.items;
        afOk = true;
        afStale = true;
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* leave afOk = false */
    }
  }

  sourceMeta.push({
    label: 'AndreaFortuna Datamarkets',
    category: 'underground-forums',
    ok: afOk,
    count: afItems.length,
    ...(afStale ? { stale: true } : {}),
  });
  for (const it of afItems) all.push(it);

  // Dedupe by URL (ignore querystrings/fragments).
  const seen = new Set<string>();
  const deduped: CybercrimeItem[] = [];
  for (const it of all) {
    const key = it.url.replace(/[?#].*$/, '');
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(it);
  }

  return {
    generated_at: new Date().toISOString(),
    sources: sourceMeta,
    total: deduped.length,
    items: roundRobinBySource(deduped, MAX_ITEMS),
  };
}

export async function cybercrimeHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(CYBERCRIME_CACHE_KEY);
  const cached = await cache.match(cacheReq);
  if (cached) return new Response(cached.body, cached);

  const body = await fetchCybercrime(c.executionCtx, c.env.KV_CACHE);
  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  return response;
}
