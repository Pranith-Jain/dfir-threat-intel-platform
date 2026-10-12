import type { Context } from 'hono';
import type { Env } from '../env';
import { listBriefings, readBriefing, type Briefing } from '../lib/briefing-builder';
import { getThreatDb } from '../lib/do-database';
import { getSiteUrl } from '../lib/site-config';

/**
 * RSS 2.0 feed of the most-recent threat briefings.
 *
 * - Lists last MAX_ITEMS briefings via KV metadata (cheap, indexed).
 * - Fetches each one's full body for the executive_summary as the
 *   item description. 10 KV reads per RSS render is acceptable.
 * - Edge-cached 1 h — RSS readers poll on their own cadence and the
 *   underlying briefings only change once per day / week.
 *
 * The Cache-Control + edge cache mean we don't re-fan-out KV reads on
 * every reader poll — each new briefing publishes invalidate naturally
 * after the cache TTL expires.
 */

const MAX_ITEMS = 10;
const CACHE_TTL = 3600;

interface BriefingMeta {
  type?: string;
  title?: string;
  date?: string;
  range_end?: string;
  date_range?: string;
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Convert ISO YYYY-MM-DD to RFC-822 (RSS 2.0 spec'd date format).
 * Anchor at end-of-day UTC so dailies land on their actual date in
 * readers that show local-tz rendered times.
 */
function toRfc822(isoDate: string): string {
  const d = new Date(isoDate + 'T23:59:59Z');
  if (!Number.isFinite(d.getTime())) return new Date().toUTCString();
  return d.toUTCString();
}

/** Compose a 1–2 paragraph item description from the briefing body. */
function itemDescription(b: Briefing): string {
  const lines: string[] = [];
  if (b.executive_summary) {
    lines.push(b.executive_summary);
  }
  // Quick stats line.
  const s = b.stats;
  if (s) {
    const bits: string[] = [];
    if (s.findings) bits.push(`${s.findings} findings`);
    if (s.cves) bits.push(`${s.cves} CVEs`);
    if (s.kevs) bits.push(`${s.kevs} KEV-listed`);
    if (s.iocs) bits.push(`${s.iocs} IOCs`);
    if (s.critical) bits.push(`${s.critical} critical`);
    if (s.high) bits.push(`${s.high} high`);
    if (bits.length > 0) lines.push(bits.join(' · '));
  }
  if (b.sources?.length) {
    lines.push(`Sources: ${b.sources.join(', ')}`);
  }
  return lines.join('\n\n');
}

export async function briefingsRssHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = getThreatDb(c.env);
  if (!db) {
    return c.text('briefings database not bound', 503, { 'cache-control': 'no-store' });
  }

  const cache = (caches as unknown as { default: Cache }).default;
  // v2: bumped after the KV->D1 history restore so the RSS edge cache drops
  // its stale pre-restore body (was showing a single briefing).
  const cacheKey = new Request('https://briefings-rss-cache.internal/v2');
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const { items: list } = await listBriefings(db, { limit: MAX_ITEMS });

  // Fetch full bodies in parallel; tolerate per-item failures.
  const settled = await Promise.allSettled(list.map((it) => readBriefing(db, it.slug)));
  type Enriched = { slug: string; meta: BriefingMeta; body: Briefing | null };
  const items: Enriched[] = list.map((it, i) => {
    const r = settled[i];
    const body = r && r.status === 'fulfilled' ? r.value : null;
    return {
      slug: it.slug,
      meta: (it.metadata as BriefingMeta | undefined) ?? {},
      body,
    };
  });

  const buildDate = new Date().toUTCString();
  const channelTitle = 'Pranith Jain — DFIR Threat Briefings';
  const channelDescription =
    'Daily and weekly threat briefings. CISA KEV + NVD + abuse.ch + OpenPhish, categorised and stat-summed.';
  const siteUrl = getSiteUrl(c.env);
  const selfUrl = `${siteUrl}/api/v1/briefings/rss`;
  const htmlIndex = `${siteUrl}/threatintel/briefings`;

  const xmlItems = items
    .map((it) => {
      const meta = it.meta;
      const body = it.body;
      const title = meta.title ?? body?.title ?? it.slug;
      const dateAnchor =
        meta.range_end ?? meta.date ?? body?.range_end ?? body?.date ?? new Date().toISOString().slice(0, 10);
      const link = `${siteUrl}/threatintel/briefings/${it.slug}`;
      const desc = body ? itemDescription(body) : (meta.date_range ?? '');
      const category = meta.type ?? body?.type ?? 'briefing';
      return `    <item>
      <title>${escapeXml(title)}</title>
      <link>${escapeXml(link)}</link>
      <guid isPermaLink="true">${escapeXml(link)}</guid>
      <pubDate>${toRfc822(dateAnchor)}</pubDate>
      <category>${escapeXml(category)}</category>
      <description>${escapeXml(desc)}</description>
    </item>`;
    })
    .join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(channelTitle)}</title>
    <link>${escapeXml(htmlIndex)}</link>
    <description>${escapeXml(channelDescription)}</description>
    <language>en</language>
    <lastBuildDate>${buildDate}</lastBuildDate>
    <ttl>60</ttl>
    <atom:link href="${escapeXml(selfUrl)}" rel="self" type="application/rss+xml"/>
${xmlItems}
  </channel>
</rss>
`;

  const response = new Response(xml, {
    status: 200,
    headers: {
      'Content-Type': 'application/rss+xml; charset=utf-8',
      'Cache-Control': `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}`,
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
