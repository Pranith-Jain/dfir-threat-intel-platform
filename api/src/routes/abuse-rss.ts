/**
 * abuse.ch killed their public RSS endpoints (urlhaus/threatfox/malwarebazaar
 * /rss/ all 404). Their CSV "recent" downloads still work, so we synthesise
 * an RSS 2.0 feed from those CSVs server-side. This lets the existing static
 * RSSFeed list keep loading abuse.ch sources without needing API keys.
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, badGateway } from '../lib/api-error';
import { getSiteUrl } from '../lib/site-config';
import { FEED_SOURCES, buildSummary, type IocEntry, type SourceId } from '../lib/ioc-feed-parsers';
import { abuseChFeedRequestForEnv, type AbuseChFeedSource } from '../lib/abusech';

const SUPPORTED: SourceId[] = ['urlhaus', 'threatfox', 'malwarebazaar'];
const FETCH_UA = 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)';

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function entryToItem(entry: IocEntry, sourceName: string, siteUrl: string): string {
  const title = `${entry.type.toUpperCase()}: ${entry.value}`;
  const link =
    entry.type === 'url' ? entry.value : `${siteUrl}/dfir/ioc-check?indicator=${encodeURIComponent(entry.value)}`;
  const description = entry.context ?? `${sourceName} ${entry.type}`;
  const guid = `${sourceName}:${entry.value}`;
  const pubDate = entry.timestamp
    ? new Date(entry.timestamp.replace(' ', 'T')).toUTCString()
    : new Date().toUTCString();
  return `    <item>
      <title>${escapeXml(title)}</title>
      <link>${escapeXml(link)}</link>
      <description>${escapeXml(description)}</description>
      <pubDate>${escapeXml(pubDate)}</pubDate>
      <guid isPermaLink="false">${escapeXml(guid)}</guid>
    </item>`;
}

export async function abuseRssHandler(c: Context<{ Bindings: Env }>) {
  const sourceParam = c.req.query('source') as SourceId | undefined;
  if (!sourceParam || !SUPPORTED.includes(sourceParam)) {
    return badRequest(c, `unsupported source; valid: ${SUPPORTED.join(', ')}`);
  }
  const meta = FEED_SOURCES[sourceParam];

  let entries: IocEntry[] = [];
  try {
    const req = abuseChFeedRequestForEnv(c.env, sourceParam as AbuseChFeedSource, { days: 7 });
    const upstream = await fetch(req.url, {
      ...req.init,
      headers: {
        'user-agent': FETCH_UA,
        ...((req.init.headers as Record<string, string> | undefined) ?? {}),
      },
      signal: AbortSignal.timeout(15_000),
      cf: { cacheTtlByStatus: { '200-299': 1800, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    if (upstream.status === 429) {
      const retryAfter = upstream.headers.get('retry-after') ?? '60';
      return c.json(
        { error: 'upstream_rate_limited', upstream: new URL(meta.url).host, source: sourceParam, upstream_status: 429 },
        429,
        { 'retry-after': retryAfter, 'cache-control': 'no-store' }
      );
    }
    if (!upstream.ok) {
      return badGateway(c, `upstream ${upstream.status} for ${sourceParam}`);
    }
    const body = await upstream.text();
    entries = buildSummary(sourceParam, body).entries;
  } catch (err) {
    logError('abuseRssHandler failed', err);
    return badGateway(c, err instanceof Error ? err.message : 'fetch failed');
  }

  const limited = entries.slice(0, 50);
  const siteUrl = getSiteUrl(c.env);
  const items = limited.map((e) => entryToItem(e, meta.name, siteUrl)).join('\n');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>${escapeXml(meta.name)}</title>
    <link>${escapeXml(`https://${new URL(meta.url).host}/`)}</link>
    <description>${escapeXml(`Recent ${sourceParam} indicators (synthesised from abuse.ch CSV — ${meta.name}).`)}</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
${items}
  </channel>
</rss>`;

  return new Response(xml, {
    status: 200,
    headers: {
      'content-type': 'application/xml; charset=utf-8',
      'cache-control': 'public, max-age=900, s-maxage=1800',
    },
  });
}
