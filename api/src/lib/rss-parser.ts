/**
 * Tiny RSS 2.0 parser. Sufficient for the breach-coverage use case —
 * 8 known feeds, well-formed XML, no Atom or RDF needs. We deliberately
 * do NOT pull in a full XML library (cost, attack surface, 200KB on
 * the worker bundle) and we hand-roll a streaming-ish extraction with
 * regex on `cd`-buffered items, which is robust enough for the
 * single-purpose headline search the route does.
 *
 * What we extract per <item>:
 *   - title (required)
 *   - link  (required)
 *   - pubDate (RFC 822 — we parse to ISO 8601)
 *   - description (first 400 chars, HTML-stripped for matching)
 *   - source / category (optional)
 *
 * What we ignore:
 *   - <enclosure>, <guid> (except as dedup key)
 *   - <content:encoded> (same as description, larger — skip)
 *   - Atom <feed> entirely (these feeds are RSS 2.0)
 *   - Namespaces we don't use
 *
 * Failure mode: a malformed <item> block is dropped silently. The
 * route reports the count of items that DID parse; a totally broken
 * feed returns 0 and is logged.
 */

export interface RssItem {
  title: string;
  link: string;
  /** ISO 8601 (UTC) of pubDate; undefined when the feed omits it. */
  pubDate?: string;
  /** Plain-text snippet, max 400 chars, HTML stripped. */
  snippet: string;
  source?: string;
  category?: string;
}

/** Extract the first N <item>...</item> blocks from an RSS body. */
function extractItemBlocks(xml: string): string[] {
  const out: string[] = [];
  const re = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    out.push(m[1] ?? '');
  }
  return out;
}

/** Extract the content of a single tag from a block. CDATA-aware. */
function extractTag(block: string, tag: string): string | undefined {
  // <tag>value</tag> OR <tag><![CDATA[value]]></tag>
  const re = new RegExp(`<${tag}\\b[^>]*>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))<\\/${tag}>`, 'i');
  const m = re.exec(block);
  if (!m) return undefined;
  return (m[1] ?? m[2] ?? '').trim();
}

/** First CDATA or text inside a self-closing-or-not tag (link is often <link/>). */
function extractLink(block: string): string | undefined {
  // <link>https://...</link>  OR  <link href="..."/> (atom-ish, rare)
  const m = /<link>([\s\S]*?)<\/link>/i.exec(block);
  if (m) return (m[1] ?? '').trim();
  const m2 = /<link\s+[^>]*href=["']([^"']+)["'][^>]*\/?>/i.exec(block);
  return m2?.[1]?.trim();
}

/** Strip HTML tags, collapse whitespace, truncate. */
function stripHtml(s: string, max: number): string {
  const noTags = s
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
  return noTags.length > max ? noTags.slice(0, max) + '…' : noTags;
}

/** Parse RFC 822 (e.g. "Wed, 04 Jun 2026 12:34:56 +0000") to ISO 8601. */
export function rfc822ToIso(s: string): string | undefined {
  // Date.parse handles RFC 822 in modern runtimes; we double-check the
  // result is a real time so a malformed string doesn't produce a NaN
  // epoch masquerading as "1970-01-01".
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) return undefined;
  return new Date(ms).toISOString();
}

/**
 * Bing News search RSS wraps every item link in a click redirector —
 * `http://www.bing.com/news/apiclick.aspx?ref=FexRss&…&url=<encoded target>`.
 * Every surface that renders a feed item should link straight to the publisher,
 * not through Bing's tracker, so the unwrap lives here with the parsers rather
 * than being copy-pasted per call site.
 *
 * Two details that are easy to get wrong and fail *silently* (the item still
 * renders, just linking through Bing):
 *
 *  1. `&amp;` — the redirect URL arrives XML-escaped in most feeds, so the query
 *     looks like `…&amp;tid=abc&amp;url=…`. `URL` does not treat `&amp;` as a
 *     separator, so `searchParams.get('url')` is null and nothing gets unwrapped.
 *     Decode before parsing rather than requiring every caller to decode first.
 *  2. `apiclick.aspx` lives under /news/, not the search path — a plain
 *     `www.bing.com` check would also mangle the search-feed's own `<link>`.
 *
 * Non-Bing links pass through untouched; a missing, malformed or non-http(s)
 * `url` param falls back to the original link.
 */
export function unwrapBingNewsLink(link: string): string {
  if (!link) return link;
  try {
    // Only the redirector path is touched; the entity decode below is a no-op
    // for every other URL.
    const candidate = link.replace(/&amp;/gi, '&').trim();
    const u = new URL(candidate);
    if (!/(^|\.)bing\.com$/i.test(u.hostname)) return link;
    if (!u.pathname.endsWith('/apiclick.aspx')) return link;
    const target = u.searchParams.get('url');
    if (!target) return link;
    const decoded = new URL(target);
    if (decoded.protocol !== 'http:' && decoded.protocol !== 'https:') return link;
    return decoded.toString();
  } catch {
    return link;
  }
}

/**
 * Parse an RSS 2.0 document. Returns one RssItem per <item>; malformed
 * items are dropped (the route reports the count). The channel-level
 * <title>/<link>/<description> are not surfaced — we only need items.
 */
export function parseRss(xml: string): RssItem[] {
  if (!xml || xml.length < 50) return [];
  // Quick sanity check: must contain <rss or <channel — skip feeds
  // that 200-OK with an HTML error page.
  if (!/<rss[\s>]/i.test(xml) && !/<channel[\s>]/i.test(xml)) return [];

  const blocks = extractItemBlocks(xml);
  const items: RssItem[] = [];
  for (const block of blocks) {
    const title = extractTag(block, 'title');
    const link = extractLink(block);
    if (!title || !link) continue; // required
    const pubDateRaw = extractTag(block, 'pubDate');
    const pubDate = pubDateRaw ? rfc822ToIso(pubDateRaw) : undefined;
    const descRaw = extractTag(block, 'description') ?? '';
    const snippet = stripHtml(descRaw, 400);
    const source = extractTag(block, 'source');
    const category = extractTag(block, 'category');
    items.push({
      title: stripHtml(title, 200),
      link: unwrapBingNewsLink(link),
      pubDate,
      snippet,
      source,
      category,
    });
  }
  return items;
}
