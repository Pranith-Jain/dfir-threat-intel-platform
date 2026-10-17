/**
 * Tests for lib/rss-parser.ts — specifically the Bing News click-redirector
 * unwrap added with the 2026-10 Google News → Bing News migration.
 *
 * Background: news.google.com 503s Cloudflare Worker egress, so every news
 * search feed moved to Bing News RSS, which wraps each item link in
 * `http://www.bing.com/news/apiclick.aspx?...&url=<encoded target>`. If the
 * unwrap regresses, every item links through Bing's tracker and the "publisher"
 * link is lost — invisible in tests that only assert item counts.
 */
import { describe, it, expect } from 'vitest';
import { parseRss, unwrapBingNewsLink } from '../../src/lib/rss-parser';

const BING_ITEM = (target: string) =>
  `<item><title>Headline</title><link>http://www.bing.com/news/apiclick.aspx?ref=FexRss&aid=&amp;tid=abc&amp;url=${encodeURIComponent(
    target
  )}&amp;c=123&amp;mkt=en-in</link><pubDate>Thu, 15 Oct 2026 10:00:00 GMT</pubDate><description>Body</description></item>`;

describe('unwrapBingNewsLink', () => {
  it('resolves the apiclick redirect to the publisher URL', () => {
    const wrapped =
      'http://www.bing.com/news/apiclick.aspx?ref=FexRss&url=https%3A%2F%2Fbleepingcomputer.com%2Fnews%2Fsecurity%2F&c=1';
    expect(unwrapBingNewsLink(wrapped)).toBe('https://bleepingcomputer.com/news/security/');
  });

  it('leaves ordinary links untouched', () => {
    for (const link of [
      'https://krebsonsecurity.com/2026/10/thing/',
      'http://www.bleepingcomputer.com/news/x/',
      'https://www.bing.com/news/search?q=test&format=RSS', // not the redirector
      '',
    ]) {
      expect(unwrapBingNewsLink(link)).toBe(link);
    }
  });

  it('does not trust a non-http(s) target', () => {
    const hostile = 'http://www.bing.com/news/apiclick.aspx?url=javascript%3Aalert%281%29&c=1';
    expect(unwrapBingNewsLink(hostile)).toBe(hostile);
  });

  it('falls back to the original link when url is missing or malformed', () => {
    for (const link of [
      'http://www.bing.com/news/apiclick.aspx?c=1',
      'http://www.bing.com/news/apiclick.aspx?url=%E0%A4%A&c=1',
    ]) {
      expect(unwrapBingNewsLink(link)).toBe(link);
    }
  });
});

describe('parseRss with a Bing mirror body', () => {
  it('unwraps links and still parses items', () => {
    const xml = `<?xml version="1.0"?><rss version="2.0"><channel>${BING_ITEM(
      'https://www.bleepingcomputer.com/news/security/ransomware-report/'
    )}${BING_ITEM('https://thehackernews.com/2026/10/story.html')}</channel></rss>`;
    const items = parseRss(xml);
    expect(items).toHaveLength(2);
    expect(items[0]?.link).toBe('https://www.bleepingcomputer.com/news/security/ransomware-report/');
    expect(items[1]?.link).toBe('https://thehackernews.com/2026/10/story.html');
    expect(items[0]?.pubDate).toBe('2026-10-15T10:00:00.000Z');
  });

  it('still rejects an HTML body served with a 200', () => {
    expect(parseRss('<!DOCTYPE html><html><body>Just a moment…</body></html>')).toHaveLength(0);
  });
});
