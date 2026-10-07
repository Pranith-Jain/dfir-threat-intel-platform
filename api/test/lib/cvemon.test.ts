import { describe, it, expect } from 'vitest';
import { parseCvemonFeed } from '../../src/lib/cvemon';

/**
 * cvemon (Intruder) CVE trends parser.
 *
 * The feed is the only source in the stack that measures ATTENTION rather
 * than severity, so a parse regression here silently changes what the
 * Trending tab and the trend-research runner believe is hot. The fixture is a
 * trimmed but structurally faithful copy of the live feed: CDATA in every
 * text node, plus the `intruder:` namespaced rank / hypeScore / cveUrl tags.
 *
 * NOTE: the ids below are synthetic. The live feed's contents change hourly
 * and must never be pinned in a test.
 */

/** Two items, ranks out of order, one with no description. */
const FEED = `<?xml version="1.0" encoding="UTF-8"?>
<rss xmlns:intruder="https://cvemon.intruder.io/rss" version="2.0">
  <channel>
    <title><![CDATA[cvemon | CVE Trends]]></title>
    <lastBuildDate>Wed, 07 Oct 2026 14:58:37 GMT</lastBuildDate>
    <pubDate>Wed, 07 Oct 2026 14:17:02 GMT</pubDate>
    <item>
      <title><![CDATA[CVE-2099-0002]]></title>
      <description><![CDATA[Currently trending CVE - Hype Score: 11 - An unauthenticated remote attacker could exploit this vulnerability by supplying crafted input.]]></description>
      <link>https://cvemon.intruder.io/cves/CVE-2099-0002</link>
      <guid isPermaLink="true">https://cvemon.intruder.io/cves/CVE-2099-0002</guid>
      <pubDate>Wed, 07 Oct 2026 14:17:02 GMT</pubDate>
      <intruder:rank>2</intruder:rank>
      <intruder:hypeScore>11</intruder:hypeScore>
      <intruder:cveUrl>https://cvemon.intruder.io/cves/CVE-2099-0002</intruder:cveUrl>
    </item>
    <item>
      <title><![CDATA[CVE-2099-0001]]></title>
      <description><![CDATA[Currently trending CVE - Hype Score: 13 - Improper validation lets an authenticated user overwrite existing modules to achieve remote code execution.]]></description>
      <link>https://cvemon.intruder.io/cves/CVE-2099-0001</link>
      <guid isPermaLink="true">https://cvemon.intruder.io/cves/CVE-2099-0001</guid>
      <pubDate>Wed, 07 Oct 2026 14:17:02 GMT</pubDate>
      <intruder:rank>1</intruder:rank>
      <intruder:hypeScore>13</intruder:hypeScore>
      <intruder:cveUrl>https://cvemon.intruder.io/cves/CVE-2099-0001</intruder:cveUrl>
    </item>
  </channel>
</rss>`;

/** Malformed / empty inputs must degrade, never throw. */
const EMPTY_FEED = `<?xml version="1.0"?><rss version="2.0"><channel><title>cvemon</title></channel></rss>`;

describe('parseCvemonFeed', () => {
  it('extracts id, rank and hype score', () => {
    const out = parseCvemonFeed(FEED);
    expect(out).toHaveLength(2);
    const first = out.find((c) => c.id === 'CVE-2099-0001');
    expect(first).toBeDefined();
    expect(first?.rank).toBe(1);
    expect(first?.hypeScore).toBe(13);
  });

  it('sorts by rank, not by feed order', () => {
    // The live feed arrives out of order (rank 2 precedes rank 1 above);
    // the UI and the trend runner both rely on rank ordering.
    const out = parseCvemonFeed(FEED);
    expect(out.map((c) => c.rank)).toEqual([1, 2]);
    expect(out[0]?.id).toBe('CVE-2099-0001');
  });

  it('strips the feed prefix from the description', () => {
    const out = parseCvemonFeed(FEED);
    const first = out.find((c) => c.id === 'CVE-2099-0001');
    expect(first?.description).not.toMatch(/Currently trending CVE/i);
    expect(first?.description).not.toMatch(/Hype Score/i);
    expect(first?.description).toContain('Improper validation');
  });

  it('captures the cve detail URL', () => {
    const out = parseCvemonFeed(FEED);
    expect(out[0]?.cveUrl).toBe('https://cvemon.intruder.io/cves/CVE-2099-0001');
  });

  it('carries the item publication date', () => {
    const out = parseCvemonFeed(FEED);
    expect(out[0]?.publishedAt).toMatch(/^2026-10-07T/);
  });

  it('handles HTML entities inside the description', () => {
    const feed = FEED.replace('supplying crafted input', 'supplying &lt;script&gt; input &amp; more');
    const out = parseCvemonFeed(feed);
    expect(out.some((c) => c.description.includes('<script>'))).toBe(true);
    expect(out.some((c) => c.description.includes('&amp;'))).toBe(false);
  });

  it('returns [] for an empty channel instead of throwing', () => {
    expect(parseCvemonFeed(EMPTY_FEED)).toEqual([]);
  });

  it('returns [] for garbage input instead of throwing', () => {
    expect(parseCvemonFeed('not xml at all')).toEqual([]);
    expect(parseCvemonFeed('')).toEqual([]);
  });

  it('falls back to a cvemon /cves/ URL when the title is not a bare id', () => {
    // Some items carry a real headline instead of just the id. The id is still
    // trustworthy because it comes from cvemon's own detail URL.
    const feed = FEED.replace(
      '<title><![CDATA[CVE-2099-0001]]></title>',
      '<title><![CDATA[Vendor patches authentication bypass in edge gateway]]></title>'
    );
    const out = parseCvemonFeed(feed);
    const first = out.find((c) => c.id === 'CVE-2099-0001');
    expect(first).toBeDefined();
    expect(first?.rank).toBe(1);
  });

  it('skips an item with no CVE id in either the title or a cvemon URL', () => {
    const feed = FEED.replace(
      /<item>\s*<title><!\[CDATA\[CVE-2099-0001\]\]><\/title>[\s\S]*?<\/item>/,
      `<item>
        <title><![CDATA[Some headline with no id]]></title>
        <description><![CDATA[Currently trending CVE - Hype Score: 5 - something]]></description>
        <link>https://news.example.com/some-story</link>
        <guid isPermaLink="false">https://news.example.com/some-story</guid>
        <intruder:rank>1</intruder:rank>
        <intruder:hypeScore>5</intruder:hypeScore>
      </item>`
    );
    const out = parseCvemonFeed(feed);
    // The id-less item is dropped; the well-formed rank-2 item survives.
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe('CVE-2099-0002');
  });

  it('does not take an id from a third-party link when the title has none', () => {
    // Neither the headline nor cvemon's own URL identifies a CVE, so the item
    // is not a CVE entry — even though its third-party link happens to contain
    // an id in the path.
    const feed = FEED.replace(
      /<item>\s*<title><!\[CDATA\[CVE-2099-0001\]\]><\/title>[\s\S]*?<\/item>/,
      `<item>
        <title><![CDATA[Weekly roundup]]></title>
        <description><![CDATA[discussion]]></description>
        <link>https://news.example.com/cve-2099-0001-fallout</link>
        <guid isPermaLink="false">https://news.example.com/cve-2099-0001-fallout</guid>
        <intruder:rank>1</intruder:rank>
        <intruder:hypeScore>5</intruder:hypeScore>
      </item>`
    );
    const out = parseCvemonFeed(feed);
    expect(out.some((c) => c.id === 'CVE-2099-0001')).toBe(false);
  });

  it('de-duplicates a repeated id', () => {
    const dup = FEED.replace(
      '<item>',
      '<item><title><![CDATA[CVE-2099-0001]]></title><description><![CDATA[duplicate]]></description>' +
        '<intruder:rank>9</intruder:rank><intruder:hypeScore>1</intruder:hypeScore></item><item>'
    );
    const out = parseCvemonFeed(dup);
    expect(out.filter((c) => c.id === 'CVE-2099-0001')).toHaveLength(1);
  });
});
