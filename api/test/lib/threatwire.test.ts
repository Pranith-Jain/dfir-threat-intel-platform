import { describe, it, expect } from 'vitest';
import { parseThreatWireFeed, parseThreatWireFlags, parseThreatWireScore } from '../../src/lib/threatwire';

/**
 * Minimal RSS 2.0 fixture standing in for https://www.threatwire.tech/feed.xml.
 * The shapes below are copied from the live feed (see the module header):
 * single-CVE news posts carry an explicit status line, multi-CVE roundups do
 * not, and the KEV posts carry a CVSS number plus a due date.
 */
function feed(items: string[]): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>ThreatWire</title><link>https://www.threatwire.tech</link>
${items.join('\n')}
</channel></rss>`;
}

function item(title: string, link: string, pubDate: string, description: string): string {
  return `<item><title>${title}</title><link>${link}</link><guid>${link}</guid><pubDate>${pubDate}</pubDate><description>${description}</description></item>`;
}

describe('parseThreatWireScore', () => {
  // The trap this ordering exists for: "CISA-ADP CVSS 3.1 6.5" read
  // left-to-right with a naive CVSS regex yields the version, not the score.
  it('reads the base score, not the CVSS version, from "CVSS 3.1 6.5"', () => {
    expect(parseThreatWireScore('CISA-ADP CVSS 3.1 6.5. Not in CISA KEV.')).toBe(6.5);
  });

  it('reads a plain "CVSS 9.8" statement', () => {
    expect(parseThreatWireScore('Added to CISA KEV on 2026-10-16. CVSS 9.8.')).toBe(9.8);
  });

  it('reads "scores it 9.5" prose', () => {
    expect(parseThreatWireScore('The Next.js advisory scores it 9.5. Not in CISA KEV.')).toBe(9.5);
  });

  it('returns undefined when no score is stated', () => {
    expect(parseThreatWireScore('Three Apple issues, all fixed.')).toBeUndefined();
  });

  it('rejects an out-of-range number', () => {
    expect(parseThreatWireScore('CVSS 31.4')).toBeUndefined();
  });
});

describe('parseThreatWireFlags', () => {
  it('reads the negative statements as false, not as undefined', () => {
    const flags = parseThreatWireFlags('Rolled out on 1 October. Not in CISA KEV. No public PoC.');
    expect(flags.kev).toBe(false);
    expect(flags.poc).toBe(false);
  });

  it('does not invert "Not in CISA KEV" into a positive KEV flag', () => {
    // "in CISA KEV" is a substring of the negative statement — the negative
    // test has to run first or every clean record reads as exploited.
    expect(parseThreatWireFlags('Not in CISA KEV.').kev).toBe(false);
    expect(parseThreatWireFlags('Added to CISA KEV on 2026-10-16.').kev).toBe(true);
  });

  it('detects a zero-day statement', () => {
    expect(parseThreatWireFlags('This is a zero-day exploited in the wild.').zero_day).toBe(true);
    expect(parseThreatWireFlags('No evidence of exploitation.').zero_day).toBe(false);
  });

  it('detects patch status', () => {
    expect(parseThreatWireFlags('Fixed in 3.4.3.').patched).toBe(true);
    expect(parseThreatWireFlags('No vendor fix is available.').patched).toBe(false);
  });

  it('leaves unstated flags undefined rather than guessing', () => {
    const flags = parseThreatWireFlags('A vendor advisory was published.');
    expect(flags.kev).toBeUndefined();
    expect(flags.poc).toBeUndefined();
    expect(flags.zero_day).toBeUndefined();
    expect(flags.patched).toBeUndefined();
  });
});

describe('parseThreatWireFeed', () => {
  it('parses a single-CVE post into one record with score and flags', () => {
    const xml = feed([
      item(
        'Next.js Image Optimization SVG RCE is CVE-2026-96889',
        'https://www.threatwire.tech/news/nextjs',
        'Thu, 15 Oct 2026 05:15:00 GMT',
        'Vercel fixed a critical unauthenticated RCE. The Next.js advisory scores it 9.5. Not in CISA KEV.'
      ),
    ]);
    const out = parseThreatWireFeed(xml);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      cve_id: 'CVE-2026-96889',
      link: 'https://www.threatwire.tech/news/nextjs',
      published: '2026-10-15T05:15:00.000Z',
      score: 9.5,
      kev: false,
      patched: true,
    });
  });

  it('fans a multi-CVE post out across ids but asserts no per-CVE flags', () => {
    const xml = feed([
      item(
        'Apple patches an EXR zero-click bug, a macOS root flaw and iCloud mail spoofing',
        'https://www.threatwire.tech/research/apple',
        'Sat, 17 Oct 2026 07:44:00 GMT',
        'CVE-2026-86869 is an ImageIO EXR flaw. CVE-2026-43783 is a macOS root escalation. All fixed.'
      ),
    ]);
    const out = parseThreatWireFeed(xml);
    expect(out.map((r) => r.cve_id)).toEqual(['CVE-2026-86869', 'CVE-2026-43783']);
    for (const row of out) {
      expect(row.score).toBeUndefined();
      expect(row.kev).toBeUndefined();
      expect(row.poc).toBeUndefined();
      expect(row.patched).toBeUndefined();
    }
  });

  it('normalises CVE ids to upper case and dedupes across posts', () => {
    const xml = feed([
      item(
        'Lower-case id',
        'https://www.threatwire.tech/cve/cve-2026-11111',
        'Thu, 15 Oct 2026 05:15:00 GMT',
        'cve-2026-11111 disclosed.'
      ),
      item(
        'Same id again',
        'https://www.threatwire.tech/cve/cve-2026-11111-2',
        'Wed, 14 Oct 2026 05:15:00 GMT',
        'CVE-2026-11111 again.'
      ),
    ]);
    const out = parseThreatWireFeed(xml);
    expect(out).toHaveLength(1);
    expect(out[0]!.cve_id).toBe('CVE-2026-11111');
    // Newest-first feed: the first post wins.
    expect(out[0]!.link).toBe('https://www.threatwire.tech/cve/cve-2026-11111');
  });

  it('drops posts that mention no CVE at all', () => {
    const xml = feed([
      item(
        'Weekly roundup',
        'https://www.threatwire.tech/news/roundup',
        'Thu, 15 Oct 2026 05:15:00 GMT',
        'A quiet week.'
      ),
    ]);
    expect(parseThreatWireFeed(xml)).toEqual([]);
  });

  it('returns [] for a non-RSS body instead of throwing', () => {
    expect(parseThreatWireFeed('<html><body>error</body></html>')).toEqual([]);
  });
});
