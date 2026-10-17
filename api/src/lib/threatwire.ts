/**
 * ThreatWire — editorial CVE wire (https://www.threatwire.tech/feed.xml).
 *
 * ThreatWire's stated rule is the same one this platform needs: "an explicit
 * line between what is confirmed and what is unknown." Every post names its
 * CVE ids and then states, in plain text, whether the issue is in CISA KEV,
 * whether a public PoC exists, whether it is a zero-day, and whether a fix
 * has shipped. Those are exactly the exploitability signals `/api/v1/cve-recent`
 * otherwise has to infer from KEV membership + EPSS.
 *
 * Two deliberate constraints:
 *
 *  1. **Flags are only extracted when a post covers exactly one CVE.** A post
 *     that discusses several ids ("Apple patches an EXR zero-click bug, a
 *     macOS root flaw...") makes "Fixed in 15.5.28" ambiguous — attaching that
 *     to both ids would assert something the source did not. Multi-CVE posts
 *     still contribute their ids (as gap-fill leads); they just carry no flags.
 *  2. **No flag is invented.** Each regex requires an explicit statement, a
 *     negative ("Not in CISA KEV", "No public PoC") leaves the flag undefined
 *     rather than false where the wording is about a *different* thing, and an
 *     unparseable CVSS number is dropped instead of defaulted.
 *
 * The feed is RSS 2.0 and well-formed; `parseRss` already covers it.
 */

import { parseRss } from './rss-parser';
import { logError } from './logger';

export const THREATWIRE_FEED_URL = 'https://www.threatwire.tech/feed.xml';

/** One CVE id mentioned by one ThreatWire post. */
export interface ThreatWireCve {
  cve_id: string;
  /** Post title, used as the row description for gap-filled ids. */
  title: string;
  /** Post URL — also the provenance link for an annotated id. */
  link: string;
  /** ISO 8601 publication time. */
  published: string;
  /** CVSS number stated in the post (single-CVE posts only). */
  score?: number;
  /** Post says the CVE is in (true) or not in (false) CISA KEV. */
  kev?: boolean;
  /** Post says a public PoC exists (true) or that none is known (false). */
  poc?: boolean;
  /** Post calls it a zero-day / exploited in the wild (true) or not (false). */
  zero_day?: boolean;
  /** Post says a fix shipped (true) or that none exists (false). */
  patched?: boolean;
}

export interface ThreatWireFetchResult {
  items: ThreatWireCve[];
  ok: boolean;
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

/** Cap on a title echoed into a row description. */
const MAX_TITLE_CHARS = 200;

/**
 * CVSS patterns, most specific first. Ordered because "CISA-ADP CVSS 3.1 6.5"
 * otherwise yields the *version* (3.1) as the score. Every pattern is anchored
 * on an explicit number that can only be a base score.
 */
const SCORE_PATTERNS: RegExp[] = [
  // "CVSS 3.1 6.5", "CVSS v4.0 9.2", "CVSS 4.0 8.1"
  /\bCVSS\s*v?[34]\.\d\s+(\d{1,2}(?:\.\d)?)\b/i,
  // "scores it 9.5", "scores this 7.8", "score of 6.4"
  /\bscores?\s+(?:it|this|the [a-z]+)?\s*(\d{1,2}\.\d)\b/i,
  // "CVSS 9.8", "CVSS score 7.5" (a decimal is required so a bare version
  // token like "CVSS 3.1" without a following base score is not matched)
  /\bCVSS\s*(?:base\s*)?(?:score\s*)?(?:of\s*)?(\d{1,2}\.\d)\b/i,
  // "9.8 CVSS"
  /\b(\d{1,2}\.\d)\s*CVSS\b/i,
];

/** Extract the first plausible base score (0 < n <= 10) from the text. */
export function parseThreatWireScore(text: string): number | undefined {
  for (const re of SCORE_PATTERNS) {
    const m = re.exec(text);
    if (!m?.[1]) continue;
    const n = Number.parseFloat(m[1]);
    if (Number.isFinite(n) && n > 0 && n <= 10) return n;
  }
  return undefined;
}

/**
 * Editorial status flags. Each pair is [explicit-negative, explicit-positive]
 * and the negative is tested first: "Not in CISA KEV" contains "in CISA KEV",
 * so a positive-first test would invert the flag.
 */
function parseFlag(text: string, negative: RegExp, positive: RegExp): boolean | undefined {
  if (negative.test(text)) return false;
  if (positive.test(text)) return true;
  return undefined;
}

export function parseThreatWireFlags(text: string): Pick<ThreatWireCve, 'kev' | 'poc' | 'zero_day' | 'patched'> {
  const kev = parseFlag(
    text,
    /\bnot\s+(?:yet\s+)?(?:in|on|added to)\s+(?:the\s+)?cisa[\s-]*kev\b/i,
    /\b(?:added to|in|listed in|on)\s+(?:the\s+)?cisa[\s-]*kev\b/i
  );
  const poc = parseFlag(
    text,
    /\bno\s+(?:public\s+|known\s+|confirmed\s+)?(?:poc|proof[- ]of[- ]concept)\b|\bwithout\s+(?:a\s+)?(?:poc|proof[- ]of[- ]concept)\b/i,
    /\bpublic\s+(?:poc|proof[- ]of[- ]concept)\b|\b(?:poc|proof[- ]of[- ]concept)\s+(?:is\s+)?(?:available|published|released|exists)\b|\bexploit\s+(?:code\s+)?(?:is\s+)?(?:public|available|released)\b/i
  );
  const zero_day = parseFlag(
    text,
    /\bno\s+(?:evidence\s+of\s+)?(?:in-the-wild\s+)?exploitation\b|\bnot\s+(?:being\s+)?exploited\b/i,
    /\bzero[- ]day\b|\b0-day\b|\bexploited\s+in\s+the\s+wild\b|\bactive(?:ly)?\s+exploited\b/i
  );
  const patched = parseFlag(
    text,
    /\bno\s+(?:vendor\s+)?(?:fix|patch)\b|\bunpatched\b|\bnot\s+(?:yet\s+)?(?:fixed|patched)\b/i,
    /\b(?:fixed|patched)\b|\bpatch(?:es)?\s+(?:is|are)\s+(?:available|released)\b/i
  );
  return { kev, poc, zero_day, patched };
}

/**
 * Parse the ThreatWire wire feed into one record per mentioned CVE id.
 *
 * A post mentioning N ids yields N records. Duplicate ids across posts keep
 * the newest post (feeds are newest-first, so the first occurrence wins).
 */
export function parseThreatWireFeed(xml: string): ThreatWireCve[] {
  const items = parseRss(xml);
  const out: ThreatWireCve[] = [];
  const seen = new Set<string>();

  for (const item of items) {
    const text = `${item.title} ${item.snippet}`;
    const ids = [...new Set((text.match(CVE_RE) ?? []).map((id) => id.toUpperCase()))];
    if (ids.length === 0) continue;

    const published = item.pubDate ?? new Date().toISOString();
    // Flags are scoped to a single-CVE post; see the module header.
    const single = ids.length === 1 ? ids[0] : undefined;
    const flags = single ? parseThreatWireFlags(text) : {};
    const score = single ? parseThreatWireScore(text) : undefined;

    for (const cve_id of ids) {
      if (seen.has(cve_id)) continue;
      seen.add(cve_id);
      out.push({
        cve_id,
        title: item.title.slice(0, MAX_TITLE_CHARS),
        link: item.link,
        published,
        ...(cve_id === single && score !== undefined ? { score } : {}),
        ...(cve_id === single ? flags : {}),
      });
    }
  }
  return out;
}

/**
 * Fetch + parse the wire feed. Never throws: a dead upstream returns
 * `{ items: [], ok: false }` so the caller can report it as one `ok:false`
 * source row without dropping the other seven CVE tiers.
 */
export async function fetchThreatWireCves(): Promise<ThreatWireFetchResult> {
  try {
    const res = await fetch(THREATWIRE_FEED_URL, {
      signal: AbortSignal.timeout(12_000),
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)',
        accept: 'application/rss+xml, application/xml, text/xml, */*',
      },
      cf: { cacheTtlByStatus: { '200-299': 1800, '400-599': 0 } },
    } as RequestInit);
    if (!res.ok) return { items: [], ok: false };
    const items = parseThreatWireFeed(await res.text());
    return { items, ok: true };
  } catch (_catchErr) {
    logError('threatwire-feed', _catchErr);
    return { items: [], ok: false };
  }
}
