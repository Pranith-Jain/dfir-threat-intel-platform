/**
 * Breach-coverage search engine — "what is public OSINT saying about
 * breach forums / leaks / data breaches today?"
 *
 * Hard guardrail: this module serves HEADLINES + LINKS, never the
 * underlying leak content. Every source is a public RSS feed from a
 * named OSINT publisher (DarkWebInformer, BleepingComputer, The
 * Record, Threatpost, HackRead, SecurityWeek, CyberScoop,
 * DataBreaches.net). None of them point at forums, dumps, or
 * credentials. This is a search engine over news, not a search
 * engine over leaks.
 *
 * Two keyword presets ship built-in:
 *   - "breach"   — broad coverage: data breaches, leaks, exposures,
 *                  credential dumps, ransomware. Used for the
 *                  "OSINT Coverage" section.
 *   - "forums"   — tight: named leak-forum brands
 *                  (BreachForums, Leakbase, Cracked, Nulled, Dread,
 *                  Exposed, LeakZone, etc.). Used for the "Forum
 *   - "custom"   — caller passes ?q=... and we AND the whitespace-
 *                  separated tokens (case-insensitive substring).
 *
 * Multi-source fan-out: all 8 feeds are fetched concurrently with
 * `fetchResilient`. Per-source failures are isolated (Promise.allSettled)
 * so a single dead feed doesn't blank the result.
 */

import { fetchResilient } from './fetch-resilient';
import { parseRss, type RssItem } from './rss-parser';

export const BREACH_COVERAGE_SOURCES: Array<{ id: string; name: string; url: string; description: string }> = [
  {
    id: 'darkwebinformer',
    name: 'Dark Web Informer',
    url: 'https://darkwebinformer.com/rss/',
    description: 'Daily dark web intelligence, ransomware leak-site posts, breach reports, and underground chatter',
  },
  {
    id: 'databreaches',
    name: 'DataBreaches.net',
    url: 'https://databreaches.net/feed/',
    description: 'Breach reporting and analysis from Dissent. Wide healthcare, education, and government coverage',
  },
  {
    id: 'bleepingcomputer-breaches',
    name: 'BleepingComputer · Data Breaches',
    // bleepingcomputer.com 403s datacenter egress — Bing News mirror instead (news.google.com 503s Worker egress).
    url: 'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
    description: 'BleepingComputer breach coverage via main feed',
  },
  {
    id: 'the-record',
    name: 'The Record',
    url: 'https://therecord.media/feed',
    description: 'Cybersecurity reporting from Recorded Future — dark web + ransomware focus',
  },
  {
    id: 'grahamcluley',
    name: 'Graham Cluley',
    url: 'https://www.grahamcluley.com/feed/',
    description: 'Independent security commentary — breach incidents + threat research roundups',
  },
  {
    id: 'hackread-breaches',
    name: 'HackRead · Data Breaches',
    url: 'https://hackread.com/category/security/data-breach/feed/',
    description: 'Global breach reporting — India + emerging-markets focus',
  },
  {
    id: 'securityweek-breaches',
    name: 'SecurityWeek · Cyber Incidents',
    url: 'https://www.securityweek.com/category/cybercrime/feed/',
    description: 'Enterprise breach incident reporting + regulator notices',
  },
  {
    id: 'cyberscoop-breaches',
    name: 'CyberScoop',
    url: 'https://cyberscoop.com/feed/',
    description: 'US government + enterprise cyber incident coverage, indictments',
  },
];

/**
 * Broad breach keyword set. Matched as case-insensitive substrings
 * against `title + " " + snippet`. Picked for high precision on the
 * 8 sources (these terms all appear in the relevant headlines, and
 * rarely on other cyber news like "patch Tuesday").
 */
const BREACH_KEYWORDS = [
  'breach',
  'data leak',
  'leak site',
  'leaked',
  'credential',
  'exposed data',
  'data exposure',
  'ransomware',
  'ransom',
  'extortion',
  'data dump',
  'leak-base',
  'leakbase',
  'hacker forum',
  'stolen data',
  'records exposed',
  'victims',
  'threat actor',
  'cybercrime',
];

/**
 * Tight forum-name keyword set. Only the named forums / leak
 * communities surface here, so "Forum Mentions" is a small, high-
 * precision list — usually 1-5 items per fetch.
 */
const FORUM_KEYWORDS = [
  'breachforums',
  'breached',
  'leakbase',
  'leak-zone',
  'leakzone',
  'cracked.to',
  'cracked forum',
  'nulled',
  'exposed forum',
  'exposed.su',
  'demonforums',
  'demon forums',
  'xss forum',
  'xss.is',
  'sinisterly',
  'dread forum',
  'dread onion',
  'ogusers',
  'raidforums',
];

/** Tokenise a `?q=` query into normalised AND-terms. */
export function tokenizeQuery(q: string): string[] {
  return q
    .toLowerCase()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

/** True if every token appears as a substring in `haystack`. */
function matchesAll(haystack: string, tokens: string[]): boolean {
  const h = haystack.toLowerCase();
  for (const t of tokens) {
    if (!h.includes(t)) return false;
  }
  return true;
}

/** True if ANY of the keywords appears in `haystack`. */
function matchesAny(haystack: string, keywords: string[]): boolean {
  const h = haystack.toLowerCase();
  for (const k of keywords) {
    if (h.includes(k)) return true;
  }
  return false;
}

export type CoverageTopic = 'breach' | 'forums' | 'custom';

export interface CoverageInputItem extends RssItem {
  source_id: string;
  source_name: string;
}

export interface FilterOptions {
  topic: CoverageTopic;
  /** Only meaningful when topic === 'custom'. Whitespace-separated AND tokens. */
  query?: string;
  /** Max items to return. Defaults to 50; hard-max 200. */
  limit?: number;
  /** Drop items without a pubDate (defaults to true — newest-first needs dates). */
  datedOnly?: boolean;
}

/** Score for ranking: prefers dated items, then keyword density, then recency. */
function score(item: CoverageInputItem, matchedKeywords: number, hasDate: boolean): number {
  return (hasDate ? 1_000_000 : 0) + matchedKeywords * 1000 + (item.pubDate ? Date.parse(item.pubDate) : 0) / 1e9;
}

export function filterByTopic(items: CoverageInputItem[], opts: FilterOptions): CoverageInputItem[] {
  const tokens = opts.topic === 'custom' ? tokenizeQuery(opts.query ?? '') : null;
  const keywordSet = opts.topic === 'forums' ? FORUM_KEYWORDS : opts.topic === 'breach' ? BREACH_KEYWORDS : null;
  const datedOnly = opts.datedOnly ?? true;
  const limit = Math.max(1, Math.min(opts.limit ?? 50, 200));

  const matched: Array<{ item: CoverageInputItem; matched: number; hasDate: boolean }> = [];
  for (const item of items) {
    const haystack = `${item.title} ${item.snippet}`;
    let m = 0;
    if (tokens) {
      if (!matchesAll(haystack, tokens)) continue;
      m = tokens.length;
    } else if (keywordSet) {
      if (!matchesAny(haystack, keywordSet)) continue;
      const h = haystack.toLowerCase();
      for (const k of keywordSet) if (h.includes(k)) m++;
    } else {
      continue;
    }
    if (datedOnly && !item.pubDate) continue;
    matched.push({ item, matched: m, hasDate: !!item.pubDate });
  }

  matched.sort((a, b) => score(b.item, b.matched, b.hasDate) - score(a.item, a.matched, a.hasDate));
  return matched.slice(0, limit).map((m) => m.item);
}

export interface FetchAndFilterOptions extends FilterOptions {
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
  /** Per-feed timeout. Defaults to 6s. */
  timeoutMs?: number;
}

export interface CoverageResult {
  items: CoverageInputItem[];
  sources: Array<{
    id: string;
    name: string;
    url: string;
    ok: boolean;
    status?: number;
    items_fetched: number;
    error?: string;
  }>;
}

async function fetchFeed(
  src: { id: string; name: string; url: string },
  fetchFn: typeof globalThis.fetch,
  signal: AbortSignal | undefined,
  timeoutMs: number
): Promise<{ items: CoverageInputItem[]; result: CoverageResult['sources'][number] }> {
  const result: CoverageResult['sources'][number] = {
    id: src.id,
    name: src.name,
    url: src.url,
    ok: false,
    items_fetched: 0,
  };
  try {
    const res = await fetchResilient(
      src.url,
      {
        headers: { accept: 'application/rss+xml, application/xml, text/xml, */*' },
        signal: signal ?? AbortSignal.timeout(timeoutMs),
      },
      { attempts: 2, baseDelayMs: 500, maxDelayMs: 1500, timeoutMs, fetch: fetchFn }
    );
    if (!res.ok) {
      result.status = res.status;
      result.error = `HTTP ${res.status}`;
      return { items: [], result };
    }
    const xml = await res.text();
    const items = parseRss(xml);
    const enriched: CoverageInputItem[] = items.map((it) => ({
      ...it,
      source_id: src.id,
      source_name: src.name,
    }));
    result.ok = true;
    result.items_fetched = enriched.length;
    return { items: enriched, result };
  } catch (e) {
    result.error = e instanceof Error ? e.message : String(e);
    return { items: [], result };
  }
}

/**
 * Fetch all 8 OSINT breach RSS feeds in parallel, then filter by the
 * chosen topic. Per-feed failures are isolated — a single dead feed
 * never blanks the result. The route serves the result with a 15-min
 * edge cache (RSS updates slowly; the user is asking "what's the
 * current news" not "what was published 30 seconds ago").
 */
export async function fetchBreachCoverage(opts: FetchAndFilterOptions): Promise<CoverageResult> {
  const fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = opts.timeoutMs ?? 6000;
  const settled = await Promise.allSettled(
    BREACH_COVERAGE_SOURCES.map((s) => fetchFeed(s, fetchFn, opts.signal, timeoutMs))
  );
  const allItems: CoverageInputItem[] = [];
  const sourceResults: CoverageResult['sources'] = [];
  for (const s of settled) {
    if (s.status === 'fulfilled') {
      allItems.push(...s.value.items);
      sourceResults.push(s.value.result);
    } else {
      // Promise.allSettled should never reject here (fetchFeed catches
      // everything) but be defensive — surface as a failed source.
      sourceResults.push({
        id: 'unknown',
        name: 'unknown',
        url: '',
        ok: false,
        items_fetched: 0,
        error: s.reason instanceof Error ? s.reason.message : String(s.reason),
      });
    }
  }
  const items = filterByTopic(allItems, opts);
  return { items, sources: sourceResults };
}
