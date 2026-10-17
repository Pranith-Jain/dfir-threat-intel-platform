import type { AggregatedFeedItem } from '../../services/rssService';
import { errMessage } from '../../lib/log';
export type FeedItem = AggregatedFeedItem & { source: string; pubDate: string };

/**
 * Curated dark-web monitoring sources. Higher-signal subset of the general
 * ThreatIntelFeed - leak sites, ransomware, breach reports, and IR writeups
 * that surface dark-web activity.
 */
export const DARKWEB_FEEDS: { id: string; label: string }[] = [
  { id: 'darkwebinformer', label: 'Dark Web Informer' },
  { id: 'ransomware-live', label: 'Ransomware.live' },
  { id: 'databreaches', label: 'DataBreaches.net' },
  { id: 'dfir-report', label: 'The DFIR Report' },
  { id: 'the-record', label: 'The Record' },
  // Added round 2: more breadth, all verified live
  { id: 'bleepingcomputer', label: 'BleepingComputer' },
  { id: 'krebsonsecurity', label: 'Krebs on Security' },
  { id: 'malware-traffic-analysis', label: 'Malware Traffic Analysis' },
  // Added 2026-05-18: dark-web / CTI research breadth, all HTTP-200+XML verified
  { id: 'cyble-blog', label: 'Cyble Research' },
  { id: 'socradar-blog', label: 'SOCRadar' },
  { id: 'bushidotoken', label: 'BushidoToken' },
  { id: 'mti-ransomware', label: 'MyThreatIntel (ransomware)' },
  { id: 'ransomware-merged', label: 'Ransomware claims (merged)' },
];

export const ALL_FEED_IDS = DARKWEB_FEEDS.map((f) => f.id);

export const STORAGE_KEY_WATCH = 'dfir.darkweb.watchlist';
export const STORAGE_KEY_SOURCES = 'dfir.darkweb.activeSources';
export const MAX_PER_SOURCE = 12;
export const MAX_ITEMS = 200;

// Watch window is capped at 30 days. Older items are dropped on the client so
// the feed reflects current threat activity, not historical noise.
export type DateWindow = '24h' | '7d' | '30d';

export function loadJson<T>(key: string, fallback: T): T {
  if (typeof window === 'undefined') return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch (_catchErr) {
    console.error('loadJson failed:', errMessage(_catchErr));
    return fallback;
  }
}

export function saveJson<T>(key: string, value: T): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch (_catchErr) {
    console.error('saveJson failed:', errMessage(_catchErr));
    /* localStorage may be disabled in private mode */
  }
}

export interface MatchedItem {
  item: FeedItem;
  watchMatches: string[];
  searchMatch: boolean;
}

export function findWatchMatches(item: FeedItem, watchlist: string[]): string[] {
  if (watchlist.length === 0) return [];
  const haystack = `${item.title ?? ''} ${item.description ?? ''}`.toLowerCase();
  return watchlist.filter((term) => term && haystack.includes(term.toLowerCase()));
}

/** Live search supports plain substring and regex (when wrapped in /pattern/). */
export function compileSearch(query: string): ((item: FeedItem) => boolean) | null {
  const trimmed = query.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('/') && trimmed.lastIndexOf('/') > 0) {
    try {
      const lastSlash = trimmed.lastIndexOf('/');
      const pattern = trimmed.slice(1, lastSlash);
      const flags = trimmed.slice(lastSlash + 1) || 'i';
      // Guard against ReDoS: cap length and refuse nested quantifiers.
      if (pattern.length > 200) return null;
      if (/(\([^)]*[+*][^)]*\)|\[[^\]]*\][+*])[+*]/.test(pattern)) return null;
      const re = new RegExp(pattern, flags);
      return (item) => re.test(`${item.title ?? ''} ${item.description ?? ''}`);
    } catch (_catchErr) {
      console.error('compileSearch failed:', errMessage(_catchErr));
      return null; // bad regex
    }
  }
  // Plain text: split on whitespace, ALL terms must appear (AND semantics)
  const tokens = trimmed.toLowerCase().split(/\s+/).filter(Boolean);
  return (item) => {
    const hay = `${item.title ?? ''} ${item.description ?? ''}`.toLowerCase();
    return tokens.every((t) => hay.includes(t));
  };
}

export function withinWindow(item: FeedItem, win: DateWindow): boolean {
  const t = new Date(item.pubDate).getTime();
  if (!t) return false;
  const ageMs = Date.now() - t;
  switch (win) {
    case '24h':
      return ageMs <= 24 * 3600_000;
    case '7d':
      return ageMs <= 7 * 86400_000;
    case '30d':
      return ageMs <= 30 * 86400_000;
  }
}

export function highlightInText(text: string, re: RegExp | null): JSX.Element {
  if (!re) return <>{text}</>;
  // String.split with a single capturing group puts the matched delimiters at
  // the ODD indices of the result - use that parity instead of re.test(part).
  // `re` carries the /g flag and .test() mutates its lastIndex, so calling it
  // once per fragment in this loop previously mis-tagged parts. (split itself
  // ignores lastIndex, so reusing one precompiled `re` across rows is safe.)
  const parts = text.split(re);
  return (
    <>
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <mark key={`${part}-${i}`} className="bg-amber-200 dark:bg-amber-700/40 text-inherit rounded px-0.5">
            {part}
          </mark>
        ) : (
          <span key={`${part}-${i}`}>{part}</span>
        )
      )}
    </>
  );
}
