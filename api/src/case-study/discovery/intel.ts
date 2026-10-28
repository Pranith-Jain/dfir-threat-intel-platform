import type { Candidate, DedupRecord } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityFromText, noveltyScore, finalScore } from '../scoring';
import { parseRssItems } from './rss-util';

/**
 * CTI research / DFIR / OSINT tradecraft feeds. Consolidated `intel` topic
 * (OSINT + DFIR + Intel) — these are research-article categories, weaker
 * discrete-event fits than CVE/ransom, so sourced from established analyst
 * blogs and surfaced as lower-weight candidates.
 */
// Broadened 2026-05-18: a 4-feed pool kept re-surfacing the same handful of
// stories. These URLs are the ones already battle-tested by the site's RSS
// aggregator (src/data/rssFeeds.ts), so they're known to resolve + parse.
const FEEDS = [
  'https://thedfirreport.com/feed/',
  // BleepingComputer 403s datacenter egress — Bing News mirror instead (news.google.com 503s Worker egress).
  'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
  'https://krebsonsecurity.com/feed/',
  'https://www.sentinelone.com/labs/feed/',
  'https://blog.talosintelligence.com/rss/',
  'https://unit42.paloaltonetworks.com/feed/',
  'https://securelist.com/feed/',
  'https://www.welivesecurity.com/feed/',
  'https://redcanary.com/feed/',
  'https://www.huntress.com/blog/rss.xml',
  'https://googleprojectzero.blogspot.com/feeds/posts/default',
  'https://feeds.feedburner.com/TheHackersNews',
];
const WINDOW_MS = 7 * 24 * 3600 * 1000;

export interface DiscoverDeps {
  fetch: typeof globalThis.fetch;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

export async function discoverIntel(deps: DiscoverDeps): Promise<Candidate[]> {
  const out: Candidate[] = [];
  const cutoff = deps.now.getTime() - WINDOW_MS;
  for (const feed of FEEDS) {
    try {
      const r = await deps.fetch(feed, {
        headers: {
          Accept: 'application/rss+xml, application/xml, */*',
          'User-Agent': 'pranithjain.qzz.io case-study-discovery',
        },
      });
      if (!r.ok) continue;
      const xml = await r.text();
      const feedHost = new URL(feed).hostname.replace(/^www\./, '');
      for (const item of parseRssItems(xml, deps.now)) {
        if (item.date.getTime() < cutoff) continue;
        const key = topicKey('intel', item.link || item.title);
        const dedup = await deps.getDedup(key);
        const score = finalScore({
          recency: recencyScore(item.date.toISOString(), deps.now),
          severity: severityFromText(item.title),
          novelty: noveltyScore(dedup, deps.now),
          sourceWeight: 0.6,
        });
        out.push({
          key,
          type: 'intel',
          title: item.title,
          rationale: `CTI research · ${feedHost} · ${item.date.toISOString().slice(0, 10)}`,
          score,
          evidence: { url: item.link, published: item.date.toISOString(), source: feed },
          discoveredAt: deps.now.toISOString(),
          status: 'pending',
        });
      }
    } catch {}
  }
  return out;
}
