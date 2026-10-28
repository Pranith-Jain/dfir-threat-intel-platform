import type { Candidate, DedupRecord } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityFromText, noveltyScore, finalScore } from '../scoring';
import { parseRssItems } from './rss-util';

/**
 * Public consumer-fraud / scam alert feeds (no key). Broadened 2026-05-18
 * from 2 → 5: a 2-feed pool surfaced the same items every run. Added feeds
 * are aggregator-proven URLs from src/data/rssFeeds.ts.
 */
const FEEDS = [
  'https://krebsonsecurity.com/feed/',
  'https://www.ic3.gov/PSA/RSS',
  'https://hackread.com/feed/',
  // BleepingComputer 403s datacenter egress — Bing News mirror instead (news.google.com 503s Worker egress).
  'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
  'https://feeds.feedburner.com/TheHackersNews',
];
const WINDOW_MS = 7 * 24 * 3600 * 1000;

export interface DiscoverDeps {
  fetch: typeof globalThis.fetch;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

export async function discoverScams(deps: DiscoverDeps): Promise<Candidate[]> {
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
      for (const item of parseRssItems(xml, deps.now)) {
        if (item.date.getTime() < cutoff) continue;
        const key = topicKey('scam', item.link || item.title);
        const dedup = await deps.getDedup(key);
        const score = finalScore({
          recency: recencyScore(item.date.toISOString(), deps.now),
          severity: severityFromText(item.title),
          novelty: noveltyScore(dedup, deps.now),
          sourceWeight: 0.7,
        });
        out.push({
          key,
          type: 'scam',
          title: item.title,
          rationale: `Consumer-fraud alert · ${item.date.toISOString().slice(0, 10)}`,
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
