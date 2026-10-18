import { createRssRunner, type RssRunnerDeps } from './rss-util';

export type DiscoverDeps = RssRunnerDeps;

// OSINT tradecraft feeds. Re-verified 2026-10-18: the OSINT Curious project
// ended (feed 404), the Medium @osint-blog custom feed 404s, sector035,
// osint.team and osintbureau are unreachable/have no feed — all removed.
// Three URLs moved and were updated in place.
const FEEDS = [
  'https://www.bellingcat.com/feed/',
  'https://osintteam.blog/feed',
  'https://nixintel.info/feed/',
  'https://hatless1der.com/feed/',
  'https://inteltechniques.com/blog/rss.xml',
  'https://www.secjuice.com/feed/',
  'https://blog.haschek.at/rss.xml',
  'https://www.alec.fyi/feed/',
  'https://blog.blacklanternsecurity.com/feed/',
  'https://webbreacher.com/feed/',
];

export const discoverOsint = createRssRunner({
  type: 'osint',
  feeds: FEEDS,
  windowMs: 7 * 24 * 3600 * 1000,
  sourceWeight: 0.6,
  rationaleLabel: 'OSINT tradecraft',
  runnerName: 'discoverOsint',
});
