import { createRssRunner, type RssRunnerDeps } from './rss-util';

export type DiscoverDeps = RssRunnerDeps;

/** Methodology/thought-leadership content is more evergreen than
 *  breaking news — use a 14-day window so slower-publishing sources
 *  (SANS, Mandiant deep-dives) don't get systematically excluded. */
// CTI vendor research feeds. Every URL re-verified 2026-10-18 from
// server-side egress; the dead ones (SANS, Cybereason -> LevelBlue,
// Security Boulevard 403, Digital Shadows gone, Trellix unreachable,
// Mandiant moved to Google Cloud) were replaced with live research feeds
// rather than left to burn a subrequest per run.
const FEEDS = [
  'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
  'https://www.crowdstrike.com/blog/feed/',
  'https://www.recordedfuture.com/feed',
  'https://www.sentinelone.com/blog/feed/',
  'https://blogs.cisco.com/security/feed',
  'https://www.socradar.io/feed/',
  'https://www.withsecure.com/feed',
  'https://blog.virustotal.com/feeds/posts/default',
  'https://www.rapid7.com/blog/rss/',
  'https://specterops.io/feed/',
  'https://labs.watchtowr.com/feed/',
  'https://blog.thinkst.com/feed/',
  // Additions from the 2026-10-18 probe — vendor research feeds that were
  // live and not already covered by another runner.
  'https://blog.qualys.com/feed',
  'https://www.tenable.com/blog/feed',
  'https://blog.cloudflare.com/rss/',
  'https://www.elastic.co/security-labs/rss/feed.xml',
];

export const discoverMethodology = createRssRunner({
  type: 'methodology',
  feeds: FEEDS,
  windowMs: 14 * 24 * 3600 * 1000,
  sourceWeight: 0.6,
  rationaleLabel: 'CTI methodology',
  runnerName: 'discoverMethodology',
});
