// Vendor threat-intel RSS feeds scanned for actor mentions.
// These are public feeds — no auth required.
// Feed health re-verified 2026-10-18 against server-side egress. Dead URLs
// (404, redirect-to-HTML, or long-frozen feeds) are removed rather than left
// in: each one costs a subrequest per run and silently contributes nothing.
export const ACTOR_RSS_FEEDS: string[] = [
  // Mandiant's blog now publishes on Google Cloud's threat-intelligence feed
  // (the old mandiant.com/resources feed redirects to an HTML page).
  'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
  'https://www.crowdstrike.com/blog/feed/',
  'https://www.microsoft.com/en-us/security/blog/feed/',
  'https://blog.talosintelligence.com/feed/',
  // Broadened 2026-05-19: more actor/APT research surface so the `actor`
  // topic has a deeper, more varied candidate pool. All aggregator-proven
  // free feeds (mirror src/data/rssFeeds.ts).
  'https://unit42.paloaltonetworks.com/feed/',
  'https://securelist.com/feed/',
  'https://www.welivesecurity.com/feed/',
  'https://www.sentinelone.com/labs/feed/',
  'https://redcanary.com/feed/',
  'https://thedfirreport.com/feed/',
];

// Government / regional advisory + state-actor research feeds. Distinct from
// ACTOR_RSS_FEEDS and intel.ts FEEDS — added 2026-06-04 for source diversity
// (OT/ICS, EU/UK/APAC, state-actor). All public RSS, no auth.
// NOTE: verify each resolves + parses on first ingest (set a real UA — CISA
// 403s default bot UAs). Providers silently rot; confirm against live output.
export const ADVISORY_RSS_FEEDS: string[] = [
  'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
  // Google TAG publishes through Cloudblog's threat-intelligence feed; the
  // old blog.google/threat-analysis-group/rss/ path is 404.
  'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
  'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
  'https://asec.ahnlab.com/en/feed/',
  'https://blogs.jpcert.or.jp/en/atom.xml',
];

// SITE_URL is now dynamically resolved via getSiteUrl(env) from site-config.
// Import site-config where env context is available and call getSiteUrl(env).
