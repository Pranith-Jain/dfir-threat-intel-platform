/**
 * Cyber fraud + cyber crime live-feed sources for /threatintel/cyber-crime.
 *
 * Distinct from /threatintel/writeups (CTI research articles) — this page
 * surfaces news of incidents themselves: indictments, takedowns, fraud
 * schemes, crypto crime, ransomware arrests, sanctions, etc.
 *
 * Each source has an optional `filterKeywords` array. When present, an
 * item is only kept if its title or description contains at least one of
 * the keywords (case-insensitive). DOJ press releases especially need
 * filtering — the feed mixes drug trafficking, immigration, and weapons
 * cases. Sources whose feeds are 100% cyber-relevant (Krebs, Elliptic,
 * Chainalysis, BankInfoSecurity Fraud) skip filtering entirely.
 */

export interface CybercrimeSource {
  url: string;
  label: string;
  /** Optional broad category badge for UI grouping. */
  category: 'law-enforcement' | 'crypto-crime' | 'news' | 'breaches' | 'fraud-research' | 'underground-forums';
  /** When set, an item is only kept if title|description matches one. */
  filterKeywords?: string[];
}

// Hot-list of cyber-relevant words. DOJ items typically reference one or
// more of these in the title or first paragraph when the case actually
// involves cyber/crypto/online fraud.
const CYBER_KEYWORDS = [
  'cyber',
  'cyberattack',
  'crypto',
  'cryptocurrency',
  'bitcoin',
  'ethereum',
  'wallet',
  'blockchain',
  'ransomware',
  'phishing',
  'phish',
  'malware',
  'hack',
  'hacker',
  'hacking',
  'breach',
  'data leak',
  'darkweb',
  'darknet',
  'online fraud',
  'wire fraud',
  'business email',
  'bec',
  'romance scam',
  'investment scam',
  'sim swap',
  'identity theft',
  'pig butchering',
  'money laundering',
  'sanctions',
  'ofac',
  'tornado cash',
  'lazarus',
  'fbi cyber',
  'doj cyber',
  'computer intrusion',
];

export const CYBERCRIME_SOURCES: CybercrimeSource[] = [
  // Law enforcement — DOJ surfaces indictments, takedowns, plea deals
  {
    url: 'https://www.justice.gov/news/rss?type=press_release',
    label: 'US DOJ',
    category: 'law-enforcement',
    filterKeywords: CYBER_KEYWORDS,
  },
  // CISA news covers federal cyber alerts + advisories
  {
    url: 'https://www.cisa.gov/news.xml',
    label: 'CISA',
    category: 'law-enforcement',
  },
  // Crypto crime specialists — no filter needed; the whole feed is on-topic
  {
    url: 'https://www.chainalysis.com/blog/rss/',
    label: 'Chainalysis',
    category: 'crypto-crime',
  },
  // Elliptic dropped its RSS feed (site reorganised to /insights/, no feed
  // link exposed) — removed 2026-10-17. Re-add if/when they publish a feed.
  // Krebs on Security — fraud investigations, BEC, identity theft. ~100%
  // cyber-relevant so we skip filtering.
  {
    url: 'https://krebsonsecurity.com/feed/',
    label: 'Krebs on Security',
    category: 'fraud-research',
  },
  // The Record — broad cybersecurity news, lots of crime coverage.
  // Filter to avoid generic CVE/vendor coverage.
  {
    url: 'https://therecord.media/feed',
    label: 'The Record',
    category: 'news',
    filterKeywords: CYBER_KEYWORDS,
  },
  // BleepingComputer — high-volume breaking news. Filter to crime/fraud only.
  // URL is the Bing News mirror: bleepingcomputer.com 403s datacenter egress and news.google.com rate-limits Worker egress.
  {
    url: 'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
    label: 'BleepingComputer',
    category: 'news',
    filterKeywords: CYBER_KEYWORDS,
  },
  // DataBreaches.net — breach disclosures + cybercrime reporting.
  {
    url: 'https://www.databreaches.net/feed/',
    label: 'DataBreaches.net',
    category: 'breaches',
  },
  // HackRead — broad news with fraud/crime coverage. Filter applied because
  // the broad feed mixes in product reviews and general tech.
  {
    url: 'https://hackread.com/feed/',
    label: 'HackRead',
    category: 'news',
    filterKeywords: CYBER_KEYWORDS,
  },
];
