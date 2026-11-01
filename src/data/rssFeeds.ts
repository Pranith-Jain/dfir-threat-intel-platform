export interface RSSFeed {
  id: string;
  name: string;
  url: string;
  description: string;
  category: 'vulnerability' | 'advisory' | 'threat-intel' | 'news' | 'general' | 'ics-cert' | 'tech';
  icon?: string;
  source?: string;
  language?: string;
}

export const rssFeeds: RSSFeed[] = [
  // ============================================================================
  // GOVERNMENT & SECURITY ADVISORIES
  // ============================================================================
  {
    id: 'cisa-alerts',
    name: 'CISA Alerts',
    url: 'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml',
    description: 'US-CERT Current Activity - Latest cybersecurity alerts and advisories',
    category: 'advisory',
    source: 'CISA',
    language: 'en-US',
  },
  {
    id: 'cisa-medical-advisories',
    name: 'CISA Medical Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml',
    description: 'Healthcare and medical device cybersecurity advisories',
    category: 'advisory',
    source: 'CISA',
    language: 'en-US',
  },
  {
    id: 'ccb-news',
    name: 'CCB Belgium - News',
    url: 'https://ccb.belgium.be/news.xml',
    description:
      'Centre for Cybersecurity Belgium - official news, NIS2 updates, national cyber resilience announcements',
    category: 'advisory',
    source: 'ccb.belgium.be',
    language: 'en',
  },
  {
    id: 'ccb-advisories',
    name: 'CCB Belgium - Advisories',
    url: 'https://ccb.belgium.be/advisories.xml',
    description: 'Centre for Cybersecurity Belgium - security advisories, vulnerability warnings, patch notifications',
    category: 'advisory',
    source: 'ccb.belgium.be',
    language: 'en',
  },

  // ============================================================================
  // THREAT INTELLIGENCE
  // ============================================================================

  // Vendor research feeds (probed and confirmed returning XML)
  {
    id: 'talos',
    name: 'Cisco Talos Intelligence',
    url: 'https://blog.talosintelligence.com/rss/',
    description: 'Threat research from Cisco Talos - daily IOCs, malware analysis, campaign tracking',
    category: 'threat-intel',
    source: 'talosintelligence.com',
    language: 'en',
  },
  {
    id: 'unit42',
    name: 'Unit 42 (Palo Alto)',
    url: 'https://unit42.paloaltonetworks.com/feed/',
    description: 'Active campaign tracking and malware analysis',
    category: 'threat-intel',
    source: 'unit42.paloaltonetworks.com',
    language: 'en',
  },
  {
    id: 'trail-of-bits',
    name: 'Trail of Bits Blog',
    url: 'https://blog.trailofbits.com/feed/',
    description:
      'Security research, audit write-ups and Patch the Planet disclosures from the Trail of Bits / OpenAI Daybreak open-source security programme.',
    category: 'threat-intel',
    source: 'blog.trailofbits.com',
    language: 'en',
  },
  {
    id: 'cisa-ics-advisories',
    name: 'CISA ICS Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
    description:
      'Industrial Control Systems / OT security advisories from CISA (affected products, mitigations, exploitability).',
    category: 'ics-cert',
    source: 'cisa.gov',
    language: 'en',
  },
  {
    id: 'wiz-cloud-threats',
    name: 'Wiz Cloud Threat Landscape',
    url: 'https://www.wiz.io/feed/cloud-threats-landscape/rss.xml',
    description:
      'Cloud / SaaS / identity threat incidents tracked by Wiz Research. Change-detection signal; full structured data on the Cloud incidents page.',
    category: 'threat-intel',
    source: 'wiz.io',
    language: 'en',
  },
  {
    id: 'eset',
    name: 'ESET WeLiveSecurity',
    url: 'https://www.welivesecurity.com/en/rss/feed/',
    description: 'European-focused threat research, esp. Russia/Ukraine cyber operations',
    category: 'threat-intel',
    source: 'welivesecurity.com',
    language: 'en',
  },
  {
    id: 'kaspersky-securelist',
    name: 'Kaspersky SecureList',
    url: 'https://securelist.com/feed/',
    description: 'Long-tail threat and malware research from Kaspersky GReAT',
    category: 'threat-intel',
    source: 'securelist.com',
    language: 'en',
  },
  {
    id: 'crowdstrike',
    name: 'CrowdStrike Blog',
    url: 'https://www.crowdstrike.com/en-us/blog/feed',
    description: 'Endpoint-driven adversary intelligence and incident reports',
    category: 'threat-intel',
    source: 'crowdstrike.com',
    language: 'en',
  },
  {
    id: 'sentinelone-labs',
    name: 'SentinelOne Labs',
    url: 'https://www.sentinelone.com/labs/feed/',
    description: 'Malware reverse engineering and threat hunting',
    category: 'threat-intel',
    source: 'sentinelone.com',
    language: 'en',
  },
  {
    id: 'mandiant',
    name: 'Google Security Blog',
    // Was feeds.feedburner.com/GoogleOnlineSecurityBlog — FeedBurner, which
    // Google deprecated: it still answers 200 but stopped re-syncing
    // (newest item Apr 2026 while the blog published that week). Canonical
    // Blogger feed, verified 2026-10 with fresh items.
    url: 'https://security.googleblog.com/feeds/posts/default?alt=rss',
    description:
      'Google online security research - APT analysis, vulnerability disclosures, and platform threat intelligence from Google + Mandiant.',
    category: 'threat-intel',
    source: 'Google Security Blog',
    language: 'en',
  },
  {
    id: 'microsoft-security',
    name: 'Microsoft Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    description: 'Microsoft Threat Intelligence, Defender research, and cloud security advisories',
    category: 'threat-intel',
    source: 'microsoft.com',
    language: 'en',
  },
  {
    id: 'sophos-news',
    name: 'Sophos News',
    url: 'https://www.sophos.com/en-us/blog/feed/',
    description: 'Sophos X-Ops threat research, malware analysis, and defensive guidance',
    category: 'threat-intel',
    source: 'sophos.com',
    language: 'en',
  },
  {
    id: 'trendmicro-research',
    name: 'Trend Micro Research',
    url: 'https://feeds.feedburner.com/TrendMicroResearch',
    description: 'Trend Micro Zero Day Initiative, APT research, and vulnerability analysis',
    category: 'threat-intel',
    source: 'trendmicro.com',
    language: 'en',
  },
  {
    id: 'withsecure-labs',
    name: 'WithSecure Labs',
    url: 'https://www.withsecure.com/rss/',
    description: 'WithSecure (F-Secure) threat research, adversary tradecraft, and detection engineering',
    category: 'threat-intel',
    source: 'withsecure.com',
    language: 'en',
  },
  {
    id: 'aws-security',
    name: 'AWS Security Blog',
    url: 'https://aws.amazon.com/blogs/security/feed/',
    description: 'AWS threat research, cloud security best practices, and incident response',
    category: 'threat-intel',
    source: 'aws.amazon.com',
    language: 'en',
  },

  // Hudson Rock / InfoStealers.com
  {
    id: 'infostealers-com',
    name: 'InfoStealers.com (Hudson Rock)',
    url: 'https://www.infostealers.com/learn-info-stealers/feed/',
    description:
      'Infostealer research, campaign tracking, and weekly reports from the Hudson Rock cybercrime intelligence team - RedLine, Lumma, Vidar, StealC, and emerging stealer families.',
    category: 'threat-intel',
    source: 'infostealers.com',
    language: 'en',
  },
  {
    id: 'infostealers-com-all',
    name: 'InfoStealers.com - All Content',
    url: 'https://www.infostealers.com/feed/',
    description: 'All infostealers.com content - blog, reports, and techniques combined feed.',
    category: 'threat-intel',
    source: 'infostealers.com',
    language: 'en',
  },
  {
    id: 'infostealers-reports',
    name: 'InfoStealers.com - Weekly Reports',
    url: 'https://www.infostealers.com/info-stealers-reports/feed/',
    description:
      'Infostealers weekly threat reports from Hudson Rock - compromised machine counts, top domains, trending families.',
    category: 'threat-intel',
    source: 'infostealers.com',
    language: 'en',
  },
  {
    id: 'infostealers-techniques',
    name: 'InfoStealers.com - Techniques',
    // Dormant upstream: the category feed's newest entry is Sep 2023 while
    // the main + reports feeds publish weekly. Kept (technique profiles are
    // still useful reference material and the /feeds/techniques path may be
    // revived), but audit-rss-catalog.mjs lists it in LOW_FREQUENCY so the
    // staleness check reports it instead of failing CI every run.
    url: 'https://www.infostealers.com/info-stealers-techniques/feed/',
    description: 'Infostealer technique profiles from Hudson Rock - Formbook, LummaC2, Aurora, and other stealer TTPs.',
    category: 'threat-intel',
    source: 'infostealers.com',
    language: 'en',
  },

  // Dark web, ransomware, and breach trackers
  {
    id: 'darkwebinformer',
    name: 'Dark Web Informer',
    url: 'https://darkwebinformer.com/rss/',
    description: 'Daily dark web intelligence, ransomware leak-site posts, breach reports, and underground chatter',
    category: 'threat-intel',
    source: 'darkwebinformer.com',
    language: 'en',
  },
  {
    id: 'daily-dark-web',
    name: 'Daily Dark Web',
    url: 'https://dailydarkweb.net/feed/',
    description:
      'Daily dark web reporting - new markets, leak-site posts, threat actor forums, and underground service listings',
    category: 'threat-intel',
    source: 'dailydarkweb.net',
    language: 'en',
  },
  {
    id: 'emsisoft-blog',
    name: 'Emsisoft Blog',
    url: 'https://www.emsisoft.com/en/blog/feed/',
    description: 'Ransomware response research, extortion group data analysis, and decryption guidance from Emsisoft',
    category: 'threat-intel',
    source: 'emsisoft.com',
    language: 'en',
  },
  {
    id: 'hunters-ledger',
    name: "The Hunter's Ledger",
    url: 'https://the-hunters-ledger.com/feed.xml',
    description:
      'Original threat intelligence research - malware analysis, open-directory investigations, IOC feeds, and hunting detections',
    category: 'threat-intel',
    source: 'the-hunters-ledger.com',
    language: 'en',
  },
  {
    id: 'fbi-ic3',
    name: 'FBI IC3 Advisories',
    url: 'https://www.ic3.gov/CSA/RSS',
    description: 'FBI Internet Crime Complaint Center - cyber security advisories, alerts, and wanted notices',
    category: 'advisory',
    source: 'ic3.gov',
    language: 'en-US',
  },
  {
    id: 'ransomware-live',
    name: 'Ransomware.live',
    url: 'https://ransomware.live/rss.xml',
    description: 'Active ransomware victim and leak-site tracker, updated continuously',
    category: 'threat-intel',
    source: 'ransomware.live',
    language: 'en',
  },
  // databreachtoday.com RSS endpoint 404s as of 2026-05. Replaced with Threatpost.
  {
    id: 'bleepingcomputer-breaches',
    name: 'BleepingComputer · Data Breaches',
    url: 'https://www.bleepingcomputer.com/feed/',
    description:
      'BleepingComputer breach coverage via main feed - renamed 2026-05; was a separate category feed that now 404s',
    category: 'threat-intel',
    source: 'bleepingcomputer.com',
    language: 'en-US',
  },
  {
    id: 'hackread-breaches',
    name: 'HackRead · Data Breaches',
    url: 'https://hackread.com/feed/',
    description: 'HackRead breach reporting - covers global incidents with notable focus on India + emerging markets',
    category: 'threat-intel',
    source: 'hackread.com',
    language: 'en',
  },
  {
    id: 'securityweek-breaches',
    name: 'SecurityWeek · Cyber Incidents',
    url: 'https://www.securityweek.com/feed/',
    description: 'SecurityWeek cybercrime category - enterprise breach incident reporting + regulator notices',
    category: 'threat-intel',
    source: 'securityweek.com',
    language: 'en',
  },
  {
    id: 'cyberscoop-breaches',
    name: 'CyberScoop',
    url: 'https://cyberscoop.com/feed/',
    description: 'CyberScoop - US government + enterprise cyber incident coverage, breaches, indictments',
    category: 'threat-intel',
    source: 'cyberscoop.com',
    language: 'en',
  },
  {
    id: 'databreaches',
    name: 'DataBreaches.net',
    url: 'https://databreaches.net/feed/',
    description:
      'Breach reporting and analysis from Dissent. Wide coverage of healthcare, education, and government incidents',
    category: 'threat-intel',
    source: 'databreaches.net',
    language: 'en',
  },
  {
    id: 'dfir-report',
    name: 'The DFIR Report',
    url: 'https://thedfirreport.com/feed/',
    description: 'In-depth incident response writeups with full IOC and TTP detail',
    category: 'threat-intel',
    source: 'thedfirreport.com',
    language: 'en',
  },
  {
    id: 'the-record',
    name: 'The Record',
    url: 'https://therecord.media/feed',
    description: 'Cybersecurity reporting from Recorded Future, with strong dark web and ransomware coverage',
    category: 'threat-intel',
    source: 'therecord.media',
    language: 'en',
  },

  // Reddit communities (RSS via .rss suffix)

  // Vendor labs and research teams (curated from awesome-threat-intel-rss and cudeso/OPML-Security-Feeds)
  {
    id: 'google-project-zero',
    name: 'Google Project Zero',
    url: 'https://projectzero.google/feed.xml',
    description: 'Zero-day vulnerability research from the Google Project Zero team',
    category: 'threat-intel',
    source: 'googleprojectzero.blogspot.com',
    language: 'en',
  },
  {
    id: 'checkpoint-research',
    name: 'Check Point Research',
    url: 'https://research.checkpoint.com/feed/',
    description: 'Malware reverse engineering and active campaign tracking from Check Point',
    category: 'threat-intel',
    source: 'research.checkpoint.com',
    language: 'en',
  },
  // sophos-xops RSS endpoint times out as of 2026-05.
  // Akamai Security Research blog RSS (/blog/rss/security-research.rss)
  // 404s as of 2026-05-24 - removed too.
  {
    id: 'malwarebytes-labs',
    name: 'Malwarebytes Labs',
    url: 'https://www.malwarebytes.com/blog/feed/index.xml',
    description: 'Consumer and enterprise malware research from Malwarebytes Labs',
    category: 'threat-intel',
    source: 'malwarebytes.com',
    language: 'en',
  },
  {
    id: 'huntress',
    name: 'Huntress Blog',
    url: 'https://www.huntress.com/blog/rss.xml',
    description: 'Detection content and incident reports from the Huntress threat ops team',
    category: 'threat-intel',
    source: 'huntress.com',
    language: 'en',
  },
  {
    id: 'red-canary',
    name: 'Red Canary',
    url: 'https://redcanary.com/feed/',
    description: 'Detection engineering and threat intel from the Red Canary team',
    category: 'threat-intel',
    source: 'redcanary.com',
    language: 'en',
  },
  {
    id: 'malware-traffic-analysis',
    name: 'Malware Traffic Analysis',
    url: 'https://www.malware-traffic-analysis.net/blog-entries.rss',
    description: "Brad Duncan's daily PCAPs, IOCs, and malware samples. One of the highest-signal IOC feeds online",
    category: 'threat-intel',
    source: 'malware-traffic-analysis.net',
    language: 'en',
  },
  {
    id: 'mitre-attack-medium',
    name: 'MITRE ATT&CK',
    url: 'https://medium.com/feed/mitre-attack',
    description: 'Official updates from the MITRE ATT&CK team on framework changes and threat groups',
    category: 'threat-intel',
    source: 'medium.com/mitre-attack',
    language: 'en',
  },
  {
    id: 'offsec-blog',
    name: 'OffSec Blog',
    url: 'https://www.offsec.com/rss.xml',
    description: 'OffSec research blog - exploitation techniques, red-team tradecraft, and offensive tooling research',
    category: 'threat-intel',
    source: 'offsec.com',
    language: 'en',
  },

  {
    id: 'dfir-lab',
    name: 'DFIR Lab',
    url: 'https://dfir-lab.ch/feed.xml',
    description: 'Digital forensics and incident response research, threat analysis, and case studies',
    category: 'threat-intel',
    source: 'DFIR Lab',
    language: 'en-US',
  },
  {
    id: 'dfir-radar',
    name: 'DFIR Radar',
    url: 'https://falhumaid.github.io/DFIR_Radar_RSS/rss.xml',
    description: 'Security advisories and threat intelligence from the DFIR Radar project',
    category: 'threat-intel',
    source: 'DFIR Radar',
    language: 'en-US',
  },
  {
    id: 'dfir-diva',
    name: 'DFIR Diva',
    url: 'https://dfirdiva.com/feed/',
    description: 'Long-running curated DFIR index - tools, training, datasets, and community resources',
    category: 'threat-intel',
    source: 'dfirdiva.com',
    language: 'en',
  },
  {
    id: 'invictus-ir',
    name: 'Invictus IR',
    url: 'https://www.invictus-ir.com/news/rss.xml',
    description: 'Intelligence-led incident response writeups, IR case notes, and adversary infrastructure analysis',
    category: 'threat-intel',
    source: 'invictus-ir.com',
    language: 'en',
  },
  {
    id: 'sans-isc',
    name: 'SANS Internet Storm Center',
    url: 'https://isc.sans.edu/rssfeed.xml',
    description: 'Daily handler diaries and security threat intelligence',
    category: 'threat-intel',
    source: 'SANS',
    language: 'en-US',
  },
  // ============================================================================
  // SECURITY NEWS
  // ============================================================================
  {
    id: 'krebsonsecurity',
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    description: 'In-depth security journalism by Brian Krebs',
    category: 'news',
    source: 'Krebs on Security',
    language: 'en-US',
  },
  {
    id: 'hackernews',
    name: 'The Hacker News',
    // FeedBurner deprecated by Google - switched to direct RSS.
    url: 'https://thehackernews.com/rss.xml',
    description: 'Latest cybersecurity news, exploits, and vulnerabilities',
    category: 'news',
    source: 'The Hacker News',
    language: 'en-US',
  },
  {
    id: 'bleepingcomputer',
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    description: 'Computer security news, tutorials, and how-to guides',
    category: 'news',
    source: 'BleepingComputer',
    language: 'en-US',
  },
  {
    id: 'securityweek',
    name: 'SecurityWeek',
    url: 'https://www.securityweek.com/feed/',
    description: 'Cybersecurity news, analysis, and enterprise security insights',
    category: 'news',
    source: 'SecurityWeek',
    language: 'en-US',
  },
  {
    id: 'schneier',
    name: 'Schneier on Security',
    url: 'https://www.schneier.com/feed/atom/',
    description: "Bruce Schneier's security blog and essays",
    category: 'general',
    source: 'Schneier',
    language: 'en-US',
  },
  {
    id: 'wired-security',
    name: 'Wired Security',
    // Wired restructured their feed paths - removed /latest/ from the path.
    url: 'https://www.wired.com/feed/category/security/rss',
    description: 'Security news and features from Wired',
    category: 'news',
    source: 'Wired',
    language: 'en-US',
  },
  {
    id: 'theregister-security',
    name: 'The Register - Security',
    url: 'https://api.theregister.com/api/v1/article?orderBy=published&site_id=2&remapper=rss&query=tag:security',
    description: 'Biting the hand that feeds IT - Security news',
    category: 'news',
    source: 'The Register',
    language: 'en-GB',
  },
  {
    id: 'helpnetsecurity',
    name: 'Help Net Security',
    url: 'https://www.bing.com/news/search?q=site%3Ahelpnetsecurity.com&format=RSS&mkt=en-US',
    description:
      'Computer security news and cybersecurity insights, served via a Bing News site-scoped mirror - helpnetsecurity.com itself returns an empty body to datacenter egress',
    category: 'news',
    source: 'Help Net Security',
    language: 'en-US',
  },
  {
    id: 'csoconline',
    name: 'CSO Online',
    url: 'https://www.csoonline.com/feed/',
    description: 'Security and risk management leadership news',
    category: 'news',
    source: 'CSO Online',
    language: 'en-US',
  },

  // ============================================================================
  // HACKER NEWS / Y COMBINATOR (AI / Tech / Cybersecurity)
  // ============================================================================
  {
    id: 'hn-frontpage',
    name: 'Hacker News',
    url: 'https://hnrss.org/frontpage',
    description: 'Hacker News front page - top tech, AI, and security stories',
    category: 'tech',
    source: 'Hacker News',
    language: 'en-US',
  },
  {
    id: 'hn-ask',
    name: 'Ask HN',
    url: 'https://hnrss.org/ask',
    description: 'Ask Hacker News - questions and discussions from the community',
    category: 'tech',
    source: 'Hacker News',
    language: 'en-US',
  },
  {
    id: 'hn-show',
    name: 'Show HN',
    url: 'https://hnrss.org/show',
    description: 'Show Hacker News - new projects, products, and demos',
    category: 'tech',
    source: 'Hacker News',
    language: 'en-US',
  },
  // hnrss.org rate-limits worker egress as of 2026-05. Replaced with Recorded Future blog.
  {
    id: 'recorded-future',
    name: 'Recorded Future Blog',
    url: 'https://www.recordedfuture.com/feed',
    description: 'Recorded Future threat research - threat intel, APT tracking, and strategic analysis',
    category: 'threat-intel',
    source: 'recordedfuture.com',
    language: 'en-US',
  },
  // The Cyber Wire feed (thecyberwire.com/feed.xml) → 404 as of 2026-06 after the
  // N2K migration; no stable public RSS replacement. Removed.
  {
    id: 'yc-blog',
    name: 'Y Combinator Blog',
    url: 'https://www.ycombinator.com/blog/rss',
    description: 'Y Combinator blog - startup essays, announcements, and YC news',
    category: 'tech',
    source: 'Y Combinator',
    language: 'en-US',
  },

  // OSV.dev RSS (osv.dev/feed/rss.xml) → 404 as of 2026-05-24; the
  // ecosystem-specific GHSA atom feeds (github.com/advisories.atom) →
  // 406 even with proper Accept headers. Both removed; npm/PyPI IOC
  // surfaces will be wired through /api/v1/osv/scan + the live-iocs
  // feed pipeline instead, not generic RSS aggregation.
  // ============================================================================
  // VULNERABILITIES & EXPLOITS
  // ============================================================================
  // CVE Details (cvedetails.com) was removed in 2026-05: their /rss.xml endpoint
  // has been Cloudflare-bot-protected and returns 403 to non-browser User-Agents
  // even via the worker proxy. The /dfir/cve page (NVD-backed) covers the same
  // workflow more authoritatively. The cvedetails.com landing page remains
  // listed in /threatintel/cve-resources as an external-link reference.
  {
    id: 'exploitdb',
    name: 'Exploit-DB',
    url: 'https://www.exploit-db.com/rss.xml',
    description: 'The Exploit Database - latest exploits and vulnerabilities',
    category: 'vulnerability',
    source: 'Offensive Security',
    language: 'en-US',
  },

  // ============================================================================
  // MALWARE ANALYSIS & SANDBOX
  // ============================================================================

  // ============================================================================
  // GENERAL SECURITY
  // ============================================================================
  // Reddit communities. Reddit aggressively rate-limits Cloudflare Worker egress
  // for the most popular subs (r/cybersecurity, r/ransomware return 502); the four
  // listed below have been verified to return parseable Atom from the proxy.

  // ============================================================================
  // SCAM WATCH SOURCES - official alerts, deepfake news, victim reports
  // ============================================================================
  {
    id: 'ftc-consumer',
    name: 'FTC Consumer Alerts',
    url: 'https://consumer.ftc.gov/blog/rss',
    description: 'Federal Trade Commission consumer-protection blog - scam alerts and emerging fraud trends',
    category: 'advisory',
    source: 'FTC',
    language: 'en-US',
  },
  {
    id: 'ic3-psas',
    name: 'FBI IC3 Public Service Announcements',
    url: 'https://www.ic3.gov/CSA/RSS',
    description: 'FBI Internet Crime Complaint Center PSAs - active fraud schemes, BEC, romance + tech-support scams',
    category: 'advisory',
    source: 'FBI IC3',
    language: 'en-US',
  },
  {
    id: 'snopes',
    name: 'Snopes',
    url: 'https://www.snopes.com/feed/',
    description: 'Misinformation + scam fact-checking; routinely covers deepfake claims and viral scam stories',
    category: 'news',
    source: 'snopes.com',
    language: 'en-US',
  },
  {
    id: 'gnews-deepfake',
    name: 'Bing News - deepfake fraud',
    url: 'https://www.bing.com/news/search?q=deepfake+fraud&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Bing News search RSS for "deepfake fraud" - synthetic-media-driven fraud incidents',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-victim',
    name: 'Bing News - digital scam victims',
    url: 'https://www.bing.com/news/search?q=scam+victim&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Bing News search RSS for "scam victim" - case-by-case fraud reporting from mainstream media',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-india-scam',
    name: 'Bing News - India scams & fraud',
    url: 'https://www.bing.com/news/search?q=India+digital+arrest+scam&format=RSS&mkt=en-IN&qft=interval%3d%2230%22',
    description:
      'India-scoped Bing News for digital-arrest and cyber-fraud scam coverage (digital arrest / UPI fraud / loan-app fraud reports).',
    category: 'news',
    source: 'Bing News (IN)',
    language: 'en-IN',
  },
  {
    id: 'gnews-india-cybercrime',
    name: 'Bing News - India cybercrime & enforcement',
    url: 'https://www.bing.com/news/search?q=India+cyber+fraud+arrest&format=RSS&mkt=en-IN&qft=interval%3d%2230%22',
    description:
      'India cybercrime enforcement coverage - I4C / 1930 helpline actions, fraud-ring busts, mule-account crackdowns.',
    category: 'news',
    source: 'Bing News (IN)',
    language: 'en-IN',
  },
  {
    id: 'gnews-pig-butcher',
    name: 'Bing News - pig butchering scam',
    url: 'https://www.bing.com/news/search?q=pig+butchering+scam&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Long-con investment + crypto fraud ("sha zhu pan") news coverage',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-job-scam',
    name: 'Bing News - job / recruiter scam',
    url: 'https://www.bing.com/news/search?q=fake+recruiter+scam&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Fake-job / fake-recruiter / employment-fraud incident coverage',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-tech-support',
    name: 'Bing News - tech support scam',
    url: 'https://www.bing.com/news/search?q=tech+support+scam&format=RSS&mkt=en-US&qft=interval%3d%227%22',
    description: 'Microsoft / Apple / IRS / IT-support impersonation incident coverage',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-investment-scam',
    name: 'Bing News - investment scam',
    url: 'https://www.bing.com/news/search?q=investment+scam+fraud&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Investment / brokerage / advisory fraud coverage',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-voice-clone',
    name: 'Bing News - AI voice deepfake',
    url: 'https://www.bing.com/news/search?q=voice+clone+scam&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Voice-cloning vishing / family-emergency / kidnapping-claim incident coverage',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-sim-swap',
    name: 'Bing News - SIM swap',
    url: 'https://www.bing.com/news/search?q=SIM+swap&format=RSS&mkt=en-US&qft=interval%3d%227%22',
    description: 'SIM-swap account-takeover incidents - banking, crypto, social-media takeovers',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-rug-pull',
    name: 'Bing News - crypto rug',
    url: 'https://www.bing.com/news/search?q=crypto+rug&format=RSS&mkt=en-US&qft=interval%3d%227%22',
    description: 'Token / DeFi rug-pull incidents - exit-scam projects, drained liquidity',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-nft-drainer',
    name: 'Bing News - wallet drainer',
    url: 'https://www.bing.com/news/search?q=wallet+drainer&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Wallet-drainer kits (Inferno, Pink, Angel), NFT phishing, seed-phrase theft',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-defi-hack',
    name: 'Bing News - DeFi exploit / hack',
    url: 'https://www.bing.com/news/search?q=crypto+exploit+hack&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Smart-contract exploits, bridge drains, oracle manipulation, flash-loan attacks',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'rekt-news',
    name: 'rekt.news',
    url: 'https://rekt.news/rss/feed.xml',
    description: 'Long-form post-mortems of major DeFi exploits, rug pulls, and protocol failures',
    category: 'threat-intel',
    source: 'rekt.news',
    language: 'en',
  },
  {
    id: 'web3-grift',
    name: 'Web3 Is Going Just Great',
    url: 'https://www.web3isgoinggreat.com/feed.xml',
    description: "Molly White's running ledger of crypto scams, rug pulls, and grift incidents",
    category: 'threat-intel',
    source: 'web3isgoinggreat.com',
    language: 'en-US',
  },

  // ============================================================================
  // INDUSTRY & FUNDRAISING - security-vendor M&A, Series A-D rounds, IPO news
  // ============================================================================
  {
    id: 'techcrunch-security',
    name: 'TechCrunch - Security',
    url: 'https://techcrunch.com/category/security/feed/',
    description: 'Security-vendor funding, M&A, breaches, and product launches as covered by TechCrunch',
    category: 'tech',
    source: 'techcrunch.com',
    language: 'en-US',
  },
  {
    id: 'venturebeat-security',
    name: 'VentureBeat - Security',
    url: 'https://www.bing.com/news/search?q=site%3Aventurebeat.com+security&format=RSS&mkt=en-US',
    description:
      'Enterprise security industry coverage - funding, AI/security crossover, vendor moves, served via a Bing News site-scoped mirror (venturebeat.com 429s datacenter egress)',
    category: 'tech',
    source: 'venturebeat.com',
    language: 'en-US',
  },
  {
    id: 'gnews-cybersec-funding',
    name: 'Bing News - cybersecurity Series A funding',
    url: 'https://www.bing.com/news/search?q=cybersecurity+Series+A+funding&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Recent Series A / B / C announcements in the cybersecurity sector',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-cybersec-acquisition',
    name: 'Bing News - cybersecurity acquisition',
    url: 'https://www.bing.com/news/search?q=cybersecurity+acquisition&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'M&A activity in cybersecurity - strategic acquisitions, vendor consolidation',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-infosec-startup',
    name: 'Bing News - AI infrastructure spending',
    url: 'https://www.bing.com/news/search?q=AI+infrastructure+spending&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'AI capex, data-centre build-outs, cloud-vendor AI spend, model-training investment',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },

  // ============================================================================
  // AI - vendor blogs, AI-section tags, AI-specific Google News queries
  // ============================================================================
  {
    id: 'techcrunch-ai',
    name: 'TechCrunch - AI',
    url: 'https://techcrunch.com/category/artificial-intelligence/feed/',
    description: 'TechCrunch AI tag - model releases, AI funding, agentic-AI products, lab moves',
    category: 'tech',
    source: 'techcrunch.com',
    language: 'en-US',
  },
  {
    id: 'verge-ai',
    name: 'The Verge - AI',
    url: 'https://www.theverge.com/rss/ai-artificial-intelligence/index.xml',
    description: 'Consumer + product-side AI coverage from The Verge',
    category: 'tech',
    source: 'theverge.com',
    language: 'en-US',
  },
  {
    id: 'openai-news',
    name: 'OpenAI News',
    url: 'https://openai.com/news/rss.xml',
    description: 'Official OpenAI announcements - model releases, safety + research notes, policy',
    category: 'tech',
    source: 'openai.com',
    language: 'en-US',
  },
  {
    id: 'google-ai',
    name: 'Google AI Blog',
    url: 'https://blog.google/innovation-and-ai/technology/ai/rss/',
    description: 'Google research and product launches under the AI tag',
    category: 'tech',
    source: 'blog.google',
    language: 'en-US',
  },
  {
    id: 'gnews-ai-security',
    name: 'Bing News - AI security incident',
    url: 'https://www.bing.com/news/search?q=AI+security+incident&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Recent AI-system security incidents - prompt injection in production, agent failures, model leaks',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-ai-funding',
    name: 'Bing News - AI startup funding',
    url: 'https://www.bing.com/news/search?q=AI+startup+funding&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Funding rounds across the AI vendor / model / tooling space',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-genai-enterprise',
    name: 'Bing News - enterprise AI deployment',
    url: 'https://www.bing.com/news/search?q=enterprise+AI+deployment&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Enterprise AI rollouts - security posture, ROI claims, governance moves',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },

  {
    id: 'anthropic-blog',
    name: 'Anthropic Blog',
    // Note: www.anthropic.com/feed.xml returns 403 - Anthropic has
    // discontinued their public RSS feed. Using a community-maintained feed
    // scraped via Playwright + GitHub Actions, updated hourly.
    url: 'https://raw.githubusercontent.com/taobojlen/anthropic-rss-feed/main/anthropic_news_rss.xml',
    description: 'Anthropic official blog - Claude releases, safety research, alignment, policy positions',
    category: 'tech',
    source: 'anthropic.com',
    language: 'en-US',
  },
  {
    id: 'huggingface-blog',
    name: 'Hugging Face Blog',
    url: 'https://huggingface.co/blog/feed.xml',
    description: 'Open-source ML/AI research - model releases, datasets, papers, community highlights',
    category: 'tech',
    source: 'huggingface.co',
    language: 'en-US',
  },
  {
    id: 'deepmind-blog',
    name: 'Google DeepMind Blog',
    url: 'https://deepmind.google/blog/rss.xml',
    description: 'DeepMind research - AI breakthroughs, safety papers, scientific applications',
    category: 'tech',
    source: 'deepmind.google',
    language: 'en-US',
  },
  {
    id: 'gnews-ai-regulation',
    name: 'Bing News - AI regulation & policy',
    url: 'https://www.bing.com/news/search?q=AI+regulation+governance+policy&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'AI regulation, governance frameworks, policy developments - EU AI Act, executive orders',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-genai-adversarial',
    name: 'Bing News - GenAI security & vulnerability',
    url: 'https://www.bing.com/news/search?q=AI+LLM+jailbreak+prompt+injection&format=RSS&mkt=en-US&qft=interval%3d%227%22',
    description: 'GenAI security incidents - prompt injection, model jailbreaks, LLM vulnerabilities, AI supply-chain',
    category: 'tech',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'the-decoder',
    name: 'The Decoder',
    url: 'https://the-decoder.com/feed/',
    description: 'AI news and analysis - model releases, enterprise AI adoption, regulation, security implications',
    category: 'tech',
    source: 'the-decoder.com',
    language: 'en-US',
  },

  // ============================================================================
  // FINANCE & BANKING - cyber threats, fintech security, financial-sector incidents
  // ============================================================================
  {
    id: 'finextra',
    name: 'Finextra',
    url: 'https://www.finextra.com/rss/headlines.aspx',
    description: 'Financial technology news - banking security, payments, regtech, digital transformation in finance',
    category: 'news',
    source: 'finextra.com',
    language: 'en-US',
  },
  {
    id: 'gnews-banking-cyber',
    name: 'Bing News - banking cyber attack',
    url: 'https://www.bing.com/news/search?q=banking+cyber&format=RSS&mkt=en-US&qft=interval%3d%227%22',
    description: 'Cyber attacks and data breaches in the banking sector - retail banks, commercial banking',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-fintech-breach',
    name: 'Bing News - fintech security breach',
    url: 'https://www.bing.com/news/search?q=fintech+security+breach&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Fintech company security incidents - neobanks, payments apps, lending platforms',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-payment-security',
    name: 'Bing News - payment system security',
    url: 'https://www.bing.com/news/search?q=payment+system+security+breach&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Payment system security - card fraud, payment processor breaches, POS malware, BICS exploits',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-insurance-cyber',
    name: 'Bing News - insurance cyber attack',
    url: 'https://www.bing.com/news/search?q=insurance+cyber&format=RSS&mkt=en-US&qft=interval%3d%227%22',
    description: 'Cyber attacks on insurance companies - claims data theft, underwriting system compromises',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },
  {
    id: 'gnews-investment-cyber',
    name: 'Bing News - investment banking cyber attack',
    url: 'https://www.bing.com/news/search?q=investment+bank+cyber+attack&format=RSS&mkt=en-US&qft=interval%3d%2230%22',
    description: 'Cyber incidents at investment banks, hedge funds, asset managers, trading platforms',
    category: 'news',
    source: 'Bing News',
    language: 'en-US',
  },

  {
    id: 'payments-dive',
    name: 'Payments Dive',
    url: 'https://www.paymentsdive.com/feeds/news/',
    description: 'Payments industry news - fintech, digital payments, payment security, fraud prevention, regulatory',
    category: 'news',
    source: 'paymentsdive.com',
    language: 'en-US',
  },
  {
    id: 'banking-dive',
    name: 'Banking Dive',
    url: 'https://www.bankingdive.com/feeds/news/',
    description: 'Banking industry news - digital banking, compliance, cybersecurity, fintech partnerships',
    category: 'news',
    source: 'bankingdive.com',
    language: 'en-US',
  },

  // ============================================================================
  // General tech - broader signal beyond pure security / AI / finance
  // ============================================================================
  {
    id: 'ars-tech',
    name: 'Ars Technica - Technology Lab',
    url: 'https://feeds.arstechnica.com/arstechnica/technology-lab',
    description: 'Long-form Ars coverage of infrastructure, OS, networking, devices, and the security crossover',
    category: 'tech',
    source: 'arstechnica.com',
    language: 'en-US',
  },
  {
    id: 'mit-tech-review',
    name: 'MIT Technology Review',
    url: 'https://www.technologyreview.com/feed/',
    description: 'Independent reporting on emerging technology, AI ethics, biotech, computing',
    category: 'tech',
    source: 'technologyreview.com',
    language: 'en-US',
  },
  // ─── Breach-focused news (added 2026-05-11) ──────────────────────────
  // Sourced separately from the broader threat-intel feeds so the
  // /threatintel/breach page can pull a curated stream that's strictly
  // about disclosed breaches - not general security news.
  {
    id: 'vpnmentor-research',
    name: 'vpnMentor Research Lab',
    url: 'https://www.vpnmentor.com/feed/',
    description:
      'vpnMentor research lab - discovered and reported breaches, particularly in exposed-database / misconfigured-cloud territory',
    category: 'threat-intel',
    source: 'vpnmentor.com',
    language: 'en',
  },
  {
    id: 'grcsolutions-breaches',
    name: 'GRC Solutions · Data Breach Blog',
    url: 'https://grcsolutions.io/feed/',
    description:
      'GRC Solutions (formerly IT Governance UK) - monthly breach round-ups + analysis of high-profile data-protection incidents',
    category: 'threat-intel',
    source: 'grcsolutions.io',
    language: 'en-GB',
  },
  {
    id: 'comparitech-breaches',
    name: 'Comparitech · Privacy Research',
    url: 'https://www.comparitech.com/blog/feed/',
    description:
      'Comparitech privacy / breach research - Bob Diachenko-style exposed-database investigations and breach reporting',
    category: 'threat-intel',
    source: 'comparitech.com',
    language: 'en',
  },
  {
    id: 'troyhunt-blog',
    name: 'Troy Hunt · HIBP blog',
    url: 'https://www.troyhunt.com/rss/',
    description:
      "Troy Hunt's personal blog - write-ups of every Have I Been Pwned acquisition, plus deep dives on credential-stuffing, breach pricing, and the post-leak data-broker ecosystem.",
    category: 'threat-intel',
    source: 'troyhunt.com',
    language: 'en',
  },
  {
    id: 'grahamcluley',
    name: 'Graham Cluley',
    url: 'https://grahamcluley.com/feed/',
    description: 'Graham Cluley - independent security blog covering data breaches, malware, and cybercrime.',
    category: 'threat-intel',
    source: 'grahamcluley.com',
    language: 'en',
  },
  {
    id: 'malwaretech',
    name: 'MalwareTech Blog',
    url: 'https://www.malwaretech.com/feed',
    description:
      'MalwareTech (Marcus Hutchins) - malware analysis, reverse engineering, and threat research from the person who stopped WannaCry.',
    category: 'threat-intel',
    source: 'malwaretech.com',
    language: 'en',
  },
  {
    id: 'hexacorn',
    name: 'Hexacorn',
    url: 'https://www.hexacorn.com/blog/feed/',
    description:
      'Hexacorn - deep-dive reverse engineering, rootkit analysis, and creative security research by Amr Thabet.',
    category: 'threat-intel',
    source: 'hexacorn.com',
    language: 'en',
  },
  {
    id: 'objective-see',
    name: 'Objective-See',
    url: 'https://objective-see.org/rss.xml',
    description:
      'Objective-See (Patrick Wardle) - macOS/iOS threat research, Apple security vulnerabilities, and malware analysis.',
    category: 'threat-intel',
    source: 'objective-see.org',
    language: 'en',
  },
  {
    id: 'elasticsecurity',
    name: 'Elastic Security Labs',
    url: 'https://www.elastic.co/security-labs/rss/feed.xml',
    description: 'Elastic Security Labs - threat research, detection rules, and adversary tradecraft analysis.',
    category: 'threat-intel',
    source: 'elastic.co',
    language: 'en',
  },
  {
    id: 'datadog-security',
    name: 'Datadog Security Labs',
    url: 'https://securitylabs.datadoghq.com/rss/feed.xml',
    description: 'Datadog Security Labs - cloud-native threat research, container security, and detection engineering.',
    category: 'threat-intel',
    source: 'datadoghq.com',
    language: 'en',
  },
  {
    id: 'flashpoint',
    name: 'Flashpoint Intel',
    url: 'https://flashpoint.io/blog/feed/',
    description: 'Flashpoint - dark web intelligence, threat actor profiles, and cybercrime ecosystem analysis.',
    category: 'threat-intel',
    source: 'flashpoint.io',
    language: 'en',
  },
  {
    id: 'intel471',
    name: 'Intel 471 Blog',
    url: 'https://intel471.com/blog/feed',
    description: 'Intel 471 - cybercrime intelligence, adversary tracking, and underground ecosystem monitoring.',
    category: 'threat-intel',
    source: 'intel471.com',
    language: 'en',
  },
  {
    id: 'wordfence',
    name: 'Wordfence Threat Intelligence',
    url: 'https://www.wordfence.com/blog/feed/',
    description: 'Wordfence - WordPress malware campaigns, plugin vulnerabilities, and threat intelligence.',
    category: 'threat-intel',
    source: 'wordfence.com',
    language: 'en',
  },
  {
    id: 'idtheftcenter',
    name: 'Identity Theft Resource Center',
    url: 'https://www.idtheftcenter.org/feed/',
    description:
      'ITRC - non-profit that tracks U.S. publicly-reported data breaches; publishes quarterly + annual reports on breach trends, victim counts, and notification compliance.',
    category: 'threat-intel',
    source: 'idtheftcenter.org',
    language: 'en',
  },
  {
    id: 'gnews-india-cyberattack',
    name: 'Bing News - India cyber attacks & breaches',
    url: 'https://www.bing.com/news/search?q=India+cyber+attack&format=RSS&mkt=en-IN&qft=interval%3d%2230%22',
    description:
      'India-scoped Bing News for cyber-attacks, data breaches, ransomware incidents and APT activity targeting Indian organisations.',
    category: 'threat-intel',
    source: 'Bing News (IN)',
    language: 'en-IN',
  },
  {
    id: 'gnews-cert-in',
    name: 'CERT-In advisories (via Bing News)',
    url: 'https://www.bing.com/news/search?q=CERT-In+advisory&format=RSS&mkt=en-IN&qft=interval%3d%2230%22',
    description:
      'Coverage of CERT-In (Indian Computer Emergency Response Team) advisories, vulnerability notes and alerts - CERT-In has no stable public RSS, so this tracks it via news.',
    category: 'threat-intel',
    source: 'Bing News (IN)',
    language: 'en-IN',
  },

  // ============================================================================
  // FEED EXPANSION 2026-05-18 - all URLs HTTP-200 + XML verified before adding.
  // Dark Web / Threat Feeds → category 'threat-intel'; Tech & AI → 'tech'.
  // ============================================================================
  {
    id: 'cyble-blog',
    name: 'Cyble Research',
    url: 'https://cyble.com/feed/',
    description: 'Threat intelligence research - dark-web monitoring, ransomware, breach and campaign analysis',
    category: 'threat-intel',
    source: 'cyble.com',
    language: 'en',
  },
  {
    id: 'socradar-blog',
    name: 'SOCRadar',
    url: 'https://socradar.io/feed/',
    description: 'Dark-web and external attack-surface threat research, leak and ransomware tracking',
    category: 'threat-intel',
    source: 'socradar.io',
    language: 'en',
  },
  {
    id: 'bushidotoken',
    name: 'BushidoToken',
    url: 'https://blog.bushidotoken.net/feeds/posts/default?alt=rss',
    description: 'Independent CTI research - ransomware, dark-web actors, campaign deep-dives',
    category: 'threat-intel',
    source: 'blog.bushidotoken.net',
    language: 'en',
  },
  {
    id: 'danielmiessler',
    name: 'Daniel Miessler',
    url: 'https://danielmiessler.com/feed',
    description: 'Essays on threat intelligence, security engineering, and AI security from Daniel Miessler',
    category: 'threat-intel',
    source: 'danielmiessler.com',
    language: 'en',
  },
  {
    id: 'rapid7-blog',
    name: 'Rapid7 Blog',
    url: 'https://www.rapid7.com/rss.xml',
    description: 'Vulnerability research, emergent-threat advisories and detection guidance',
    category: 'threat-intel',
    source: 'rapid7.com',
    language: 'en',
  },
  {
    id: 'jpcert',
    name: 'JPCERT/CC Eyes',
    url: 'https://blogs.jpcert.or.jp/en/atom.xml',
    description: 'Japan CERT incident & malware analysis - APT tooling, ICS, regional campaigns',
    category: 'threat-intel',
    source: 'jpcert.or.jp',
    language: 'en',
  },
  {
    id: 'ncsc-uk',
    name: 'NCSC UK',
    url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
    description: 'UK National Cyber Security Centre advisories, guidance and threat reports',
    category: 'advisory',
    source: 'ncsc.gov.uk',
    language: 'en-GB',
  },
  {
    id: 'ahnlab-asec',
    name: 'AhnLab ASEC',
    url: 'https://asec.ahnlab.com/en/feed/',
    description: 'AhnLab Security Emergency-response Center - malware, phishing and APT analysis',
    category: 'threat-intel',
    source: 'asec.ahnlab.com',
    language: 'en',
  },
  {
    id: 'import-ai',
    name: 'Import AI (Jack Clark)',
    url: 'https://importai.substack.com/feed',
    description: 'Weekly AI research & policy analysis newsletter',
    category: 'tech',
    source: 'importai.substack.com',
    language: 'en',
  },
  {
    // Synthesised RSS - MyThreatIntel ransomware victims (telegram) in RSS
    // form, built in-process by buildMtiRansomwareRss. The aggregator
    // intercepts any URL with pathname /api/v1/feeds/mti-ransomware before
    // the host check, so the host value here is cosmetic.
    id: 'mti-ransomware',
    name: 'MyThreatIntel (ransomware)',
    url: 'https://internal.pranithjain.com/api/v1/feeds/mti-ransomware',
    description:
      'MyThreatIntel Telegram-based ransomware victim tracking, republished as an RSS feed from the synthesised same-origin endpoint',
    category: 'threat-intel',
    source: 'MyThreatIntel (Telegram)',
    language: 'en',
  },
  {
    // Synthesised RSS - re-publishes the merged ransomware victim claims from
    // all trackers (Ransomlook, ransomware.live, ransomfeed.it, ransomwatch,
    // andreafortuna) sorted newest-first. Same-origin → aggregator-eligible.
    id: 'ransomware-merged',
    name: 'Ransomware claims (merged)',
    url: 'https://pranithjain.qzz.io/api/v1/feeds/ransomware-merged',
    description:
      'Merged ransomware victim claims from Ransomlook, ransomware.live, ransomfeed.it, ransomwatch, and andreafortuna',
    category: 'threat-intel',
    source: 'ransomlook.io + ransomware.live',
    language: 'en',
  },
  // ============================================================================
  // FEEDSPOT HIGH-QUALITY FEEDS 2026-06 - curated from rss.feedspot.com/hacker_rss_feeds/
  // ============================================================================
  {
    id: 'tisiphone',
    name: 'Tisiphone (Lesley Carhart)',
    url: 'https://tisiphone.net/feed/',
    description:
      'DFIR, threat intelligence, incident response, digital forensics, and OSINT from Lesley Carhart, full-spectrum cyber-warrior',
    category: 'threat-intel',
    source: 'tisiphone.net',
    language: 'en',
  },
  {
    id: 'detectify',
    name: 'Detectify Blog',
    url: 'https://blog.detectify.com/feed/',
    description:
      'Web security vulnerability research, bug bounty write-ups, and security culture insights from the Detectify team',
    category: 'threat-intel',
    source: 'blog.detectify.com',
    language: 'en',
  },
  {
    id: 'embracethered',
    name: 'Embrace The Red',
    url: 'https://embracethered.com/blog/index.xml',
    description:
      'AI/LLM security research, red-team exploit analysis, prompt injection vulnerabilities, and defensive insights',
    category: 'threat-intel',
    source: 'embracethered.com',
    language: 'en',
  },
  {
    id: 'knowbe4',
    name: 'KnowBe4 Security Awareness',
    url: 'https://blog.knowbe4.com/rss.xml',
    description:
      'Security awareness training blog - social engineering, ransomware, phishing attacks, and cybercrime trends',
    category: 'threat-intel',
    source: 'blog.knowbe4.com',
    language: 'en',
  },
  {
    id: 'cqure-academy',
    name: 'CQURE Academy',
    url: 'https://cqureacademy.com/blog/feed/',
    description:
      'Windows internals, identity theft protection, penetration testing, malware, forensics, and incident response',
    category: 'threat-intel',
    source: 'cqureacademy.com',
    language: 'en',
  },
  {
    id: 'hackingarticles',
    name: 'Hacking Articles (Raj Chandel)',
    url: 'https://www.hackingarticles.in/feed/',
    description:
      'Comprehensive penetration testing tutorials - system exploitation, vulnerability research, tools, and CTF walkthroughs',
    category: 'threat-intel',
    source: 'hackingarticles.in',
    language: 'en',
  },
  {
    id: 'darknet',
    name: 'Darknet',
    url: 'https://www.darknet.org.uk/feed/',
    description:
      'Hacking news, tools, and tutorials - password cracking, cryptography, network security, and pen-testing',
    category: 'news',
    source: 'darknet.org.uk',
    language: 'en',
  },
  // ── Added 2026-10 ────────────────────────────────────────────────────────
  // OffSeq Threat Radar. NB: https://radar.offseq.com/feeds is the HTML
  // directory page (Next.js app shell, 45KB of markup, zero RSS items); the
  // machine-readable feed is /rss.xml, which is what this entry uses. Both
  // host and URL were missing from the fetch allowlist before this pass, so
  // the feed failed with `host_not_in_allowlist` even before the URL was
  // correct — see api/src/lib/feed-hosts.ts.
  {
    id: 'offseq-radar',
    name: 'OffSeq Threat Radar',
    url: 'https://radar.offseq.com/rss.xml',
    description:
      'OffSeq threat-intelligence radar - community-curated threat reports and source activity, with AI triage',
    category: 'threat-intel',
    source: 'radar.offseq.com',
    language: 'en',
  },
];

/**
 * Feeds shown in the live Threat Intel panel on the /dfir landing page.
 * Auto-derived from category but with an explicit exclusion list so the
 * scam-watch / industry / AI feeds (which live in their own dedicated
 * tools - /threatintel/scam-watch and /threatintel/tech-ai-news) don't pollute the
 * landing page's threat-intel surface.
 */
const EXCLUDE_FROM_LANDING = new Set<string>([
  // Structured-source feeds whose full data lives on a dedicated page; the RSS
  // is only a change-detection signal, so keep it out of the landing card.
  // Wiz RSS is a change-detection signal; full cloud incidents live on the Cloud-incidents page.
  'wiz-cloud-threats',
  // Scam Watch sources (live at /threatintel/scam-watch)
  'ftc-consumer',
  'ic3-psas',
  'snopes',
  'gnews-deepfake',
  'gnews-victim',
  'gnews-pig-butcher',
  'gnews-job-scam',
  'gnews-tech-support',
  'gnews-investment-scam',
  'gnews-voice-clone',
  'gnews-sim-swap',
  'gnews-rug-pull',
  'gnews-nft-drainer',
  'gnews-defi-hack',
  'rekt-news',
  'web3-grift',
]);

export const defaultFeeds = rssFeeds
  .filter((f) => f.category === 'threat-intel' || f.category === 'advisory' || f.category === 'news')
  .filter((f) => !EXCLUDE_FROM_LANDING.has(f.id))
  .map((f) => f.id);

/**
 * Tech / AI / Industry feeds - rendered as the full surface at
 * /threatintel/tech-ai-news. The /dfir landing page used to host these via the
 * standalone TechNewsFeed component; that role has been folded into the
 * Tech & AI card on LiveSnapshotPanel (which uses a smaller curated subset
 * of these IDs - see TECH_AI_SNAPSHOT_FEED_IDS in that file). Three
 * sections, three lists.
 */
export const landingAiFeeds = [
  'techcrunch-ai',
  'verge-ai',
  'openai-news',
  'google-ai',
  'anthropic-blog',
  'deepmind-blog',
  'huggingface-blog',
  'the-decoder',
  'gnews-ai-security',
  'gnews-ai-funding',
  'gnews-genai-enterprise',
  'gnews-ai-regulation',
  'gnews-genai-adversarial',
  'recorded-future',
  'import-ai',
];

export const landingFinanceFeeds = [
  'finextra',
  'gnews-banking-cyber',
  'gnews-fintech-breach',
  'gnews-payment-security',
  'gnews-insurance-cyber',
  'gnews-investment-cyber',
];

export const landingIndustryFeeds = [
  'techcrunch-security',
  'venturebeat-security',
  'gnews-cybersec-funding',
  'gnews-cybersec-acquisition',
  'gnews-infosec-startup',
];

export const landingGeneralTechFeeds = ['ars-tech', 'mit-tech-review', 'hn-frontpage', 'hn-ask', 'hn-show', 'yc-blog'];

/** Backward-compat alias retained for any older callers. */
export const defaultTechFeeds = landingGeneralTechFeeds;

/**
 * Threat-feeds surface - used as the dedicated /threatintel/threat-feeds page.
 * The /dfir landing page used to host these via the standalone
 * ThreatIntelFeed component; that role has been folded into the Threat
 * Intel card on LiveSnapshotPanel (which uses a smaller curated subset -
 * see THREAT_INTEL_SNAPSHOT_FEED_IDS in that file). Six sections,
 * hand-picked so each tab has a coherent identity.
 */
export const landingThreatGovernment = [
  'cisa-alerts',
  'cisa-medical-advisories',
  'ncsc-uk',
  // ccb-* removed 2026-06: ccb.belgium.be is Cloudflare-fronted and
  // intermittently returns 403 to the Worker's datacenter egress IP
  // (documented in feeds-aggregate.ts cacheTtlByStatus comment).
];
// gnews-* removed 2026-05-24: Google News rate-limits Worker IPs (503).
// India coverage now relies on the global feeds - Krebs, BleepingComputer,
// etc. that cover India-relevant incidents.
export const landingThreatIndia: string[] = [];

export const landingThreatVendor = [
  'talos',
  'unit42',
  'trail-of-bits',
  'mandiant',
  'crowdstrike',
  'eset',
  'kaspersky-securelist',
  'sentinelone-labs',
  'google-project-zero',
  'checkpoint-research',
  'malwarebytes-labs',
  'huntress',
  'red-canary',
  'microsoft-security',
  'sophos-news',
  'trendmicro-research',
  'withsecure-labs',
  'malware-traffic-analysis',
  'dfir-lab',
  'dfir-radar',
  'sans-isc',
  'rapid7-blog',
  'jpcert',
  'ahnlab-asec',
  'detectify',
  'knowbe4',
  'cqure-academy',
  'recorded-future',
  'aws-security',
];

export const landingThreatInvestigation = [
  'dfir-report',
  'the-record',
  'darkwebinformer',
  'databreaches',
  'mitre-attack-medium',
  'cyble-blog',
  'socradar-blog',
  'bushidotoken',
  'infostealers-com',
  'tisiphone',
  'embracethered',
  'darknet',
  'offseq-radar',
  // ThreatFeed (jozeta/ThreatFeed) registry cross-check 2026-11-01 - six curated
  // security sources our hub lacked; each URL probed and confirmed RSS.
  'dfir-diva',
  'invictus-ir',
  'daily-dark-web',
  'offsec-blog',
  'emsisoft-blog',
  'danielmiessler',
];

// Reddit blocks Cloudflare Worker egress IPs at the network level (see
// api/src/routes/reddit-feed.ts), so the /feeds/proxy + /feeds/aggregate paths
// can NEVER fetch r/*.rss - they returned errors here. Reddit threat-intel
// content is served instead at /threatintel/reddit, fed by a GitHub Action that
// publishes reddit-feed.json to the reddit-feed-data branch (raw.githubusercontent).
// Emptied so this page stops surfacing perpetually-failing feeds.
export const landingThreatReddit: string[] = [];

// exploitdb removed 2026-06: www.exploit-db.com is Cloudflare-fronted and
// returns 403 to Worker egress IPs (same root cause as cvedetails.com, which
// was removed 2026-05 for the same reason - see comment at line 560).
export const landingThreatVulns: string[] = [];

export const landingThreatNews = [
  'krebsonsecurity',
  'hackernews',
  'bleepingcomputer',
  'securityweek',
  'schneier',
  'wired-security',
  'theregister-security',
  'helpnetsecurity',
  'csoconline',
  'malwaretech',
  'hexacorn',
  'objective-see',
  'elasticsecurity',
  'datadog-security',
  'flashpoint',
  'intel471',
  'wordfence',
];

// Feed categories for filtering
export const feedCategories = [
  { id: 'all', label: 'All Feeds' },
  { id: 'vulnerability', label: 'Vulnerabilities' },
  { id: 'advisory', label: 'Advisories' },
  { id: 'ics-cert', label: 'ICS-CERT' },
  { id: 'threat-intel', label: 'Threat Intel' },
  { id: 'news', label: 'News' },
  { id: 'tech', label: 'Tech & AI' },
  { id: 'general', label: 'General' },
];

// Get feed statistics
export function getFeedStats() {
  return {
    total: rssFeeds.length,
    byCategory: feedCategories.slice(1).map((cat) => ({
      ...cat,
      count: rssFeeds.filter((f) => f.category === cat.id).length,
    })),
  };
}

/**
 * Feeds deliberately retired from this catalog (removed 2026-05..2026-08).
 * Single structured registry so future sync/tooling can consult it and the
 * catalog page can render the history. Keys are the old feed ids; the reason
 * records why it is gone. DO NOT re-add these without a working live URL.
 */
export const RETIRED_FEEDS: Record<string, string> = {
  'supplychain-attacks': 'HTTP 402 (requires payment)',
  cybernews: '403 from Worker egress IP',
  'lyrie-research': 'feed went dead',
  threatpost: 'site frozen / feeds removed upstream (2023)',
  countercept: 'duplicate of withsecure-labs',
  'chronicle-blog': 'duplicate of google-cloud-blog',
  'netscope-research': 'feed went dead',
  thehackerblog: 'feed went dead',
  pentestlab: 'feed went dead',
  'curated-intel': 'out-of-scope curated feed',
  vxdb: 'feed schema incompatible',
  doublepulsar: 'out-of-scope curated feed',
  'reddit-r-threatintel': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-cybersecurity': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-netsec': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-hacking': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-malware': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-apt': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-osint': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-scams': 'reddit blocks Worker egress IPs (network-level)',
  'reddit-r-vxunderground': 'reddit blocks Worker egress IPs (network-level)',
  'ccb-belg': 'ccb.belgium.be Cloudflare-fronted, 403 to Worker egress',
  cvedetails: 'cvedetails.com Cloudflare-fronted, 403 (2026-05)',
  exploitdb: 'exploit-db.com Cloudflare-fronted, 403 (2026-06)',
  'wired-rss': 'feed path restructured upstream, 404 (removed /latest/)',
  'gnews-cyber': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-india': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-ai': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-cloud': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-devsecops': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-ics': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-iot': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-mobile': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-ransomware': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'gnews-supply-chain': 'google news rate-limits Worker IPs, 503 (2026-05-24)',
  'redhunt-research': 'upstream blog feed empty since 2023 (lastBuildDate 2023-01-16)',
  'hackers-arise': 'HTTP 403 to every non-browser client; feed effectively dead (2026-10)',
  'google-news-search': 'all news.google.com search RSS 503d Worker egress (2026-10) — replaced by Bing News mirrors',
};
