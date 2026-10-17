export interface ArticleSource {
  id: number;
  title: string;
  url: string;
  published_date: string;
  source_type: string;
}

export interface ThreatStory {
  headline: string;
  narrative: string;
  impact_assessment: string;
  action_required: string;
  timeline?: Array<{ date: string; event: string; significance: string }>;
  sources: number[];
}

export interface ActorProfile {
  name: string;
  motivation: string;
  recent_activity: string;
  aliases: string[];
  targets: string[];
  ttps: string[];
  sources: number[];
}

export interface DashboardCve {
  cve: string;
  product: string;
  vendor: string;
  cvss: number;
  severity: string;
  exploitation_status: string;
  remediation: string;
}

export interface HuntingLead {
  title: string;
  context: string;
  query: string;
  indicators: string[];
  sources: number[];
}

export interface SupplyChainIncident {
  title: string;
  ecosystem: string;
  attack_vector: string;
  severity: string;
  status: string;
  threat_actor: string | null;
  url: string;
  summary: string;
}

export interface DashboardStats {
  top_actors: [string, number][];
  top_targeted_industries: [string, number][];
  emerging_trends: string[];
  declining_threats: string[];
  key_changes: string;
}

export interface TiDashboardReport {
  slug: string;
  week_start: string;
  week_end: string;
  generated_at: string;
  metadata: {
    documents_analyzed: number;
    reading_time_minutes: number;
    time_period_days: number;
  };
  sources: ArticleSource[];
  executive_brief: string;
  threat_stories: ThreatStory[];
  actor_profiles: ActorProfile[];
  critical_vulnerabilities: DashboardCve[];
  hunting_leads: HuntingLead[];
  supply_chain_incidents: SupplyChainIncident[];
  statistics: DashboardStats;
}

export interface Article {
  id: number;
  title: string;
  url: string;
  published_date: string;
  source_type: string;
  summary: string | null;
  feed_source: string | null;
}

export interface RawSupplyChainIncident {
  title: string;
  url: string;
  ecosystem: string;
  attack_vector: string;
  severity: string;
  status: string;
  threat_actor: string | null;
  published_date: string;
  summary: string;
}

export const NEWS_FEEDS = [
  { id: 'thehackernews', name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', type: 'news' },
  {
    id: 'bleepingcomputer',
    name: 'BleepingComputer',
    // bleepingcomputer.com 403s datacenter egress — Bing News mirror instead (news.google.com 503s Worker egress).
    url: 'https://www.bing.com/news/search?q=site%3Ableepingcomputer.com&format=RSS&mkt=en-US',
    type: 'news',
  },
  { id: 'darkreading', name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml', type: 'news' },
  { id: 'securityweek', name: 'SecurityWeek', url: 'https://feeds.feedblitz.com/securityweek&x=1', type: 'news' },
] as const;

export const SUPPLY_CHAIN_FEED = 'https://www.supplychainattack.org/';

export const IMPACT_LEVELS = ['Critical', 'High', 'Medium', 'Low'] as const;
