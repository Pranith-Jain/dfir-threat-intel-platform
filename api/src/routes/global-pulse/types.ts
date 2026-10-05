/* ─── Types ─────────────────────────────────────────────────────────────── */

export type PulseKind =
  | 'earthquake'
  | 'ioc_activity'
  | 'geopolitical'
  | 'tech_news'
  | 'reddit'
  | 'telegram'
  | 'x_feed'
  | 'scam'
  | 'breach'
  | 'briefing'
  | 'cyber_attack'
  | 'aircraft'
  | 'war_room'
  | 'c2_tracker'
  | 'cisa_advisory'
  | 'blocklist'
  | 'infostealer'
  | 'phishing'
  | 'malware'
  | 'ransomware'
  | 'cybercrime'
  | 'research'
  | 'cve'
  | 'actor_sighting'
  | 'ioc_correlation'
  | 'secret_leak'
  | 'malicious_package'
  | 'exploit'
  | 'github_advisory'
  | 'supply_chain_attacks'
  | 'kev'
  | 'honeypot'
  | 'ai_llm_campaign'
  | 'ai_llm_research'
  | 'firm'
  | 'maritime'
  | 'cyberpulse'
  | 'rss'
  | 'honeypot';

export interface PulseEvent {
  id: string;
  kind: PulseKind;
  title: string;
  description: string;
  lat: number;
  lng: number;
  magnitude?: number;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  url?: string;
  country?: string;
  cti?: 'ransomware' | 'cve' | 'ioc' | 'threat' | 'other';
  /**
   * True when the CVE is CISA-KEV-listed (confirmed exploited in the wild).
   * Set by the KEV-catalog and 24h-digest converters. The frontend renders
   * these as 0-DAY chips — the closest thing this stack has to a 0-day flag.
   */
  kev?: boolean;
  /**
   * ctiwatch exploit_status for the CVE ('poc' | 'weaponized' | 'in_the_wild').
   * Absent (or 'none') means no known public exploit. Rendered as a PoC chip.
   */
  exploitStatus?: string;
  /**
   * True when the same indicator (CVE id or ransomware victim) was reported
   * by 2+ distinct sources in this build — the "in trends" signal. Stamped by
   * markTrendingEvents, never by individual converters.
   */
  trending?: boolean;
}

export interface GlobalPulseResponse {
  generated_at: string;
  total_events: number;
  events: PulseEvent[];
  layers: Record<PulseKind, number>;
}

export type Sev = PulseEvent['severity'];

export interface TechLocation {
  name: string;
  lat: number;
  lng: number;
  type: 'datacenter' | 'ixp' | 'cloud_region' | 'tech_hq' | 'startup_hub';
  operator?: string;
  country: string;
}

export interface GeopoliticalLocation {
  name: string;
  lat: number;
  lng: number;
  type: 'conflict_zone' | 'sanctioned_country' | 'military_base' | 'nuclear_site' | 'disputed_territory';
  description: string;
  country: string;
  severity: PulseEvent['severity'];
}

export interface XClaimsResponse {
  generated_at: string;
  handles: string[];
  ransomware: Array<{
    victim: string;
    group: string;
    discovered: string;
    description?: string;
    source_url: string;
    sector?: string;
    country?: string;
  }>;
  breach: Array<{
    victim?: string;
    text: string;
    source_url: string;
    discovered: string;
    handle: string;
  }>;
}

export interface ActorTimelineResponse {
  generated_at: string;
  groups: Array<{
    slug: string;
    display_name: string;
    posts_in_window: number;
    all_time_count: number;
    description?: string;
    raas?: boolean;
    mitre?: { id: string; name: string };
  }>;
}

export interface IocCorrelationResponse {
  generated_at: string;
  ips: Array<{ value: string; source_count: number; sources: string[]; context?: string; last_seen?: string }>;
  urls: Array<{ value: string; source_count: number; sources: string[]; context?: string; last_seen?: string }>;
  domains: Array<{ value: string; source_count: number; sources: string[]; context?: string; last_seen?: string }>;
  hashes: Array<{ value: string; source_count: number; sources: string[]; context?: string; last_seen?: string }>;
}
