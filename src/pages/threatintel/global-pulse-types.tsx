import type { ReactNode } from 'react';
import {
  Radio,
  Zap,
  Bug,
  Skull,
  Shield,
  Newspaper,
  Rss,
  MessageSquare,
  AtSign,
  AlertTriangle,
  ShieldAlert,
  Flame,
  Box,
  Crosshair,
  Anchor,
  BrainCircuit,
  FileText,
} from 'lucide-react';

export type PulseKind =
  | 'ioc_activity'
  | 'reddit'
  | 'telegram'
  | 'x_feed'
  | 'scam'
  | 'breach'
  | 'briefing'
  | 'cyber_attack'
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
  | 'cyberpulse'
  | 'rss'
  | 'honeypot'
  | 'ai_llm_campaign'
  | 'ai_llm_research'
  | 'firm'
  | 'maritime';

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
  /** CISA-KEV-listed (confirmed exploited) — rendered as a 0-DAY chip. */
  kev?: boolean;
  /** ctiwatch exploit_status ('poc' | 'weaponized' | 'in_the_wild') — PoC chip. */
  exploitStatus?: string;
  /** Reported by 2+ distinct sources this build — trending chip + rank boost. */
  trending?: boolean;
}

/**
 * Within-severity rank class. Mirrors signalClass() in
 * api/src/routes/global-pulse/converters.ts — keep the two in sync: confirmed
 * harm (ransom victims, KEV 0-days) above vulnerability records, which sit
 * above raw infrastructure observations.
 */
export function signalRank(e: Pick<PulseEvent, 'kind' | 'trending'>): number {
  const base =
    e.kind === 'ransomware' || e.kind === 'kev'
      ? 3
      : e.kind === 'cve' || e.kind === 'exploit' || e.kind === 'cisa_advisory' || e.kind === 'github_advisory'
        ? 2
        : 1;
  return base + (e.trending ? 1 : 0);
}

export interface GlobalPulseResponse {
  generated_at: string;
  total_events: number;
  events: PulseEvent[];
  layers: Record<PulseKind, number>;
}

/* ─── Layer config ──────────────────────────────────────────────────────── */

export interface LayerDef {
  label: string;
  shortLabel: string;
  icon: ReactNode;
  color: string;
  bgColor: string;
  group: 'intel' | 'social';
}

export const LAYER_DEFS: Record<PulseKind, LayerDef> = {
  ioc_activity: {
    label: 'IOC Activity',
    shortLabel: 'IOC',
    icon: <Radio size={14} />,
    color: 'text-rose-600 dark:text-rose-400',
    bgColor: 'bg-rose-500/10 border-rose-500/20',
    group: 'intel',
  },
  cyber_attack: {
    label: 'Live IOCs',
    shortLabel: 'IOC',
    icon: <Zap size={14} />,
    color: 'text-rose-600 dark:text-rose-400',
    bgColor: 'bg-rose-500/10 border-rose-500/20',
    group: 'intel',
  },
  cve: {
    label: 'CVEs',
    shortLabel: 'CVE',
    icon: <Bug size={14} />,
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-500/10 border-amber-500/20',
    group: 'intel',
  },
  actor_sighting: {
    label: 'Threat Actors',
    shortLabel: 'ACTOR',
    icon: <Skull size={14} />,
    color: 'text-purple-600 dark:text-purple-400',
    bgColor: 'bg-purple-500/10 border-purple-500/20',
    group: 'intel',
  },
  ioc_correlation: {
    label: 'IOC Correlations',
    shortLabel: 'CORR',
    icon: <Crosshair size={14} />,
    color: 'text-cyan-600 dark:text-cyan-400',
    bgColor: 'bg-cyan-500/10 border-cyan-500/20',
    group: 'intel',
  },
  secret_leak: {
    label: 'GitHub Leaks',
    shortLabel: 'LEAK',
    icon: <ShieldAlert size={14} />,
    color: 'text-rose-600 dark:text-rose-400',
    bgColor: 'bg-rose-500/10 border-rose-500/20',
    group: 'intel',
  },
  malicious_package: {
    label: 'Malicious Packages',
    shortLabel: 'PKG',
    icon: <Box size={14} />,
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-500/10 border-orange-500/20',
    group: 'intel',
  },
  exploit: {
    label: 'Public Exploits',
    shortLabel: 'XPLOIT',
    icon: <Zap size={14} />,
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-500/10 border-amber-500/20',
    group: 'intel',
  },
  github_advisory: {
    label: 'GitHub Advisories',
    shortLabel: 'GHSA',
    icon: <Shield size={14} />,
    color: 'text-sky-600 dark:text-sky-400',
    bgColor: 'bg-sky-500/10 border-sky-500/20',
    group: 'intel',
  },
  kev: {
    label: 'CISA KEV',
    shortLabel: 'KEV',
    icon: <Flame size={14} />,
    color: 'text-rose-500',
    bgColor: 'bg-rose-600/10 border-rose-600/20',
    group: 'intel',
  },
  ransomware: {
    label: 'Ransomware',
    shortLabel: 'RANSOM',
    icon: <Skull size={14} />,
    color: 'text-rose-500',
    bgColor: 'bg-rose-600/10 border-rose-600/20',
    group: 'intel',
  },
  infostealer: {
    label: 'Infostealers',
    shortLabel: 'STEALER',
    icon: <Bug size={14} />,
    color: 'text-orange-500',
    bgColor: 'bg-orange-600/10 border-orange-600/20',
    group: 'intel',
  },
  phishing: {
    label: 'Phishing',
    shortLabel: 'PHISH',
    icon: <AlertTriangle size={14} />,
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-500/10 border-amber-500/20',
    group: 'intel',
  },
  malware: {
    label: 'Malware',
    shortLabel: 'MAL',
    icon: <Bug size={14} />,
    color: 'text-rose-600 dark:text-rose-400',
    bgColor: 'bg-rose-500/10 border-rose-500/20',
    group: 'intel',
  },
  cybercrime: {
    label: 'Cybercrime',
    shortLabel: 'CRIME',
    icon: <Zap size={14} />,
    color: 'text-rose-600 dark:text-rose-400',
    bgColor: 'bg-rose-500/10 border-rose-500/20',
    group: 'intel',
  },
  c2_tracker: {
    label: 'C2 Tracker',
    shortLabel: 'C2',
    icon: <Crosshair size={14} />,
    color: 'text-rose-500',
    bgColor: 'bg-rose-600/10 border-rose-600/20',
    group: 'intel',
  },
  supply_chain_attacks: {
    label: 'Supply Chain',
    shortLabel: 'CHAIN',
    icon: <Box size={14} />,
    color: 'text-cyan-500',
    bgColor: 'bg-cyan-600/10 border-cyan-600/20',
    group: 'intel',
  },
  cisa_advisory: {
    label: 'CISA Advisories',
    shortLabel: 'ADV',
    icon: <AlertTriangle size={14} />,
    color: 'text-amber-500',
    bgColor: 'bg-amber-600/10 border-amber-600/20',
    group: 'intel',
  },
  blocklist: {
    label: 'Blocklist',
    shortLabel: 'BL',
    icon: <ShieldAlert size={14} />,
    color: 'text-muted',
    bgColor: 'bg-slate-500/10 border-slate-500/20',
    group: 'intel',
  },
  breach: {
    label: 'Breaches',
    shortLabel: 'BREACH',
    icon: <ShieldAlert size={14} />,
    color: 'text-rose-600 dark:text-rose-400',
    bgColor: 'bg-rose-500/10 border-rose-500/20',
    group: 'intel',
  },
  scam: {
    label: 'Scam',
    shortLabel: 'SCAM',
    icon: <AlertTriangle size={14} />,
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-500/10 border-amber-500/20',
    group: 'intel',
  },
  briefing: {
    label: 'Briefings',
    shortLabel: 'INTEL',
    icon: <Newspaper size={14} />,
    color: 'text-emerald-600 dark:text-emerald-400',
    bgColor: 'bg-emerald-500/10 border-emerald-500/20',
    group: 'intel',
  },
  research: {
    label: 'Research',
    shortLabel: 'RSRCH',
    icon: <Newspaper size={14} />,
    color: 'text-sky-600 dark:text-sky-400',
    bgColor: 'bg-sky-500/10 border-sky-500/20',
    group: 'social',
  },
  reddit: {
    label: 'Reddit',
    shortLabel: 'RDDT',
    icon: <Rss size={14} />,
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-500/10 border-orange-500/20',
    group: 'social',
  },
  telegram: {
    label: 'Telegram',
    shortLabel: 'TG',
    icon: <MessageSquare size={14} />,
    color: 'text-cyan-600 dark:text-cyan-400',
    bgColor: 'bg-cyan-500/10 border-cyan-500/20',
    group: 'social',
  },
  x_feed: {
    label: 'X/Bluesky',
    shortLabel: 'X',
    icon: <AtSign size={14} />,
    color: 'text-brand-600 dark:text-brand-400',
    bgColor: 'bg-brand-500/10 border-brand-500/20',
    group: 'social',
  },
  cyberpulse: {
    label: 'CyberPulse Incidents',
    shortLabel: 'CP',
    icon: <Radio size={14} />,
    color: 'text-fuchsia-600 dark:text-fuchsia-400',
    bgColor: 'bg-fuchsia-500/10 border-fuchsia-500/20',
    group: 'intel',
  },
  rss: {
    label: 'RSS Feeds',
    shortLabel: 'RSS',
    icon: <Rss size={14} />,
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-500/10 border-orange-500/20',
    group: 'social',
  },
  honeypot: {
    label: 'AI Honeypot',
    shortLabel: 'HONEY',
    icon: <Crosshair size={14} />,
    color: 'text-teal-600 dark:text-teal-400',
    bgColor: 'bg-teal-500/10 border-teal-500/20',
    group: 'intel',
  },
  // AI/LLM narrative intel. Violet/fuchsia so these read as a family alongside
  // the teal honeypot layer without colliding with the red malware/C2 palette.
  ai_llm_campaign: {
    label: 'AI/LLM Campaigns',
    shortLabel: 'AICAM',
    icon: <BrainCircuit size={14} />,
    color: 'text-violet-600 dark:text-violet-400',
    bgColor: 'bg-violet-500/10 border-violet-500/20',
    group: 'intel',
  },
  ai_llm_research: {
    label: 'AI/LLM Research',
    shortLabel: 'AIPAP',
    icon: <FileText size={14} />,
    color: 'text-fuchsia-600 dark:text-fuchsia-400',
    bgColor: 'bg-fuchsia-500/10 border-fuchsia-500/20',
    group: 'intel',
  },
  firm: {
    label: 'FIRMS Fires',
    shortLabel: 'FIRE',
    icon: <Flame size={14} />,
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-500/10 border-orange-500/20',
    group: 'intel',
  },
  maritime: {
    label: 'Maritime (UKMTO)',
    shortLabel: 'SEA',
    icon: <Anchor size={14} />,
    color: 'text-sky-600 dark:text-sky-400',
    bgColor: 'bg-sky-500/10 border-sky-500/20',
    group: 'intel',
  },
};

/* ─── Helpers ───────────────────────────────────────────────────────────── */

export const SEVERITY_CONFIG = {
  critical: {
    dot: 'bg-rose-500',
    ring: 'ring-rose-500/30',
    text: 'text-rose-600 dark:text-rose-400',
    bg: 'bg-rose-500/10',
    badge: 'danger' as const,
    pulse: true,
  },
  high: {
    dot: 'bg-orange-500',
    ring: 'ring-orange-500/30',
    text: 'text-orange-600 dark:text-orange-400',
    bg: 'bg-orange-500/10',
    badge: 'warning' as const,
    pulse: false,
  },
  medium: {
    dot: 'bg-amber-500',
    ring: 'ring-amber-500/30',
    text: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-500/10',
    badge: 'warning' as const,
    pulse: false,
  },
  low: {
    dot: 'bg-emerald-500',
    ring: 'ring-emerald-500/30',
    text: 'text-emerald-600 dark:text-emerald-400',
    bg: 'bg-emerald-500/10',
    badge: 'default' as const,
    pulse: false,
  },
};

export function formatTime(ts: string): string {
  const d = new Date(ts).getTime();
  if (isNaN(d)) return '-';
  const diff = Date.now() - d;
  if (diff < 60_000) return 'now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`;
  return `${Math.floor(diff / 86_400_000)}d`;
}

export function formatTimeFull(ts: string): string {
  return new Date(ts).toLocaleString();
}

export const ALL_KINDS = Object.keys(LAYER_DEFS) as PulseKind[];
