/** Types + pure helpers for the Global Hack Map-style situation room. */

import type { PulseEvent } from '../global-pulse-types';

export type GhmTab = 'cves' | 'breaches' | 'malware' | 'outages';
export type GhmWindow = '24h' | '7d' | '30d';

/** Mirror of /api/v1/cve-recent — kept local so the bundle never imports api/src. */
export interface GhmCve {
  id: string;
  published: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';
  score: number | null;
  kev: boolean;
  kev_added?: string;
  kev_ransomware?: boolean;
  epss?: number;
  epss_percentile?: number;
  vendor?: string;
  product?: string;
  has_exploit?: boolean;
  has_fix?: boolean;
  listed_by?: string[];
  listed_by_count?: number;
  origin?: string;
}

export interface GhmCveFeed {
  generated_at: string;
  count: number;
  kev_count: number;
  cves: GhmCve[];
}

/** Mirror of public/data/cve-intel/vulntracker-trending.json. */
export interface GhmTrending {
  generatedAt: string;
  count: number;
  upstream: { site: string; url: string; attribution: string };
  items: Array<{
    id: string;
    rank: number;
    title: string;
    severity: string;
    cvss: number | null;
    exploited: boolean;
    people: number;
    posts: number;
    lastPostedAt: string | null;
  }>;
}

export const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i;

/** Only a validated CVE id is ever passed to a prompt or a detail route. */
export function cveFromText(text: string): string {
  return text.match(CVE_RE)?.[0]?.toUpperCase() ?? '';
}

export const WINDOW_MS: Record<GhmWindow, number> = {
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
};

export function severityTone(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return 'text-rose-600 dark:text-rose-400 border-rose-500/40 bg-rose-500/10';
    case 'HIGH':
      return 'text-orange-600 dark:text-orange-400 border-orange-500/40 bg-orange-500/10';
    case 'MEDIUM':
      return 'text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/10';
    case 'LOW':
      return 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10';
    default:
      return 'text-muted border-line-1 bg-surface-200';
  }
}

/** "Microsoft Office" style label from a CVE row's vendor/product fields. */
export function productLabel(cve: GhmCve): string {
  const parts = [cve.vendor, cve.product].filter((p): p is string => Boolean(p && p.trim()));
  if (parts.length) return parts.join(' ').trim().slice(0, 70);
  return cveFromText(cve.description) ? cve.id : cve.description.split(/[—:;]/)[0]!.trim().slice(0, 60) || cve.id;
}

/** GHM-style signal line: what attackers are actually doing with this CVE. */
export function cveSignal(cve: GhmCve): 'ransomware' | 'exploited' | 'exploit' | 'news' {
  if (cve.kev_ransomware) return 'ransomware';
  if (cve.kev) return 'exploited';
  if (cve.has_exploit) return 'exploit';
  return 'news';
}

export function epssPercent(value?: number): string {
  return value == null ? '' : `${(value * 100).toFixed(1)}%`;
}

export interface GhmSelection {
  event: PulseEvent | null;
  cve: GhmCve | null;
}
