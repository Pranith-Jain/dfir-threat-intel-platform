/**
 * Canonical metadata for the upstream IOC feed sources surfaced across the
 * threat-intel pages (Live IOC stream, SOC IOC dashboard). Centralizing it
 * here keeps the per-source pill colors, human-readable labels, and the SOC
 * criticality weights from drifting apart as new feeds are added.
 *
 * Source keys match the ids emitted by the `/api/v1/live-iocs` handler.
 *
 * - `label`  - human-readable name (used in the derived "Sources: …" prose).
 * - `color`  - Tailwind pill classes (border + bg + text, with dark: variants).
 * - `weight` - SOC criticality source weight (0-60), the dominant signal in
 *              the per-IOC criticality score. Omit to use the default.
 */

export interface SourceMeta {
  label: string;
  color: string;
  weight?: number;
}

/** Default pill classes for an unknown source (faithful to the old maps). */
export const DEFAULT_SOURCE_COLOR = 'border-slate-300 dark:border-line-1 text-slate-500';

/** Default SOC criticality source weight for an unknown source. */
export const DEFAULT_SOURCE_WEIGHT = 20;

export const SOURCE_META: Record<string, SourceMeta> = {
  tweetfeed: {
    label: 'TweetFeed',
    color: 'border-cyan-500/40 bg-cyan-500/10 text-sky-700 dark:text-sky-300',
    weight: 25,
  },
  'sans-isc': {
    label: 'SANS ISC',
    color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    weight: 35,
  },
  'c2-intel': {
    label: 'C2IntelFeeds',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 60,
  },
  'c2-intel-domains': {
    label: 'C2IntelFeeds domains',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 60,
  },
  urlhaus: {
    label: 'URLhaus',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    weight: 45,
  },
  threatfox: {
    label: 'ThreatFox',
    color: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
    weight: 50,
  },
  'emerging-threats': {
    label: 'Emerging Threats compromised-ips',
    color: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    weight: 20,
  },
  'otx-reputation': {
    label: 'AlienVault OTX reputation',
    color: 'border-teal-500/40 bg-teal-500/10 text-teal-700 dark:text-teal-300',
    weight: 30,
  },
  malwarebazaar: {
    label: 'MalwareBazaar',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 40,
  },
  phishtank: {
    label: 'PhishTank',
    color: 'border-pink-500/40 bg-pink-500/10 text-pink-700 dark:text-pink-300',
    weight: 25,
  },
  openphish: {
    label: 'OpenPhish',
    color: 'border-indigo-500/40 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
    weight: 28,
  },
  sslbl: {
    label: 'SSL Blacklist',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 55,
  },
  'sslbl-c2': {
    label: 'SSL Blacklist C2',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 55,
  },
  botvrij: {
    label: 'Botvrij',
    color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    weight: 18,
  },
  'andreafortuna-defacements': {
    label: 'AndreaFortuna Defacements',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    weight: 10,
  },
  'af-defacements': {
    label: 'AndreaFortuna Defacements',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    weight: 10,
  },
  binarydefense: {
    label: 'Binary Defense',
    color: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    weight: 22,
  },
  'binary-defense': {
    label: 'Binary Defense',
    color: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    weight: 22,
  },
  'tor-exit': {
    label: 'Tor Exit Nodes',
    color: 'border-purple-500/40 bg-purple-500/10 text-purple-700 dark:text-purple-300',
  },
  'avanzato-c2': {
    label: 'Avanzato C2',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  'cps-collected': {
    label: 'CPS Collected',
    color: 'border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300',
  },
  'blocklist-de': {
    label: 'Blocklist.de',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 15,
  },
  cinsscore: {
    label: 'CINSscore',
    color: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  },
  cinsarmy: {
    label: 'CINS Army',
    color: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    weight: 12,
  },
  'bbcan177-ips': {
    label: 'BBcan177 IPs',
    color: 'border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300',
  },
  'bbcan177-dnsbl': {
    label: 'BBcan177 DNSBL',
    color: 'border-indigo-500/40 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  },
  'domains-blacklist': {
    label: 'Domains Blacklist',
    color: 'border-slate-500/40 bg-slate-500/10 text-slate-700 dark:text-slate-300',
  },
  'botvrij-urls': {
    label: 'Botvrij URLs',
    color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    weight: 18,
  },
  'bruteforce-blocker': {
    label: 'Brute Force Blocker',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  ipsum: {
    label: 'IPsum',
    color: DEFAULT_SOURCE_COLOR,
    weight: 18,
  },
  'phishing-army': {
    label: 'Phishing Army',
    color: 'border-pink-500/40 bg-pink-500/10 text-pink-700 dark:text-pink-300',
    weight: 20,
  },
  mythreatintel: {
    label: 'MyThreatIntel',
    color: DEFAULT_SOURCE_COLOR,
    weight: 30,
  },
  'crypto-scam': {
    label: 'Crypto Scam',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 15,
  },
  'threatview-ip': {
    label: 'Threatview IP',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    weight: 20,
  },
  'threatview-domains': {
    label: 'Threatview Domains',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    weight: 20,
  },
  'viriback-c2': {
    label: 'ViriBack C2',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 45,
  },
  'certpl-warnings': {
    label: 'CERT.PL',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 20,
  },
  phishunt: {
    label: 'phishunt',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 15,
  },
  'feed-scheduler': {
    label: 'Feed Scheduler',
    color: DEFAULT_SOURCE_COLOR,
    weight: 5,
  },
  swiftioc: {
    label: 'SwiftIOC',
    color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300',
    weight: 25,
  },
  'webamon-campaigns': {
    label: 'Webamon Campaigns',
    color: DEFAULT_SOURCE_COLOR,
    weight: 30,
  },

  // ── Dedicated AI / LLM threat intelligence ─────────────────────────────
  // Violet/fuchsia reserved for the AI-LLM family so these rows are visually
  // separable from the generic blocklist noise around them.
  'ai-honeypots': {
    label: 'AI Honeypot',
    color: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    weight: 40,
  },
  'llm-threatintel': {
    label: 'LLM ThreatIntel',
    color: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
    weight: 45,
  },

  // ── Curated open-source C2 feeds ───────────────────────────────────────
  'foxit-cobaltstrike': {
    label: 'Fox-IT Cobalt Strike',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 55,
  },
  'carbonblack-c2': {
    label: 'Carbon Black C2',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 55,
  },
  'threatview-c2': {
    label: 'Threatview C2',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 50,
  },
  'c2intel-domains': {
    label: 'C2IntelFeeds C2 domains',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 45,
  },
  'threatfox-hostfile': {
    label: 'ThreatFox hosts',
    color: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
    weight: 40,
  },
  'threatfox-urls': {
    label: 'ThreatFox URLs',
    color: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
    weight: 40,
  },
  'threatcluster-ip': {
    label: 'ThreatCluster IP',
    color: DEFAULT_SOURCE_COLOR,
    weight: 25,
  },
  'threatcluster-domains': {
    label: 'ThreatCluster domains',
    color: DEFAULT_SOURCE_COLOR,
    weight: 25,
  },
  'sslbl-ja3': {
    label: 'SSLBL JA3',
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    weight: 45,
  },
  greensnow: {
    label: 'GreenSnow',
    color: DEFAULT_SOURCE_COLOR,
    weight: 20,
  },
  siberkapan: {
    label: 'SiberKapan',
    color: DEFAULT_SOURCE_COLOR,
    weight: 18,
  },
  'bruteforce-login': {
    label: 'Blocklist.de brute-force',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 22,
  },
  'bl-de-ssh': {
    label: 'Blocklist.de SSH',
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    weight: 22,
  },
  'tsirolnik-spam': {
    label: 'tsirolnik spam',
    color: DEFAULT_SOURCE_COLOR,
    weight: 15,
  },
  'botvrij-domain': {
    label: 'Botvrij domains',
    color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    weight: 22,
  },
};

/**
 * Resolve metadata for a source key, falling back to sensible defaults so new
 * feeds render with a neutral pill / label / weight instead of being dropped.
 * The fallback label is the raw key (matching the old behavior where the id
 * was shown verbatim).
 */
export function getSourceMeta(key: string): Required<SourceMeta> {
  const meta = SOURCE_META[key];
  return {
    label: meta?.label ?? key,
    color: meta?.color ?? DEFAULT_SOURCE_COLOR,
    weight: meta?.weight ?? DEFAULT_SOURCE_WEIGHT,
  };
}

/** Pill color classes for a source key (default-safe). */
export function sourceColor(key: string): string {
  return SOURCE_META[key]?.color ?? DEFAULT_SOURCE_COLOR;
}

/** SOC criticality source weight for a source key (default-safe). */
export function sourceWeight(key: string): number {
  return SOURCE_META[key]?.weight ?? DEFAULT_SOURCE_WEIGHT;
}

/**
 * Derive the "Sources: …" prose from a live sources array (or any source-key
 * list) so the sentence stays in sync with whatever the feed actually returns.
 * Falls back to the canonical key labels for the full catalog when given no
 * keys (e.g. before the first fetch).
 */
export function sourcesSentence(keys?: readonly { id: string }[] | readonly string[]): string {
  const ids: string[] =
    keys && keys.length ? keys.map((k) => (typeof k === 'string' ? k : k.id)) : Object.keys(SOURCE_META);
  const seen = new Set<string>();
  const labels: string[] = [];
  for (const id of ids) {
    const label = getSourceMeta(id).label;
    if (seen.has(label)) continue;
    seen.add(label);
    labels.push(label);
  }
  return labels.join(', ');
}
