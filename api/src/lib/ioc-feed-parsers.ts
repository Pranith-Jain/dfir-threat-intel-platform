/**
 * ioc-feed-parsers.ts
 * Pure parsing functions for each IOC feed format.
 * No network calls — takes raw text/object, returns normalized entries.
 */

export type IocType = 'url' | 'domain' | 'ipv4' | 'hash' | 'cve';

export interface IocEntry {
  type: IocType;
  value: string;
  context?: string;
  timestamp?: string;
}

export interface IocFeedSummary {
  source:
    | 'urlhaus'
    | 'malwarebazaar'
    | 'threatfox'
    | 'openphish'
    | 'cisa-kev'
    | 'blocklist-de'
    | 'binary-defense'
    | 'ipsum'
    | 'phishing-army'
    | 'tweetfeed'
    | 'bitwire'
    | 'bitwire-inbound'
    | 'malwareworld'
    | 'threatview-ip'
    | 'threatview-domains'
    | 'viriback-c2'
    | 'certpl-warnings'
    | 'phishunt'
    | 'swiftioc'
    // Dedicated AI / LLM threat intelligence — see feed-curation.ts.
    | 'ai-honeypots'
    | 'llm-threatintel'
    // Curated open-source C2 / blocklist feeds.
    | 'foxit-cobaltstrike'
    | 'carbonblack-c2'
    | 'sslbl-ja3';
  source_name: string;
  fetched_at: string;
  count: number;
  total_in_feed?: number;
  entries: IocEntry[];
  cache_control_seconds: number;
}

const CAP = 100;
const CACHE_TTL = 1800;

/** Cap that effectively means "no cap" — used by briefing-builder which needs the full feed for date-window filtering. */
export const UNCAPPED = Number.MAX_SAFE_INTEGER;

/** Strip surrounding double-quotes from a CSV field value */
function unquote(s: string): string {
  const t = s.trim();
  if (t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1).replace(/""/g, '"');
  }
  return t;
}

/**
 * Split a CSV line respecting double-quoted fields (basic RFC 4180).
 * Does NOT handle newlines inside quoted fields (feeds don't use them).
 */
function splitCsvLine(line: string): string[] {
  const fields: string[] = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuote && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuote = !inQuote;
      }
    } else if (ch === ',' && !inQuote) {
      fields.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

/** Parse non-empty, non-comment lines from a CSV body */
function csvLines(body: string): string[][] {
  return body
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'))
    .map(splitCsvLine);
}

// ─── URLhaus ────────────────────────────────────────────────────────────────
// Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
// Feed is newest-first → take first CAP rows.

export function parseUrlhaus(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 3) continue;
    const value = unquote(cols[2] ?? '');
    if (!value) continue;
    const threat = unquote(cols[5] ?? '');
    const tags = unquote(cols[6] ?? '');
    const context = [threat, tags].filter(Boolean).join(' | ') || undefined;
    const timestamp = unquote(cols[1] ?? '') || undefined;
    entries.push({ type: 'url', value, context, timestamp });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── MalwareBazaar ──────────────────────────────────────────────────────────
// Columns: first_seen_utc(0), sha256_hash(1), md5_hash(2), sha1_hash(3),
//          reporter(4), file_name(5), file_type_guess(6), mime_type(7),
//          signature(8), clamav(9), vtpercent(10), imphash(11), ssdeep(12), tlsh(13)
// Feed is newest-first → take first CAP rows.

export function parseMalwarebazaar(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 2) continue;
    const value = unquote(cols[1] ?? '');
    if (!value) continue;
    const signature = unquote(cols[8] ?? '');
    const fileType = unquote(cols[6] ?? '');
    const context = [signature, fileType].filter(Boolean).join(' | ') || undefined;
    const timestamp = unquote(cols[0] ?? '') || undefined;
    entries.push({ type: 'hash', value, context, timestamp });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── ThreatFox ───────────────────────────────────────────────────────────────
// Columns: first_seen(0), ioc_id(1), ioc_value(2), ioc_type(3),
//          threat_type(4), fk_malware(5), malware_alias(6), malware_printable(7),
//          last_seen(8), confidence_level(9), reference(10), tags(11),
//          anonymous(12), reporter(13)
// ioc_type → our type mapping:
//   ip:port → ipv4 (strip port)
//   domain → domain
//   url → url
//   md5_hash / sha1_hash / sha256_hash → hash

function threatfoxIocType(raw: string): IocType | null {
  const t = raw.toLowerCase().trim();
  if (t.startsWith('ip:port')) return 'ipv4';
  if (t === 'domain') return 'domain';
  if (t === 'url') return 'url';
  if (t.includes('hash')) return 'hash';
  return null;
}

export function parseThreatfox(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 4) continue;
    const rawType = unquote(cols[3] ?? '');
    const type = threatfoxIocType(rawType);
    if (!type) continue;
    let value = unquote(cols[2] ?? '');
    if (!value) continue;
    // For ip:port, strip the port part
    if (type === 'ipv4') {
      const colon = value.lastIndexOf(':');
      if (colon !== -1 && colon > value.indexOf(':')) {
        // IPv6-style or ip:port — strip port if it's ip:port
        value = value.substring(0, colon);
      } else if (colon !== -1) {
        value = value.substring(0, colon);
      }
    }
    const context = unquote(cols[7] ?? '') || undefined;
    const timestamp = unquote(cols[0] ?? '') || undefined;
    entries.push({ type, value, context, timestamp });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── OpenPhish ───────────────────────────────────────────────────────────────
// Plain text, one URL per line.

export function parseOpenPhish(body: string, cap: number = CAP): IocEntry[] {
  return body
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && (l.startsWith('http://') || l.startsWith('https://')))
    .slice(0, cap)
    .map((value) => ({ type: 'url' as IocType, value }));
}

// ─── CISA KEV ────────────────────────────────────────────────────────────────
// JSON: { vulnerabilities: Array<{ cveID, vendorProject, product, vulnerabilityName, dateAdded, ... }> }
// Sorted oldest-first in the feed → take last CAP rows (newest).

interface CisaVuln {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
}

interface CisaKevJson {
  vulnerabilities?: CisaVuln[];
  total?: number;
}

export function parseCisaKev(body: string): { entries: IocEntry[]; total: number } {
  let parsed: CisaKevJson;
  try {
    parsed = JSON.parse(body) as CisaKevJson;
  } catch {
    return { entries: [], total: 0 };
  }
  const vulns = parsed.vulnerabilities ?? [];
  const total = parsed.total ?? vulns.length;
  // Sort by dateAdded DESC so newest entries come first, then take CAP
  const sorted = [...vulns].sort((a, b) => (b.dateAdded ?? '').localeCompare(a.dateAdded ?? ''));
  const slice = sorted.slice(0, CAP);
  const entries: IocEntry[] = [];
  for (const v of slice) {
    const value = v.cveID ?? '';
    if (!value) continue;
    const context = [v.vendorProject, v.product, v.vulnerabilityName].filter(Boolean).join(' | ') || undefined;
    const timestamp = v.dateAdded || undefined;
    entries.push({ type: 'cve', value, context, timestamp });
  }
  return { entries, total };
}

// ─── Plain-text IP / CIDR blocklists ────────────────────────────────────────
// Used by: blocklist.de, Binary Defense, bitwire, sslbl. One IP/CIDR per line,
// optional comment lines starting with #.

const IPV4_LINE_RE = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/;

export function parsePlainTextIps(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    const match = trimmed.match(IPV4_LINE_RE);
    if (!match) continue;
    entries.push({ type: 'ipv4', value: match[0] });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── Ipsum (stamparm) ────────────────────────────────────────────────────────
// Plain text: "<ip>\t<score>" or just "<ip>". Score is the number of source
// blocklists that flagged it — higher means stronger consensus.

export function parseIpsum(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split(/\s+/);
    const ip = parts[0];
    if (!ip || !IPV4_LINE_RE.test(ip)) continue;
    const score = parts[1];
    entries.push({ type: 'ipv4', value: ip, context: score ? `consensus: ${score} sources` : undefined });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── Phishing Army domain blocklist ─────────────────────────────────────────
// Format follows hosts(5) syntax: `0.0.0.0 evil.example.com` or just `evil.example.com`.

const DOMAIN_LINE_RE = /^(?:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function parsePhishingArmy(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;
    // Strip leading "0.0.0.0 " or "127.0.0.1 " from hosts-format lines
    const candidate = trimmed.replace(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+/, '').trim();
    if (!DOMAIN_LINE_RE.test(candidate)) continue;
    entries.push({ type: 'domain', value: candidate });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── SwiftIOC high-confidence feed (PKHarsimran) ─────────────────────────
// CSV: indicator,type,source,first_seen,last_seen,confidence,score,
// sightings,tlp,tags,reference,context. Indicators arrive DEFANGED
// (77[.]239[.]124[.]108) — refanged here (live-iocs refangs again
// downstream, idempotent). Feed is score-desc; the file is ~3MB so the
// standard per-feed cap takes the most-corroborated head.

const SWIFTIOC_TYPES = new Set(['ipv4', 'domain', 'url', 'hash']);

function refangIndicator(v: string): string {
  return v
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/^hxxps?/i, (m) => (m.length === 5 ? 'https' : 'http'));
}

export function parseSwiftioc(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 7) continue;
    const rawType = unquote(cols[1] ?? '').toLowerCase();
    if (!SWIFTIOC_TYPES.has(rawType)) continue;
    const value = refangIndicator(unquote(cols[0] ?? ''));
    if (!value || value.length < 3) continue;
    const score = Number(unquote(cols[6] ?? ''));
    const sightings = unquote(cols[7] ?? '');
    const tags = unquote(cols[9] ?? '');
    const context = [`score ${Number.isFinite(score) ? score : '?'}`, sightings ? `${sightings} sightings` : '', tags]
      .filter(Boolean)
      .join(' · ');
    entries.push({
      type: rawType as IocEntry['type'],
      value,
      context: context || undefined,
      timestamp: unquote(cols[4] ?? '') || undefined,
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── TweetFeed (0xDanielLopez) ──────────────────────────────────────────────
// Plain CSV without quotes: date,source,type,ioc,tags,info_url
// `type` is one of: domain, url, ip, sha256, md5, sha1
// Newest-last → reverse iterate to take newest first.

function tweetfeedType(raw: string): IocType | null {
  const t = raw.toLowerCase().trim();
  if (t === 'ip') return 'ipv4';
  if (t === 'domain') return 'domain';
  if (t === 'url') return 'url';
  if (t === 'sha256' || t === 'md5' || t === 'sha1') return 'hash';
  return null;
}

export function parseTweetFeed(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  const lines = body
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  // Iterate newest-first
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line) continue;
    const cols = line.split(',');
    if (cols.length < 4) continue;
    const typeCol = cols[2];
    if (!typeCol) continue;
    const type = tweetfeedType(typeCol);
    if (!type) continue;
    const value = cols[3];
    if (!value) continue;
    // TweetFeed CSV is unquoted and untrusted. Reject malformed IP values so a
    // crafted field (spaces/quotes/newlines) can't poison the live-IOC set or,
    // via blocklist-builder, inject rules into the downloadable firewall lists.
    if (
      type === 'ipv4' &&
      !/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(value)
    )
      continue;
    const tags = cols[4] || undefined;
    const reporter = cols[1] || undefined;
    const context = [reporter, tags].filter(Boolean).join(' | ') || undefined;
    const timestamp = cols[0] || undefined;
    entries.push({ type, value, context, timestamp });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── SANS ISC top attack sources ────────────────────────────────────────────
// JSON: [{ ip, attacks, count, firstseen, lastseen }, ...]
// Newest-touched first (ISC sorts by attack count desc, lastseen is recent).

interface SansIscEntry {
  ip?: string;
  attacks?: number;
  count?: number;
  lastseen?: string;
}

export function parseSansIsc(body: string, cap: number = CAP): IocEntry[] {
  let parsed: SansIscEntry[];
  try {
    parsed = JSON.parse(body) as SansIscEntry[];
  } catch {
    return [];
  }
  const entries: IocEntry[] = [];
  for (const e of parsed) {
    const ip = e.ip?.trim();
    if (!ip || !IPV4_LINE_RE.test(ip)) continue;
    const attacks = e.attacks ?? 0;
    const count = e.count ?? 0;
    entries.push({
      type: 'ipv4',
      value: ip,
      context: `attacks=${attacks} · sensors=${count}`,
      timestamp: e.lastseen,
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── C2IntelFeeds (drb-ra) — Cobalt Strike + similar C2 IPs ─────────────────
// CSV: header `#ip,ioc` then rows `<ip>,<context>`. Context is e.g.
// "Possible Cobaltstrike C2 IP", "Sliver C2 server" — usable as-is for
// downstream display.

export function parseC2IntelFeeds(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf(',');
    const ip = idx === -1 ? trimmed : trimmed.slice(0, idx).trim();
    const context = idx === -1 ? undefined : trimmed.slice(idx + 1).trim() || undefined;
    if (!IPV4_LINE_RE.test(ip)) continue;
    entries.push({ type: 'ipv4', value: ip, context });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── AlienVault OTX reputation ──────────────────────────────────────────────
// Plain text with comments. Data lines: `<ip> # <classification> <country>,,<lat>,<lon>`
// Classification examples: "Malicious Host", "Scanning Host", "Spamming".

export function parseAlienVaultReputation(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Split on '#' to separate IP from classification metadata.
    const hashIdx = trimmed.indexOf('#');
    const ip = (hashIdx === -1 ? trimmed : trimmed.slice(0, hashIdx)).trim();
    if (!IPV4_LINE_RE.test(ip)) continue;
    const meta = hashIdx === -1 ? '' : trimmed.slice(hashIdx + 1).trim();
    // Take the classification phrase up to first comma (drops lat/lon noise).
    const classification = meta.split(',')[0]?.trim() || undefined;
    entries.push({ type: 'ipv4', value: ip, context: classification });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── BlocklistProject hosts-format domain lists ──────────────────────────────
// Format: `0.0.0.0 <domain>` (hosts(5) style). Skips comments. Used for
// category-specific lists (ransomware, scam, malware, phishing).

const HOSTS_LINE_RE = /^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+)$/i;

export function parseHostsFormat(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;
    const match = HOSTS_LINE_RE.exec(trimmed);
    if (!match) continue;
    const domain = match[1]!.toLowerCase();
    // Skip the localhost-style entries that some hosts files include.
    if (domain === 'localhost' || domain === 'localhost.localdomain') continue;
    entries.push({ type: 'domain', value: domain });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── SSLBL (abuse.ch) — SSL/TLS-fingerprinted botnet C2 IPs ──────────────────
// CSV: "Firstseen","DstIP","DstPort". Comment lines start with '#'.

export function parseSslblC2(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const cols = trimmed.split(',').map((c) => c.replace(/^"|"$/g, '').trim());
    const firstSeen = cols[0];
    const ip = cols[1];
    const port = cols[2];
    if (!ip || !IPV4_LINE_RE.test(ip)) continue;
    entries.push({
      type: 'ipv4',
      value: ip,
      context: port ? `SSL/TLS C2 :${port}` : 'SSL/TLS C2',
      timestamp: firstSeen && /^\d{4}-\d\d-\d\d/.test(firstSeen) ? firstSeen : undefined,
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ─── Source metadata ─────────────────────────────────────────────────────────

export type SourceId = IocFeedSummary['source'];

export interface FeedSource {
  id: SourceId;
  name: string;
  url: string;
}

export const FEED_SOURCES: Record<SourceId, FeedSource> = {
  urlhaus: {
    id: 'urlhaus',
    name: 'Abuse.ch URLhaus',
    url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
  },
  malwarebazaar: {
    id: 'malwarebazaar',
    name: 'Abuse.ch MalwareBazaar',
    url: 'https://bazaar.abuse.ch/export/csv/recent/',
  },
  threatfox: {
    id: 'threatfox',
    name: 'Abuse.ch ThreatFox',
    url: 'https://threatfox.abuse.ch/export/csv/recent/',
  },
  openphish: {
    id: 'openphish',
    name: 'OpenPhish',
    url: 'https://openphish.com/feed.txt',
  },
  'cisa-kev': {
    id: 'cisa-kev',
    name: 'CISA KEV',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  },
  'blocklist-de': {
    id: 'blocklist-de',
    name: 'Blocklist.de (last 48h)',
    url: 'https://lists.blocklist.de/lists/all.txt',
  },
  'binary-defense': {
    id: 'binary-defense',
    name: 'Binary Defense Banlist',
    url: 'https://www.binarydefense.com/banlist.txt',
  },
  ipsum: {
    id: 'ipsum',
    name: 'Ipsum (3+ source consensus)',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
  },
  'phishing-army': {
    id: 'phishing-army',
    name: 'Phishing Army',
    url: 'https://phishing.army/download/phishing_army_blocklist.txt',
  },
  tweetfeed: {
    id: 'tweetfeed',
    name: 'TweetFeed (today)',
    url: 'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv',
  },
  bitwire: {
    id: 'bitwire',
    name: 'Bitwire IP Blocklist (outbound)',
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt',
  },
  'bitwire-inbound': {
    id: 'bitwire-inbound',
    name: 'Bitwire IP Blocklist (inbound)',
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt',
  },
  malwareworld: {
    id: 'malwareworld',
    name: 'MalwareWorld Bad Reputation',
    url: 'https://malwareworld.com/data/type_BadReputation_ips.txt',
  },
  'threatview-ip': {
    id: 'threatview-ip',
    name: 'Threatview.io IP Blocklist',
    url: 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt',
  },
  'threatview-domains': {
    id: 'threatview-domains',
    name: 'Threatview.io Domain Blocklist',
    url: 'https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt',
  },
  'viriback-c2': {
    id: 'viriback-c2',
    name: 'ViriBack C2 Tracker',
    url: 'https://tracker.viriback.com/dump.php',
  },
  'certpl-warnings': {
    id: 'certpl-warnings',
    name: 'CERT.PL Warning List',
    url: 'https://hole.cert.pl/domains/v2/domains.txt',
  },
  phishunt: {
    id: 'phishunt',
    name: 'phishunt',
    url: 'https://phishunt.io/feed.txt',
  },
  swiftioc: {
    id: 'swiftioc',
    name: 'SwiftIOC High-Confidence',
    url: 'https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/main/public/iocs/high_confidence.csv',
  },
  // ── Dedicated AI / LLM threat intelligence ─────────────────────────────
  // JSON upstreams, so `url` is informational here — buildSummary dispatches
  // on the source id and the JSON branch ignores it.
  'ai-honeypots': {
    id: 'ai-honeypots',
    name: 'AI Honeypot Observatory',
    url: 'https://ai-honeypots.com/feeds/iocs.json',
  },
  'llm-threatintel': {
    id: 'llm-threatintel',
    name: 'LLM ThreatIntel',
    url: 'https://llm-threatintel.com/data/iocs.json',
  },
  // ── Curated open-source C2 feeds ───────────────────────────────────────
  'foxit-cobaltstrike': {
    id: 'foxit-cobaltstrike',
    name: 'Fox-IT Cobalt Strike servers',
    url: 'https://raw.githubusercontent.com/fox-it/cobaltstrike-extraneous-space/master/cobaltstrike-servers.csv',
  },
  'carbonblack-c2': {
    id: 'carbonblack-c2',
    name: 'Carbon Black active C2',
    url: 'https://raw.githubusercontent.com/carbonblack/active_c2_ioc_public/main/cobaltstrike/actor-specific/cobaltstrike_pyxie.csv',
  },
  'sslbl-ja3': {
    id: 'sslbl-ja3',
    name: 'abuse.ch SSLBL JA3 fingerprints',
    url: 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv',
  },
};

// ─── Plain URL list (one URL per line, http-prefixed) ────────────────────────
// Used by: Phishing.Database, VXVault, and similar URL-only feeds.

export function parseUrlList(body: string, cap: number = CAP): IocEntry[] {
  return body
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('http'))
    .slice(0, cap)
    .map((value) => ({ type: 'url', value }));
}

// ─── ViriBack C2 Tracker ────────────────────────────────────────────────────
// CSV: Malware Family,URL,IP Address,First Seen

export function parseViriback(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 4) continue;
    const family = unquote(cols[0] ?? '');
    const url = unquote(cols[1] ?? '');
    const ip = unquote(cols[2] ?? '');
    const timestamp = unquote(cols[3] ?? '') || undefined;
    const context = `ViriBack C2: ${family || 'unknown'}`;
    if (ip) {
      entries.push({ type: 'ipv4', value: ip, context, timestamp });
      if (entries.length >= cap) break;
    }
    if (url && url.startsWith('http')) {
      entries.push({ type: 'url', value: url, context, timestamp });
      if (entries.length >= cap) break;
    }
  }
  return entries;
}

// ─── Threatview.io Domain Blocklist ─────────────────────────────────────────
// Plain text, one domain per line.

const BARE_DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function parseThreatviewDomains(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    if (!BARE_DOMAIN_RE.test(trimmed)) continue;
    entries.push({ type: 'domain', value: trimmed });
    if (entries.length >= cap) break;
  }
  return entries;
}

// ══════════════════════════════════════════════════════════════════════════
// Dedicated AI / LLM threat-intelligence sources
// ══════════════════════════════════════════════════════════════════════════
//
// These two upstreams are LLM-security-specific rather than generic blocklists:
// they carry per-indicator ATTRIBUTION (actor category, ATT&CK techniques,
// honeypot persona/model detail) that a plain IP list cannot. That extra
// context is the whole reason to ingest them — it is what makes a row
// actionable rather than just another address to block.

/**
 * Normalize any parseable timestamp to canonical `…Z` ISO 8601.
 *
 * NOT cosmetic. `finalizeLiveIocs` filters freshness with a *lexicographic*
 * comparison (`item.observed_at >= cutoffIso`) and sorts newest-first the same
 * way. Upstreams publish mixed offset formats — ai-honeypots emits
 * `2026-10-01T07:14:38.806561+00:00`, llm-threatintel emits a date-only
 * `2026-09-23`. `+00:00` sorts *before* `Z` (`+` is 0x2B, `Z` is 0x5A), so an
 * unconverted timestamp sits up to a fraction of a second "in the past"
 * relative to the cutoff and a date-only value sorts ahead of every same-day
 * timestamped row. Both corrupt the ordering and the staleness window.
 *
 * Anything unparseable returns undefined so the item is treated as an undated
 * bulk-snapshot entry rather than carrying a garbage timestamp that fails the
 * lexicographic test and gets silently dropped as stale.
 */
export function toIsoTimestamp(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const t = s.trim();
  if (!t) return undefined;
  const ms = Date.parse(t);
  if (!Number.isFinite(ms)) return undefined;
  return new Date(ms).toISOString();
}

/**
 * AI Honeypot Observatory (ai-honeypots.com) — `feeds/iocs.json`.
 *
 * Top level is `{ feed_id, published, window_days, tlp, license, taxonomy,
 * summary, indicators: [...] }`. Each indicator carries `ioc_type` (only `ip`
 * today), `actor_category`, `confidence` (low…very-high), `ttps`,
 * `first_seen` / `last_seen`, and hit/persona counters.
 *
 * Feed order is already sorted most-confident-first upstream, so a plain
 * `cap` slice keeps the highest-signal rows — no re-sort needed.
 *
 * `last_seen` (not `first_seen`) is the observation timestamp: it is what the
 * live-IOC freshness window should key on, since a long-lived scanner keeps
 * producing fresh hits and must not age out.
 */
export function parseAiHoneypots(body: string, cap: number = CAP): IocEntry[] {
  let doc: { indicators?: unknown };
  try {
    doc = JSON.parse(body) as { indicators?: unknown };
  } catch {
    return [];
  }
  if (!Array.isArray(doc.indicators)) return [];
  const entries: IocEntry[] = [];
  for (const raw of doc.indicators) {
    const r = raw as {
      ioc_type?: string;
      value?: string;
      actor_category?: string;
      confidence?: string;
      ttps?: string[];
      total_hits?: number;
      distinct_personas?: number;
      last_seen?: string;
      first_seen?: string;
    };
    const value = (r.value ?? '').trim();
    if (!r.ioc_type || !value) continue;
    if (r.ioc_type !== 'ip' && r.ioc_type !== 'ipv4') continue;
    if (!IPV4_LINE_RE.test(value)) continue;
    const bits = [
      r.actor_category,
      r.confidence ? `conf:${r.confidence}` : undefined,
      r.total_hits !== undefined ? `hits:${r.total_hits}` : undefined,
      r.distinct_personas !== undefined ? `personas:${r.distinct_personas}` : undefined,
      r.ttps?.length ? r.ttps.join(',') : undefined,
    ].filter(Boolean);
    const timestamp = toIsoTimestamp(r.last_seen ?? r.first_seen);
    entries.push({
      type: 'ipv4',
      value,
      context: `AI honeypot — ${bits.join(' | ')}`,
      ...(timestamp ? { timestamp } : {}),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * LLM ThreatIntel (llm-threatintel.com) — `data/iocs.json`.
 *
 * `{ last_updated, iocs: [{ value, type, context, first_seen, source,
 * campaign, status }] }`. `type` is one of domain/ipv4/url/hash per the
 * upstream feed, mapped onto our IocType.
 *
 * Lifecycle filtering matches `buildAiLlmIntel` — the two must agree or the live
 * stream and the AI/LLM page disagree about how many indicators are current.
 * Upstream statuses observed on the live feed (2026-10-05): active 684, unknown
 * 22, removed 53, inactive 10. Only `removed` and `inactive` are dropped:
 * `unknown` means "not yet triaged", not "retired", so filtering it would hide
 * indicators the upstream has published but not yet adjudicated.
 */
export function parseLlmThreatintelIocs(body: string, cap: number = CAP): IocEntry[] {
  let doc: { iocs?: unknown };
  try {
    doc = JSON.parse(body) as { iocs?: unknown };
  } catch {
    return [];
  }
  if (!Array.isArray(doc.iocs)) return [];
  const entries: IocEntry[] = [];
  for (const raw of doc.iocs) {
    const r = raw as {
      value?: string;
      type?: string;
      context?: string;
      first_seen?: string;
      source?: string;
      campaign?: string;
      status?: string;
    };
    const value = (r.value ?? '').trim();
    if (!value || !r.type) continue;
    if (r.status && r.status !== 'active' && r.status !== 'unknown') continue;
    const type = LLM_TYPE_MAP[r.type];
    if (!type) continue;
    const bits = [r.source, r.campaign].filter(Boolean);
    const base = r.context ?? 'LLM threat intel';
    // Upstream ships date-only `first_seen`; canonicalize so the lexicographic
    // freshness filter in finalizeLiveIocs compares like with like.
    const timestamp = toIsoTimestamp(r.first_seen);
    entries.push({
      type,
      value,
      context: bits.length ? `${base} (${bits.join(' · ')})` : base,
      ...(timestamp ? { timestamp } : {}),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/** llm-threatintel `type` values → our IocType. */
const LLM_TYPE_MAP: Record<string, IocType> = {
  domain: 'domain',
  ipv4: 'ipv4',
  ip: 'ipv4',
  url: 'url',
  hash: 'hash',
};

// ══════════════════════════════════════════════════════════════════════════
// Curated open-source feeds (see feed-curation.ts for the audit + provenance)
// ══════════════════════════════════════════════════════════════════════════

/**
 * Normalize the several loose date formats these feeds publish into ISO.
 * Handles: `2017-06-20`, `2017-06-20 12:00:00`, `2020/09/04 23:32:24`, and
 * Threatview's `08 February 2026 03:26 PM UTC`.
 */
export function looseDateToIso(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const t = s.trim();
  if (!t) return undefined;
  // ISO-ish (already contains T, or date-only): let Date.parse handle it.
  if (/^\d{4}-\d{2}-\d{2}/.test(t)) {
    const v = Date.parse(t.includes('T') ? t : t.replace(' ', 'T'));
    return Number.isFinite(v) ? new Date(v).toISOString() : undefined;
  }
  // `2020/09/04 23:32:24`
  const slash = /^(\d{4})\/(\d{2})\/(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/.exec(t);
  if (slash) {
    const [, y, mo, d, h, mi, sec] = slash;
    const v = Date.UTC(+y!, +mo! - 1, +d!, +h!, +mi!, +sec!);
    return Number.isFinite(v) ? new Date(v).toISOString() : undefined;
  }
  // `08 February 2026 03:26 PM UTC`
  const word = /^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})\s+(\d{1,2}):(\d{2})\s*(AM|PM)/i.exec(t);
  if (word) {
    const [, d, mon, y, h, mi, ampm] = word;
    const months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
    const mi2 = months.indexOf((mon ?? '').slice(0, 3).toLowerCase());
    if (mi2 >= 0) {
      let hour = +h!;
      if (/pm/i.test(ampm ?? '') && hour < 12) hour += 12;
      if (/am/i.test(ampm ?? '') && hour === 12) hour = 0;
      const v = Date.UTC(+y!, mi2, +d!, hour, +mi!);
      return Number.isFinite(v) ? new Date(v).toISOString() : undefined;
    }
  }
  return undefined;
}

/**
 * Fox-IT "Cobalt Strike extraneous space" — `cobaltstrike-servers.csv`.
 * Header: `ip,port,first_seen,last_seen`.
 */
export function parseCobaltStrikeCsv(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 2) continue;
    const ip = unquote(cols[0] ?? '');
    if (!IPV4_LINE_RE.test(ip)) continue; // also skips the header row
    const port = unquote(cols[1] ?? '');
    entries.push({
      type: 'ipv4',
      value: ip,
      context: port ? `Cobalt Strike team server :${port}` : 'Cobalt Strike team server',
      timestamp: looseDateToIso(unquote(cols[3] ?? '') || unquote(cols[2] ?? '')),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * Carbon Black active-C2 program — `cobaltstrike_pyxie.csv`.
 *
 * TAB-separated (despite the `.csv` extension):
 * `c2_ip, first_seen, last_seen, protocol, port, version, watermark,
 *  pubkey_md5, domains, host_header`. Dates use `2020/09/04 23:32:24`.
 */
export function parseCarbonBlackC2(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  const lines = body.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const cols = trimmed.split('\t');
    const ip = (cols[0] ?? '').trim();
    if (!IPV4_LINE_RE.test(ip)) continue;
    const protocol = (cols[3] ?? '').trim();
    const port = (cols[4] ?? '').trim();
    const version = (cols[5] ?? '').trim();
    const bits = [protocol && port ? `${protocol}:${port}` : undefined, version ? `CS ${version}` : undefined].filter(
      Boolean
    );
    entries.push({
      type: 'ipv4',
      value: ip,
      context: `Cobalt Strike C2 — ${bits.join(' · ') || 'Carbon Black active C2'}`,
      timestamp: looseDateToIso((cols[2] ?? cols[1] ?? '').trim()),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * Threatview.io high-confidence Cobalt Strike C2.
 * CSV: `IP, Date of Detection, Host, Protocol, Beacon Config, Comment`.
 * Detection date is prose: `08 February 2026 03:26 PM UTC`.
 */
export function parseThreatviewC2(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 2) continue;
    const ip = unquote(cols[0] ?? '');
    if (!IPV4_LINE_RE.test(ip)) continue;
    const protocol = unquote(cols[3] ?? '');
    const beacon = unquote(cols[4] ?? '');
    entries.push({
      type: 'ipv4',
      value: ip,
      context: `Cobalt Strike C2 — ${protocol || 'unknown protocol'}${beacon ? ` ${beacon}` : ''}`,
      timestamp: looseDateToIso(unquote(cols[1] ?? '')),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * abuse.ch ThreatFox **hostfile** — `downloads/hostfile/`.
 *
 * NB: the file is hosts(5)-format and its address column is the literal
 * placeholder `127.0.0.1` on ALL 38,123 rows (verified 2026-10-05) — the
 * upstream ships a DOMAIN blocklist in hosts syntax. Emitting that column would
 * produce 38k copies of loopback, so only the hostname is taken, and the IP is
 * emitted only if an upstream row ever ships a real one.
 */
export function parseThreatfoxHostfile(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  const seen = new Set<string>();
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const tab = trimmed.indexOf('\t');
    const addr = tab === -1 ? '' : trimmed.slice(0, tab).trim();
    const host = (tab === -1 ? trimmed : trimmed.slice(tab + 1).trim()).toLowerCase();
    if (DOMAIN_LINE_RE.test(host) && !seen.has(host)) {
      seen.add(host);
      entries.push({ type: 'domain', value: host, context: 'ThreatFox botnet C2 host' });
      if (entries.length >= cap) break;
    }
    // A non-placeholder address column (upstream has never shipped one, but the
    // format allows it) is still a usable indicator.
    if (addr && addr !== '127.0.0.1' && addr !== '0.0.0.0' && IPV4_LINE_RE.test(addr)) {
      const key = `ip:${addr}`;
      if (!seen.has(key)) {
        seen.add(key);
        entries.push({ type: 'ipv4', value: addr, context: 'ThreatFox botnet C2 host' });
        if (entries.length >= cap) break;
      }
    }
  }
  return entries;
}

/**
 * abuse.ch ThreatFox recent URLs — `export/csv/urls/recent/`.
 *
 * Quoted CSV, columns verified against the live feed (2026-10-05):
 *   0 timestamp · 1 id · 2 url · 3 ioc_type · 4 usage_type · 5 tag ·
 *   6 malware (literal "None" when unnamed) · 7 family ("ClearFake") ·
 *   8 empty · 9 confidence · …
 *
 * Column 6 is NOT the family — it is the malware name, which upstream fills
 * with the string "None" when there isn't one. Prefer the non-placeholder
 * family at column 7, then the tag at column 5 (which carries the more
 * specific `js.clearfake` taxonomy), so a row is never attributed to "None".
 */
export function parseThreatfoxUrls(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 3) continue;
    const url = unquote(cols[2] ?? '');
    if (!url.startsWith('http')) continue;
    // First column that carries something other than a null placeholder wins.
    const attribution = [cols[7], cols[6], cols[5]]
      .map((c) => unquote(c ?? ''))
      .find((c) => c && c.toLowerCase() !== 'none' && c.toLowerCase() !== 'n/a');
    entries.push({
      type: 'url',
      value: url,
      context: attribution ? `ThreatFox payload delivery — ${attribution}` : 'ThreatFox payload delivery',
      timestamp: toIsoTimestamp(unquote(cols[0] ?? '')),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * C2IntelFeeds C2-domain lists — `#domain,ioc,uri_path`.
 * The `ioc` column carries the attribution ("Possible Cobalt Strike C2 Domain").
 */
export function parseC2IntelDomains(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const cols of csvLines(body)) {
    if (cols.length < 2) continue;
    const domain = unquote(cols[0] ?? '').toLowerCase();
    if (!DOMAIN_LINE_RE.test(domain)) continue; // skips the `#domain` header
    const attribution = unquote(cols[1] ?? '');
    const path = unquote(cols[2] ?? '');
    entries.push({
      type: 'domain',
      value: domain,
      context: [attribution || 'C2 domain', path ? `uri ${path}` : ''].filter(Boolean).join(' · '),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * Botvrij.eu domain blocklist — `blocklist_domain.csv`.
 *
 * Upstream emits a CSV header (`value,decay_sore,value_type,event_id,event_info`
 * — note the upstream typo in `decay_sore`) and then one BARE DOMAIN per line,
 * so the rows are not actually CSV records. `csvLines` would mis-split a domain
 * containing a comma; take the raw line instead.
 */
export function parseBotvrijDomains(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const raw of body.split('\n')) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (trimmed.toLowerCase().startsWith('value,')) continue; // header
    const domain = trimmed.toLowerCase();
    if (!DOMAIN_LINE_RE.test(domain)) continue;
    entries.push({ type: 'domain', value: domain });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * abuse.ch SSLBL JA3 fingerprint blacklist — `ja3_fingerprints.csv`.
 * Rows: `ja3_md5, first_seen, last_seen, malware_family`, no header, banner
 * of `#` comments above.
 *
 * A JA3 fingerprint IS the MD5 of a hashed TLS ClientHello, so `hash` is the
 * correct IocType — the value drops straight into JA3 detection rules.
 */
export function parseSslblJa3(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const cols = trimmed.split(',');
    const ja3 = (cols[0] ?? '').trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(ja3)) continue;
    const family = (cols[3] ?? '').trim();
    entries.push({
      type: 'hash',
      value: ja3,
      context: family ? `JA3 client fingerprint — ${family}` : 'JA3 client fingerprint',
      timestamp: looseDateToIso((cols[2] ?? cols[1] ?? '').trim()),
    });
    if (entries.length >= cap) break;
  }
  return entries;
}

/** One bare domain per line (tsirolnik spam-domains, threatcluster domains…). */
export function parsePlainDomainList(body: string, cap: number = CAP): IocEntry[] {
  const entries: IocEntry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    const domain = trimmed.toLowerCase();
    if (!DOMAIN_LINE_RE.test(domain)) continue;
    entries.push({ type: 'domain', value: domain });
    if (entries.length >= cap) break;
  }
  return entries;
}

/**
 * Build a normalized IocFeedSummary from raw upstream text + source id.
 */
/**
 * Parse a feed body into IOC entries.
 *
 * @param sourceId — abuse.ch / OpenPhish / KEV source identifier
 * @param rawBody — raw CSV / TXT / JSON body
 * @param cap — max entries to return; defaults to CAP (100). Pass UNCAPPED to
 *   get the full feed, used by briefing-builder which needs to date-filter
 *   across the full window before display-capping.
 */
export function buildSummary(sourceId: SourceId, rawBody: string, cap: number = CAP): IocFeedSummary {
  const meta = FEED_SOURCES[sourceId];
  const fetchedAt = new Date().toISOString();

  let entries: IocEntry[];
  let totalInFeed: number | undefined;

  switch (sourceId) {
    case 'urlhaus':
      entries = parseUrlhaus(rawBody, cap);
      break;
    case 'malwarebazaar':
      entries = parseMalwarebazaar(rawBody, cap);
      break;
    case 'threatfox':
      entries = parseThreatfox(rawBody, cap);
      break;
    case 'openphish':
      entries = parseOpenPhish(rawBody, cap);
      break;
    case 'cisa-kev': {
      const r = parseCisaKev(rawBody);
      entries = r.entries;
      totalInFeed = r.total;
      break;
    }
    case 'blocklist-de':
    case 'binary-defense':
    case 'bitwire':
    case 'bitwire-inbound':
    case 'malwareworld':
      entries = parsePlainTextIps(rawBody, cap);
      break;
    case 'ipsum':
      entries = parseIpsum(rawBody, cap);
      break;
    case 'phishing-army':
      entries = parsePhishingArmy(rawBody, cap);
      break;
    case 'tweetfeed':
      entries = parseTweetFeed(rawBody, cap);
      break;
    case 'threatview-ip':
      entries = parsePlainTextIps(rawBody, cap);
      break;
    case 'threatview-domains':
      entries = parseThreatviewDomains(rawBody, cap);
      break;
    case 'viriback-c2':
      entries = parseViriback(rawBody, cap);
      break;
    case 'certpl-warnings':
      entries = parseThreatviewDomains(rawBody, cap);
      break;
    case 'phishunt':
      entries = parseUrlList(rawBody, cap);
      break;
    case 'swiftioc':
      entries = parseSwiftioc(rawBody, cap);
      break;
    case 'ai-honeypots':
      entries = parseAiHoneypots(rawBody, cap);
      break;
    case 'llm-threatintel':
      entries = parseLlmThreatintelIocs(rawBody, cap);
      break;
    case 'foxit-cobaltstrike':
      entries = parseCobaltStrikeCsv(rawBody, cap);
      break;
    case 'carbonblack-c2':
      entries = parseCarbonBlackC2(rawBody, cap);
      break;
    case 'sslbl-ja3':
      entries = parseSslblJa3(rawBody, cap);
      break;
  }

  return {
    source: sourceId,
    source_name: meta.name,
    fetched_at: fetchedAt,
    count: entries.length,
    ...(totalInFeed !== undefined ? { total_in_feed: totalInFeed } : {}),
    entries,
    cache_control_seconds: CACHE_TTL,
  };
}
