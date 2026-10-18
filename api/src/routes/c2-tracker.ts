import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';

const C2INTEL_30D = 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s-30day.csv';
const C2INTEL_90D = 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s-90day.csv';
const THREATFOX_CSV = 'https://threatfox.abuse.ch/export/csv/recent/';
// CriticalPathSecurity Public-Intelligence-Feeds — hourly-updated CS
// beacon IPs aggregated from multiple operator sources, plaintext one
// IP per line. Added 2026-05-24.
const CPS_CS_IPS =
  'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cobaltstrike_ips.txt';
const CPS_AVANZATO_C2 =
  'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/avanzato_c2.txt';
const CPS_COLLECTED =
  'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cps-collected-iocs.txt';
// CriminalIP C2-Daily-Feed — daily-updated CSV with named C2 framework
// per entry (c2_meshagent, c2_havoc, c2_mythic, c2_metasploit, …).
// Path includes today's date in UTC; if today hasn't been pushed yet we
// fall back to yesterday. Added 2026-05-24.
const CRIMINALIP_BASE = 'https://raw.githubusercontent.com/criminalip/C2-Daily-Feed/main/';
// TweetFeed (0xDanielLopez) — crowdsourced #C2-tagged tweets, weekly
// rolling CSV. Filtered to ip/domain rows tagged with #C2 for the
// analyst-context layer (each row carries source tweet URL).
const TWEETFEED_WEEK = 'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv';

const CACHE_TTL = 1800;
const FETCH_TIMEOUT = 12_000;

export interface C2Entry {
  ip: string;
  framework: string;
  first_seen: string;
  /** All source feed identifiers that reported this IP. */
  sources: string[];
  context?: string;
  port?: number;
}

export interface C2Response {
  generated_at: string;
  count: number;
  sources: { id: string; name: string; count: number }[];
  frameworks: Record<string, number>;
  entries: C2Entry[];
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
      headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: '*/*' },
      cf: { cacheTtl: 1500, cacheEverything: true },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch (_catchErr) {
    logError('fetchText failed', _catchErr);
    return null;
  }
}

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function deriveFramework(ioc: string): string {
  const lower = ioc.toLowerCase();
  if (lower.includes('cobalt')) return 'cobaltstrike';
  if (lower.includes('sliver')) return 'sliver';
  if (lower.includes('metasploit') || lower.includes('meterpreter')) return 'metasploit';
  if (lower.includes('havoc')) return 'havoc';
  if (lower.includes('brute ratel') || lower.includes('bruteratel')) return 'bruteratel';
  if (lower.includes('nighthawk')) return 'nighthawk';
  if (lower.includes('deimos')) return 'deimos';
  if (lower.includes('poshc2')) return 'poshc2';
  if (lower.includes('empire')) return 'empire';
  if (lower.includes('mythic')) return 'mythic';
  if (lower.includes('pwnrig')) return 'pwnrig';
  if (lower.includes('covenant')) return 'covenant';
  if (lower.includes('adaptix')) return 'adaptix';
  if (lower.includes('quasar')) return 'quasar';
  if (lower.includes('vshell')) return 'vshell';
  return 'unknown';
}

function threatfoxFramework(malware: string): string {
  const lower = malware.toLowerCase().replace(/\s+/g, '');
  if (lower.includes('cobalt_strike') || lower.includes('cobaltstrike')) return 'cobaltstrike';
  if (lower.includes('sliver')) return 'sliver';
  if (lower.includes('meterpreter')) return 'metasploit';
  if (lower.includes('havoc')) return 'havoc';
  if (lower.includes('brute') && lower.includes('ratel')) return 'bruteratel';
  if (lower.includes('vshell')) return 'vshell';
  if (lower.includes('asyncrat')) return 'asyncrat';
  if (lower.includes('remcos')) return 'remcos';
  if (lower.includes('dcrat')) return 'dcrat';
  if (lower.includes('quasar')) return 'quasar';
  if (lower.includes('adaptix')) return 'adaptix';
  const cleaned = lower.replace(/^(win|apk|elf|js)\./, '');
  if (cleaned && cleaned !== 'unknown') return cleaned;
  return 'unknown';
}

// ─── C2IntelFeeds parser ───────────────────────────────────────────────────

function parseC2Intels(body: string, sourceLabel: string): C2Entry[] {
  const entries: C2Entry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const cols = trimmed.split(',');
    if (cols.length < 2) continue;
    const ip = cols[0]?.trim();
    if (!ip || !IPV4_RE.test(ip)) continue;
    const port = parseInt(cols[1] ?? '', 10);
    const ioc = cols.length >= 3 ? cols.slice(2).join(',').trim() : '';
    const fw = deriveFramework(ioc);
    entries.push({
      ip,
      framework: fw,
      first_seen: '',
      sources: [sourceLabel],
      context: ioc || undefined,
      port: isFinite(port) ? port : undefined,
    });
  }
  return entries;
}

// ─── ThreatFox parser ──────────────────────────────────────────────────────

function parseThreatfoxC2(body: string): C2Entry[] {
  const entries: C2Entry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // ThreatFox CSVs include a space AFTER each comma — trim
    // first, THEN strip surrounding quotes, otherwise the leading
    // quote survives and string compares like `=== 'ip:port'` fail.
    const cols = trimmed.split(',').map((c) => c.trim().replace(/^"|"$/g, ''));
    if (cols.length < 6) continue;
    const iocType = cols[3] ?? '';
    if (iocType !== 'ip:port') continue;
    const rawValue = cols[2] ?? '';
    const colon = rawValue.lastIndexOf(':');
    const ip = colon === -1 ? rawValue : rawValue.slice(0, colon);
    if (!ip || !IPV4_RE.test(ip)) continue;
    const port = colon === -1 ? undefined : parseInt(rawValue.slice(colon + 1), 10);
    const malware = cols[5]?.trim() || '';
    const printable = cols[7]?.trim() || '';
    const context = printable || malware || 'C2';
    const firstSeen = cols[0]?.trim() || '';
    entries.push({
      ip,
      framework: malware ? threatfoxFramework(malware) : 'unknown',
      first_seen: firstSeen,
      sources: ['threatfox'],
      context: context,
      port: port !== undefined && isFinite(port) ? port : undefined,
    });
  }
  return entries;
}

// ─── CriticalPathSecurity Cobalt Strike IPs (plaintext) ────────────────────

function parseCpsCobaltStrike(body: string): C2Entry[] {
  const seen = new Set<string>();
  const entries: C2Entry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (!IPV4_RE.test(trimmed)) continue;
    if (seen.has(trimmed)) continue; // file dedupes hourly but may carry repeats
    seen.add(trimmed);
    entries.push({
      ip: trimmed,
      framework: 'cobaltstrike',
      first_seen: '',
      sources: ['cps'],
      context: 'CriticalPathSecurity CS feed',
    });
  }
  return entries;
}

// ─── CPS Avanzato C2 IPs (plain-text, one per line) ────────────────────────

function parseCpsAvanzatoC2(body: string): C2Entry[] {
  const entries: C2Entry[] = [];
  const seen = new Set<string>();
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || !IPV4_RE.test(trimmed)) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    entries.push({
      ip: trimmed,
      framework: 'avanzato',
      first_seen: '',
      sources: ['cps-avanzato'],
      context: 'Avanzato malware C2',
    });
  }
  return entries;
}

// ─── CPS Collected IOCs (plain-text IPs, one per line) ─────────────────────

function parseCpsCollected(body: string): C2Entry[] {
  const entries: C2Entry[] = [];
  const seen = new Set<string>();
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || !IPV4_RE.test(trimmed)) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    entries.push({
      ip: trimmed,
      framework: 'unknown',
      first_seen: '',
      sources: ['cps-collected'],
      context: 'CPS collected IOC',
    });
  }
  return entries;
}

// ─── CriminalIP daily C2 feed (CSV with named framework column) ────────────

function parseCriminalIp(body: string): C2Entry[] {
  const entries: C2Entry[] = [];
  const lines = body.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]?.trim();
    if (!line) continue;
    // Header row: IP,Target C2,OpenPorts,Score(Inbound/Outbound),Country,Scan Time
    if (i === 0 && line.toLowerCase().startsWith('ip,')) continue;
    const cols = line.split(',').map((c) => c.replace(/^"|"$/g, '').trim());
    if (cols.length < 6) continue;
    const ip = cols[0] ?? '';
    if (!IPV4_RE.test(ip)) continue;
    const targetC2 = cols[1] ?? '';
    const port = parseInt(cols[2] ?? '', 10);
    const country = cols[4] ?? '';
    const scanTime = cols[5] ?? '';
    // Normalise "c2_meshagent" → "meshagent", "c2_havoc" → "havoc".
    const fw = targetC2.toLowerCase().replace(/^c2[_\s-]+/, '') || 'unknown';
    entries.push({
      ip,
      framework: fw,
      first_seen: scanTime,
      sources: ['criminalip'],
      context: country ? `criminalip · ${country.toUpperCase()}` : 'criminalip',
      port: isFinite(port) ? port : undefined,
    });
  }
  return entries;
}

// ─── TweetFeed (crowdsourced #C2-tagged IPs) ───────────────────────────────

function parseTweetFeedC2(body: string): C2Entry[] {
  const entries: C2Entry[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const cols = trimmed.split(',');
    if (cols.length < 5) continue;
    // Format: Timestamp,Username,Type,Indicator,Tags,Twitter_URL
    const type = (cols[2] ?? '').trim();
    if (type !== 'ip') continue; // domain/url left to other feeds
    const ip = (cols[3] ?? '').trim();
    if (!IPV4_RE.test(ip)) continue;
    const tags = (cols[4] ?? '').toLowerCase();
    if (!tags.includes('#c2')) continue; // C2-only filter
    const fw = deriveFramework(tags);
    entries.push({
      ip,
      framework: fw,
      first_seen: cols[0]?.trim() || '',
      sources: ['tweetfeed'],
      context: `tweetfeed · ${(cols[1] ?? '').trim() || 'anon'}`,
    });
  }
  return entries;
}

// ─── Merge sources for deduped IPs ─────────────────────────────────────────

/**
 * Merge all C2 feeds into a single list, deduped by IP.
 *
 * The priority-based approach used to drop secondary-source entries when
 * another feed already had the same IP. This version **merges sources**:
 * every feed that reported an IP contributes its source tag to the entry,
 * so no feed's signal is ever dropped.
 */
function mergeSources(entries: C2Entry[], seen: Map<string, C2Entry>): void {
  for (const e of entries) {
    const existing = seen.get(e.ip);
    if (!existing) {
      seen.set(e.ip, { ...e, sources: [...e.sources] });
    } else {
      const merged = new Set([...existing.sources, ...e.sources]);
      existing.sources = [...merged];
    }
  }
}

// ─── Main fetch ─────────────────────────────────────────────────────────────

/** Build today's CriminalIP CSV URL in UTC. Falls back to yesterday if
 *  the daily push hasn't landed yet (the repo pushes ~09:01 UTC). */
function criminalipUrls(): string[] {
  const now = new Date();
  const fmt = (d: Date) =>
    `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
  const today = fmt(now);
  const yesterday = fmt(new Date(now.getTime() - 86_400_000));
  return [`${CRIMINALIP_BASE}${today}.csv`, `${CRIMINALIP_BASE}${yesterday}.csv`];
}

async function fetchCriminalIp(): Promise<string | null> {
  for (const url of criminalipUrls()) {
    const body = await fetchText(url);
    if (body && body.length > 100) return body;
  }
  return null;
}

async function fetchC2Tracker(): Promise<C2Response> {
  const rawTexts = await Promise.all([
    fetchText(C2INTEL_30D),
    fetchText(C2INTEL_90D),
    fetchText(THREATFOX_CSV),
    fetchText(CPS_CS_IPS),
    fetchCriminalIp(),
    fetchText(TWEETFEED_WEEK),
    fetchText(CPS_AVANZATO_C2),
    fetchText(CPS_COLLECTED),
  ]);

  const sourceEntries: { id: string; name: string; entries: C2Entry[] }[] = [
    { id: 'c2intel-30d', name: 'C2Intel (30d)', entries: rawTexts[0] ? parseC2Intels(rawTexts[0], 'c2intel') : [] },
    { id: 'c2intel-90d', name: 'C2Intel (90d)', entries: rawTexts[1] ? parseC2Intels(rawTexts[1], 'c2intel') : [] },
    { id: 'threatfox', name: 'ThreatFox', entries: rawTexts[2] ? parseThreatfoxC2(rawTexts[2]) : [] },
    { id: 'cps', name: 'CriticalPathSecurity', entries: rawTexts[3] ? parseCpsCobaltStrike(rawTexts[3]) : [] },
    { id: 'criminalip', name: 'CriminalIP Daily', entries: rawTexts[4] ? parseCriminalIp(rawTexts[4]) : [] },
    { id: 'tweetfeed', name: 'TweetFeed (#C2)', entries: rawTexts[5] ? parseTweetFeedC2(rawTexts[5]) : [] },
    { id: 'cps-avanzato', name: 'CPS Avanzato C2', entries: rawTexts[6] ? parseCpsAvanzatoC2(rawTexts[6]) : [] },
    { id: 'cps-collected', name: 'CPS Collected IOCs', entries: rawTexts[7] ? parseCpsCollected(rawTexts[7]) : [] },
  ];

  const seen = new Map<string, C2Entry>();
  for (const { entries } of sourceEntries) {
    mergeSources(entries, seen);
  }

  const merged = [...seen.values()];

  // Per-source counts — an entry with 2+ sources counts for each
  const sourceTags: Array<{ tag: string; id: string; name: string }> = [
    { tag: 'c2intel', id: 'c2intel', name: 'C2IntelFeeds' },
    { tag: 'threatfox', id: 'threatfox', name: 'ThreatFox' },
    { tag: 'cps', id: 'cps', name: 'CriticalPathSecurity' },
    { tag: 'criminalip', id: 'criminalip', name: 'CriminalIP Daily' },
    { tag: 'tweetfeed', id: 'tweetfeed', name: 'TweetFeed (#C2)' },
    { tag: 'cps-avanzato', id: 'cps-avanzato', name: 'CPS Avanzato C2' },
    { tag: 'cps-collected', id: 'cps-collected', name: 'CPS Collected IOCs' },
  ];
  const sourceSummary = sourceTags
    .map(({ tag, id, name }) => ({
      id,
      name,
      count: merged.filter((e) => e.sources.includes(tag)).length,
    }))
    .filter((s) => s.count > 0);

  const frameworkCounts: Record<string, number> = {};
  for (const e of merged) {
    frameworkCounts[e.framework] = (frameworkCounts[e.framework] ?? 0) + 1;
  }

  // Stratified slice: cap each framework at PER_FRAMEWORK_CAP so the
  // dominant family (cobaltstrike, ~2500 entries) doesn't crowd out
  // every other framework's representation. Without this the flat
  // top-500 slice shipped only cobaltstrike + a handful of metasploit
  // and the FE framework filters for asyncrat / mythic / havoc / etc
  // rendered 0 results despite the counts pill saying otherwise.
  const PER_FRAMEWORK_CAP = 400;
  const seenPerFw: Record<string, number> = {};
  const sliced: C2Entry[] = [];
  for (const e of merged) {
    const used = seenPerFw[e.framework] ?? 0;
    if (used >= PER_FRAMEWORK_CAP) continue;
    seenPerFw[e.framework] = used + 1;
    sliced.push(e);
  }

  return {
    generated_at: new Date().toISOString(),
    count: merged.length,
    sources: sourceSummary,
    frameworks: frameworkCounts,
    entries: sliced,
  };
}

// ─── Handler ────────────────────────────────────────────────────────────────

export async function c2TrackerHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  // v8: stratified entries slice (per-framework cap 400) so framework
  // filters show real entries instead of 0 for non-cobaltstrike families.
  const cacheKey = new Request('https://c2-cache.internal/v8');
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const data = await fetchC2Tracker();
  const body = JSON.stringify(data);

  const response = new Response(body, {
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL}, stale-while-revalidate=${CACHE_TTL * 4}`,
      'access-control-allow-origin': '*',
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
