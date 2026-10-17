import type { Context } from 'hono';
import { logError } from '../lib/logger';
import { lookupCve } from '../lib/cve-lookup';
import type { GithubEnv } from '../lib/github-api';
import { ACTOR_ALIASES } from '../data/threat-actor-aliases';
import { rankSections } from '../lib/search/rank';
import { safeNullLog } from '../lib/safe-catch';

// ── Cache keys (imported where available, hardcoded for internal-only keys) ──
import { LIVE_IOCS_CACHE_KEY, type LiveIocsResponse } from './live-iocs';
import { RANSOMWARE_RECENT_CACHE_KEY, type RansomwareVictim } from './ransomware-recent';
import { DETECTIONS_CACHE_KEY, type DetectionsResponse } from './detections';
import { CVE_RECENT_CACHE_KEY, type CveRecentResponse } from './cve-recent';
import { WRITEUPS_CACHE_KEY, type WriteupsResponse } from './writeups';
import { CYBERCRIME_CACHE_KEY, type CybercrimeResponse } from './cybercrime';
import { MALWARE_SAMPLES_CACHE_KEY, type MalwareSamplesResponse } from './malware-samples';
import { isHandleShaped, lookupHandle } from '../lib/scrapedintel';

const C2_CACHE_KEY = 'https://c2-cache.internal/v8';
const ACTOR_TIMELINE_CACHE_KEY = 'https://actor-timeline-cache.internal/v3-mti';
const IOC_CORRELATION_CACHE_KEY = 'https://ioc-correlation-cache.internal/v6-mti-hashes';
const BREACH_CACHE_KEY = 'https://breach-cache.internal/v6-hibp-only';
const MALPEDIA_CACHE_KEY = 'https://malpedia-cache.internal/v2';

// ── Response types ───────────────────────────────────────────────────────────

export interface SearchItem {
  label: string;
  description?: string;
  url?: string;
  source: string;
  subkind?: string;
  /** Relevance score (0–100). Always set by rankSections in non-empty responses;
   *  optional only so the source searchers can build items without it. */
  score?: number;
}

export interface SearchSection {
  label: string;
  kind: string;
  total: number;
  items: SearchItem[];
}

interface UnifiedSearchResponse {
  q: string;
  generated_at: string;
  total: number;
  sections: SearchSection[];
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function q(s: string): string {
  return s.toLowerCase().trim();
}

function matches(needle: string, haystack: string): boolean {
  return haystack.toLowerCase().includes(needle);
}

async function readCachedJson<T>(cacheKey: string): Promise<T | null> {
  try {
    const cache = (caches as unknown as { default: Cache }).default;
    const cached = await cache.match(new Request(cacheKey));
    if (cached) return (await cached.json()) as T;
  } catch (_catchErr) {
    logError('readCachedJson failed', _catchErr);
    /* cold cache */
  }
  return null;
}

function buildItem(
  label: string,
  desc: string | undefined,
  url: string | undefined,
  source: string,
  subkind?: string
): SearchItem {
  return { label, description: desc, url, source, subkind };
}

// ── Source searchers ─────────────────────────────────────────────────────────

async function searchRansomware(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<{
    victims: RansomwareVictim[];
    groups: { group: string; count: number }[];
  }>(RANSOMWARE_RECENT_CACHE_KEY);
  if (!data) return { label: 'Ransomware Victims', kind: 'ransomware', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();

  for (const g of data.groups ?? []) {
    if (matches(needle, g.group) && !seen.has(g.group)) {
      seen.add(g.group);
      items.push(
        buildItem(
          g.group,
          `${g.count} victim${g.count === 1 ? '' : 's'} this period`,
          undefined,
          'ransomware-recent',
          'group'
        )
      );
    }
  }
  for (const v of data.victims ?? []) {
    if (matches(needle, v.victim) && !seen.has(v.victim)) {
      seen.add(v.victim);
      items.push(buildItem(v.victim, `group: ${v.group}`, undefined, 'ransomware-recent', 'victim'));
    }
  }

  return { label: 'Ransomware Victims', kind: 'ransomware', total: items.length, items };
}

async function searchC2(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<{
    entries: Array<{ ip: string; framework: string; context?: string; port?: number }>;
  }>(C2_CACHE_KEY);
  if (!data) return { label: 'C2 IPs', kind: 'c2', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  for (const e of data.entries ?? []) {
    if (matches(needle, e.ip) || matches(needle, e.framework) || (e.context && matches(needle, e.context))) {
      if (seen.has(e.ip)) continue;
      seen.add(e.ip);
      items.push(
        buildItem(
          `${e.ip}${e.port ? `:${e.port}` : ''}`,
          `C2: ${e.framework}${e.context ? ` — ${e.context}` : ''}`,
          undefined,
          'c2-tracker',
          e.framework
        )
      );
    }
  }

  return { label: 'C2 IPs', kind: 'c2', total: items.length, items };
}

async function searchLiveIocs(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<LiveIocsResponse>(LIVE_IOCS_CACHE_KEY);
  if (!data) return { label: 'Live IOCs', kind: 'iocs', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  for (const ioc of data.items ?? []) {
    if (matches(needle, ioc.value) || (ioc.context && matches(needle, ioc.context))) {
      if (seen.has(ioc.value)) continue;
      seen.add(ioc.value);
      items.push(
        buildItem(
          ioc.value,
          `${ioc.kind} · ${ioc.source}${ioc.context ? ` — ${ioc.context}` : ''}`,
          undefined,
          'live-iocs',
          ioc.kind
        )
      );
      if (items.length >= 50) break;
    }
  }

  return { label: 'Live IOCs', kind: 'iocs', total: items.length, items };
}

async function searchDetections(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<DetectionsResponse>(DETECTIONS_CACHE_KEY);
  if (!data) return { label: 'Detections', kind: 'detections', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  for (const d of data.detections ?? []) {
    const match =
      matches(needle, d.rule_name) ||
      matches(needle, d.rule_id) ||
      (d.indicators ?? []).some((i: { value: string }) => matches(needle, i.value));
    if (!match) continue;
    const key = `${d.rule_id}:${d.group_key ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push(
      buildItem(
        d.rule_name,
        `severity: ${d.severity} · ${d.match_count} indicator${d.match_count === 1 ? '' : 's'}${d.group_key ? ` · ${d.group_key}` : ''}`,
        undefined,
        'detections',
        d.severity
      )
    );
  }

  return { label: 'Detections', kind: 'detections', total: items.length, items };
}

async function searchActorTimeline(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<{
    groups: Array<{ slug: string; name: string; victim_count: number; techniques_used: number }>;
  }>(ACTOR_TIMELINE_CACHE_KEY);
  if (!data) return { label: 'Actor Timeline', kind: 'actors', total: 0, items: [] };

  const items: SearchItem[] = [];
  for (const g of data.groups ?? []) {
    if (matches(needle, g.name) || matches(needle, g.slug)) {
      items.push(
        buildItem(
          g.name,
          `${g.victim_count} victim${g.victim_count === 1 ? '' : 's'} · ${g.techniques_used} TTPs`,
          `/threatintel/actors/${g.slug}`,
          'actor-timeline',
          'actor'
        )
      );
    }
  }

  return { label: 'Actor Timeline', kind: 'actors', total: items.length, items };
}

async function searchCves(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<CveRecentResponse>(CVE_RECENT_CACHE_KEY);
  if (!data) return { label: 'CVEs', kind: 'cves', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  const nl = q(needle);
  const isCveId = /^cve-\d{4}-\d{4,7}$/i.test(needle.trim());

  for (const cve of data.cves ?? []) {
    const id = cve.id ?? '';
    if (isCveId) {
      if (q(id) === nl) {
        items.push(
          buildItem(
            id,
            cve.description ? `${cve.description.slice(0, 200)}…` : '',
            `https://nvd.nist.gov/vuln/detail/${id}`,
            'cve-recent',
            'cve'
          )
        );
      }
    } else {
      if (matches(needle, id) || (cve.description && matches(needle, cve.description))) {
        if (seen.has(id)) continue;
        seen.add(id);
        items.push(
          buildItem(
            id,
            cve.description ? `${cve.description.slice(0, 200)}…` : '',
            `https://nvd.nist.gov/vuln/detail/${id}`,
            'cve-recent',
            'cve'
          )
        );
      }
    }
    if (items.length >= 20) break;
  }

  return { label: 'CVEs', kind: 'cves', total: items.length, items };
}

async function searchWriteups(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<WriteupsResponse>(WRITEUPS_CACHE_KEY);
  if (!data) return { label: 'Writeups', kind: 'writeups', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  for (const w of data.items ?? []) {
    if (matches(needle, w.title ?? '') || matches(needle, w.description ?? '')) {
      if (seen.has(w.title)) continue;
      seen.add(w.title);
      items.push(
        buildItem(
          w.title ?? '(untitled)',
          w.description ? `${w.description.slice(0, 200)}${w.description.length > 200 ? '…' : ''}` : '',
          w.url,
          w.source ?? 'writeups'
        )
      );
    }
    if (items.length >= 20) break;
  }

  return { label: 'Writeups', kind: 'writeups', total: items.length, items };
}

async function searchCybercrime(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<CybercrimeResponse>(CYBERCRIME_CACHE_KEY);
  if (!data) return { label: 'Cybercrime', kind: 'cybercrime', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  for (const item of data.items ?? []) {
    if (matches(needle, item.title ?? '') || matches(needle, item.description ?? '')) {
      if (seen.has(item.title)) continue;
      seen.add(item.title);
      items.push(
        buildItem(
          item.title ?? '(untitled)',
          item.description ? `${item.description.slice(0, 200)}${item.description.length > 200 ? '…' : ''}` : '',
          item.url,
          'cybercrime'
        )
      );
    }
    if (items.length >= 20) break;
  }

  return { label: 'Cybercrime', kind: 'cybercrime', total: items.length, items };
}

async function searchIocCorrelation(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<{
    ips: Array<{ value: string; source_count: number; sources: string[] }>;
    urls: Array<{ value: string; source_count: number; sources: string[] }>;
    domains: Array<{ value: string; source_count: number; sources: string[] }>;
    hashes: Array<{ value: string; source_count: number; sources: string[] }>;
  }>(IOC_CORRELATION_CACHE_KEY);
  if (!data) return { label: 'IOC Correlation', kind: 'correlation', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();

  for (const kind of ['ips', 'urls', 'domains', 'hashes'] as const) {
    for (const entry of (data[kind] ?? []) as Array<{ value: string; source_count: number; sources: string[] }>) {
      if (matches(needle, entry.value)) {
        if (seen.has(entry.value)) continue;
        seen.add(entry.value);
        items.push(
          buildItem(
            entry.value,
            `${entry.source_count} source${entry.source_count === 1 ? '' : 's'}: ${(entry.sources ?? []).join(', ')}`,
            undefined,
            'ioc-correlation',
            kind === 'ips' ? 'ip' : kind === 'urls' ? 'url' : kind === 'domains' ? 'domain' : 'hash'
          )
        );
      }
    }
  }

  return { label: 'IOC Correlation', kind: 'correlation', total: items.length, items };
}

async function searchBreaches(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<{
    breaches: Array<{ Name: string; Title?: string; Domain?: string; BreachDate?: string; PwnCount?: number }>;
  }>(BREACH_CACHE_KEY);
  if (!data) return { label: 'Breach Disclosures', kind: 'breaches', total: 0, items: [] };

  const items: SearchItem[] = [];
  for (const b of data.breaches ?? []) {
    if (matches(needle, b.Name) || matches(needle, b.Title ?? '') || matches(needle, b.Domain ?? '')) {
      items.push(
        buildItem(
          b.Title ?? b.Name,
          `${b.Domain ?? ''} · ${b.BreachDate ?? ''}${b.PwnCount ? ` · ${b.PwnCount.toLocaleString()} records` : ''}`,
          undefined,
          'breach-disclosures'
        )
      );
    }
  }

  return { label: 'Breach Disclosures', kind: 'breaches', total: items.length, items };
}

async function searchMalwareSamples(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<MalwareSamplesResponse>(MALWARE_SAMPLES_CACHE_KEY);
  if (!data) return { label: 'Malware Samples', kind: 'malware', total: 0, items: [] };

  const items: SearchItem[] = [];
  const seen = new Set<string>();
  for (const s of data.samples ?? []) {
    if (
      matches(needle, s.sha256) ||
      matches(needle, s.sha1 ?? '') ||
      matches(needle, s.md5 ?? '') ||
      matches(needle, s.signature ?? '') ||
      matches(needle, s.file_type ?? '')
    ) {
      if (seen.has(s.sha256)) continue;
      seen.add(s.sha256);
      items.push(
        buildItem(
          s.sha256.slice(0, 16) + '…',
          `${s.signature ?? 'unknown'} · ${s.file_type ?? ''}${s.first_seen ? ` · ${s.first_seen}` : ''}`,
          s.bazaar_url,
          'malware-samples',
          s.signature ? 'malware' : 'sample'
        )
      );
      if (items.length >= 30) break;
    }
  }

  return { label: 'Malware Samples', kind: 'malware', total: items.length, items };
}

// ── Live CVE lookup ─────────────────────────────────────────────────────────
async function searchCveLookup(needle: string, env?: GithubEnv): Promise<SearchSection> {
  const isCve = /^CVE-\d{4}-\d{4,7}$/i.test(needle.trim());
  if (!isCve) return { label: 'CVE Lookup (live)', kind: 'cves', total: 0, items: [] };

  const result = await lookupCve(needle.trim().toUpperCase(), undefined, env);
  if (!result.ok) return { label: 'CVE Lookup (live)', kind: 'cves', total: 0, items: [] };

  const { data } = result;
  const items: SearchItem[] = [
    buildItem(
      data.cve_id,
      [
        data.cvss ? `${data.cvss.severity} ${data.cvss.base_score}` : '',
        data.epss ? `EPSS ${(data.epss.score * 100).toFixed(2)}%` : '',
        data.kev.in_kev ? 'CISA KEV' : '',
        data.poc ? `${data.poc.count} PoCs` : '',
      ]
        .filter(Boolean)
        .join(' · '),
      `https://nvd.nist.gov/vuln/detail/${data.cve_id}`,
      'cve-lookup',
      data.cvss?.severity?.toLowerCase() ?? 'cve'
    ),
  ];

  return { label: 'CVE Lookup (live)', kind: 'cves', total: items.length, items };
}

// ── Live IOC Check ───────────────────────────────────────────────────────────
const IOC_RE_IP = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IOC_RE_DOMAIN = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
const IOC_RE_HASH = /^[a-fA-F0-9]{32,64}$/;

async function searchIocCheck(needle: string, env: import('../env').Env): Promise<SearchSection> {
  const q = needle.trim();
  const iocType = IOC_RE_IP.test(q) ? 'ip' : IOC_RE_DOMAIN.test(q) ? 'domain' : IOC_RE_HASH.test(q) ? 'hash' : null;
  if (!iocType) return { label: 'IOC Check (live)', kind: 'iocs', total: 0, items: [] };

  // Quick reputation check via abuseipdb for IPs, otherwise signal from live IOC feeds
  const items: SearchItem[] = [];

  // Only call AbuseIPDB when a real key is configured. The old code sent a
  // hardcoded 'dummy' key, guaranteeing a 401 and silently returning nothing.
  if (iocType === 'ip' && env.ABUSEIPDB_API_KEY) {
    try {
      const res = await safeNullLog(
        'fetch-abuseipdb',
        fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(q)}&maxAgeInDays=90`, {
          headers: { Key: env.ABUSEIPDB_API_KEY, Accept: 'application/json' },
          signal: AbortSignal.timeout(5000),
        })
      );
      if (res?.ok) {
        const data = (await res.json()) as {
          data?: {
            abuseConfidenceScore: number;
            totalReports: number;
            countryCode?: string;
            isp?: string;
            domain?: string;
            lastReportedAt?: string;
          };
        };
        if (data?.data && data.data.abuseConfidenceScore > 0) {
          items.push(
            buildItem(
              q,
              `AbuseIPDB: ${data.data.abuseConfidenceScore}% · ${data.data.totalReports} reports${data.data.countryCode ? ` · ${data.data.countryCode}` : ''}`,
              `https://www.abuseipdb.com/check/${q}`,
              'ioc-check',
              `score-${data.data.abuseConfidenceScore}`
            )
          );
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* skip */
    }

    // Check blocklist.de
    try {
      const bl = await safeNullLog(
        'fetch-blocklist-de',
        fetch(`https://api.blocklist.de/api.php?ip=${encodeURIComponent(q)}`, {
          signal: AbortSignal.timeout(4000),
        })
      );
      if (bl?.ok) {
        const text = await bl.text();
        if (text.includes('found')) {
          items.push(
            buildItem(
              q,
              'Listed on blocklist.de',
              `https://www.blocklist.de/en/view.html?ip=${encodeURIComponent(q)}`,
              'ioc-check',
              'blocklist'
            )
          );
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* skip */
    }
  }

  if (iocType === 'domain') {
    // Check URLhaus
    try {
      const uh = await safeNullLog(
        'fetch-urlhaus',
        fetch(`https://urlhaus-api.abuse.ch/v1/host/`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: `host=${encodeURIComponent(q)}`,
          signal: AbortSignal.timeout(5000),
        })
      );
      if (uh?.ok) {
        const ud = (await uh.json()) as { query_status?: string; url_count?: number };
        if (ud.query_status === 'ok' && (ud.url_count ?? 0) > 0) {
          items.push(
            buildItem(
              q,
              `${ud.url_count} URLs on URLhaus`,
              `https://urlhaus.abuse.ch/host/${encodeURIComponent(q)}/`,
              'ioc-check',
              'malicious'
            )
          );
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* skip */
    }
  }

  if (iocType === 'hash') {
    // Check MalwareBazaar
    try {
      const mb = await safeNullLog(
        'fetch-malwarebazaar-hash',
        fetch('https://mb-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: `query=get_info&hash=${q}`,
          signal: AbortSignal.timeout(5000),
        })
      );
      if (mb?.ok) {
        const md = (await mb.json()) as {
          query_status?: string;
          data?: Array<{ signature?: string; file_type?: string; first_seen?: string }>;
        };
        if (md.query_status === 'ok' && md.data?.[0]) {
          const entry = md.data[0];
          items.push(
            buildItem(
              q.slice(0, 16) + '…',
              `MalwareBazaar: ${entry.signature ?? 'unknown'} · ${entry.file_type ?? ''}${entry.first_seen ? ` · ${entry.first_seen}` : ''}`,
              `https://bazaar.abuse.ch/sample/${q}/`,
              'ioc-check',
              'malware'
            )
          );
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* skip */
    }
  }

  return { label: 'IOC Check (live)', kind: 'iocs', total: items.length, items };
}

async function searchMalpedia(needle: string): Promise<SearchSection> {
  const data = await readCachedJson<{
    families: Array<{ name: string; common_name?: string; description?: string; aliases?: string[] }>;
  }>(MALPEDIA_CACHE_KEY);
  if (!data) return { label: 'Malpedia Families', kind: 'malware', total: 0, items: [] };

  const items: SearchItem[] = [];
  for (const f of data.families ?? []) {
    if (
      matches(needle, f.name) ||
      matches(needle, f.common_name ?? '') ||
      matches(needle, f.description ?? '') ||
      (f.aliases ?? []).some((a) => matches(needle, a))
    ) {
      items.push(
        buildItem(
          f.common_name ?? f.name,
          f.description ? f.description.slice(0, 200) : '',
          undefined,
          'malpedia',
          'malware-family'
        )
      );
      if (items.length >= 20) break;
    }
  }

  return { label: 'Malpedia Families', kind: 'malware', total: items.length, items };
}

// ── Handler ──────────────────────────────────────────────────────────────────

const SEARCHER_TIMEOUT_MS = 12_000;

async function searchActorKb(needle: string): Promise<SearchSection> {
  const ql = needle.toLowerCase().trim();
  if (ql.length < 2) return { label: 'Threat Actor KB', kind: 'actors', total: 0, items: [] };
  const matches = ACTOR_ALIASES.filter(
    (a) => a.canonical.toLowerCase().includes(ql) || a.aliases.some((al) => al.toLowerCase().includes(ql))
  );
  if (matches.length === 0) return { label: 'Threat Actor KB', kind: 'actors', total: 0, items: [] };
  const items: SearchItem[] = matches
    .slice(0, 15)
    .map((a) =>
      buildItem(
        a.canonical,
        [a.mitreId ? `MITRE ${a.mitreId}` : '', a.aliases.length > 0 ? `Aliases: ${a.aliases.join(', ')}` : '']
          .filter(Boolean)
          .join(' · '),
        a.mitreId ? `https://attack.mitre.org/groups/${a.mitreId}/` : undefined,
        'actor-kb',
        a.canonical.toLowerCase().includes(ql) ? 'high' : 'medium'
      )
    );
  return { label: 'Threat Actor KB', kind: 'actors', total: items.length, items };
}

// Live ScrapedIntel forum-handle lookup (threatactorusernames.com). Only fires for
// handle-shaped freetext — IOCs/CVEs have their own searchers — and is cache-first:
// it only spends an upstream call when the egress budget can be coordinated via KV.
// All rate-limit / cold / error states collapse to an empty section (dropped).
async function searchScrapedIntelHandles(needle: string, env: import('../env').Env): Promise<SearchSection> {
  const label = 'Forum Handles (ScrapedIntel)';
  const empty: SearchSection = { label, kind: 'actors', total: 0, items: [] };
  const qn = needle.trim();
  if (!isHandleShaped(qn)) return empty;
  if (IOC_RE_IP.test(qn) || IOC_RE_DOMAIN.test(qn) || IOC_RE_HASH.test(qn) || /^cve-\d{4}-\d{4,7}$/i.test(qn)) {
    return empty;
  }
  try {
    // Tighter timeout than the dedicated route so a hung upstream can't hold the
    // 12s fan-out open; lookupHandle is cache-only unless KV is bound to budget egress.
    const out = await lookupHandle(qn, env, { timeoutMs: 4000 });
    const items: SearchItem[] = (out.data?.results ?? [])
      .slice(0, 15)
      .map((m) =>
        buildItem(
          m.username,
          `${m.forum_count} forum${m.forum_count === 1 ? '' : 's'}: ${m.forums.map((f) => f.forum).join(', ')}`,
          `/threatintel/scrapedintel-usernames?q=${encodeURIComponent(m.username)}`,
          'scrapedintel',
          'handle'
        )
      );
    return { label, kind: 'actors', total: items.length, items };
  } catch (_catchErr) {
    logError('searchScrapedIntelHandles failed', _catchErr);
    return empty;
  }
}

export async function unifiedSearchHandler(ctx: Context<{ Bindings: import('../env').Env }>): Promise<Response> {
  const qParam = ctx.req.query('q')?.trim();
  if (!qParam) {
    return ctx.json({ q: '', generated_at: new Date().toISOString(), total: 0, sections: [] });
  }
  if (qParam.length > 200) {
    return ctx.json({ error: 'query too long' }, 400);
  }

  const needle = q(qParam);
  const deadline = Date.now() + SEARCHER_TIMEOUT_MS;

  const results = await Promise.allSettled([
    searchRansomware(needle),
    searchC2(needle),
    searchLiveIocs(needle),
    searchDetections(needle),
    searchActorTimeline(needle),
    searchCves(needle),
    searchWriteups(needle),
    searchCybercrime(needle),
    searchIocCorrelation(needle),
    searchBreaches(needle),
    searchMalwareSamples(needle),
    searchMalpedia(needle),
    searchCveLookup(needle, ctx.env),
    searchIocCheck(needle, ctx.env),
    searchActorKb(needle),
    searchScrapedIntelHandles(needle, ctx.env),
  ]);

  const sections: SearchSection[] = [];
  let total = 0;
  for (const r of results) {
    if (r.status !== 'fulfilled' || r.value.total === 0) continue;
    if (Date.now() > deadline) break;
    sections.push(r.value);
    total += r.value.total;
  }

  // Relevance ranking: items within each section by match score, sections by
  // their best item (ties fall back to count → preserves the old order when
  // scores are equal). Replaces the previous count-only sort.
  const ranked = rankSections(needle, sections);

  const response: UnifiedSearchResponse = {
    q: qParam,
    generated_at: new Date().toISOString(),
    total,
    sections: ranked,
  };

  return ctx.json(response, 200, {
    'Cache-Control': 'public, max-age=120',
  });
}
