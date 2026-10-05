import { logError } from '../../lib/logger';
import type {
  PulseEvent,
  PulseKind,
  Sev,
  XClaimsResponse,
  ActorTimelineResponse,
  IocCorrelationResponse,
} from './types';
import { COUNTRY_COORDS, countryNameToCode } from './geo';
import { asSev } from './shared';
import type { CveDigestEntry } from '../cve-digest';

/* ─── Converters ────────────────────────────────────────────────────────── */

export function iocFromThreatMap(data: {
  countries: Array<{ countryCode: string; country: string; count: number; sources: Record<string, number> }>;
}): PulseEvent[] {
  return (data.countries ?? [])
    .filter((c) => c.count > 0)
    .flatMap((c) => {
      try {
        const baseCoords = COUNTRY_COORDS[c.countryCode];
        const jitterLat = (Math.random() - 0.5) * 3;
        const jitterLng = (Math.random() - 0.5) * 5;
        return [
          {
            id: `ioc-${c.countryCode}`,
            kind: 'ioc_activity' as const,
            title: `${c.country ?? 'Unknown'} — ${c.count ?? 0} malicious IPs`,
            description: `Threat activity from ${Object.keys(c.sources ?? {}).length} feed sources`,
            lat: (baseCoords?.[0] ?? 0) + jitterLat,
            lng: (baseCoords?.[1] ?? 0) + jitterLng,
            timestamp: new Date().toISOString(),
            severity:
              (c.count ?? 0) > 1000
                ? ('critical' as const)
                : (c.count ?? 0) > 500
                  ? ('high' as const)
                  : (c.count ?? 0) > 100
                    ? ('medium' as const)
                    : ('low' as const),
            source: 'threat-map',
            country: c.country,
          },
        ];
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return [];
      }
    });
}

export function fromReddit(data: {
  items?: Array<{ title: string; sub: string; sub_topic: string; link: string; pub_date: string }>;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 40).flatMap((i) => {
    try {
      return [
        {
          id: `reddit-${(i.link ?? '').slice(-20) || 'x'}`,
          kind: 'reddit' as const,
          title: i.title ?? '',
          description: `r/${i.sub ?? '?'} · ${i.sub_topic ?? ''}`,
          lat: 0,
          lng: 0,
          timestamp: i.pub_date || new Date().toISOString(),
          severity: 'low' as const,
          source: `r/${i.sub ?? '?'}`,
          url: i.link,
        },
      ];
    } catch (_catchErr) {
      logError('fromReddit failed', _catchErr);
      return [];
    }
  });
}

export function fromTelegram(data: {
  items?: Array<{ text: string; channel_name: string; channel_topic: string; permalink: string; datetime: string }>;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 40).map((i) => ({
    id: `tg-${i.permalink.slice(-20)}`,
    kind: 'telegram' as const,
    title: i.text.slice(0, 120) || `Message from ${i.channel_name}`,
    description: `${i.channel_name} · ${i.channel_topic}`,
    lat: 0,
    lng: 0,
    timestamp: i.datetime || new Date().toISOString(),
    severity: 'low' as const,
    source: `TG: ${i.channel_name}`,
    url: i.permalink,
  }));
}

export function fromXFeed(data: {
  items?: Array<{
    text: string;
    handle_name: string;
    platform: string;
    handle_topic: string;
    link: string;
    pub_date: string;
  }>;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 40).map((i) => ({
    id: `x-${i.link.slice(-20)}`,
    kind: 'x_feed' as const,
    title: i.text.slice(0, 120) || `Post by ${i.handle_name}`,
    description: `${i.handle_name} · ${i.platform} · ${i.handle_topic}`,
    lat: 0,
    lng: 0,
    timestamp: i.pub_date || new Date().toISOString(),
    severity: 'low' as const,
    source: `${i.platform}: ${i.handle_name}`,
    url: i.link,
  }));
}

export function fromScam(data: {
  items?: Array<{ domain: string; tld: string }>;
  generated_at?: string;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 30).map((i, idx) => ({
    id: `scam-${i.domain}-${idx}`,
    kind: 'scam' as const,
    title: i.domain,
    description: `Crypto scam/phishing domain · ${i.tld}`,
    lat: 0,
    lng: 0,
    timestamp: data.generated_at || new Date().toISOString(),
    severity: 'medium' as const,
    source: 'Crypto Scam Feed',
    url: `https://${i.domain}`,
  }));
}

export function fromBreaches(data: {
  breaches?: Array<{
    name: string;
    title: string;
    pwn_count?: number;
    added_date?: string;
    breach_date?: string;
    domain?: string;
  }>;
}): PulseEvent[] {
  return (data.breaches ?? []).slice(0, 30).map((b) => ({
    id: `breach-${b.name}`,
    kind: 'breach' as const,
    title: b.title,
    description: `${(b.pwn_count ?? 0).toLocaleString()} accounts breached`,
    // Breaches are global — no specific geo
    lat: 0,
    lng: 0,
    timestamp: b.added_date || b.breach_date || new Date().toISOString(),
    severity:
      (b.pwn_count ?? 0) > 10_000_000
        ? ('critical' as const)
        : (b.pwn_count ?? 0) > 1_000_000
          ? ('high' as const)
          : ('medium' as const),
    source: 'HIBP',
    url: `https://haveibeenpwned.com/api/v3/breach/${b.name}`,
  }));
}

export function fromBriefings(items: Array<{ slug: string; metadata: Record<string, unknown> }>): PulseEvent[] {
  return items.slice(0, 10).map((b) => ({
    id: `briefing-${b.slug}`,
    kind: 'briefing' as const,
    title: (b.metadata.title as string) ?? b.slug,
    description: `${(b.metadata.type as string) ?? 'daily'} briefing · ${(b.metadata.findings as number) ?? 0} findings`,
    lat: 0,
    lng: 0,
    timestamp: (b.metadata.date as string) ?? new Date().toISOString(),
    severity: 'low' as const,
    source: 'Briefings',
    url: `/threatintel/briefings/${b.slug}`,
  }));
}

const IOC_KIND: Record<string, PulseKind> = {
  'viriback-c2': 'c2_tracker',
  'threatview-ip': 'blocklist',
  'threatview-domains': 'blocklist',
  'certpl-warnings': 'phishing',
  phishunt: 'phishing',
};

export function fromLiveIocs(data: {
  items?: Array<{ value: string; kind: string; source: string; observed_at?: string }>;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 50).flatMap((i, idx) => {
    try {
      return [
        {
          id: `liveioc-${idx}-${(i.value ?? '').slice(-15) || 'x'}`,
          kind: IOC_KIND[i.source ?? ''] ?? 'cyber_attack',
          title: `${(i.kind ?? '').toUpperCase()}: ${(i.value ?? '').slice(0, 80)}`,
          description: `Live IOC from ${i.source ?? 'unknown'}`,
          lat: 0,
          lng: 0,
          timestamp: i.observed_at || new Date().toISOString(),
          severity: 'high' as const,
          source: i.source ?? 'unknown',
          url: '/threatintel/live-iocs',
        },
      ];
    } catch (_catchErr) {
      logError('fromLiveIocs failed', _catchErr);
      return [];
    }
  });
}

// ── GitHub secret leaks (secret-leaks) ──────────────────────────────────
export function fromSecretLeaks(data: {
  leaks?: Array<{ repo?: string; provider?: string; severity?: string; timestamp?: string; url?: string }>;
}): PulseEvent[] {
  return (data.leaks ?? []).slice(0, 25).map((l, i) => ({
    id: `secret-${i}-${(l.repo ?? '').slice(-18)}`,
    kind: 'secret_leak' as const,
    title: l.repo || 'leaked secret',
    description: `${l.provider ?? 'secret'} key leaked in public repo`,
    lat: 0,
    lng: 0,
    timestamp: l.timestamp || new Date().toISOString(),
    severity: asSev(l.severity, 'high'),
    source: 'GitHub Leaks',
    url: l.url,
  }));
}

// ── Malicious packages (malicious-packages) ─────────────────────────────
export function fromMaliciousPackages(data: {
  packages?: Array<{ name?: string; ecosystem?: string; ossf_url?: string }>;
}): PulseEvent[] {
  return (data.packages ?? []).slice(0, 25).map((p, i) => ({
    id: `malpkg-${i}-${(p.name ?? '').slice(-18)}`,
    kind: 'malicious_package' as const,
    title: p.name || 'malicious package',
    description: `${p.ecosystem ?? 'package'} malware (OpenSSF)`,
    lat: 0,
    lng: 0,
    timestamp: new Date().toISOString(),
    severity: 'high' as const,
    source: 'OpenSSF',
    url: p.ossf_url,
  }));
}

// ── Public exploits (exploit-db) ────────────────────────────────────────
export function fromExploitDb(data: {
  results?: Array<{ description?: string; type?: string; platform?: string; date?: string; url?: string }>;
}): PulseEvent[] {
  return (data.results ?? []).slice(0, 20).map((e, i) => ({
    id: `exploit-${i}-${(e.description ?? '').slice(0, 18)}`,
    kind: 'exploit' as const,
    title: (e.description || 'exploit').slice(0, 120),
    description: `${e.type ?? 'exploit'} · ${e.platform ?? 'multi'}`,
    lat: 0,
    lng: 0,
    timestamp: e.date || new Date().toISOString(),
    severity: 'high' as const,
    source: 'Exploit-DB',
    url: e.url,
  }));
}

// ── GitHub security advisories (github-security) ────────────────────────
export function fromGithubAdvisories(data: {
  advisories?: Array<{
    ghsa_id?: string;
    summary?: string;
    severity?: string;
    published_at?: string;
    vulnerabilities?: Array<{ package?: { ecosystem?: string; name?: string } }>;
  }>;
}): PulseEvent[] {
  return (data.advisories ?? []).slice(0, 20).map((a, i) => {
    const pkg = a.vulnerabilities?.[0]?.package;
    return {
      id: `ghsa-${i}-${(a.ghsa_id ?? '').slice(-18)}`,
      kind: 'github_advisory' as const,
      title: (a.summary || a.ghsa_id || 'advisory').slice(0, 120),
      description: pkg ? `${pkg.ecosystem ?? ''}: ${pkg.name ?? ''}`.trim() : 'GitHub advisory',
      lat: 0,
      lng: 0,
      timestamp: a.published_at || new Date().toISOString(),
      severity: asSev(a.severity),
      source: 'GitHub GHSA',
      url: a.ghsa_id ? `https://github.com/advisories/${a.ghsa_id}` : undefined,
    };
  });
}

// ── CISA Known Exploited Vulnerabilities (cisa-kev) ─────────────────────
export function fromCisaKev(data: {
  vulnerabilities?: Array<{
    cve_id?: string;
    product?: string;
    vulnerability_name?: string;
    date_added?: string;
    known_ransomware_campaign_use?: string;
  }>;
}): PulseEvent[] {
  return (data.vulnerabilities ?? []).slice(0, 25).map((v, i) => ({
    id: `kev-${i}-${v.cve_id ?? ''}`,
    kind: 'kev' as const,
    title: `${v.cve_id ?? ''} ${v.product ?? ''}`.trim() || 'KEV',
    description: v.vulnerability_name || 'Known exploited vulnerability',
    lat: 0,
    lng: 0,
    timestamp: v.date_added || new Date().toISOString(),
    severity: v.known_ransomware_campaign_use === 'Known' ? ('critical' as const) : ('high' as const),
    source: 'CISA KEV',
    url: v.cve_id ? `https://nvd.nist.gov/vuln/detail/${v.cve_id}` : undefined,
    // Every row here is KEV-listed by construction — flag it so the frontend
    // renders the 0-DAY chip and the merge sort ranks it with the 0-days.
    kev: true,
  }));
}

// ── 24h CVE digest (cve-digest) ───────────────────────────────────────────
// The digest is a COMPLETE 24h window (unlike cve-recent's paged sample) with
// per-row exploit intelligence (KEV flag, exploit_status, EPSS). This is the
// 0-day surface: KEV-listed rows are confirmed exploited in the wild, and
// weaponized/PoC rows have public exploit code. Selection is signal-first —
// KEV, then exploited, then criticals, then top-up with highs by score —
// capped so one layer can't flood the map the way the C2 triple-source did.

const CVE_DIGEST_CAP = 40;

export function fromCveDigest(data: { entries?: CveDigestEntry[] }): PulseEvent[] {
  const entries = data.entries ?? [];
  const kev = entries.filter((e) => e.is_in_kev);
  const exploited = entries.filter((e) => !e.is_in_kev && e.exploit_status != null && e.exploit_status !== 'none');
  const critical = entries.filter(
    (e) => !e.is_in_kev && (e.exploit_status == null || e.exploit_status === 'none') && e.severity === 'CRITICAL'
  );
  const picked = [...kev, ...exploited, ...critical];
  if (picked.length < CVE_DIGEST_CAP) {
    const pickedIds = new Set(picked.map((e) => e.cve_id));
    const highs = entries
      .filter((e) => !pickedIds.has(e.cve_id) && e.severity === 'HIGH')
      .sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
    picked.push(...highs.slice(0, CVE_DIGEST_CAP - picked.length));
  }
  return picked.slice(0, CVE_DIGEST_CAP).map((e) => {
    const isKev = e.is_in_kev;
    const exploitedStatus = e.exploit_status != null && e.exploit_status !== 'none' ? e.exploit_status : undefined;
    // KEV-listed = confirmed exploited = critical, unconditionally. This also
    // keeps the CVE-ID dedupe in the handler lossless: a digest KEV row never
    // drops severity relative to the KEV-catalog row it displaces.
    const severity: PulseEvent['severity'] = isKev
      ? 'critical'
      : e.severity === 'CRITICAL'
        ? 'critical'
        : e.severity === 'HIGH'
          ? 'high'
          : e.severity === 'MEDIUM'
            ? 'medium'
            : 'low';
    const flags = [
      isKev ? 'KEV-listed — exploited in the wild' : null,
      exploitedStatus ? `exploit: ${exploitedStatus.replace(/_/g, ' ')}` : null,
      e.score != null ? `CVSS ${e.score.toFixed(1)}` : null,
    ]
      .filter(Boolean)
      .join(' · ');
    return {
      id: `digest-${e.cve_id}`,
      kind: (isKev ? 'kev' : 'cve') as PulseEvent['kind'],
      title: e.cve_id,
      description: `${(e.description ?? '').slice(0, 140)}${flags ? ` — ${flags}` : ''}`,
      lat: 0,
      lng: 0,
      ...(e.score != null ? { magnitude: e.score } : {}),
      timestamp: e.published,
      severity,
      source: isKev ? 'CISA KEV · 24h digest' : 'CTIWatch · 24h digest',
      url: e.ctiwatch_url,
      kev: isKev || undefined,
      ...(exploitedStatus ? { exploitStatus: exploitedStatus } : {}),
    };
  });
}

const CVE_ID_RE = /CVE-\d{4}-\d{4,7}/i;

/** Extract a CVE ID from an event id or title, for cross-layer dedupe. */
export function eventCveId(e: Pick<PulseEvent, 'id' | 'title'>): string | null {
  return CVE_ID_RE.exec(`${e.id} ${e.title}`)?.[0]?.toUpperCase() ?? null;
}

/**
 * Rank class for within-severity ordering — the fix for "C2 everytime".
 * Severity still dominates (a critical C2 outranks a high CVE), but within a
 * tier, confirmed-harm signals (ransom victims, KEV 0-days) sort above
 * vulnerability records, which sort above raw infrastructure observations.
 */
export function signalClass(e: Pick<PulseEvent, 'kind' | 'trending'>): number {
  const base =
    e.kind === 'ransomware' || e.kind === 'kev'
      ? 3
      : e.kind === 'cve' || e.kind === 'exploit' || e.kind === 'cisa_advisory' || e.kind === 'github_advisory'
        ? 2
        : 1;
  return base + (e.trending ? 1 : 0);
}

const sevRank = (s: PulseEvent['severity']): number =>
  s === 'critical' ? 4 : s === 'high' ? 3 : s === 'medium' ? 2 : 1;

/**
 * Feed ordering: severity, then signal class, then recency. Exported so the
 * handler and the tests share one comparator — the frontend mirrors it in
 * GlobalPulse.tsx (see signalRank there; keep the two in sync).
 */
export function comparePulseEvents(a: PulseEvent, b: PulseEvent): number {
  const sd = sevRank(b.severity) - sevRank(a.severity);
  if (sd !== 0) return sd;
  const cd = signalClass(b) - signalClass(a);
  if (cd !== 0) return cd;
  const ta = new Date(a.timestamp).getTime();
  const tb = new Date(b.timestamp).getTime();
  return Number.isNaN(ta) || Number.isNaN(tb) ? 0 : tb - ta;
}

/**
 * Drop duplicate CVE sightings across the cve/kev layers, keeping the
 * richest record. The 24h-digest rows carry exploit_status + EPSS + the
 * freshest timestamps, so they win; KEV-catalog rows win over plain
 * cve-recent rows (confirmed-exploited beats merely-published).
 */
export function dedupeCveEvents(events: PulseEvent[]): PulseEvent[] {
  const rankSource = (e: PulseEvent): number => {
    if (e.id.startsWith('digest-')) return 3;
    if (e.kind === 'kev') return 2;
    if (e.kind === 'cve') return 1;
    return 0;
  };
  const seen = new Map<string, PulseEvent>();
  const out: PulseEvent[] = [];
  for (const e of events) {
    if (e.kind !== 'cve' && e.kind !== 'kev') {
      out.push(e);
      continue;
    }
    const cve = eventCveId(e);
    if (!cve) {
      out.push(e);
      continue;
    }
    const prev = seen.get(cve);
    if (!prev) {
      seen.set(cve, e);
      out.push(e);
    } else if (rankSource(e) > rankSource(prev)) {
      seen.set(cve, e);
      out[out.indexOf(prev)] = e;
    }
    // else: weaker duplicate dropped silently.
  }
  return out;
}

/**
 * Stamp the "in trends" signal: a CVE id (or ransomware victim) reported by
 * 2+ DISTINCT sources in this build. Mutates in place and returns the input
 * for pipeline convenience.
 */
export function markTrendingEvents(events: PulseEvent[]): PulseEvent[] {
  const byKey = new Map<string, Set<string>>();
  const keyOf = (e: PulseEvent): string | null => {
    const cve =
      e.kind === 'cve' || e.kind === 'kev' || e.kind === 'exploit' || e.kind === 'github_advisory'
        ? eventCveId(e)
        : null;
    if (cve) return `cve:${cve}`;
    if (e.kind === 'ransomware') {
      // Victim is the stable half of "victim — group" titles (also X-claim
      // variants append " (X claim)" to the group half, so split there).
      const victim = e.title.split('—')[0]?.trim().toLowerCase();
      if (victim) return `victim:${victim}`;
    }
    return null;
  };
  for (const e of events) {
    const k = keyOf(e);
    if (!k) continue;
    const sources = byKey.get(k) ?? new Set<string>();
    sources.add(e.source);
    byKey.set(k, sources);
  }
  for (const e of events) {
    const k = keyOf(e);
    if (k && (byKey.get(k)?.size ?? 0) >= 2) e.trending = true;
  }
  return events;
}

export function fromStealerForum(data: {
  forums?: Array<{ category: string; entries?: Array<{ name: string; url?: string; status?: string }> }>;
  chatter?: Array<{ text?: string; source?: string; date?: string }>;
}): PulseEvent[] {
  const events: PulseEvent[] = [];
  for (const forum of data.forums ?? []) {
    for (const entry of forum.entries ?? []) {
      if (events.length >= 30) break;
      events.push({
        id: `stealer-${events.length}-${entry.name.slice(-15)}`,
        kind: 'infostealer' as const,
        title: entry.name.slice(0, 120),
        description: `${forum.category} · ${entry.status || 'unknown'}`,
        lat: 0,
        lng: 0,
        timestamp: new Date().toISOString(),
        severity: 'high' as const,
        source: forum.category,
        url: entry.url,
      });
    }
  }
  return events;
}

export function fromPhishing(data: {
  urls?: Array<{ url: string; source?: string; first_seen?: string }>;
}): PulseEvent[] {
  return (data.urls ?? []).slice(0, 30).map((i, idx) => ({
    id: `phish-${idx}-${i.url.slice(-20)}`,
    kind: 'phishing' as const,
    title: i.url.slice(0, 100),
    description: `Phishing URL from ${i.source || 'unknown'}`,
    lat: 0,
    lng: 0,
    timestamp: i.first_seen || new Date().toISOString(),
    severity: 'high' as const,
    source: i.source || 'Phishing Feed',
    url: i.url,
  }));
}

export function fromMalware(data: {
  samples?: Array<{ sha256: string; reporter?: string; first_seen?: string; file_type?: string; signature?: string }>;
}): PulseEvent[] {
  return (data.samples ?? []).slice(0, 20).map((i, idx) => ({
    id: `malware-${idx}-${i.sha256.slice(-12)}`,
    kind: 'malware' as const,
    title: `Sample: ${i.sha256.slice(0, 16)}…`,
    description: `${i.file_type || 'binary'} · ${i.signature || 'no signature'}`,
    lat: 0,
    lng: 0,
    timestamp: i.first_seen || new Date().toISOString(),
    severity: 'high' as const,
    source: i.reporter || 'MalwareBazaar',
  }));
}

export function fromWebamonCampaigns(data: {
  generated_at?: string;
  ok?: boolean;
  top_campaigns?: Array<{
    campaign_id: string;
    name: string;
    delta_24h?: number;
    unique_domains_total?: number;
    tags?: string[];
    first_seen?: string;
    last_seen?: string;
  }>;
  changes?: Array<{ campaign_id: string; changes?: { countries?: string[] } }>;
  clusters?: {
    top?: Array<{
      cluster_id: string;
      fingerprint_type: string;
      severity: string;
      unique_domains: number;
      delta_24h: number;
      detected_at?: string;
    }>;
  };
}): PulseEvent[] {
  if (data.ok === false) return [];
  const events: PulseEvent[] = [];
  const countryByCampaign = new Map<string, string>();
  for (const e of data.changes ?? []) {
    const country = e.changes?.countries?.[0];
    if (country && !countryByCampaign.has(e.campaign_id)) countryByCampaign.set(e.campaign_id, country);
  }
  const coord = (country?: string): { lat: number; lng: number; country?: string } => {
    const cc = country ? countryNameToCode(country) : undefined;
    return { lat: cc ? (COUNTRY_COORDS[cc]?.[0] ?? 0) : 0, lng: cc ? (COUNTRY_COORDS[cc]?.[1] ?? 0) : 0, country };
  };
  for (const c of (data.top_campaigns ?? []).slice(0, 15)) {
    const delta = c.delta_24h ?? 0;
    if (delta <= 0) continue;
    const g = coord(countryByCampaign.get(c.campaign_id));
    const tags = c.tags?.length ? ` · ${c.tags.slice(0, 3).join(', ')}` : '';
    events.push({
      id: `webamon-${c.campaign_id}`,
      kind: 'phishing' as const,
      title: `${c.name}: +${delta} domains/24h`,
      description: `Webamon tracked estate · ${(c.unique_domains_total ?? 0).toLocaleString()} domains total${tags}`,
      lat: g.lat,
      lng: g.lng,
      magnitude: delta,
      timestamp: c.last_seen || c.first_seen || data.generated_at || new Date().toISOString(),
      severity: delta >= 300 ? ('critical' as const) : delta >= 50 ? ('high' as const) : ('medium' as const),
      source: 'Webamon',
      url: 'https://intel.webamon.com',
      country: g.country,
    });
  }
  for (const cl of (data.clusters?.top ?? []).slice(0, 10)) {
    if (cl.severity === 'watch') continue;
    events.push({
      id: `webamon-cluster-${cl.cluster_id.slice(-24)}`,
      kind: 'malware' as const,
      title: `Emerging ${cl.fingerprint_type} cluster · ${cl.unique_domains.toLocaleString()} domains`,
      description: `Webamon emerging cluster (+${cl.delta_24h}/24h) · not yet a tracked campaign`,
      lat: 0,
      lng: 0,
      magnitude: cl.unique_domains,
      timestamp: cl.detected_at || data.generated_at || new Date().toISOString(),
      severity: cl.severity === 'critical' ? ('critical' as const) : ('high' as const),
      source: 'Webamon',
      url: 'https://intel.webamon.com',
    });
  }
  return events;
}

export function fromRansomware(data: {
  victims?: Array<{
    victim: string;
    group: string;
    discovered: string;
    country?: string;
    sector?: string;
    source_url?: string;
  }>;
}): PulseEvent[] {
  return (data.victims ?? []).slice(0, 30).map((v) => {
    // Look up coordinates from country name
    const cc = countryNameToCode(v.country);
    return {
      id: `ransom-${v.victim}-${v.group}`,
      kind: 'ransomware' as const,
      title: `${v.victim} — ${v.group}`,
      description: `${v.sector || 'Unknown'} sector · ${v.country || 'Unknown country'}`,
      lat: cc ? (COUNTRY_COORDS[cc]?.[0] ?? 0) : 0,
      lng: cc ? (COUNTRY_COORDS[cc]?.[1] ?? 0) : 0,
      timestamp: v.discovered || new Date().toISOString(),
      severity: 'critical' as const,
      source: v.group,
      url: v.source_url,
      country: v.country,
    };
  });
}

export function fromCybercrime(data: {
  items?: Array<{ title: string; source?: string; url?: string; date?: string; published?: string }>;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 30).map((i, idx) => ({
    id: `crime-${idx}-${i.title.slice(-15)}`,
    kind: 'cybercrime' as const,
    title: i.title.slice(0, 120),
    description: `Cybercrime intel from ${i.source || 'unknown'}`,
    lat: 0,
    lng: 0,
    timestamp: i.published || i.date || new Date().toISOString(),
    severity: 'medium' as const,
    source: i.source || 'Cybercrime',
    url: i.url,
  }));
}

export function fromWriteups(data: {
  items?: Array<{ title: string; source?: string; url?: string; published?: string }>;
}): PulseEvent[] {
  return (data.items ?? []).slice(0, 15).map((i, idx) => ({
    id: `writeup-${idx}-${i.title.slice(-15)}`,
    kind: 'research' as const,
    title: i.title.slice(0, 120),
    description: `Research from ${i.source || 'unknown'}`,
    lat: 0,
    lng: 0,
    timestamp: i.published || new Date().toISOString(),
    severity: 'low' as const,
    source: i.source || 'Research',
    url: i.url,
  }));
}

export function fromCveRecent(data: {
  cves?: Array<{
    id: string;
    severity: string;
    score: number | null;
    kev: boolean;
    published: string;
    description?: string;
  }>;
}): PulseEvent[] {
  return (data.cves ?? []).slice(0, 20).map((c) => {
    // Derive severity from the CVSS score when available — more granular
    // than the upstream severity string (which only has CRITICAL/HIGH/MEDIUM/LOW).
    // Falls back to the string if the score is null/0 (unscored CVEs).
    const score = typeof c.score === 'number' && c.score > 0 ? c.score : null;
    const severity: Sev = score
      ? score >= 9.0
        ? 'critical'
        : score >= 7.0
          ? 'high'
          : score >= 4.0
            ? 'medium'
            : 'low'
      : c.severity === 'CRITICAL'
        ? 'critical'
        : c.severity === 'HIGH'
          ? 'high'
          : c.severity === 'MEDIUM'
            ? 'medium'
            : 'low';
    const scoreLabel = score ? score.toFixed(1) : 'N/A';
    return {
      id: `cve-${c.id}`,
      kind: 'cve' as const,
      title: c.id,
      description: c.description?.slice(0, 100) || `CVSS ${scoreLabel} · ${c.kev ? 'CISA KEV' : 'NVD'}`,
      lat: 0,
      lng: 0,
      magnitude: score ?? undefined,
      timestamp: c.published || new Date().toISOString(),
      severity,
      source: c.kev ? 'CISA KEV' : 'NVD',
      url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
    };
  });
}

/* ─── X Claims (ransomware claims from Twitter) ──────────────────────────── */

export function fromXClaims(data: XClaimsResponse): PulseEvent[] {
  const events: PulseEvent[] = [];
  for (const v of (data.ransomware ?? []).slice(0, 20)) {
    events.push({
      id: `xclaim-ransom-${v.victim}-${v.group}`,
      kind: 'ransomware',
      title: `${v.victim} — ${v.group} (X claim)`,
      description: `${v.description || 'Ransomware claim from X/Twitter'} · ${v.sector || 'Unknown sector'}`,
      lat: 0,
      lng: 0,
      timestamp: v.discovered || new Date().toISOString(),
      severity: 'critical',
      source: `X: ${v.group}`,
      url: v.source_url,
      country: v.country,
    });
  }
  for (const [bi, b] of (data.breach ?? []).slice(0, 10).entries()) {
    events.push({
      id: `xclaim-breach-${b.discovered}-${b.victim?.slice(0, 20) || ''}-${bi}`,
      kind: 'breach',
      title: `Breach claim: ${b.victim || 'Unknown'}`,
      description: b.text.slice(0, 120),
      lat: 0,
      lng: 0,
      timestamp: b.discovered || new Date().toISOString(),
      severity: 'high',
      source: `X: @${b.handle}`,
      url: b.source_url,
    });
  }
  return events;
}

/* ─── Actor Timeline (threat actor activity) ──────────────────────────────── */

export function fromActorTimeline(data: ActorTimelineResponse): PulseEvent[] {
  return (data.groups ?? [])
    .filter((g) => g.posts_in_window > 0)
    .slice(0, 20)
    .map((g) => ({
      id: `actor-${g.slug}`,
      kind: 'actor_sighting',
      title: `${g.display_name} — ${g.posts_in_window} posts (30d)`,
      description: `${g.raas ? 'RaaS · ' : ''}${g.description?.slice(0, 100) || 'Active threat actor group'}${g.mitre ? ` · MITRE: ${g.mitre.name}` : ''}`,
      lat: 0,
      lng: 0,
      timestamp: new Date(data.generated_at).toISOString(),
      severity: g.posts_in_window > 100 ? 'critical' : g.posts_in_window > 20 ? 'high' : 'medium',
      source: 'Actor Timeline',
    }));
}

/* ─── IOC Correlation (cross-feed IOCs) ──────────────────────────────────── */

export function fromIocCorrelation(data: IocCorrelationResponse): PulseEvent[] {
  const events: PulseEvent[] = [];
  const byKind = { ips: 'ip', urls: 'url', domains: 'domain', hashes: 'hash' } as const;
  for (const [key, kind] of Object.entries(byKind)) {
    const items = (data as unknown as Record<string, unknown>)[key] as Array<{
      value: string;
      source_count: number;
      sources: string[];
      context?: string;
      last_seen?: string;
    }>;
    for (const i of (items ?? []).filter((i) => i.source_count >= 2).slice(0, 10)) {
      events.push({
        id: `ioc-corr-${kind}-${i.value.slice(0, 20)}`,
        kind: 'ioc_correlation',
        title: `${kind.toUpperCase()}: ${i.value.slice(0, 80)}`,
        description: `Cross-feed IOC (${i.source_count} sources) · ${i.context || 'No context'}`,
        lat: 0,
        lng: 0,
        timestamp: i.last_seen || data.generated_at,
        severity: i.source_count >= 5 ? 'critical' : i.source_count >= 3 ? 'high' : 'medium',
        source: i.sources[0] || 'IOC Correlation',
      });
    }
  }
  return events;
}

/* ─── NASA FIRMS thermal anomalies ───────────────────────────────────────── */
/* Shape: { generated_at, fires: FirmsFire[] } — see api/src/routes/firms-ukmto.ts.
   Each fire becomes a PulseEvent with FRP-derived severity:
     - FRP < 1 MW                       → dropped (background noise)
     - FRP < 10 MW + brightness >= 340 K → 'medium'
     - FRP 10..50 MW                    → 'high'
     - FRP >= 50 MW                     → 'critical'
   Capped at 250, sorted FRP desc. */

interface FirmFireLike {
  id?: string;
  lat: number;
  lng: number;
  frp: number;
  brightness: number;
  acq_date: string;
  acq_time: string;
  satellite?: string;
  confidence?: string;
  daynight?: 'D' | 'N';
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function fromFirms(data: { fires?: FirmFireLike[] } | null | undefined): PulseEvent[] {
  if (!data) return [];
  const fires = (data.fires ?? []).filter((f) => typeof f.frp === 'number' && f.frp >= 1);
  // Sort by FRP desc, cap at 250.
  const top = [...fires].sort((a, b) => b.frp - a.frp).slice(0, 250);
  return top.map((f) => {
    const severity: Sev = f.frp >= 50 ? 'critical' : f.frp >= 10 ? 'high' : f.brightness >= 340 ? 'medium' : 'low';
    const hh = f.acq_time ? f.acq_time.slice(0, 2) : '00';
    const mm = f.acq_time ? f.acq_time.slice(2, 4) : '00';
    const ts = `${f.acq_date ?? ''}T${pad2(parseInt(hh || '0', 10))}:${pad2(parseInt(mm || '0', 10))}Z`;
    return {
      id: `firms-${f.id ?? `${f.acq_date}-${f.acq_time}-${f.lat}-${f.lng}`}`,
      kind: 'firm' as const,
      title: `FIRMS fire · FRP ${f.frp.toFixed(1)} MW${f.satellite ? ` · ${f.satellite}` : ''}`,
      description: `Brightness ${f.brightness.toFixed(1)} K · confidence ${f.confidence ?? 'n/a'} · ${f.daynight ?? '?'}`,
      lat: f.lat,
      lng: f.lng,
      timestamp: ts,
      severity,
      source: 'NASA FIRMS',
    };
  });
}

/* ─── UKMTO maritime incidents ───────────────────────────────────────────── */
/* Shape: { generated_at, incidents: UkmtoIncident[] }.
   Severity is category-driven:
     - 'Piracy' / 'Armed Attack'              → 'critical'
     - 'Suspicious Approach' / hijack / board  → 'high'
     - anything else                          → 'medium'
   Date string is parsed to ISO; nullish input returns []. */

interface UkmtoIncidentLike {
  id?: string;
  title: string;
  category: string;
  date: string;
  lat: number;
  lng: number;
}

export function fromUkmto(data: { incidents?: UkmtoIncidentLike[] } | null | undefined): PulseEvent[] {
  if (!data) return [];
  return (data.incidents ?? []).map((i) => {
    const cat = (i.category ?? '').toLowerCase();
    const severity: Sev =
      cat.includes('piracy') || cat.includes('armed')
        ? 'critical'
        : cat.includes('suspicious') || cat.includes('hijack') || cat.includes('board')
          ? 'high'
          : 'medium';
    let ts: string;
    try {
      ts = new Date(i.date).toISOString();
    } catch (_catchErr) {
      logError('fromUkmto failed', _catchErr);
      ts = new Date().toISOString();
    }
    return {
      id: `ukmto-${i.id ?? `${i.date}-${i.lat}-${i.lng}`}`,
      kind: 'maritime' as const,
      title: i.title || `UKMTO ${i.category}`,
      description: `${i.category} · ${i.lat.toFixed(2)}, ${i.lng.toFixed(2)}`,
      lat: i.lat,
      lng: i.lng,
      timestamp: ts,
      severity,
      source: 'UKMTO',
    };
  });
}

/* ─── CyberPulse incidents (D1-backed breach/leak tracker) ────────────────── */

export function fromCyberPulse(data: {
  incidents?: Array<{
    id: string;
    incident_type: string;
    severity: string;
    title: string;
    description?: string;
    victim_name?: string;
    victim_country?: string;
    victim_sector?: string;
    threat_actor?: string;
    records_count?: number;
    source_platform?: string;
    discovered_at?: string;
    url?: string;
  }>;
}): PulseEvent[] {
  return (data.incidents ?? []).slice(0, 30).map((inc) => {
    // Geo-locate by victim country code if we have coords for it.
    const coords = inc.victim_country ? COUNTRY_COORDS[inc.victim_country] : undefined;
    const jitterLat = coords ? (Math.random() - 0.5) * 2 : 0;
    const jitterLng = coords ? (Math.random() - 0.5) * 4 : 0;

    const sev: Sev =
      inc.severity === 'critical'
        ? 'critical'
        : inc.severity === 'high'
          ? 'high'
          : inc.severity === 'low' || inc.severity === 'info'
            ? 'low'
            : 'medium';

    const actor = inc.threat_actor ? ` · ${inc.threat_actor}` : '';
    const records =
      inc.records_count && inc.records_count > 0 ? ` · ${inc.records_count.toLocaleString('en-US')} records` : '';
    const sector = inc.victim_sector ? ` · ${inc.victim_sector}` : '';

    return {
      id: `cp-${inc.id}`,
      kind: 'cyberpulse' as const,
      title: inc.victim_name || inc.title?.slice(0, 60) || 'Unknown incident',
      description: `${inc.incident_type}${sector}${actor}${records}`.slice(0, 140),
      lat: coords ? coords[0] + jitterLat : 0,
      lng: coords ? coords[1] + jitterLng : 0,
      timestamp: inc.discovered_at || new Date().toISOString(),
      severity: sev,
      source: inc.source_platform || 'CyberPulse',
      country: inc.victim_country,
      url: inc.url,
    };
  });
}

export function fromRss(data: {
  articles?: Array<{ title: string; link: string; description?: string; pub_date: string; source: string }>;
}): PulseEvent[] {
  return (data.articles ?? []).slice(0, 50).map((item) => ({
    id: `rss-${(item.link ?? '').slice(-32) || Math.random().toString(36).slice(2)}`,
    kind: 'rss' as const,
    title: (item.title ?? '').slice(0, 120),
    description: (item.description ?? '').slice(0, 200),
    lat: 0,
    lng: 0,
    timestamp: item.pub_date || new Date().toISOString(),
    severity: 'low' as const,
    source: item.source || 'RSS',
    url: item.link,
  }));
}

/**
 * Dedicated AI/LLM intel (llm-threatintel + ai-honeypots) → pulse events.
 *
 * The narrative surfaces, NOT the observed IPs: campaigns/actors, write-ups,
 * and the trend rollup. `honeypot` already renders observed addresses on the
 * map; duplicating them here would double-count the same infrastructure on the
 * same screen.
 *
 * Campaign posts carry no geography, so `lat/lng` are 0 — same convention as
 * `fromHoneypot`, which the map treats as "unlocated".
 */
export function fromAiLlmIntel(data: {
  actors?: Array<{
    id: string;
    names?: string[];
    type?: string;
    first_seen?: string;
    status?: string;
    distribution?: string[];
    ttps?: string[];
    description?: string;
  }>;
  posts?: Array<{
    id: string;
    title: string;
    date: string;
    author?: string;
    tags?: string[];
    excerpt?: string;
    url?: string;
  }>;
  blog?: Array<{
    id: string;
    title: string;
    date: string;
    author?: string;
    tags?: string[];
    excerpt?: string;
    url?: string;
  }>;
  honeypot_actor_classes?: Array<{ category: string; description?: string; count: number }>;
}): PulseEvent[] {
  const events: PulseEvent[] = [];
  const today = new Date().toISOString();

  for (const a of (data.actors ?? []).slice(0, 25)) {
    const ttps = (a.ttps ?? []).slice(0, 3).join(', ');
    events.push({
      id: `aillm-campaign-${a.id}`.slice(0, 120),
      kind: 'ai_llm_campaign' as const,
      title: (a.names?.[0] || a.id).slice(0, 120),
      description: [a.type, a.status, ttps ? `techniques: ${ttps}` : ''].filter(Boolean).join(' · ').slice(0, 220),
      lat: 0,
      lng: 0,
      timestamp: a.first_seen || today,
      // A tracked active campaign outranks a background trend. The technique
      // list is the discriminator: credential/execution TT&CK means the
      // campaign is doing something, not just being catalogued.
      severity: (a.ttps ?? []).some((t) => /T1059|T1552|T1204|T1190/.test(t)) ? 'high' : 'medium',
      source: 'LLM ThreatIntel',
      url: `https://llm-threatintel.com/#${a.id}`,
    });
  }

  const narrative = [...(data.posts ?? []), ...(data.blog ?? [])].slice(0, 30);
  for (const p of narrative) {
    const tags = p.tags ?? [];
    events.push({
      id: `aillm-post-${p.id}`.slice(0, 120),
      kind: 'ai_llm_research' as const,
      title: p.title.slice(0, 120),
      description: [p.excerpt?.slice(0, 180), tags.length ? `tags: ${tags.slice(0, 5).join(', ')}` : '']
        .filter(Boolean)
        .join(' · ')
        .slice(0, 220),
      lat: 0,
      lng: 0,
      timestamp: p.date || today,
      severity: tags.some((t) => /clickfix|phishing|injection|mcp|exfiltrat|malware|rat|stealer/.test(t))
        ? 'high'
        : 'medium',
      source: 'LLM ThreatIntel',
      url: p.url || 'https://llm-threatintel.com/',
    });
  }

  return events;
}

export function fromHoneypot(data: {
  source_url?: string;
  indicators?: Array<{
    ioc_type: string;
    value: string;
    confidence: string;
    actor_category: string;
    ttps: string[];
    last_seen: string;
    first_seen: string;
    total_hits: number;
    distinct_personas: number;
  }>;
}): PulseEvent[] {
  return (data.indicators ?? []).slice(0, 60).map((ind) => {
    const hits = ind.total_hits ?? 0;
    const conf = (ind.confidence ?? '').toLowerCase();
    const severity: Sev = conf === 'high' || hits >= 100 ? 'high' : conf === 'medium' || hits >= 20 ? 'medium' : 'low';
    const ttps = (ind.ttps ?? []).slice(0, 3).join(', ');
    return {
      id: `honeypot-${ind.ioc_type ?? 'ioc'}-${(ind.value ?? '').slice(-32) || Math.random().toString(36).slice(2)}`,
      kind: 'honeypot' as const,
      title: `${ind.ioc_type ?? 'ioc'}: ${ind.value ?? 'unknown'}`.slice(0, 120),
      description: `${ind.actor_category ?? 'unknown actor'} · ${hits} hits · ${ind.distinct_personas ?? 0} personas${
        ttps ? ` · ${ttps}` : ''
      }`.slice(0, 220),
      lat: 0,
      lng: 0,
      timestamp: ind.last_seen || ind.first_seen || new Date().toISOString(),
      severity,
      source: 'AI Honeypot',
      url: data.source_url,
    };
  });
}
