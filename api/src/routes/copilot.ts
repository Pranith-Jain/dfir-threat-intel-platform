import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError } from '../lib/api-error';
import { LIVE_IOCS_CACHE_KEY } from './live-iocs';
import { safeNullLog } from '../lib/safe-catch';
import { neutralizeUntrusted } from '../lib/prompt-fence';
import { RANSOMWARE_RECENT_CACHE_KEY } from './ransomware-recent';
import { ACTOR_TIMELINE_CACHE_KEY } from './actor-timeline';
import { CVE_RECENT_CACHE_KEY } from './cve-recent';
import { WRITEUPS_CACHE_KEY } from './writeups';
import { MALWARE_SAMPLES_CACHE_KEY } from './malware-samples';
import { DETECTIONS_CACHE_KEY } from './detections';
import { CYBERCRIME_CACHE_KEY } from './cybercrime';
import { IOC_CORRELATION_CACHE_KEY } from './ioc-correlation';
import { NEGOTIATIONS_CACHE_KEY } from './negotiations';
import { type IndicatorType } from '../lib/indicator';
import type { Indicator, ProviderEnv, ProviderResult, ProviderAdapter } from '../providers/types';
import { lookupCve } from '../lib/cve-lookup';
import { fetchRlUpstream } from './ransomwarelive';
import { ACTOR_ALIASES } from '../data/threat-actor-aliases';
import { virustotal as vtProvider } from '../providers/virustotal';
import { abuseipdb as abuseProvider } from '../providers/abuseipdb';
import { otx as otxProvider } from '../providers/otx';
import { greynoise as gnProvider } from '../providers/greynoise';
import { urlscan as urlscanProvider } from '../providers/urlscan';
import { malwarebazaar as mbProvider } from '../providers/malwarebazaar';
import { malshare as msProvider } from '../providers/malshare';
import { queryCorpus, formatRetrievedContext } from '../lib/rag-embedder';
import { computeConfidence, type ConfidenceScore } from '../lib/confidence';
import { validateAiOutput } from '../lib/ai-output-validator';

export interface Source {
  name: string;
  items: number;
  data: unknown;
}

export interface CopilotResponse {
  query: string;
  query_type: string;
  narrative: string;
  sources: Source[];
  model_used: string;
  processed_at: string;
  _meta?: { total_sources: number; total_items: number };
  /** Computed analytic confidence based on source reliability grading */
  confidence?: ConfidenceScore;
}

import { detectType } from '../lib/report/subject-resolver';
import type { SubjectType } from '../lib/report/types';

export type QueryType = SubjectType;

export async function readCache<T>(key: string): Promise<T | null> {
  try {
    const cache = caches.default;
    const cached = await cache.match(new Request(key));
    if (cached) return (await cached.json()) as T;
  } catch (_catchErr) {
    logError('readCache failed', _catchErr);
    /* miss */
  }
  return null;
}

// Internal cache keys not exported from their modules
export const C2_CACHE_KEY = 'https://c2-cache.internal/v8';
const MALPEDIA_CACHE_KEY = 'https://malpedia-cache.internal/v2';
export const BREACH_CACHE_KEY = 'https://breach-cache.internal/v6-hibp-only';

export const matchText = (query: string, text: string | undefined): boolean =>
  text?.toLowerCase().includes(query.toLowerCase()) ?? false;

const matchCve = (query: string, id: string | undefined) => (id ?? '').toUpperCase() === query.trim().toUpperCase();

/**
 * Loose shape for the heterogeneous, cache-sourced records the search
 * predicates filter over. Every field is optional; the index signature covers
 * provider-specific fields not enumerated here. Replaces per-predicate `any`.
 */
interface SearchItem {
  id?: string;
  title?: string;
  description?: string;
  value?: string;
  source?: string;
  ip?: string;
  domain?: string;
  victim?: string;
  group?: string;
  slug?: string;
  display_name?: string;
  rule_name?: string;
  rule_id?: string;
  sha256?: string;
  name?: string;
  common_name?: string;
  tags?: string[];
  indicators?: Array<{ value?: string }>;
  [key: string]: unknown;
}

function buildSourceAdder(_query: string) {
  return async <T>(
    name: string,
    key: string,
    extract: (data: T) => SearchItem[],
    filter?: (item: SearchItem) => boolean
  ): Promise<Source | null> => {
    const data = await readCache<T>(key);
    if (!data) return null;
    const items = extract(data).filter(filter ?? (() => true));
    if (items.length === 0) return null;
    return { name, items: items.length, data: items.slice(0, 30) };
  };
}

export async function gatherSources(query: string, type: QueryType) {
  const add = buildSourceAdder(query);
  const q = query.trim();
  const ql = q.toLowerCase();

  // Build all cache read promises per query type — fully parallel
  let promises: Promise<Source | null>[];

  // Live CVE lookup — fetches NVD / EPSS / KEV / PoC in parallel
  let cveLiveSource: Source | null = null;
  if (type === 'cve') {
    const doCveLookup = async (): Promise<Source | null> => {
      const result = await lookupCve(q.toUpperCase());
      if (!result.ok) return null;
      return { name: 'CVE Search (live)', items: 1, data: { ...result.data } };
    };
    const cvePromise = doCveLookup();

    const cachePromises = [
      add(
        'Recent CVEs',
        CVE_RECENT_CACHE_KEY,
        (d: { cves: SearchItem[] }) => d.cves,
        (c) => matchCve(q, c.id)
      ),
      add(
        'Breach Disclosures',
        BREACH_CACHE_KEY,
        (d: { breaches: SearchItem[] }) => d.breaches,
        (b) => b.description?.toLowerCase().includes(ql) ?? false
      ),
      add(
        'Actor Timeline',
        ACTOR_TIMELINE_CACHE_KEY,
        (d: { groups: SearchItem[] }) => d.groups,
        (g) => (g.description ?? '').toLowerCase().includes(ql)
      ),
      add(
        'Writeups',
        WRITEUPS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (w) =>
          matchText(ql, w.title) ||
          matchText(ql, w.description) ||
          (w.tags?.some((t: string) => matchText(ql, t)) ?? false)
      ),
      add(
        'Detections',
        DETECTIONS_CACHE_KEY,
        (d: { detections: SearchItem[] }) => d.detections,
        (d) => matchText(ql, d.rule_name) || matchText(ql, d.rule_id)
      ),
      add(
        'Cybercrime',
        CYBERCRIME_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (c) => matchText(ql, c.title) || matchText(ql, c.description)
      ),
      add(
        'IOC Correlation',
        IOC_CORRELATION_CACHE_KEY,
        (d: { hashes: SearchItem[]; ips: SearchItem[]; domains: SearchItem[] }) => [
          ...(d.hashes ?? []),
          ...(d.ips ?? []),
          ...(d.domains ?? []),
        ],
        (e) => matchText(ql, e.value)
      ),
    ];
    promises = cachePromises;
    cveLiveSource = await cvePromise;
  } else if (type === 'ip') {
    promises = [
      add(
        'Live IOCs',
        LIVE_IOCS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (i) => i.value === q
      ),
      add(
        'C2 Tracker',
        C2_CACHE_KEY,
        (d: { entries: SearchItem[] }) => d.entries,
        (e) => e.ip === q
      ),
      add(
        'IOC Correlation',
        IOC_CORRELATION_CACHE_KEY,
        (d: { ips: SearchItem[] }) => d.ips,
        (e) => e.value === q
      ),
      add(
        'Ransomware Recent',
        RANSOMWARE_RECENT_CACHE_KEY,
        (d: { victims: SearchItem[] }) => d.victims,
        (v) => v.victim?.includes(q) ?? false
      ),
      add(
        'Actor Timeline',
        ACTOR_TIMELINE_CACHE_KEY,
        (d: { groups: SearchItem[] }) => d.groups,
        (g) => matchText(ql, g.description)
      ),
      add(
        'Writeups',
        WRITEUPS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (w) => matchText(ql, w.title) || matchText(ql, w.description)
      ),
      add(
        'Detections',
        DETECTIONS_CACHE_KEY,
        (d: { detections: SearchItem[] }) => d.detections,
        (d) => (d.indicators ?? []).some((i) => i.value === q)
      ),
    ];
  } else if (type === 'domain') {
    promises = [
      add(
        'Live IOCs',
        LIVE_IOCS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (i) => i.value === q
      ),
      add(
        'IOC Correlation',
        IOC_CORRELATION_CACHE_KEY,
        (d: { domains: SearchItem[] }) => d.domains,
        (e) => e.value === q
      ),
      add(
        'Breach Disclosures',
        BREACH_CACHE_KEY,
        (d: { breaches: SearchItem[] }) => d.breaches,
        (b) => b.domain?.toLowerCase() === q.toLowerCase() || (b.description ?? '').toLowerCase().includes(ql)
      ),
      add(
        'Writeups',
        WRITEUPS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (w) => matchText(ql, w.title) || matchText(ql, w.description)
      ),
      add(
        'Actor Timeline',
        ACTOR_TIMELINE_CACHE_KEY,
        (d: { groups: SearchItem[] }) => d.groups,
        (g) => matchText(ql, g.description)
      ),
      add(
        'Detections',
        DETECTIONS_CACHE_KEY,
        (d: { detections: SearchItem[] }) => d.detections,
        (d) => (d.indicators ?? []).some((i) => i.value === q)
      ),
    ];
  } else if (type === 'hash') {
    promises = [
      add(
        'Live IOCs',
        LIVE_IOCS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (i) => i.value === q
      ),
      add(
        'Malware Samples',
        MALWARE_SAMPLES_CACHE_KEY,
        (d: { samples: Array<{ sha256: string; signature?: string }> }) => d.samples,
        (s) => s.sha256 === q
      ),
      add(
        'IOC Correlation',
        IOC_CORRELATION_CACHE_KEY,
        (d: { hashes: SearchItem[] }) => d.hashes,
        (e) => e.value === q
      ),
      add(
        'Writeups',
        WRITEUPS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (w) => matchText(ql, w.title) || matchText(ql, w.description)
      ),
      add(
        'Actor Timeline',
        ACTOR_TIMELINE_CACHE_KEY,
        (d: { groups: SearchItem[] }) => d.groups,
        (g) => matchText(ql, g.description)
      ),
    ];
  } else {
    // actor, ransomware, generic — gather everything
    promises = [
      add(
        'Ransomware Recent',
        RANSOMWARE_RECENT_CACHE_KEY,
        (d: { victims: SearchItem[] }) => d.victims,
        (v) => matchText(ql, v.group)
      ),
      add(
        'Actor Timeline',
        ACTOR_TIMELINE_CACHE_KEY,
        (d: { groups: SearchItem[] }) => d.groups,
        (g) => matchText(ql, g.display_name) || matchText(ql, g.slug)
      ),
      add(
        'Recent CVEs',
        CVE_RECENT_CACHE_KEY,
        (d: { cves: SearchItem[] }) => (Array.isArray(d.cves) ? d.cves.slice(0, 50) : []),
        (c) => matchText(ql, c.description) || matchText(ql, c.id)
      ),
      add(
        'Live IOCs',
        LIVE_IOCS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (i) => matchText(ql, i.value) || matchText(ql, i.source)
      ),
      add(
        'Writeups',
        WRITEUPS_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (w) => matchText(ql, w.title) || matchText(ql, w.description)
      ),
      add(
        'Breach Disclosures',
        BREACH_CACHE_KEY,
        (d: { breaches: SearchItem[] }) => d.breaches,
        (b) => (b.description ?? '').toLowerCase().includes(ql)
      ),
      add(
        'Detections',
        DETECTIONS_CACHE_KEY,
        (d: { detections: SearchItem[] }) => d.detections,
        (d) => matchText(ql, d.rule_name) || matchText(ql, d.rule_id)
      ),
      add(
        'Cybercrime',
        CYBERCRIME_CACHE_KEY,
        (d: { items: SearchItem[] }) => d.items,
        (c) => matchText(ql, c.title) || matchText(ql, c.description)
      ),
      add(
        'Negotiations',
        NEGOTIATIONS_CACHE_KEY,
        (d: { groups: SearchItem[] }) => d.groups,
        (g) => matchText(ql, g.group)
      ),
      add(
        'Malpedia',
        MALPEDIA_CACHE_KEY,
        (d: { families: SearchItem[] }) => d.families,
        (f) => matchText(ql, f.name) || matchText(ql, f.common_name)
      ),
    ];
  }

  // Execute ALL cache reads in parallel
  const results = await Promise.allSettled(promises);
  const sources: Source[] = [];
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value) sources.push(r.value);
  }
  if (cveLiveSource) sources.push(cveLiveSource);
  return sources;
}

const PROVIDER_TIMEOUT = 8000;

function queryTypeToIndicatorType(qt: QueryType): IndicatorType | null {
  if (qt === 'ip') return 'ipv4';
  if (qt === 'domain') return 'domain';
  if (qt === 'hash') return 'hash';
  return null;
}

function buildProviderEnv(env: Env): ProviderEnv {
  return {
    VT_API_KEY: env.VT_API_KEY ?? '',
    ABUSEIPDB_API_KEY: env.ABUSEIPDB_API_KEY ?? '',
    SHODAN_API_KEY: env.SHODAN_API_KEY ?? '',
    CENSYS_PAT: env.CENSYS_PAT ?? '',
    CENSYS_ORG_ID: env.CENSYS_ORG_ID ?? '',
    NETLAS_API_KEY: env.NETLAS_API_KEY ?? '',
    OTX_API_KEY: env.OTX_API_KEY ?? '',
    URLSCAN_API_KEY: env.URLSCAN_API_KEY ?? '',
    HYBRID_ANALYSIS_API_KEY: env.HYBRID_ANALYSIS_API_KEY ?? '',
    ABUSECH_AUTH_KEY: env.ABUSECH_AUTH_KEY,
    MALSHARE_API_KEY: env.MALSHARE_API_KEY,
    POLYSWARM_API_KEY: env.POLYSWARM_API_KEY,
  };
}

type ProviderEntry = { id: string; adapter: ProviderAdapter };

const ENRICHMENT_PROVIDERS: Record<string, ProviderEntry[]> = {
  ipv4: [
    { id: 'virustotal', adapter: vtProvider },
    { id: 'abuseipdb', adapter: abuseProvider },
    { id: 'otx', adapter: otxProvider },
    { id: 'greynoise', adapter: gnProvider },
  ],
  domain: [
    { id: 'virustotal', adapter: vtProvider },
    { id: 'otx', adapter: otxProvider },
    { id: 'urlscan', adapter: urlscanProvider },
  ],
  hash: [
    { id: 'virustotal', adapter: vtProvider },
    { id: 'malwarebazaar', adapter: mbProvider },
    { id: 'malshare', adapter: msProvider },
    { id: 'otx', adapter: otxProvider },
  ],
};

export async function gatherLiveEnrichment(query: string, queryType: QueryType, env: Env): Promise<Source[]> {
  const pEnv = buildProviderEnv(env);

  // For IP/domain/hash — run provider adapters
  const indType = queryTypeToIndicatorType(queryType);
  if (indType) {
    const indicator: Indicator = { type: indType, value: query.trim() };
    const entries = ENRICHMENT_PROVIDERS[indType];
    if (!entries) return [];

    const results = await Promise.allSettled(
      entries.map(async (entry) => {
        const signal = AbortSignal.timeout(PROVIDER_TIMEOUT);
        return entry.adapter(indicator, pEnv, signal);
      })
    );

    const enriched: ProviderResult[] = [];
    for (const r of results) {
      if (r.status === 'fulfilled') enriched.push(r.value);
    }
    if (enriched.length === 0) return [];

    const dataItems = enriched.map((r) => ({
      source: r.source,
      status: r.status,
      score: r.score,
      verdict: r.verdict,
      tags: r.tags,
      summary: r.raw_summary,
      error: r.error,
    }));
    const categories = dataItems.map((d) => `${d.source}: ${d.verdict} (score=${d.score})`).join(', ');
    return [
      {
        name: 'Live Enrichment',
        items: dataItems.length,
        data: { providers: dataItems, summary: categories },
      },
    ];
  }

  // For CVE — Shodan CVEDB adds exploitation context (CVSS, EPSS, KEV, ransomware).
  if (queryType === 'cve') {
    try {
      const res = await fetch(`https://cvedb.shodan.io/cve/${query.trim().toUpperCase()}`, {
        headers: { accept: 'application/json', 'user-agent': 'pranithjain-dfir/1.0' },
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT),
      });
      if (res.ok) {
        const d = (await res.json()) as {
          summary?: string;
          cvss?: number;
          cvss_v3?: number;
          epss?: number;
          ranking_epss?: number;
          kev?: boolean;
          ransomware_campaign?: string;
          propose_action?: string;
        };
        return [
          {
            name: 'Shodan CVEDB (live)',
            items: 1,
            data: {
              cvss: typeof d.cvss_v3 === 'number' ? d.cvss_v3 : (d.cvss ?? null),
              epss: d.epss ?? null,
              epss_percentile: d.ranking_epss ?? null,
              kev: d.kev === true,
              ransomware_campaign: d.ransomware_campaign ?? null,
              propose_action: d.propose_action ?? null,
              summary: d.summary ?? null,
            },
          },
        ];
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* cvedb optional */
    }
    return [];
  }

  // For actor/ransomware — check Malpedia live + Wikipedia for background context
  if (queryType === 'actor' || queryType === 'ransomware' || queryType === 'generic') {
    const liveSources: Source[] = [];
    const q = query.trim();

    // Threat actor KB search (from curated ACTOR_ALIASES index)
    const ql = q.toLowerCase();
    const kbMatches = ACTOR_ALIASES.filter(
      (a) => a.canonical.toLowerCase().includes(ql) || a.aliases.some((al) => al.toLowerCase().includes(ql))
    );
    if (kbMatches.length > 0) {
      liveSources.push({
        name: 'Threat Actor KB',
        items: kbMatches.length,
        data: kbMatches.slice(0, 10).map((a) => ({
          canonical: a.canonical,
          aliases: a.aliases,
          mitreId: a.mitreId ?? null,
          slug: a.slug,
        })),
      });
    }

    // Ransomware group KB — uses MITRE ATT&CK group techniques lookup
    try {
      const { techniquesForGroup } = await import('../lib/ransomware-group-techniques');
      const { mitreGroupRef } = await import('../lib/ransomware-mitre-groups');
      // Check if the query matches any known ransomware group
      const rgMatches = ACTOR_ALIASES.filter(
        (a) =>
          a.mitreId && (a.canonical.toLowerCase().includes(ql) || a.aliases.some((al) => al.toLowerCase().includes(ql)))
      );
      for (const match of rgMatches) {
        if (match.mitreId) {
          const ref = mitreGroupRef(match.mitreId);
          const techniques = techniquesForGroup(match.mitreId);
          if (ref) {
            liveSources.push({
              name: 'Ransomware KB',
              items: techniques.length + 1,
              data: {
                group: match.canonical,
                mitreName: ref.name ?? '',
                mitreUrl: ref.url ?? '',
                techniques: techniques.map((t) => ({ id: t.id, name: t.name, tactic: t.tactic })),
              },
            });
          }
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* ransomware KB optional */
    }

    // Malpedia live lookup
    try {
      const mpRes = await safeNullLog(
        'fetch-malpedia',
        fetch(`https://malpedia.caad.fkie.fraunhofer.de/api/get/family/${encodeURIComponent(q)}`, {
          signal: AbortSignal.timeout(5000),
        })
      );
      if (mpRes?.ok) {
        const mpData = (await mpRes.json()) as Record<string, unknown>;
        liveSources.push({
          name: 'Malpedia (live)',
          items: 1,
          data: mpData,
        });
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* malpedia optional */
    }

    // Wikipedia summary for well-known threat actors / ransomware
    // Tries direct page first, falls back to search API for redirects
    try {
      const wikiTitle = q.replace(/\s+/g, '_');
      const wikiRes = await safeNullLog(
        'fetch-wikipedia',
        fetch(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(wikiTitle)}`, {
          headers: { 'User-Agent': 'pranithjain-copilot/1.0' },
          signal: AbortSignal.timeout(4000),
        })
      );
      if (wikiRes?.ok) {
        const wikiData = (await wikiRes.json()) as {
          extract?: string;
          pageid?: number;
          title?: string;
          content_urls?: { desktop?: { page?: string } };
        };
        if (wikiData.extract) {
          liveSources.push({
            name: 'Wikipedia',
            items: 1,
            data: {
              title: wikiData.title,
              extract: wikiData.extract,
              url: wikiData.content_urls?.desktop?.page ?? `https://en.wikipedia.org/wiki/${encodeURIComponent(q)}`,
            },
          });
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* wikipedia direct page miss */
    }
    // Fallback: search Wikipedia for related pages
    if (liveSources.length === 0) {
      try {
        const searchUrl = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(q + ' cyber')}&format=json&srlimit=3&origin=*`;
        const srRes = await safeNullLog(
          'fetch-wikipedia-search',
          fetch(searchUrl, {
            headers: { 'User-Agent': 'pranithjain-copilot/1.0' },
            signal: AbortSignal.timeout(4000),
          })
        );
        if (srRes?.ok) {
          const srData = (await srRes.json()) as { query?: { search?: Array<{ title: string; snippet: string }> } };
          const results = srData?.query?.search ?? [];
          if (results.length > 0) {
            liveSources.push({
              name: 'Wikipedia',
              items: results.length,
              data: results.slice(0, 3).map((r) => ({
                title: r.title,
                snippet: r.snippet.replace(/<[^>]+>/g, ''),
                url: `https://en.wikipedia.org/wiki/${encodeURIComponent(r.title.replace(/\s+/g, '_'))}`,
              })),
            });
          }
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* wikipedia search failed */
      }
    }

    // ransomware.live group profile — live TTPs, exploited CVEs, tooling (PRO key).
    try {
      const rl = (await fetchRlUpstream(env, `/group/${encodeURIComponent(ql)}`)) as {
        description?: string;
        ttps?: unknown[];
        vulnerabilities?: { CVE?: string }[];
        tools?: Record<string, string[]>;
        victims?: number;
      } | null;
      if (rl && (rl.description || (rl.ttps?.length ?? 0) > 0 || (rl.vulnerabilities?.length ?? 0) > 0)) {
        liveSources.push({
          name: 'Ransomware.live Profile',
          items: (rl.ttps?.length ?? 0) + (rl.vulnerabilities?.length ?? 0),
          data: {
            description: rl.description ?? null,
            victims: rl.victims ?? null,
            ttps: rl.ttps ?? [],
            exploited_cves: (rl.vulnerabilities ?? []).map((v) => v.CVE).filter(Boolean),
            tools: rl.tools ?? {},
          },
        });
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* RL profile optional */
    }

    return liveSources;
  }

  // ── For IP / domain / email: breach exposure (XposedOrNot + LeakCheck +
  //    LeakIX + HudsonRock + ProjectDiscovery + HackMyIP) ───────────────
  // SubjectType doesn't include 'email' explicitly, so we also detect a
  // bare email by regex. Domain queries can also be sent through the breach
  // domain endpoint.
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isEmail = emailRe.test(query.trim());
  if (queryType === 'ip' || queryType === 'domain' || isEmail) {
    const breachType: 'email' | 'domain' = isEmail || queryType === 'domain' ? (isEmail ? 'email' : 'domain') : 'email';
    try {
      const url = `https://pranithjain.qzz.io/api/v1/breach/${breachType}?${breachType}=${encodeURIComponent(query.trim())}`;
      const res = await fetch(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = (await res.json()) as {
          found?: boolean;
          breach_count?: number;
          sources_queried?: string[];
          source?: string;
          breaches?: Array<{
            name?: string;
            source?: string;
            breach_date?: string;
            pwn_count?: number;
            data_classes?: string[];
          }>;
        };
        if (data.found && (data.breach_count ?? 0) > 0) {
          return [
            {
              name: 'Breach Exposure',
              items: data.breaches?.length ?? 0,
              data: {
                target: query.trim(),
                type: breachType,
                breach_count: data.breach_count ?? 0,
                first_source: data.source ?? null,
                sources_queried: data.sources_queried ?? [],
                breaches: (data.breaches ?? []).slice(0, 10).map((b) => ({
                  name: b.name,
                  source: b.source,
                  breach_date: b.breach_date,
                  pwn_count: b.pwn_count,
                  data_classes: b.data_classes,
                })),
              },
            },
          ];
        }
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* breach lookup optional */
    }
  }

  return [];
}

export function buildSystemPrompt(
  query: string,
  queryType: QueryType,
  confidence?: ConfidenceScore,
  role?: string
): string {
  const isActor = queryType === 'actor' || queryType === 'ransomware';

  const roleFraming: Record<string, string> = {
    ciso: `<persona>CISO / Executive Advisor</persona>
<focus>You are a CISO's strategic advisor. Frame answers in business context: lead with risk posture, financial/regulatory impact, and strategic implications. Quantify where possible. End with concrete recommendations phrased as "consider" or "review" actions. Avoid technical deep-dives unless asked.</focus>`,
    detection: `<persona>Detection Engineering Lead</persona>
<focus>You are a Detection Engineering lead. Frame answers for rule development: lead with the TTP mapped to MITRE ATT&CK, provide detection logic ideas (Sigma, KQL, Splunk SPL), highlight bypass risks and detection gaps, include data source requirements.</focus>`,
    ir: `<persona>Senior Incident Responder</persona>
<focus>You are a senior Incident Responder. Frame answers for rapid triage: lead with actionable IOCs and immediate containment steps, prioritize by severity and dwell time, include forensic artifact locations, note false-positive indicators, end with the single most impactful next action.</focus>`,
    cti: `<persona>Threat Intelligence Analyst</persona>
<focus>You are a Threat Intelligence analyst. Frame answers for analytical depth: lead with actor attribution, confidence level, and source triangulation, include campaign context and victimology, cross-reference with MITRE ATT&CK, surface intelligence gaps and collection priorities.</focus>`,
  };

  const activeRole = role && roleFraming[role] ? roleFraming[role] : null;

  const confidenceBlock = confidence
    ? `
<confidence>
**Computed from source reliability grading:**

| Metric | Value |
|--------|-------|
| Overall score | ${confidence.score}/100 |
| Level | ${confidence.level} |
| Sources contributing | ${confidence.sources_contributing} |
| Contradictory sources | ${confidence.contradictory_sources} |
| Admiralty grade | ${confidence.admiralty ? `${confidence.admiralty.reliability}-${confidence.admiralty.credibility}: ${confidence.admiralty.label}` : 'N/A'} |
| Reasoning | ${confidence.reasoning} |

Use this computed confidence to calibrate the [High]/[Medium]/[Low] tags in your Key Findings. Do NOT contradict this computed score — if the score is low, the findings should reflect that.
</confidence>`
    : `
<confidence>
- **High**: corroborated by ≥2 independent sources, or a single authoritative source (CISA KEV, NVD, Malpedia, Wikipedia for established subjects).
- **Medium**: single structured source, or plausible general knowledge with concrete specifics.
- **Low**: weak signal, general knowledge without corroboration, or stale data.
When relying primarily on general knowledge, you MUST include at the top of Key Findings: "⚠️ No curated threat intelligence sources matched this query. Analysis is based on general cybersecurity knowledge and may not reflect the most current threat landscape."
</confidence>`;
  return `${activeRole ?? '<role>You are a senior CTI analyst at a global SOC/MDR writing a formal intelligence report for fellow analysts and incident responders. Your reports are evidence-driven, technically precise, and professionally structured.</role>'}

<task>Produce a structured intelligence report about "${query}" in Markdown.

Report structure (use these exact headings):

## TL;DR
One-paragraph executive summary — what this is, why it matters, key takeaway, and current threat level.

## Key Findings
4-6 bullet points, each with a confidence tag: [High] [Medium] [Low]. Lead with the most operationally significant finding. Example:
- [High] CVE-2024-1709 is exploited in the wild, included in CISA KEV with known ransomware use by LockBit, Black Basta, and Cl0p [1].
- [Medium] ScreenConnect auth bypass allows unauthenticated RCE — CVSS 9.8, EPSS 97.4% [2].
- [Medium] 15+ victims reported across manufacturing, healthcare, and education sectors in the last 30 days [3].

## Detailed Analysis
2-5 paragraphs with technical depth. Extract specifics from source data — do NOT write generic prose. Include:
${
  isActor
    ? `- Origins, aliases, motivation, geographic attribution
- Affiliate or RaaS structure (who can join, revenue splits)
- TTPs: initial access vectors, privilege escalation, lateral movement, exfiltration methods
- Notable campaigns with dates, victims, sectors, and countries (extracted from Ransomware Recent / Actor Timeline sources)
- Ransom model: average demand, negotiation patterns, discount rates (from Negotiations source if available)`
    : queryType === 'cve'
      ? `- Attack vector, complexity, privileges required, user interaction (from CVSS vector)
- Exploit status: is there a public PoC? Is it being exploited in the wild? (from KEV + EPSS)
- EPSS probability score and percentile — how likely is exploitation in the next 30 days
- Affected products and versions (from affected_products list)
- Known ransomware / actor groups exploiting this CVE (from heuristic NVD/KEV scanning + actor_links)`
      : `- Live enrichment verdicts from provider sources: detection ratios, reputation scores, geolocation, ASN
- Associated malware families, C2 frameworks, and threat actor tags
- Historical context: first seen, breach associations, correlation across feeds`
}

## MITRE ATT&CK Context${isActor ? '' : ' (include if source data contains technique references, otherwise skip)'}
List technique IDs with tactic mapping. Extract these from the data — do not hallucinate techniques.${isActor ? `\n\nIf source data contains technique references (e.g. from Ransomware KB / Malpedia / Actor Timeline MITRE fields), enumerate them as a table:\n\`\`\`\n| Tactic | Technique ID | Name |\n|--------|-------------|------|\n| TA0040 | T1486 | Data Encrypted for Impact |\n\`\`\`` : ''}

${
  isActor
    ? `## Campaign Timeline
Chronological list of recent victim disclosures or campaign activity extracted from source data. Include victim name, sector, country, and discovery date when available. If the Actor Timeline source shows month-by-month posting cadence, summarise the trend.

`
    : ''
}${
    isActor
      ? `## Financial Data (if Negotiations source available)
Ransom demands, negotiated settlements, discount percentages, and payment status extracted from the Negotiations source. Highlight any notable patterns in negotiation behaviour.

`
      : ''
  }${
    queryType === 'hash' || queryType === 'ip' || queryType === 'domain'
      ? `## Indicators of Compromise
Structured IOC table with values, types, source confidence, and associated malware families. Prefer a markdown table format.

`
      : `## Related CVEs (for actor/ransomware queries)
CVEs attributed to this actor, with severity, KEV status, and EPSS score where available. Explain the relationship — which CVEs are being actively weaponised by this group.

`
  }
## Recommendations
3-5 actionable, prioritised recommendations for defenders. Be specific:
- **Detection**: specific log sources, Sigma/YARA rule IDs, or hunt queries (reference Detections source if available)
- **Prevention**: patching priorities, network segmentation, email filtering rules
- **Response**: IOI (indicators of interest) to monitor, specific artefacts to collect during IR

## Source References
Numbered list of sources used in this report. Reference them inline in the text like [1], [2] etc.
</task>

<ground_rules>
- SOURCES ARE YOUR EVIDENCE. Every claim in the report must cite the source that supports it. Use the ref="N" attribute from each <source> tag for inline citation: e.g. "CVE-2024-1709 is exploited in the wild by LockBit [1]".
- If a <retrieved_corpus> block is present in the prompt, it contains pre-indexed knowledge from a corpus of past analyses, reports, and technical notes. Cite it as [R1], [R2], etc. matching the ref attributes. Do NOT conflate <retrieved_corpus> citations with <source> citations.
- Sources below MAY be empty. This does NOT mean the subject is unknown — use your training knowledge for well-known actors, ransomware families, and CVEs. Mark general-knowledge claims with "(general knowledge)" and a confidence label.
- NEVER say "no intelligence found" or "no data available" for a well-known subject. If you genuinely don't recognise the query, say: "This query does not match any known threat actor, malware, or CVE in available sources or general knowledge."
- Do NOT invent CVE IDs, CVSS scores, EPSS values, or technical details not present in provided data or verified general knowledge.
- CVE IDs must be complete (e.g. CVE-2024-1234, never "CVE-2024").
- EXTRACT SPECIFICS from the data — do not write "recent attacks have been observed" without naming victims, dates, sectors, and countries from the source data.
- BANNED REPORT OPENERS (formulaic AI tells): "You're likely already aware", "You're probably wondering", "You might be wondering", "Chances are", "In today's", "Let's dive into", "In this report". Lead with the specific finding, not a presumptive "you" statement.
- Write in a professional, neutral tone. Use technical precision. Avoid marketing language.
- Maximum 1500 words.
</ground_rules>

<reasoning>
Before writing, assess:
1. Scan each source — what specific facts does it contribute? Victim names? CVSS scores? Technique IDs? Malware family tags?
2. Cross-reference sources for corroboration — which facts appear in multiple sources?
3. Determine overall confidence from source overlap, freshness, and authority.
4. Map source names to Reference numbers [1..N] for inline citation.
5. Identify gaps the data doesn't cover — note these honestly as "general knowledge" or "no data in available sources."
Then write the report with evidence tracing back to sources.
</reasoning>

${confidenceBlock}

<coverage>
${isActor ? `- Actor/ransomware: extract SPECIFIC victim names, sectors, countries, and discovery dates from Ransomware Recent source. Mention aliases (from Threat Actor KB). Describe affiliate/RaaS model, known TTPs with technique IDs from MITRE data, and recent campaign patterns. Use Negotiations source for financial data if present.` : queryType === 'cve' ? `- CVE: extract full CVSS vector (not just score), EPSS probability as percentage, CISA KEV status with date_added, affected products list, and actor attribution. Mention specific PoC references from the source data.` : `- IP/domain/hash: extract specific provider verdicts (VT detection ratio, AbuseIPDB confidence score, GreyNoise classification). Mention associated malware families and C2 frameworks from tags. Include geolocation data (country, ASN).`}
- If the "Ransomware KB" source is present for actor queries, it contains MITRE technique IDs and tactic mappings — include these in the MITRE ATT&CK Context section.
- If the "Writeups" source is present, extract specific article titles, authors, and publication dates — use these as references in the analysis.
- If the "Wikipedia" source is present, use its extract for historical context but prefer structured data for specific claims.
</coverage>`;
}

const SCHEMA_NOTES: Record<string, string> = {
  'Live IOCs':
    'Each item: { value (the IOC text), kind (ip|domain|hash|url), source (feed name), context (malware family / tags), reporter, reference_url, observed_at }. EXTRACT: specific IOCs with their associated malware family tags and feed sources.',
  'Ransomware Recent':
    'Each item: { victim (org name), group (ransomware gang), discovered, description, sector, country, screen_url }. EXTRACT: victim organisation names, sectors (healthcare/manufacturing/etc), countries, and discovery dates for the Campaign Timeline section.',
  'Actor Timeline':
    'Each item: { slug, display_name, posts_in_window (last 30d posts), description, raas (bool), mitre (MITRE ATT&CK ref), mirrors_reachable }. EXTRACT: RaaS status, posting frequency trend, MITRE reference ID if present.',
  'Recent CVEs':
    'Each item: { id, published, description, severity (CRITICAL/HIGH/MEDIUM/LOW), score (CVSS), kev (bool, CISA KEV), actors[] }. EXTRACT: severity, CVSS score, KEV flag, and actor names for the Related CVEs section.',
  'Breach Disclosures':
    'Each item: { name, title, domain, breach_date, pwn_count, description, data_classes[], verified }. EXTRACT: breach name, date, data classes exposed, and verification status.',
  Writeups:
    'Each item: { title, url, source, published, description, tags[], author }. EXTRACT: article title, author, publication date — cite as reference in analysis.',
  'Malware Samples':
    'Each item: { sha256, sha1, md5, first_seen, file_type, file_size_bytes, signature (malware family), reporter, tags[], bazaar_url }. EXTRACT: malware family classification, first-seen date, file type.',
  'C2 Tracker':
    'Each item: { ip, framework (Cobalt Strike/Havoc/Mythic/etc), context, port }. EXTRACT: C2 framework type, IP addresses for IOC section.',
  'IOC Correlation':
    'Each item: { value, source_count (number of feeds seeing this IOC), sources[] }. Higher source_count = higher confidence. EXTRACT: high-confidence IOCs (source_count >= 2) with the feeds that corroborate them.',
  Detections:
    'Each item: { rule_name, rule_id, severity, match_count, group_key, indicators[] }. Sigma/YARA/Suricata rules matching. EXTRACT: rule names and IDs for the Recommendations > Detection section.',
  Cybercrime:
    'Each item: { title, url, description, published }. EXTRACT: relevant news items with dates for recent activity context.',
  Negotiations:
    'Each item: { group, ransom_amount, discount_percent, settlement_status, victim, date }. EXTRACT: ransom demand amounts, negotiated discounts, settlement outcomes for the Financial Data section.',
  Malpedia:
    'Each item: { name, common_name, description, aliases[] }. EXTRACT: malware aliases and description for context in Detailed Analysis.',
  'Live Enrichment':
    'Each entry: { source, status (ok|error), score (0-100), verdict (clean|suspicious|malicious|unknown), tags[], summary }. EXTRACT: provider-specific verdicts, detection ratios, geolocation, ASN, abuse reports, malware family tags.',
  'CVE Search (live)':
    'Live NVD + EPSS + CISA KEV + CIRCL lookup. Contains: cve_id, published, description, cvss (version, base_score, severity, vector), epss (score, percentile, date), kev (in_kev, date_added, vulnerability_name, known_ransomware), cwe[], references[], affected_products[], actors[], actor_links[]. EXTRACT: full CVSS vector, EPSS percentile, KEV status with date_added, affected products, actor links.',
  'Ransomware KB':
    'Contains: group name, MITRE reference (name + URL), and techniques array with { id, name, tactic } per technique. EXTRACT: use the techniques list to populate the MITRE ATT&CK Context section — each technique has an ID (e.g. T1486), name, and tactic mapping.',
  'Threat Actor KB':
    'Contains: canonical name, aliases array, mitreId (MITRE ATT&CK Group ID) if assigned. EXTRACT: aliases for the Detailed Analysis, mitreId for MITRE ATT&CK Context.',
  Wikipedia:
    'Contains: title, extract (plain-text summary), url. EXTRACT: use the summary for historical background and general context in Detailed Analysis. Prefer structured data over Wikipedia for specific claims.',
};

export function buildUserPrompt(query: string, queryType: QueryType, sources: Source[], ragContext?: string): string {
  const intro = `<investigation>
Query: ${query}
Type: ${queryType}
</investigation>

`;
  const ragBlock = ragContext ? `${ragContext}\n\n` : '';
  let body = '';
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i]!;
    const refNum = i + 1;
    body += `<source ref="${refNum}" name="${src.name}" results="${src.items}">\n`;
    const note = SCHEMA_NOTES[src.name];
    if (note) body += `  <!-- ${note} -->\n`;
    body += neutralizeUntrusted(JSON.stringify(src.data, null, 2));
    body += '\n</source>\n\n';
  }
  if (!body)
    body =
      '<source name="none" results="0">No sources returned data. Use general knowledge ONLY with mandatory disclaimer.</source>\n';

  const citationNote =
    sources.length > 0
      ? `\n<instruction>You have ${sources.length} source(s) above. Reference them inline using [1], [2], etc. matching the ref="N" attributes, and list them in the ## Source References section at the end.</instruction>`
      : '';
  return intro + ragBlock + body + citationNote;
}

export async function callNvidia(env: Env, system: string, user: string): Promise<string> {
  const key = env.NVIDIA_API_KEY;
  if (!key) throw new Error('NVIDIA_API_KEY not set');
  const models = ['minimaxai/minimax-m2.7', 'z-ai/glm-5.2'];
  for (const model of models) {
    const res = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        max_tokens: 4000,
        temperature: 0.3,
      }),
      signal: AbortSignal.timeout(18000),
    });
    if (res.ok) {
      const data = await res.json<{ choices?: Array<{ message?: { content?: string } }> }>();
      if (data?.choices?.[0]?.message?.content) return data.choices[0].message.content;
    }
  }
  throw new Error('NVIDIA models unavailable');
}

function extractWorkersAiText(res: Record<string, unknown>): string | undefined {
  if (typeof res.response === 'string' && res.response.trim()) return res.response;
  if (typeof res.text === 'string' && res.text.trim()) return res.text;
  const choices = res.choices as Array<Record<string, unknown>> | undefined;
  if (choices?.[0]) {
    const msg = choices[0].message as Record<string, unknown> | undefined;
    if (typeof msg?.content === 'string' && (msg.content as string).trim()) return msg.content as string;
    if (typeof choices[0].text === 'string') return choices[0].text as string;
  }
  return undefined;
}

function buildAiInput(
  model: string,
  system: string,
  user: string,
  maxTokens: number,
  temperature: number
): Record<string, unknown> {
  // Models using the newer instructions+input format (Responses API)
  if (model.startsWith('@cf/openai/')) {
    return { instructions: system, input: user, max_tokens: maxTokens, temperature };
  }
  // All other models use the messages format
  return {
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    max_tokens: maxTokens,
    temperature,
  };
}

export async function callWorkersAi(env: Env, system: string, user: string): Promise<string> {
  const models = [
    '@cf/openai/gpt-oss-120b',
    '@cf/qwen/qwen3-30b-a3b-fp8',
    '@cf/moonshotai/kimi-k2.6',
    '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
  ];
  for (const model of models) {
    try {
      const res = (await env.AI.run(
        model as Parameters<typeof env.AI.run>[0],
        buildAiInput(model, system, user, 4000, 0.3) as Parameters<typeof env.AI.run>[1]
      )) as Record<string, unknown>;
      const text = extractWorkersAiText(res);
      if (text) return text;
    } catch (_catchErr) {
      logError('callWorkersAi failed', _catchErr);
      continue;
    }
  }
  throw new Error('All Workers AI models failed');
}

export async function callGroq(env: Env, system: string, user: string): Promise<string> {
  const key = env.GROQ_API_KEY;
  if (!key) throw new Error('GROQ_API_KEY not set');
  const models = ['openai/gpt-oss-120b', 'qwen/qwen3-32b', 'openai/gpt-oss-20b'];
  for (const model of models) {
    try {
      const isReasoning = model.startsWith('openai/gpt-oss') || model.startsWith('qwen/qwen3');
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${key}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: system },
            { role: 'user', content: user },
          ],
          ...(isReasoning ? { max_completion_tokens: 4000, reasoning_effort: 'medium' } : { max_tokens: 4000 }),
          temperature: 0.3,
        }),
        signal: AbortSignal.timeout(18000),
      });
      if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        throw new Error(`Groq ${model}: HTTP ${res.status}${errBody ? ` ${errBody.slice(0, 200)}` : ''}`);
      }
      const data = await res.json<{ choices?: Array<{ message?: { content?: string } }> }>();
      const text = data?.choices?.[0]?.message?.content;
      if (text) return text;
    } catch (err) {
      logError(`copilot Groq  failed`, err);
      continue;
    }
  }
  throw new Error('All Groq models failed');
}

export async function copilotInvestigateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  // Overall 25s timeout — prevents the Worker from hanging when LLM providers
  // are slow. Cloudflare Workers free-plan CPU limit is 30s; 25s leaves headroom.
  const OVERALL_TIMEOUT = 25_000;
  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('Request timed out — try a simpler query')), OVERALL_TIMEOUT)
  );

  const work = async (): Promise<Response> => {
    try {
      let query: string;
      let role: string | undefined;
      if (c.req.method === 'GET') {
        query = c.req.query('q') ?? '';
      } else {
        const body = await c.req.json<{ query: string; role?: string }>();
        query = body.query ?? '';
        role = body.role;
      }
      if (!query || query.trim().length === 0) {
        return badRequest(c, 'query is required (POST body or ?q= param)');
      }
      if (query.length > 500) {
        return badRequest(c, 'query too long (max 500 chars)');
      }

      const queryType = detectType(query);
      // Parallel: cache sources + live enrichment (no more unified-search subrequest)
      const [sources, liveSources] = await Promise.all([
        gatherSources(query.trim(), queryType),
        gatherLiveEnrichment(query.trim(), queryType, c.env),
      ]);
      const allSources = [...sources, ...liveSources];

      // ── RAG: retrieve relevant context from Vectorize corpus ──────────────
      let ragContext: string | undefined;
      try {
        // Short queries (<5 chars) skip RAG — noise-to-signal is too low
        if (query.trim().length >= 5 && c.env.VECTORIZE) {
          const results = await queryCorpus(c.env, query.trim(), 8, undefined);
          if (results.length > 0) ragContext = formatRetrievedContext(results);
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        // RAG is additive — failure is non-fatal
      }

      // ── Compute analytic confidence from source reliability ──────────────
      const confidence = computeConfidence({
        sourceIds: allSources.map((s) =>
          s.name
            .toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^a-z0-9-]/g, '')
        ),
        findingType:
          queryType === 'cve'
            ? 'vulnerability'
            : queryType === 'actor' || queryType === 'ransomware'
              ? 'attribution'
              : 'general',
      });

      const system = buildSystemPrompt(query.trim(), queryType, confidence, role);
      const user = buildUserPrompt(query.trim(), queryType, allSources, ragContext);

      let narrative = '';
      let modelUsed = '';

      const providerChain = [
        { name: 'Groq', call: () => callGroq(c.env, system, user), label: 'groq:openai/gpt-oss-120b' },
        { name: 'Workers AI', call: () => callWorkersAi(c.env, system, user), label: 'workers-ai' },
        { name: 'Nvidia', call: () => callNvidia(c.env, system, user), label: 'nvidia' },
      ];
      let lastErr: Error | null = null;
      for (const provider of providerChain) {
        try {
          narrative = await provider.call();
          modelUsed = provider.label;
          lastErr = null;
          break;
        } catch (e) {
          lastErr = e instanceof Error ? e : new Error(String(e));
          logError(`copilot  failed`, lastErr);
        }
      }
      if (lastErr) throw new Error(`All LLM providers failed: ${lastErr.message}`);

      // ── Post-process validation: ground claims, strip fabrications ────
      const sourceData = allSources.map((s) => JSON.stringify(s.data)).join('\n');
      const validation = validateAiOutput(narrative, sourceData, { minWords: 100, requireCitations: true });
      narrative = validation.cleaned;

      const totalSourceItems = allSources.reduce((n, s) => n + s.items, 0);
      const response: CopilotResponse = {
        query: query.trim(),
        query_type: queryType,
        narrative,
        sources: allSources.map((s) => ({ name: s.name, items: s.items, data: s.data })),
        model_used: modelUsed,
        processed_at: new Date().toISOString(),
        confidence,
        _meta: {
          total_sources: allSources.length,
          total_items: totalSourceItems,
          ...((validation as unknown as Record<string, unknown>).quality
            ? {
                quality_score: ((validation as unknown as Record<string, unknown>).quality as Record<string, unknown>)
                  .score,
                quality_issues: ((validation as unknown as Record<string, unknown>).quality as Record<string, unknown>)
                  .issues,
              }
            : {}),
        },
      };

      return c.json(response, 200, { 'Cache-Control': 'no-store' });
    } catch (e) {
      logError('copilot investigate failed', e);
      return internalError(c, e);
    }
  };

  return Promise.race([work(), timeoutPromise]).catch((e) => {
    const msg = e instanceof Error ? e.message : String(e);
    logError('copilot investigate timeout/fatal', msg);
    return internalError(c, e instanceof Error ? e : new Error(String(e)));
  });
}
