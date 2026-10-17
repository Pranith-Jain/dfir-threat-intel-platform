/**
 * Live threat-intel enrichment — OTX (AlienVault), ThreatFox, MalwareBazaar,
 * and ransomware.live.
 *
 * Each provider wraps its HTTP call in a try/except with a 20s timeout so
 * one failing provider never poisons the rest. Results include a
 * `diagnostics[]` array for provider health visibility.
 *
 * These are QUERY-SPECIFIC search tools — they let an LLM ask targeted
 * questions ("search OTX for LockBit") rather than consuming the full
 * aggregated feed from get_live_iocs.
 *
 * API keys:
 *   - OTX: OTX_API_KEY (free at otx.alienvault.com, optional — tool degrades without it)
 *   - ThreatFox: no key needed (free API)
 *   - MalwareBazaar: no key needed (free API)
 *   - ransomware.live: no key needed (public API)
 */

import { errMessage } from './err';

const FETCH_TIMEOUT_MS = 20_000;

// ── OTX (AlienVault) ─────────────────────────────────────────────────────

export interface OtxPulse {
  id: string;
  name: string;
  description: string;
  tags: string[];
  created: string;
  modified: string;
  tlp: string;
  indicator_count: number;
  malware_families: string[];
  attack_ids: string[];
  indicators: Array<{ type: string; value: string; description?: string }>;
}

export interface OtxSearchResult {
  query: string;
  pulses: OtxPulse[];
  total: number;
  diagnostics: Array<{ provider: string; status: 'ok' | 'skipped' | 'failed'; ms: number; error?: string }>;
}

export async function searchOtxPulses(query: string, apiKey?: string): Promise<OtxSearchResult> {
  const result: OtxSearchResult = { query, pulses: [], total: 0, diagnostics: [] };

  if (!apiKey) {
    result.diagnostics.push({
      provider: 'otx',
      status: 'skipped',
      ms: 0,
      error: 'OTX_API_KEY not set — get a free key at https://otx.alienvault.com',
    });
    return result;
  }

  const t0 = Date.now();
  try {
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/search/pulses?q=${encodeURIComponent(query)}&limit=20&page=1`,
      {
        headers: { 'X-OTX-API-KEY': apiKey, accept: 'application/json' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      }
    );

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      result.diagnostics.push({
        provider: 'otx',
        status: 'failed',
        ms: Date.now() - t0,
        error: `HTTP ${res.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const data = (await res.json()) as {
      results?: Array<{
        id: string;
        name: string;
        description: string;
        tags: string[];
        created: string;
        modified: string;
        tlp: string;
        indicator_count: number;
        malware_families: unknown[];
        attack_ids: Array<{ display_name: string }>;
      }>;
    };

    const pulses = (data.results ?? []).map((p) => ({
      id: p.id,
      name: p.name ?? '',
      description: p.description ?? '',
      tags: p.tags ?? [],
      created: p.created ?? '',
      modified: p.modified ?? '',
      tlp: p.tlp ?? 'white',
      indicator_count: p.indicator_count ?? 0,
      malware_families: (p.malware_families ?? [])
        .map((m) =>
          typeof m === 'string'
            ? m
            : ((m as { display_name?: string; name?: string })?.display_name ?? (m as { name?: string })?.name ?? '')
        )
        .filter(Boolean),
      attack_ids: (p.attack_ids ?? []).map((a) => a.display_name ?? '').filter(Boolean),
      indicators: [] as Array<{ type: string; value: string; description?: string }>,
    }));

    // Fetch indicators for top 5 pulses
    if (pulses.length > 0 && apiKey) {
      const fetchIndicators = async (
        pulseId: string
      ): Promise<Array<{ type: string; value: string; description?: string }>> => {
        try {
          const r = await fetch(`https://otx.alienvault.com/api/v1/pulses/${pulseId}/indicators?limit=50`, {
            headers: { 'X-OTX-API-KEY': apiKey, accept: 'application/json' },
            signal: AbortSignal.timeout(10_000),
          });
          if (!r.ok) return [];
          const d = (await r.json()) as { results?: Array<{ type: string; indicator: string; description?: string }> };
          return (d.results ?? [])
            .filter((i) => i.indicator)
            .map((i) => ({ type: i.type, value: i.indicator, description: i.description }));
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          return [];
        }
      };

      const allIndicators = await Promise.all(pulses.slice(0, 5).map((p) => fetchIndicators(p.id)));
      for (let i = 0; i < Math.min(5, pulses.length); i++) {
        const pulse = pulses[i];
        if (pulse) pulse.indicators = allIndicators[i] ?? [];
      }
    }

    result.pulses = pulses;
    result.total = pulses.length;
    result.diagnostics.push({ provider: 'otx', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'otx',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}

// ── ThreatFox ─────────────────────────────────────────────────────────────

export interface ThreatfoxIoc {
  ioc_type: string;
  ioc_value: string;
  malware: string;
  malware_printable: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
  comment: string;
  reporter: string;
}

export interface ThreatfoxSearchResult {
  query: string;
  iocs: ThreatfoxIoc[];
  total: number;
  diagnostics: Array<{ provider: string; status: 'ok' | 'skipped' | 'failed'; ms: number; error?: string }>;
}

export async function searchThreatfox(searchTerm: string): Promise<ThreatfoxSearchResult> {
  const result: ThreatfoxSearchResult = { query: searchTerm, iocs: [], total: 0, diagnostics: [] };

  const t0 = Date.now();
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: searchTerm }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      result.diagnostics.push({
        provider: 'threatfox',
        status: 'failed',
        ms: Date.now() - t0,
        error: `HTTP ${res.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const data = (await res.json()) as {
      query_status: string;
      data?: Array<{
        ioc_type: string;
        ioc: string;
        malware: string;
        malware_printable: string;
        confidence_level: number;
        first_seen: string;
        last_seen: string;
        tags: string[];
        comment: string;
        reporter: string;
      }>;
    };

    if (data.query_status === 'no_data') {
      result.diagnostics.push({ provider: 'threatfox', status: 'ok', ms: Date.now() - t0 });
      return result;
    }

    if (data.query_status !== 'ok') {
      result.diagnostics.push({
        provider: 'threatfox',
        status: 'failed',
        ms: Date.now() - t0,
        error: `query_status: ${data.query_status}`,
      });
      return result;
    }

    result.iocs = (data.data ?? []).slice(0, 100).map((ioc) => ({
      ioc_type: ioc.ioc_type ?? '',
      ioc_value: ioc.ioc ?? '',
      malware: ioc.malware ?? '',
      malware_printable: ioc.malware_printable ?? '',
      confidence: ioc.confidence_level != null ? ioc.confidence_level / 100 : 0,
      first_seen: ioc.first_seen ?? '',
      last_seen: ioc.last_seen ?? '',
      tags: ioc.tags ?? [],
      comment: ioc.comment ?? '',
      reporter: ioc.reporter ?? '',
    }));
    result.total = result.iocs.length;
    result.diagnostics.push({ provider: 'threatfox', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'threatfox',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────

export interface MalwarebazaarSample {
  sha256: string;
  md5: string;
  file_name: string;
  file_type: string;
  signature: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  reporter: string;
}

export interface MalwarebazaarSearchResult {
  query: string;
  search_mode: 'tag' | 'signature';
  samples: MalwarebazaarSample[];
  total: number;
  diagnostics: Array<{ provider: string; status: 'ok' | 'skipped' | 'failed'; ms: number; error?: string }>;
}

export async function searchMalwarebazaar(query: string): Promise<MalwarebazaarSearchResult> {
  const result: MalwarebazaarSearchResult = { query, search_mode: 'tag', samples: [], total: 0, diagnostics: [] };

  const t0 = Date.now();
  try {
    // Try tag search first, fall back to signature search
    let res = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ query: 'get_taginfo', tag: query, limit: '50' }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    let data = (await res.json()) as {
      query_status: string;
      data?: Array<{
        sha256_hash: string;
        md5_hash: string;
        file_name: string;
        file_type: string;
        signature: string;
        tags: string[];
        first_seen: string;
        last_seen: string;
        reporter: string;
      }>;
    };

    if (data.query_status === 'no_results' || !data.data?.length) {
      // Fall back to signature search
      result.search_mode = 'signature';
      res = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ query: 'get_siginfo', signature: query, limit: '50' }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      data = (await res.json()) as typeof data;
    }

    if (data.query_status === 'no_results') {
      result.diagnostics.push({ provider: 'malwarebazaar', status: 'ok', ms: Date.now() - t0 });
      return result;
    }

    if (data.query_status !== 'ok') {
      result.diagnostics.push({
        provider: 'malwarebazaar',
        status: 'failed',
        ms: Date.now() - t0,
        error: `query_status: ${data.query_status}`,
      });
      return result;
    }

    result.samples = (data.data ?? []).map((s) => ({
      sha256: s.sha256_hash ?? '',
      md5: s.md5_hash ?? '',
      file_name: s.file_name ?? '',
      file_type: s.file_type ?? '',
      signature: s.signature ?? '',
      tags: s.tags ?? [],
      first_seen: s.first_seen ?? '',
      last_seen: s.last_seen ?? '',
      reporter: s.reporter ?? '',
    }));
    result.total = result.samples.length;
    result.diagnostics.push({ provider: 'malwarebazaar', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'malwarebazaar',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}

// ── ransomware.live ───────────────────────────────────────────────────────

export interface RansomwareLiveGroup {
  name: string;
  description: string;
  onion_urls: string[];
  victims: Array<{
    victim: string;
    domain?: string;
    country?: string;
    attackdate?: string;
    activity?: string;
    post_title?: string;
  }>;
  ttps: string[];
  tools: string[];
  victim_count: number;
}

export interface RansomwareLiveSearchResult {
  query: string;
  groups: RansomwareLiveGroup[];
  total: number;
  diagnostics: Array<{ provider: string; status: 'ok' | 'skipped' | 'failed'; ms: number; error?: string }>;
}

export async function searchRansomwareLive(groupName: string): Promise<RansomwareLiveSearchResult> {
  const result: RansomwareLiveSearchResult = { query: groupName, groups: [], total: 0, diagnostics: [] };

  const t0 = Date.now();
  const headers = { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' };

  try {
    // 1. Get all groups and match
    const groupsRes = await fetch('https://api.ransomware.live/v2/groups', {
      headers,
      signal: AbortSignal.timeout(15_000),
    });
    if (!groupsRes.ok) {
      result.diagnostics.push({
        provider: 'ransomware.live',
        status: 'failed',
        ms: Date.now() - t0,
        error: `groups HTTP ${groupsRes.status}`,
      });
      return result;
    }

    const allGroups = (await groupsRes.json()) as Array<{ name: string }>;
    const query = groupName.toLowerCase();
    const matched = allGroups.filter((g) => (g.name ?? '').toLowerCase().includes(query)).slice(0, 5);

    if (!matched.length) {
      result.diagnostics.push({ provider: 'ransomware.live', status: 'ok', ms: Date.now() - t0 });
      return result;
    }

    // 2. Fetch detail for each matched group
    const fetchDetail = async (name: string): Promise<RansomwareLiveGroup | null> => {
      try {
        const r = await fetch(`https://api.ransomware.live/v2/group/${encodeURIComponent(name)}`, {
          headers,
          signal: AbortSignal.timeout(10_000),
        });
        if (!r.status) return null;
        const text = await r.text();
        if (!text.trim().startsWith('{') && !text.trim().startsWith('[')) return null;
        const data = JSON.parse(text) as {
          name: string;
          description?: string;
          locations?: Array<{ fqdn?: string; available?: boolean }>;
          ttps?: string[];
          tools?: string[];
          _victim_count?: number;
        };

        const onionUrls = (data.locations ?? []).filter((l) => l.fqdn && l.fqdn.includes('.onion')).map((l) => l.fqdn!);

        return {
          name: data.name ?? name,
          description: data.description ?? '',
          onion_urls: onionUrls,
          victims: [],
          ttps: data.ttps ?? [],
          tools: data.tools ?? [],
          victim_count: data._victim_count ?? 0,
        };
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        return null;
      }
    };

    const details = await Promise.all(matched.map((g) => fetchDetail(g.name)));

    // 3. Fetch recent victims for matched groups
    const matchedNames = new Set(matched.map((g) => g.name.toLowerCase()));
    let recentVictims: Array<{
      group: string;
      victim?: string;
      domain?: string;
      country?: string;
      attackdate?: string;
      activity?: string;
      post_title?: string;
    }> = [];
    try {
      const vr = await fetch('https://api.ransomware.live/v2/recentvictims', {
        headers,
        signal: AbortSignal.timeout(10_000),
      });
      if (vr.ok) {
        const vText = await vr.text();
        if (vText.trim().startsWith('[')) {
          const raw = JSON.parse(vText) as typeof recentVictims;
          recentVictims = raw.filter((v) => matchedNames.has((v.group ?? '').toLowerCase()));
        }
      }
    } catch (_catchErr) {
      console.error('handler failed:', errMessage(_catchErr));
      /* ignore */
    }

    // 4. Assemble
    for (const detail of details) {
      if (!detail) continue;
      detail.victims = recentVictims
        .filter((v) => v.group.toLowerCase() === detail.name.toLowerCase())
        .slice(0, 30)
        .map((v) => ({
          victim: v.victim ?? v.post_title ?? '',
          domain: v.domain,
          country: v.country,
          attackdate: v.attackdate,
          activity: v.activity,
          post_title: v.post_title,
        }));
      result.groups.push(detail);
    }

    result.total = result.groups.length;
    result.diagnostics.push({ provider: 'ransomware.live', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'ransomware.live',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}
