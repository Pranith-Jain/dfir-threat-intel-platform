/**
 * Platform Data Discovery Runner
 *
 * Integrates the platform's own live data sources into the content
 * discovery pipeline. Instead of only using external RSS feeds, this
 * runner mines the platform's cached intelligence for content-worthy
 * events:
 *
 *   1. Telegram leak channel activity   → /api/v1/telegram-leaks/search
 *   2. Trending IOCs                    → /api/v1/ioc-lifecycle/trending
 *   3. Threat-pulse actors and malware  → /api/v1/threat-pulse
 *
 * Each sub-runner reads the EXACT response shape of the endpoint it calls.
 * That matters: these three used to read field names the endpoints never
 * returned (`recent_leaks`, `ioc.count`, `data.actors`), so every run
 * produced zero candidates with no error anywhere. A field-shape drift in
 * this file is invisible in the pipeline logs — it just silently removes a
 * whole topic from the daily mix.
 *
 * NOTE: Ransomware victim discovery is intentionally EXCLUDED here (the
 * `darkweb` runner covers the underground ground, and ransom-victim
 * discovery moved to the dedicated ransomware surfaces). Running it here
 * too would process the same data through different normalization/dedup
 * key patterns, producing duplicate case studies for the same activity.
 */

import type { Candidate, DedupRecord } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';

export interface PlatformDataDeps {
  /** Fetch from the platform's own API endpoints (internal, no auth needed). */
  apiFetch: (path: string) => Promise<unknown>;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

// ── Telegram Leak Discovery ──────────────────────────────────────

/** One row as returned by /api/v1/telegram-leaks/search. `domains_found` is a
 *  JSON string in D1, not an array — parse it before use. */
interface TelegramLeakEntry {
  channel_handle?: string;
  leak_type?: string;
  credential_count?: number | null;
  domains_found?: string | string[] | null;
  severity?: string;
  discovered_at?: string;
}

/** Normalize the D1-stored domain blob into a string array. */
function parseDomains(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((d): d is string => typeof d === 'string');
  if (typeof v === 'string' && v.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(v) as unknown;
      return Array.isArray(parsed) ? parsed.filter((d): d is string => typeof d === 'string') : [];
    } catch {
      return [];
    }
  }
  return [];
}

export async function discoverFromTelegramLeaks(deps: PlatformDataDeps): Promise<Candidate[]> {
  try {
    // The stats endpoint is a severity/channel rollup with no per-leak rows.
    // The search endpoint is the one that returns the entries themselves.
    const data = (await deps.apiFetch('/api/v1/telegram-leaks/search?limit=200')) as {
      entries?: TelegramLeakEntry[];
    };

    const entries = data?.entries ?? [];
    if (!entries.length) return [];

    const candidates: Candidate[] = [];
    const twentyFourHoursAgo = new Date(deps.now.getTime() - 24 * 3600 * 1000);

    // Group leaks by channel
    const channelLeaks = new Map<
      string,
      { leaks: TelegramLeakEntry[]; totalCreds: number; domains: Set<string>; latest: string }
    >();
    for (const leak of entries) {
      const channel = leak.channel_handle;
      const discovered = new Date(leak.discovered_at ?? '');
      if (!channel || Number.isNaN(discovered.getTime()) || discovered < twentyFourHoursAgo) continue;

      const creds = typeof leak.credential_count === 'number' ? leak.credential_count : 0;
      const existing = channelLeaks.get(channel) ?? {
        leaks: [],
        totalCreds: 0,
        domains: new Set<string>(),
        latest: '',
      };
      existing.leaks.push(leak);
      existing.totalCreds += creds;
      for (const d of parseDomains(leak.domains_found)) existing.domains.add(d);
      if (!existing.latest || discovered.toISOString() > existing.latest) existing.latest = discovered.toISOString();
      channelLeaks.set(channel, existing);
    }

    for (const [channel, info] of channelLeaks.entries()) {
      if (info.leaks.length < 2) continue; // Need multiple leaks to be interesting

      // Use stable key without date - suppression window handles freshness
      const key = topicKey('telegram-leak', channel);
      const dedup = await deps.getDedup(key);

      const score = finalScore({
        recency: recencyScore(info.latest, deps.now),
        severity: severityScore({ victims: info.totalCreds / 1000 }),
        novelty: noveltyScore(dedup, deps.now),
        sourceWeight: 0.85,
      });

      candidates.push({
        key,
        type: 'breach',
        title: `Telegram leak: ${info.totalCreds} credentials from ${channel}`,
        rationale: `${info.leaks.length} leak events · ${info.totalCreds} credentials · ${info.domains.size} domains affected · Last 24h`,
        score,
        evidence: {
          channel,
          leakCount: info.leaks.length,
          totalCredentials: info.totalCreds,
          domains: [...info.domains].slice(0, 10),
          leakTypes: [...new Set(info.leaks.map((l) => l.leak_type).filter((t): t is string => !!t))],
          source: 'platform/telegram-leaks',
        },
        discoveredAt: deps.now.toISOString(),
        status: 'pending',
      });
    }
    return candidates;
  } catch {
    return [];
  }
}

// ── Trending IOC Discovery ───────────────────────────────────────

/**
 * One row from /api/v1/ioc-lifecycle/trending (`rowToLifecycle`). The
 * canonical names are `observation_count`, `indicator_type` and
 * `sources_seen`; the short aliases are accepted so a future rename on the
 * route side degrades to a missing candidate instead of a NaN score.
 */
interface TrendingIoc {
  indicator?: string;
  indicator_type?: string;
  type?: string;
  observation_count?: number;
  count?: number;
  sources_seen?: string[] | string;
  last_sources?: string[] | string;
  sources?: string[];
  last_seen?: string;
}

function stringList(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((s): s is string => typeof s === 'string');
  if (typeof v === 'string' && v.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(v) as unknown;
      return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === 'string') : [];
    } catch {
      return [];
    }
  }
  return [];
}

export async function discoverFromTrendingIocs(deps: PlatformDataDeps): Promise<Candidate[]> {
  try {
    const data = (await deps.apiFetch('/api/v1/ioc-lifecycle/trending?limit=20')) as {
      trending?: TrendingIoc[];
    };

    if (!data?.trending?.length) return [];

    const candidates: Candidate[] = [];

    for (const ioc of data.trending) {
      if (!ioc.indicator) continue;
      const count = ioc.observation_count ?? ioc.count ?? 0;
      if (count < 5) continue; // Need significant activity

      const iocType = ioc.indicator_type ?? ioc.type ?? 'indicator';
      const sources = stringList(ioc.sources_seen).length
        ? stringList(ioc.sources_seen)
        : stringList(ioc.last_sources).length
          ? stringList(ioc.last_sources)
          : stringList(ioc.sources);
      const lastSeen =
        ioc.last_seen && !Number.isNaN(Date.parse(ioc.last_seen)) ? ioc.last_seen : deps.now.toISOString();

      const key = topicKey('trending-ioc', `${iocType}-${ioc.indicator.slice(0, 20)}`);
      const dedup = await deps.getDedup(key);

      const score = finalScore({
        recency: recencyScore(lastSeen, deps.now),
        severity: severityScore({ victims: count / 10 }),
        novelty: noveltyScore(dedup, deps.now),
        sourceWeight: 0.8,
      });

      // Only surface high-activity IOCs
      if (score < 0.5) continue;

      candidates.push({
        key,
        type: 'intel',
        title: `Trending ${iocType}: ${ioc.indicator} seen ${count} times`,
        rationale: `Active IOC across ${sources.length} sources in last 24h · ${count} observations`,
        score,
        evidence: {
          indicator: ioc.indicator,
          indicatorType: iocType,
          observationCount: count,
          sources,
          lastSeen,
          source: 'platform/ioc-lifecycle',
        },
        discoveredAt: deps.now.toISOString(),
        status: 'pending',
      });
    }
    return candidates;
  } catch {
    return [];
  }
}

// ── Threat Pulse Discovery ───────────────────────────────────────

/**
 * One entity from /api/v1/threat-pulse. The endpoint returns a single
 * `entities[]` array keyed by `kind` ('cve' | 'actor' | 'technique' |
 * 'malware'), NOT separate `actors` / `malware` arrays. Only actor and
 * malware entities are surfaced here: CVEs already have three dedicated
 * runners and techniques are not a publishable content type.
 */
interface PulseEntity {
  label?: string;
  kind?: string;
  source_count?: number;
  sources?: string[];
}

export async function discoverFromThreatPulse(deps: PlatformDataDeps): Promise<Candidate[]> {
  try {
    const data = (await deps.apiFetch('/api/v1/threat-pulse')) as {
      generated_at?: string;
      entities?: PulseEntity[];
    };

    const entities = data?.entities ?? [];
    if (!entities.length) return [];

    const generatedAt =
      data.generated_at && !Number.isNaN(Date.parse(data.generated_at)) ? data.generated_at : deps.now.toISOString();

    // The pulse snapshot aggregates multi-day feed windows; a snapshot older
    // than 48h means the upstream job is stale and its "trending" claims are
    // no longer fresh enough to publish.
    const generated = new Date(generatedAt).getTime();
    if (deps.now.getTime() - generated > 48 * 3600 * 1000) return [];

    const candidates: Candidate[] = [];

    for (const entity of entities) {
      const kind = entity.kind;
      if (kind !== 'actor' && kind !== 'malware') continue;
      const label = entity.label?.trim();
      if (!label) continue;

      const mentions = entity.source_count ?? 0;
      if (mentions < 3) continue;

      const sources = entity.sources ?? [];
      const key = topicKey(kind === 'actor' ? 'pulse-actor' : 'pulse-malware', label.toLowerCase());
      const dedup = await deps.getDedup(key);
      const score = finalScore({
        recency: recencyScore(generatedAt, deps.now),
        severity: severityScore({ victims: mentions }),
        novelty: noveltyScore(dedup, deps.now),
        sourceWeight: 0.9,
      });

      if (score < 0.6) continue;

      candidates.push({
        key,
        type: kind === 'actor' ? 'actor' : 'malware',
        title:
          kind === 'actor'
            ? `${label}: trending across ${mentions} sources`
            : `${label}: active across ${mentions} intel sources`,
        rationale: `Mentioned across ${mentions} intel surfaces in the current pulse · Sources: ${sources.slice(0, 3).join(', ')}`,
        score,
        evidence: {
          entity: label,
          mentions,
          sources,
          latest: generatedAt,
          source: 'platform/threat-pulse',
        },
        discoveredAt: deps.now.toISOString(),
        status: 'pending',
      });
    }
    return candidates;
  } catch {
    return [];
  }
}
