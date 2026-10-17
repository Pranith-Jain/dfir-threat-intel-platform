/**
 * Shared IOC provider fan-out — runs the full 27+ provider suite for any
 * indicator type. Used by both the SSE streaming IOC checker and the
 * non-streaming hunt-v2 handler.
 */

import type { Env } from '../env';
import { detectType, refang } from './indicator';
import type { Indicator } from '../providers/types';
import { WEIGHTS, compositeScore } from './scoring';
import { ProviderCache } from './cache';
import { isCircuitOpen, recordProviderFailure, recordProviderSuccess } from './circuit-breaker';
import { admiraltyGrade } from './admiralty';
import type { ProviderResult, ProviderId } from '../providers/types';
import { ADAPTERS, buildProviderEnv, PROVIDER_SUPPORT, providerTimeoutMs } from '../providers';

const PROVIDER_CHUNK_SIZE = 10;

async function runChunked<T>(items: T[], fn: (item: T) => Promise<void>, size: number): Promise<void> {
  for (let i = 0; i < items.length; i += size) {
    const chunk = items.slice(i, i + size);
    await Promise.allSettled(chunk.map(fn));
  }
}

function makeSkippedResult(source: ProviderId): ProviderResult {
  return {
    source,
    status: 'unsupported',
    score: 0,
    verdict: 'unknown',
    raw_summary: {},
    tags: ['circuit-open'],
    fetched_at: new Date().toISOString(),
    cached: false,
  };
}

function makeErrorResult(source: ProviderId, err: unknown): ProviderResult {
  return {
    source,
    status: 'error',
    score: 0,
    verdict: 'unknown',
    raw_summary: {},
    tags: [],
    error: err instanceof Error ? err.message : String(err),
    fetched_at: new Date().toISOString(),
    cached: false,
  };
}

/** Tier-2 providers that add minimal signal — skip when tier-1 has actionable results. */
const LOW_VALUE_PROVIDERS = new Set<ProviderId>([
  'cinsarmy',
  'bitwire',
  'blocklistde',
  'binarydefense',
  'ipsum',
  'tweetfeed',
  'c2tracker',
  'sslbl',
  'malwareworld',
  'phishingArmy',
  'doh',
  'hashlookup',
  'malshare',
  'x4bnet',
  'certpl',
  'digitalside',
  'stopforumspam',
  'dshield',
  'intodns',
  'opensourcemalware',
  'secrets',
  'webamon',
  'zoomeye',
  'tre-ge',
  'spur',
  'phishstats',
  'criminalip',
  'vulncheck',
  'emailrep',
  'malpedia',
  'otx',
]);

export interface HuntingContext {
  /** Malware family names extracted from threatfox/malwarebazaar/otx hits. */
  malware_families: string[];
  /** ThreatFox match details (first/last seen, confidence). */
  threatfox_hits: Array<{ malware: string; confidence: number; first_seen: string; last_seen: string }>;
  /** MalwareBazaar sample details (signature, file type, file name). */
  malwarebazaar_hits: Array<{ signature: string; file_type: string; file_name: string }>;
  /** OTX pulse names this indicator appears in. */
  otx_pulses: string[];
  /** Provider IDs that found this indicator malicious. */
  malicious_sources: ProviderId[];
  /** Provider IDs that found this indicator suspicious. */
  suspicious_sources: ProviderId[];
}

export interface IocProviderRunResult {
  collected: ProviderResult[];
  composite: ReturnType<typeof compositeScore>;
  admiralty: ReturnType<typeof admiraltyGrade>;
  eligible: ProviderId[];
  hunting: HuntingContext;
}

function buildHuntingContext(results: ProviderResult[]): HuntingContext {
  const ctx: HuntingContext = {
    malware_families: [],
    threatfox_hits: [],
    malwarebazaar_hits: [],
    otx_pulses: [],
    malicious_sources: [],
    suspicious_sources: [],
  };

  for (const r of results) {
    if (r.status !== 'ok') continue;

    if (r.verdict === 'malicious') ctx.malicious_sources.push(r.source);
    else if (r.verdict === 'suspicious') ctx.suspicious_sources.push(r.source);

    if (r.source === 'threatfox') {
      const rs = r.raw_summary as Record<string, unknown>;
      const malware = rs.malware as string[] | undefined;
      if (malware?.length) ctx.malware_families.push(...malware);
      if (rs.match_count && (rs.match_count as number) > 0) {
        ctx.threatfox_hits.push({
          malware: (malware ?? [])[0] ?? '',
          confidence: (rs.confidence as number) ?? 0,
          first_seen: (rs.first_seen as string) ?? '',
          last_seen: (rs.last_seen as string) ?? '',
        });
      }
    }

    if (r.source === 'malwarebazaar') {
      const rs = r.raw_summary as Record<string, unknown>;
      if (rs.signature) {
        ctx.malware_families.push(rs.signature as string);
        ctx.malwarebazaar_hits.push({
          signature: rs.signature as string,
          file_type: (rs.file_type as string) ?? '',
          file_name: (rs.file_name as string) ?? '',
        });
      }
    }

    if (r.source === 'otx') {
      const rs = r.raw_summary as Record<string, unknown>;
      const pulses = rs.sample_pulses as string[] | undefined;
      if (pulses?.length) ctx.otx_pulses.push(...pulses);
      if (r.score >= 70) ctx.malware_families.push(...(r.tags ?? []));
    }

    // Extract malware family from tags
    for (const tag of r.tags ?? []) {
      if (tag.startsWith('malware:') && !ctx.malware_families.includes(tag.slice(8))) {
        ctx.malware_families.push(tag.slice(8));
      }
    }
  }

  ctx.malware_families = [...new Set(ctx.malware_families)];
  ctx.otx_pulses = [...new Set(ctx.otx_pulses)];
  return ctx;
}

/**
 * Run the full provider fan-out for an indicator. Returns collected results,
 * composite score, and admiralty grade — everything downstream consumers need.
 *
 * Tier system: tier-1 providers always run. Tier-2 (low-value blocklists)
 * only run when tier-1 returns no actionable signals — reducing subrequests
 * from ~27 to ~12 for typical IOC checks.
 */
export async function runIocProviders(
  raw: string,
  env: Env,
  onResult?: (r: ProviderResult) => void,
  options?: { skipLowValue?: boolean }
): Promise<IocProviderRunResult> {
  const type = detectType(raw);
  const indicator: Indicator = { type, value: refang(raw.trim()) };
  const allEligible = (Object.keys(ADAPTERS) as ProviderId[]).filter((p) => PROVIDER_SUPPORT[p].includes(type));
  const providerEnv = buildProviderEnv(env);
  const cache = new ProviderCache(env.KV_CACHE);

  const collected: ProviderResult[] = [];

  // Split into tier-1 (high-value) and tier-2 (low-value)
  const tier1 = allEligible.filter((p) => !LOW_VALUE_PROVIDERS.has(p));
  const tier2 = allEligible.filter((p) => LOW_VALUE_PROVIDERS.has(p));

  await cache.primeBatch(indicator);

  // Always run tier-1 providers
  await runChunked(
    tier1,
    async (p) => {
      if (isCircuitOpen(p)) {
        const skipped = makeSkippedResult(p);
        collected.push(skipped);
        onResult?.(skipped);
        return;
      }
      const cached = cache.getBatched(p);
      if (cached) {
        collected.push(cached);
        onResult?.(cached);
        await recordProviderSuccess(p);
        return;
      }
      const signal = AbortSignal.timeout(providerTimeoutMs(p));
      try {
        const r = await ADAPTERS[p](indicator, providerEnv, signal);
        collected.push(r);
        onResult?.(r);
        if (r.status === 'ok') {
          cache.stageBatched(p, indicator, r);
          await recordProviderSuccess(p);
        } else {
          recordProviderFailure(p);
        }
      } catch (err) {
        recordProviderFailure(p);
        const errResult = makeErrorResult(p, err);
        collected.push(errResult);
        onResult?.(errResult);
      }
    },
    PROVIDER_CHUNK_SIZE
  );

  // Only skip tier-2 when there's strong corroborated malicious evidence (weight >= 2, score >= 70).
  // A single weak "suspicious" from a low-weight provider (e.g. ipinfo flagged VPN usage)
  // should not block 30+ tier-2 corroboration sources (OTX, CINS Army, etc.).
  const tierWeights = WEIGHTS[type] ?? {};
  const hasStrongMalicious = collected.some(
    (r) => r.status === 'ok' && r.verdict === 'malicious' && r.score >= 70 && (tierWeights[r.source] ?? 1) >= 2
  );
  if (!hasStrongMalicious && !options?.skipLowValue) {
    await runChunked(
      tier2,
      async (p) => {
        if (isCircuitOpen(p)) {
          const skipped = makeSkippedResult(p);
          collected.push(skipped);
          onResult?.(skipped);
          return;
        }
        const cached = cache.getBatched(p);
        if (cached) {
          collected.push(cached);
          onResult?.(cached);
          await recordProviderSuccess(p);
          return;
        }
        const signal = AbortSignal.timeout(providerTimeoutMs(p));
        try {
          const r = await ADAPTERS[p](indicator, providerEnv, signal);
          collected.push(r);
          onResult?.(r);
          if (r.status === 'ok') {
            cache.stageBatched(p, indicator, r);
            await recordProviderSuccess(p);
          } else {
            recordProviderFailure(p);
          }
        } catch (err) {
          recordProviderFailure(p);
          const errResult = makeErrorResult(p, err);
          collected.push(errResult);
          onResult?.(errResult);
        }
      },
      PROVIDER_CHUNK_SIZE
    );
  }

  await cache.flushBatch(indicator);

  const composite = compositeScore(type, collected);
  const adv = admiraltyGrade(
    type,
    collected.filter((r) => r.status === 'ok').map((r) => r.source)
  );

  const hunting = buildHuntingContext(collected);
  return { collected, composite, admiralty: adv, eligible: allEligible, hunting };
}
