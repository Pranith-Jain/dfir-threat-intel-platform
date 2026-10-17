/**
 * POST /api/v1/sample/scan — "lite 0x12" free hash fan-out.
 *
 * Accepts a hash (JSON body `{ hash }` or `?hash=` query) and runs the
 * same multi-provider score pipeline as /api/v1/ioc/check, but
 * specifically for the sample-scan use case:
 *
 *   - Terminal `done` event attaches the public-sandbox deep links so
 *     the user can one-click detonate the sample in a free public
 *     sandbox if the local verdict is inconclusive.
 *   - Aggregates signature / family tags across all providers so the
 *     UI can render a "0x12-lite" report (verdict, score, families,
 *     signatures, public-sandbox links).
 *
 * Why hash-only and not multipart upload: Cloudflare Workers Free
 * caps CPU at 10 ms / invocation, and a 32 MB SHA-256 in V8 needs
 * ~30 ms of CPU. The frontend `SampleScan` page already hashes the
 * file client-side via the existing `analyseFile` helper, so we just
 * accept the SHA-256 here. The same constraint is why the existing
 * `/api/v1/file/analyze` is also hash-only.
 *
 * Why this is "lite 0x12": Cloudflare Containers require the Workers
 * Paid plan ($5/mo minimum), so the "spin up a Linux container, run
 * clamscan / yara / capa / olevba" path is out. This endpoint covers
 * the same surface for 0x12darksandbox.net's free tier of public
 * engines without self-hosting.
 *
 * @see docs/free/sample-scan.md
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { compositeScore } from '../lib/scoring';
import { sseStream } from '../lib/sse';
import { claimSseSlot, SSE_MAX_CONCURRENT } from '../lib/sse-concurrency';
import { ProviderCache } from '../lib/cache';
import { isCircuitOpen, recordProviderFailure, recordProviderSuccess } from '../lib/circuit-breaker';
import { publicSandboxesFor } from '../lib/sample-scan';
import type { ProviderResult, ProviderId, ProviderEnv, ProviderAdapter, Indicator, Verdict } from '../providers/types';
import { PROVIDER_SUPPORT, providerTimeoutMs } from '../providers/types';
import { virustotal } from '../providers/virustotal';
import { hybridanalysis } from '../providers/hybridanalysis';
import { otx } from '../providers/otx';
import { threatfox } from '../providers/threatfox';
import { malwarebazaar } from '../providers/malwarebazaar';
import { malshare } from '../providers/malshare';
import { hashlookup } from '../providers/hashlookup';
import { yaraify } from '../providers/yaraify';
import { kaspersky } from '../providers/kaspersky';
import { trackEvent, visitorCountry } from '../lib/analytics';

// ─── Constants ────────────────────────────────────────────────────────────

const PROVIDER_CHUNK_SIZE = 10;

const HASH_PROVIDERS: ReadonlyArray<ProviderId> = [
  'virustotal',
  'hybridanalysis',
  'otx',
  'threatfox',
  'malwarebazaar',
  'malshare',
  'hashlookup',
  'yaraify',
  'kaspersky',
];

const ADAPTERS: Record<ProviderId, ProviderAdapter> = {
  virustotal,
  hybridanalysis,
  otx,
  threatfox,
  malwarebazaar,
  malshare,
  hashlookup,
  yaraify,
  kaspersky,
} as unknown as Record<ProviderId, ProviderAdapter>;

// ─── Types ────────────────────────────────────────────────────────────────

type Ctx = Context<{ Bindings: Env }>;

export interface SampleScanMeta {
  hash: string;
  hash_type: 'md5' | 'sha1' | 'sha256';
  filename?: string;
  size?: number;
  providers: ProviderId[];
}

export interface SampleScanDone {
  hash: string;
  hash_type: 'md5' | 'sha1' | 'sha256';
  filename?: string;
  size?: number;
  score: number;
  verdict: Verdict;
  confidence: 'low' | 'medium' | 'high';
  contributing: number;
  /** Public-sandbox deep links the user can one-click to detonate the sample. */
  public_sandboxes: Array<{
    name: string;
    description: string;
    requires_key: boolean;
    url: string;
  }>;
  signatures: string[];
  families: string[];
}

// ─── Hash detection ───────────────────────────────────────────────────────

export function detectHashType(s: string): 'md5' | 'sha1' | 'sha256' | null {
  const t = s.trim().toLowerCase();
  if (/^[a-f0-9]{32}$/.test(t)) return 'md5';
  if (/^[a-f0-9]{40}$/.test(t)) return 'sha1';
  if (/^[a-f0-9]{64}$/.test(t)) return 'sha256';
  return null;
}

// ─── Provider env ─────────────────────────────────────────────────────────

function buildProviderEnv(c: Ctx): ProviderEnv {
  return {
    VT_API_KEY: c.env.VT_API_KEY ?? '',
    ABUSEIPDB_API_KEY: c.env.ABUSEIPDB_API_KEY ?? '',
    SHODAN_API_KEY: c.env.SHODAN_API_KEY ?? '',
    CENSYS_PAT: c.env.CENSYS_PAT ?? '',
    CENSYS_ORG_ID: c.env.CENSYS_ORG_ID ?? '',
    NETLAS_API_KEY: c.env.NETLAS_API_KEY ?? '',
    OTX_API_KEY: c.env.OTX_API_KEY ?? '',
    URLSCAN_API_KEY: c.env.URLSCAN_API_KEY ?? '',
    HYBRID_ANALYSIS_API_KEY: c.env.HYBRID_ANALYSIS_API_KEY ?? '',
    ABUSECH_AUTH_KEY: c.env.ABUSECH_AUTH_KEY,
    MALSHARE_API_KEY: c.env.MALSHARE_API_KEY,
    CROWDSEC_API_KEY: c.env.CROWDSEC_API_KEY,
    IPINFO_TOKEN: c.env.IPINFO_TOKEN,
    CRIMINALIP_API_KEY: c.env.CRIMINALIP_API_KEY,
    KASPERSKY_API_KEY: c.env.KASPERSKY_API_KEY,
    SPUR_API_KEY: c.env.SPUR_API_KEY,
    VULNCHECK_API_TOKEN: c.env.VULNCHECK_API_TOKEN,
    POLYSWARM_API_KEY: c.env.POLYSWARM_API_KEY,
  };
}

// ─── Input parsing ────────────────────────────────────────────────────────

interface ParsedInput {
  hash: string;
  hashType: 'md5' | 'sha1' | 'sha256';
}

async function parseInput(c: Ctx): Promise<ParsedInput | { error: Response }> {
  // JSON body — the path the frontend uses (analyseFile already produced the hash).
  const contentType = c.req.header('content-type') ?? '';
  if (contentType.toLowerCase().includes('application/json')) {
    let body: { hash?: string; filename?: string; size?: number };
    try {
      body = (await c.req.json()) as { hash?: string; filename?: string; size?: number };
    } catch (_catchErr) {
      logError('parseInput failed', _catchErr);
      return { error: badRequest(c, 'invalid JSON') };
    }
    const hash = body.hash?.trim().toLowerCase();
    if (!hash) return { error: badRequest(c, 'missing hash') };
    const hashType = detectHashType(hash);
    if (!hashType) {
      return { error: badRequest(c, 'invalid hash (expected MD5/SHA-1/SHA-256)') };
    }
    return { hash, hashType };
  }

  // Query string `?hash=` fallback — easy to share / smoke-test.
  const q = c.req.query('hash');
  if (q) {
    const hash = q.trim().toLowerCase();
    const hashType = detectHashType(hash);
    if (!hashType) {
      return { error: badRequest(c, 'invalid hash (expected MD5/SHA-1/SHA-256)') };
    }
    return { hash, hashType };
  }

  return { error: badRequest(c, 'expected JSON body { hash } or ?hash=') };
}

// ─── Provider fan-out (mirrors ioc-controller pattern) ────────────────────

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

async function runChunked<T>(items: T[], fn: (item: T) => Promise<void>, size: number): Promise<void> {
  for (let i = 0; i < items.length; i += size) {
    const chunk = items.slice(i, i + size);
    await Promise.allSettled(chunk.map(fn));
  }
}

async function runHashFanOut(
  hash: string,
  env: ProviderEnv,
  cache: ProviderCache,
  write: (event: string, data: unknown) => void
): Promise<ProviderResult[]> {
  const indicator: Indicator = { type: 'hash', value: hash };
  const eligible = HASH_PROVIDERS.filter((p) => PROVIDER_SUPPORT[p].includes('hash'));
  const collected: ProviderResult[] = [];
  await cache.primeBatch(indicator);
  await runChunked(
    eligible,
    async (p) => {
      if (isCircuitOpen(p)) {
        const skipped = makeSkippedResult(p);
        collected.push(skipped);
        write('result', skipped);
        return;
      }
      const cached = cache.getBatched(p);
      if (cached) {
        collected.push(cached);
        write('result', cached);
        await recordProviderSuccess(p);
        return;
      }
      const signal = AbortSignal.timeout(providerTimeoutMs(p));
      try {
        const r = await ADAPTERS[p](indicator, env, signal);
        collected.push(r);
        write('result', r);
        if (r.status === 'ok') {
          cache.stageBatched(p, indicator, r);
          await recordProviderSuccess(p);
        } else {
          recordProviderFailure(p);
        }
      } catch (err) {
        logError('handler failed', err);
        recordProviderFailure(p);
        const errResult = makeErrorResult(p, err);
        collected.push(errResult);
        write('result', errResult);
      }
    },
    PROVIDER_CHUNK_SIZE
  );
  await cache.flushBatch(indicator);
  return collected;
}

// ─── Public-sandbox link builder ──────────────────────────────────────────

function buildPublicSandboxLinks(hash: string, type: 'md5' | 'sha1' | 'sha256') {
  return publicSandboxesFor(hash, type).map((s) => {
    const url = s.build ? s.build(hash, type) : '';
    return {
      name: s.name,
      description: s.description,
      requires_key: s.requiresKey,
      url,
    };
  });
}

// ─── Handler ──────────────────────────────────────────────────────────────

export async function sampleScanHandler(c: Ctx): Promise<Response> {
  const parsed = await parseInput(c);
  if ('error' in parsed) return parsed.error;

  const ip = c.req.header('cf-connecting-ip') ?? 'anon';
  const slot = await claimSseSlot(c, ip);
  if (!slot) {
    return c.json(
      { error: 'sse_concurrent_limit', max_concurrent: SSE_MAX_CONCURRENT, retry_hint: 'wait before retrying' },
      429,
      { 'retry-after': '5', 'cache-control': 'no-store' }
    );
  }

  const providerEnv = buildProviderEnv(c);
  const cache = new ProviderCache(c.env.KV_CACHE);

  return sseStream<unknown>(async (write) => {
    const meta: SampleScanMeta = {
      hash: parsed.hash,
      hash_type: parsed.hashType,
      providers: HASH_PROVIDERS.filter((p) => PROVIDER_SUPPORT[p].includes('hash')),
    };
    write('meta', meta);

    const results = await runHashFanOut(parsed.hash, providerEnv, cache, write);
    const composite = compositeScore('hash', results);

    // Aggregate signature / family tags across all providers — these are the
    // most useful actionable data points for the "0x12-lite" report.
    const signatureSet = new Set<string>();
    const familySet = new Set<string>();
    for (const r of results) {
      if (r.status !== 'ok') continue;
      for (const t of r.tags) {
        signatureSet.add(t);
        const colon = t.indexOf(':');
        if (colon > 0) {
          const family = t.slice(colon + 1).trim();
          if (family && family.length <= 40) familySet.add(family);
        }
      }
    }

    const done: SampleScanDone = {
      hash: parsed.hash,
      hash_type: parsed.hashType,
      score: composite.score,
      verdict: composite.verdict,
      confidence: composite.confidence,
      contributing: composite.contributing,
      public_sandboxes: buildPublicSandboxLinks(parsed.hash, parsed.hashType),
      signatures: [...signatureSet].slice(0, 200),
      families: [...familySet].slice(0, 50),
    };
    write('done', done);

    trackEvent(c.env, 'sample_scan', {
      blobs: [parsed.hashType, composite.verdict, composite.confidence],
      doubles: [composite.score, composite.contributing],
      indexes: [visitorCountry(c.req.raw)],
    });

    c.executionCtx.waitUntil(slot.release());
  });
}
