/**
 * Threat Dossier route.
 *
 * Produces a structured per-entity dossier with 5W+H analysis and
 * Diamond Model mapping — matching Exvora's "Threat Dossier" feature.
 *
 * Endpoints:
 *   POST /api/v1/dossier — generate dossier for a query (IOC, CVE, actor)
 *   GET  /api/v1/dossier/:type/:value — retrieve cached dossier
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { kvBackedGet } from '../lib/route-cache';
import { shouldWriteLastGood } from '../lib/lastgood-debounce';
import { logError } from '../lib/logger';
import { trackEvent } from '../lib/analytics';
import { badRequest, internalError, notFound } from '../lib/api-error';
import { detectType } from '../lib/report/subject-resolver';
import { extractFiveW, type FiveW } from '../lib/fivew-extract';
import { buildDiamondModel, type DiamondModel, type ExtractedIoc } from '../lib/report-analyzer';

// ── Types ──────────────────────────────────────────────────────────────

interface DossierEntity {
  type: 'cve' | 'actor' | 'ip' | 'domain' | 'hash' | 'campaign' | 'ransomware' | 'generic';
  value: string;
  label: string;
}

interface EnrichmentResult {
  entity: DossierEntity;
  /** Raw enrichment data for 5W/H extraction. */
  rawText: string;
  sources: string[];
  scores?: {
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: number;
    malicious?: boolean;
  };
}

interface DossierResponse {
  entity: DossierEntity;
  fiveW: FiveW | null;
  diamond: DiamondModel | null;
  enrichment: EnrichmentResult;
  /**
   * Explainable risk decomposition (ThreatLens pattern): every factor names
   * its contribution and the evidence behind it, so `risk_score` is auditable
   * instead of a black-box number. Deterministic — no LLM involved.
   */
  factors: RiskFactor[];
  risk_score: number;
  generated_at: string;
  tlp: string;
}

export interface RiskFactor {
  name: string;
  /** Points contributed to risk_score (0-100 scale). */
  contribution: number;
  evidence: string;
}

const SEVERITY_POINTS: Record<string, number> = { critical: 40, high: 30, medium: 20, low: 10, info: 0 };

/**
 * Deterministic explainable scoring from the dossier's own artifacts.
 * Additive and capped at 100; each factor carries its evidence string.
 */
export function buildRiskFactors(
  fiveW: FiveW | null,
  diamond: DiamondModel | null,
  enrichment: EnrichmentResult
): { factors: RiskFactor[]; risk_score: number } {
  const factors: RiskFactor[] = [];
  const severity = enrichment.scores?.severity ?? 'info';
  factors.push({
    name: 'severity',
    contribution: SEVERITY_POINTS[severity] ?? 0,
    evidence: `enrichment severity=${severity}`,
  });
  const confidence = enrichment.scores?.confidence ?? 0;
  factors.push({
    name: 'confidence',
    contribution: Math.round(Math.max(0, Math.min(100, confidence)) * 0.2),
    evidence: `model confidence=${confidence}%`,
  });
  if (enrichment.scores?.malicious === true) {
    factors.push({ name: 'confirmed_malicious', contribution: 20, evidence: 'KEV listing / malicious flag present' });
  }
  const iocCount = (diamond as unknown as { iocs?: unknown[] } | null)?.iocs?.length ?? 0;
  if (iocCount > 0) {
    factors.push({
      name: 'corroborating_indicators',
      contribution: Math.min(15, iocCount * 5),
      evidence: `${iocCount} diamond-model indicator(s)`,
    });
  }
  if (fiveW) {
    factors.push({ name: 'structured_intel', contribution: 5, evidence: '5W+H extraction succeeded' });
  }
  if (enrichment.sources.length > 1) {
    factors.push({
      name: 'multi_source',
      contribution: Math.min(10, (enrichment.sources.length - 1) * 5),
      evidence: `${enrichment.sources.length} sources: ${enrichment.sources.slice(0, 3).join(', ')}`,
    });
  }
  const risk_score = Math.min(
    100,
    factors.reduce((s, f) => s + f.contribution, 0)
  );
  return { factors, risk_score };
}

// ── Route ──────────────────────────────────────────────────────────────

/**
 * POST /api/v1/dossier
 * Body: { query: string, queryType?: string }
 * Returns a structured dossier with 5W+H + Diamond Model.
 */
export async function dossierHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    let body: { query?: string; queryType?: string };
    try {
      body = await c.req.json();
    } catch (_catchErr) {
      logError('dossierHandler failed', _catchErr);
      return badRequest(c, 'Invalid JSON body');
    }

    const query = body.query?.trim();
    if (!query) return badRequest(c, 'query is required');
    if (query.length > 500) return badRequest(c, 'query too long (max 500 chars)');

    const queryType = body.queryType ?? (detectType(query) as string);
    const entity = classifyEntity(query, queryType);

    // Early return for CVE — we can enrich directly from KV cache
    if (entity.type === 'cve') {
      return await buildCveDossier(c, entity);
    }

    // For other types, enrich via the agent DO or inline providers
    const enrichment = await enrichEntity(c, entity);
    if (!enrichment) {
      return c.json(buildMinimalDossier(entity, query, `No enrichment available for '${query}'`));
    }

    // Extract 5W+H from the enrichment text
    let fiveW: FiveW | null = null;
    try {
      const ai = c.env.AI;
      if (ai) {
        fiveW = await extractFiveW(enrichment.rawText, c.env);
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      // 5W extraction is best-effort
    }

    // Build Diamond Model from enrichment data
    const diamond = buildDiamondModelFromEnrichment(entity, enrichment, fiveW);

    const { factors, risk_score } = buildRiskFactors(fiveW, diamond, enrichment);
    try {
      trackEvent(c.env, 'dossier_build', { blobs: [entity.type], doubles: [risk_score, factors.length] });
    } catch {
      /* analytics best-effort */
    }

    return c.json({
      entity,
      fiveW,
      diamond,
      enrichment,
      factors,
      risk_score,
      generated_at: new Date().toISOString(),
      tlp: 'CLEAR',
    } satisfies DossierResponse);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e);
  }
}

/**
 * GET /api/v1/dossier/:type/:value — check KV cache for an existing dossier.
 */
export async function dossierGetHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const type = c.req.param('type');
  const value = c.req.param('value');
  if (!type || !value) return badRequest(c, 'type and value required');

  const kv = c.env.KV_CACHE;
  if (!kv) return notFound(c, 'KV cache not available');

  // L1-first: the dossier is an AI-generated snapshot, so a short per-colo
  // Cache-API shadow (5 min) collapses repeat GETs to ~1 KV read per colo per
  // window while bounding staleness after a regeneration in another colo.
  const backed = await kvBackedGet<unknown>(kv, `dossier:${type}:${value}`, DOSSIER_SHADOW_TTL_SECONDS);
  const cached = backed.value;
  if (!cached) return notFound(c, 'no cached dossier');

  return c.json(cached, 200, { 'Cache-Control': 'public, max-age=300' });
}

// ── Helpers ────────────────────────────────────────────────────────────

/** Per-colo Cache-API shadow TTL for dossier reads (see dossierGetHandler). */
const DOSSIER_SHADOW_TTL_SECONDS = 300;

function classifyEntity(query: string, queryType: string): DossierEntity {
  const safe = queryType;
  const type = (['cve', 'actor', 'ip', 'domain', 'hash', 'campaign', 'ransomware'] as const).includes(
    safe as 'cve' | 'actor' | 'ip' | 'domain' | 'hash' | 'campaign' | 'ransomware'
  )
    ? (safe as DossierEntity['type'])
    : 'generic';

  return { type, value: query, label: query };
}

async function buildCveDossier(c: Context<{ Bindings: Env }>, entity: DossierEntity): Promise<Response> {
  const kv = c.env.KV_CACHE;
  // L1-first read of the shared EPSS/enrichment blob (the same `cve:<id>` keys
  // ioc-enrich-deep reads); 1h shadow matches its ~24h data stability.
  const cached = kv ? (await kvBackedGet<Record<string, unknown>>(kv, `cve:${entity.value}`, 3600)).value : null;

  const data = cached ?? {};
  const cvss = data.cvss as Record<string, unknown> | undefined;
  const epss = data.epss as Record<string, unknown> | undefined;
  const kev = data.kev as Record<string, unknown> | undefined;

  const rawText = [
    `CVE: ${entity.value}`,
    cvss ? `CVSS: ${JSON.stringify(cvss)}` : '',
    epss ? `EPSS: ${JSON.stringify(epss)}` : '',
    kev ? `KEV: ${JSON.stringify(kev)}` : '',
    data.description ? `Description: ${data.description}` : '',
    data.vulncheck ? `VulnCheck: ${JSON.stringify(data.vulncheck)}` : '',
  ]
    .filter(Boolean)
    .join('\n');

  let fiveW: FiveW | null = null;
  try {
    const ai = c.env.AI;
    if (ai) {
      fiveW = await extractFiveW(rawText, c.env);
    }
  } catch (_catchErr) {
    logError('buildCveDossier failed', _catchErr);
    // best-effort
  }

  const entities: string[] = [];
  if (data.description) entities.push(`vulnerability: ${data.description}`);
  if (kev?.in_kev) entities.push('cisa_kev: listed');
  if ((data as Record<string, unknown>).exploit_poc) entities.push('poc: available');

  const iocs: ExtractedIoc[] = [
    {
      value: entity.value,
      kind: 'cve',
      confidence: 85,
      confidence_band: 'high',
      evidence: 'CVE identifier',
      source: 'report-text',
    },
  ];

  const diamond = buildDiamondModel({ actors: [], malware: [] }, [], iocs, fiveW, rawText);

  const enrichment: EnrichmentResult = {
    entity,
    rawText,
    sources: ['kv-cache'],
    scores: {
      severity:
        (((cvss as Record<string, unknown>)?.severity as string)?.toLowerCase() as
          'critical' | 'high' | 'medium' | 'low' | 'info') ?? 'medium',
      confidence: epss?.score ? Math.round(Number(epss.score) * 100) : 50,
      malicious: kev?.in_kev === true,
    },
  };

  const { factors: cveFactors, risk_score: cveRisk } = buildRiskFactors(fiveW, diamond, enrichment);
  try {
    trackEvent(c.env, 'dossier_build', { blobs: [`${entity.type}:cve`], doubles: [cveRisk, cveFactors.length] });
  } catch {
    /* analytics best-effort */
  }

  const dossier: DossierResponse = {
    entity,
    fiveW,
    diamond,
    enrichment,
    factors: cveFactors,
    risk_score: cveRisk,
    generated_at: new Date().toISOString(),
    tlp: 'CLEAR',
  };

  // Cache for fast re-read, debounced per CVE: regenerating the same dossier
  // twice in 6h rewrites byte-identical JSON, so skip the repeat write.
  if (kv && (await shouldWriteLastGood(`dossier:cve:${entity.value}`)))
    await kv
      .put(`dossier:cve:${entity.value}`, JSON.stringify(dossier), { expirationTtl: 7200 })
      .catch((err) => logError('dossier cache put failed:', err));

  return c.json(dossier);
}

async function enrichEntity(c: Context<{ Bindings: Env }>, entity: DossierEntity): Promise<EnrichmentResult | null> {
  const kv = c.env.KV_CACHE;
  const parts: string[] = [];
  const sources: string[] = [];

  // Try actor name lookup
  if (entity.type === 'actor' || entity.type === 'ransomware') {
    const actorKey = `actor:${entity.value}`;
    // L1-first: cron-synced reference data, safe to shadow 1h per colo.
    const cached = kv ? (await kvBackedGet<unknown>(kv, actorKey, 3600)).value : null;
    if (cached) {
      parts.push(JSON.stringify(cached));
      sources.push('actor-kv-cache');
    }
  }

  // Try unified search
  try {
    const searchRes = await fetch(
      `${c.env.SELF ? 'http://self' : ''}/api/v1/unified-search?q=${encodeURIComponent(entity.value)}&limit=5`,
      { headers: { 'x-internal-agent': 'true' }, signal: AbortSignal.timeout(10000) }
    );
    if (searchRes.ok) {
      const searchData = (await searchRes.json()) as { results?: unknown[] };
      if (searchData.results?.length) {
        parts.push(JSON.stringify(searchData.results.slice(0, 3)));
        sources.push('unified-search');
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* best-effort */
  }

  if (parts.length === 0) return null;

  return {
    entity,
    rawText: parts.join('\n---\n'),
    sources,
    scores: { severity: 'medium', confidence: 50 },
  };
}

function buildDiamondModelFromEnrichment(
  entity: DossierEntity,
  enrichment: EnrichmentResult,
  fiveW: FiveW | null
): DiamondModel | null {
  try {
    const iocs: ExtractedIoc[] = [
      {
        value: entity.value,
        kind:
          entity.type === 'ip' ? 'ip' : entity.type === 'domain' ? 'domain' : entity.type === 'hash' ? 'hash' : 'cve',
        confidence: 80,
        confidence_band: 'high',
        evidence: enrichment.sources.join(', '),
        source: 'report-text',
      },
    ];

    const actors: string[] = entity.type === 'actor' || entity.type === 'ransomware' ? [entity.value] : [];

    return buildDiamondModel({ actors, malware: [] }, [], iocs, fiveW, enrichment.rawText);
  } catch (_catchErr) {
    logError('buildDiamondModelFromEnrichment failed', _catchErr);
    return null;
  }
}

function buildMinimalDossier(entity: DossierEntity, query: string, note: string): DossierResponse {
  const enrichment: EnrichmentResult = {
    entity,
    rawText: note,
    sources: [],
    scores: { severity: 'info', confidence: 0 },
  };
  const { factors, risk_score } = buildRiskFactors(null, null, enrichment);
  return {
    entity,
    fiveW: null,
    diamond: null,
    enrichment,
    factors,
    risk_score,
    generated_at: new Date().toISOString(),
    tlp: 'CLEAR',
  };
}
