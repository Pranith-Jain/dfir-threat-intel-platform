/**
 * AI Threat Analysis Engine
 *
 * Uses Workers AI to analyze threats, generate risk scores, and provide
 * natural language summaries of threat intelligence data.
 *
 * POST /api/v1/ti/analyze — Analyze a threat indicator
 * POST /api/v1/ti/summarize — Summarize threat data
 * POST /api/v1/ti/risk-score — Calculate composite risk score
 * POST /api/v1/ti/hunt — Generate hunting queries
 * POST /api/v1/ti/brief — Generate threat brief
 */

import { Hono } from 'hono';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { safeJsonBody } from '../lib/safe-body';
import type { D1Database, KVNamespace, Ai } from '@cloudflare/workers-types';
import { routeCacheGet, routeCachePut } from '../lib/route-cache';
import { runCompletion } from '../case-study/generation/ai-client';
import { NO_EM_DASH_RULE, stripConnectorEmDashes } from '../lib/prose-style';

interface AiEnv {
  BRIEFINGS_DB: D1Database;
  KV_CACHE: KVNamespace;
  AI: Ai;
  GROQ_API_KEY?: string;
  GOOGLE_AI_STUDIO_API_KEY?: string;
  NVIDIA_API_KEY?: string;
}

interface ThreatContext {
  type: string;
  first_seen: string | null;
  last_seen: string | null;
  source_count: number;
  related_iocs: string[];
  associated_cves: string[];
  actor: string | null;
}

interface ThreatAnalysis {
  indicator: string;
  type: string;
  risk_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
  confidence: number;
  summary: string;
  recommendations: string[];
  related_threats: string[];
  mitre_techniques: string[];
  first_seen: string;
  last_seen: string;
  sources: number;
}

interface RiskScore {
  overall: number;
  breakdown: {
    severity: number;
    exposure: number;
    recency: number;
    attribution: number;
    ioc_density: number;
  };
  factors: string[];
  recommendations: string[];
}

const ai = new Hono<{ Bindings: AiEnv }>();

async function runAiPrompt(
  prompt: string,
  env: { GROQ_API_KEY?: string; GOOGLE_AI_STUDIO_API_KEY?: string; NVIDIA_API_KEY?: string }
): Promise<string> {
  try {
    const result = await runCompletion(
      null,
      {
        system: '',
        user: prompt,
        maxTokens: 1024,
      },
      {
        nvidiaKey: env.NVIDIA_API_KEY,
        groqKey: env.GROQ_API_KEY,
        googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
      }
    );
    return result.text;
  } catch (e) {
    logError('runAiPrompt failed', e);
    return `AI analysis unavailable: ${(e as Error).message || 'unknown error'}`;
  }
}

ai.post('/analyze', async (c) => {
  const db = c.env.BRIEFINGS_DB;

  const parsed = await safeJsonBody<{ indicator: string; type?: string }>(c, {
    maxBytes: 4 * 1024,
    maxDepth: 4,
  });
  if ('error' in parsed) return parsed.error;
  const { indicator, type } = parsed.value;

  if (typeof indicator !== 'string' || indicator.length < 3 || indicator.length > 256) {
    return badRequest(c, 'indicator must be a 3–256 char string');
  }
  if (type !== undefined && (typeof type !== 'string' || type.length > 32)) {
    return badRequest(c, 'type must be a short string');
  }

  const cacheKey = `ti:ai:analyze:${indicator}`;
  const cached = await routeCacheGet<object>(cacheKey);
  if (cached) return c.json(cached);

  const context = await gatherIndicatorContext(db, indicator);

  const prompt = `Analyze this threat indicator and provide a structured assessment.

Indicator: ${indicator}
Type: ${type || context.type || 'unknown'}

Known context:
- First seen: ${context.first_seen || 'unknown'}
- Last seen: ${context.last_seen || 'unknown'}
- Sources reporting: ${context.source_count || 0}
- Related IOCs: ${(context.related_iocs || []).slice(0, 5).join(', ') || 'none'}
- Associated CVEs: ${(context.associated_cves || []).slice(0, 3).join(', ') || 'none'}
- Threat actor attribution: ${context.actor || 'unknown'}

Provide:
1. Risk score (0-100) with justification
2. Risk level (critical/high/medium/low/minimal)
3. Confidence level (0-1)
4. Brief summary (2-3 sentences)
5. Top 3 recommendations
6. Related MITRE ATT&CK techniques (if applicable)

Respond in JSON format:
{
  "risk_score": number,
  "risk_level": "critical"|"high"|"medium"|"low"|"minimal",
  "confidence": number,
  "summary": "string",
  "recommendations": ["string", "string", "string"],
  "mitre_techniques": ["T1234", "T5678"],
  "related_threats": ["string"]
}${NO_EM_DASH_RULE}`;

  const aiResponse = await runAiPrompt(prompt, c.env);

  // If AI is unavailable, return fallback analysis
  if (aiResponse.startsWith('AI analysis unavailable')) {
    const fallbackAnalysis: ThreatAnalysis = {
      indicator,
      type: type || context.type || 'unknown',
      risk_score: 50,
      risk_level: 'medium',
      confidence: 0.2,
      summary: 'AI analysis unavailable. Manual review recommended.',
      recommendations: ['Manual analysis required', 'Check threat intelligence databases', 'Monitor for changes'],
      related_threats: [],
      mitre_techniques: [],
      first_seen: context.first_seen || new Date().toISOString(),
      last_seen: context.last_seen || new Date().toISOString(),
      sources: context.source_count || 0,
    };
    return c.json(fallbackAnalysis);
  }

  let analysis: ThreatAnalysis;
  try {
    const parsed = JSON.parse(aiResponse);
    analysis = {
      indicator,
      type: type || context.type || 'unknown',
      risk_score: parsed.risk_score || 50,
      risk_level: parsed.risk_level || 'medium',
      confidence: parsed.confidence || 0.5,
      summary: typeof parsed.summary === 'string' ? stripConnectorEmDashes(parsed.summary) : 'Analysis pending',
      recommendations: Array.isArray(parsed.recommendations)
        ? parsed.recommendations.map((r: unknown) => (typeof r === 'string' ? stripConnectorEmDashes(r) : r))
        : [],
      related_threats: Array.isArray(parsed.related_threats)
        ? parsed.related_threats.map((r: unknown) => (typeof r === 'string' ? stripConnectorEmDashes(r) : r))
        : [],
      // `mitre_techniques` is a list of T-codes, not prose: left untouched.
      mitre_techniques: parsed.mitre_techniques || [],
      first_seen: context.first_seen || new Date().toISOString(),
      last_seen: context.last_seen || new Date().toISOString(),
      sources: context.source_count || 0,
    };
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    analysis = {
      indicator,
      type: type || 'unknown',
      risk_score: 50,
      risk_level: 'medium',
      confidence: 0.3,
      summary: stripConnectorEmDashes(aiResponse.slice(0, 500)),
      recommendations: ['Manual review recommended'],
      related_threats: [],
      mitre_techniques: [],
      first_seen: context.first_seen || new Date().toISOString(),
      last_seen: context.last_seen || new Date().toISOString(),
      sources: context.source_count || 0,
    };
  }

  c.executionCtx.waitUntil(routeCachePut(cacheKey, analysis, 3600));
  return c.json(analysis);
});

ai.post('/summarize', async (c) => {
  const body = await c.req.json<{ text: string; type?: string }>();

  if (!body.text) {
    return badRequest(c, 'text required');
  }

  const prompt = `Summarize this threat intelligence data concisely. Focus on:
- Key threats identified
- Severity assessment
- Recommended actions
- Timeline of events

Data:
${body.text.slice(0, 4000)}

Provide a structured summary in JSON:
{
  "summary": "2-3 sentence overview",
  "key_threats": ["threat1", "threat2"],
  "severity": "critical"|"high"|"medium"|"low",
  "recommended_actions": ["action1", "action2"],
  "timeline": [{"event": "string", "date": "string"}]
}${NO_EM_DASH_RULE}`;

  const response = await runAiPrompt(prompt, c.env);

  // Fallback if AI unavailable
  if (response.startsWith('AI analysis unavailable')) {
    return c.json({
      summary: 'AI summarization unavailable. Manual review required.',
      key_threats: [],
      severity: 'unknown',
      recommended_actions: ['Manual analysis required'],
    });
  }

  try {
    const parsed = JSON.parse(response) as Record<string, unknown>;
    // Prose fields only; `severity` is an enum and must not be touched.
    if (typeof parsed.summary === 'string') parsed.summary = stripConnectorEmDashes(parsed.summary);
    for (const key of ['key_threats', 'recommended_actions'] as const) {
      if (Array.isArray(parsed[key])) {
        parsed[key] = parsed[key].map((v) => (typeof v === 'string' ? stripConnectorEmDashes(v) : v));
      }
    }
    return c.json(parsed);
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return c.json({ summary: stripConnectorEmDashes(response.slice(0, 1000)), severity: 'medium' });
  }
});

ai.post('/risk-score', async (c) => {
  const db = c.env.BRIEFINGS_DB;
  const _kv = c.env.KV_CACHE;
  const parsedRisk = await safeJsonBody<{ indicators: string[]; context?: string }>(c, {
    maxBytes: 16 * 1024,
    maxDepth: 4,
  });
  if ('error' in parsedRisk) return parsedRisk.error;
  const body = parsedRisk.value;

  if (!Array.isArray(body.indicators) || body.indicators.length === 0 || body.indicators.length > 10) {
    return badRequest(c, 'indicators must be an array of 1–10 strings');
  }
  if (body.indicators.some((i) => typeof i !== 'string' || i.length < 2 || i.length > 256)) {
    return badRequest(c, 'each indicator must be a 2–256 char string');
  }

  const indicatorData = await Promise.all(
    body.indicators.slice(0, 10).map(async (indicator) => {
      const context = await gatherIndicatorContext(db, indicator);
      return { indicator, ...context };
    })
  );

  const totalSources = indicatorData.reduce((sum, d) => sum + (d.source_count || 0), 0);
  const uniqueActors = new Set(indicatorData.filter((d) => d.actor).map((d) => d.actor)).size;
  const hasCves = indicatorData.some((d) => d.associated_cves?.length > 0);
  const recentActivity = indicatorData.filter((d) => {
    if (!d.last_seen) return false;
    return Date.now() - new Date(d.last_seen).getTime() < 86400000;
  }).length;

  const breakdown = {
    severity: Math.min(100, totalSources * 5 + uniqueActors * 15),
    exposure: Math.min(100, indicatorData.length * 10),
    recency: Math.min(100, (recentActivity / Math.max(indicatorData.length, 1)) * 100),
    attribution: Math.min(100, uniqueActors * 20 + (hasCves ? 30 : 0)),
    ioc_density: Math.min(100, indicatorData.length * 8),
  };

  const overall = Math.round(
    breakdown.severity * 0.25 +
      breakdown.exposure * 0.2 +
      breakdown.recency * 0.2 +
      breakdown.attribution * 0.2 +
      breakdown.ioc_density * 0.15
  );

  const factors: string[] = [];
  if (totalSources > 5) factors.push(`High source diversity (${totalSources} sources)`);
  if (uniqueActors > 0) factors.push(`Attributed to ${uniqueActors} threat actor(s)`);
  if (hasCves) factors.push('Associated with known CVEs');
  if (recentActivity > 0) factors.push(`${recentActivity} indicators with recent activity`);

  const recommendations: string[] = [];
  if (overall > 70) {
    recommendations.push('Immediate investigation recommended');
    recommendations.push('Consider blocking associated IOCs');
  } else if (overall > 40) {
    recommendations.push('Monitor for escalation');
    recommendations.push('Review related threat intelligence');
  } else {
    recommendations.push('Continue routine monitoring');
  }

  const riskScore: RiskScore = {
    overall,
    breakdown,
    factors,
    recommendations,
  };

  return c.json(riskScore);
});

ai.post('/hunt', async (c) => {
  const body = await c.req.json<{ scenario: string; platform?: string }>();

  if (!body.scenario) {
    return badRequest(c, 'scenario required');
  }

  const platform = body.platform || 'microsoft';

  const prompt = `Generate threat hunting queries for this scenario on ${platform}.

Scenario: ${body.scenario}

Generate 3-5 detection queries tailored to this scenario. Include:
1. KQL query for Microsoft Sentinel/Defender
2. Sigma rule equivalent (if applicable)
3. YARA rule for file-based detection (if applicable)
4. Query description and expected results
5. MITRE ATT&CK technique mapping

Respond in JSON:
{
  "queries": [
    {
      "name": "string",
      "platform": "kql"|"sigma"|"yara",
      "query": "string",
      "description": "string",
      "mitre": "T1234",
      "severity": "critical"|"high"|"medium"|"low"
    }
  ]
}`;

  const response = await runAiPrompt(prompt, c.env);

  // Fallback if AI unavailable
  if (response.startsWith('AI analysis unavailable')) {
    return c.json({
      queries: [
        {
          name: 'Manual query required',
          platform: 'kql',
          query: '// AI unavailable - generate queries manually',
          description: body.scenario,
          severity: 'medium',
        },
      ],
    });
  }

  try {
    return c.json(JSON.parse(response));
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return c.json({
      queries: [
        { name: 'Fallback query', platform: 'kql', query: response.slice(0, 2000), description: body.scenario },
      ],
    });
  }
});

ai.post('/brief', async (c) => {
  const db = c.env.BRIEFINGS_DB;
  const _kv = c.env.KV_CACHE;

  const body = await c.req.json<{ topic?: string; hours?: number }>();

  const hours = body.hours || 24;
  const topic = body.topic || 'general threat landscape';

  const since = new Date(Date.now() - hours * 3600000).toISOString();

  const [ransomware, cves, iocs] = await Promise.all([
    db
      .prepare('SELECT COUNT(*) as cnt FROM ransomware_groups WHERE created_at > ?')
      .bind(since)
      .first<{ cnt: number }>()
      .catch(() => ({ cnt: 0 })),
    db
      .prepare('SELECT COUNT(*) as cnt FROM cve_recent WHERE published_at > ?')
      .bind(since)
      .first<{ cnt: number }>()
      .catch(() => ({ cnt: 0 })),
    db
      .prepare('SELECT COUNT(*) as cnt FROM live_iocs WHERE first_seen > ?')
      .bind(since)
      .first<{ cnt: number }>()
      .catch(() => ({ cnt: 0 })),
  ]);

  const prompt = `Generate a threat intelligence brief covering: ${topic}

Data summary (last ${hours} hours):
- New ransomware groups: ${ransomware?.cnt ?? 0}
- New CVEs: ${cves?.cnt ?? 0}
- New IOCs: ${iocs?.cnt ?? 0}

Create a professional threat brief with:
1. Executive summary (3-4 sentences)
2. Key developments
3. Risk assessment
4. Recommended actions
5. Outlook

Format as JSON:
{
  "title": "string",
  "executive_summary": "string",
  "key_developments": ["string"],
  "risk_assessment": "string",
  "recommended_actions": ["string"],
  "outlook": "string"
}`;

  const response = await runAiPrompt(prompt, c.env);

  // Fallback if AI unavailable
  if (response.startsWith('AI analysis unavailable')) {
    return c.json({
      title: `Threat Brief: ${topic}`,
      executive_summary: 'AI brief generation unavailable. Manual analysis required.',
      key_developments: [],
      risk_assessment: 'Unable to generate automated assessment',
      recommended_actions: ['Manual threat analysis required', 'Review available intelligence feeds'],
      outlook: 'Threat landscape assessment pending',
    });
  }

  try {
    return c.json(JSON.parse(response));
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return c.json({
      title: `Threat Brief: ${topic}`,
      executive_summary: response.slice(0, 1000),
      key_developments: [],
      risk_assessment: 'Analysis in progress',
      recommended_actions: ['Continue monitoring'],
      outlook: 'Threat landscape under review',
    });
  }
});

async function gatherIndicatorContext(db: D1Database, indicator: string): Promise<ThreatContext> {
  const context: ThreatContext = {
    type: detectIndicatorType(indicator),
    first_seen: null,
    last_seen: null,
    source_count: 0,
    related_iocs: [],
    associated_cves: [],
    actor: null,
  };

  try {
    const ioc = await db
      .prepare(
        `
      SELECT first_seen, last_seen, source, type
      FROM live_iocs WHERE indicator = ?
    `
      )
      .bind(indicator)
      .first<{ first_seen: string; last_seen: string; source: string; type: string }>();

    if (ioc) {
      context.first_seen = ioc.first_seen;
      context.last_seen = ioc.last_seen;
      context.type = ioc.type;
    }

    const sources = await db
      .prepare(
        `
      SELECT COUNT(DISTINCT source) as cnt FROM live_iocs WHERE indicator = ?
    `
      )
      .bind(indicator)
      .first<{ cnt: number }>();
    context.source_count = sources?.cnt ?? 0;

    if (indicator.startsWith('CVE-')) {
      const cve = await db
        .prepare(
          `
        SELECT cve_id, published_at FROM cve_recent WHERE cve_id = ?
      `
        )
        .bind(indicator)
        .first<{ cve_id: string; published_at: string }>();
      if (cve) {
        context.associated_cves = [cve.cve_id];
        if (!context.first_seen) context.first_seen = cve.published_at;
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    // Graceful degradation - tables may not exist
  }

  return context;
}

function detectIndicatorType(indicator: string): string {
  if (/^CVE-\d{4}-\d+$/i.test(indicator)) return 'cve';
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator)) return 'ip';
  if (/^[a-fA-F0-9]{32,64}$/.test(indicator)) return 'hash';
  if (/^https?:\/\//i.test(indicator)) return 'url';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(indicator)) return 'domain';
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(indicator)) return 'email';
  return 'unknown';
}

export default ai;
