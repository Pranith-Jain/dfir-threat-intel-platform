import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, serviceUnavailable } from '../lib/api-error';
import { runCompletion } from '../case-study/generation/ai-client';

/**
 * POST /api/v1/ir-playbooks/generate
 * Generate an incident response playbook for a given incident type.
 */

interface PlaybookStep {
  id: string;
  title: string;
  description: string;
  tools: string[];
  estimated_time: string;
  critical: boolean;
}

interface Playbook {
  id: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  steps: PlaybookStep[];
  tools_used: string[];
  estimated_total_time: string;
}

interface PlaybookResponse {
  incident_type: string;
  playbook: Playbook;
  related_playbooks: Array<{ id: string; title: string; category: string }>;
  _validation?: {
    step_count?: number;
  };
}

const SYSTEM_PROMPT = `You are a senior incident response manager. Generate a structured IR playbook for the given incident type.

Respond with ONLY a JSON object matching this schema, no prose:

{
  "playbook": {
    "id": "kebab-case-id",
    "title": "Playbook Title",
    "category": "Category",
    "severity": "critical|high|medium|low",
    "description": "2-3 sentence overview",
    "steps": [
      {
        "id": "step-1",
        "title": "Step Title",
        "description": "Detailed instructions for this step",
        "tools": ["Tool Name 1", "Tool Name 2"],
        "estimated_time": "15 min",
        "critical": true
      }
    ],
    "tools_used": ["Tool1", "Tool2"],
    "estimated_total_time": "2 hours"
  },
  "related_playbooks": [
    { "id": "related-id", "title": "Related Playbook", "category": "Category" }
  ]
}

Rules:
- 6-10 steps per playbook.
- Each step should reference specific tools from the DFIR toolkit where applicable (IOC Check, Threat Graph, Attack Chain, STIX Builder, etc.).
- Mark critical steps (containment, evidence preservation) with critical: true.
- Be specific and actionable — not generic advice.
- Include realistic time estimates.
- Suggest 2-3 related playbooks.`;

const MAX_CALL_TIMEOUT = 15000;

const VALID_TYPES = [
  'ransomware',
  'phishing',
  'data-breach',
  'bec',
  'insider-threat',
  'supply-chain',
  'apt',
  'malware',
  'ddos',
  'credential-theft',
];

export async function irPlaybookHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  let body: { incident_type?: string; context?: string };
  try {
    body = await c.req.json();
  } catch (_catchErr) {
    logError('irPlaybookHandler failed', _catchErr);
    return badRequest(c, 'invalid JSON');
  }

  const incidentType = body.incident_type?.trim().toLowerCase();
  if (!incidentType || !VALID_TYPES.includes(incidentType)) {
    return c.json(
      {
        error: 'bad_request',
        message: `incident_type required, one of: ${VALID_TYPES.join(', ')}`,
      },
      400
    );
  }

  const context = body.context?.trim();
  const userPrompt = `Incident type: ${incidentType}${context ? `\nAdditional context: ${context}` : ''}\n\nGenerate a complete IR playbook.`;

  try {
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), MAX_CALL_TIMEOUT)
    );
    const result = await Promise.race([
      runCompletion(
        c.env.AI,
        { system: SYSTEM_PROMPT, user: userPrompt, maxTokens: 3000, temperature: 0.3 },
        {
          googleKey: c.env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: c.env.GROQ_API_KEY,
          nvidiaKey: c.env.NVIDIA_API_KEY as string | undefined,
        }
      ),
      timeoutPromise,
    ]);

    const text = typeof result.text === 'string' ? result.text : '';
    const jsonStart = text.indexOf('{');
    const jsonEnd = text.lastIndexOf('}');
    if (jsonStart < 0 || jsonEnd < 0) throw new Error('no JSON in response');

    const parsed = JSON.parse(text.slice(jsonStart, jsonEnd + 1)) as {
      playbook?: Partial<Playbook>;
      related_playbooks?: Array<{ id?: string; title?: string; category?: string }>;
    };

    const pb = parsed.playbook;
    if (!pb?.title || !pb?.steps) throw new Error('incomplete playbook');

    // Validate steps have meaningful content (not just filler)
    const validatedSteps = (pb.steps ?? [])
      .map((s, i) => ({
        id: s.id ?? `step-${i + 1}`,
        title: s.title ?? `Step ${i + 1}`,
        description: s.description ?? '',
        tools: s.tools ?? [],
        estimated_time: s.estimated_time ?? '15 min',
        critical: s.critical ?? false,
      }))
      .filter((s) => s.description.length > 20); // Drop empty/filler steps

    const response: PlaybookResponse = {
      incident_type: incidentType,
      playbook: {
        id: pb.id ?? incidentType,
        title: pb.title,
        category: pb.category ?? incidentType,
        severity: (['critical', 'high', 'medium', 'low'].includes(pb.severity ?? '') ? pb.severity : 'high') as
          'critical' | 'high' | 'medium' | 'low',
        description: pb.description ?? '',
        steps: validatedSteps,
        tools_used: pb.tools_used ?? [],
        estimated_total_time: pb.estimated_total_time ?? '1-2 hours',
      },
      related_playbooks: (parsed.related_playbooks ?? [])
        .filter((r) => r.id && r.title)
        .slice(0, 3)
        .map((r) => ({ id: r.id!, title: r.title!, category: r.category ?? '' })),
      _validation: {
        step_count: validatedSteps.length,
      },
    };

    return c.json(response, 200, { 'cache-control': 'public, max-age=3600' });
  } catch (err) {
    logError('ir-playbook', err);
    return serviceUnavailable(c, 'Failed to generate playbook');
  }
}
