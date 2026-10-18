/**
 * Detection Opportunities extraction — generates SIEM detection rules,
 * monitoring guidance, and CLI verification commands from threat reports.
 *
 * Uses LLM to produce structured detection content that analysts can
 * immediately use for threat hunting and monitoring.
 * Retries once with a simplified prompt if the first attempt fails.
 */

import type { Env } from '../env';
import { runCompletion } from '../case-study/generation/ai-client';
import { extractJson } from './llm-json';

export interface DetectionRule {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  mitreId?: string;
  query?: string;
  platform?: string;
}

export interface MonitoringGuidance {
  category: string;
  items: string[];
}

export interface CliCommand {
  purpose: string;
  command: string;
  platform?: string;
}

export interface DetectionOpportunities {
  siemRules: DetectionRule[];
  monitoringGuidance: MonitoringGuidance[];
  cliCommands: CliCommand[];
  detectionLimitations: string[];
  model?: string;
}

const EMPTY: DetectionOpportunities = {
  siemRules: [],
  monitoringGuidance: [],
  cliCommands: [],
  detectionLimitations: [],
};

const SYSTEM = `You are a threat detection engineer. Given a threat report, extract detection opportunities that analysts can immediately implement.

Return JSON with this exact structure:
{
  "siemRules": [
    {
      "title": "rule name",
      "description": "what this rule detects",
      "severity": "critical|high|medium|low",
      "mitreId": "optional T-code",
      "query": "optional KQL/Sigma query",
      "platform": "optional: windows|linux|network|cloud"
    }
  ],
  "monitoringGuidance": [
    {
      "category": "category name",
      "items": ["specific monitoring action 1", "action 2"]
    }
  ],
  "cliCommands": [
    {
      "purpose": "what this command checks",
      "command": "the actual CLI/PowerShell command",
      "platform": "optional: windows|linux|fortinet|cisco"
    }
  ],
  "detectionLimitations": [
    "limitation 1: description"
  ]
}

Generate 3-8 SIEM rules, 3-5 monitoring categories, 3-6 CLI commands, and 2-4 limitations.
Rules:
- Every SIEM rule needs a concrete log source in the description (e.g. Sysmon Event ID 1, Zeek conn.log, M365 audit) and a query in Sigma or KQL dialect — mark which in the platform field. No generic "monitor for suspicious activity" rules.
- CLI commands must be copy-paste runnable with the correct platform tag (windows/linux/macos/network/cloud).
- Limitations must name what the detection CANNOT see (blind spots), not restate the rules.
Output JSON only. No prose, no markdown fences.`;

const RETRY_SYSTEM = `Return a JSON object with keys: siemRules (array of objects with title/description/severity), monitoringGuidance (array of objects with category/items), cliCommands (array of objects with purpose/command), detectionLimitations (array of strings).`;

const TIMEOUT_MS = 25_000;
const MAX_INPUT_CHARS = 6000;

export async function extractDetectionOpportunities(
  text: string,
  ttps: { id: string; name: string; tactic: string }[],
  env: Env
): Promise<DetectionOpportunities> {
  const ttpContext =
    ttps.length > 0
      ? `\n\nIdentified MITRE ATT&CK techniques:\n${ttps.map((t) => `- ${t.id}: ${t.name} (${t.tactic})`).join('\n')}`
      : '';
  const input = text.length > MAX_INPUT_CHARS ? text.slice(0, MAX_INPUT_CHARS) + '\n…[truncated]' : text;

  const result = await tryExtract(SYSTEM, `${input}${ttpContext}`, env);
  if (result && (result.siemRules.length > 0 || result.cliCommands.length > 0)) return result;

  const retry = await tryExtract(RETRY_SYSTEM, `${input}${ttpContext}`, env);
  return retry ?? result ?? EMPTY;
}

async function tryExtract(system: string, input: string, env: Env): Promise<DetectionOpportunities | null> {
  try {
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('detection timeout')), TIMEOUT_MS)
    );
    const r = await Promise.race([
      runCompletion(
        env.AI,
        {
          system,
          user: `Extract detection opportunities from this threat report.\n\nReport text:\n${input}`,
          maxTokens: 3000,
          temperature: 0.3,
        },
        {
          googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: env.GROQ_API_KEY,
          nvidiaKey: env.NVIDIA_API_KEY as string | undefined,
          preferGroq: false,
        }
      ),
      timeout,
    ]);
    const raw = typeof r.text === 'string' ? r.text : '';
    const parsed = extractJson<Record<string, unknown>>(raw);
    if (!parsed) return null;
    return {
      siemRules: Array.isArray(parsed.siemRules) ? (parsed.siemRules as DetectionRule[]).slice(0, 8) : [],
      monitoringGuidance: Array.isArray(parsed.monitoringGuidance)
        ? (parsed.monitoringGuidance as MonitoringGuidance[]).slice(0, 5)
        : [],
      cliCommands: Array.isArray(parsed.cliCommands) ? (parsed.cliCommands as CliCommand[]).slice(0, 6) : [],
      detectionLimitations: Array.isArray(parsed.detectionLimitations)
        ? (parsed.detectionLimitations as string[]).slice(0, 4)
        : [],
      model: r.modelUsed,
    };
  } catch {
    return null;
  }
}
