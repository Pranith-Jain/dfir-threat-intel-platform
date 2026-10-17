/**
 * Agent self-evaluation — 5-axis quality scorecard for the final report.
 *
 * Runs AFTER the QA verifier (which fact-checks). Self-eval rates the
 * report on 5 axes (accuracy, completeness, clarity, actionability,
 * conciseness) with concrete evidence per criterion. The scorecard is
 * attached to the agent state so the UI can surface it.
 *
 * Inspired by the agent-self-evaluation skill: a model must not grade
 * its own output without evidence — each axis requires a specific
 * citation from the report or the collected data.
 */
import type { Ai } from '@cloudflare/workers-types';
import { runCompletion, type CompletionInput, isRateLimited } from '../../case-study/generation/ai-client';
import type { AgentStep } from './types';
import { extractJsonObject } from './schemas';
import { neutralizeUntrusted } from '../prompt-fence';

export interface SelfEvalAxis {
  axis: 'accuracy' | 'completeness' | 'clarity' | 'actionability' | 'conciseness';
  score: number; // 1-5
  evidence: string; // concrete citation from the report or data
  improvement: string; // specific suggestion for next time
}

export interface SelfEvalResult {
  axes: SelfEvalAxis[];
  overallScore: number; // average of 5 axes, 1-5
  topGap: string; // the single highest-impact improvement
  modelUsed: string;
}

const SELF_EVAL_SYSTEM_PROMPT = `You are a senior intelligence analyst reviewing a CTI report for quality. Rate the report on 5 axes, each 1-5, with concrete evidence.

Axes:
1. accuracy — Are claims supported by the collected data? Are sources cited?
2. completeness — Does it cover the query fully? Are there obvious gaps?
3. clarity — Is it well-structured, readable, and unambiguous?
4. actionability — Can a defender act on this? Are there concrete recommendations?
5. conciseness — Is it free of padding, repetition, and irrelevant detail?

Rules:
- Each axis MUST cite a specific passage from the report or a specific data point as evidence.
- Each axis MUST include one concrete improvement suggestion.
- Be honest — do not inflate scores. A 3 means "adequate", a 5 means "exemplary".
- The topGap is the single highest-impact improvement across all axes.

Respond as JSON:
{
  "axes": [
    { "axis": "accuracy", "score": 4, "evidence": "...", "improvement": "..." },
    { "axis": "completeness", "score": 3, "evidence": "...", "improvement": "..." },
    { "axis": "clarity", "score": 4, "evidence": "...", "improvement": "..." },
    { "axis": "actionability", "score": 3, "evidence": "...", "improvement": "..." },
    { "axis": "conciseness", "score": 4, "evidence": "...", "improvement": "..." }
  ],
  "topGap": "..."
}`;

/**
 * Run a 5-axis self-evaluation on the final report.
 *
 * If all LLM providers are exhausted, returns a null result gracefully
 * (the report is still delivered without a scorecard — self-eval is
 * additive, never blocking).
 */
export async function selfEvaluateReport(
  ai: Ai,
  query: string,
  queryType: string,
  report: string,
  steps: AgentStep[],
  opts: {
    groqKey?: string;
    nvidiaKey?: string;
    googleKey?: string;
    recordUsage?: (model: string, inputText: string, outputText: string, role: string) => void;
  }
): Promise<SelfEvalResult | null> {
  // Build a compact summary of collected data for the evaluator to cross-check
  const toolCount = steps.reduce((n, s) => n + s.results.filter((r) => r.status === 'ok').length, 0);
  const toolsUsed = [...new Set(steps.flatMap((s) => s.toolCalls.map((tc) => tc.tool)))];
  const dataSummary = `Investigation collected ${toolCount} tool results across ${toolsUsed.length} distinct tools: ${toolsUsed.join(', ')}.`;

  const userPrompt = `Query: ${query}
Query type: ${queryType}

${dataSummary}

Report to evaluate:
---
${neutralizeUntrusted(report.slice(0, 8000))}
---

Rate this report on the 5 axes. Respond as JSON.`;

  const providers: Array<{ name: string; build: () => CompletionInput }> = [];

  if (opts.googleKey) {
    providers.push({
      name: 'gemini',
      build: () => ({
        provider: 'google',
        model: 'gemini-3.8-flash',
        system: SELF_EVAL_SYSTEM_PROMPT,
        user: userPrompt,
        temperature: 0.3,
        maxTokens: 1200,
        apiKey: opts.googleKey!,
      }),
    });
  }
  if (opts.groqKey) {
    providers.push({
      name: 'groq',
      build: () => ({
        provider: 'groq',
        model: 'openai/gpt-oss-120b',
        system: SELF_EVAL_SYSTEM_PROMPT,
        user: userPrompt,
        temperature: 0.3,
        maxTokens: 1200,
        apiKey: opts.groqKey!,
      }),
    });
  }
  if (opts.nvidiaKey) {
    providers.push({
      name: 'nvidia',
      build: () => ({
        provider: 'nvidia',
        model: 'meta/llama-3.1-70b-instruct',
        system: SELF_EVAL_SYSTEM_PROMPT,
        user: userPrompt,
        temperature: 0.3,
        maxTokens: 1200,
        apiKey: opts.nvidiaKey!,
      }),
    });
  }

  for (const p of providers) {
    try {
      const result = await runCompletion(ai, p.build());
      if (result.text) {
        opts.recordUsage?.(p.name, userPrompt, result.text, 'self-eval');
        try {
          const jsonStr = extractJsonObject(result.text);
          const parsed = JSON.parse(jsonStr) as { axes: Array<Record<string, unknown>>; topGap?: string };
          if (parsed && Array.isArray(parsed.axes) && parsed.axes.length === 5) {
            const axes: SelfEvalAxis[] = parsed.axes.map((a) => ({
              axis: a.axis as SelfEvalAxis['axis'],
              score: Math.max(1, Math.min(5, Number(a.score) || 3)),
              evidence: String(a.evidence ?? ''),
              improvement: String(a.improvement ?? ''),
            }));
            const overallScore = Math.round((axes.reduce((n, a) => n + a.score, 0) / axes.length) * 10) / 10;
            return {
              axes,
              overallScore,
              topGap: String(parsed.topGap ?? axes[0]?.improvement ?? ''),
              modelUsed: p.name,
            };
          }
        } catch {
          // JSON parse failed — try next provider
          continue;
        }
      }
      if (isRateLimited(result)) continue;
    } catch {
      continue;
    }
  }

  return null;
}
