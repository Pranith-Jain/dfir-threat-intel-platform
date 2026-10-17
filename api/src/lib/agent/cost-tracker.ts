/**
 * Cost tracking — per-investigation token usage and cost estimation.
 * Tracks LLM calls, tool executions, and total investigation cost.
 */

export interface CostEntry {
  /** Provider + model used. */
  model: string;
  /** Estimated input tokens. */
  inputTokens: number;
  /** Estimated output tokens. */
  outputTokens: number;
  /** Estimated cost in USD. */
  costUsd: number;
  /** What this call was for (planner, synthesizer, qa, observer). */
  role: string;
  /** Timestamp. */
  ts: number;
}

export interface InvestigationCost {
  entries: CostEntry[];
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCostUsd: number;
  /** Breakdown by role. */
  byRole: Record<string, { tokens: number; cost: number }>;
}

/** Cost per 1K tokens (approximate, as of 2026-09). */
const COST_PER_1K: Record<string, number> = {
  'groq:openai/gpt-oss-120b': 0.0006,
  'groq:openai/gpt-oss-20b': 0.0003,
  'groq:llama-3.3-70b-versatile': 0.00059,
  'groq:llama-3.1-8b-instant': 0.00005,
  'gemini:gemini-3.8-flash': 0.0001,
  'gemini:gemini-3.7-flash': 0.0001,
  'gemini:gemini-3.6-flash': 0.0001,
  'gemini:gemini-3.5-flash': 0.0001,
  'gemini:gemini-3.5-flash-lite': 0.0001,
  'gemini:gemini-2.5-flash': 0.0001,
  'nvidia:meta/llama-3.3-70b-instruct': 0.0006,
  'nvidia:meta/llama-3.1-70b-instruct': 0.0006,
  'nvidia:minimaxai/minimax-m2.7': 0.00045,
  'nvidia:z-ai/glm-5.2': 0.0004,
  'workers-ai:llama-3.3-70b-instruct-fp8-fast': 0.0001,
  'workers-ai:llama-3.1-8b-instruct-fp8': 0.00002,
  'workers-ai:qwen3-30b-a3b-fp8': 0.00005,
  'workers-ai:gpt-oss-120b': 0.00015,
  'workers-ai:llama-3.1-8b-instant': 0.00005,
};

/** Max budget per investigation (USD). Hard limit to prevent runaway costs. */
export const MAX_INVESTIGATION_COST_USD = 0.5;

/**
 * Estimate cost for a completion call based on the model and token counts.
 */
export function estimateCost(model: string, inputTokens: number, outputTokens: number): number {
  const rate = COST_PER_1K[model] ?? 0.001; // default to $1/1K if unknown
  return ((inputTokens + outputTokens) / 1000) * rate;
}

/**
 * Rough token estimate from text length (4 chars ≈ 1 token).
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Create a new cost tracker for an investigation.
 */
export function createCostTracker(): InvestigationCost {
  return {
    entries: [],
    totalInputTokens: 0,
    totalOutputTokens: 0,
    totalCostUsd: 0,
    byRole: {},
  };
}

/**
 * Record a completion call in the cost tracker.
 */
export function recordCompletion(
  cost: InvestigationCost,
  model: string,
  inputText: string,
  outputText: string,
  role: string
): void {
  const inputTokens = estimateTokens(inputText);
  const outputTokens = estimateTokens(outputText);
  const costUsd = estimateCost(model, inputTokens, outputTokens);

  cost.entries.push({
    model,
    inputTokens,
    outputTokens,
    costUsd,
    role,
    ts: Date.now(),
  });

  cost.totalInputTokens += inputTokens;
  cost.totalOutputTokens += outputTokens;
  cost.totalCostUsd += costUsd;

  if (!cost.byRole[role]) cost.byRole[role] = { tokens: 0, cost: 0 };
  cost.byRole[role].tokens += inputTokens + outputTokens;
  cost.byRole[role].cost += costUsd;
}

/**
 * Check if the investigation has exceeded its budget.
 */
export function isOverBudget(cost: InvestigationCost): boolean {
  return cost.totalCostUsd >= MAX_INVESTIGATION_COST_USD;
}

/**
 * Get a summary string for display.
 */
export function costSummary(cost: InvestigationCost): string {
  const tokenK = ((cost.totalInputTokens + cost.totalOutputTokens) / 1000).toFixed(1);
  return `${tokenK}K tokens · $${cost.totalCostUsd.toFixed(4)} · ${cost.entries.length} LLM calls`;
}
