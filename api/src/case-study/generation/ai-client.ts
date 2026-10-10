import { logError } from '../../lib/logger';
/**
 * LLM client — multi-provider with fallback chain: Gemini → Groq → NVIDIA →
 * Workers AI.
 *
 * Gemini (3.8 → 3.7 → 3.6-flash free tiers, 1M ctx) is the PRIMARY for agent/
 * analyst work. Groq (gpt-oss-120b, streaming) is next — and stays primary for
 * the synthesizer via preferGroq. NVIDIA after that; Workers AI (first-party,
 * no external quota) is the last line of defence.
 *
 * NOTE: Infron (llm.onerouter.pro :free endpoints) was removed from the chain
 * (2026-09) — unreliable free endpoints, retired in favour of the
 * Gemini/Groq/NVIDIA free tiers + Workers AI.
 */

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL: string = 'openai/gpt-oss-120b';
/**
 * Model ladder. `llama-3.1-8b-instant` and `llama-3.3-70b-versatile` were
 * moved to paid Enterprise-only tiers by Groq on 2026-08-24; on a free-tier
 * key they answer `404 model_not_found`. They used to be GROQ_MODEL_FALLBACK
 * and GROQ_MODEL_TINY here, so every LLM call burned two doomed requests
 * (each up to the full 15s timeout) before reaching a working model — which
 * is what pushed the daily briefing build past the free-plan 50-subrequest
 * cap and left it unpersisted. Both slots now use live, cheap models.
 */
export const GROQ_MODEL_FALLBACK: string = 'meta-llama/llama-4-scout-17b-16e-instruct';
const GROQ_MODEL_FAST: string = 'openai/gpt-oss-20b';
const GROQ_MODEL_TINY: string = 'qwen/qwen3-32b';
const GROQ_TIMEOUT_MS = 15_000;

const GOOGLE_GEMINI_URL = 'https://generativelanguage.googleapis.com/v1beta/models';
// Free-tier chain (Sep 2026): 3.8-flash (newest, most intelligent Flash) →
// 3.7-flash (high-speed daily driver) → 3.6-flash → 3.5-flash-lite (cheapest,
// highest RPM) → 2.5-flash (legacy, most stable quota). Pro models are
// paid-only since Apr 2026 — never list them here.
const GEMINI_MODELS = [
  'gemini-3.8-flash',
  'gemini-3.7-flash',
  'gemini-3.6-flash',
  'gemini-3.5-flash-lite',
  'gemini-2.5-flash',
];
const GEMINI_TIMEOUT_MS = 20_000;

const NVIDIA_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';
const NVIDIA_MODEL = 'meta/llama-3.3-70b-instruct';
const NVIDIA_TIMEOUT_MS = 20_000;

// Provider health tracking — imported dynamically to avoid circular deps
let _providerHealth: typeof import('../../lib/agent/provider-health') | null = null;
async function getProviderHealth() {
  if (!_providerHealth) {
    try {
      _providerHealth = await import('../../lib/agent/provider-health');
    } catch {
      /* optional */
    }
  }
  return _providerHealth;
}

export interface CompletionInput {
  system: string;
  user: string;
  maxTokens?: number;
  temperature?: number;
}

export interface CompletionOutput {
  text: string;
  modelUsed: string;
  /** Provider that produced this output (e.g. "google", "groq"). Optional —
   *  set by some callers for logging, not by the core runCompletion path. */
  provider?: string;
  /** Model name (alias for modelUsed in tests). */
  model?: string;
}

export interface CompletionOpts {
  /**
   * @deprecated Infron was removed from the provider chain (2026-09).
   * Accepted but ignored — kept so existing callers still compile.
   */
  infronKey?: string;
  groqKey?: string;
  nvidiaKey?: string;
  googleKey?: string;
  quality?: boolean;
  role?: string;
  preferGroq?: boolean;
  /** Skip directly to a specific provider (e.g. 'gemini' for large-context QA). */
  preferProvider?: 'groq' | 'gemini' | 'nvidia';
  /** With preferProvider: use ONLY that provider, no fall-through. Used by the
   *  ensemble QA so each parallel call makes exactly one provider fetch instead
   *  of walking the whole chain (keeps subrequests bounded on the free plan). */
  exclusiveProvider?: boolean;
  /** Skip this provider entirely (e.g. QA must not grade the model that generated the report). */
  excludeProvider?: 'groq' | 'gemini' | 'nvidia';
  /** Invoked on success with the model + prompt/response text for cost tracking. */
  recordUsage?: (model: string, inputText: string, outputText: string, role: string) => void;
}

export class RateLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RateLimitError';
  }
}

export function isRateLimited(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (msg.includes('context window') || msg.includes('5021') || (msg.includes('token') && msg.includes('exceeded'))) {
    return false;
  }
  return (
    msg.includes('rate') ||
    msg.includes('429') ||
    msg.includes('too many') ||
    msg.includes('limit') ||
    msg.includes('exceeded') ||
    msg.includes('quota') ||
    msg.includes('capacity')
  );
}

export function isAuthError(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('401') ||
    msg.includes('403') ||
    msg.includes('unauthorized') ||
    msg.includes('forbidden') ||
    msg.includes('invalid api key') ||
    msg.includes('invalid key') ||
    msg.includes('api key invalid') ||
    msg.includes('authentication failed') ||
    msg.includes('not authorized') ||
    msg.includes('permission denied')
  );
}

/**
 * A 413 / "request too large" means THIS prompt exceeds the model's input
 * window — it is NOT a provider-health signal. Distinguished so the circuit
 * breaker isn't tripped by one oversized prompt (which would wrongly skip the
 * provider for every subsequent, possibly smaller, request).
 */
export function isRequestTooLarge(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return msg.includes('413') || msg.includes('too large') || msg.includes('request too large');
}

/**
 * True when the invocation has hit the Workers free-plan 50-subrequest cap
 * ("Too many subrequests by single Worker invocation"). Once exhausted, EVERY
 * further fetch/KV/`ai.run` in this invocation fails the same way — so the
 * fallback chain must stop immediately instead of burning the remaining
 * provider models (each of which is guaranteed to fail). Relevant in the
 * CronJobDO alarm, where the hourly pipeline shares one invocation budget
 * with the briefing-heal LLM call.
 */
export function isSubrequestExhausted(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return msg.includes('subrequest') || msg.includes('sub-request') || msg.includes('sub request');
}

// ── Workers AI fallback ─────────────────────────────────────────────────
// Always available on the Worker (no external API key, no shared quota) and
// large-context, so it neither 413s on a big prompt nor trips the same rate
// limits as the external providers. The last line of defence when Groq,
// Gemini, and NVIDIA are all rate-limited / circuit-broken / oversized /
// timed out. Model order mirrors the proven chain in routes/agent.ts.
const WORKERS_AI_MODELS = [
  '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
  '@cf/qwen/qwen3-30b-a3b-fp8',
  '@cf/openai/gpt-oss-120b',
  '@cf/meta/llama-3.1-8b-instruct',
];

interface WorkersAiBinding {
  run: (model: string, input: Record<string, unknown>) => Promise<unknown>;
}

export function isWorkersAi(ai: unknown): ai is WorkersAiBinding {
  return !!ai && typeof ai === 'object' && typeof (ai as { run?: unknown }).run === 'function';
}

export async function runWorkersAI(
  ai: WorkersAiBinding,
  input: CompletionInput
): Promise<{ text: string; model: string }> {
  let lastErr = 'no model attempted';
  for (const model of WORKERS_AI_MODELS) {
    try {
      const res = (await ai.run(model, {
        messages: [
          { role: 'system', content: input.system },
          { role: 'user', content: input.user },
        ],
        max_tokens: input.maxTokens ?? 4000,
        temperature: input.temperature ?? 0.5,
      })) as { response?: string; choices?: Array<{ message?: { content?: string } }> };
      const text =
        (typeof res?.response === 'string' ? res.response : undefined) ?? res?.choices?.[0]?.message?.content;
      if (typeof text === 'string' && text.trim()) return { text, model };
      lastErr = `${model}: empty response`;
    } catch (err) {
      lastErr = `${model}: ${err instanceof Error ? err.message : String(err)}`;
      logError('runWorkersAI failed', new Error(lastErr.slice(0, 200)));
      // Invocation subrequest budget is spent — remaining models would all
      // fail identically, so do not burn them (free-plan 50-subrequest cap
      // is shared with the whole cron alarm). Re-throw to fail fast.
      if (isSubrequestExhausted(err)) throw err;
    }
  }
  throw new Error(`workers-ai exhausted: ${lastErr}`);
}

async function runGroq(key: string, input: CompletionInput, model?: string): Promise<string> {
  let res: Response;
  try {
    const m = model ?? GROQ_MODEL;
    const isReasoning = m === GROQ_MODEL || m === GROQ_MODEL_FAST;
    const body: Record<string, unknown> = {
      model: m,
      messages: [
        { role: 'system', content: input.system },
        { role: 'user', content: input.user },
      ],
      ...(isReasoning
        ? {
            // A reasoning pass spends from the same budget as the answer, so a
            // small maxTokens (the briefing summary asks for 400) can be fully
            // consumed before any content is emitted. Floor the reasoning
            // budget so short prompts still return text.
            max_completion_tokens: Math.max(input.maxTokens ?? 4000, 2048),
            reasoning_effort: 'medium',
          }
        : { max_tokens: input.maxTokens ?? 4000 }),
      temperature: input.temperature ?? 0.5,
    };
    res = await fetch(GROQ_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(GROQ_TIMEOUT_MS),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logError('runGroq request failed', new Error(msg));
    throw new Error(`groq request failed: ${msg}`);
  }
  if (res.status === 429) {
    logError('runGroq rate limited', new Error('429'));
    throw new RateLimitError('groq rate limited (429)');
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    const msg = `groq HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ''}`;
    logError('runGroq failed', new Error(msg));
    throw new Error(msg);
  }
  const j = (await res.json()) as {
    choices?: Array<{ message?: { content?: string | null; reasoning_content?: string | null } }>;
  };
  const msg = j?.choices?.[0]?.message;
  // Reasoning models (gpt-oss-*) put their thinking in `reasoning_content`
  // and leave `content` empty when the completion budget is consumed by the
  // reasoning pass. Accept either, so a short maxTokens doesn't read as a
  // provider failure and push us onto the next model for nothing.
  const text = msg?.content?.trim() || msg?.reasoning_content?.trim() || '';
  if (!text) throw new Error('groq empty response');
  return text;
}

async function runGemini(key: string, input: CompletionInput): Promise<{ text: string; model: string }> {
  let lastError: Error | null = null;
  for (const model of GEMINI_MODELS) {
    const url = `${GOOGLE_GEMINI_URL}/${model}:generateContent?key=${key}`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: `${input.system}\n\n${input.user}` }] }],
          generationConfig: {
            maxOutputTokens: input.maxTokens ?? 4000,
            temperature: input.temperature ?? 0.5,
          },
        }),
        signal: AbortSignal.timeout(GEMINI_TIMEOUT_MS),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        const msg = `gemini HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ''}`;
        if (res.status === 401 || res.status === 403) throw new Error(msg);
        lastError = new Error(msg);
        continue;
      }
      const j = (await res.json()) as { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }> };
      const text = j?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (typeof text !== 'string' || !text.trim()) throw new Error('gemini empty response');
      return { text, model };
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }
  const msg = (lastError?.message ?? 'all models failed').slice(0, 200);
  logError('runGemini failed', new Error(msg));
  throw new Error(`gemini failed: ${msg}`);
}

async function runNvidia(key: string, input: CompletionInput): Promise<string> {
  try {
    const res = await fetch(NVIDIA_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: NVIDIA_MODEL,
        messages: [
          { role: 'system', content: input.system },
          { role: 'user', content: input.user },
        ],
        max_tokens: input.maxTokens ?? 4000,
        temperature: input.temperature ?? 0.5,
      }),
      signal: AbortSignal.timeout(NVIDIA_TIMEOUT_MS),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`nvidia HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ''}`);
    }
    const j = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const text = j?.choices?.[0]?.message?.content;
    if (typeof text !== 'string' || !text.trim()) throw new Error('nvidia empty response');
    return text;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logError('runNvidia failed', new Error(msg.slice(0, 200)));
    throw new Error(`nvidia failed: ${msg}`);
  }
}

export async function runCompletion(
  _ai: unknown,
  input: CompletionInput,
  opts: CompletionOpts = {}
): Promise<CompletionOutput> {
  const errors: string[] = [];
  const groqKey = opts.groqKey;
  const health = await getProviderHealth();
  const inputText = `${input.system}\n${input.user}`;
  const usageRole = opts.role ?? 'completion';

  // Build provider order. Gemini is the PRIMARY LLM for the agent/analyst paths
  // (free tiers, 1M ctx). Groq gpt-oss-120b is next, NVIDIA after, Workers AI
  // last (first-party, no external quota).
  // `preferGroq` keeps the synthesizer + feed summaries on Groq for streaming
  // output; the case-study generator is the only main-streaming caller.
  const fallbackOrder = ['gemini', 'groq', 'nvidia'] as const;
  const providers: Array<(typeof fallbackOrder)[number]> = opts.preferProvider
    ? opts.exclusiveProvider
      ? [opts.preferProvider]
      : [opts.preferProvider, ...fallbackOrder.filter((p) => p !== opts.preferProvider)]
    : opts.preferGroq
      ? ['groq', 'gemini', 'nvidia']
      : ['gemini', 'groq', 'nvidia'];

  // Judge-independence guard: never let QA grade the model that generated the
  // report being verified. excludeProvider drops that provider from the chain
  // entirely so a different model runs the verification pass.
  const filteredProviders = opts.excludeProvider ? providers.filter((p) => p !== opts.excludeProvider) : providers;
  const providersToTry = filteredProviders.length > 0 ? filteredProviders : providers;

  for (const provider of providersToTry) {
    // Skip providers that are rate-limited or circuit-broken
    if (health && !(await health.isProviderHealthy(provider))) {
      errors.push(`${provider}: skipped (rate-limited or circuit-broken)`);
      continue;
    }

    if (provider === 'groq' && groqKey) {
      // gpt-oss-120b (quality) → 70b-versatile → 20b (fast) → 8b-instant
      // (volume: 500k TPD free). Provider-level failure is recorded ONCE per
      // invocation (after all models fail) — per-model recording inflated
      // consecutiveFailures 3-4x and wrongly opened the circuit breaker.
      const groqModels = [GROQ_MODEL, GROQ_MODEL_FALLBACK, GROQ_MODEL_FAST, GROQ_MODEL_TINY];
      let groqSucceeded = false;
      let groqAnyNonRateLimit = false;
      for (const model of groqModels) {
        const startMs = Date.now();
        try {
          const text = await runGroq(groqKey, input, model);
          groqSucceeded = true;
          if (health) await health.recordSuccess('groq', Date.now() - startMs);
          opts.recordUsage?.(`groq:${model}`, inputText, text, usageRole);
          return { text, modelUsed: `groq:${model}` };
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err);
          logError('runCompletion groq failed', new Error(`${model}: ${errMsg.slice(0, 200)}`));
          errors.push(`groq:${model}: ${errMsg.slice(0, 80)}`);
          // A 413 means THIS prompt is too big for Groq's models — the remaining
          // Groq models will also 413 on the same input, and it isn't a provider-
          // health signal, so bail without tripping the circuit breaker (which
          // would wrongly skip Groq for later, smaller requests). Fall through to
          // gemini/nvidia/workers-ai, which have larger input windows.
          if (isSubrequestExhausted(err)) throw err;
          if (isRequestTooLarge(err)) break;
          if (isAuthError(err)) break;
          if (!isRateLimited(err)) groqAnyNonRateLimit = true;
        }
      }
      if (!groqSucceeded && health) await health.recordFailure('groq', !groqAnyNonRateLimit);
    } else if (provider === 'gemini' && opts.googleKey) {
      const startMs = Date.now();
      try {
        const { text, model } = await runGemini(opts.googleKey, input);
        if (health) await health.recordSuccess('gemini', Date.now() - startMs);
        opts.recordUsage?.(`gemini:${model}`, inputText, text, usageRole);
        return { text, modelUsed: `gemini:${model}` };
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        logError('runCompletion gemini failed', new Error(errMsg.slice(0, 200)));
        errors.push(`gemini: ${errMsg.slice(0, 80)}`);
        if (isSubrequestExhausted(err)) throw err;
        if (health) await health.recordFailure('gemini', isRateLimited(err));
      }
    } else if (provider === 'nvidia' && opts.nvidiaKey) {
      const startMs = Date.now();
      try {
        const text = await runNvidia(opts.nvidiaKey, input);
        if (health) await health.recordSuccess('nvidia', Date.now() - startMs);
        opts.recordUsage?.(`nvidia:${NVIDIA_MODEL}`, inputText, text, usageRole);
        return { text, modelUsed: `nvidia:${NVIDIA_MODEL}` };
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        logError('runCompletion nvidia failed', new Error(errMsg.slice(0, 200)));
        errors.push(`nvidia: ${errMsg.slice(0, 80)}`);
        if (isSubrequestExhausted(err)) throw err;
        if (health) await health.recordFailure('nvidia', isRateLimited(err));
      }
    }
  }

  // Final fallback: Workers AI — always available on the Worker, large-context
  // (won't 413 on a big LinkedIn prompt), and not subject to the external
  // providers' rate limits. This is what closes the
  // "All LLM providers exhausted" failure when Groq/Gemini/NVIDIA are all
  // rate-limited, circuit-broken, oversized, or timed out.
  if (isWorkersAi(_ai)) {
    try {
      const { text, model } = await runWorkersAI(_ai, input);
      opts.recordUsage?.(`workers-ai:${model.split('/').pop()}`, inputText, text, usageRole);
      return { text, modelUsed: `workers-ai:${model.split('/').pop()}` };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      errors.push(`workers-ai: ${errMsg.slice(0, 80)}`);
      // Budget is spent — rethrow so the caller knows it's not a transient
      // provider issue (a retry inside the same invocation would also fail).
      if (isSubrequestExhausted(err)) throw err;
    }
  }

  throw new Error(`All LLM providers exhausted. Errors:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
}

// ── Streaming ────────────────────────────────────────────────────────────

/** Timeout for a streamed completion (longer than one-shot — tokens arrive over time). */
const STREAM_TIMEOUT_MS = 120_000;

/**
 * Parse a single Groq/OpenAI SSE line into its delta text. Returns null for
 * non-data lines, the terminal `[DONE]`, lines without a content delta, or
 * malformed JSON. Pure and unit-tested.
 */
export function parseSseDelta(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('data:')) return null;
  const payload = trimmed.slice(5).trim();
  if (!payload || payload === '[DONE]') return null;
  try {
    const j = JSON.parse(payload) as { choices?: Array<{ delta?: { content?: string } }> };
    const content = j?.choices?.[0]?.delta?.content;
    return typeof content === 'string' && content.length > 0 ? content : null;
  } catch {
    return null;
  }
}

/**
 * Stream a Groq completion, invoking `onToken` for each content delta.
 * Returns the full accumulated text. Throws on any failure so the caller can
 * fall back to the whole-text chain.
 */
async function runGroqStream(key: string, input: CompletionInput, onToken: (token: string) => void): Promise<string> {
  const body: Record<string, unknown> = {
    model: GROQ_MODEL,
    stream: true,
    messages: [
      { role: 'system', content: input.system },
      { role: 'user', content: input.user },
    ],
    max_completion_tokens: input.maxTokens ?? 4000,
    temperature: input.temperature ?? 0.5,
  };
  const res = await fetch(GROQ_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(STREAM_TIMEOUT_MS),
  });
  if (res.status === 429) throw new RateLimitError('groq rate limited (429)');
  if (!res.ok || !res.body) throw new Error(`groq stream HTTP ${res.status}`);

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let full = '';
  let buffer = '';
  // Hard cap: an unbounded `full += delta` lets a runaway stream OOM the
  // isolate. Fail loudly past the cap instead of truncating silently —
  // callers already surface thrown errors as unavailable.
  const MAX_STREAM_CHARS = 500_000;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) {
      const delta = parseSseDelta(line);
      if (delta) {
        full += delta;
        if (full.length > MAX_STREAM_CHARS) {
          try {
            await reader.cancel();
          } catch {
            /* already closed */
          }
          throw new Error(`groq stream exceeded ${MAX_STREAM_CHARS} chars`);
        }
        onToken(delta);
      }
    }
  }
  if (!full.trim()) throw new Error('groq empty stream');
  return full;
}

/**
 * Streaming completion. Tries Groq SSE first (invoking `onToken` per delta);
 * on any failure falls back to the whole-text `runCompletion` chain, emitting
 * the result as a single chunk. Always resolves to the full text + model.
 *
 * Gemini is the whole-text chain's primary but is non-streaming here, so the
 * streamed case lands on Groq (gpt-oss-120b).
 */
export async function runCompletionStream(
  ai: unknown,
  input: CompletionInput,
  opts: CompletionOpts,
  onToken: (token: string) => void
): Promise<CompletionOutput> {
  const health = await getProviderHealth();
  if (opts.groqKey && (!health || (await health.isProviderHealthy('groq')))) {
    const startMs = Date.now();
    try {
      const text = await runGroqStream(opts.groqKey, input, onToken);
      if (health) await health.recordSuccess('groq', Date.now() - startMs);
      opts.recordUsage?.(`groq:${GROQ_MODEL}`, `${input.system}\n${input.user}`, text, opts.role ?? 'completion');
      return { text, modelUsed: `groq:${GROQ_MODEL}` };
    } catch (err) {
      logError('runCompletionStream groq failed', err instanceof Error ? err : new Error(String(err).slice(0, 120)));
      if (health) await health.recordFailure('groq', isRateLimited(err));
      // fall through to the whole-text chain
    }
  }
  const out = await runCompletion(ai, input, opts);
  onToken(out.text);
  return out;
}
