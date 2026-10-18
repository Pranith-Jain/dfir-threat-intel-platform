/**
 * LLM provider health tracking — monitors rate limits, response times, and
 * success rates to route requests intelligently.
 *
 * Stored in a module-level (per-isolate) map, NOT the Cache-API. A Workers
 * isolate keeps module state across invocations in the same colo, so the
 * circuit breaker still works across requests — but with ZERO subrequests.
 *
 * Why this matters: the Cache-API counts against the free-plan limit of 50
 * subrequests per Worker invocation. The old Cache-API-backed implementation
 * did ~3 subrequests per LLM call (isProviderHealthy match + recordSuccess/
 * recordFailure match+put). Across a synthesis + ensemble-QA invocation that
 * churn exhausted the budget and every QA provider call failed with "Too many
 * subrequests by single Worker invocation". In-memory tracking removes that
 * cost entirely while preserving cross-request circuit-breaking.
 */

export type Provider = 'groq' | 'gemini' | 'nvidia';

interface ProviderHealth {
  /** Timestamp of last rate-limit error (ms since epoch). 0 = not rate-limited. */
  lastRateLimit: number;
  /** Consecutive failures (reset on success). */
  consecutiveFailures: number;
  /** Timestamp of the most recent failure (ms since epoch). 0 = none yet. */
  lastFailure: number;
  /** Total successes (for success rate). */
  successes: number;
  /** Total failures (for success rate). */
  failures: number;
  /** Average response time (ms). */
  avgResponseMs: number;
  /** Number of samples for avgResponseMs. */
  responseSamples: number;
}

const RATE_LIMIT_COOLDOWN_MS = 60_000; // 1 minute cooldown after rate limit
const MAX_CONSECUTIVE_FAILURES = 3; // circuit breaker threshold
// Half-open reset window: after the circuit has been open this long, allow ONE
// probe request through. A success closes the circuit; a failure re-opens it.
// Without this the breaker stayed open for the whole isolate lifetime and a
// provider that recovered mid-session was skipped for hours.
const CIRCUIT_RESET_MS = 5 * 60_000;

/** Per-isolate health store. Persists across invocations within an isolate. */
const healthStore = new Map<Provider, ProviderHealth>();

function emptyHealth(): ProviderHealth {
  return {
    lastRateLimit: 0,
    consecutiveFailures: 0,
    lastFailure: 0,
    successes: 0,
    failures: 0,
    avgResponseMs: 0,
    responseSamples: 0,
  };
}

function getHealth(provider: Provider): ProviderHealth {
  return healthStore.get(provider) ?? emptyHealth();
}

/**
 * Check if a provider is healthy enough to use.
 * Returns false if rate-limited or circuit-broken.
 */
export async function isProviderHealthy(provider: Provider): Promise<boolean> {
  const health = getHealth(provider);
  // Rate-limited — skip for cooldown period
  if (health.lastRateLimit > 0 && Date.now() - health.lastRateLimit < RATE_LIMIT_COOLDOWN_MS) {
    return false;
  }
  // Circuit breaker — too many consecutive failures. Half-open: after the
  // reset window a probe is allowed through so a recovered provider is
  // re-adopted on its first success instead of staying skipped forever.
  if (health.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
    return Date.now() - health.lastFailure >= CIRCUIT_RESET_MS;
  }
  return true;
}

/**
 * Record a successful call to a provider.
 */
export async function recordSuccess(provider: Provider, responseMs: number): Promise<void> {
  const existing = getHealth(provider);
  const totalSamples = existing.responseSamples + 1;
  const avgMs = (existing.avgResponseMs * existing.responseSamples + responseMs) / totalSamples;
  healthStore.set(provider, {
    lastRateLimit: 0,
    consecutiveFailures: 0,
    lastFailure: 0,
    successes: existing.successes + 1,
    failures: existing.failures,
    avgResponseMs: avgMs,
    responseSamples: totalSamples,
  });
}

/**
 * Record a failure (rate limit or other error).
 */
export async function recordFailure(provider: Provider, isRateLimit: boolean): Promise<void> {
  const existing = getHealth(provider);
  healthStore.set(provider, {
    lastRateLimit: isRateLimit ? Date.now() : existing.lastRateLimit,
    consecutiveFailures: existing.consecutiveFailures + 1,
    lastFailure: Date.now(),
    successes: existing.successes,
    failures: existing.failures + 1,
    avgResponseMs: existing.avgResponseMs,
    responseSamples: existing.responseSamples,
  });
}

/**
 * Get health summary for all providers (for observability).
 */
export async function getProviderHealthSummary(): Promise<Record<Provider, ProviderHealth & { healthy: boolean }>> {
  const providers: Provider[] = ['groq', 'gemini', 'nvidia'];
  const summary = {} as Record<Provider, ProviderHealth & { healthy: boolean }>;
  for (const p of providers) {
    const health = getHealth(p);
    summary[p] = { ...health, healthy: await isProviderHealthy(p) };
  }
  return summary;
}

/**
 * Reset a provider's health (e.g., after manual intervention).
 */
export async function resetProviderHealth(provider: Provider): Promise<void> {
  healthStore.delete(provider);
}
