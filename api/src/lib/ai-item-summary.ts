/**
 * Per-post AI summary generator.
 *
 * Companion to ai-summary.ts (which summarises a whole feed surface). This one
 * produces a single, one-sentence summary for ONE feed item — rendered under
 * each post by the frontend <PostSummary> component.
 *
 * Cost control (per-item summarisation is far more LLM-heavy than one card):
 *   - Each item is summarised at most once, then cached in KV by a content hash
 *     for 7 days. The same item appearing across pages / reloads is free.
 *   - The route caps how many items are summarised per request.
 *   - Runs on Groq's openai/gpt-oss-120b (preferGroq) like every AI summary.
 *
 * Gracefully degrades: any failure yields null so the post simply renders
 * without a summary line.
 */

import type { Env } from '../env';
import { runCompletion } from '../case-study/generation/ai-client';
import { fenceUntrusted, neutralizeUntrusted, UNTRUSTED_DATA_SYSTEM_NOTE } from './prompt-fence';
import { routeCacheGet, routeCachePut } from './route-cache';

export interface ItemInput {
  /** Stable client-side id (used to map the summary back to the post). */
  id: string;
  title: string;
  body?: string;
  source?: string;
}

const SYSTEM_PROMPT = `You are a senior cyber-threat-intelligence analyst. Summarise ONE security feed item in a single sentence (max 35 words) for a CTI analyst skimming a feed.

Rules:
- One sentence. No preamble ("This article…"), no markdown, no bullet points.
- Be specific: keep concrete names — threat actors, malware families, CVE IDs, vendors, packages.
- State the key fact or "so what", not a restatement of the title.
- If the item is too thin to summarise, return the single most important fact from it.
- Output plain text only.

${UNTRUSTED_DATA_SYSTEM_NOTE}`;

const CACHE_PREFIX = 'ais:item:v1:';
const CACHE_TTL_S = 7 * 24 * 3600; // 7 days
const CALL_TIMEOUT_MS = 10_000;
const MAX_BODY_CHARS = 600;
const MAX_SUMMARY_CHARS = 320;

/** SHA-256 hex of the item's salient content — the per-item cache key. */
async function contentHash(item: ItemInput): Promise<string> {
  const basis = `${item.title}\n${(item.body ?? '').slice(0, 1000)}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(basis));
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < 16; i += 1) hex += bytes[i]!.toString(16).padStart(2, '0');
  return hex;
}

function buildUserPrompt(item: ItemInput): string {
  // Title/body/source are attacker-authorable (feed authors) — fence them so an
  // embedded "ignore previous instructions" cannot steer the summary.
  const src = item.source ? ` [${neutralizeUntrusted(item.source.slice(0, 120))}]` : '';
  const body = neutralizeUntrusted((item.body ?? '').replace(/\s+/g, ' ').trim().slice(0, MAX_BODY_CHARS));
  const block = `${neutralizeUntrusted(item.title.slice(0, 300))}${src}\n${body}`;
  return fenceUntrusted(block, 'FEED_ITEM');
}

/**
 * Summarise a single item. Returns the cached summary when present, otherwise
 * generates + caches one, including the provider:model that produced it (for
 * the route's modelHint). Returns null on any failure (caller skips the line).
 */
export async function generateItemSummary(
  item: ItemInput,
  env: Env
): Promise<{ summary: string; model: string } | null> {
  if (!item.title || item.title.trim().length === 0) return null;

  const kv = env.KV_CACHE;
  let key: string | null = null;
  if (kv) {
    try {
      key = CACHE_PREFIX + (await contentHash(item));
      // L1-first read: content-hash keys are write-once (same input → same
      // summary), so a per-colo Cache-API shadow can never serve a divergent
      // value. Collapses the N-per-page KV reads to ~1 KV read per colo for
      // the life of the entry. Text semantics — historical entries were
      // written via kv.get(key) text mode, so the shadow stores the raw
      // string rather than a JSON envelope.
      const l1 = await routeCacheGet<string>(key);
      if (l1) return { summary: l1, model: 'cache' };
      const raw = await kv.get(key);
      if (raw) {
        void routeCachePut(key, raw, CACHE_TTL_S);
        return { summary: raw, model: 'cache' };
      }
    } catch {
      /* cache unavailable — generate fresh */
    }
  }

  try {
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('ai-item-summary timeout')), CALL_TIMEOUT_MS)
    );
    const result = await Promise.race([
      runCompletion(
        env.AI,
        { system: SYSTEM_PROMPT, user: buildUserPrompt(item), maxTokens: 120, temperature: 0.2 },
        {
          googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: env.GROQ_API_KEY,
          nvidiaKey: env.NVIDIA_API_KEY as string | undefined,
          preferGroq: true,
        }
      ),
      timeoutPromise,
    ]);

    let text = typeof result.text === 'string' ? result.text.trim() : '';
    // Collapse to one line and bound length defensively.
    text = text.replace(/\s+/g, ' ').trim();
    if (text.length > MAX_SUMMARY_CHARS) text = text.slice(0, MAX_SUMMARY_CHARS).replace(/\s+\S*$/, '') + '…';
    if (text.length < 10) return null;

    if (kv && key) {
      try {
        // Write-through: KV stays the cross-colo store; the per-colo Cache-API
        // shadow (fire-and-forget) makes same-colo re-reads free.
        await kv.put(key, text, { expirationTtl: CACHE_TTL_S });
        void routeCachePut(key, text, CACHE_TTL_S);
      } catch {
        /* best-effort cache write */
      }
    }
    return { summary: text, model: result.modelUsed ?? 'groq:openai/gpt-oss-120b' };
  } catch {
    return null;
  }
}
