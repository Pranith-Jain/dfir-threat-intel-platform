/**
 * AI-powered threat-intelligence summary generator.
 *
 * Given a collection of feed items (writeups, cybercrime, signals, etc.),
 * produces a concise analyst-grade summary covering:
 *   - TL;DR + what's new vs background noise
 *   - Key themes and trends (with item counts)
 *   - Notable threat actors / campaigns / CVEs (evidence-linked)
 *   - Severity + confidence calibration
 *   - Prioritized defender actions
 *
 * Uses the shared LLM client with preferGroq: every AI summary runs on Groq's
 * openai/gpt-oss-120b first, with Gemini → NVIDIA → Workers AI as fallback.
 * Gracefully degrades: on any failure returns null so the caller can skip
 * the summary card without blocking the page.
 */

import type { Env } from '../env';
import { runCompletion, runWorkersAI, isWorkersAi } from '../case-study/generation/ai-client';
import { findUngroundedCves, extractCves } from './ai-output-validator';
import { fenceUntrusted, neutralizeUntrusted, UNTRUSTED_DATA_SYSTEM_NOTE } from './prompt-fence';
import { NO_EM_DASH_RULE, stripConnectorEmDashes } from './prose-style';
import { logError } from './logger';

export interface SummaryInput {
  /** Page surface name (e.g. "CTI Writeups", "Cybercrime", "Signal"). */
  surface: string;
  /** ISO date the summary covers. */
  date: string;
  /** Items to summarize. title + body are joined; source is metadata. */
  items: Array<{ title: string; body: string; source?: string }>;
  /** Max items to feed into the prompt. Default 30. */
  maxItems?: number;
}

export interface SummaryResult {
  summary: string;
  tweet: string;
  /** LinkedIn-formatted post body (no URL — the client appends it). */
  linkedin: string;
  modelUsed: string;
  itemCount: number;
  _validation?: {
    quality_score?: number;
    ungrounded_cves?: string[];
  };
}

const SYSTEM_PROMPT = `You are a senior cyber-threat-intelligence analyst briefing a SOC lead. Given a list of security items from a specific feed surface, produce THREE outputs separated by lines containing ONLY the markers ---TWEET--- and ---LINKEDIN--- (in that order).

OUTPUT 1 — FULL SUMMARY (200-350 words):
Structure it EXACTLY like this:
1. **TL;DR**: One or two punchy sentences — the single most important development AND why it matters right now.
2. **What's new**: 1-2 bullets (prefixed with "- ") on what actually changed in this cut vs background noise (new actor, new CVE, new campaign, escalation). If nothing is new, say so in one line and skip the bullets.
3. **Key themes**: 2-4 bullets (prefixed with "- ") of dominant trends. Quantify each with an item count, e.g. "Ransomware dominates (7/22 items)". Order by prevalence.
4. **Notable entities**: Specific threat actors, malware families, CVEs, or campaigns — each with a one-phrase evidence link, e.g. "CVE-2026-1234 (RCE in Edge, exploited in the wild per 3 items)". Group by type.
5. **Severity & confidence**: One line, e.g. "Severity: HIGH — active exploitation reported. Confidence: medium — single-source reporting on attribution."
6. **Analyst takeaway**: 1-2 prioritized defender actions, most urgent first. Name the control (patch, hunt query, block), not generic advice.

OUTPUT 2 — TWEET (after ---TWEET---):
A single tweet-ready line (max 280 chars) that a security professional would actually post. Include 1-3 relevant hashtags (#ThreatIntel, #CyberSecurity, #InfoSec, #CVE, etc). Make it punchy, specific, and jargon-light enough for a broad tech audience. No markdown formatting.

OUTPUT 3 — LINKEDIN POST (after ---LINKEDIN---):
A LinkedIn post (300-600 chars, plus 3-5 hashtags) written for practitioners, using the 2026 LinkedIn engagement rules:
1. **HOOK** — first 1-2 lines (<= 210 chars, all inside the above-the-fold window): a complete, standalone concrete point — named actor/CVE/campaign + a hard number. NOT a teaser; the reader learns something specific without clicking "see more".
2. **INSIGHT** — 1-2 short paragraphs (2-4 lines each) with the analytical take the coverage misses. Lead with the take, then support it.
3. **A bullet list** of 3-5 scannable concrete facts (named CVE / vendor / sector / group). One bullet = one fact.
4. **CLOSE** — one line takeaway + a substantive question in the style a SOC lead or IR consultant would actually answer. NOT "Thoughts?".
5. **FINAL LINE**: at most 3 hashtags, specific to the case — never a generic stack (#ThreatIntel works; #CyberSecurity #InfoSec alone is too generic).
Rules for LinkedIn: NO URL in the body — the client adds it so the reader can move it to the first comment. No markdown headers, no **bold**, no asterisks. At most ONE emoji (🔴 ⚠️) — never decorative.

Rules (all outputs):
- Be specific and factual. Reference actual names, CVE IDs, and actors from the items. NEVER invent IOCs, CVE IDs, actor names, or numbers — every entity must appear in the items above.
- Calibrate: distinguish confirmed reporting ("3 items report X") from single-source claims ("one item claims X — uncorroborated").
- Write like a human analyst, not a corporate release. Avoid filler phrases ("in today's evolving threat landscape", "robust", "leverage", "delve").
- If the items are thin or low-signal, say so honestly in one line rather than padding.
- Do not use markdown headers (#). Use bold (**) only in the full summary.
- The tweet must stand alone and make sense without the full summary.
- The LinkedIn post must read differently from the tweet, same substance but platform-native structure.
${NO_EM_DASH_RULE}
${UNTRUSTED_DATA_SYSTEM_NOTE}`;

const MAX_BODY_CHARS = 14000;
// Outer bound for the whole runCompletion chain (Groq → Gemini → NVIDIA →
// Workers AI). Long enough that a slow-but-healthy Gemini/Groq fallback can
// actually respond after a rate-limitted Groq (single Groq timeout is 15s,
// so an 18s cap fired the timeout BEFORE any fallback had a chance — the
// classic "AI summary sometimes never generates" 503). Short enough that
// on total chain failure we still recover via the Workers-AI fallback below
// and return before the frontend's 35s abort. 28s threads that needle.
const CALL_TIMEOUT_MS = 28_000;
// Bounds the recovery re-attempt after the chain races out. Workers AI is
// first-party infra (no external rate quota), so it usually answers in 2-5s.
const FALLBACK_TIMEOUT_MS = 12_000;

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/i;
// High-signal keywords for ranking feed items before the LLM cut.
const SIGNAL_RE =
  /\b(0-?day|rce|exploit|ransomware|breach|leak|c2|apt|lazarus|volt typhoon|lockbit|cl0p|kev|critical|cvss\s*9|cvss\s*10)\b/i;

export function normalizeTitle(t: string): string {
  return t
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

export function scoreItem(title: string, body: string): number {
  const text = `${title} ${body}`;
  let score = 0;
  if (CVE_RE.test(text)) score += 3;
  const signals = text.match(new RegExp(SIGNAL_RE.source, 'gi'));
  if (signals) score += Math.min(signals.length, 3);
  // Prefer items with substance — a title-only stub carries no signal.
  if (body.trim().length > 120) score += 1;
  return score;
}

export interface ShapedItem {
  title: string;
  body: string;
  source?: string;
  /** 0-based rank after signal sorting (0 = highest signal). */
  rank: number;
  /** Body char budget assigned by tier. */
  budget: number;
}

export interface ShapedInput {
  items: ShapedItem[];
  /** Duplicates removed by title normalization. */
  dupesRemoved: number;
}

/**
 * Pure shaping pass shared by buildUserPrompt and unit tests:
 * 1. Dedup by normalized title (same story syndicated across feeds).
 * 2. Rank by threat signal so CVEs / active exploitation win the LLM budget.
 * 3. Tiered body budgets: top-10 items get full context, the tail gets stubs.
 */
export function shapeItemsForPrompt(items: SummaryInput['items'], maxItems = 30): ShapedInput {
  const seen = new Set<string>();
  const deduped: SummaryInput['items'] = [];
  for (const item of items) {
    const key = normalizeTitle(item.title);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    deduped.push(item);
  }
  const dupesRemoved = items.length - deduped.length;
  const shaped = deduped
    .map((item, i) => ({ item, i, score: scoreItem(item.title, item.body) }))
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .map(({ item }, rank) => ({
      title: item.title,
      body: item.body,
      source: item.source,
      rank,
      // Single-report inputs (report-analyzer) get a deep-read budget so the
      // summary sees the full attack chain, not a stub. Feed cuts stay
      // tiered: top-10 get 600 chars, the tail gets 250.
      budget: deduped.length === 1 ? 3500 : rank < 10 ? 600 : 250,
    }))
    .slice(0, maxItems);
  return { items: shaped, dupesRemoved };
}

function buildUserPrompt(input: SummaryInput): string {
  const { items, dupesRemoved } = shapeItemsForPrompt(input.items, input.maxItems ?? 30);
  // Feed item title/body/source are attacker-authorable (feed authors). Fence
  // them as untrusted data so an embedded "ignore previous instructions" in a
  // feed title cannot steer the summary. Surface/date are app metadata.
  const itemLines: string[] = [];
  for (const item of items) {
    const src = item.source ? ` [${neutralizeUntrusted(item.source)}]` : '';
    const body = neutralizeUntrusted(item.body.replace(/\s+/g, ' ').trim().slice(0, item.budget));
    itemLines.push(`- ${neutralizeUntrusted(item.title)}${src}: ${body}`);
  }
  const lines: string[] = [
    `Surface: ${input.surface}`,
    `Date: ${input.date}`,
    `Items (${items.length} of ${input.items.length}${dupesRemoved > 0 ? `, ${dupesRemoved} duplicates removed` : ''}):`,
    '',
    fenceUntrusted(itemLines.join('\n'), 'FEED_ITEMS'),
  ];
  const joined = lines.join('\n');
  return joined.length > MAX_BODY_CHARS ? joined.slice(0, MAX_BODY_CHARS) + '\n…[truncated]' : joined;
}

/**
 * Generate an AI summary for a feed surface. Returns null on any failure
 * (rate limit, timeout, parse error) so callers can skip gracefully.
 */
export async function generateAiSummary(input: SummaryInput, env: Env): Promise<SummaryResult | null> {
  if (input.items.length === 0) return null;

  const userPrompt = buildUserPrompt(input);

  let text = '';
  let modelUsed = '';

  try {
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('ai-summary timeout')), CALL_TIMEOUT_MS)
    );
    const result = await Promise.race([
      runCompletion(
        env.AI,
        {
          system: SYSTEM_PROMPT,
          user: userPrompt,
          // gpt-oss-120b is a reasoning model: max_completion_tokens must cover
          // the internal reasoning trace AND the visible output. The prompt asks
          // for three outputs (analyst summary + tweet + LinkedIn post), so
          // 2400 gives headroom for the richer summary structure (TL;DR,
          // entities with evidence, severity/confidence) plus the trace.
          maxTokens: 2400,
          temperature: 0.3,
        },
        {
          googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
          groqKey: env.GROQ_API_KEY,
          nvidiaKey: env.NVIDIA_API_KEY as string | undefined,
          preferGroq: true,
        }
      ),
      timeoutPromise,
    ]);
    text = typeof result.text === 'string' ? result.text.trim() : '';
    modelUsed = result.modelUsed;
  } catch (err) {
    // The whole chain raced out (slow/rate-limited Groq + slow fallbacks) or
    // every provider failed. DON'T give up here — the Workers-AI recovery
    // below usually still lands a summary.
    logError(
      `generateAiSummary[${input.surface}] chain failed/timeout`,
      err instanceof Error ? err : new Error(String(err))
    );
  }

  if (!text || text.length < 50) {
    // Empty/near-empty completion — the classic reasoning-model symptom when
    // max_completion_tokens is exhausted on the internal trace, or the chain
    // raced out. Retry the same prompt directly on Workers AI: it has no
    // reasoning-trace token tax (fp8 instruct models emit visible text
    // directly) and no external rate quota.
    if (isWorkersAi(env.AI)) {
      try {
        const fallbackTimeout = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('ai-summary fallback timeout')), FALLBACK_TIMEOUT_MS)
        );
        const fb = await Promise.race([
          runWorkersAI(env.AI, { system: SYSTEM_PROMPT, user: userPrompt, maxTokens: 2400, temperature: 0.3 }),
          fallbackTimeout,
        ]);
        const fbText = typeof fb.text === 'string' ? fb.text.trim() : '';
        if (fbText.length >= 50) {
          text = fbText;
          modelUsed = `workers-ai:${fb.model.split('/').pop()}`;
        } else {
          logError(
            `generateAiSummary[${input.surface}] fallback short output`,
            new Error(`${fbText.length} chars from ${fb.model}`)
          );
        }
      } catch (err) {
        logError(
          `generateAiSummary[${input.surface}] fallback failed`,
          err instanceof Error ? err : new Error(String(err))
        );
      }
    }
  }

  if (!text || text.length < 50) {
    // Log it so the cause isn't lost behind the generic 503, then degrade.
    logError(`generateAiSummary[${input.surface}] no usable output`, new Error(`${text.length} chars, ${modelUsed}`));
    return null;
  }

  try {
    const tweetSplit = text.split('---TWEET---');
    // Style pass before truncation so a connector dash near the 280/3000
    // boundary cannot be cut in half into a stray comma.
    const summary = stripConnectorEmDashes(tweetSplit[0]!).trim();
    const linkedinSplit = (tweetSplit[1] ?? '').split('---LINKEDIN---');
    const tweet =
      stripConnectorEmDashes(linkedinSplit[0] ?? '')
        .trim()
        .slice(0, 280) || summary.split('\n')[0]!.slice(0, 280);
    // LinkedIn fallback: if the model skipped the block (e.g. low-signal items),
    // reuse the summary stripped of markdown rather than leaving the field empty.
    const linkedin =
      stripConnectorEmDashes(linkedinSplit[1] ?? '')
        .trim()
        .slice(0, 3000) || summary.replace(/\*\*/g, '').trim().slice(0, 900);

    // Validate grounding against source items
    const sourceText = input.items.map((i) => `${i.title} ${i.body}`).join(' ');
    const ungrounded = [
      ...new Set([...findUngroundedCves(summary, sourceText), ...findUngroundedCves(linkedin, sourceText)]),
    ];
    const sourceCves = new Set(extractCves(sourceText));
    const textCves = extractCves(summary);
    const groundedCves = textCves.filter((c) => sourceCves.has(c));

    // Quality score: start at 100, deduct for issues
    let quality = 100;
    if (ungrounded.length > 0) quality -= ungrounded.length * 15;
    if (textCves.length > 0 && groundedCves.length === 0) quality -= 20;
    quality = Math.max(0, Math.min(100, quality));

    return {
      summary,
      tweet,
      linkedin,
      modelUsed,
      itemCount: Math.min(input.items.length, input.maxItems ?? 30),
      _validation: {
        quality_score: quality,
        ungrounded_cves: ungrounded.length > 0 ? ungrounded : undefined,
      },
    };
  } catch (err) {
    // Never swallow silently — the route turns null into a generic 503, so the
    // worker log is the ONLY place the real cause (provider exhaustion, auth,
    // timeout, parse failure) surfaces. Keep returning null so the caller still
    // degrades gracefully, but make the failure diagnosable.
    logError(`generateAiSummary[${input.surface}] failed`, err);
    return null;
  }
}
