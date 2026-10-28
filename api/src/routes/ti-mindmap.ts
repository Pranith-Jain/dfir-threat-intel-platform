/**
 * TI Mindmap edge tools — LLM mindmap studio (port).
 *
 * Research lineage: format81/TI-Mindmap-GPT (GPLv3, Streamlit) and the
 * public TI Mindmap HUB research docs (CC BY-NC 4.0). This is an
 * edge-native reimplementation, NOT upstream code:
 *
 *  • Streamlit/Ollama/OpenAI/Mistral BYOK does NOT port. Every call uses
 *    the platform runCompletion chain (gemini → groq → nvidia → Workers AI)
 *    via api/src/case-study/generation/ai-client.ts; the platform's keys
 *    and quotas apply. model=oss pins open-weights only.
 *  • PyPDF2 OCR and VirusTotal key enrichment do NOT port (the platform
 *    has a dedicated 60+-provider IOC surface). url → text uses the same
 *    SSRF-guarded fetch + readability-lite extraction as FlowViz.
 *  • Deterministic TTPs ride the shared keyword scanner (lib/ttp-extract)
 *    and everything is validated/grounded per this repo's LLM discipline:
 *    strict schemas, tolerant parsers, per-class caps, verbatim grounding.
 *
 * Endpoints (all under /api/v1/ti-mindmap/):
 *   GET  /ti-mindmap/          — index + lineage + artifacts list
 *   POST /ti-mindmap/analyze   — {text|url, model?, language?} →
 *         {tweet Dossier, mermaid mindmap + parsed tree, ordered TTPs,
 *          mermaid timeline, ATT&CK Navigator layer, modelUsed, elapsed}
 *   POST /ti-mindmap/assistant — {text, question} → {answer, model}
 *
 * MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, badGateway } from '../lib/api-error';
import { safeJsonBody } from '../lib/safe-body';
import { fenceUntrusted, UNTRUSTED_DATA_SYSTEM_NOTE } from '../lib/prompt-fence';
import { runCompletion } from '../case-study/generation/ai-client';
import { extractTTPsKeyword, type TtpHit } from '../lib/ttp-extract';
import { TACTIC_ORDER } from '../lib/attack-flow';
import { flowvizSecureFetch } from '../lib/flowviz-validate';
import { extractArticleLite } from './flowviz';
import {
  TIMINDMAP_MAX_SOURCE_CHARS,
  buildAssistantPrompt,
  buildMermaidTimeline,
  buildMindmapPrompt,
  buildNavigatorLayer,
  buildTweetPrompt,
  navigatorFileName,
  orderTtpsByExecution,
  parseTweetResponse,
  sanitizeMermaidMindmap,
  type NavigatorLayer,
  type SanitizedMindmap,
  type TweetDossier,
} from '../lib/ti-mindmap';

const SOURCE =
  'TI Mindmap Studio (edge port) — researched from format81/TI-Mindmap-GPT (GPLv3) + TI Mindmap HUB research docs (CC BY-NC 4.0); independent reimplementation.';
const SOURCE_URLS = [
  'https://github.com/format81/TI-Mindmap-GPT',
  'https://github.com/TI-Mindmap-HUB-Org/ti-mindmap-hub-research',
];
const LICENSE =
  'Independent implementation: Mermaid mindmap behaviour follows the documented upstream methodology; ATT&CK® © The MITRE Corporation.';
const MAX_URL_CHARS = 2000;
const MAX_INPUT_CHARS = 80_000;

export const tiMindmapRouter = new Hono<{ Bindings: Env }>();

// ── Model selector (FlowViz contract: auto | oss) ──────────────────────

/** Normalize the model selector. Pure. */
export function normalizeTiMindmapModel(v: unknown): 'auto' | 'oss' {
  return v === 'oss' ? 'oss' : 'auto';
}

async function runTiMindmapLlm(
  env: Env,
  system: string,
  user: string,
  model: 'auto' | 'oss',
  role: string,
  maxTokens: number,
  temperature: number
): Promise<{ text: string; modelUsed: string }> {
  return runCompletion(
    env.AI,
    { system, user, maxTokens, temperature },
    {
      role,
      ...(model === 'oss'
        ? { preferProvider: 'groq' as const, exclusiveProvider: true, groqKey: env.GROQ_API_KEY ?? '' }
        : {}),
    }
  );
}

// ── Input resolution (url OR text; mirrors FlowViz) ───────────────────

interface AnalyzeBody {
  text?: string;
  url?: string;
  model?: string;
  language?: string;
}

interface ResolvedText {
  text: string;
  title?: string;
}

/** Deterministic error payloads so callers can build Hono responses. */
function rr(err: { code: 400 | 502; message: string }): { error: { code: 400 | 502; message: string } } {
  return { error: err };
}

async function resolveAnalyzeText(body: AnalyzeBody): Promise<ResolvedText | ReturnType<typeof rr>> {
  const text = typeof body.text === 'string' ? body.text.slice(0, MAX_INPUT_CHARS).trim() : '';
  const url = typeof body.url === 'string' ? body.url.trim().slice(0, MAX_URL_CHARS) : '';
  if (text.length >= 200) return { text };
  if (!url) {
    return text.length > 0
      ? rr({ code: 400, message: `Provide {text} (>=200 chars); got ${text.length} chars and no {url}` })
      : rr({ code: 400, message: 'requires text, url, or article' });
  }
  let res: Response;
  try {
    res = await flowvizSecureFetch(url, { maxBytes: 5_000_000, timeoutMs: 15000, accept: 'text/html' });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (['private-host', 'invalid-scheme', 'invalid-url', 'credentials-in-url'].includes(msg)) {
      return rr({ code: 400, message: `Blocked URL (${msg})` });
    }
    if (msg === 'response-too-large') return rr({ code: 400, message: 'Article too large (5 MB cap)' });
    if (msg === 'too-many-redirects') return rr({ code: 502, message: 'Too many redirects' });
    logError('ti-mindmap analyze fetch failed', e);
    return rr({ code: 502, message: 'Article fetch failed' });
  }
  const ct = res.headers.get('content-type') ?? '';
  if (ct && !/text\/html|application\/xhtml/i.test(ct)) {
    return rr({ code: 400, message: `Not an HTML article (content-type: ${ct.slice(0, 80)})` });
  }
  const html = await res.text().catch(() => '');
  const { title, text: extracted } = extractArticleLite(html);
  if (extracted.length < 200) {
    return rr({ code: 502, message: 'Could not extract article text (paywall or JS-rendered page)' });
  }
  return { text: extracted.slice(0, MAX_INPUT_CHARS), title };
}

// ── Handlers ──────────────────────────────────────────────────────────

const TTM_BASE_SYSTEM = 'You are a senior cyber threat intelligence analyst summarizing threat reports.';

export interface AnalyzeResult {
  title: string | null;
  textLength: number;
  elapsed_ms: number;
  tweet: TweetDossier | null;
  mindmap: SanitizedMindmap | null;
  ttps: TtpHit[];
  timeline_mermaid: string;
  navigator: NavigatorLayer;
  navigator_file: string;
  branches: { tweet: string | null; mindmap: string | null };
  models: { tweet: string | null; mindmap: string | null };
  warnings: string[];
  /**
   * Echo of the extracted article text (same bound the LLM saw) so the SPA
   * Chat tab can address the report after a URL-mode analysis.
   */
  source_text?: string;
}

async function runAnalyze(
  env: Env,
  text: string,
  opts: { model: 'auto' | 'oss'; language?: string }
): Promise<AnalyzeResult> {
  const started = Date.now();
  const source = fenceUntrusted('ARTICLE', text.slice(0, TIMINDMAP_MAX_SOURCE_CHARS));
  const warnings: string[] = [];

  // Branch 1: tweet dossier (single structured JSON call).
  let tweet: TweetDossier | null = null;
  let tweetModel: string | null = null;
  try {
    const out = await runTiMindmapLlm(
      env,
      `${TTM_BASE_SYSTEM} Return only strict JSON.`,
      buildTweetPrompt({ text: source, language: opts.language }),
      opts.model,
      'ti-mindmap-tweet',
      700,
      0.2
    );
    tweet = parseTweetResponse(out.text);
    tweetModel = out.modelUsed;
  } catch (e) {
    logError('ti-mindmap tweet branch failed', e);
    warnings.push('tweet dossier failed');
  }

  // Branch 2: Mermaid mindmap (few-shot constrained call + hardening).
  let mindmap: SanitizedMindmap | null = null;
  let mindmapModel: string | null = null;
  try {
    const out = await runTiMindmapLlm(
      env,
      `${TTM_BASE_SYSTEM} Output only the mermaid mindmap block.`,
      UNTRUSTED_DATA_SYSTEM_NOTE + '\n\n' + buildMindmapPrompt({ text: source, language: opts.language }),
      opts.model,
      'ti-mindmap-mindmap',
      8000,
      0.3
    );
    mindmapModel = out.modelUsed;
    mindmap = sanitizeMermaidMindmap(out.text);
    for (const w of mindmap.warnings) warnings.push(`mindmap: ${w}`);
  } catch (e) {
    logError('ti-mindmap mindmap branch failed', e);
    warnings.push('mindmap generation failed');
  }

  // Branch 3 (deterministic): keyword TTP scan → order → timeline + layer.
  let ttps: TtpHit[] = [];
  try {
    ttps = orderTtpsByExecution(extractTTPsKeyword(text), TACTIC_ORDER);
  } catch (e) {
    logError('ti-mindmap ttp scan failed', e);
    warnings.push('ttp scan failed');
  }
  const timeline = buildMermaidTimeline(ttps);
  const name = tweet?.headline ?? mindmap?.tree?.label ?? 'TI Mindmap';
  const navigator = buildNavigatorLayer({
    name,
    ttps,
    description: `ATT&CK Navigator layer produced by the TI Mindmap Studio edge port from ${ttps.length} keyword-observed techniques.`,
  });
  return {
    title: tweet?.headline ?? mindmap?.tree?.label ?? null,
    textLength: text.length,
    elapsed_ms: Date.now() - started,
    tweet,
    mindmap,
    ttps,
    timeline_mermaid: timeline,
    navigator,
    navigator_file: navigatorFileName(name),
    branches: { tweet: tweet ? 'ok' : 'failed', mindmap: mindmap?.ok ? 'ok' : mindmap ? 'degraded' : 'failed' },
    models: { tweet: tweetModel, mindmap: mindmapModel },
    warnings,
  };
}

export interface TiMindmapAnalyzeBody extends AnalyzeBody {
  /** Convenience alias some callers use. */
  article?: string;
}

tiMindmapRouter.get('/ti-mindmap/', (c) =>
  c.json({
    source: SOURCE,
    source_urls: SOURCE_URLS,
    license: LICENSE,
    artifacts: ['tweet_dossier', 'mermaid_mindmap', 'mindmap_tree', 'ttp_timeline', 'navigator_layer'],
    models: {
      auto: 'Default platform chain (gemini → groq → nvidia → workers-ai).',
      oss: 'Open-weights only: groq gpt-oss exclusive, no fall-through.',
    },
    provider_tt_note:
      'IOCs / STIX / Diamond run on the dedicated report-analyzer surface; this endpoint composes narrated artifacts only.',
  })
);

tiMindmapRouter.post('/ti-mindmap/analyze', async (c) => {
  const parsed = await safeJsonBody<TiMindmapAnalyzeBody>(c, { maxBytes: 128 * 1024 });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;
  const model = normalizeTiMindmapModel(body.model);
  const language = typeof body.language === 'string' ? body.language.slice(0, 40) : undefined;
  if (!body.text && !body.url && !body.article) {
    return badRequest(c, 'requires text, url, or article');
  }
  const resolved = await resolveAnalyzeText({ ...body, text: body.text ?? body.article });
  if ('error' in resolved) {
    return resolved.error.code === 400 ? badRequest(c, resolved.error.message) : badGateway(c, resolved.error.message);
  }
  if (resolved.text.length < 200)
    return badRequest(c, `Provide {text} (>=200 chars) or {url}; got ${resolved.text.length} chars`);
  try {
    const result = await runAnalyze(c.env, resolved.text, { model, language });
    return c.json(
      {
        ...result,
        title: resolved.title ?? result.title,
        source_text: resolved.text.slice(0, TIMINDMAP_MAX_SOURCE_CHARS),
        source: SOURCE,
        source_urls: SOURCE_URLS,
      },
      200,
      {
        'Cache-Control': 'no-store',
      }
    );
  } catch (e) {
    logError('ti-mindmap analyze failed', e);
    return badGateway(c, 'Analysis failed (LLM unavailable or invalid output)');
  }
});

// ── Assistant: chat with the report ───────────────────────────────────

const ASSISTANT_SYSTEM =
  'You are a cyber threat intelligence analyst answering questions about a specific report. Ground every claim in the report text. If the report does not support a claim, say so.';

tiMindmapRouter.post('/ti-mindmap/assistant', async (c) => {
  const parsed = await safeJsonBody<{ text?: string; question?: string; model?: string }>(c, { maxBytes: 128 * 1024 });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;
  const model = normalizeTiMindmapModel(body.model);
  const question = (body.question ?? '').trim().slice(0, 500);
  const text = (body.text ?? '').trim().slice(0, MAX_INPUT_CHARS);
  if (!question || question.length < 3) return badRequest(c, 'requires {question} (>=3 chars)');
  if (text.length < 200) return badRequest(c, `requires {text} (>=200 chars); got ${text.length}`);
  try {
    const out = await runTiMindmapLlm(
      c.env,
      `${ASSISTANT_SYSTEM} ${UNTRUSTED_DATA_SYSTEM_NOTE}`,
      buildAssistantPrompt({ question, text: text.slice(0, TIMINDMAP_MAX_SOURCE_CHARS) }),
      model,
      'ti-mindmap-assistant',
      1400,
      0.2
    );
    return c.json({ answer: out.text.trim() || 'The model returned an empty answer.', modelUsed: out.modelUsed }, 200, {
      'Cache-Control': 'no-store',
    });
  } catch (e) {
    logError('ti-mindmap assistant failed', e);
    return badGateway(c, 'Assistant failed (LLM unavailable)');
  }
});
