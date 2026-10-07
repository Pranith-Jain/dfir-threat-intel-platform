import type { Ai } from '@cloudflare/workers-types';
import type { Candidate, Post, PostSource } from '../types';
import { buildPrompt } from './templates';
import { runCompletion } from './ai-client';
import { postProcess } from './post-process';
import { renderHeroSvg } from './hero-svg';
import { generateAiImage, buildHeroImagePrompt, buildBodyImagePrompt, injectBodyImage } from './ai-image';
import { validateIocsLive, type IocValidationEnv } from './ioc-live-validation';
import { verifyAndPruneReferences } from './verify-references';
import { researchCandidate } from '../research';
import type { LinkStatus } from '../../lib/verify-url';

/**
 * Generation entry point.
 *
 * The pipeline is now: RESEARCH → WRITE → NORMALISE.
 *
 * Research runs first and produces a dossier (see `research/`). That dossier
 * replaces the old arrangement where an LLM pass extracted "verified facts"
 * from raw JSON before writing — a step that cost an inference and returned
 * the model's own summary of the evidence, which is where invented details
 * entered the pipeline. Extraction is now deterministic code, and the
 * sources are actually fetched.
 *
 * Two LLM calls are gone as a result: the pre-generation fact-verify pass,
 * and the QA-triggered repair pass. The repair pass existed to fix failures
 * from the scoring gate; with the gate removed there is nothing to repair,
 * and a retry against the same prompt mostly produced different slop.
 */

function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 80);
}

function excerptFrom(body: string, max = 200): string {
  const stripped = body
    .replace(/^##.*$/gm, '')
    .replace(/[`*_>#-]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return stripped.length <= max ? stripped : `${stripped.slice(0, max - 1)}…`;
}

function tagsFor(c: Candidate): string[] {
  const t: string[] = [c.type];
  const ev = c.evidence;
  if (ev?.vendor) t.push(slugify(String(ev.vendor)));
  if (ev?.product) t.push(slugify(String(ev.product)));
  if (ev?.family) t.push(slugify(String(ev.family)));
  if (ev?.group) t.push(slugify(String(ev.group)));
  if (Array.isArray(ev.mitre_techniques)) {
    for (const tech of ev.mitre_techniques.slice(0, 4)) {
      if (typeof tech === 'string') t.push(slugify(tech));
    }
  }
  // Briefing findings carry hundreds of vendors; take a few distinct ones so
  // the tag row stays a compact label rather than a data dump.
  if (Array.isArray(ev.sections)) {
    const vendors = new Set<string>();
    for (const section of ev.sections) {
      if (!section || typeof section !== 'object') continue;
      const findings = (section as Record<string, unknown>).findings;
      if (!Array.isArray(findings)) continue;
      for (const finding of findings) {
        if (finding && typeof finding === 'object' && 'vendor' in (finding as Record<string, unknown>)) {
          const v = (finding as Record<string, unknown>).vendor;
          if (typeof v === 'string' && vendors.size < 6) vendors.add(slugify(v));
        }
      }
    }
    t.push(...vendors);
  }
  return [...new Set(t)].filter(Boolean).slice(0, 12);
}

/** Extract source URLs from candidate evidence. */
function extractSources(evidence: Record<string, unknown>): PostSource[] {
  const sources: PostSource[] = [];
  const seen = new Set<string>();
  const push = (url: unknown, title: string) => {
    if (typeof url !== 'string' || !url.startsWith('http') || seen.has(url)) return;
    seen.add(url);
    sources.push({ url, title });
  };

  if (Array.isArray(evidence.urls)) for (const u of evidence.urls) push(u, '');
  // Titles are positional against `urls` for the actor runner.
  if (Array.isArray(evidence.urls) && Array.isArray(evidence.titles)) {
    for (let i = 0; i < Math.min(evidence.titles.length, evidence.urls.length); i++) {
      const title = evidence.titles[i];
      const s = sources[i];
      if (s && typeof title === 'string') s.title = title;
    }
  }
  if (Array.isArray(evidence.victims)) {
    for (const v of evidence.victims) {
      if (v?.url) push(v.url, `${v.victim ?? ''} — ${evidence.group ?? ''}`.trim());
    }
  }
  if (evidence.cveId && typeof evidence.cveId === 'string') {
    push(`https://nvd.nist.gov/vuln/detail/${evidence.cveId}`, `NVD — ${evidence.cveId}`);
  }
  if (evidence.sourceUrl)
    push(evidence.sourceUrl, typeof evidence.sourceTitle === 'string' ? evidence.sourceTitle : '');
  if (Array.isArray(evidence.sources)) {
    for (const s of evidence.sources) {
      if (typeof s === 'string') {
        push(s, s.includes('pranithjain.qzz.io/threatintel/briefings/') ? 'Live briefing page' : '');
      }
    }
  }
  if (Array.isArray(evidence.sections)) {
    for (const section of evidence.sections) {
      if (!section || typeof section !== 'object') continue;
      const findings = (section as Record<string, unknown>).findings;
      if (!Array.isArray(findings)) continue;
      for (const finding of findings) {
        const f = finding as Record<string, unknown>;
        push(f.source_url, typeof f.source === 'string' ? f.source : '');
      }
    }
  }
  return sources;
}

export interface GeneratePostDeps {
  candidate: Candidate;
  ai: Ai;
  now: Date;
  /** Groq key — quality primary; Workers AI is the fallback. */
  groqKey?: string;
  /** Google AI Studio key for the Gemini fallback. */
  googleKey?: string;
  /** NVIDIA key for the NVIDIA fallback. */
  nvidiaKey?: string;
  infronKey?: string;
  /** Threat-intel provider keys for cross-checking extracted IOCs. When
   *  unset, the indicator list is passed through uncrossed. */
  validationEnv?: IocValidationEnv;
  /** Admin-supplied regeneration guidance, forwarded verbatim. */
  notes?: string;
  /** SELF binding — lets the research stage query the platform's own API. */
  self?: { fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response> };
  /** HMAC secret for self-fetch auth. Absent = skip platform enrichment. */
  internalTokenSecret?: string;
  /** Injectable reference-URL verifier. Tests pass a deterministic stub. */
  verifyRefs?: (urls: string[]) => Promise<Map<string, LinkStatus>>;
  /** Optional AI illustrations. Absent/disabled = SVG hero only. */
  aiImages?: {
    enabled: boolean;
    put: (slug: string, name: string, bytes: Uint8Array) => Promise<void>;
  };
  /** Optional description of the author's real writing rhythm. */
  voiceProfile?: string;
}

export async function generatePost(deps: GeneratePostDeps): Promise<Post> {
  const { candidate, ai, now, groqKey, googleKey, nvidiaKey, infronKey, notes } = deps;

  // ── Step 1: Research ───────────────────────────────────────────────
  // Deterministic extraction plus real source fetches. This is the stage
  // that replaces the removed "fact verify" LLM pass.
  const dossier = await researchCandidate({
    candidate,
    now,
    self: deps.self,
    internalTokenSecret: deps.internalTokenSecret,
  });

  const sources = extractSources(candidate.evidence);

  // ── Step 2: Write ──────────────────────────────────────────────────
  const { system, user } = buildPrompt({
    type: candidate.type,
    title: candidate.title,
    dossier,
    voiceProfile: deps.voiceProfile,
    notes,
  });

  const completion = await runCompletion(
    ai,
    { system, user },
    { infronKey, googleKey, groqKey, nvidiaKey, quality: true, preferGroq: true }
  );

  // The grounding source of truth for post-process is the rendered dossier,
  // not the raw evidence JSON: it is what the writer actually saw.
  const dossierText = JSON.stringify({
    subject: dossier.subject,
    cves: dossier.cves,
    pages: dossier.pages.map((p) => ({ url: p.url, title: p.title, publisher: p.publisher })),
    entities: dossier.entities,
    indicators: dossier.indicators,
  });
  const processed = postProcess({
    type: candidate.type,
    raw: completion.text,
    factsText: dossierText,
  });

  if (!processed.ok) {
    throw new Error(`generation failed: ${processed.errors.join('; ')}`);
  }

  // ── Step 3: Indicator cross-check ─────────────────────────────────
  // Indicators extracted from prose are leads. When provider keys exist,
  // drop the ones no provider recognises.
  let iocs = processed.iocs;
  if (deps.validationEnv) {
    try {
      const live = await validateIocsLive(processed.iocs, deps.validationEnv);
      iocs = live.iocs;
    } catch {
      // Provider unavailable — keep the unverified list rather than
      // silently emptying it.
    }
  }

  // ── Step 4: Citation verification ──────────────────────────────────
  // HEAD-check the union of the post's sources and its reference URLs, and
  // drop the confirmed-dead ones from both surfaces before they ship as
  // clickable links.
  const refCheck = await verifyAndPruneReferences({
    body: processed.body,
    sources,
    verify: deps.verifyRefs,
  });

  const slug = `${candidate.key}-${slugify(candidate.title).slice(0, 40)}`.replace(/-+/g, '-');
  const hero = renderHeroSvg({ title: candidate.title, type: candidate.type });

  // ── Step 5: Illustrations (best-effort) ────────────────────────────
  let heroImageUrl: string | undefined;
  let bodyWithImages = refCheck.body;
  if (deps.aiImages?.enabled) {
    const promptCtx = { title: candidate.title, type: candidate.type };
    try {
      const heroBytes = await generateAiImage(ai, buildHeroImagePrompt(promptCtx));
      if (heroBytes) {
        await deps.aiImages.put(slug, 'hero', heroBytes);
        heroImageUrl = `/api/v1/blog-image/${slug}/hero`;
      }
      const bodyBytes = await generateAiImage(ai, buildBodyImagePrompt(promptCtx));
      if (bodyBytes) {
        await deps.aiImages.put(slug, 'body1', bodyBytes);
        bodyWithImages = injectBodyImage(refCheck.body, `/api/v1/blog-image/${slug}/body1`, candidate.title);
      }
    } catch {
      // Illustration failure never blocks a publish.
    }
  }

  return {
    slug,
    type: candidate.type,
    title: candidate.title,
    excerpt: excerptFrom(refCheck.body),
    publishedAt: now.toISOString(),
    candidateId: candidate.key,
    body: bodyWithImages,
    hero,
    heroImageUrl,
    iocs,
    tags: tagsFor(candidate),
    sources: refCheck.sources,
    audit: processed.audit,
    linkVerification:
      refCheck.report.checked > 0
        ? {
            checked: refCheck.report.checked,
            verified: refCheck.report.verified,
            unchecked: refCheck.report.unchecked,
            broken: refCheck.report.broken.length,
            brokenUrls: refCheck.report.broken.slice(0, 5),
          }
        : undefined,
    evidence: candidate.evidence,
  };
}
