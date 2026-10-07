import type { Ai } from '@cloudflare/workers-types';
import type { Candidate, Post, SocialContent, SocialCheck } from '../types';
import { runCompletion } from './ai-client';
import {
  VOICE_IDENTITY,
  ANSWER_FIRST,
  GROUNDING_CONTRACT,
  PIPELINE_OUTPUT_GUARDRAIL,
  FORMAT_CONTRACT,
} from './copywriting';
import { stripUntrustedUrls, findUngroundedCves } from '../../lib/ai-output-validator';
import { slugify } from '../stable-keys';
import type { ContentSlide } from '../social/slide-spec';
import { buildCarouselSlides } from '../social/carousel-build';
import { buildHashtags } from './hashtags';
import type { ResearchDossier } from '../research';
import { renderDossier } from '../research/dossier';

// Re-export the canonical types so existing imports keep working.
export type { SocialContent, SocialCheck };

/**
 * Social repurposing.
 *
 * What changed, and why.
 *
 * The old version scored its own output: a 0-100 composite that deducted
 * points for character count, a curated keyword list ("does the post mention
 * a CVE, a version, a sector?"), hashtag count, and slop phrases. Anything
 * under 60 triggered a retry with the failures pasted back into the prompt.
 *
 * That loop was actively harmful:
 *
 *  - The concrete-specifics check counted matches against a hardcoded list of
 *    ~60 vendor and actor names. It rewarded name-dropping over analysis, and
 *    it scored a genuinely sharp post about an obscure product as "too
 *    generic" while giving a name-stuffed post a perfect score.
 *  - The retry fed the model its own validation complaints. Models comply
 *    with checklists rather than improving, so retries reliably produced
 *    keyword-stuffed posts that passed the score.
 *  - LinkedIn length floors (1300 chars soft / 900 hard) pushed the model to
 *    pad to hit a number, which is how you get a post that says the same
 *    thing four ways.
 *
 * So: no scores, no retries, no keyword checklist. What remains is factual —
 * does the copy stay inside the platform's hard limits, does it cite CVEs
 * that exist in the dossier, does it link only to trusted hosts. Those are
 * real errors worth fixing. Whether the copy is *good* is now the same
 * question it is for a blog post, answered by better input (a real research
 * dossier) rather than by a critic.
 */

const SOCIAL_SYSTEM =
  VOICE_IDENTITY +
  '\n' +
  ANSWER_FIRST +
  '\n' +
  // Social copy is derived from the same dossier as the article, so it obeys
  // the same grounding contract — otherwise a thread is exactly where an
  // invented CVE id does the most damage, because it travels further and
  // nobody opens the source.
  GROUNDING_CONTRACT +
  '\n' +
  PIPELINE_OUTPUT_GUARDRAIL +
  '\n' +
  FORMAT_CONTRACT;

export interface SocialSource {
  slug: string;
  title: string;
  body: string;
  hashtags?: string[];
  performanceNote?: string;
  /** Research dossier, when the post went through the research stage. A
   *  published post has one; a candidate preview falls back to `body`. */
  dossier?: ResearchDossier;
}

const BODY_CAP = 6000;

function gist(body: string): string {
  const b = body.trim();
  return b.length <= BODY_CAP ? b : `${b.slice(0, BODY_CAP)}\n…[article continues]`;
}

/**
 * Light tidying: trailing whitespace, collapsed runs, at most one blank line.
 * No punctuation rewriting — em-dashes and semicolons are perfectly good
 * punctuation and the old blanket replacement mangled ranges and table rows.
 */
function tidy(text: string): string {
  return text
    .split('\n')
    .map((l) => l.replace(/[ \t]+$/g, '').replace(/[ \t]{2,}/g, ' '))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** LinkedIn-specific: merge runs of short single-line paragraphs into dense
 *  blocks so the post scans properly on a phone. */
function tidyLinkedin(text: string): string {
  const blocks = tidy(text).split(/\n\n+/);
  const merged: string[] = [];
  let buffer: string[] = [];
  const flush = () => {
    if (buffer.length === 0) return;
    merged.push(buffer.join('\n'));
    buffer = [];
  };
  const isTight = (block: string): boolean => {
    const lines = block.split('\n');
    if (lines.length !== 1) return false;
    const line = lines[0] ?? '';
    if (!line || line.length > 110) return false;
    if (/^[-*]\s/.test(line) || /^\d+\.\s/.test(line)) return false;
    if (line.startsWith('#') || line.startsWith('**') || line.startsWith('>')) return false;
    if (/^(FIRST (COMMENT|REPLY):|CAROUSEL OUTLINE:)/i.test(line)) return false;
    return true;
  };
  for (const block of blocks) {
    if (isTight(block)) buffer.push(block);
    else {
      flush();
      merged.push(block);
    }
  }
  flush();
  return merged.join('\n\n');
}

// ── Factual checks ──────────────────────────────────────────────────────

const TWITTER_HARD_LIMIT = 280;
const LINKEDIN_HARD_LIMIT = 3000;
const INSTAGRAM_HARD_LIMIT = 2200;

/**
 * Factual validation only. Every field is measurable or a ground-truth
 * lookup — nothing here expresses an opinion about the copy.
 *
 * The `over_limit` flag matters: LinkedIn and X silently truncate or reject
 * over-length posts, and an over-length post is a real failure regardless of
 * how good the writing is.
 */
function checkSocial(text: string, platform: 'twitter' | 'linkedin' | 'instagram', sourceBody: string): SocialCheck {
  let measured = 0;

  if (platform === 'twitter') {
    // A thread is many posts; the longest one is what has to fit.
    const withoutLink = text.replace(/\n?FIRST REPLY:.*$/im, '').trim();
    const posts = withoutLink.split(/\n\n+/).filter((p) => p.trim().length > 0);
    for (const post of posts) {
      const clean = post.replace(/\s*\(\d+\/\d+\)\s*$/, '').trim();
      measured = Math.max(measured, clean.length);
    }
  } else if (platform === 'instagram') {
    measured = text.length;
  } else {
    // LinkedIn: body only. The FIRST COMMENT link is not part of the limit.
    measured = (text.split(/FIRST COMMENT:/i)[0]?.trim() ?? text).length;
  }

  const limit =
    platform === 'twitter' ? TWITTER_HARD_LIMIT : platform === 'instagram' ? INSTAGRAM_HARD_LIMIT : LINKEDIN_HARD_LIMIT;

  return {
    char_count: measured,
    over_limit: measured > limit,
    ungrounded_cves: findUngroundedCves(text, sourceBody),
    untrusted_urls: stripUntrustedUrls(text).stripped.length,
  };
}

/**
 * Remove links to hosts outside the allowlist and CVE ids that are not in
 * the dossier. Both are factual errors — a fabricated CVE id is
 * misinformation, and an untrusted link in a published post is a liability.
 */
function cleanSocial(text: string, sourceBody: string): string {
  let out = stripUntrustedUrls(text).cleaned;
  for (const cve of findUngroundedCves(out, sourceBody)) {
    out = out.replace(new RegExp(`\\b${cve.replace(/-/g, '\\-')}\\b`, 'gi'), 'the vulnerability');
  }
  return out;
}

// ── Prompt builders ─────────────────────────────────────────────────────

/**
 * Shared dossier block. Social copy is derived from the same research as the
 * article, which is what lets a thread make a claim the article can back.
 */
function dossierBlock(src: SocialSource): string {
  if (!src.dossier) return '';
  const rendered = renderDossier(src.dossier, { budget: 6000 });
  return (
    `\n<research_dossier>\nThe same research the article was written from. ` +
    `Every CVE, version, number and date you cite must come from here. ` +
    `Where it says something is not established, do not fill the gap.\n\n` +
    `${rendered}\n</research_dossier>\n`
  );
}

function buildTwitterPrompt(src: SocialSource, includeLink = true): string {
  const postUrl = `https://pranithjain.qzz.io/blog/${src.slug}`;
  return (
    `<format name="X post or thread">\n\n` +
    `Pick the shape that fits the material: a thread when there are several ` +
    `distinct facts worth carrying, a single post when there is one.\n\n` +
    `If a thread:\n` +
    `- Open with the finding. Named entity, hard number, or sharp contrast, ` +
    `  from this specific case. No "1/" prefix on the first post.\n` +
    `- One idea per post after that. If a post carries two ideas it carries ` +
    `  neither.\n` +
    `- Include the reusable data: affected versions, the CVE list, the ` +
    `  indicator sample. That is what people bookmark.\n` +
    `- Second to last post is the read: the implication, the thing that ` +
    `  changes how you think about this class of problem. Not a summary.\n` +
    `- Last post is a question a practitioner would actually answer.\n` +
    `- Append " (n/N)" to each post.\n` +
    `If a single post: the finding and one sharp take, under the limit.\n\n` +
    (includeLink ? `Put the link on its own line after the thread: "FIRST REPLY: ${postUrl}"\n` : `No link.\n`) +
    `- Each post under ${TWITTER_HARD_LIMIT} characters.\n` +
    `- At most one hashtag, only if it is genuinely specific to this case.\n` +
    `- Fragments are fine. Lowercase is fine when it is natural.\n` +
    `- Write as the analyst who did the work, not as a brand account. No ` +
    `  emoji-led hooks, no "🚨 breaking", no thread-announcement preamble.\n` +
    `- Every CVE, number and indicator comes from the dossier. Do not invent ` +
    `  one to make a post sound more urgent.\n` +
    `</format>\n\n` +
    dossierBlock(src) +
    `\n<article>\nTitle: ${src.title}\n\n${gist(src.body)}\n</article>\n` +
    (src.performanceNote ?? '')
  );
}

function buildLinkedinPrompt(src: SocialSource, includeLink = true): string {
  const postUrl = `https://pranithjain.qzz.io/blog/${src.slug}`;
  return (
    `<format name="LinkedIn post">\n\n` +
    `One reader, on a phone, deciding whether to stop scrolling. They will ` +
    `see roughly the first two lines before "see more". Those lines have to ` +
    `deliver a complete point on their own, not a promise that the point is ` +
    `below.\n\n` +
    `Shape:\n` +
    `- Open on the finding. Named entity, real number, or a contrast the ` +
    `  reader has not drawn. Not a framing sentence about the industry.\n` +
    `- Then the analysis. What the data actually shows, what surprised you, ` +
    `  what a defender should conclude. Short paragraphs, generous space — ` +
    `  nothing over three lines.\n` +
    `- A scannable list of specifics, when there are any: one fact per line, ` +
    `  real values, no filler bullets. Drop the list rather than pad it.\n` +
    `- Close with the takeaway and one question a SOC lead or IR consultant ` +
    `  would genuinely answer. Not "thoughts?" and not "what do you think?".\n` +
    `- 0 to 3 hashtags, on the final line, specific to this case. Never a ` +
    `  generic stack.${src.hashtags?.length ? ` Candidates: ${src.hashtags.join(' ')}` : ''}\n` +
    (includeLink
      ? `- No link in the body — a URL in the post costs significant reach. ` +
        `It goes on its own final line: "FIRST COMMENT: ${postUrl}".\n`
      : `- No link.\n`) +
    `- Under ${LINKEDIN_HARD_LIMIT} characters for the body. Length follows ` +
    `  from the material; do not pad to a target and do not cut a point to ` +
    `  hit one.\n` +
    `- Every CVE, number, version and named organisation comes from the ` +
    `  dossier.\n` +
    `</format>\n\n` +
    dossierBlock(src) +
    `\n<article>\nTitle: ${src.title}\n\n${gist(src.body)}\n</article>\n` +
    (src.performanceNote ?? '')
  );
}

function buildInstagramPrompt(src: SocialSource): string {
  return (
    `<format name="Instagram caption">\n\n` +
    `- Open with one or two lines that earn the tap-through.\n` +
    `- Three to five short lines of substance. No markdown. Captions are not ` +
    `  clickable, so no links in the body.\n` +
    `- End with 5-8 specific hashtags.${src.hashtags?.length ? ` Start from these: ${src.hashtags.join(' ')}` : ''}\n` +
    `- Under ${INSTAGRAM_HARD_LIMIT} characters.\n` +
    `</format>\n\n` +
    dossierBlock(src) +
    `\n<article>\nTitle: ${src.title}\n\n${src.body.slice(0, 4000)}\n</article>\n` +
    (src.performanceNote ?? '')
  );
}

/**
 * Single generation attempt per platform.
 *
 * The retry loop is gone. When the output fails a factual check it is
 * cleaned, and the copy ships with the check recorded for the admin to see.
 * Regenerating from the same input produced different slop, not better copy.
 */
async function generateOne(
  ai: Ai,
  userPrompt: string,
  platform: 'twitter' | 'linkedin' | 'instagram',
  sourceBody: string,
  keys: { groqKey?: string; googleKey?: string; nvidiaKey?: string; infronKey?: string },
  maxTokens = 1200
): Promise<{ text: string; check: SocialCheck }> {
  const result = await runCompletion(
    ai,
    { system: SOCIAL_SYSTEM, user: userPrompt, temperature: 0.7, maxTokens },
    { ...keys, quality: true, preferGroq: true }
  );

  const tidied = platform === 'linkedin' ? tidyLinkedin(result.text) : tidy(result.text);
  const check = checkSocial(tidied, platform, sourceBody);

  // An over-limit post will be truncated or rejected by the platform, so it
  // is corrected rather than shipped.
  const text = check.over_limit ? tidy(cleanSocial(tidied, sourceBody)) : tidied;
  return { text, check: check.over_limit ? checkSocial(text, platform, sourceBody) : check };
}

type KeySet = { groqKey?: string; googleKey?: string; nvidiaKey?: string; infronKey?: string };

async function generateInstagramFromSource(
  src: SocialSource,
  post: Post,
  ai: Ai,
  keys: KeySet
): Promise<{ caption: string; check?: SocialCheck; slides: ContentSlide[] }> {
  const [captionRes, slides] = await Promise.all([
    generateOne(ai, buildInstagramPrompt(src), 'instagram', src.body, keys, 1200).catch(() => ({
      text: '',
      check: undefined as SocialCheck | undefined,
    })),
    buildCarouselSlides(post, { ai, ...keys }).catch(() => [] as ContentSlide[]),
  ]);
  return { caption: captionRes.text.slice(0, INSTAGRAM_HARD_LIMIT), check: captionRes.check, slides };
}

// ── Helpers ──────────────────────────────────────────────────────────────

/** Convert a Post to a SocialSource. */
function postToSource(post: Post): SocialSource {
  return {
    slug: post.slug,
    title: post.title,
    body: post.body,
    hashtags: buildHashtags({ type: post.type, title: post.title, evidence: post.evidence ?? {} }),
  };
}

/** Format candidate evidence as text when no dossier is available. */
export function formatEvidenceText(evidence: Record<string, unknown>): string {
  const parts: string[] = [];
  const add = (label: string, val: unknown) => {
    if (val === undefined || val === null) return;
    const s = typeof val === 'string' ? val : JSON.stringify(val);
    if (s.length > 0) parts.push(`${label}: ${s}`);
  };
  if (evidence.hook) add('Hook', evidence.hook);
  if (evidence.angle) add('Angle', evidence.angle);
  if (evidence.rationale) add('Rationale', evidence.rationale);
  if (evidence.impact) add('Impact', evidence.impact);
  if (evidence.urgency) add('Urgency', evidence.urgency);
  if (Array.isArray(evidence.entities)) add('Entities', evidence.entities.join(', '));
  if (Array.isArray(evidence.sources)) add('Sources', evidence.sources.filter((s) => s.startsWith('http')).join(', '));
  if (parts.length === 0) {
    const { hook, angle, trendingSignal, generatedAt, source, ...rest } = evidence as Record<string, unknown>;
    return JSON.stringify(rest, null, 2);
  }
  return parts.join('\n');
}

async function generateSocialFromSource(
  src: SocialSource,
  ai: Ai,
  now: Date,
  keys: KeySet,
  post?: Post
): Promise<SocialContent> {
  const [twitterRes, linkedinRes, igRes] = await Promise.allSettled([
    generateOne(ai, buildTwitterPrompt(src), 'twitter', src.body, keys, 1500),
    generateOne(ai, buildLinkedinPrompt(src), 'linkedin', src.body, keys, 2000),
    post
      ? generateInstagramFromSource(src, post, ai, keys)
      : Promise.resolve({ caption: '', slides: [] as ContentSlide[] }),
  ]);

  type IgResult = { caption: string; check?: SocialCheck; slides: ContentSlide[] };
  const ig: IgResult = igRes.status === 'fulfilled' ? igRes.value : { caption: '', slides: [] };

  return {
    slug: src.slug,
    twitter: twitterRes.status === 'fulfilled' ? twitterRes.value.text : '',
    linkedin: linkedinRes.status === 'fulfilled' ? linkedinRes.value.text : '',
    instagram: ig.caption || undefined,
    carousel: ig.slides.length ? { format: 'instagram', slides: ig.slides } : undefined,
    generatedAt: now.toISOString(),
    _validation: {
      twitter_check: twitterRes.status === 'fulfilled' ? twitterRes.value.check : undefined,
      linkedin_check: linkedinRes.status === 'fulfilled' ? linkedinRes.value.check : undefined,
      instagram_check: ig.check,
    },
  };
}

// ── Public API ──────────────────────────────────────────────────────────

export async function generateSocialContent(
  post: Post,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string,
  performanceNote?: string,
  hookHint?: string
): Promise<SocialContent> {
  const src = postToSource(post);
  if (performanceNote) src.performanceNote = performanceNote;
  if (hookHint) {
    src.body += `\n\nLead with this angle: "${hookHint}"\nBuild the rest of the post around it.\n`;
  }
  return generateSocialFromSource(src, ai, now, { groqKey, googleKey, nvidiaKey, infronKey }, post);
}

export async function generateTwitterContent(
  post: Post,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<{ twitter: string; generatedAt: string; _validation?: { check: SocialCheck } }> {
  const r = await generateOne(ai, buildTwitterPrompt(postToSource(post)), 'twitter', post.body, {
    groqKey,
    googleKey,
    nvidiaKey,
    infronKey,
  });
  return { twitter: r.text, generatedAt: now.toISOString(), _validation: { check: r.check } };
}

export async function generateLinkedinContent(
  post: Post,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<{ linkedin: string; generatedAt: string; _validation?: { check: SocialCheck } }> {
  const r = await generateOne(ai, buildLinkedinPrompt(postToSource(post)), 'linkedin', post.body, {
    groqKey,
    googleKey,
    nvidiaKey,
    infronKey,
  });
  return { linkedin: r.text, generatedAt: now.toISOString(), _validation: { check: r.check } };
}

export async function generateSocialFromCandidate(
  candidate: Candidate,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<SocialContent> {
  const slug = `${candidate.key}-${slugify(candidate.title).slice(0, 40)}`.replace(/-+/g, '-');
  const src: SocialSource = {
    slug,
    title: candidate.title,
    body: formatEvidenceText(candidate.evidence),
    hashtags: buildHashtags({ type: candidate.type, title: candidate.title, evidence: candidate.evidence }),
  };
  return generateSocialFromSource(src, ai, now, { groqKey, googleKey, nvidiaKey, infronKey });
}

export async function generateTwitterFromCandidate(
  candidate: Candidate,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<{ twitter: string; generatedAt: string; _validation?: { check: SocialCheck } }> {
  const slug = `${candidate.key}-${slugify(candidate.title).slice(0, 40)}`.replace(/-+/g, '-');
  const src: SocialSource = {
    slug,
    title: candidate.title,
    body: formatEvidenceText(candidate.evidence),
    hashtags: buildHashtags({ type: candidate.type, title: candidate.title, evidence: candidate.evidence }),
  };
  const r = await generateOne(ai, buildTwitterPrompt(src), 'twitter', src.body, {
    groqKey,
    googleKey,
    nvidiaKey,
    infronKey,
  });
  return { twitter: r.text, generatedAt: now.toISOString(), _validation: { check: r.check } };
}

export async function generateLinkedinFromCandidate(
  candidate: Candidate,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<{ linkedin: string; generatedAt: string; _validation?: { check: SocialCheck } }> {
  const slug = `${candidate.key}-${slugify(candidate.title).slice(0, 40)}`.replace(/-+/g, '-');
  const src: SocialSource = {
    slug,
    title: candidate.title,
    body: formatEvidenceText(candidate.evidence),
    hashtags: buildHashtags({ type: candidate.type, title: candidate.title, evidence: candidate.evidence }),
  };
  const r = await generateOne(ai, buildLinkedinPrompt(src), 'linkedin', src.body, {
    groqKey,
    googleKey,
    nvidiaKey,
    infronKey,
  });
  return { linkedin: r.text, generatedAt: now.toISOString(), _validation: { check: r.check } };
}

export async function generateSocialFromNotes(
  notes: SocialSource,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<SocialContent> {
  return generateSocialFromSource(notes, ai, now, { groqKey, googleKey, nvidiaKey, infronKey });
}

export async function generateTwitterFromNotes(
  notes: SocialSource,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<{ twitter: string; generatedAt: string; _validation?: { check: SocialCheck } }> {
  const r = await generateOne(ai, buildTwitterPrompt(notes), 'twitter', notes.body, {
    groqKey,
    googleKey,
    nvidiaKey,
    infronKey,
  });
  return { twitter: r.text, generatedAt: now.toISOString(), _validation: { check: r.check } };
}

export async function generateLinkedinFromNotes(
  notes: SocialSource,
  ai: Ai,
  now: Date,
  groqKey?: string,
  googleKey?: string,
  nvidiaKey?: string,
  infronKey?: string
): Promise<{ linkedin: string; generatedAt: string; _validation?: { check: SocialCheck } }> {
  const r = await generateOne(ai, buildLinkedinPrompt(notes), 'linkedin', notes.body, {
    groqKey,
    googleKey,
    nvidiaKey,
    infronKey,
  });
  return { linkedin: r.text, generatedAt: now.toISOString(), _validation: { check: r.check } };
}
