/**
 * Voice profile extraction from real published posts.
 *
 * The content-engine skill says: "build a voice profile from real examples
 * before writing" and "use brand-voice as the canonical workflow when voice
 * consistency matters across more than one output."
 *
 * The existing system has a strong hand-written VOICE_IDENTITY in
 * copywriting.ts — that's the prescriptive voice (what the author SHOULD
 * sound like). This module extracts the DESCRIPTIVE voice (what the author
 * ACTUALLY sounds like) from published posts, so the generation prompts can
 * carry both: the prescriptive rules + a measured profile of the real
 * writing.
 *
 * The profile is deterministic (no LLM call — pure text statistics) so it
 * can run on every generation without cost. It measures:
 *   - Sentence length distribution (the author's rhythm)
 *   - Contraction rate (how casual vs formal)
 *   - Hook form distribution (which of the 8 hook formulas the author leans on)
 *   - Vocabulary markers (the author's domain vocabulary — tools, techniques)
 *   - Structural patterns (section count, bullet density, code-block usage)
 *
 * The output is a compact string injected into the system prompt as
 * <voice_profile> so the model can match the author's real rhythm, not just
 * the prescriptive rules.
 */

import type { PostIndexEntry, Post } from '../types';
import { kvBulkGetText } from '../../lib/safe-catch';
import { kv } from '../kv-keys';

export interface VoiceProfile {
  /** Number of posts analyzed. */
  sampleSize: number;
  /** Average sentence length in words. */
  avgSentenceLength: number;
  /** Median sentence length (less skewed by outliers). */
  medianSentenceLength: number;
  /** Contraction rate: contractions per 100 words. Higher = more casual. */
  contractionRate: number;
  /** Em-dash usage per 1000 words (the voice bans these — a high rate
   *  means the post-process stripper is working overtime). */
  emDashRate: number;
  /** Hook form distribution: which opening patterns the author uses. */
  hookForms: Record<string, number>;
  /** Top domain vocabulary (tools, techniques, frameworks the author names). */
  topVocabulary: Array<{ word: string; count: number }>;
  /** Average sections per post. */
  avgSections: number;
  /** Average bullet density (bullets per post). */
  avgBullets: number;
  /** Code-block usage rate (posts with fenced code / 100 posts). */
  codeBlockRate: number;
  /** First-person usage rate ("I", "we") per 1000 words. */
  firstPersonRate: number;
  /** Generated profile string for prompt injection. */
  profileString: string;
}

/** Hook form patterns — mirrors the 8 formulas in the copywriting rules.
 *  Matched against the opening line of the post (after stripping markdown).
 *  Patterns are flexible: they match the hook's CHARACTER, not its exact
 *  first word — a data-shock hook can start with a named entity followed
 *  by a hard number ("LockBit posted 15 victims"). */
const HOOK_PATTERNS: Array<{ form: string; pattern: RegExp }> = [
  { form: 'contrarian', pattern: /^(stop|don't|never|wrong|myth|unpopular|overrated|won't save)/i },
  // Data-shock: starts with a number OR contains a hard number in the first 60 chars
  { form: 'data-shock', pattern: /^\d|\b\d+\s*(victims|breaches|days|hours|percent|%|million|billion)\b/i },
  { form: 'curiosity-gap', pattern: /^(the one|there's one|nobody|secret|hidden|one (field|rule|thing))/i },
  { form: 'story', pattern: /^(last week|yesterday|at \d|i (almost|found|got|investigated))/i },
  { form: 'list', pattern: /^\d+\s+(things|ways|rules|signs|mistakes|tools)|\b\d+\s+(things|ways|rules)\b/i },
  { form: 'how-to', pattern: /^how to\b/i },
  { form: 'hot-take', pattern: /^(unpopular opinion|hot take|i'll say)/i },
  { form: 'question', pattern: /^(what|why|when|how|can you|do you)\b/i },
];

/** Domain vocabulary — tools, techniques, frameworks the author names.
 *  These are the "save magnet" words that signal practitioner voice. */
const VOCABULARY_WORDS = [
  'sigma',
  'yara',
  'kql',
  'splunk',
  'spl',
  'edr',
  'siem',
  'xdr',
  'mdr',
  'mitre',
  'attack',
  'cve',
  'cvss',
  'kev',
  'cisa',
  'nvd',
  'mfa',
  'phishing',
  'bec',
  'ransomware',
  'infostealer',
  'lateral',
  'detection',
  'hunt',
  'ioc',
  'indicator',
  'telemetry',
  'sysmon',
  'powershell',
  'cobalt',
  'strike',
  'mimikatz',
  'evilginx',
  'dwell',
  'triage',
  'playbook',
  'runbook',
  'soc',
  'dfir',
  'okta',
  'azure',
  'aws',
  'gcp',
  'kubernetes',
  'lockbit',
  'cl0p',
  'alphv',
  'akira',
  'play',
  'royal',
];

const CONTRACTION_RE =
  /\b(you're|don't|can't|won't|it's|that's|we're|we'll|i'm|i've|i'll|isn't|wasn't|weren't|haven't|hasn't|wouldn't|couldn't|shouldn't|didn't|doesn't)\b/gi;
const EM_DASH_RE = /[—–]/g;
const FIRST_PERSON_RE = /\b(i|i'm|i've|i'll|we|we're|we've|we'll)\b/gi;
const SENTENCE_SPLIT_RE = /(?<=[.!?])\s+(?=[A-Z0-9])/;

function median(nums: number[]): number {
  if (nums.length === 0) return 0;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1]! + sorted[mid]!) / 2 : sorted[mid]!;
}

function countWords(text: string): number {
  return text.split(/\s+/).filter(Boolean).length;
}

/** Extract the hook (first sentence/paragraph) from a post body. */
function extractHook(body: string): string {
  // Strip the preamble before the first ## heading, take the first sentence.
  const firstHeading = body.search(/^##\s+/m);
  const preamble = firstHeading >= 0 ? body.slice(0, firstHeading) : body;
  const firstSentence = preamble.split(SENTENCE_SPLIT_RE)[0] ?? preamble;
  return firstSentence.trim().slice(0, 200);
}

/** Classify a hook into one of the 8 forms. */
function classifyHook(hook: string): string | null {
  for (const { form, pattern } of HOOK_PATTERNS) {
    if (pattern.test(hook)) return form;
  }
  return null;
}

/** Count vocabulary word occurrences in a body. */
function countVocabulary(body: string): Map<string, number> {
  const lc = body.toLowerCase();
  const counts = new Map<string, number>();
  for (const word of VOCABULARY_WORDS) {
    // Word-boundary match so "edr" doesn't match inside "bedrock"
    const re = new RegExp(`(?:^|[^a-z0-9])${word}(?:[^a-z0-9]|$)`, 'g');
    const matches = lc.match(re);
    if (matches) counts.set(word, matches.length);
  }
  return counts;
}

/**
 * Build a voice profile from a set of published posts. Pure — no LLM call,
 * no network. Runs on the post index + bodies.
 *
 * @param posts - The posts to analyze. Needs at least 3 for a meaningful
 *   profile; fewer returns a profile with sampleSize noted but lower
 *   confidence.
 */
export function buildVoiceProfile(posts: Post[]): VoiceProfile {
  const sampleSize = posts.length;
  if (sampleSize === 0) {
    return {
      sampleSize: 0,
      avgSentenceLength: 0,
      medianSentenceLength: 0,
      contractionRate: 0,
      emDashRate: 0,
      hookForms: {},
      topVocabulary: [],
      avgSections: 0,
      avgBullets: 0,
      codeBlockRate: 0,
      firstPersonRate: 0,
      profileString:
        '<voice_profile>\nNo published posts to analyze yet. Voice profile will develop as content is published.\n</voice_profile>',
    };
  }

  const allSentences: number[] = [];
  const hookForms: Record<string, number> = {};
  const vocabCounts = new Map<string, number>();
  let totalWords = 0;
  let totalContractions = 0;
  let totalEmDashes = 0;
  let totalFirstPerson = 0;
  let totalSections = 0;
  let totalBullets = 0;
  let postsWithCodeBlocks = 0;

  for (const post of posts) {
    const body = post.body;
    totalWords += countWords(body);

    // Sentence lengths
    const sentences = body.split(SENTENCE_SPLIT_RE).filter((s) => s.trim().length > 0);
    for (const s of sentences) {
      allSentences.push(countWords(s));
    }

    // Contractions, em-dashes, first-person
    totalContractions += (body.match(CONTRACTION_RE) ?? []).length;
    totalEmDashes += (body.match(EM_DASH_RE) ?? []).length;
    totalFirstPerson += (body.match(FIRST_PERSON_RE) ?? []).length;

    // Hook form
    const hook = extractHook(body);
    const form = classifyHook(hook);
    if (form) hookForms[form] = (hookForms[form] ?? 0) + 1;

    // Vocabulary
    const postVocab = countVocabulary(body);
    for (const [word, count] of postVocab) {
      vocabCounts.set(word, (vocabCounts.get(word) ?? 0) + count);
    }

    // Structure
    totalSections += (body.match(/^##\s+.+/gm) ?? []).length;
    totalBullets += (body.match(/^\s*[-*+]\s/gm) ?? []).length;
    if (/```/.test(body)) postsWithCodeBlocks++;
  }

  const avgSentenceLength = allSentences.length > 0 ? allSentences.reduce((a, b) => a + b, 0) / allSentences.length : 0;
  const medianSentenceLength = median(allSentences);
  const contractionRate = totalWords > 0 ? (totalContractions / totalWords) * 100 : 0;
  const emDashRate = totalWords > 0 ? (totalEmDashes / totalWords) * 1000 : 0;
  const firstPersonRate = totalWords > 0 ? (totalFirstPerson / totalWords) * 1000 : 0;
  const avgSections = totalSections / sampleSize;
  const avgBullets = totalBullets / sampleSize;
  const codeBlockRate = (postsWithCodeBlocks / sampleSize) * 100;

  // Top vocabulary (top 15)
  const topVocabulary = [...vocabCounts.entries()]
    .map(([word, count]) => ({ word, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  // Build the prompt-injection string
  const dominantHookForms = Object.entries(hookForms)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([form, count]) => `${form} (${count})`)
    .join(', ');

  const profileString = buildProfileString({
    sampleSize,
    avgSentenceLength,
    medianSentenceLength,
    contractionRate,
    emDashRate,
    hookForms,
    dominantHookForms,
    topVocabulary,
    avgSections,
    avgBullets,
    codeBlockRate,
    firstPersonRate,
  });

  return {
    sampleSize,
    avgSentenceLength: Number(avgSentenceLength.toFixed(1)),
    medianSentenceLength: Number(medianSentenceLength.toFixed(1)),
    contractionRate: Number(contractionRate.toFixed(1)),
    emDashRate: Number(emDashRate.toFixed(1)),
    hookForms,
    topVocabulary,
    avgSections: Number(avgSections.toFixed(1)),
    avgBullets: Number(avgBullets.toFixed(1)),
    codeBlockRate: Number(codeBlockRate.toFixed(0)),
    firstPersonRate: Number(firstPersonRate.toFixed(1)),
    profileString,
  };
}

function buildProfileString(p: {
  sampleSize: number;
  avgSentenceLength: number;
  medianSentenceLength: number;
  contractionRate: number;
  emDashRate: number;
  hookForms: Record<string, number>;
  dominantHookForms: string;
  topVocabulary: Array<{ word: string; count: number }>;
  avgSections: number;
  avgBullets: number;
  codeBlockRate: number;
  firstPersonRate: number;
}): string {
  const lines: string[] = [
    '<voice_profile>',
    `Derived from ${p.sampleSize} published post(s). Match this rhythm:`,
    `- Sentence length: avg ${p.avgSentenceLength} words, median ${p.medianSentenceLength}. Vary rhythm — short punch then longer analytical sentence.`,
    `- Contraction rate: ${p.contractionRate}/100 words. ${p.contractionRate > 3 ? 'Casual, conversational — use contractions freely.' : 'Formal-leaning — use contractions sparingly.'}`,
    `- First-person rate: ${p.firstPersonRate}/1000 words. ${p.firstPersonRate > 5 ? 'The author writes in first person — "I", "we" are natural.' : 'The author writes in third person — lead with the finding, not the author.'}`,
  ];

  if (p.emDashRate > 2) {
    lines.push(
      `- Em-dash rate: ${p.emDashRate}/1000 words (HIGH — the voice bans em-dashes; the post-process strips them. Write periods or commas instead.)`
    );
  }

  if (p.dominantHookForms) {
    lines.push(`- Dominant hook forms: ${p.dominantHookForms}. Rotate — don't reuse the same form twice in a row.`);
  }

  if (p.topVocabulary.length > 0) {
    const topWords = p.topVocabulary
      .slice(0, 8)
      .map((v) => v.word)
      .join(', ');
    lines.push(
      `- Domain vocabulary the author uses: ${topWords}. Name tools and techniques by name, don't generalize.`
    );
  }

  lines.push(
    `- Structure: avg ${p.avgSections} sections, ${p.avgBullets} bullets per post. ${p.codeBlockRate}% of posts include code blocks (detection artifacts).`
  );

  lines.push(
    "This is the DESCRIPTIVE voice (what the author actually sounds like). The prescriptive rules in #WHO YOU ARE and #COPYWRITING RULES still govern — this profile helps you match the author's real rhythm, not override the rules."
  );
  lines.push('</voice_profile>');

  return lines.join('\n');
}

/**
 * Fetch published posts from KV and build a voice profile. Capped at the
 * most recent 50 posts (enough for a stable profile without reading the
 * entire index). The profile is cached in KV with a 24h TTL so it's not
 * rebuilt on every generation.
 */
const VOICE_PROFILE_KV_KEY = 'meta:voice-profile';
const VOICE_PROFILE_TTL = 24 * 3600; // 24h

export interface VoiceProfileCacheEntry {
  profile: VoiceProfile;
  builtAt: string; // ISO
  postCount: number;
}

/** Build a voice profile from the post index + bodies. */
export async function buildVoiceProfileFromIndex(ns: KVNamespace, maxPosts = 50): Promise<VoiceProfile> {
  // Read the cached profile first (24h TTL)
  try {
    const cached = await ns.get<VoiceProfileCacheEntry>(VOICE_PROFILE_KV_KEY, 'json');
    if (cached) {
      const age = Date.now() - Date.parse(cached.builtAt);
      if (age < VOICE_PROFILE_TTL * 1000) {
        return cached.profile;
      }
    }
  } catch {
    // cache miss — rebuild
  }

  // Fetch the post index, then the most recent N post bodies
  const { listPostIndex } = await import('../storage/posts');
  const index = await listPostIndex(ns);
  // Sort by publishedAt desc, take the most recent N
  const recent = [...index].sort((a, b) => (b.publishedAt ?? '').localeCompare(a.publishedAt ?? '')).slice(0, maxPosts);

  // Fetch post bodies — ONE bulk read instead of N individual gets.
  //
  // Two problems were fixed here:
  //   1. KEY BUG. The old code read `post:${entry.slug}`, but the canonical
  //      key is `posts:${slug}` (`kv.post()` in kv-keys.ts, written by
  //      `putPost`). Every one of those reads missed and returned null, so
  //      `posts` was ALWAYS empty and `buildVoiceProfile([])` produced a
  //      profile from zero real examples. Now routed through `kv.post()`,
  //      which is also the fix if the key format ever changes again — the
  //      old literal was a second, silently-drifting source of truth.
  //   2. SUBREQUEST COST. 50 sequential gets is 50 subrequests out of the
  //      free plan's 50/invocation budget — the entire request budget for
  //      one rebuild. `kvBulkGetText` does it in 1.
  const posts: Post[] = [];
  const raw = await kvBulkGetText(
    ns,
    recent.map((entry: PostIndexEntry) => kv.post(entry.slug))
  );
  for (const entry of recent) {
    const text = raw.get(kv.post(entry.slug));
    if (!text) continue;
    try {
      const post = JSON.parse(text) as Post;
      if (post?.body) posts.push(post);
    } catch {
      // skip unreadable posts
    }
  }

  const profile = buildVoiceProfile(posts);

  // Cache it
  try {
    const entry: VoiceProfileCacheEntry = {
      profile,
      builtAt: new Date().toISOString(),
      postCount: posts.length,
    };
    await ns.put(VOICE_PROFILE_KV_KEY, JSON.stringify(entry));
  } catch {
    // non-critical — the profile still returns
  }

  return profile;
}

/** Get the voice profile string for prompt injection (cached, 24h TTL). */
export async function getVoiceProfileString(ns: KVNamespace): Promise<string> {
  try {
    const profile = await buildVoiceProfileFromIndex(ns);
    return profile.profileString;
  } catch {
    // If anything fails, return an empty string — the prescriptive
    // VOICE_IDENTITY in the prompt still governs.
    return '';
  }
}
