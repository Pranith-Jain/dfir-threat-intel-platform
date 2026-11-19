import { Hono } from 'hono';
import type { Env } from '../../env';
import { logError } from '../../lib/logger';
import { badRequest, conflict } from '../../lib/api-error';
import { safeJsonBody } from '../../lib/safe-body';
import { putPost, listPostIndex, removePost } from '../../case-study/storage/posts';
import { upsertCsPostD1, deleteCsPostD1 } from '../../case-study/storage/cs-posts-d1';
import { renderHeroSvg } from '../../case-study/generation/hero-svg';
import { getSchedule, setSchedule } from '../../case-study/storage/schedule';
import { generateSocialForPost, type CaseStudyEnv } from '../../case-study/run';
import { buildVoiceProfileFromIndex } from '../../case-study/generation/voice-profile';
import { kv as csKvKeys } from '../../case-study/kv-keys';
import { renderRss } from '../../case-study/rendering/rss';
import { getSiteUrl } from '../../lib/site-config';
import type { CaseStudyType, Post, PostIOC, PostSource } from '../../case-study/types';
import { validSlug, TYPES } from './shared';

export const postsRouter = new Hono<{ Bindings: Env }>();

postsRouter.get('/posts', async (c) => {
  return c.json({ posts: await listPostIndex(c.env.CASE_STUDIES) });
});

postsRouter.post('/posts/:slug/unpublish', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  await removePost(c.env.CASE_STUDIES, slug);
  // KV is the source of truth for the blog, but D1 mirrors published posts
  // for unified search. Without this the search index keeps a ghost result.
  if (c.env.BRIEFINGS_DB) {
    try {
      await deleteCsPostD1(c.env.BRIEFINGS_DB, slug);
    } catch (err) {
      logError('deleteCsPostD1 failed', err);
    }
  }
  // Clean up schedule slots referencing this slug
  const schedule = await getSchedule(c.env.CASE_STUDIES);
  const updated = schedule.map((s) =>
    s.publishedSlug === slug ? { ...s, status: 'pending' as const, publishedSlug: undefined } : s
  );
  if (updated.some((s, i) => s.status !== schedule[i]?.status)) {
    await setSchedule(c.env.CASE_STUDIES, updated);
  }
  return c.json({ ok: true });
});

// ─── Manual post creation ───────────────────────────────────────────────
// Bypasses the entire discovery → approve → plan → publish pipeline.
// Accepts user-written markdown and publishes it immediately.
postsRouter.post('/posts/manual', async (c) => {
  // Body bounded to 256 KB — generous for a long-form markdown post with
  // sources + IOCs, but well under the worker memory ceiling. Depth 6
  // covers `iocs[i].…` (3) plus headroom.
  const parsed = await safeJsonBody<{
    type: CaseStudyType;
    title: string;
    body: string;
    tags?: string[];
    sources?: PostSource[];
    iocs?: PostIOC[];
  }>(c, { maxBytes: 256 * 1024, maxDepth: 6 });
  if ('error' in parsed) return parsed.error;
  const { type, title, body, tags, sources, iocs } = parsed.value;

  if (!TYPES.includes(type)) return badRequest(c, 'invalid type');
  if (!title || !body) return badRequest(c, 'title and body required');
  if (sources) {
    for (let i = 0; i < sources.length; i++) {
      const s = sources[i];
      if (!s || typeof s.url !== 'string') return badRequest(c, `sources[${i}].url must be a string`);
      try {
        const u = new URL(s.url);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error();
        if (!u.hostname.includes('.')) throw new Error();
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return badRequest(c, `sources[${i}].url is not a valid HTTP URL: ${s.url}`);
      }
    }
  }

  const baseSlug = title
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 80);
  // Manual titles previously silently overwrote any existing post with the
  // same slug. Append `-2`, `-3`, … until we find a free slug instead.
  let slug = baseSlug;
  let suffix = 2;
  while ((await c.env.CASE_STUDIES.get(csKvKeys.post(slug))) !== null) {
    slug = `${baseSlug}-${suffix}`.slice(0, 80);
    suffix += 1;
    if (suffix > 50) return conflict(c, 'too many slug collisions');
  }

  const now = new Date().toISOString();
  const post: Post = {
    slug,
    type,
    title,
    excerpt: body
      .replace(/^##.*$/gm, '')
      .replace(/[`*_>#-]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 200),
    publishedAt: now,
    candidateId: `manual-${slug}`,
    body,
    // Manual posts have no AI illustration; use the same typographic SVG
    // the generation pipeline emits so the blog hero is never an empty src.
    hero: renderHeroSvg({ title, type }),
    iocs: iocs ?? [],
    tags: tags ?? [type],
    sources: sources ?? [],
  };

  const postIndex = await putPost(c.env.CASE_STUDIES, post);

  // Keep D1/unified search in step with KV for manually published posts too.
  if (c.env.BRIEFINGS_DB) {
    try {
      await upsertCsPostD1(c.env.BRIEFINGS_DB, post);
    } catch (err) {
      logError('upsertCsPostD1 failed', err);
    }
  }

  // RSS only needs index-level fields; reuse the index putPost just wrote
  // instead of re-reading posts:index from KV.
  const rss = renderRss(postIndex, { siteUrl: getSiteUrl(c.env) });
  await c.env.CASE_STUDIES.put(csKvKeys.metaRss, rss);

  generateSocialForPost(slug, c.env as unknown as CaseStudyEnv, new Date()).catch((err) =>
    logError('auto-social failed', err)
  );

  return c.json({ ok: true, slug });
});

// ─── Voice profile ─────────────────────────────────────────────────────
// Returns the descriptive voice profile derived from published posts.
// The operator can inspect what the author's real writing rhythm looks
// like (sentence length, contraction rate, hook forms, vocabulary) and
// how it compares to the prescriptive VOICE_IDENTITY rules.
postsRouter.get('/voice-profile', async (c) => {
  const profile = await buildVoiceProfileFromIndex(c.env.CASE_STUDIES);
  return c.json({ profile });
});
