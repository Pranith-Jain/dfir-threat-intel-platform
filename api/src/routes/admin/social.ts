import { Hono } from 'hono';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../../env';
import { logError } from '../../lib/logger';
import { badRequest, notFound, serviceUnavailable, internalError } from '../../lib/api-error';
import { safeJsonBody } from '../../lib/safe-body';
import { getAi } from '../../lib/ai-binding';
import {
  getSocialSchedule,
  upsertSocialSchedule,
  markSocialPosted,
  isSocialPlatform,
  approveSocialPlatform,
  unapproveSocialPlatform,
  readAutopostQueue,
} from '../../case-study/storage/social-schedule';
import { getAllMetrics, upsertMetric } from '../../case-study/storage/social-metrics';
import { kvBulkGetText } from '../../lib/safe-catch';
import { computeTypePerformance, engagementScore, type MetricsRecord } from '../../case-study/analytics/analytics';
import { postToTwitter, postToLinkedin } from '../../case-study/posting/social-poster';
import { notifySocialFailed, type WebhookEnv } from '../../case-study/notifications';
import {
  generateSocialContent,
  generateTwitterContent,
  generateLinkedinContent,
} from '../../case-study/generation/social';
import { getTopPerformingTypes, buildPerformanceNote } from '../../case-study/analytics/content-performance';
import { kv as csKvKeys } from '../../case-study/kv-keys';
import type { SocialContent } from '../../case-study/types';
import { listPostIndex } from '../../case-study/storage/posts';
import { validSlug, getPostOrDraft, fetchOgCardPng } from './shared';
import { renderCarouselSlideSvg } from '../../case-study/social/carousel-svg';
import { carouselSlideToPng } from '../../lib/social-carousel-raster';

export const socialRouter = new Hono<{ Bindings: Env }>();

socialRouter.get('/social-schedule/:slug', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const schedule = await getSocialSchedule(c.env.CASE_STUDIES, slug);
  return c.json({ schedule });
});

socialRouter.post('/social-schedule/:slug/:platform/mark-posted', async (c) => {
  const slug = c.req.param('slug');
  const platform = c.req.param('platform');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  if (!isSocialPlatform(platform)) return badRequest(c, 'platform must be twitter, linkedin, or instagram');
  const schedule = await markSocialPosted(c.env.CASE_STUDIES, slug, platform);
  return c.json({ ok: true, schedule });
});

socialRouter.post('/social-schedule/:slug/:platform/approve', async (c) => {
  const slug = c.req.param('slug');
  const platform = c.req.param('platform');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  if (!isSocialPlatform(platform)) return badRequest(c, 'platform must be twitter, linkedin, or instagram');

  const socialKey =
    platform === 'twitter'
      ? csKvKeys.socialTwitter(slug)
      : platform === 'linkedin'
        ? csKvKeys.socialLinkedin(slug)
        : csKvKeys.social(slug);
  const socialText = await c.env.CASE_STUDIES.get<string>(socialKey);
  if (socialText) {
    const hasLink = /^[ \t]*FIRST (COMMENT|REPLY):[ \t]*https?:\/\/[^\s]+$/im.test(socialText);
    if (!hasLink) {
      return c.json(
        {
          error: 'no_link_in_content',
          hint: `The ${platform} content has no FIRST REPLY / FIRST COMMENT link. Generate or edit the copy to include one before approving.`,
        },
        400
      );
    }
  }

  const parsed = await safeJsonBody<{ scheduledAt?: string }>(c, { maxBytes: 1024 });
  if ('error' in parsed) return parsed.error;
  let scheduledAt: string | undefined;
  const at = parsed.value?.scheduledAt ?? '';
  if (at !== '') {
    if (Number.isNaN(Date.parse(at))) return badRequest(c, 'invalid scheduledAt');
    scheduledAt = new Date(at).toISOString();
  } else {
    scheduledAt = new Date().toISOString();
  }
  const schedule = await approveSocialPlatform(c.env.CASE_STUDIES, slug, platform, new Date(), scheduledAt);
  return c.json({ ok: true, schedule });
});

socialRouter.post('/social-schedule/:slug/:platform/unapprove', async (c) => {
  const slug = c.req.param('slug');
  const platform = c.req.param('platform');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  if (!isSocialPlatform(platform)) return badRequest(c, 'platform must be twitter, linkedin, or instagram');
  const schedule = await unapproveSocialPlatform(c.env.CASE_STUDIES, slug, platform);
  return c.json({ ok: true, schedule });
});

socialRouter.get('/social-queue', async (c) => {
  const queue = await readAutopostQueue(c.env.CASE_STUDIES);
  const bySlug = new Map<string, NonNullable<Awaited<ReturnType<typeof getSocialSchedule>>> | null>();
  const items: Array<{
    slug: string;
    platform: string;
    status: string;
    scheduledAt?: string;
    postUrl?: string;
    error?: string;
    attempts?: number;
  }> = [];
  // Dedupe slugs FIRST, then ONE batched KV read for all schedules. The old
  // loop awaited one KV get per unique slug inline (up to MAX_SCHEDULE_READS
  // = 40 sequential subrequests, brushing the free-plan 50 cap); a batch
  // `get(keys[])` counts as ONE subrequest per ≤100-key chunk regardless of
  // key count. Same total data, a fraction of the subrequest budget.
  const MAX_SCHEDULE_READS = 40;
  const slugs: string[] = [];
  for (const q of queue) {
    if (!bySlug.has(q.slug)) {
      if (slugs.length >= MAX_SCHEDULE_READS) break;
      slugs.push(q.slug);
    }
  }
  if (slugs.length > 0) {
    const rawSchedules = await kvBulkGetText(
      c.env.CASE_STUDIES,
      slugs.map((s) => csKvKeys.socialSchedule(s))
    );
    for (const s of slugs) {
      const raw = rawSchedules.get(csKvKeys.socialSchedule(s));
      if (!raw) {
        bySlug.set(s, null);
        continue;
      }
      try {
        bySlug.set(s, JSON.parse(raw) as NonNullable<Awaited<ReturnType<typeof getSocialSchedule>>>);
      } catch {
        bySlug.set(s, null);
      }
    }
  }
  for (const q of queue) {
    const entry = bySlug.get(q.slug)?.[q.platform];
    if (!entry) continue;
    items.push({
      slug: q.slug,
      platform: q.platform,
      status: entry.status,
      scheduledAt: entry.scheduledAt,
      postUrl: entry.postUrl,
      error: entry.error,
      attempts: entry.attempts,
    });
  }
  items.sort((a, b) => (a.scheduledAt ?? '').localeCompare(b.scheduledAt ?? ''));
  return c.json({ autopostEnabled: c.env.SOCIAL_AUTOPOST_ENABLED === 'true', queue: items });
});

socialRouter.get('/social-analytics', async (c) => {
  const records = await getAllMetrics(c.env.CASE_STUDIES);
  const posts = records
    .map((r) => ({ ...r, engagement: engagementScore(r.metrics) }))
    .sort((a, b) => b.engagement - a.engagement);
  return c.json({ posts, byType: computeTypePerformance(records) });
});

socialRouter.post('/social-metrics/:slug/:platform', async (c) => {
  const slug = c.req.param('slug');
  const platform = c.req.param('platform');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  if (!isSocialPlatform(platform)) return badRequest(c, 'platform must be twitter, linkedin, or instagram');
  const parsed = await safeJsonBody<{
    impressions?: number;
    likes?: number;
    reposts?: number;
    replies?: number;
    clicks?: number;
    postUrl?: string;
  }>(c, { maxBytes: 1024 });
  if ('error' in parsed) return parsed.error;
  const b = parsed.value ?? {};
  const num = (x: unknown) => (typeof x === 'number' && Number.isFinite(x) && x >= 0 ? x : undefined);
  const index = await listPostIndex(c.env.CASE_STUDIES);
  const entry = index.find((e) => e.slug === slug);
  const record: MetricsRecord = {
    slug,
    platform,
    type: entry?.type ?? 'analysis',
    postUrl: typeof b.postUrl === 'string' ? b.postUrl : undefined,
    metrics: {
      impressions: num(b.impressions),
      likes: num(b.likes),
      reposts: num(b.reposts),
      replies: num(b.replies),
      clicks: num(b.clicks),
    },
    fetchedAt: new Date().toISOString(),
  };
  await upsertMetric(c.env.CASE_STUDIES, record);
  return c.json({ ok: true, record });
});

socialRouter.post('/social-schedule/:slug/:platform', async (c) => {
  const slug = c.req.param('slug');
  const platform = c.req.param('platform');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  if (!isSocialPlatform(platform)) return badRequest(c, 'platform must be twitter, linkedin, or instagram');
  type ScheduleStatus = 'pending' | 'approved' | 'posted' | 'failed';
  const parsed = await safeJsonBody<{ scheduledAt?: string; status?: ScheduleStatus }>(c, { maxBytes: 1024 });
  if ('error' in parsed) return parsed.error;
  const patch: { scheduledAt?: string; status?: ScheduleStatus } = {};
  if (parsed.value && 'scheduledAt' in parsed.value) {
    const at = parsed.value.scheduledAt ?? '';
    if (at !== '' && Number.isNaN(Date.parse(at))) return badRequest(c, 'invalid scheduledAt');
    patch.scheduledAt = at === '' ? undefined : new Date(at).toISOString();
  }
  const ALLOWED_STATUS: ScheduleStatus[] = ['pending', 'approved', 'posted', 'failed'];
  if (parsed.value?.status !== undefined) {
    if (!ALLOWED_STATUS.includes(parsed.value.status)) return badRequest(c, 'invalid status');
    patch.status = parsed.value.status;
  }
  const schedule = await upsertSocialSchedule(c.env.CASE_STUDIES, slug, platform, patch);
  return c.json({ ok: true, schedule });
});

// ─── Social content generation (combined Twitter + LinkedIn) ──────────
socialRouter.post('/social/:slug', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const post = await getPostOrDraft(c.env, slug);
  if (!post) return notFound(c, 'post not found');

  let performanceNote: string | undefined;
  try {
    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (db) {
      const top = await getTopPerformingTypes(db, 3);
      performanceNote = buildPerformanceNote(top);
    }
  } catch {}

  try {
    const social = await generateSocialContent(
      post,
      getAi(c.env),
      new Date(),
      c.env.GROQ_API_KEY,
      c.env.GOOGLE_AI_STUDIO_API_KEY,
      c.env.NVIDIA_API_KEY as string | undefined,
      c.env.INFRON_API_KEY,
      performanceNote
    );
    await c.env.CASE_STUDIES.put(csKvKeys.social(slug), JSON.stringify(social));
    return c.json({ ok: true, social });
  } catch (err) {
    logError('social generation failed:', err);
    return internalError(c, 'social_generation_failed');
  }
});

// ─── A/B hook selection — regenerate social copy with a chosen hook ──
socialRouter.post('/social/:slug/use-hook', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const { hook } = await c.req.json<{ hook?: string }>();
  if (!hook || typeof hook !== 'string') return badRequest(c, 'hook required');

  const post = await getPostOrDraft(c.env, slug);
  if (!post) return notFound(c, 'post not found');

  try {
    const social = await generateSocialContent(
      post,
      getAi(c.env),
      new Date(),
      c.env.GROQ_API_KEY,
      c.env.GOOGLE_AI_STUDIO_API_KEY,
      c.env.NVIDIA_API_KEY as string | undefined,
      c.env.INFRON_API_KEY,
      undefined,
      hook
    );
    await c.env.CASE_STUDIES.put(csKvKeys.social(slug), JSON.stringify(social));
    return c.json({ ok: true, social });
  } catch (err) {
    logError('use-hook regeneration failed:', err);
    return internalError(c, 'hook_regeneration_failed');
  }
});

socialRouter.get('/social-index', async (c) => {
  const ns = c.env.CASE_STUDIES;
  const index: Record<string, { twitter: boolean; linkedin: boolean }> = {};
  const mark = (slug: string, patch: Partial<{ twitter: boolean; linkedin: boolean }>) => {
    index[slug] = { twitter: false, linkedin: false, ...index[slug], ...patch };
  };
  let cursor: string | undefined;
  for (let page = 0; page < 10; page += 1) {
    const res = await ns.list({ prefix: 'social:', cursor });
    for (const k of res.keys) {
      const rest = k.name.slice('social:'.length);
      if (rest.startsWith('standalone:')) continue;
      if (rest.endsWith(':twitter')) mark(rest.slice(0, -':twitter'.length), { twitter: true });
      else if (rest.endsWith(':linkedin')) mark(rest.slice(0, -':linkedin'.length), { linkedin: true });
      else if (rest && !rest.includes(':')) mark(rest, { twitter: true, linkedin: true });
    }
    if (res.list_complete) break;
    cursor = res.cursor;
  }
  return c.json({ index });
});

// ─── Carousel slide PNG render (on-demand, admin-gated) ───────────────
// GET /api/v1/admin/social/carousel/:slug/:i.png
// Must be registered BEFORE /social/:slug to avoid the wildcard catching
// "carousel" as the slug value. Hono matches in registration order.
socialRouter.get('/social/carousel/:slug/:file', async (c) => {
  const slug = c.req.param('slug');
  const fileParam = c.req.param('file');
  const fileMatch = fileParam.match(/^(\d+)\.png$/);
  if (!fileMatch) return c.notFound();
  const i = Number(fileMatch[1]);
  if (!validSlug(slug)) return badRequest(c, 'bad slug');
  const social = await c.env.CASE_STUDIES.get<SocialContent>(`social:${slug}`, 'json');
  const slides = social?.carousel?.slides;
  if (!slides || i < 0 || i >= slides.length || !slides[i]) return c.notFound();
  const svg = renderCarouselSlideSvg(slides[i]!, { index: i, total: slides.length });
  const png = await carouselSlideToPng(c.env as Parameters<typeof carouselSlideToPng>[0], svg);
  return new Response(png, {
    headers: { 'content-type': 'image/png', 'cache-control': 'private, max-age=300' },
  });
});

socialRouter.get('/social/:slug', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const [combined, twitter, linkedin] = await Promise.all([
    c.env.CASE_STUDIES.get<SocialContent>(csKvKeys.social(slug), 'json'),
    c.env.CASE_STUDIES.get<string>(csKvKeys.socialTwitter(slug)),
    c.env.CASE_STUDIES.get<string>(csKvKeys.socialLinkedin(slug)),
  ]);
  // Return the full combined social object (which carries `_validation`,
  //  instagram, carousel and hooks) so the frontend can surface the
  //  per-platform factual checks. Fall back to a minimal reconstruction only
  //  when the combined blob is absent (legacy posts generated before the
  //  `_validation` field existed).
  let social: SocialContent;
  if (combined) {
    // Override twitter/linkedin with the per-platform blobs when they exist
    // (the admin can regenerate one platform independently — those land in
    //  separate KV keys, not back in the combined blob).
    social = {
      ...combined,
      twitter: twitter ?? combined.twitter,
      linkedin: linkedin ?? combined.linkedin,
    };
  } else {
    social = {
      slug,
      twitter: twitter ?? '',
      linkedin: linkedin ?? '',
      generatedAt: new Date().toISOString(),
    };
  }
  if (!social.twitter && !social.linkedin) return notFound(c, 'not found');
  return c.json({ ok: true, social });
});

socialRouter.delete('/social/:slug', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  await Promise.all([
    c.env.CASE_STUDIES.delete(csKvKeys.social(slug)),
    c.env.CASE_STUDIES.delete(csKvKeys.socialTwitter(slug)),
    c.env.CASE_STUDIES.delete(csKvKeys.socialLinkedin(slug)),
  ]);
  return c.json({ ok: true });
});

// ─── Individual social platform generation ────────────────────────────
socialRouter.post('/social/:slug/twitter', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const post = await getPostOrDraft(c.env, slug);
  if (!post) return notFound(c, 'post not found');

  try {
    const { twitter, generatedAt } = await generateTwitterContent(
      post,
      getAi(c.env),
      new Date(),
      c.env.GROQ_API_KEY,
      c.env.GOOGLE_AI_STUDIO_API_KEY,
      c.env.NVIDIA_API_KEY as string | undefined,
      c.env.INFRON_API_KEY
    );
    await c.env.CASE_STUDIES.put(csKvKeys.socialTwitter(slug), twitter);
    return c.json({ ok: true, platform: 'twitter', content: twitter, generatedAt });
  } catch (err) {
    logError('twitter generation failed:', err);
    return c.json(
      { error: 'twitter_generation_failed', detail: err instanceof Error ? err.message : String(err) },
      500
    );
  }
});

socialRouter.post('/social/:slug/linkedin', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const post = await getPostOrDraft(c.env, slug);
  if (!post) return notFound(c, 'post not found');

  try {
    const { linkedin, generatedAt } = await generateLinkedinContent(
      post,
      getAi(c.env),
      new Date(),
      c.env.GROQ_API_KEY,
      c.env.GOOGLE_AI_STUDIO_API_KEY,
      c.env.NVIDIA_API_KEY as string | undefined,
      c.env.INFRON_API_KEY
    );
    await c.env.CASE_STUDIES.put(csKvKeys.socialLinkedin(slug), linkedin);
    return c.json({ ok: true, platform: 'linkedin', content: linkedin, generatedAt });
  } catch (err) {
    logError('linkedin generation failed:', err);
    return c.json(
      { error: 'linkedin_generation_failed', detail: err instanceof Error ? err.message : String(err) },
      500
    );
  }
});

// ─── Post to social platforms ──────────────────────────────────────
// `?dry_run=true` composes exactly what WOULD be posted (content + image
// attach decision) and returns it without publishing or marking posted —
// the n8n workflow's Slack dry-run lane, in-process.

socialRouter.post('/social/:slug/post-twitter', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const dryRun = c.req.query('dry_run') === 'true';

  const social = await c.env.CASE_STUDIES.get<string>(csKvKeys.socialTwitter(slug));
  if (!social) return badRequest(c, 'no_twitter_content — generate social content first');

  if (dryRun) {
    return c.json({ ok: true, dry_run: true, platform: 'twitter', final_post: social });
  }

  const image = await fetchOgCardPng(c.env, 'blog', slug);
  const result = await postToTwitter(
    social,
    {
      apiKey: c.env.X_API_KEY ?? '',
      apiKeySecret: c.env.X_API_KEY_SECRET ?? '',
      accessToken: c.env.X_ACCESS_TOKEN ?? '',
      accessTokenSecret: c.env.X_ACCESS_TOKEN_SECRET ?? '',
    },
    image
  );

  if (!result.ok) {
    notifySocialFailed(c.env as unknown as WebhookEnv, slug, 'twitter', result.error ?? 'unknown').catch((err) =>
      logError('notifySocialFailed (twitter) failed', err)
    );
    return c.json(result, 400);
  }

  await markSocialPosted(c.env.CASE_STUDIES, slug, 'twitter');
  return c.json(result);
});

socialRouter.post('/social/:slug/post-linkedin', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const dryRun = c.req.query('dry_run') === 'true';

  if (!dryRun && !c.env.LINKEDIN_ACCESS_TOKEN) {
    return serviceUnavailable(c, 'linkedin_token_missing');
  }

  const image = await fetchOgCardPng(c.env, 'blog', slug);

  const social = await c.env.CASE_STUDIES.get<string>(csKvKeys.socialLinkedin(slug));
  const linkedinFromCombined =
    social ?? (await c.env.CASE_STUDIES.get<SocialContent>(csKvKeys.social(slug), 'json'))?.linkedin ?? undefined;
  if (!linkedinFromCombined) return badRequest(c, 'no_linkedin_content — generate social content first');

  if (dryRun) {
    return c.json({
      ok: true,
      dry_run: true,
      platform: 'linkedin',
      final_post: linkedinFromCombined,
      image_attached: !!image,
    });
  }

  const result = await postToLinkedin(
    linkedinFromCombined,
    // Guarded above: non-dry-run requires the token.
    (c.env.LINKEDIN_ACCESS_TOKEN ?? '') as string,
    image
  );
  if (!result.ok) {
    notifySocialFailed(c.env as unknown as WebhookEnv, slug, 'linkedin', result.error ?? 'unknown').catch((err) =>
      logError('notifySocialFailed (linkedin) failed', err)
    );
    return c.json(result, 400);
  }

  await markSocialPosted(c.env.CASE_STUDIES, slug, 'linkedin');
  return c.json(result);
});
