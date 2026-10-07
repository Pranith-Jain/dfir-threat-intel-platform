import { Hono } from 'hono';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../../env';
import { logError } from '../../lib/logger';
import { badRequest, notFound } from '../../lib/api-error';
import { safeJsonBody } from '../../lib/safe-body';
import { getAi } from '../../lib/ai-binding';
import { listDraftIndex, getDraft, approveDraft, rejectDraft, putDraft } from '../../case-study/storage/drafts';
import { getCandidate } from '../../case-study/storage/candidates';
import { removeSlot } from '../../case-study/storage/schedule';
import { renderMarkdown } from '../../case-study/rendering/markdown';
import { postProcess } from '../../case-study/generation/post-process';
import { generatePost } from '../../case-study/generation';
import { generateSocialForPost, type CaseStudyEnv } from '../../case-study/run';
import type { WebhookEnv } from '../../case-study/notifications';
import { notifyPublished } from '../../case-study/notifications';
import { listPostIndex } from '../../case-study/storage/posts';
import { kv as csKvKeys } from '../../case-study/kv-keys';
import { renderRss } from '../../case-study/rendering/rss';
import { getSiteUrl } from '../../lib/site-config';
import type { Candidate, Post } from '../../case-study/types';
import { validSlug } from './shared';

export const draftsRouter = new Hono<{ Bindings: Env }>();

draftsRouter.get('/drafts', async (c) => {
  return c.json({
    drafts: await listDraftIndex(c.env.CASE_STUDIES),
    approvalRequired: c.env.BLOG_APPROVAL_REQUIRED === 'true',
  });
});

draftsRouter.get('/drafts/:slug', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const draft = await getDraft(c.env.CASE_STUDIES, slug);
  if (!draft) return notFound(c, 'not found');
  // Render markdown server-side so the admin preview matches exactly
  // what visitors will see post-approval (same sanitiser + linkify pass).
  const bodyHtml = renderMarkdown(draft.body);
  return c.json({ post: draft, bodyHtml });
});

draftsRouter.post('/drafts/:slug/approve', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const now = new Date();
  const promoted = await approveDraft(c.env.CASE_STUDIES, slug, now);
  if (!promoted) return notFound(c, 'not found');
  // Refresh RSS so the new post shows up in the feed immediately, same
  // as the auto-publish flow does.
  const rss = renderRss(await listPostIndex(c.env.CASE_STUDIES), { siteUrl: getSiteUrl(c.env) });
  await c.env.CASE_STUDIES.put(csKvKeys.metaRss, rss);

  generateSocialForPost(promoted.slug, c.env as unknown as CaseStudyEnv, now).catch((err) =>
    logError('auto-social failed', err)
  );

  notifyPublished(c.env as unknown as WebhookEnv, promoted.slug, promoted.title, promoted.type).catch((err) =>
    logError('notifyPublished failed', err)
  );

  // Mirror to D1 for search
  const d1 = c.env.BRIEFINGS_DB as D1Database | undefined;
  if (d1) {
    void import('../../case-study/storage/cs-posts-d1')
      .then(({ upsertCsPostD1 }) => upsertCsPostD1(d1, promoted).catch((err) => logError('upsertCsPostD1 failed', err)))
      .catch(() => {});
  }

  return c.json({ ok: true, slug: promoted.slug, approvedAt: promoted.approvedAt });
});

draftsRouter.post('/drafts/:slug/reject', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  // Clean up the schedule slot the publisher parked this draft under.
  // The draft Post carries the original candidateId; without this the
  // slot stays `status: 'draft'` pointing at nothing, and the next
  // hourly publisher tick records an `approved candidate missing`
  // failure for it. Mirrors what /approved/:id/unapprove does for the
  // non-draft path (which already calls removeSlot).
  const draft = await getDraft(c.env.CASE_STUDIES, slug);
  if (draft?.candidateId) {
    await removeSlot(c.env.CASE_STUDIES, draft.candidateId);
  }
  await rejectDraft(c.env.CASE_STUDIES, slug);
  return c.json({ ok: true });
});

/**
 * Inline draft editing — update the body and/or title of a draft without
 * an LLM call. Re-runs postProcess on the edited body so linkify + QA
 * stay consistent. Returns the updated preview.
 */
draftsRouter.post('/drafts/:slug/edit', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const draft = await getDraft(c.env.CASE_STUDIES, slug);
  if (!draft) return notFound(c, 'draft not found');

  const parsed = await safeJsonBody<{ body?: string; title?: string }>(c, { maxBytes: 256 * 1024 });
  if ('error' in parsed) return parsed.error;
  const { body, title } = parsed.value ?? {};
  if (!body && !title) return badRequest(c, 'at least body or title required');

  const factsText = JSON.stringify(draft.sources ?? {});
  const out = postProcess({ type: draft.type, raw: body ?? draft.body, factsText });
  const edited: Post = {
    ...draft,
    title: title ?? draft.title,
    body: out.body ?? body ?? draft.body,
    iocs: out.iocs ?? draft.iocs,
    audit: out.audit,
  };
  await putDraft(c.env.CASE_STUDIES, edited);
  return c.json({
    ok: true,
    slug,
    title: edited.title,
    body: edited.body,
    bodyHtml: renderMarkdown(edited.body),
    iocs: edited.iocs,
    audit: edited.audit,
  });
});

/**
 * Regenerate a draft in place. Two modes:
 *
 *  1. **Default (no body, or `{"mode":"fix"}`)** — run the existing
 *     body through `postProcess()`. This is the deterministic path:
 *     the linkify step (BleepingComputer / The Hacker News / Krebs /
 *     CISA KEV / …) repairs unlinked reference bullets, the disallowed-
 *     ref filter drops fabricated URLs, the placeholder filter strips
 *     example.com leftovers. No LLM call — fast (sub-second) and free.
 *     Use this when a draft slipped through QA with a small citation
 *     bug (the "BleepingComputer" / "The Hacker News" with no URL
 *     failure mode that motivated this endpoint).
 *
 *  2. **`{"mode":"rewrite", "notes":"…"}`** — call `generatePost()`
 *     with the original candidate (looked up by `Post.candidateId` +
 *     `Post.type`) and the admin-supplied `notes` injected into the
 *     prompt. This is the LLM path: re-issues the full generation
 *     with the admin's guidance ("drop the Sigma rule, add an attack
 *     flow chart", "make every reference a clickable link", etc).
 *     Costs one LLM call and one self-heal pass.
 *
 *  Either mode overwrites the draft atomically (new draft entry +
 *  updated index entry). The slug is preserved unless the LLM mode
 *  produces a title-derived slug the model renames — in that case the
 *  old draft is removed and the new one written under the new slug.
 *
 *  Returns `{ ok, slug, title, body, bodyHtml, qa, changed, mode }`
 *  so the admin UI can show a diff against the previous version.
 */
draftsRouter.post('/drafts/:slug/regenerate', async (c) => {
  const slug = c.req.param('slug');
  if (!validSlug(slug)) return badRequest(c, 'invalid slug');
  const draft = await getDraft(c.env.CASE_STUDIES, slug);
  if (!draft) return notFound(c, 'draft not found');

  const parsed = await safeJsonBody<{ mode?: 'fix' | 'rewrite'; notes?: string }>(c, { maxBytes: 4096 });
  const body = 'value' in parsed ? parsed.value : {};
  const mode: 'fix' | 'rewrite' = body.mode ?? 'fix';
  const now = new Date();

  if (mode === 'fix') {
    // Deterministic repair — no LLM, no candidate lookup.
    const factsText = JSON.stringify(draft.sources ?? {});
    const out = postProcess({ type: draft.type, raw: draft.body, factsText });
    if (!out.ok) {
      return c.json(
        {
          error: 'fix_failed',
          issues: out.errors,
          audit: out.audit,
          body: out.body,
        },
        422
      );
    }
    const changed = out.body !== draft.body || JSON.stringify(out.iocs) !== JSON.stringify(draft.iocs);
    if (changed) {
      const repaired: Post = {
        ...draft,
        body: out.body,
        iocs: out.iocs,
        audit: out.audit,
      };
      await putDraft(c.env.CASE_STUDIES, repaired);
      return c.json({
        ok: true,
        slug,
        title: repaired.title,
        body: repaired.body,
        bodyHtml: renderMarkdown(repaired.body),
        iocs: repaired.iocs,
        audit: repaired.audit,
        changed: true,
        mode,
      });
    }
    return c.json({
      ok: true,
      slug,
      title: draft.title,
      body: draft.body,
      bodyHtml: renderMarkdown(draft.body),
      iocs: draft.iocs,
      audit: draft.audit,
      changed: false,
      mode,
    });
  }

  // mode === 'rewrite' — full LLM regeneration.
  // Look up the original candidate (draft carries candidateId + type).
  // If the candidate was already removed (publisher deletes after
  // generation succeeds), rebuild a minimal Candidate from the draft
  // so the LLM still has facts to work with.
  let candidate: Candidate | null = null;
  if (draft.candidateId) {
    candidate = await getCandidate(c.env.CASE_STUDIES, draft.type, draft.candidateId);
  }
  // Prefer the evidence snapshot persisted on the Post at generation
  // time (generatePost writes it so rewrite-mode can see the original
  // facts even after the candidate blob was deleted). Falls back to
  // the live candidate's evidence when present, then to a draft-
  // derived skeleton.
  if (candidate && draft.evidence && Object.keys(draft.evidence).length > 0) {
    candidate = { ...candidate, evidence: { ...candidate.evidence, ...draft.evidence } };
  }
  if (!candidate) {
    // Candidate was deleted post-generation. Reconstruct a minimal one
    // from the draft itself so the rewrite still has grounded facts.
    candidate = {
      key: draft.candidateId || draft.slug,
      type: draft.type,
      title: draft.title,
      rationale: '',
      score: 0,
      evidence: {
        title: draft.title,
        slug: draft.slug,
        existingBody: draft.body,
        sources: draft.sources,
        // Tag the reconstruction so the model knows the source is the
        // previous draft and not a fresh candidate.
        regenerated: true,
      },
      discoveredAt: draft.publishedAt,
      status: 'pending',
    };
  }
  try {
    const newPost = await generatePost({
      candidate,
      ai: getAi(c.env),
      now,
      groqKey: c.env.GROQ_API_KEY,
      googleKey: c.env.GOOGLE_AI_STUDIO_API_KEY,
      nvidiaKey: c.env.NVIDIA_API_KEY as string | undefined,
      infronKey: c.env.INFRON_API_KEY,
      notes: body.notes,
    });
    // If the LLM produced a different slug, remove the old draft first
    // so we don't end up with two drafts on the index.
    if (newPost.slug !== slug) {
      await rejectDraft(c.env.CASE_STUDIES, slug);
    }
    await putDraft(c.env.CASE_STUDIES, newPost);
    return c.json({
      ok: true,
      slug: newPost.slug,
      title: newPost.title,
      body: newPost.body,
      bodyHtml: renderMarkdown(newPost.body),
      iocs: newPost.iocs,
      audit: newPost.audit,
      changed: true,
      mode,
    });
  } catch (err) {
    logError('handler failed', err);
    // Surface the actual post-process / LLM error so the admin can see
    // WHY the rewrite failed (e.g. "missing section: ## Lessons learned",
    // "qa failed: too thin (56 words < 160)"). 422 not 500 — the request
    // is well-formed; the model just couldn't satisfy the constraints.
    // The message is included in BOTH the `error` and `message` fields
    // because the client helper extracts only the `error` field from
    // 4xx/5xx bodies.
    const detail = err instanceof Error ? err.message : String(err);
    logError('regenerate-rewrite', detail);
    return c.json(
      {
        error: `rewrite_failed: ${detail}`,
        message: detail,
      },
      422
    );
  }
});
