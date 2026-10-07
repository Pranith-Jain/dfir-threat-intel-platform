import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { requireAdminMiddleware } from '../lib/admin-auth';
import { safeJsonBody } from '../lib/safe-body';
import { getAi } from '../lib/ai-binding';
import { getSchedule } from '../case-study/storage/schedule';
import { listPostIndex } from '../case-study/storage/posts';
import { countAllCandidates } from '../case-study/storage/candidates';
import { countApproved } from '../case-study/storage/approved';
import { countFailures } from '../case-study/storage/failed';
import { generatePost } from '../case-study/generation';
import { putDraft } from '../case-study/storage/drafts';
import { generateLinkedinFromNotes, generateTwitterFromNotes } from '../case-study/generation/social';
import type { Candidate, CaseStudyType } from '../case-study/types';

import { candidatesRouter } from './admin/candidates';
import { approvedRouter } from './admin/approved';
import { scheduleRouter } from './admin/schedule';
import { socialRouter } from './admin/social';
import { draftsRouter } from './admin/drafts';
import { postsRouter } from './admin/posts';
import { failuresRouter } from './admin/failures';
import { inferenceRouter } from './admin/inference';
import { runRouter } from './admin/run';
import { calendarRouter } from './admin/calendar';
import { linkAuditRouter } from './admin/link-audit';

export function registerAdminRoutes(app: Hono<{ Bindings: Env }>): void {
  const admin = new Hono<{ Bindings: Env }>();
  admin.use('*', requireAdminMiddleware);

  // ─── Generate content from custom input ─────────────────────────────
  // Powers the admin "Generate" tab. Mirrors the reference n8n LinkedIn
  // pipeline's contract: brand configuration (topic/audience/tone) →
  // composition → approval gate (weak/empty content is REJECTED with a
  // reason, never returned as usable) → normalized single `final_post`
  // field per format → optional dry-run (compose without persisting).
  admin.post('/generate', async (c) => {
    const parsed = await safeJsonBody<{
      title?: string;
      topic?: string;
      content?: string;
      audience?: string;
      tone?: string;
      formats?: string[];
      type?: string;
      notes?: string;
      dry_run?: boolean;
    }>(c, { maxBytes: 128 * 1024 });
    if ('error' in parsed) return parsed.error;
    const { title, topic, content, audience, tone, formats: rawFormats, type, notes, dry_run } = parsed.value;

    const subject = (title ?? topic ?? '').trim();
    if (!subject) return badRequest(c, 'title or topic is required');
    if (!content?.trim() && !notes?.trim() && !topic?.trim()) {
      return badRequest(c, 'content, notes, or topic is required');
    }

    const formats = rawFormats && rawFormats.length > 0 ? rawFormats : ['blog', 'linkedin', 'twitter'];
    const now = new Date();

    const slug = subject
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .slice(0, 80);

    /** Brand-configuration hints folded into the source body (n8n layer 1). */
    const brandConfig = [
      content?.trim() ?? '',
      notes?.trim() ? `<admin_notes>${notes.trim()}</admin_notes>` : '',
      audience?.trim() ? `Target audience: ${audience.trim()}.` : '',
      tone?.trim() ? `Tone: ${tone.trim()}.` : '',
    ]
      .filter(Boolean)
      .join('\n\n');

    const result: Record<string, unknown> = {};
    const errors: string[] = [];

    /** Approval gate — mirrors the n8n "reject weak/empty output" node. */
    /**
     * The only automatic rejection left for generated social copy: nothing at
     * all, or something too short to be a post.
     *
     * The `quality_score_below_threshold` check that used to live here read a
     * composite score built from character counts, a hardcoded vendor/actor
     * keyword list, hashtag count and slop phrases. It rejected sharp posts
     * about unfamiliar products as "low quality" and passed name-stuffed ones.
     * Real errors (a CVE id not in the dossier, a link to an untrusted host)
     * are already fixed in `generation/social.ts` before the copy returns,
     * and are surfaced for review rather than used as a gate.
     */
    function approve(text: string | undefined, minLen: number) {
      const trimmed = (text ?? '').trim();
      if (trimmed.length === 0) {
        return { rejected: true, reason: 'empty_content' };
      }
      if (trimmed.length < minLen) {
        return { rejected: true, reason: `too_short (${trimmed.length} < ${minLen} chars)` };
      }
      return { rejected: false };
    }

    for (const fmt of formats) {
      try {
        if (fmt === 'blog') {
          const pseudo: Candidate = {
            key: `custom-${slug}`,
            type: (type as CaseStudyType | undefined) ?? 'analysis',
            title: subject,
            rationale: subject,
            score: 0.8,
            evidence: { userContent: brandConfig },
            discoveredAt: now.toISOString(),
            status: 'pending',
          };
          const post = await generatePost({
            candidate: pseudo,
            ai: getAi(c.env),
            now,
            groqKey: c.env.GROQ_API_KEY,
            googleKey: c.env.GOOGLE_AI_STUDIO_API_KEY,
            infronKey: c.env.INFRON_API_KEY,
            // Lets the research stage read the platform's own corpus
            // (writeups, trending CVEs, darkweb hits) via the SELF binding.
            self: c.env.SELF,
            internalTokenSecret: c.env.INTERNAL_TOKEN_SECRET,
          });
          const gate = approve(post.body, 500);
          if (!gate.rejected && !dry_run) await putDraft(c.env.CASE_STUDIES, post);
          result.blog = {
            slug: post.slug,
            title: post.title,
            final_post: post.body,
            status: dry_run ? 'dry_run' : gate.rejected ? 'rejected' : 'draft',
            ...gate,
          };
        } else if (fmt === 'linkedin' || fmt === 'twitter') {
          const gen = fmt === 'linkedin' ? generateLinkedinFromNotes : generateTwitterFromNotes;
          const notesBody = { slug: `custom-${slug}`, title: subject, body: brandConfig };
          const out = (await gen(
            notesBody,
            getAi(c.env),
            now,
            c.env.GROQ_API_KEY,
            c.env.GOOGLE_AI_STUDIO_API_KEY,
            c.env.NVIDIA_API_KEY as string | undefined,
            c.env.INFRON_API_KEY
          )) as {
            linkedin?: string;
            twitter?: string;
            generatedAt: string;
            _validation?: unknown;
          };
          const text = fmt === 'linkedin' ? out.linkedin : out.twitter;
          const gate = approve(text, fmt === 'linkedin' ? 400 : 120);
          result[fmt] = {
            final_post: text ?? '',
            generatedAt: out.generatedAt,
            validation: out._validation,
            status: gate.rejected ? 'rejected' : 'ready',
            ...gate,
          };
        } else {
          errors.push(`unknown format: ${fmt}`);
        }
      } catch (err) {
        logError('handler failed', err);
        errors.push(`${fmt}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return c.json({
      ok: errors.length === 0,
      slug: `custom-${slug}`,
      dry_run: dry_run === true,
      result,
      errors: errors.length > 0 ? errors : undefined,
    });
  });

  // ─── Health (counts + Groq connectivity test) ──────────────────────
  admin.get('/health', async (c) => {
    const ns = c.env.CASE_STUDIES;
    const [pendingCount, approvedCount, failureCount, schedule, postsIndex] = await Promise.all([
      countAllCandidates(ns),
      countApproved(ns),
      countFailures(ns),
      getSchedule(ns),
      listPostIndex(ns),
    ]);
    let groqTest: { ok: boolean; detail: string } | undefined;
    if (c.env.GROQ_API_KEY) {
      try {
        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { Authorization: `Bearer ${c.env.GROQ_API_KEY}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            model: 'openai/gpt-oss-120b',
            messages: [{ role: 'user', content: 'hi' }],
            max_completion_tokens: 5,
          }),
          signal: AbortSignal.timeout(10_000),
        });
        const body = await r.text().catch(() => '');
        groqTest = r.ok
          ? { ok: true, detail: `HTTP ${r.status}` }
          : { ok: false, detail: `HTTP ${r.status}: ${body.slice(0, 120)}` };
      } catch (e) {
        logError('handler failed', e);
        groqTest = { ok: false, detail: e instanceof Error ? e.message : String(e) };
      }
    }

    return c.json({
      pendingCount,
      approvedCount,
      scheduleCount: schedule.length,
      failureCount,
      postsCount: postsIndex.length,
      approvalRequired: c.env.BLOG_APPROVAL_REQUIRED === 'true',
      secrets: {
        groq: !!c.env.GROQ_API_KEY,
        google: !!c.env.GOOGLE_AI_STUDIO_API_KEY,
        vulncheck: !!c.env.VULNCHECK_API_TOKEN,
      },
      groqTest,
    });
  });

  // Mount domain sub-routers
  admin.route('/', candidatesRouter);
  admin.route('/', approvedRouter);
  admin.route('/', scheduleRouter);
  admin.route('/', socialRouter);
  admin.route('/', draftsRouter);
  admin.route('/', postsRouter);
  admin.route('/', failuresRouter);
  admin.route('/', inferenceRouter);
  admin.route('/', runRouter);
  admin.route('/', calendarRouter);
  admin.route('/', linkAuditRouter);

  app.route('/api/v1/admin', admin);
}
