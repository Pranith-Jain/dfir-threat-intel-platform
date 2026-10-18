import { Hono } from 'hono';
import type { KVNamespace } from '@cloudflare/workers-types';
import type { Env } from '../../env';
import { logError } from '../../lib/logger';
import { notFound } from '../../lib/api-error';
import { safeJsonBody } from '../../lib/safe-body';
import { getAi } from '../../lib/ai-binding';
import {
  listAllCandidates,
  listCandidates,
  getCandidate,
  deleteCandidate,
  interleaveByType,
} from '../../case-study/storage/candidates';
import { approve } from '../../case-study/storage/approved';
import { suppressDedupMany } from '../../case-study/storage/dedup';
import { putDraft } from '../../case-study/storage/drafts';
import { kv as csKvKeys } from '../../case-study/kv-keys';
import { generatePost } from '../../case-study/generation';
import { generateLinkedinFromCandidate, generateTwitterFromCandidate } from '../../case-study/generation/social';
import type { Candidate, CaseStudyType } from '../../case-study/types';
import { TYPES } from './shared';

export const candidatesRouter = new Hono<{ Bindings: Env }>();

async function deleteCandidatesByType(ns: KVNamespace, filterType: CaseStudyType | null): Promise<number> {
  const types = filterType ? [filterType] : TYPES;
  const stableKeys: string[] = [];
  for (const t of types) {
    const list = await listCandidates(ns, t);
    for (const cand of list) stableKeys.push(cand.key);
  }
  const prefix = filterType ? csKvKeys.candidatesPrefix(filterType) : csKvKeys.candidatesAllPrefix;
  let cursor: string | undefined;
  for (let page = 0; page < 5; page += 1) {
    const res = await ns.list({ prefix, cursor });
    for (const k of res.keys) await ns.delete(k.name);
    if (res.list_complete) break;
    cursor = res.cursor;
  }
  const until = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  await suppressDedupMany(ns, stableKeys, until);
  return stableKeys.length;
}

candidatesRouter.get('/candidates', async (c) => {
  const all = await listAllCandidates(c.env.CASE_STUDIES);
  // Score order alone put KEV CVEs (severity 1.0) at the top of every screen.
  // Round-robin by type so the operator sees the day's actual mix first.
  return c.json({ pending: interleaveByType(all) });
});

candidatesRouter.post('/candidates/:id/approve', async (c) => {
  const id = c.req.param('id');
  const typeHint = (c.req.query('type') ?? '') as CaseStudyType | '';
  let found: Candidate | null = null;
  let foundType: CaseStudyType | null = null;
  if (typeHint && TYPES.includes(typeHint as CaseStudyType)) {
    const cand = await getCandidate(c.env.CASE_STUDIES, typeHint as CaseStudyType, id);
    if (cand) {
      found = cand;
      foundType = typeHint as CaseStudyType;
    }
  }
  if (!found || !foundType) {
    for (const t of TYPES) {
      const cand = await getCandidate(c.env.CASE_STUDIES, t, id);
      if (cand) {
        found = cand;
        foundType = t;
        break;
      }
    }
  }
  if (!found || !foundType) return notFound(c, `not found: `);
  await approve(c.env.CASE_STUDIES, found);
  await deleteCandidate(c.env.CASE_STUDIES, foundType, id);
  return c.json({ ok: true, approved: id });
});

candidatesRouter.post('/candidates/:id/skip', async (c) => {
  const id = c.req.param('id');
  const typeHint = (c.req.query('type') ?? '') as CaseStudyType;
  if (typeHint && TYPES.includes(typeHint)) {
    await deleteCandidate(c.env.CASE_STUDIES, typeHint, id);
  } else {
    for (const t of TYPES) {
      const cnd = await getCandidate(c.env.CASE_STUDIES, t, id);
      if (cnd) {
        await deleteCandidate(c.env.CASE_STUDIES, t, id);
        break;
      }
    }
  }
  const until = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  await suppressDedupMany(c.env.CASE_STUDIES, [id], until);
  return c.json({ ok: true });
});

candidatesRouter.post('/candidates/skip-all', async (c) => {
  const typeHint = (c.req.query('type') ?? '') as CaseStudyType | '';
  const filterType = typeHint && TYPES.includes(typeHint as CaseStudyType) ? (typeHint as CaseStudyType) : null;
  const cleared = await deleteCandidatesByType(c.env.CASE_STUDIES, filterType);
  return c.json({ ok: true, cleared });
});

candidatesRouter.post('/candidates/:key/generate', async (c) => {
  const key = c.req.param('key');
  const parsed = await safeJsonBody<{ formats?: string[]; type?: string }>(c, { maxBytes: 4096 });
  if ('error' in parsed) return parsed.error;
  const formats = parsed.value?.formats ?? ['linkedin', 'twitter'];
  const typeHint = (parsed.value?.type || c.req.query('type') || '') as string as CaseStudyType;
  let candidate: Candidate | null = null;

  if (typeHint && TYPES.includes(typeHint)) {
    candidate = await getCandidate(c.env.CASE_STUDIES, typeHint, key);
  }
  if (!candidate) {
    for (const t of TYPES) {
      candidate = await getCandidate(c.env.CASE_STUDIES, t, key);
      if (candidate) break;
    }
  }
  if (!candidate) return notFound(c, `candidate not found: `);

  const now = new Date();
  const result: Record<string, unknown> = {};
  const errors: string[] = [];
  for (const fmt of formats) {
    try {
      if (fmt === 'blog') {
        const post = await generatePost({
          candidate,
          ai: getAi(c.env),
          now,
          groqKey: c.env.GROQ_API_KEY,
          googleKey: c.env.GOOGLE_AI_STUDIO_API_KEY,
          infronKey: c.env.INFRON_API_KEY,
        });
        await putDraft(c.env.CASE_STUDIES, post);
        result.blog = { slug: post.slug, title: post.title, status: 'draft' };
        if (typeHint && TYPES.includes(typeHint)) {
          await deleteCandidate(c.env.CASE_STUDIES, typeHint, key);
        } else {
          const ft = candidate.type;
          if (TYPES.includes(ft)) await deleteCandidate(c.env.CASE_STUDIES, ft, key);
        }
      } else if (fmt === 'linkedin') {
        const { linkedin, generatedAt, _validation } = await generateLinkedinFromCandidate(
          candidate,
          getAi(c.env),
          now,
          c.env.GROQ_API_KEY,
          c.env.GOOGLE_AI_STUDIO_API_KEY,
          c.env.NVIDIA_API_KEY as string | undefined,
          c.env.INFRON_API_KEY
        );
        await c.env.CASE_STUDIES.put(csKvKeys.socialCandidateLinkedin(key), linkedin);
        result.linkedin = { content: linkedin, generatedAt, validation: _validation };
      } else if (fmt === 'twitter') {
        const { twitter, generatedAt, _validation } = await generateTwitterFromCandidate(
          candidate,
          getAi(c.env),
          now,
          c.env.GROQ_API_KEY,
          c.env.GOOGLE_AI_STUDIO_API_KEY,
          c.env.NVIDIA_API_KEY as string | undefined,
          c.env.INFRON_API_KEY
        );
        await c.env.CASE_STUDIES.put(csKvKeys.socialCandidateTwitter(key), twitter);
        result.twitter = { content: twitter, generatedAt, validation: _validation };
      } else {
        errors.push(`unknown format: ${fmt}`);
      }
    } catch (err) {
      logError('handler failed', err);
      errors.push(`${fmt}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (result.linkedin || result.twitter) {
    const combined = {
      slug: key,
      twitter: ((result.twitter as Record<string, unknown> | undefined)?.content as string) ?? '',
      linkedin: ((result.linkedin as Record<string, unknown> | undefined)?.content as string) ?? '',
      generatedAt: now.toISOString(),
    };
    await c.env.CASE_STUDIES.put(csKvKeys.socialCandidate(key), JSON.stringify(combined));
  }

  return c.json({ ok: errors.length === 0, result, errors: errors.length > 0 ? errors : undefined });
});
