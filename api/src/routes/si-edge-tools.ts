/* eslint-disable @typescript-eslint/no-unused-vars */
/**
 * SI edge tools — REST surface for the 5 H3AD-SEC replicas.
 *
 * Endpoints (all under /api/v1/si/):
 *   POST /si/parse         PARSE-X  — raw text → 18-type artifact extract
 *   POST /si/mailscope     MAILSCOPE — email headers → hop chain + auth verdicts
 *   GET  /si/shiftlog      SHIFTLOG — list shift handover entries
 *   POST /si/shiftlog      SHIFTLOG — create a new entry
 *   GET  /si/shiftlog/:id  SHIFTLOG — fetch a single entry
 *   PATCH /si/shiftlog/:id SHIFTLOG — patch an entry
 *   POST /si/shiftlog/:id/close SHIFTLOG — close an entry
 *   POST /si/hypos         HYPOS — generate ranked hypotheses
 *   GET  /si/promptvault   PROMPTVAULT — list prompts
 *   GET  /si/promptvault/:slug PROMPTVAULT — fetch single prompt
 *   POST /si/promptvault   PROMPTVAULT — create a prompt
 *   POST /si/promptvault/:slug/rate PROMPTVAULT — rate a prompt
 *   GET  /si/promptvault-categories PROMPTVAULT — list categories
 *
 * The actual logic lives in worker/lib/* — this file is a thin Hono adapter.
 * Routes use the in-process SELF service binding (where present) or fall
 * back to a public fetch.
 */
import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError, notFound } from '../lib/api-error';
import { requireAdminRole } from '../lib/auth';

type Variables = { validated?: unknown };

// --- Schemas ---------------------------------------------------------------

const ParseRequestSchema = z.object({
  text: z.string(),
  refang: z.boolean().optional(),
  foldHomographs: z.boolean().optional(),
  maxChars: z.number().int().positive().max(5_000_000).optional(),
  kinds: z.array(z.string()).optional(),
});

const MailScopeRequestSchema = z.object({
  headers: z.string(),
  maxChars: z.number().int().positive().max(5_000_000).optional(),
});

const ShiftLogCreateSchema = z.object({
  shift: z.enum(['morning', 'afternoon', 'night', 'weekend', 'oncall']),
  author: z.string().min(1).max(64),
  startedAt: z.string().optional(),
  openCases: z.array(z.string()).optional(),
  iocs: z.array(z.string()).optional(),
  escalations: z.array(z.string()).optional(),
  notes: z.string().optional(),
});

const ShiftLogUpdateSchema = z.object({
  openCases: z.array(z.string()).optional(),
  iocs: z.array(z.string()).optional(),
  escalations: z.array(z.string()).optional(),
  notes: z.string().optional(),
  endedAt: z.string().nullable().optional(),
});

const HyposRequestSchema = z.object({
  text: z.string().min(1),
  iocs: z.array(z.string()).optional(),
  environment: z.enum(['endpoint', 'identity', 'cloud', 'network', 'email', 'saas', 'unknown']).optional(),
  topN: z.number().int().min(1).max(10).optional(),
  includeSkills: z.boolean().optional(),
});

const PromptVaultCreateSchema = z.object({
  slug: z.string().regex(/^[a-z0-9][a-z0-9\-_]{1,63}$/),
  title: z.string().min(1).max(200),
  category: z.enum([
    'detection-engineering',
    'threat-hunting',
    'incident-response',
    'threat-intelligence',
    'malware-analysis',
    'cloud-security',
    'identity-security',
    'osint',
    'phishing-analysis',
    'reverse-engineering',
    'forensics',
    'governance',
    'general',
  ]),
  tags: z.array(z.string()).optional(),
  author: z.string().min(1).max(64),
  body: z.string().min(1).max(32000),
});

const PromptVaultRateSchema = z.object({
  rating: z.number().int().min(1).max(5),
});

// --- Helper: dynamically import the worker lib modules --------------------

async function loadParseMod() {
  return await import('../lib/si-parse');
}
async function loadMailScopeMod() {
  return await import('../lib/si-mailscope');
}
async function loadShiftLogMod() {
  return await import('../lib/si-shiftlog');
}
async function loadHyposMod() {
  return await import('../lib/si-hypos');
}
async function loadPromptVaultMod() {
  return await import('../lib/si-promptvault');
}

// --- Routes ----------------------------------------------------------------

export const siEdgeToolsRouter = new Hono<{ Bindings: Env }>();

// PARSE-X
siEdgeToolsRouter.post('/si/parse', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = ParseRequestSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadParseMod();
    const result = mod.siParseText(parsed.data.text, {
      refang: parsed.data.refang,
      foldHomographs: parsed.data.foldHomographs,
      maxChars: parsed.data.maxChars,
      kinds: parsed.data.kinds as NonNullable<Parameters<typeof mod.siParseText>[1]>['kinds'],
    });
    return c.json(result);
  } catch (e) {
    logError('loadPromptVaultMod failed', e);
    return internalError(c, `parse_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// MAILSCOPE
siEdgeToolsRouter.post('/si/mailscope', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = MailScopeRequestSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadMailScopeMod();
    const result = mod.siParseEmailHeaders(parsed.data.headers, { maxChars: parsed.data.maxChars });
    return c.json(result);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `mailscope_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// SHIFTLOG
siEdgeToolsRouter.get('/si/shiftlog', async (c) => {
  const author = c.req.query('author');
  const shift = c.req.query('shift');
  const openOnly = c.req.query('open_only') === 'true';
  const limit = c.req.query('limit') ? Math.min(100, Math.max(1, Number(c.req.query('limit')) || 1)) : undefined;
  try {
    const mod = await loadShiftLogMod();
    const list = await mod.shiftlogList(c.env, {
      author,
      shift: shift as NonNullable<Parameters<typeof mod.shiftlogList>[1]>['shift'],
      openOnly,
      limit,
    });
    return c.json({ entries: list, count: list.length });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `shiftlog_list_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.post('/si/shiftlog', requireAdminRole(), async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = ShiftLogCreateSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadShiftLogMod();
    const entry = await mod.shiftlogCreate(c.env, parsed.data);
    return c.json(entry, 201);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `shiftlog_create_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.get('/si/shiftlog/:id', async (c) => {
  const id = c.req.param('id');
  try {
    const mod = await loadShiftLogMod();
    const entry = await mod.shiftlogGet(c.env, id);
    if (!entry) return notFound(c, 'shiftlog_entry_not_found');
    return c.json(entry);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `shiftlog_get_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.patch('/si/shiftlog/:id', requireAdminRole(), async (c) => {
  const id = c.req.param('id');
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = ShiftLogUpdateSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadShiftLogMod();
    const entry = await mod.shiftlogUpdate(c.env, id, parsed.data);
    if (!entry) return notFound(c, 'shiftlog_entry_not_found');
    return c.json(entry);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `shiftlog_update_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.post('/si/shiftlog/:id/close', requireAdminRole(), async (c) => {
  const id = c.req.param('id');
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const endedAt = (body as { endedAt?: string })?.endedAt;
  try {
    const mod = await loadShiftLogMod();
    const entry = await mod.shiftlogClose(c.env, id, endedAt);
    if (!entry) return notFound(c, 'shiftlog_entry_not_found');
    return c.json(entry);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `shiftlog_close_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// HYPOS
siEdgeToolsRouter.post('/si/hypos', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = HyposRequestSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadHyposMod();
    const result = await mod.siHyposGenerate(parsed.data, { ASSETS: c.env.ASSETS });
    return c.json(result);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `hypos_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// PROMPTVAULT
siEdgeToolsRouter.get('/si/promptvault-categories', async (c) => {
  try {
    const mod = await loadPromptVaultMod();
    return c.json({ categories: mod.promptVaultCategories() });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `promptvault_categories_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.get('/si/promptvault', async (c) => {
  const category = c.req.query('category');
  const tag = c.req.query('tag');
  const q = c.req.query('q');
  const limit = c.req.query('limit') ? Math.min(100, Math.max(1, Number(c.req.query('limit')) || 1)) : undefined;
  try {
    const mod = await loadPromptVaultMod();
    const list = await mod.promptVaultList(c.env, { category, tag, q, limit });
    return c.json({ entries: list, count: list.length });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `promptvault_list_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.get('/si/promptvault/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadPromptVaultMod();
    const p = await mod.promptVaultGet(c.env, slug);
    if (!p) return notFound(c, 'prompt_not_found');
    return c.json(p);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `promptvault_get_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.post('/si/promptvault', requireAdminRole(), async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = PromptVaultCreateSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadPromptVaultMod();
    const p = await mod.promptVaultCreate(c.env, parsed.data);
    return c.json(p, 201);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `promptvault_create_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

siEdgeToolsRouter.post('/si/promptvault/:slug/rate', requireAdminRole(), async (c) => {
  const slug = c.req.param('slug');
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (e) {
    return badRequest(c, 'invalid_json_body');
  }
  const parsed = PromptVaultRateSchema.safeParse(body);
  if (!parsed.success) return badRequest(c, `invalid_body: ${parsed.error.message}`);
  try {
    const mod = await loadPromptVaultMod();
    const p = await mod.promptVaultRate(c.env, { slug, rating: parsed.data.rating });
    if (!p) return notFound(c, 'prompt_not_found');
    return c.json(p);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `promptvault_rate_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
