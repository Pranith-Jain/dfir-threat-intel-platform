/**
 * Vera — multi-mode chat routes.
 *
 * Wraps the existing InvestigatorAgentDO with a 4-mode conversational shell:
 *   ask          — quick, sourced, ≤120 words, max 3 steps, narrow toolset
 *   investigate  — full agent mesh, mode-aware prompt
 *   draft        — full TLP-marked report contract (delegates to buildSynthesizerPrompt)
 *   challenge    — adversarial stress-test of the analyst's hypothesis
 *
 * Session state lives in the existing `copilot_sessions` table (D1) so the
 * analyst's history persists across page reloads, just like the chat route.
 *
 * Endpoints (registered in api/src/index.ts):
 *   POST /api/v1/agents/chat                — start a new Vera turn (mode + query)
 *   GET  /api/v1/agents/chat/modes          — list the 4 modes (id, label, maxSteps, description)
 *   GET  /api/v1/agents/chat/:sessionId/stream  — SSE: tool steps + final answer
 *   GET  /api/v1/agents/chat/:sessionId     — fetch chat history
 *   GET  /api/v1/agents/chat/sessions       — list recent Vera sessions
 */

import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError, notFound, serviceUnavailable } from '../lib/api-error';
import { callerOwnerId, ownerVisibilityFilter, ownerCheck } from '../lib/ownership';
import { detectType } from '../lib/report/subject-resolver';
import { trackEvent, visitorCountry } from '../lib/analytics';
import { VERA_MODES, getVeraMode, type VeraMode } from '../lib/agent/vera-prompts';
import type { AgentState } from '../lib/agent/types';
import {
  ANALYST_ROLES,
  ROLE_DISPLAY_NAMES,
  ROLE_TOOLS,
  ROLE_RESPONSE_FORMATS,
  buildRolePreamble,
  type AnalystRole,
} from '../lib/agent/role-prompts';

interface VeraMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  mode?: VeraMode;
  query_type?: string;
  agent_id?: string;
  model_used?: string;
  processed_at?: string;
  /** Citations the assistant extracted. */
  citations?: string[];
  /** Tool calls Vera made, for the mesh-viz. */
  tools_used?: string[];
  /** Analyst persona for role-aware responses. */
  analyst_role?: AnalystRole;
}

interface VeraSession {
  id: string;
  messages: VeraMessage[];
  created_at: string;
  updated_at: string;
  role?: AnalystRole;
  mode?: VeraMode;
}

function generateId(): string {
  return `vera_${Date.now()}_${crypto.randomUUID()}`;
}

function isValidMode(m: unknown): m is VeraMode {
  return typeof m === 'string' && m in VERA_MODES;
}

/** Follow-up + pronoun heuristic; lifted from copilot-chat. */
const FOLLOW_UP_PATTERNS = /^(what|how|when|where|why|who|can|could|would|tell|explain|elaborate|more|also|and|so)\b/i;
const PRONOUN_REF_PATTERNS = /\b(this|that|it|these|those|them|the previous|the above|the earlier)\b/i;

function isFollowUpQuery(query: string): boolean {
  const cleaned = query.replace(/[^\w\s]/g, '').trim();
  if (cleaned.length < 10 && FOLLOW_UP_PATTERNS.test(cleaned)) return true;
  if (PRONOUN_REF_PATTERNS.test(query)) return true;
  return false;
}

const VAGUE_TYPES = new Set(['general', 'generic']);

function getLastSubstantiveQuery(messages: VeraMessage[]): { query: string; type: string } | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.role === 'user' && m.query_type && !VAGUE_TYPES.has(m.query_type)) {
      return { query: m.content, type: m.query_type };
    }
  }
  return null;
}

async function loadSession(c: Context<{ Bindings: Env }>, db: D1Database, id: string): Promise<VeraSession | null> {
  const row = await db
    .prepare('SELECT id, mode, messages_json, created_at, updated_at, role, owner_hash FROM vera_sessions WHERE id = ?')
    .bind(id)
    .first<{
      id: string;
      mode: string;
      messages_json: string;
      created_at: string;
      updated_at: string;
      role: string | null;
      owner_hash: string | null;
    }>();
  if (!row) return null;
  if (ownerCheck(c, row.owner_hash) === 'hidden') return null;
  return {
    id: row.id,
    messages: JSON.parse(row.messages_json) as VeraMessage[],
    created_at: row.created_at,
    updated_at: row.updated_at,
    role: (row.role as AnalystRole) ?? undefined,
    mode: (row.mode as VeraMode) ?? undefined,
  };
}

async function saveSession(c: Context<{ Bindings: Env }>, db: D1Database, session: VeraSession): Promise<void> {
  await db
    .prepare(
      `INSERT INTO vera_sessions (id, mode, messages_json, created_at, updated_at, role, owner_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         messages_json = excluded.messages_json,
         updated_at = excluded.updated_at,
         role = COALESCE(excluded.role, role)`
    )
    .bind(
      session.id,
      session.mode ?? 'ask',
      JSON.stringify(session.messages),
      session.created_at,
      new Date().toISOString(),
      session.role ?? null,
      callerOwnerId(c)
    )
    .run();
}

function isValidRole(r: unknown): r is AnalystRole {
  return typeof r === 'string' && ANALYST_ROLES.includes(r as AnalystRole);
}

/**
 * POST /api/v1/agents/chat
 * Body: { sessionId?: string, mode: 'ask'|'investigate'|'draft'|'challenge', query: string }
 * Returns: { sessionId, agentId, mode, queryType }
 */
export async function veraChatHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    let body: { sessionId?: string; mode?: string; query?: string; role?: string };
    try {
      body = await c.req.json();
    } catch (_catchErr) {
      logError('veraChatHandler failed', _catchErr);
      return badRequest(c, 'Invalid JSON body');
    }

    const query = body.query?.trim();
    if (!query) return badRequest(c, 'query is required');
    if (query.length > 2000) return badRequest(c, 'query too long (max 2000 chars)');
    const mode: VeraMode = isValidMode(body.mode) ? body.mode : 'ask';
    const role: AnalystRole = isValidRole(body.role) ? body.role : 'cti';

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const doNamespace = c.env.INVESTIGATOR_AGENT;
    if (!doNamespace) return serviceUnavailable(c, 'Agent not configured');

    let session: VeraSession;
    if (body.sessionId) {
      const existing = await loadSession(c, db, body.sessionId);
      if (!existing) return notFound(c, 'session not found');
      session = existing;
      // Use the session's existing role if not explicitly set
    } else {
      session = {
        id: generateId(),
        messages: [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        role,
        mode,
      };
    }

    // Apply or override role + mode
    session.role = role;
    session.mode = mode;

    const queryType = detectType(query) as string;
    const isFollowUp = isFollowUpQuery(query);

    let effectiveQuery = query.trim();
    let effectiveType = queryType;
    if (isFollowUp || VAGUE_TYPES.has(queryType)) {
      const prev = getLastSubstantiveQuery(session.messages);
      if (prev) {
        effectiveQuery = prev.query;
        effectiveType = prev.type;
      }
    }

    const modeCfg = getVeraMode(mode);
    const agentId = crypto.randomUUID();
    const doId = doNamespace.idFromName(agentId);
    const stub = doNamespace.get(doId);

    // Filter tools by role
    const roleTools = ROLE_TOOLS[role] ?? null;
    const allowedTools = modeCfg.allowedTools
      ? modeCfg.allowedTools.filter((t) => !roleTools || roleTools.includes(t))
      : roleTools;

    const doRes = await stub.fetch('https://agent/investigate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: agentId,
        query: effectiveQuery,
        queryType: effectiveType,
        maxSteps: modeCfg.maxSteps,
        mode,
        role,
        allowedTools,
        rolePreamble: buildRolePreamble(role),
        responseFormat: ROLE_RESPONSE_FORMATS[role],
      }),
    });

    if (!doRes.ok) {
      const errBody = await doRes.text().catch(() => '');
      return internalError(c, new Error(`Vera agent failed: ${doRes.status} ${errBody.slice(0, 200)}`));
    }

    session.messages.push({ role: 'user', content: query, mode, query_type: queryType });
    session.messages.push({ role: 'system', content: '', mode, agent_id: agentId });
    await saveSession(c, db, session);

    trackEvent(c.env, 'api_call', {
      blobs: ['/api/v1/agents/chat'],
      indexes: [visitorCountry(c.req.raw)],
    });

    return c.json(
      { sessionId: session.id, agentId, mode, role, queryType: effectiveType, maxSteps: modeCfg.maxSteps },
      201
    );
  } catch (e) {
    logError('vera chat handler failed', e);
    return internalError(c, e);
  }
}

/**
 * GET /api/v1/agents/chat/modes
 * Returns the four Vera modes so the UI can render the mode selector.
 */
export async function veraChatModesHandler(_c: Context<{ Bindings: Env }>): Promise<Response> {
  return Response.json(
    Object.values(VERA_MODES).map((m) => ({
      id: m.id,
      label: m.label,
      description: m.description,
      maxSteps: m.maxSteps,
    })),
    { headers: { 'cache-control': 'public, max-age=300' } }
  );
}

/**
 * GET /api/v1/agents/chat/roles
 * Returns the four analyst roles for role-aware copilot.
 */
export async function veraChatRolesHandler(_c: Context<{ Bindings: Env }>): Promise<Response> {
  return Response.json(
    ANALYST_ROLES.map((id) => ({
      id,
      label: ROLE_DISPLAY_NAMES[id],
      tools: ROLE_TOOLS[id],
    })),
    { headers: { 'cache-control': 'public, max-age=300' } }
  );
}

/**
 * GET /api/v1/agents/chat/:sessionId/stream — SSE stream of tool steps + final answer.
 * Same shape as copilotChatStreamHandler so the React client can reuse its parser.
 */
export async function veraChatStreamHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const sessionId = c.req.param('sessionId');
  if (!sessionId) return badRequest(c, 'sessionId required');

  const db = c.env.BRIEFINGS_DB as D1Database | undefined;
  if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

  const doNamespace = c.env.INVESTIGATOR_AGENT;
  if (!doNamespace) return serviceUnavailable(c, 'Agent not configured');

  const session = await loadSession(c, db, sessionId);
  if (!session) return notFound(c, 'session not found');

  const systemMsg = [...session.messages].reverse().find((m) => m.role === 'system' && m.agent_id);
  const agentId = systemMsg?.agent_id;
  if (!agentId) return badRequest(c, 'no active investigation');

  const doId = doNamespace.idFromName(agentId);
  const stub = doNamespace.get(doId);

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let lastStep = -1;
      let closed = false;

      const send = (data: string) => {
        if (!closed) {
          try {
            controller.enqueue(encoder.encode(`data: ${data}\n\n`));
          } catch (_catchErr) {
            logError('veraChatStreamHandler failed', _catchErr);
            closed = true;
          }
        }
      };

      const interval = setInterval(() => {
        void (async () => {
          if (closed) {
            clearInterval(interval);
            return;
          }
          try {
            const res = await stub.fetch(`https://agent/state?id=${encodeURIComponent(agentId)}`);
            if (!res.ok) return;
            const state = (await res.json()) as AgentState;

            for (const step of state.steps) {
              if (step.stepNumber > lastStep) {
                send(
                  JSON.stringify({
                    type: 'step',
                    step,
                    specialist: (step as { specialist?: string }).specialist ?? null,
                  })
                );
                lastStep = step.stepNumber;
              }
            }

            if (state.status === 'done' || state.status === 'error') {
              clearInterval(interval);

              const report = state.status === 'done' ? (state.report ?? null) : null;
              const errMsg = state.status === 'error' ? (state.error ?? 'Unknown error') : null;

              const toolsUsed = Array.from(
                new Set(state.steps.flatMap((s) => (s.results ?? []).map((r) => r.tool).filter(Boolean)))
              );

              if (report) {
                session.messages.push({
                  role: 'assistant',
                  content: report,
                  mode: systemMsg.mode,
                  agent_id: agentId,
                  query_type: state.queryType,
                  model_used: state.modelUsed ?? undefined,
                  processed_at: state.completedAt ?? new Date().toISOString(),
                  tools_used: toolsUsed,
                  analyst_role: session.role,
                });

                const maxHistory = 24;
                if (session.messages.length > maxHistory) {
                  session.messages = session.messages.slice(-maxHistory);
                }

                try {
                  await saveSession(c, db, session);
                } catch (_catchErr) {
                  logError('handler failed', _catchErr);
                  /* non-fatal */
                }
              }

              send(
                JSON.stringify({
                  type: state.status,
                  report,
                  error: errMsg,
                  modelUsed: state.modelUsed,
                  toolsUsed,
                  selfEval: state.selfEval,
                  qa: state.qa,
                  dataGaps: state.dataGaps,
                  cost: state.cost,
                  priorIntelligence: state.priorIntelligence,
                })
              );

              closed = true;
              try {
                controller.close();
              } catch (_catchErr) {
                logError('handler failed', _catchErr);
                /* already closed */
              }
            }
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
            /* poll */
          }
        })();
      }, 700);

      const heartbeat = setInterval(() => {
        if (!closed) send(JSON.stringify({ type: 'heartbeat' }));
        else clearInterval(heartbeat);
      }, 15000);

      c.req.raw.signal.addEventListener('abort', () => {
        closed = true;
        clearInterval(interval);
        clearInterval(heartbeat);
        try {
          controller.close();
        } catch (_catchErr) {
          logError('handler failed', _catchErr);
          /* already closed */
        }
      });
    },
  });

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    },
  });
}

/**
 * GET /api/v1/agents/chat/:sessionId
 */
export async function veraChatHistoryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const sessionId = c.req.param('sessionId');
    if (!sessionId) return badRequest(c, 'sessionId required');

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const session = await loadSession(c, db, sessionId);
    if (!session) return notFound(c, 'session not found');

    return c.json({
      sessionId: session.id,
      messages: session.messages,
      created_at: session.created_at,
      updated_at: session.updated_at,
    });
  } catch (e) {
    logError('vera chat history handler failed', e);
    return internalError(c, e);
  }
}

/**
 * GET /api/v1/agents/chat/sessions?limit=20
 * Lists recent Vera sessions, newest first.
 */
export async function veraSessionsListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const limitRaw = Number(c.req.query('limit') ?? 20);
    const limit = Math.min(Number.isFinite(limitRaw) ? limitRaw : 20, 100);

    const vis = ownerVisibilityFilter(c);
    const res = await db
      .prepare(
        `SELECT id, mode, messages_json, created_at, updated_at, role
         FROM vera_sessions
         WHERE ${vis.clause}
         ORDER BY updated_at DESC
         LIMIT ?`
      )
      .bind(...vis.bindings, limit)
      .all<{
        id: string;
        mode: string;
        messages_json: string;
        created_at: string;
        updated_at: string;
        role: string | null;
      }>();

    const sessions = (res.results ?? []).map((r) => {
      const messages = JSON.parse(r.messages_json) as VeraMessage[];
      const lastUser = [...messages].reverse().find((m) => m.role === 'user');
      return {
        id: r.id,
        mode: r.mode,
        role: r.role ?? 'cti',
        preview: lastUser?.content?.slice(0, 120) ?? '(empty)',
        message_count: messages.length,
        created_at: r.created_at,
        updated_at: r.updated_at,
      };
    });

    return c.json({ sessions }, 200, { 'Cache-Control': 'no-store' });
  } catch (e) {
    logError('vera sessions list handler failed', e);
    return internalError(c, e);
  }
}

/**
 * DELETE /api/v1/agents/chat/:sessionId
 * Delete a Vera session.
 */
export async function veraChatDeleteHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const sessionId = c.req.param('sessionId');
    if (!sessionId) return badRequest(c, 'sessionId required');

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const existing = await loadSession(c, db, sessionId);
    if (!existing) return notFound(c, 'session not found');

    await db.prepare('DELETE FROM vera_sessions WHERE id = ?').bind(sessionId).run();
    return c.json({ deleted: true });
  } catch (e) {
    logError('vera chat delete handler failed', e);
    return internalError(c, e);
  }
}

/**
 * POST /api/v1/agents/chat/:sessionId/cancel
 * Cancel an active Vera investigation.
 */
export async function veraChatCancelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const sessionId = c.req.param('sessionId');
    if (!sessionId) return badRequest(c, 'sessionId required');

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const doNamespace = c.env.INVESTIGATOR_AGENT;
    if (!doNamespace) return serviceUnavailable(c, 'Agent not configured');

    const session = await loadSession(c, db, sessionId);
    if (!session) return notFound(c, 'session not found');

    const systemMsg = [...session.messages].reverse().find((m) => m.role === 'system' && m.agent_id);
    const agentId = systemMsg?.agent_id;
    if (!agentId) return badRequest(c, 'no active investigation');

    const doId = doNamespace.idFromName(agentId);
    const stub = doNamespace.get(doId);
    const res = await stub.fetch(`https://agent/cancel?id=${encodeURIComponent(agentId)}`, { method: 'DELETE' });
    if (!res.ok) return internalError(c, new Error('Failed to cancel investigation'));

    return c.json({ cancelled: true });
  } catch (e) {
    logError('vera chat cancel handler failed', e);
    return internalError(c, e);
  }
}
