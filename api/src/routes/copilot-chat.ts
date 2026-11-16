import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError, notFound, serviceUnavailable } from '../lib/api-error';
import { visitorOwnerId, visitorVisibilityFilter, visitorOwns } from '../lib/visitor';
import type { AgentState } from '../lib/agent/types';
import { detectType } from '../lib/report/subject-resolver';

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  agent_id?: string;
  query_type?: string;
  model_used?: string;
  processed_at?: string;
  sources?: Array<{ name: string; items: number }>;
  _meta?: { total_sources: number; total_items: number };
}

interface ChatSession {
  id: string;
  title?: string;
  messages: ChatMessage[];
  created_at: string;
  updated_at: string;
}

function generateId(): string {
  return `chat_${Date.now()}_${crypto.randomUUID()}`;
}

const CVE_ANYWHERE = /CVE-\d{4}-\d{4,}/i;
const IP_ANYWHERE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

const FOLLOW_UP_PATTERNS =
  /^(what|how|when|where|why|who|can|could|would|tell|explain|elaborate|tell me|can you|more|also|and|so)\b/i;
const PRONOUN_REF_PATTERNS = /\b(this|that|it|these|those|them|the previous|the above|the earlier)\b/i;

function extractEntity(query: string): string | null {
  const cve = CVE_ANYWHERE.exec(query);
  if (cve) return cve[0]!.toUpperCase();
  const ip = IP_ANYWHERE.exec(query);
  if (ip) return ip[0]!;
  return null;
}

function isFollowUpQuery(query: string): boolean {
  const cleaned = query.replace(/[^\w\s]/g, '').trim();
  if (cleaned.length < 10 && FOLLOW_UP_PATTERNS.test(cleaned)) return true;
  if (PRONOUN_REF_PATTERNS.test(query)) return true;
  return false;
}

const VAGUE_TYPES = new Set(['general', 'generic']);

function getLastSubstantiveQuery(messages: ChatMessage[]): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.role === 'user' && m.query_type && !VAGUE_TYPES.has(m.query_type)) {
      return m.content;
    }
  }
  return null;
}

function getLastSubstantiveQueryType(messages: ChatMessage[]): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.role === 'user' && m.query_type && !VAGUE_TYPES.has(m.query_type)) {
      return m.query_type;
    }
  }
  return null;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + '…';
}

async function loadSession(c: Context<{ Bindings: Env }>, db: D1Database, id: string): Promise<ChatSession | null> {
  const row = await db
    .prepare('SELECT id, title, messages_json, created_at, updated_at, owner_hash FROM copilot_sessions WHERE id = ?')
    .bind(id)
    .first<{
      id: string;
      title: string;
      messages_json: string;
      created_at: string;
      updated_at: string;
      owner_hash: string | null;
    }>();
  if (!row) return null;
  if (!visitorOwns(c, row.owner_hash)) return null;
  return {
    id: row.id,
    title: row.title,
    messages: JSON.parse(row.messages_json) as ChatMessage[],
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

async function saveSession(c: Context<{ Bindings: Env }>, db: D1Database, session: ChatSession): Promise<void> {
  await db
    .prepare(
      `INSERT INTO copilot_sessions (id, title, messages_json, created_at, updated_at, owner_hash)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET title = excluded.title, messages_json = excluded.messages_json, updated_at = excluded.updated_at`
    )
    .bind(
      session.id,
      session.title ?? '',
      JSON.stringify(session.messages),
      session.created_at,
      new Date().toISOString(),
      visitorOwnerId(c)
    )
    .run();
}

export async function copilotChatListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));
    const vis = visitorVisibilityFilter(c);
    const rows = await db
      .prepare(
        `SELECT id, title, messages_json, created_at, updated_at FROM copilot_sessions WHERE ${vis.clause} ORDER BY updated_at DESC LIMIT 50`
      )
      .bind(...vis.bindings)
      .all<{ id: string; title: string; messages_json: string; created_at: string; updated_at: string }>();
    const sessions = (rows.results ?? [])
      .map((row) => {
        const msgs = JSON.parse(row.messages_json) as ChatMessage[];
        const userCount = msgs.filter((m) => m.role === 'user').length;
        const firstUser = msgs.find((m) => m.role === 'user');
        const title = row.title || (firstUser ? truncate(firstUser.content, 55) : 'Untitled');
        return {
          id: row.id,
          title,
          messageCount: userCount,
          created_at: row.created_at,
          updated_at: row.updated_at,
        };
      })
      .filter((s) => s.messageCount > 0);
    return c.json({ sessions });
  } catch (e) {
    logError('copilotChatListHandler failed', e);
    return internalError(c, e);
  }
}

export async function copilotChatHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const body = await c.req.json<{ sessionId?: string; query: string }>();
    const query = body.query?.trim();
    if (!query) return badRequest(c, 'query is required');
    if (query.length > 500) return badRequest(c, 'query too long (max 500 chars)');

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const doNamespace = c.env.INVESTIGATOR_AGENT;
    if (!doNamespace) return serviceUnavailable(c, 'Agent not configured');

    let session: ChatSession;
    let isNewSession = false;
    if (body.sessionId) {
      const existing = await loadSession(c, db, body.sessionId);
      if (!existing) return notFound(c, 'session not found');
      session = existing;
    } else {
      session = {
        id: generateId(),
        messages: [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      isNewSession = true;
    }

    if (!session.title) {
      session.title = truncate(query, 55);
    }

    const queryType = detectType(query) as string;
    const isFollowUp = isFollowUpQuery(query);

    let effectiveQuery = query.trim();
    let effectiveType = queryType;

    if (isFollowUp || VAGUE_TYPES.has(queryType)) {
      const extracted = extractEntity(query);
      if (extracted) {
        effectiveQuery = extracted;
        effectiveType = detectType(extracted) as string;
      } else if (session.messages.length > 0) {
        const prevQuery = getLastSubstantiveQuery(session.messages);
        const prevType = getLastSubstantiveQueryType(session.messages);
        if (prevQuery && prevType) {
          effectiveQuery = prevQuery;
          effectiveType = prevType;
        }
      }
    }

    const agentId = crypto.randomUUID();
    const doId = doNamespace.idFromName(agentId);
    const stub = doNamespace.get(doId);

    const doRes = await stub.fetch('https://agent/investigate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: agentId, query: effectiveQuery, queryType: effectiveType, maxSteps: 6 }),
    });

    if (!doRes.ok) {
      return internalError(c, new Error('failed to start agent investigation'));
    }

    session.messages.push({ role: 'user', content: query, query_type: queryType });
    session.messages.push({ role: 'system', content: '', agent_id: agentId });
    await saveSession(c, db, session);

    return c.json({ sessionId: session.id, agentId, isNewSession });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e);
  }
}

export async function copilotChatStreamHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
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
            logError('copilotChatStreamHandler failed', _catchErr);
            closed = true;
          }
        }
      };

      let pollDelay = 400;
      const MAX_POLL_DELAY = 4000;
      const pollTimeout = (delay: number) => new Promise((resolve) => setTimeout(resolve, delay));

      const poll = async () => {
        if (closed) return;
        try {
          const res = await stub.fetch(`https://agent/state?id=${encodeURIComponent(agentId)}`);
          if (!res.ok) {
            scheduleNext(pollDelay);
            return;
          }
          const state = (await res.json()) as AgentState;

          let hasNew = false;
          for (const step of state.steps) {
            if (step.stepNumber > lastStep) {
              send(JSON.stringify({ type: 'step', step }));
              lastStep = step.stepNumber;
              hasNew = true;
            }
          }

          if (hasNew) pollDelay = 400; // reset on activity

          if (state.status === 'done' || state.status === 'error') {
            cleanup();
            const report = state.status === 'done' ? (state.report ?? 'Investigation completed.') : null;
            const errMsg = state.status === 'error' ? (state.error ?? 'Unknown error') : null;

            if (report) {
              const assistantMsg: ChatMessage = {
                role: 'assistant',
                content: report,
                agent_id: agentId,
                query_type: state.queryType,
                model_used: state.modelUsed ?? undefined,
                processed_at: state.completedAt ?? new Date().toISOString(),
              };
              if (state.sources) {
                assistantMsg.sources = state.sources;
                assistantMsg._meta = {
                  total_sources: state.sources.length,
                  total_items: state.sources.reduce((n, s) => n + s.items, 0),
                };
              }
              session.messages.push(assistantMsg);

              const maxHistory = 50;
              if (session.messages.length > maxHistory) {
                const systemMsgs = session.messages.filter((m) => m.role === 'system');
                const recent = session.messages.slice(-maxHistory + systemMsgs.length);
                session.messages = [...systemMsgs, ...recent.slice(-maxHistory)];
              }

              try {
                await saveSession(c, db, session);
              } catch (_catchErr) {
                logError('handler failed', _catchErr);
              }
            }

            send(
              JSON.stringify({
                type: state.status,
                report,
                error: errMsg,
                modelUsed: state.modelUsed,
                sources: state.sources,
                _meta: state.sources
                  ? {
                      total_sources: state.sources.length,
                      total_items: state.sources.reduce((n, s) => n + s.items, 0),
                    }
                  : undefined,
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
            }
            return;
          }

          scheduleNext(hasNew ? 400 : Math.min(pollDelay * 1.5, MAX_POLL_DELAY));
        } catch (_catchErr) {
          logError('handler failed', _catchErr);
          scheduleNext(pollDelay);
        }
      };

      const scheduleNext = (delay: number) => {
        pollDelay = delay;
        if (!closed) void pollTimeout(delay).then(poll);
      };

      const heartbeatInterval = setInterval(() => {
        if (!closed) send(JSON.stringify({ type: 'heartbeat' }));
        else clearInterval(heartbeatInterval);
      }, 15000);

      const timeoutTimer = setTimeout(() => {
        if (!closed) {
          cleanup();
          closed = true;
          send(JSON.stringify({ type: 'error', error: 'Stream timed out after 120s' }));
          try {
            controller.close();
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
          }
        }
      }, 120_000);

      let cleanupRan = false;
      const cleanup = () => {
        if (cleanupRan) return;
        cleanupRan = true;
        clearInterval(heartbeatInterval);
        clearTimeout(timeoutTimer);
      };

      c.req.raw.signal.addEventListener(
        'abort',
        () => {
          cleanup();
          closed = true;
          try {
            controller.close();
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
          }
        },
        { once: true }
      );

      void poll(); // start first poll
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

export async function copilotChatCancelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
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
    logError('copilotChatCancelHandler failed', e);
    return internalError(c, e);
  }
}

export async function copilotChatDeleteHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const sessionId = c.req.param('sessionId');
    if (!sessionId) return badRequest(c, 'sessionId required');

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const existing = await loadSession(c, db, sessionId);
    if (!existing) return notFound(c, 'session not found');

    await db.prepare('DELETE FROM copilot_sessions WHERE id = ?').bind(sessionId).run();
    return c.json({ deleted: true });
  } catch (e) {
    logError('copilotChatDeleteHandler failed', e);
    return internalError(c, e);
  }
}

export async function copilotChatHistoryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const sessionId = c.req.param('sessionId');
    if (!sessionId) return badRequest(c, 'sessionId required');

    const db = c.env.BRIEFINGS_DB as D1Database | undefined;
    if (!db) return internalError(c, new Error('BRIEFINGS_DB not bound'));

    const session = await loadSession(c, db, sessionId);
    if (!session) return notFound(c, 'session not found');

    return c.json({
      sessionId: session.id,
      title: session.title,
      messages: session.messages,
      created_at: session.created_at,
      updated_at: session.updated_at,
    });
  } catch (e) {
    logError('copilotChatHistoryHandler failed', e);
    return internalError(c, e);
  }
}
