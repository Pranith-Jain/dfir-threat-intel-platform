import type { Context } from 'hono';
import type { Env } from '../env';
import { safeJsonBody } from '../lib/safe-body';
import { badRequest, notFound, serviceUnavailable } from '../lib/api-error';
import type { D1Database } from '@cloudflare/workers-types';

// ── Types ──────────────────────────────────────────────────────────────

export interface Notebook {
  id: string;
  title: string;
  description: string;
  status: 'open' | 'investigating' | 'resolved' | 'archived';
  tags: string[];
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
  updated_at: string;
}

export interface NotebookEntry {
  id: string;
  notebook_id: string;
  entry_type: 'note' | 'ioc' | 'finding' | 'timeline' | 'artifact';
  content: string;
  metadata: Record<string, unknown>;
  pinned: boolean;
  created_at: string;
  updated_at: string;
}

// ── D1 helpers ─────────────────────────────────────────────────────────

async function ensureNotebookTables(db: D1Database): Promise<void> {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS investigation_notebooks (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open', tags TEXT NOT NULL DEFAULT '[]',
        severity TEXT NOT NULL DEFAULT 'info', created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`
    )
    .run();
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS notebook_entries (
        id TEXT PRIMARY KEY, notebook_id TEXT NOT NULL, entry_type TEXT NOT NULL DEFAULT 'note',
        content TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', pinned INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`
    )
    .run();
}

function rowToNotebook(row: Record<string, unknown>): Notebook {
  return {
    id: row.id as string,
    title: row.title as string,
    description: (row.description as string) ?? '',
    status: (row.status as Notebook['status']) ?? 'open',
    tags: JSON.parse((row.tags as string) ?? '[]') as string[],
    severity: (row.severity as Notebook['severity']) ?? 'info',
    created_at: row.created_at as string,
    updated_at: row.updated_at as string,
  };
}

function rowToEntry(row: Record<string, unknown>): NotebookEntry {
  return {
    id: row.id as string,
    notebook_id: row.notebook_id as string,
    entry_type: (row.entry_type as NotebookEntry['entry_type']) ?? 'note',
    content: row.content as string,
    metadata: JSON.parse((row.metadata as string) ?? '{}') as Record<string, unknown>,
    pinned: Boolean(row.pinned),
    created_at: row.created_at as string,
    updated_at: row.updated_at as string,
  };
}

// ── Handlers ───────────────────────────────────────────────────────────

// sql-audit: accept-reason the interpolated fragment is a ternary between two
// hardcoded strings (' WHERE status = ?' or ''); the `status` value itself is
// bound via .bind(). Nothing user-supplied reaches the statement text.
export async function listNotebooksHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const status = c.req.query('status');
  const limit = Math.min(Number(c.req.query('limit') ?? '50'), 200);
  const offset = Number(c.req.query('offset') ?? '0');

  let query =
    'SELECT id, title, description, status, tags, severity, created_at, updated_at FROM investigation_notebooks';
  const params: unknown[] = [];
  if (status) {
    query += ' WHERE status = ?';
    params.push(status);
  }
  query += ' ORDER BY updated_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const result = await db
    .prepare(query)
    .bind(...params)
    .all<Record<string, unknown>>();
  const notebooks = (result.results ?? []).map(rowToNotebook);

  const countResult = await db
    .prepare(`SELECT COUNT(*) as total FROM investigation_notebooks${status ? ' WHERE status = ?' : ''}`)
    .bind(...(status ? [status] : []))
    .first<{ total: number }>();

  return c.json({ notebooks, total: countResult?.total ?? 0, limit, offset });
}

export async function getNotebookHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const id = c.req.param('id');
  const row = await db
    .prepare(
      'SELECT id, title, description, status, tags, severity, created_at, updated_at FROM investigation_notebooks WHERE id = ?'
    )
    .bind(id)
    .first<Record<string, unknown>>();
  if (!row) return notFound(c, 'notebook not found');

  const entries = await db
    .prepare(
      'SELECT id, notebook_id, entry_type, content, metadata, pinned, created_at, updated_at FROM notebook_entries WHERE notebook_id = ? ORDER BY pinned DESC, created_at DESC'
    )
    .bind(id)
    .all<Record<string, unknown>>();

  return c.json({
    notebook: rowToNotebook(row),
    entries: (entries.results ?? []).map(rowToEntry),
  });
}

export async function createNotebookHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const parsed = await safeJsonBody<{
    title: string;
    description?: string;
    tags?: string[];
    severity?: Notebook['severity'];
  }>(c, {
    maxBytes: 8 * 1024,
    maxDepth: 4,
  });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;

  if (!body.title?.trim()) return badRequest(c, 'title is required');

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const tags = JSON.stringify(body.tags ?? []);
  const severity = body.severity ?? 'info';

  await db
    .prepare(
      `INSERT INTO investigation_notebooks (id, title, description, tags, severity, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(id, body.title.trim(), (body.description ?? '').trim(), tags, severity, now, now)
    .run();

  const row = await db
    .prepare(
      'SELECT id, title, description, status, tags, severity, created_at, updated_at FROM investigation_notebooks WHERE id = ?'
    )
    .bind(id)
    .first<Record<string, unknown>>();
  return c.json({ notebook: rowToNotebook(row!) }, 201);
}

export async function updateNotebookHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const id = c.req.param('id');
  const existing = await db
    .prepare(
      'SELECT id, title, description, status, tags, severity, created_at, updated_at FROM investigation_notebooks WHERE id = ?'
    )
    .bind(id)
    .first<Record<string, unknown>>();
  if (!existing) return notFound(c, 'notebook not found');

  const parsed = await safeJsonBody<Partial<Pick<Notebook, 'title' | 'description' | 'status' | 'tags' | 'severity'>>>(
    c,
    {
      maxBytes: 8 * 1024,
      maxDepth: 4,
    }
  );
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;

  const current = rowToNotebook(existing);
  const updated = {
    title: body.title ?? current.title,
    description: body.description ?? current.description,
    status: body.status ?? current.status,
    tags: body.tags ?? current.tags,
    severity: body.severity ?? current.severity,
  };

  const now = new Date().toISOString();
  await db
    .prepare(
      `UPDATE investigation_notebooks SET title = ?, description = ?, status = ?, tags = ?, severity = ?, updated_at = ? WHERE id = ?`
    )
    .bind(updated.title, updated.description, updated.status, JSON.stringify(updated.tags), updated.severity, now, id)
    .run();

  const row = await db
    .prepare(
      'SELECT id, title, description, status, tags, severity, created_at, updated_at FROM investigation_notebooks WHERE id = ?'
    )
    .bind(id)
    .first<Record<string, unknown>>();
  return c.json({ notebook: rowToNotebook(row!) });
}

export async function deleteNotebookHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const id = c.req.param('id');
  const existing = await db.prepare('SELECT id FROM investigation_notebooks WHERE id = ?').bind(id).first();
  if (!existing) return notFound(c, 'notebook not found');

  await db.prepare('DELETE FROM notebook_entries WHERE notebook_id = ?').bind(id).run();
  await db.prepare('DELETE FROM investigation_notebooks WHERE id = ?').bind(id).run();
  return c.json({ deleted: true });
}

// ── Entry handlers ─────────────────────────────────────────────────────

export async function addEntryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const notebookId = c.req.param('id');
  const nb = await db.prepare('SELECT id FROM investigation_notebooks WHERE id = ?').bind(notebookId).first();
  if (!nb) return notFound(c, 'notebook not found');

  const parsed = await safeJsonBody<{
    entry_type?: NotebookEntry['entry_type'];
    content: string;
    metadata?: Record<string, unknown>;
    pinned?: boolean;
  }>(c, {
    maxBytes: 256 * 1024,
    maxDepth: 6,
  });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;

  if (!body.content?.trim()) return badRequest(c, 'content is required');

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const entryType = body.entry_type ?? 'note';
  const metadata = JSON.stringify(body.metadata ?? {});
  const pinned = body.pinned ? 1 : 0;

  await db
    .prepare(
      `INSERT INTO notebook_entries (id, notebook_id, entry_type, content, metadata, pinned, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(id, notebookId, entryType, body.content.trim(), metadata, pinned, now, now)
    .run();

  // Touch the notebook's updated_at
  await db.prepare('UPDATE investigation_notebooks SET updated_at = ? WHERE id = ?').bind(now, notebookId).run();

  const row = await db
    .prepare(
      'SELECT id, notebook_id, entry_type, content, metadata, pinned, created_at, updated_at FROM notebook_entries WHERE id = ?'
    )
    .bind(id)
    .first<Record<string, unknown>>();
  return c.json({ entry: rowToEntry(row!) }, 201);
}

export async function updateEntryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const entryId = c.req.param('entryId');
  const existing = await db
    .prepare(
      'SELECT id, notebook_id, entry_type, content, metadata, pinned, created_at, updated_at FROM notebook_entries WHERE id = ?'
    )
    .bind(entryId)
    .first<Record<string, unknown>>();
  if (!existing) return notFound(c, 'entry not found');

  const parsed = await safeJsonBody<Partial<Pick<NotebookEntry, 'content' | 'entry_type' | 'metadata' | 'pinned'>>>(c, {
    maxBytes: 256 * 1024,
    maxDepth: 6,
  });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;

  const current = rowToEntry(existing);
  const content = body.content ?? current.content;
  const entryType = body.entry_type ?? current.entry_type;
  const metadata = body.metadata ? JSON.stringify(body.metadata) : JSON.stringify(current.metadata);
  const pinned = body.pinned !== undefined ? (body.pinned ? 1 : 0) : current.pinned ? 1 : 0;
  const now = new Date().toISOString();

  await db
    .prepare(
      'UPDATE notebook_entries SET content = ?, entry_type = ?, metadata = ?, pinned = ?, updated_at = ? WHERE id = ?'
    )
    .bind(content, entryType, metadata, pinned, now, entryId)
    .run();

  await db
    .prepare('UPDATE investigation_notebooks SET updated_at = ? WHERE id = ?')
    .bind(now, current.notebook_id)
    .run();

  const row = await db
    .prepare(
      'SELECT id, notebook_id, entry_type, content, metadata, pinned, created_at, updated_at FROM notebook_entries WHERE id = ?'
    )
    .bind(entryId)
    .first<Record<string, unknown>>();
  return c.json({ entry: rowToEntry(row!) });
}

export async function deleteEntryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const entryId = c.req.param('entryId');
  const existing = await db
    .prepare(
      'SELECT id, notebook_id, entry_type, content, metadata, pinned, created_at, updated_at FROM notebook_entries WHERE id = ?'
    )
    .bind(entryId)
    .first<Record<string, unknown>>();
  if (!existing) return notFound(c, 'entry not found');

  await db.prepare('DELETE FROM notebook_entries WHERE id = ?').bind(entryId).run();
  const now = new Date().toISOString();
  await db
    .prepare('UPDATE investigation_notebooks SET updated_at = ? WHERE id = ?')
    .bind(now, existing.notebook_id)
    .run();

  return c.json({ deleted: true });
}

export async function notebookStatsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureNotebookTables(db);

  const nbCount = await db.prepare('SELECT COUNT(*) as total FROM investigation_notebooks').first<{ total: number }>();
  const entryCount = await db.prepare('SELECT COUNT(*) as total FROM notebook_entries').first<{ total: number }>();
  const byStatus = await db
    .prepare('SELECT status, COUNT(*) as count FROM investigation_notebooks GROUP BY status')
    .all<{ status: string; count: number }>();
  const byType = await db
    .prepare('SELECT entry_type, COUNT(*) as count FROM notebook_entries GROUP BY entry_type')
    .all<{ entry_type: string; count: number }>();

  return c.json({
    notebooks: nbCount?.total ?? 0,
    entries: entryCount?.total ?? 0,
    by_status: Object.fromEntries((byStatus.results ?? []).map((r) => [r.status, r.count])),
    by_entry_type: Object.fromEntries((byType.results ?? []).map((r) => [r.entry_type, r.count])),
  });
}
