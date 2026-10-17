/**
 * SHIFTLOG — SOC shift handover tracker.
 *
 * Edge-native handover log replicated from
 * https://h3ad-sec.github.io/SHIFTLOG/. Stores entries in D1
 * (BRIEFINGS_DB) with table `shiftlog_entries` so multiple analysts
 * can record / fetch / update the running handover.
 *
 * Tables are created on first use via a CREATE TABLE IF NOT EXISTS
 * migration — no separate D1 migration step required. Idempotent.
 *
 * Entry shape:
 *   {
 *     id: string,        // ULID-like: sl_<base32 ts><base32 rand>
 *     shift: 'morning' | 'afternoon' | 'night' | 'weekend' | 'oncall',
 *     author: string,    // analyst handle
 *     startedAt: string, // ISO timestamp
 *     endedAt: string | null,
 *     openCases: string[],  // case ids
 *     iocs: string[],       // plain IOC strings
 *     escalations: string[],
 *     notes: string,
 *     createdAt: string,
 *     updatedAt: string,
 *   }
 *
 * Exposed as:
 *   - MCP tools `si_shiftlog_list`, `si_shiftlog_create`, `si_shiftlog_update`, `si_shiftlog_close`
 *   - REST  /api/v1/si/shiftlog
 */

import { errMessage } from './err';

export interface EnvWithDb {
  BRIEFINGS_DB?: D1Database;
}

export type Shift = 'morning' | 'afternoon' | 'night' | 'weekend' | 'oncall';

export interface ShiftLogEntry {
  id: string;
  shift: Shift;
  author: string;
  startedAt: string;
  endedAt: string | null;
  openCases: string[];
  iocs: string[];
  escalations: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateShiftLogInput {
  shift: Shift;
  author: string;
  startedAt?: string;
  openCases?: string[];
  iocs?: string[];
  escalations?: string[];
  notes?: string;
}

export interface UpdateShiftLogInput {
  openCases?: string[];
  iocs?: string[];
  escalations?: string[];
  notes?: string;
  endedAt?: string | null;
}

const ALLOWED_SHIFTS: Shift[] = ['morning', 'afternoon', 'night', 'weekend', 'oncall'];

// ---------------------------------------------------------------------------
// Schema bootstrap — runs CREATE TABLE IF NOT EXISTS once per Worker
// instance, then a no-op on subsequent calls. Cheap.
// ---------------------------------------------------------------------------

let schemaReady: Promise<void> | null = null;

function ensureSchema(db: D1Database): Promise<void> {
  if (!schemaReady) {
    schemaReady = (async () => {
      await db
        .prepare(
          `CREATE TABLE IF NOT EXISTS shiftlog_entries (
          id TEXT PRIMARY KEY,
          shift TEXT NOT NULL,
          author TEXT NOT NULL,
          started_at TEXT NOT NULL,
          ended_at TEXT,
          open_cases TEXT NOT NULL DEFAULT '[]',
          iocs TEXT NOT NULL DEFAULT '[]',
          escalations TEXT NOT NULL DEFAULT '[]',
          notes TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
        )
        .run();
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_shiftlog_started ON shiftlog_entries(started_at DESC)').run();
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_shiftlog_author ON shiftlog_entries(author)').run();
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

// ---------------------------------------------------------------------------
// ID generation — base32 timestamp + 6 random bytes. Sortable by time.
// ---------------------------------------------------------------------------

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function generateId(now: Date = new Date()): string {
  let ts = '';
  let t = now.getTime();
  for (let i = 0; i < 10; i++) {
    ts = B32[t % 32] + ts;
    t = Math.floor(t / 32);
  }
  let rand = '';
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  for (let i = 0; i < bytes.length; i++) {
    rand += B32[bytes[i]! % 32];
  }
  return `sl_${ts}${rand}`;
}

function rowToEntry(row: Record<string, unknown>): ShiftLogEntry {
  return {
    id: String(row.id),
    shift: String(row.shift) as Shift,
    author: String(row.author),
    startedAt: String(row.started_at),
    endedAt: row.ended_at ? String(row.ended_at) : null,
    openCases: safeJsonArray(row.open_cases),
    iocs: safeJsonArray(row.iocs),
    escalations: safeJsonArray(row.escalations),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function safeJsonArray(v: unknown): string[] {
  if (!v) return [];
  if (typeof v !== 'string') return [];
  try {
    const parsed = JSON.parse(v);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch (_catchErr) {
    console.error('safeJsonArray failed:', errMessage(_catchErr));
    return [];
  }
}

// ---------------------------------------------------------------------------
// CRUD operations.
// ---------------------------------------------------------------------------

export async function shiftlogCreate(env: EnvWithDb, input: CreateShiftLogInput): Promise<ShiftLogEntry> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing — Worker cannot store SHIFTLOG entries.');
  if (!ALLOWED_SHIFTS.includes(input.shift)) {
    throw new Error(`Invalid shift '${input.shift}'. Allowed: ${ALLOWED_SHIFTS.join(', ')}`);
  }
  if (!input.author || input.author.length > 64) {
    throw new Error('author is required and must be ≤64 chars');
  }
  await ensureSchema(db);
  const now = new Date();
  const id = generateId(now);
  const startedAt = input.startedAt ?? now.toISOString();
  const openCases = (input.openCases ?? []).map(String).slice(0, 100);
  const iocs = (input.iocs ?? []).map(String).slice(0, 500);
  const escalations = (input.escalations ?? []).map(String).slice(0, 100);
  const notes = String(input.notes ?? '').slice(0, 8000);
  const createdAt = now.toISOString();
  await db
    .prepare(
      `INSERT INTO shiftlog_entries
        (id, shift, author, started_at, ended_at, open_cases, iocs, escalations, notes, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9, ?9)`
    )
    .bind(
      id,
      input.shift,
      input.author,
      startedAt,
      JSON.stringify(openCases),
      JSON.stringify(iocs),
      JSON.stringify(escalations),
      notes,
      createdAt
    )
    .run();
  return {
    id,
    shift: input.shift,
    author: input.author,
    startedAt,
    endedAt: null,
    openCases,
    iocs,
    escalations,
    notes,
    createdAt,
    updatedAt: createdAt,
  };
}

export async function shiftlogGet(env: EnvWithDb, id: string): Promise<ShiftLogEntry | null> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  await ensureSchema(db);
  const row = await db
    .prepare(
      'SELECT id, shift, author, started_at, ended_at, open_cases, iocs, escalations, notes, created_at, updated_at FROM shiftlog_entries WHERE id = ?1'
    )
    .bind(id)
    .first();
  return row ? rowToEntry(row) : null;
}

export async function shiftlogList(
  env: EnvWithDb,
  opts: { author?: string; shift?: Shift; openOnly?: boolean; limit?: number } = {}
): Promise<ShiftLogEntry[]> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  await ensureSchema(db);
  const limit = Math.min(100, Math.max(1, opts.limit ?? 20));
  const conds: string[] = [];
  const binds: unknown[] = [];
  if (opts.author) {
    conds.push('author = ?');
    binds.push(opts.author);
  }
  if (opts.shift) {
    conds.push('shift = ?');
    binds.push(opts.shift);
  }
  if (opts.openOnly) {
    conds.push('ended_at IS NULL');
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const sql = `SELECT id, shift, author, started_at, ended_at, open_cases, iocs, escalations, notes, created_at, updated_at FROM shiftlog_entries ${where} ORDER BY started_at DESC LIMIT ${limit}`;
  const res = await db
    .prepare(sql)
    .bind(...binds)
    .all();
  return (res.results ?? []).map((r) => rowToEntry(r as Record<string, unknown>));
}

export async function shiftlogUpdate(
  env: EnvWithDb,
  id: string,
  patch: UpdateShiftLogInput
): Promise<ShiftLogEntry | null> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  await ensureSchema(db);
  const existing = await shiftlogGet(env, id);
  if (!existing) return null;
  const updated: ShiftLogEntry = {
    ...existing,
    openCases: patch.openCases ?? existing.openCases,
    iocs: patch.iocs ?? existing.iocs,
    escalations: patch.escalations ?? existing.escalations,
    notes: patch.notes ?? existing.notes,
    endedAt: patch.endedAt === undefined ? existing.endedAt : patch.endedAt,
    updatedAt: new Date().toISOString(),
  };
  await db
    .prepare(
      `UPDATE shiftlog_entries
         SET open_cases = ?1, iocs = ?2, escalations = ?3, notes = ?4,
             ended_at = ?5, updated_at = ?6
       WHERE id = ?7`
    )
    .bind(
      JSON.stringify(updated.openCases),
      JSON.stringify(updated.iocs),
      JSON.stringify(updated.escalations),
      updated.notes,
      updated.endedAt,
      updated.updatedAt,
      id
    )
    .run();
  return updated;
}

export async function shiftlogClose(env: EnvWithDb, id: string, endedAt?: string): Promise<ShiftLogEntry | null> {
  return shiftlogUpdate(env, id, { endedAt: endedAt ?? new Date().toISOString() });
}
