import type { Context } from 'hono';
import type { Env } from '../env';
import { badRequest, notFound, serviceUnavailable } from '../lib/api-error';
import { safeJsonBody } from '../lib/safe-body';
import { callerOwnerId, ownerVisibilityFilter, ownerCheck } from '../lib/ownership';
import type { D1Database } from '@cloudflare/workers-types';

const WS_COLS =
  'id, title, description, target, target_type, phase, status, exposure_score, exposure_label, tags, metadata, created_at, updated_at, owner_hash';

/** Fetch a workspace row, 404ing when missing OR owned by another caller. */
async function getVisibleWorkspace(
  c: Context<{ Bindings: Env }>,
  db: D1Database,
  id: string | undefined
): Promise<Record<string, unknown> | null> {
  const row = await db.prepare(`SELECT ${WS_COLS} FROM investigation_workspaces WHERE id = ?`).bind(id).first();
  if (!row) return null;
  if (ownerCheck(c, row.owner_hash as string | null) === 'hidden') return null;
  return row;
}

/** Child collections (subjects/connections/findings/timeline) hang off a
 *  workspace — gate them all on the parent's visibility. */
async function wsVisible(c: Context<{ Bindings: Env }>, db: D1Database, id: string | undefined): Promise<boolean> {
  return (await getVisibleWorkspace(c, db, id)) !== null;
}

// ─── Helpers ──────────────────────────────────────────────────────────

function genId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}

async function ensureWorkspaceTables(db: D1Database): Promise<void> {
  await db
    .prepare(
      `
    CREATE TABLE IF NOT EXISTS investigation_workspaces (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
      target TEXT NOT NULL DEFAULT '', target_type TEXT NOT NULL DEFAULT 'domain',
      phase TEXT NOT NULL DEFAULT 'acquire', status TEXT NOT NULL DEFAULT 'open',
      exposure_score INTEGER DEFAULT 0, exposure_label TEXT NOT NULL DEFAULT 'Unknown',
      tags TEXT NOT NULL DEFAULT '[]', metadata TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
  `
    )
    .run();
  await db
    .prepare(
      `
    CREATE TABLE IF NOT EXISTS ws_subjects (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, subject_type TEXT NOT NULL,
      label TEXT NOT NULL, value TEXT NOT NULL DEFAULT '', confidence INTEGER DEFAULT 50,
      trust_score INTEGER DEFAULT 3, verified INTEGER NOT NULL DEFAULT 0,
      aliases TEXT NOT NULL DEFAULT '[]', notes TEXT NOT NULL DEFAULT '',
      first_seen TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
  `
    )
    .run();
  await db
    .prepare(
      `
    CREATE TABLE IF NOT EXISTS ws_connections (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, from_subject_id TEXT NOT NULL,
      to_subject_id TEXT NOT NULL, relationship TEXT NOT NULL DEFAULT 'linked_to',
      strength TEXT NOT NULL DEFAULT 'confirmed', notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
  `
    )
    .run();
  await db
    .prepare(
      `
    CREATE TABLE IF NOT EXISTS ws_findings (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, subject_id TEXT,
      finding_type TEXT NOT NULL DEFAULT 'infrastructure', weight TEXT NOT NULL DEFAULT 'MEDIUM',
      description TEXT NOT NULL, source_url TEXT NOT NULL DEFAULT '',
      source_reliability TEXT DEFAULT 'C', confidence INTEGER DEFAULT 50,
      trust_score INTEGER DEFAULT 3, collection_method TEXT NOT NULL DEFAULT 'search',
      tags TEXT NOT NULL DEFAULT '[]', validated INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
  `
    )
    .run();
  await db
    .prepare(
      `
    CREATE TABLE IF NOT EXISTS ws_timeline (
      id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL,
      event_date TEXT NOT NULL, event_type TEXT NOT NULL DEFAULT 'observation',
      description TEXT NOT NULL, subject_id TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
  `
    )
    .run();
}

function rowToWs(row: Record<string, unknown>) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    target: row.target,
    targetType: row.target_type,
    phase: row.phase,
    status: row.status,
    exposureScore: row.exposure_score,
    exposureLabel: row.exposure_label,
    tags: JSON.parse((row.tags as string) || '[]'),
    metadata: JSON.parse((row.metadata as string) || '{}'),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ─── Workspace CRUD ───

export async function listWorkspacesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureWorkspaceTables(db);

  const status = c.req.query('status');
  // `|| 50` absorbs a non-numeric `limit` (Number('abc') is NaN, and Math.min(…, NaN)
  // is NaN) which would otherwise reach SQL as `LIMIT NaN` — a SQLite syntax error
  // and a 500. Same idiom as cti-collector.ts / cyberpulse.ts.
  const limit = Math.min(Number(c.req.query('limit')) || 50, 200);

  const vis = ownerVisibilityFilter(c);
  let query = `SELECT id, title, description, target, target_type, phase, status, exposure_score, exposure_label, tags, metadata, created_at, updated_at FROM investigation_workspaces WHERE ${vis.clause}`;
  const params: unknown[] = [...vis.bindings];
  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }
  query += ' ORDER BY updated_at DESC LIMIT ?';
  params.push(limit);

  const { results } = await db
    .prepare(query)
    .bind(...params)
    .all();
  return c.json({ workspaces: results.map(rowToWs), count: results.length });
}

export async function createWorkspaceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureWorkspaceTables(db);

  const body = await safeJsonBody<{
    title: string;
    description?: string;
    target?: string;
    target_type?: string;
    tags?: string[];
  }>(c, { maxBytes: 8192 });
  if ('error' in body) return body.error;
  if (!body.value.title) return badRequest(c, 'title required');

  const id = genId('ws');
  const now = new Date().toISOString();
  const b = body.value;
  await db
    .prepare(
      `
    INSERT INTO investigation_workspaces (id, title, description, target, target_type, tags, created_at, updated_at, owner_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .bind(
      id,
      b.title,
      b.description || '',
      b.target || '',
      b.target_type || 'domain',
      JSON.stringify(b.tags || []),
      now,
      now,
      callerOwnerId(c)
    )
    .run();

  const row = await db.prepare(`SELECT ${WS_COLS} FROM investigation_workspaces WHERE id = ?`).bind(id).first();
  return c.json(rowToWs(row!), 201);
}

export async function getWorkspaceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureWorkspaceTables(db);

  const id = c.req.param('id');
  const ws = await getVisibleWorkspace(c, db, id);
  if (!ws) return notFound(c, 'workspace not found');

  const subjects = (
    await db
      .prepare(
        'SELECT id, workspace_id, subject_type, label, value, confidence, trust_score, verified, aliases, notes, first_seen, created_at FROM ws_subjects WHERE workspace_id = ?'
      )
      .bind(id)
      .all()
  ).results;
  const connections = (
    await db
      .prepare(
        'SELECT id, workspace_id, from_subject_id, to_subject_id, relationship, strength, notes, created_at FROM ws_connections WHERE workspace_id = ?'
      )
      .bind(id)
      .all()
  ).results;
  const findings = (
    await db
      .prepare(
        'SELECT id, workspace_id, subject_id, finding_type, weight, description, source_url, source_reliability, confidence, trust_score, collection_method, tags, validated, created_at FROM ws_findings WHERE workspace_id = ?'
      )
      .bind(id)
      .all()
  ).results;
  const timeline = (
    await db
      .prepare(
        'SELECT id, workspace_id, event_date, event_type, description, subject_id, created_at FROM ws_timeline WHERE workspace_id = ? ORDER BY event_date'
      )
      .bind(id)
      .all()
  ).results;

  return c.json({ workspace: rowToWs(ws), subjects, connections, findings, timeline });
}

export async function updateWorkspaceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureWorkspaceTables(db);

  const id = c.req.param('id');
  const body = await safeJsonBody<Record<string, unknown>>(c, { maxBytes: 4096 });
  if ('error' in body) return body.error;

  const sets: string[] = [];
  const values: unknown[] = [];
  const b = body.value;
  for (const key of ['title', 'description', 'phase', 'status', 'exposure_score', 'exposure_label']) {
    const dbKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
    if (b[key] !== undefined) {
      sets.push(`${dbKey} = ?`);
      values.push(b[key]);
    }
  }
  if (b.tags !== undefined) {
    sets.push('tags = ?');
    values.push(JSON.stringify(b.tags));
  }
  if (b.metadata !== undefined) {
    sets.push('metadata = ?');
    values.push(JSON.stringify(b.metadata));
  }

  if (sets.length === 0) return badRequest(c, 'no fields to update');
  sets.push("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')");
  values.push(id);

  await db
    .prepare(`UPDATE investigation_workspaces SET ${sets.join(', ')} WHERE id = ?`)
    .bind(...values)
    .run();
  const row = await getVisibleWorkspace(c, db, id);
  if (!row) return notFound(c, 'workspace not found');
  return c.json(rowToWs(row));
}

export async function deleteWorkspaceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  await ensureWorkspaceTables(db);

  const id = c.req.param('id');
  const ws = await getVisibleWorkspace(c, db, id);
  if (!ws) return notFound(c, 'workspace not found');
  await db.prepare('DELETE FROM ws_timeline WHERE workspace_id = ?').bind(id).run();
  await db.prepare('DELETE FROM ws_findings WHERE workspace_id = ?').bind(id).run();
  await db.prepare('DELETE FROM ws_connections WHERE workspace_id = ?').bind(id).run();
  await db.prepare('DELETE FROM ws_subjects WHERE workspace_id = ?').bind(id).run();
  await db.prepare('DELETE FROM investigation_workspaces WHERE id = ?').bind(id).run();
  return c.json({ success: true });
}

// ─── Subjects ───

export async function listSubjectsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const { results } = await db
    .prepare(
      'SELECT id, workspace_id, subject_type, label, value, confidence, trust_score, verified, aliases, notes, first_seen, created_at FROM ws_subjects WHERE workspace_id = ?'
    )
    .bind(wsId)
    .all();
  return c.json({ subjects: results, count: results.length });
}

export async function createSubjectHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const body = await safeJsonBody<{
    label: string;
    subject_type: string;
    value?: string;
    confidence?: number;
    trust_score?: number;
    verified?: boolean;
    aliases?: string[];
    notes?: string;
    first_seen?: string;
  }>(c, { maxBytes: 4096 });
  if ('error' in body) return body.error;
  if (!body.value.label || !body.value.subject_type) return badRequest(c, 'label and subject_type required');

  const id = genId('sub');
  const b = body.value;
  await db
    .prepare(
      `
    INSERT INTO ws_subjects (id, workspace_id, subject_type, label, value, confidence, trust_score, verified, aliases, notes, first_seen, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
  `
    )
    .bind(
      id,
      wsId,
      b.subject_type,
      b.label,
      b.value || '',
      b.confidence ?? 50,
      b.trust_score ?? 3,
      b.verified ? 1 : 0,
      JSON.stringify(b.aliases || []),
      b.notes || '',
      b.first_seen || ''
    )
    .run();

  const row = await db
    .prepare(
      'SELECT id, workspace_id, subject_type, label, value, confidence, trust_score, verified, aliases, notes, first_seen, created_at FROM ws_subjects WHERE id = ?'
    )
    .bind(id)
    .first();
  return c.json(row, 201);
}

// ─── Connections ───

export async function listConnectionsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const { results } = await db
    .prepare(
      'SELECT id, workspace_id, from_subject_id, to_subject_id, relationship, strength, notes, created_at FROM ws_connections WHERE workspace_id = ?'
    )
    .bind(wsId)
    .all();
  return c.json({ connections: results, count: results.length });
}

export async function createConnectionHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const body = await safeJsonBody<{
    from_subject_id: string;
    to_subject_id: string;
    relationship: string;
    strength?: string;
    notes?: string;
  }>(c, { maxBytes: 4096 });
  if ('error' in body) return body.error;
  const b = body.value;
  if (!b.from_subject_id || !b.to_subject_id || !b.relationship)
    return badRequest(c, 'from_subject_id, to_subject_id, relationship required');

  const id = genId('conn');
  await db
    .prepare(
      `
    INSERT INTO ws_connections (id, workspace_id, from_subject_id, to_subject_id, relationship, strength, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
  `
    )
    .bind(id, wsId, b.from_subject_id, b.to_subject_id, b.relationship, b.strength || 'confirmed', b.notes || '')
    .run();

  const row = await db
    .prepare(
      'SELECT id, workspace_id, from_subject_id, to_subject_id, relationship, strength, notes, created_at FROM ws_connections WHERE id = ?'
    )
    .bind(id)
    .first();
  return c.json(row, 201);
}

// ─── Findings ───

export async function listFindingsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const { results } = await db
    .prepare(
      'SELECT id, workspace_id, subject_id, finding_type, weight, description, source_url, source_reliability, confidence, trust_score, collection_method, tags, validated, created_at FROM ws_findings WHERE workspace_id = ?'
    )
    .bind(wsId)
    .all();
  return c.json({ findings: results, count: results.length });
}

export async function createFindingHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const body = await safeJsonBody<{
    description: string;
    subject_id?: string;
    finding_type?: string;
    weight?: string;
    source_url?: string;
    confidence?: number;
    tags?: string[];
  }>(c, { maxBytes: 8192 });
  if ('error' in body) return body.error;
  if (!body.value.description) return badRequest(c, 'description required');

  const id = genId('fnd');
  const b = body.value;
  await db
    .prepare(
      `
    INSERT INTO ws_findings (id, workspace_id, subject_id, finding_type, weight, description, source_url, confidence, tags, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
  `
    )
    .bind(
      id,
      wsId,
      b.subject_id || null,
      b.finding_type || 'infrastructure',
      b.weight || 'MEDIUM',
      b.description,
      b.source_url || '',
      b.confidence ?? 50,
      JSON.stringify(b.tags || [])
    )
    .run();

  const row = await db
    .prepare(
      'SELECT id, workspace_id, subject_id, finding_type, weight, description, source_url, source_reliability, confidence, trust_score, collection_method, tags, validated, created_at FROM ws_findings WHERE id = ?'
    )
    .bind(id)
    .first();
  return c.json(row, 201);
}

// ─── Timeline ───

export async function listTimelineHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const { results } = await db
    .prepare(
      'SELECT id, workspace_id, event_date, event_type, description, subject_id, created_at FROM ws_timeline WHERE workspace_id = ? ORDER BY event_date'
    )
    .bind(wsId)
    .all();
  return c.json({ timeline: results, count: results.length });
}

export async function addTimelineHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const wsId = c.req.param('id');
  if (!(await wsVisible(c, db, wsId))) return notFound(c, 'workspace not found');
  const body = await safeJsonBody<{
    event_date: string;
    description: string;
    event_type?: string;
    subject_id?: string;
  }>(c, { maxBytes: 4096 });
  if ('error' in body) return body.error;
  if (!body.value.event_date || !body.value.description) return badRequest(c, 'event_date and description required');

  const b = body.value;
  const result = await db
    .prepare(
      `
    INSERT INTO ws_timeline (workspace_id, event_date, event_type, description, subject_id)
    VALUES (?, ?, ?, ?, ?)
  `
    )
    .bind(wsId, b.event_date, b.event_type || 'observation', b.description, b.subject_id || null)
    .run();

  return c.json({ id: result.meta?.last_row_id, workspaceId: wsId, ...b }, 201);
}

// ─── Exposure Scoring ───

function clamp(v: number, lo = 0, hi = 100): number {
  return Math.max(lo, Math.min(hi, v));
}
const SCORE_BANDS: [number, string][] = [
  [76, 'Critical'],
  [51, 'Elevated'],
  [26, 'Moderate'],
  [0, 'Minimal'],
];
function scoreLabel(s: number) {
  for (const [t, l] of SCORE_BANDS) if (s >= t) return l;
  return 'Minimal';
}

export async function exposureScoreHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const body = await safeJsonBody<Record<string, unknown>>(c, { maxBytes: 16384 });
  if ('error' in body) return body.error;
  const b = body.value;
  if (!b.target) return badRequest(c, 'target required');

  const dimensions: Array<{ name: string; score: number; weight: number; signals: string[] }> = [];

  // IOC Reputation
  if (b.ioc_reputation) {
    const r = b.ioc_reputation as Record<string, unknown>;
    let score = 0;
    const signals: string[] = [];
    if (r.abuseScore !== undefined) {
      score = Math.max(score, clamp(r.abuseScore as number));
      signals.push(`AbuseIPDB: ${r.abuseScore}%`);
    }
    if (r.vtPositives !== undefined && r.vtTotal) {
      const ratio = ((r.vtPositives as number) / (r.vtTotal as number)) * 100;
      score = Math.max(score, clamp(ratio));
      signals.push(`VT: ${r.vtPositives}/${r.vtTotal}`);
    }
    if (r.inBlocklists) {
      score = Math.max(score, 80);
      signals.push('In blocklists');
    }
    if (r.isC2) {
      score = Math.max(score, 95);
      signals.push('Confirmed C2');
    }
    if (!signals.length) signals.push('No reputation signals');
    dimensions.push({ name: 'IOC Reputation', score, weight: 0.25, signals });
  }

  // Breach Exposure
  if (b.breach_exposure) {
    const r = b.breach_exposure as Record<string, unknown>;
    let score = 0;
    const signals: string[] = [];
    if (r.breachCount && (r.breachCount as number) > 0) {
      score = clamp((r.breachCount as number) * 15);
      signals.push(`${r.breachCount} breach(es)`);
    }
    if (r.hasStealerLogs) {
      score = clamp(score + 30);
      signals.push('Stealer logs');
    }
    if (!signals.length) signals.push('No breach exposure');
    dimensions.push({ name: 'Breach Exposure', score, weight: 0.2, signals });
  }

  // Infrastructure
  if (b.infrastructure) {
    const r = b.infrastructure as Record<string, unknown>;
    let score = 0;
    const signals: string[] = [];
    if (r.openPorts && (r.openPorts as number) > 10) {
      score = clamp(score + 25);
      signals.push(`${r.openPorts} open ports`);
    }
    if (!r.hasDMARC) {
      score = clamp(score + 15);
      signals.push('No DMARC');
    }
    if (r.exposedAdminPanels) {
      score = clamp(score + 20);
      signals.push('Exposed admin panels');
    }
    if (!signals.length) signals.push('Infrastructure OK');
    dimensions.push({ name: 'Infrastructure', score, weight: 0.2, signals });
  }

  // Attack Surface
  if (b.attack_surface) {
    const r = b.attack_surface as Record<string, unknown>;
    let score = 0;
    const signals: string[] = [];
    if (r.subdomainCount && (r.subdomainCount as number) > 50) {
      score = clamp(score + 20);
      signals.push(`${r.subdomainCount} subdomains`);
    }
    const svc = r.exposedServices as string[] | undefined;
    if (svc && svc.length) {
      score = clamp(score + svc.length * 8);
      signals.push(`Services: ${svc.join(', ')}`);
    }
    if (!signals.length) signals.push('Limited attack surface');
    dimensions.push({ name: 'Attack Surface', score, weight: 0.15, signals });
  }

  // Threat Intel
  if (b.threat_intel) {
    const r = b.threat_intel as Record<string, unknown>;
    let score = 0;
    const signals: string[] = [];
    if (r.greynoiseClass === 'malicious') {
      score = clamp(score + 60);
      signals.push('GreyNoise: malicious');
    }
    if (r.threatFoxMatch) {
      score = clamp(score + 40);
      signals.push('ThreatFox match');
    }
    if (r.ransomwareVictim) {
      score = clamp(score + 50);
      signals.push('Ransomware victim');
    }
    if (!signals.length) signals.push('No threat intel associations');
    dimensions.push({ name: 'Threat Intel', score, weight: 0.2, signals });
  }

  if (!dimensions.length) return badRequest(c, 'at least one dimension required');

  const totalWeight = dimensions.reduce((s, d) => s + d.weight, 0);
  const compositeScore = Math.round(dimensions.reduce((s, d) => s + d.score * d.weight, 0) / totalWeight);
  const label = scoreLabel(compositeScore);
  const recommendations = dimensions.filter((d) => d.score >= 50).map((d) => `${d.name}: ${d.score}/100`);

  return c.json({
    target: b.target,
    targetType: b.target_type || 'domain',
    compositeScore,
    label,
    dimensions,
    recommendations,
    calculatedAt: new Date().toISOString(),
  });
}

// ─── STIX Export ───

export async function exportStixCtiHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const body = await safeJsonBody<{
    indicators: Array<{ value: string; type?: string; confidence?: number; tlp?: string; tags?: string[] }>;
    bundle_name?: string;
    default_tlp?: string;
  }>(c, { maxBytes: 65536 });
  if ('error' in body) return body.error;
  if (!body.value.indicators?.length) return badRequest(c, 'indicators array required');

  const now = new Date().toISOString();
  const objects: Record<string, unknown>[] = [];
  let indIdx = 0;

  for (const ind of body.value.indicators) {
    indIdx++;
    const id = `indicator--${indIdx.toString(16).padStart(8, '0')}-${Date.now().toString(36)}`;
    let pattern = `[artifact:payload_bin = '${ind.value}']`;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ind.value)) pattern = `[ipv4-addr:value = '${ind.value}']`;
    else if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ind.value) && !ind.value.includes('/'))
      pattern = `[domain-name:value = '${ind.value}']`;
    else if (/^https?:\/\//i.test(ind.value)) pattern = `[url:value = '${ind.value}']`;
    else if (/^[a-f0-9]{64}$/i.test(ind.value)) pattern = `[file:hashes.'SHA-256' = '${ind.value}']`;

    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id,
      created: now,
      modified: now,
      name: ind.value,
      pattern,
      pattern_type: 'stix',
      valid_from: now,
      confidence: ind.confidence ?? 50,
      labels: ind.tags || [],
      object_marking_refs: [`marking-definition--tlp-${(ind.tlp || body.value.default_tlp || 'green').toLowerCase()}`],
    });
  }

  return c.json({
    type: 'bundle',
    id: `bundle--export-${Date.now().toString(36)}`,
    spec_version: '2.1',
    created: now,
    objects,
  });
}

// ─── ASCII Graph ───

const NODE_ICONS: Record<string, string> = {
  person: '👤',
  domain: '🌐',
  org: '🏢',
  username: '@',
  email: '📧',
  ip: '🖥',
  phone: '📱',
  location: '📍',
  asset: '📦',
  device: '🖥️',
  crypto: '💰',
  custom: '🏷️',
};

export async function renderGraphHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const body = await safeJsonBody<Record<string, unknown>>(c, { maxBytes: 32768 });
  if ('error' in body) return body.error;
  const b = body.value;
  if (!b.nodes && !b.events && !b.dimensions) return badRequest(c, 'nodes, events, or dimensions required');

  if (b.type === 'timeline' || b.events) {
    const events = (b.events || []) as Array<{ date: string; description: string }>;
    const lines = ['Timeline', '─'.repeat(40)];
    for (const e of events) lines.push(`${(e.date || '').padEnd(12)} ├── ${e.description}`);
    return c.json({ ascii: lines.join('\n'), type: 'timeline' });
  }

  if (b.type === 'risk' || b.dimensions) {
    const dims = (b.dimensions || []) as Array<{ name: string; score: number }>;
    const maxN = Math.max(...dims.map((d) => d.name.length), 15);
    const lines = ['Risk Assessment', '─'.repeat(maxN + 45)];
    for (const d of dims) {
      const barLen = Math.round((d.score || 0) / 2.5);
      lines.push(`${(d.name || '').padEnd(maxN)} ${'█'.repeat(barLen)}${'░'.repeat(40 - barLen)} ${d.score}/100`);
    }
    return c.json({ ascii: lines.join('\n'), type: 'risk' });
  }

  // Entity graph
  const nodes = (b.nodes || []) as Array<{
    id: string;
    type: string;
    label: string;
    trustScore: number;
    verified?: boolean;
  }>;
  const edges = (b.edges || []) as Array<{ from: string; to: string; relationship: string; strength: string }>;
  const lines: string[] = [];
  if (b.title)
    lines.push(
      `╭${'─'.repeat((b.title as string).length + 2)}╮`,
      `│ ${b.title} │`,
      `╰${'─'.repeat((b.title as string).length + 2)}╯`,
      ''
    );

  for (const node of nodes) {
    const icon = NODE_ICONS[node.type] || '•';
    const trust = `[${node.trustScore || '?'}/5]`;
    const text = `${icon} ${node.label} ${trust}`;
    lines.push(`┌${'─'.repeat(text.length + 2)}┐`, `│ ${text} │`, `└${'─'.repeat(text.length + 2)}┘`);
  }
  lines.push('', 'Connections:');
  for (const edge of edges) {
    const from = nodes.find((n) => n.id === edge.from);
    const to = nodes.find((n) => n.id === edge.to);
    if (!from || !to) continue;
    const arrow = edge.strength === 'confirmed' ? '═══▶' : '···▶';
    lines.push(
      `${NODE_ICONS[from.type] || '•'} ${from.label} ${arrow} [${edge.relationship}] ${NODE_ICONS[to.type] || '•'} ${to.label}`
    );
  }
  return c.json({ ascii: lines.join('\n'), type: 'entities' });
}

// ─── AEAD Workflow ───

const PHASES = ['acquire', 'enrich', 'assess', 'deliver', 'complete'] as const;

export async function workflowStateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const ws = await getVisibleWorkspace(c, db, c.req.param('id'));
  if (!ws) return notFound(c, 'workspace not found');
  const phaseIdx = PHASES.indexOf(ws.phase as (typeof PHASES)[number]);
  return c.json({
    workspaceId: ws.id,
    target: ws.target,
    targetType: ws.target_type,
    currentPhase: ws.phase,
    phases: PHASES.map((p, i) => ({
      phase: p,
      status: i < phaseIdx ? 'complete' : i === phaseIdx ? 'active' : 'pending',
      commandsRun: [],
      findingsCount: 0,
      subjectsDiscovered: 0,
    })),
  });
}

export async function workflowAdvanceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('id');
  const ws = await getVisibleWorkspace(c, db, id);
  if (!ws) return notFound(c, 'workspace not found');
  const idx = PHASES.indexOf(ws.phase as (typeof PHASES)[number]);
  if (idx >= PHASES.length - 1) return c.json({ workspace: rowToWs(ws), nextPhase: ws.phase });
  const next = PHASES[idx + 1];
  await db
    .prepare(
      `UPDATE investigation_workspaces SET phase = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?`
    )
    .bind(next, id)
    .run();
  const updated = await getVisibleWorkspace(c, db, id);
  return c.json({ workspace: rowToWs(updated!), nextPhase: next });
}

export async function workflowSummaryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('id');
  const ws = await getVisibleWorkspace(c, db, id);
  if (!ws) return notFound(c, 'workspace not found');
  const subjects =
    (await db.prepare('SELECT COUNT(*) as c FROM ws_subjects WHERE workspace_id = ?').bind(id).first())?.c ?? 0;
  const findings =
    (await db.prepare('SELECT COUNT(*) as c FROM ws_findings WHERE workspace_id = ?').bind(id).first())?.c ?? 0;
  return c.json({ workspace: rowToWs(ws), subjectsCount: subjects, findingsCount: findings, currentPhase: ws.phase });
}

// ─── Workspace Export ───

export async function exportWorkspaceHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('id');
  const ws = await getVisibleWorkspace(c, db, id);
  if (!ws) return notFound(c, 'workspace not found');

  const subjects = (
    await db
      .prepare(
        'SELECT id, workspace_id, subject_type, label, value, confidence, trust_score, verified, aliases, notes, first_seen, created_at FROM ws_subjects WHERE workspace_id = ?'
      )
      .bind(id)
      .all()
  ).results;
  const connections = (
    await db
      .prepare(
        'SELECT id, workspace_id, from_subject_id, to_subject_id, relationship, strength, notes, created_at FROM ws_connections WHERE workspace_id = ?'
      )
      .bind(id)
      .all()
  ).results;
  const findings = (
    await db
      .prepare(
        'SELECT id, workspace_id, subject_id, finding_type, weight, description, source_url, source_reliability, confidence, trust_score, collection_method, tags, validated, created_at FROM ws_findings WHERE workspace_id = ?'
      )
      .bind(id)
      .all()
  ).results;
  const timeline = (
    await db
      .prepare(
        'SELECT id, workspace_id, event_date, event_type, description, subject_id, created_at FROM ws_timeline WHERE workspace_id = ? ORDER BY event_date'
      )
      .bind(id)
      .all()
  ).results;

  return c.json({ workspace: rowToWs(ws), subjects, connections, findings, timeline });
}
