import { Hono } from 'hono';
import type { Env } from '../env';
import { serviceUnavailable } from '../lib/api-error';

const app = new Hono<{ Bindings: Env }>();

interface EstateAssetRow {
  id: string;
  asset_type: string;
  value: string;
  label: string;
  tags: string;
  criticality: string;
  metadata: string;
  created_at: string;
  updated_at?: string;
}

interface AlertFeedRow {
  id: string;
  alert_type: string;
  title: string;
  description: string;
  confidence: number;
  severity: string;
  source: string;
  source_url?: string;
  topics: string;
  matched_assets: string;
  matched_sector: string;
  tlp: string;
  read: number;
  dismissed: number;
  created_at: string;
}

interface CountResult {
  c: number;
}

// ── Estate Config ──────────────────────────────────────────────────────────

const SECTORS = [
  'financial-services',
  'healthcare',
  'government',
  'technology',
  'defense',
  'retail',
  'manufacturing',
  'telecommunications',
  'energy',
  'education',
  'media',
  'legal',
  'nonprofit',
  'other',
] as const;

const REGIONS = [
  'north-america',
  'south-america',
  'europe',
  'asia-pacific',
  'middle-east',
  'africa',
  'global',
] as const;

const DATA_TYPES = [
  'pii',
  'phi',
  'financial',
  'intellectual-property',
  'credentials',
  'cardholder-data',
  'classified',
  'source-code',
  'customer-records',
  'internal-comms',
] as const;

export const estateRoutes = app
  .get('/config', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const row = await db
      .prepare(
        'SELECT id, sector, sub_sector, region, tech_stack, priorities, data_types, created_at, updated_at FROM estate_config WHERE id = ?'
      )
      .bind('default')
      .first();
    if (!row) {
      return c.json({
        sector: '',
        sub_sector: '',
        region: '',
        tech_stack: [],
        priorities: [],
        data_types: [],
      });
    }
    return c.json({
      sector: row.sector,
      sub_sector: row.sub_sector,
      region: row.region,
      tech_stack: (() => {
        try {
          return JSON.parse(row.tech_stack as string);
        } catch {
          return [];
        }
      })(),
      priorities: (() => {
        try {
          return JSON.parse(row.priorities as string);
        } catch {
          return [];
        }
      })(),
      data_types: (() => {
        try {
          return JSON.parse(row.data_types as string);
        } catch {
          return [];
        }
      })(),
    });
  })
  .put('/config', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const body = await c.req.json();
    const sector = String(body.sector ?? '');
    const subSector = String(body.sub_sector ?? '');
    const region = String(body.region ?? '');
    const techStack = JSON.stringify(body.tech_stack ?? []);
    const priorities = JSON.stringify(body.priorities ?? []);
    const dataTypes = JSON.stringify(body.data_types ?? []);

    await db
      .prepare(
        `
      INSERT INTO estate_config (id, sector, sub_sector, region, tech_stack, priorities, data_types, updated_at)
      VALUES ('default', ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      ON CONFLICT(id) DO UPDATE SET
        sector=excluded.sector, sub_sector=excluded.sub_sector, region=excluded.region,
        tech_stack=excluded.tech_stack, priorities=excluded.priorities,
        data_types=excluded.data_types, updated_at=excluded.updated_at
    `
      )
      .bind(sector, subSector, region, techStack, priorities, dataTypes)
      .run();

    return c.json({ ok: true });
  })
  .get('/sectors', (c) => c.json({ sectors: SECTORS }))
  .get('/regions', (c) => c.json({ regions: REGIONS }))
  .get('/data-types', (c) => c.json({ dataTypes: DATA_TYPES }))

  // ── Assets ─────────────────────────────────────────────────────────────

  .get('/assets', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const type = c.req.query('type');
    const rows = type
      ? await db
          .prepare(
            'SELECT id, asset_type, value, label, tags, criticality, metadata, created_at, updated_at FROM estate_assets WHERE asset_type = ? ORDER BY created_at DESC'
          )
          .bind(type)
          .all()
      : await db
          .prepare(
            'SELECT id, asset_type, value, label, tags, criticality, metadata, created_at, updated_at FROM estate_assets ORDER BY created_at DESC'
          )
          .all();
    const assets = (rows.results ?? []).map((r) => {
      const row = r as unknown as EstateAssetRow;
      return {
        ...r,
        tags: JSON.parse(row.tags ?? '[]'),
        metadata: JSON.parse(row.metadata ?? '{}'),
        created_at: row.created_at,
        updated_at: row.updated_at,
      };
    });
    return c.json({ assets });
  })
  .post('/assets', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const body = await c.req.json();
    const id = crypto.randomUUID();
    const assetType = String(body.asset_type ?? 'other');
    const value = String(body.value ?? '');
    const label = String(body.label ?? value);
    const tags = JSON.stringify(body.tags ?? []);
    const criticality = String(body.criticality ?? 'medium');
    const metadata = JSON.stringify(body.metadata ?? {});

    await db
      .prepare(
        `
      INSERT INTO estate_assets (id, asset_type, value, label, tags, criticality, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(value) DO UPDATE SET
        asset_type=excluded.asset_type, label=excluded.label, tags=excluded.tags,
        criticality=excluded.criticality, metadata=excluded.metadata,
        updated_at=strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    `
      )
      .bind(id, assetType, value, label, tags, criticality, metadata)
      .run();

    return c.json({ id, ok: true });
  })
  .delete('/assets/:id', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    await db.prepare('DELETE FROM estate_assets WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ ok: true });
  })

  // ── Alert Feed ────────────────────────────────────────────────────────

  .get('/alerts', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const limit = Math.min(Number(c.req.query('limit')) || 50, 200);
    const severity = c.req.query('severity');
    const type = c.req.query('type');
    const unread = c.req.query('unread');

    let sql = 'SELECT id, title, source_url, dismissed, created_at FROM alert_feeds WHERE dismissed = 0';
    const params: unknown[] = [];
    if (severity) {
      sql += ' AND severity = ?';
      params.push(severity);
    }
    if (type) {
      sql += ' AND alert_type = ?';
      params.push(type);
    }
    if (unread === 'true') {
      sql += ' AND read = 0';
    }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const rows = await db
      .prepare(sql)
      .bind(...params)
      .all();
    const alerts = (rows.results ?? []).map((r) => {
      const row = r as unknown as AlertFeedRow;
      return {
        ...r,
        topics: JSON.parse(row.topics ?? '[]'),
        matched_assets: JSON.parse(row.matched_assets ?? '[]'),
      };
    });
    return c.json({ alerts, total: alerts.length });
  })
  .post('/alerts', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const body = await c.req.json();
    const id = crypto.randomUUID();
    await db
      .prepare(
        `
      INSERT INTO alert_feeds (id, alert_type, title, description, confidence, severity, source, source_url, topics, matched_assets, matched_sector, tlp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
      )
      .bind(
        id,
        body.alert_type ?? 'intel',
        body.title ?? '',
        body.description ?? '',
        body.confidence ?? 75,
        body.severity ?? 'medium',
        body.source ?? '',
        body.source_url ?? '',
        JSON.stringify(body.topics ?? []),
        JSON.stringify(body.matched_assets ?? []),
        body.matched_sector ?? 0,
        body.tlp ?? 'CLEAR'
      )
      .run();
    return c.json({ id, ok: true });
  })
  .post('/alerts/:id/read', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    await db.prepare('UPDATE alert_feeds SET read = 1 WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ ok: true });
  })
  .post('/alerts/:id/dismiss', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    await db.prepare('UPDATE alert_feeds SET dismissed = 1 WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ ok: true });
  })
  .get('/alerts/stats', async (c) => {
    const db = c.env.BRIEFINGS_DB;
    if (!db) return serviceUnavailable(c, 'DB unavailable');
    const total = await db.prepare('SELECT COUNT(*) as c FROM alert_feeds WHERE dismissed = 0').first();
    const unread = await db.prepare('SELECT COUNT(*) as c FROM alert_feeds WHERE dismissed = 0 AND read = 0').first();
    const bySeverity = await db
      .prepare(
        "SELECT severity, COUNT(*) as c FROM alert_feeds WHERE dismissed = 0 GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
      )
      .all();
    const totalRow = total as unknown as CountResult | null;
    const unreadRow = unread as unknown as CountResult | null;
    return c.json({
      total: totalRow?.c ?? 0,
      unread: unreadRow?.c ?? 0,
      bySeverity: (bySeverity.results ?? []).map((r) => {
        const row = r as unknown as CountResult & { severity: string };
        return { severity: row.severity, count: row.c };
      }),
    });
  });

export type EstateRoutes = typeof estateRoutes;
