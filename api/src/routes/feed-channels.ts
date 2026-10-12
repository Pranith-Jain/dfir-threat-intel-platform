/**
 * Feed alert channel CRUD.
 *
 * `feed-scheduler.ts` owns fetching; this owns "tell someone when you find
 * something". Split rather than merged because the channel surface has a
 * different lifecycle: channels are created and deleted often, while jobs are
 * long-lived config, and a UI editing channels should not have to reason about
 * job state.
 *
 * All routes are admin-gated by the prefix registration in index.ts, which
 * matches the job routes they hang off.
 *
 *   GET    /api/v1/feed-scheduler/:jobId/channels
 *   POST   /api/v1/feed-scheduler/:jobId/channels
 *   PATCH  /api/v1/feed-channels/:channelId
 *   DELETE /api/v1/feed-channels/:channelId
 *   POST   /api/v1/feed-channels/:channelId/test
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, serviceUnavailable } from '../lib/api-error';
import {
  deliverChannel,
  listChannels,
  normaliseChannel,
  type AlertChannel,
  type ChannelType,
} from '../lib/feed-delivery';

const CHANNELS_TABLE = 'feed_alert_channels';
const LOG_TABLE = 'feed_delivery_log';

const CHANNEL_TYPES: ChannelType[] = ['webhook', 'slack', 'discord', 'email'];

/**
 * Validate and normalise a channel payload.
 *
 * `target` is deliberately NOT validated for reachability here. A Slack webhook
 * that 404s must be creatable so the operator can save the rest of their
 * config, discover the failure from the test endpoint, and fix it — rejecting
 * the create would strand them with a half-configured channel and no signal.
 */
/** The subset of a channel a caller supplies; the rest is server-owned. */
type ChannelInput = Omit<
  AlertChannel,
  'id' | 'job_id' | 'created_at' | 'last_delivered_at' | 'last_status' | 'last_error'
>;

function parseChannelBody(body: unknown): { ok: true; value: ChannelInput } | { ok: false; error: string } {
  if (!body || typeof body !== 'object') return { ok: false, error: 'body must be a JSON object' };
  const b = body as Record<string, unknown>;

  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name) return { ok: false, error: 'name required' };

  const type = typeof b.type === 'string' ? (b.type.toLowerCase() as ChannelType) : null;
  if (!type || !CHANNEL_TYPES.includes(type)) {
    return { ok: false, error: `type must be one of ${CHANNEL_TYPES.join(', ')}` };
  }

  const target = typeof b.target === 'string' ? b.target.trim() : '';
  if (!target) return { ok: false, error: 'target required' };

  // URL-shaped targets get a cheap syntactic check. SSRF is handled at send
  // time by pinnedFetchFollow, which is the only place that can resolve DNS and
  // see a redirect chain.
  if (type !== 'email') {
    try {
      const u = new URL(target);
      if (u.protocol !== 'https:') {
        return { ok: false, error: 'target must be https' };
      }
    } catch {
      return { ok: false, error: 'target must be a valid URL' };
    }
  } else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(target.split(',')[0] ?? '')) {
    return { ok: false, error: 'email target must be an address or comma-separated list' };
  }

  const num = (v: unknown, fallback: number, min: number, max: number) => {
    const n = typeof v === 'number' ? v : Number(v);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(Math.max(Math.round(n), min), max);
  };

  const matchTags = Array.isArray(b.match_tags)
    ? b.match_tags
        .filter((t): t is string => typeof t === 'string')
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean)
    : [];

  return {
    ok: true,
    value: {
      name,
      type,
      target,
      // Alert channels default OFF. A new channel that starts delivering
      // immediately pages everyone the moment it is created, which is the
      // fastest way to get a feature switched off permanently.
      enabled: b.enabled === true,
      match_tags: matchTags,
      min_new_items: num(b.min_new_items, 1, 1, 100_000),
      cooldown_hours: num(b.cooldown_hours, 6, 0, 720),
    },
  };
}

export async function listJobChannelsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!c.env.BRIEFINGS_DB) return serviceUnavailable(c, 'database not available');
  const jobId = c.req.param('jobId') ?? '';
  const channels = await listChannels(c.env, jobId);
  return c.json({ job_id: jobId, count: channels.length, channels });
}

export async function createJobChannelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!c.env.BRIEFINGS_DB) return serviceUnavailable(c, 'database not available');
  const jobId = c.req.param('jobId') ?? '';
  if (!jobId) return badRequest(c, 'jobId required');

  const parsed = parseChannelBody(await c.req.json().catch(() => null));
  if (!parsed.ok) return badRequest(c, parsed.error);

  const id = crypto.randomUUID();
  await c.env.BRIEFINGS_DB.prepare(
    `INSERT INTO ${CHANNELS_TABLE}
       (id, job_id, name, type, target, enabled, match_tags, min_new_items, cooldown_hours, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      jobId,
      parsed.value.name,
      parsed.value.type,
      parsed.value.target,
      parsed.value.enabled ? 1 : 0,
      JSON.stringify(parsed.value.match_tags),
      parsed.value.min_new_items,
      parsed.value.cooldown_hours,
      new Date().toISOString()
    )
    .run();

  const [channel] = await listChannels(c.env, jobId).then((c2) => c2.filter((x) => x.id === id));
  return c.json({ channel }, 201);
}

export async function updateChannelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!c.env.BRIEFINGS_DB) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('channelId') ?? '';

  const row = await c.env.BRIEFINGS_DB.prepare(`SELECT * FROM ${CHANNELS_TABLE} WHERE id = ?`)
    .bind(id)
    .first<Record<string, unknown>>();
  if (!row) return notFound(c, 'channel not found');
  const existing = normaliseChannel(row);

  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body) return badRequest(c, 'body must be a JSON object');

  // PATCH semantics: merge onto the existing row so a caller sending only
  // `{enabled: false}` does not blank the target.
  const merged = parseChannelBody({
    name: body.name ?? existing.name,
    type: body.type ?? existing.type,
    target: body.target ?? existing.target,
    enabled: body.enabled ?? existing.enabled,
    match_tags: body.match_tags ?? existing.match_tags,
    min_new_items: body.min_new_items ?? existing.min_new_items,
    cooldown_hours: body.cooldown_hours ?? existing.cooldown_hours,
  });
  if (!merged.ok) return badRequest(c, merged.error);

  await c.env.BRIEFINGS_DB.prepare(
    `UPDATE ${CHANNELS_TABLE}
        SET name = ?, type = ?, target = ?, enabled = ?, match_tags = ?,
            min_new_items = ?, cooldown_hours = ?
      WHERE id = ?`
  )
    .bind(
      merged.value.name,
      merged.value.type,
      merged.value.target,
      merged.value.enabled ? 1 : 0,
      JSON.stringify(merged.value.match_tags),
      merged.value.min_new_items,
      merged.value.cooldown_hours,
      id
    )
    .run();

  const updated = await c.env.BRIEFINGS_DB.prepare(`SELECT * FROM ${CHANNELS_TABLE} WHERE id = ?`)
    .bind(id)
    .first<Record<string, unknown>>();
  return c.json({ channel: updated ? normaliseChannel(updated) : null });
}

export async function deleteChannelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!c.env.BRIEFINGS_DB) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('channelId') ?? '';
  const existing = await c.env.BRIEFINGS_DB.prepare(`SELECT id FROM ${CHANNELS_TABLE} WHERE id = ?`).bind(id).first();
  if (!existing) return notFound(c, 'channel not found');

  await c.env.BRIEFINGS_DB.prepare(`DELETE FROM ${CHANNELS_TABLE} WHERE id = ?`).bind(id).run();
  return c.json({ deleted: id });
}

/**
 * Send a test alert.
 *
 * Bypasses `min_new_items` and the cooldown, because both exist to stop a
 * production feed from paging someone and neither should stop an operator
 * finding out that their webhook URL is wrong. Goes through the same
 * `deliverChannel` path, so what the test proves is what production will do.
 */
export async function testChannelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!c.env.BRIEFINGS_DB) return serviceUnavailable(c, 'database not available');
  const id = c.req.param('channelId') ?? '';

  const row = await c.env.BRIEFINGS_DB.prepare(`SELECT * FROM ${CHANNELS_TABLE} WHERE id = ?`)
    .bind(id)
    .first<Record<string, unknown>>();
  if (!row) return notFound(c, 'channel not found');
  const channel = normaliseChannel(row);

  const outcome = await deliverChannel(c.env, channel, channel.name, [
    '198.51.100.7',
    '2001:db8::1',
    'test-indicator-from-utcnow.example',
  ]);

  if (outcome.status === 'skipped') {
    // Re-run with suppression lifted rather than reporting a skip as a pass.
    const forced: AlertChannel = { ...channel, enabled: true, min_new_items: 0, cooldown_hours: 0 };
    const forcedOutcome = await deliverChannel(c.env, forced, channel.name, ['198.51.100.7', '2001:db8::1']);
    return c.json(
      {
        channel: id,
        delivered: forcedOutcome.status === 'ok',
        status: forcedOutcome.status,
        error: forcedOutcome.reason ?? null,
        note: 'suppression thresholds ignored for this test',
      },
      forcedOutcome.status === 'ok' ? 200 : 502
    );
  }

  return c.json(
    { channel: id, delivered: outcome.status === 'ok', status: outcome.status, error: outcome.reason ?? null },
    outcome.status === 'ok' ? 200 : 502
  );
}

/**
 * Recent delivery attempts across all channels.
 *
 * Separate from run history on purpose: a run can be `ok` while its delivery is
 * `error`, and an operator debugging "why didn't I get the alert" needs to see
 * that distinction rather than infer it.
 */
export async function deliveryLogHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  if (!c.env.BRIEFINGS_DB) return serviceUnavailable(c, 'database not available');
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 50), 1), 200);
  try {
    const { results } = await c.env.BRIEFINGS_DB.prepare(
      `SELECT l.*, ch.name AS channel_name, ch.type AS channel_type
         FROM ${LOG_TABLE} l
         LEFT JOIN ${CHANNELS_TABLE} ch ON ch.id = l.channel_id
        ORDER BY l.attempted_at DESC
        LIMIT ?`
    )
      .bind(limit)
      .all<Record<string, unknown>>();
    return c.json({ total: results?.length ?? 0, entries: results ?? [] });
  } catch (err) {
    logError('delivery log read failed', err);
    return serviceUnavailable(c, 'delivery log unavailable');
  }
}
