/**
 * Feed alert delivery.
 *
 * The scheduler in `feed-scheduler.ts` could fetch a feed, parse it and record
 * an item count, and then had nowhere to send the result. This closes that.
 *
 * Two design points worth stating, because both were learned the hard way by
 * systems that lacked them:
 *
 *  1. **Suppression is not optional.** A feed that yields thousands of
 *     indicators per run and a channel that alerts on every run produce a
 *     channel nobody reads, and an unread channel suppresses the one alert
 *     that mattered. `min_new_items` and `cooldown_hours` exist so a channel
 *     can be noisy without being ignored.
 *
 *  2. **A failed delivery is not a failed fetch.** They are logged separately
 *     (feed_delivery_log vs feed_run_history) precisely so a dead Slack webhook
 *     does not read as a broken feed.
 *
 * Outbound URLs are attacker-influenced in the sense that an operator with
 * admin rights sets them, so every send goes through `pinnedFetchFollow`, the
 * same SSRF guard the feed fetcher uses. A delivery webhook is as capable of
 * reaching internal infrastructure as a feed URL is, and it runs on a schedule
 * rather than on demand.
 */
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { pinnedFetchFollow } from './ssrf-guard';
import { safeNull } from './safe-catch';

export type ChannelType = 'webhook' | 'slack' | 'discord' | 'email';

export interface AlertChannel {
  id: string;
  job_id: string;
  name: string;
  type: ChannelType;
  target: string;
  enabled: boolean;
  match_tags: string[];
  min_new_items: number;
  cooldown_hours: number;
  last_delivered_at: string | null;
  last_status: 'ok' | 'error' | 'skipped' | null;
  last_error: string | null;
  created_at: string;
}

export interface DeliveryOutcome {
  channelId: string;
  status: 'ok' | 'error' | 'skipped';
  reason?: string;
  itemCount: number;
}

const CHANNELS_TABLE = 'feed_alert_channels';
const LOG_TABLE = 'feed_delivery_log';
const DELIVERY_TIMEOUT_MS = 10_000;

/**
 * Items are truncated before formatting.
 *
 * A 4,000-indicator payload into a Slack message either fails the 3000-block
 * limit or gets silently cut off by the receiver. Sending a counted sample
 * with an explicit "and N more" keeps the alert actionable and the call
 * successful.
 */
const MAX_ITEMS_IN_MESSAGE = 20;

/**
 * Should this channel fire for this run?
 *
 * Exported separately from the send so the decision is testable without a
 * network call, and so the reason for a skip is reportable rather than implicit.
 */
export function shouldDeliver(
  channel: Pick<AlertChannel, 'match_tags' | 'min_new_items' | 'cooldown_hours' | 'last_delivered_at' | 'enabled'>,
  newItems: string[],
  itemTags: string[] = []
): { deliver: boolean; reason?: string } {
  if (!channel.enabled) return { deliver: false, reason: 'channel disabled' };

  if (newItems.length < channel.min_new_items) {
    return { deliver: false, reason: `${newItems.length} new items below threshold ${channel.min_new_items}` };
  }

  if (channel.last_delivered_at) {
    const last = new Date(channel.last_delivered_at).getTime();
    const elapsedHours = (Date.now() - last) / 3_600_000;
    if (Number.isFinite(last) && elapsedHours < channel.cooldown_hours) {
      return {
        deliver: false,
        reason: `in cooldown, ${elapsedHours.toFixed(1)}h of ${channel.cooldown_hours}h elapsed`,
      };
    }
  }

  // Tag filtering is an AND across the channel's tags: a channel tagged
  // `ransomware` wants ransomware, and a channel tagged both `ransomware` and
  // `apt` wants items that are both.
  const required = channel.match_tags ?? [];
  if (required.length > 0) {
    const have = new Set([...itemTags, ...newItems.flatMap((i) => tagOf(i))]);
    const missing = required.filter((t) => !have.has(t));
    if (missing.length > 0) {
      return { deliver: false, reason: `no items matched tags: ${missing.join(', ')}` };
    }
  }

  return { deliver: true };
}

/**
 * Leading `#tag` prefix, which is how feed items carry their classification.
 * The tag is followed by the indicator itself (`#ransomware 1.2.3.4`), so this
 * anchors at the start and stops at the first whitespace rather than requiring
 * the whole item to be the tag.
 */
function tagOf(item: string): string[] {
  const m = /^#([a-z0-9_-]{2,32})(?=\s|$)/i.exec(item.trim());
  return m ? [m[1]!.toLowerCase()] : [];
}

/**
 * Format an alert for a channel type.
 *
 * Each receiver has its own payload schema and rejecting a malformed webhook
 * body looks identical to a network failure from the caller's side, so the
 * shapes are built here rather than left to each caller to remember.
 */
export function formatAlert(
  channel: AlertChannel,
  jobName: string,
  newItems: string[]
): {
  headers: Record<string, string>;
  body: string;
} {
  const shown = newItems.slice(0, MAX_ITEMS_IN_MESSAGE);
  const overflow = newItems.length - shown.length;
  const lines = [
    `*${jobName}* — ${newItems.length} new indicator${newItems.length === 1 ? '' : 's'}`,
    ...shown.map((i) => `• \`${i}\``),
  ];
  if (overflow > 0) lines.push(`_…and ${overflow} more._`);

  if (channel.type === 'slack' || channel.type === 'discord') {
    // Both accept a plain `text` field; Discord ignores unknown fields, Slack
    // renders the same string as mrkdwn, so one shape serves both.
    return {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: lines.join('\n') }),
    };
  }

  if (channel.type === 'email') {
    // No mail provider is wired yet, so this emits the RFC-822 body rather than
    // pretending to send. Wiring an actual transport is a one-line change at
    // the call site; faking a send here would be worse than not offering it.
    return {
      headers: { 'content-type': 'text/plain' },
      body: [
        `To: ${channel.target}`,
        `Subject: [feed] ${jobName}: ${newItems.length} new indicators`,
        '',
        ...lines,
      ].join('\n'),
    };
  }

  return {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      source: 'pranithjain.feed-alert',
      job: jobName,
      count: newItems.length,
      items: shown,
      truncated: overflow > 0 ? overflow : undefined,
    }),
  };
}

/**
 * Deliver one channel's alert.
 *
 * `pinnedFetchFollow` rather than bare `fetch`: this URL is configured by an
 * operator and executed on a schedule, which is exactly the profile SSRF guards
 * exist for. A webhook that can reach `169.254.169.254` on every cron tick is a
 * credential-exfiltration loop.
 */
export async function deliverChannel(
  env: Env,
  channel: AlertChannel,
  jobName: string,
  newItems: string[],
  itemTags: string[] = []
): Promise<DeliveryOutcome> {
  const gate = shouldDeliver(channel, newItems, itemTags);
  if (!gate.deliver) {
    await logDelivery(env, channel, 'skipped', 0, gate.reason ?? 'suppressed');
    return { channelId: channel.id, status: 'skipped', reason: gate.reason, itemCount: newItems.length };
  }

  const { headers, body } = formatAlert(channel, jobName, newItems);

  try {
    const res = await pinnedFetchFollow(channel.target, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`channel returned HTTP ${res.status}`);

    await recordDelivery(env, channel, 'ok', newItems.length, null);
    return { channelId: channel.id, status: 'ok', itemCount: newItems.length };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logError('feed alert delivery failed', err);
    await recordDelivery(env, channel, 'error', newItems.length, message);
    return { channelId: channel.id, status: 'error', reason: message, itemCount: newItems.length };
  }
}

async function logDelivery(
  env: Env,
  channel: AlertChannel,
  status: 'ok' | 'error' | 'skipped',
  itemCount: number,
  error: string | null
): Promise<void> {
  // A logging failure must never propagate: losing the audit row is bad, but
  // turning it into a thrown error would break the fetch path that succeeded.
  const db = env.BRIEFINGS_DB;
  if (!db) return;
  try {
    await safeNull(
      db
        .prepare(
          `INSERT INTO ${LOG_TABLE} (channel_id, job_id, attempted_at, status, item_count, error)
         VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(channel.id, channel.job_id, new Date().toISOString(), status, itemCount, error)
        .run()
    );
  } catch (err) {
    logError('feed delivery log failed', err);
  }
}

async function recordDelivery(
  env: Env,
  channel: AlertChannel,
  status: 'ok' | 'error' | 'skipped',
  itemCount: number,
  error: string | null
): Promise<void> {
  const db = env.BRIEFINGS_DB;
  if (!db) return;
  try {
    await safeNull(
      db
        .prepare(
          `UPDATE ${CHANNELS_TABLE}
            SET last_delivered_at = ?, last_status = ?, last_error = ?
          WHERE id = ?`
        )
        .bind(new Date().toISOString(), status, error, channel.id)
        .run()
    );
  } catch (err) {
    logError('feed channel state update failed', err);
  }
}

/**
 * Coerce a D1 row into an `AlertChannel`.
 *
 * D1 returns `enabled` as the integer 0/1 and `match_tags` as the JSON string
 * that was stored, while the rest of the codebase works with a boolean and a
 * string array. Normalising in one place is what stops that mismatch from
 * producing a `false`-that-is-actually-`0` bug at some future call site, which
 * is the kind of thing that silently disables a channel.
 *
 * Exported because the channel CRUD routes read rows directly and must apply
 * the same coercion, not their own idea of it.
 */
export function normaliseChannel(row: Record<string, unknown>): AlertChannel {
  let tags: string[] = [];
  const raw = row.match_tags;
  if (Array.isArray(raw)) tags = raw.filter((t): t is string => typeof t === 'string');
  else if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) tags = parsed.filter((t): t is string => typeof t === 'string');
    } catch {
      tags = [];
    }
  }

  const enabledRaw = row.enabled;
  return {
    id: String(row.id ?? ''),
    job_id: String(row.job_id ?? ''),
    name: String(row.name ?? ''),
    type: String(row.type ?? 'webhook') as ChannelType,
    target: String(row.target ?? ''),
    enabled: enabledRaw === 1 || enabledRaw === true || enabledRaw === '1',
    match_tags: tags,
    min_new_items: typeof row.min_new_items === 'number' ? row.min_new_items : 1,
    cooldown_hours: typeof row.cooldown_hours === 'number' ? row.cooldown_hours : 6,
    last_delivered_at: typeof row.last_delivered_at === 'string' ? row.last_delivered_at : null,
    last_status: (row.last_status as AlertChannel['last_status']) ?? null,
    last_error: typeof row.last_error === 'string' ? row.last_error : null,
    created_at: String(row.created_at ?? ''),
  };
}

/** Channels attached to a job, enabled or not. */
export async function listChannels(env: Env, jobId: string): Promise<AlertChannel[]> {
  const db = env.BRIEFINGS_DB;
  if (!db) return [];
  const { results } = await db
    .prepare(`SELECT * FROM ${CHANNELS_TABLE} WHERE job_id = ? ORDER BY created_at ASC`)
    .bind(jobId)
    .all<Record<string, unknown>>();
  return (results ?? []).map(normaliseChannel);
}

/**
 * Fan a run out to every enabled channel on a job.
 *
 * Deliberately sequential. Channels are few and sends are infrequent, and
 * parallelising would make a rate-limited receiver produce a burst of
 * simultaneous retries, which is how a working channel gets banned.
 */
export async function deliverToJobChannels(
  env: Env,
  jobId: string,
  jobName: string,
  newItems: string[],
  itemTags: string[] = []
): Promise<DeliveryOutcome[]> {
  const channels = (await listChannels(env, jobId)).filter((c) => c.enabled);
  const out: DeliveryOutcome[] = [];
  for (const channel of channels) {
    out.push(await deliverChannel(env, channel, jobName, newItems, itemTags));
  }
  return out;
}
