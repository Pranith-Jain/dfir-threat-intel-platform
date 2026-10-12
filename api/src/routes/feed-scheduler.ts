import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { safeJsonBody } from '../lib/safe-body';
import { badRequest, notFound, serviceUnavailable } from '../lib/api-error';
import { ensureGraphTables, upsertNode, type NodeType } from './threat-graph';
import { recordIocObservation } from './ioc-lifecycle';
import { pinnedFetchFollow } from '../lib/ssrf-guard';
import { safeNull } from '../lib/safe-catch';
import { deliverToJobChannels, type DeliveryOutcome } from '../lib/feed-delivery';
import type { D1Database } from '@cloudflare/workers-types';

const FEED_JOBS_TABLE = 'feed_jobs';
const FEED_HISTORY_TABLE = 'feed_run_history';

interface FeedJob {
  id: string;
  name: string;
  source_url: string;
  interval_minutes: number;
  parser: 'plaintext-ips' | 'plaintext-domains' | 'plaintext-urls' | 'plaintext-hashes' | 'csv' | 'json';
  enabled: boolean;
  created_at: string;
  last_run_at: string | null;
  last_status: 'pending' | 'running' | 'ok' | 'error' | null;
  last_item_count: number;
  last_error: string | null;
  tags: string[];
}

interface FeedRunHistory {
  job_id: string;
  started_at: string;
  finished_at: string;
  status: 'ok' | 'error';
  item_count: number;
  error: string | null;
}

const JOBS_CACHE_KEY = 'https://feed-jobs-cache.internal/v1';
// Backstop TTL only — every saveJobs() write-throughs this Cache-API entry, so
// it stays coherent regardless of TTL. 300s (was 30s) cuts KV reads from an
// admin dashboard that polls the jobs list.
const JOBS_CACHE_TTL = 300;
const MAX_HISTORY = 20;

function cacheApi(): Cache | null {
  try {
    return (caches as unknown as { default: Cache }).default;
  } catch (_catchErr) {
    logError('cacheApi failed', _catchErr);
    return null;
  }
}

async function readJobsCached(): Promise<FeedJob[] | null> {
  const cache = cacheApi();
  if (!cache) return null;
  try {
    const r = await cache.match(JOBS_CACHE_KEY);
    return r ? ((await r.json()) as FeedJob[]) : null;
  } catch (_catchErr) {
    logError('readJobsCached failed', _catchErr);
    return null;
  }
}

async function writeJobsCache(jobs: FeedJob[]): Promise<void> {
  const cache = cacheApi();
  if (!cache) return;
  try {
    await cache.put(
      JOBS_CACHE_KEY,
      new Response(JSON.stringify(jobs), {
        headers: { 'content-type': 'application/json', 'cache-control': `max-age=${JOBS_CACHE_TTL}` },
      })
    );
  } catch (_catchErr) {
    logError('writeJobsCache failed', _catchErr);
    /* best-effort */
  }
}

async function listJobs(db: D1Database): Promise<FeedJob[]> {
  const cached = await readJobsCached();
  if (cached) return cached;
  const { results } = await db
    .prepare(
      `SELECT id, name, source_url, interval_minutes, parser, enabled, created_at, last_run_at, last_status, last_item_count, last_error, tags FROM ${FEED_JOBS_TABLE} ORDER BY created_at DESC`
    )
    .all<FeedJob>();
  const jobs = (results ?? []).map((r) => ({ ...r, tags: JSON.parse((r.tags as unknown as string) ?? '[]') }));
  await writeJobsCache(jobs);
  return jobs;
}

async function saveJobs(db: D1Database, jobs: FeedJob[]): Promise<void> {
  for (const job of jobs) {
    await db
      .prepare(
        `INSERT OR REPLACE INTO ${FEED_JOBS_TABLE}
         (id, name, source_url, interval_minutes, parser, enabled, created_at, last_run_at, last_status, last_item_count, last_error, tags)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        job.id,
        job.name,
        job.source_url,
        job.interval_minutes,
        job.parser,
        job.enabled ? 1 : 0,
        job.created_at,
        job.last_run_at,
        job.last_status,
        job.last_item_count,
        job.last_error,
        JSON.stringify(job.tags)
      )
      .run();
  }
  await writeJobsCache(jobs);
}

export type { FeedJob, FeedRunHistory };
export { listJobs, saveJobs };

/**
 * Read run history for a specific job from D1.
 */
async function readJobHistory(db: D1Database, jobId: string): Promise<FeedRunHistory[]> {
  const { results } = await db
    .prepare(
      `SELECT id, job_id, started_at, finished_at, status, item_count, error FROM ${FEED_HISTORY_TABLE} WHERE job_id = ? ORDER BY started_at DESC LIMIT ?`
    )
    .bind(jobId, MAX_HISTORY)
    .all<FeedRunHistory>();
  return results ?? [];
}

/**
 * Append a run history entry to D1.
 */
async function appendJobHistory(db: D1Database, history: FeedRunHistory): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ${FEED_HISTORY_TABLE} (job_id, started_at, finished_at, status, item_count, error)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(history.job_id, history.started_at, history.finished_at, history.status, history.item_count, history.error)
    .run();
  // Prune old entries beyond MAX_HISTORY for this job
  await db
    .prepare(
      `DELETE FROM ${FEED_HISTORY_TABLE} WHERE job_id = ? AND id NOT IN (
        SELECT id FROM ${FEED_HISTORY_TABLE} WHERE job_id = ? ORDER BY started_at DESC LIMIT ?
      )`
    )
    .bind(history.job_id, history.job_id, MAX_HISTORY)
    .run();
}

/**
 * Read all job histories from D1 (for the all-history endpoint).
 */
async function readAllHistories(db: D1Database): Promise<Record<string, FeedRunHistory[]>> {
  const { results } = await db
    .prepare(
      `SELECT h.* FROM ${FEED_HISTORY_TABLE} h
       INNER JOIN (
         SELECT job_id, MAX(started_at) as max_started
         FROM ${FEED_HISTORY_TABLE}
         GROUP BY job_id
       ) latest ON h.job_id = latest.job_id
       ORDER BY h.started_at DESC`
    )
    .all<FeedRunHistory>();
  const grouped: Record<string, FeedRunHistory[]> = {};
  for (const row of results ?? []) {
    const arr = grouped[row.job_id] ?? [];
    if (arr.length < MAX_HISTORY) arr.push(row);
    grouped[row.job_id] = arr;
  }
  return grouped;
}

/**
 * Delete a job's history from D1.
 */
async function deleteJobHistory(db: D1Database, jobId: string): Promise<void> {
  await db.prepare(`DELETE FROM ${FEED_HISTORY_TABLE} WHERE job_id = ?`).bind(jobId).run();
}

function now(): string {
  return new Date().toISOString();
}

const VALID_PARSERS: FeedJob['parser'][] = [
  'plaintext-ips',
  'plaintext-domains',
  'plaintext-urls',
  'plaintext-hashes',
  'csv',
  'json',
];

const PRESETS: { id: string; name: string; source_url: string; parser: FeedJob['parser']; tags: string[] }[] = [
  {
    id: 'cins-army',
    name: 'CINS Army Bad IPs',
    source_url: 'https://cinsscore.com/list/ci-badguys.txt',
    parser: 'plaintext-ips',
    tags: ['blocklist', 'ip'],
  },
  {
    id: 'blocklist-de',
    name: 'Blocklist.de All',
    source_url: 'https://lists.blocklist.de/lists/all.txt',
    parser: 'plaintext-ips',
    tags: ['blocklist', 'ip', 'attacker'],
  },
  {
    id: 'cert-pl',
    name: 'CERT Polska Phishing Domains',
    source_url: 'https://hole.cert.pl/domains/v2/domains.txt',
    parser: 'plaintext-domains',
    tags: ['phishing', 'domain', 'cert-pl'],
  },
  {
    id: 'tor-exit',
    name: 'Tor Exit Nodes',
    source_url: 'https://check.torproject.org/torbulkexitlist',
    parser: 'plaintext-ips',
    tags: ['tor', 'anonymizer', 'ip'],
  },
  {
    id: 'x4bnet-vpn',
    name: 'X4BNet VPN Endpoints',
    source_url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
    parser: 'plaintext-ips',
    tags: ['vpn', 'proxy', 'ip'],
  },
  {
    id: 'binarydefense',
    name: 'BinaryDefense Ban List',
    source_url: 'https://www.binarydefense.com/banlist.txt',
    parser: 'plaintext-ips',
    tags: ['blocklist', 'ip'],
  },
  {
    id: 'spamhaus-drop',
    name: 'Spamhaus DROP List',
    source_url: 'https://www.spamhaus.org/drop/drop.txt',
    parser: 'plaintext-ips',
    tags: ['blocklist', 'ip', 'spamhaus'],
  },
  {
    id: 'phishing-army',
    name: 'Phishing Army Blocklist',
    source_url: 'https://phishing.army/download/phishing_army_blocklist.txt',
    parser: 'plaintext-domains',
    tags: ['phishing', 'domain'],
  },
];

export async function listFeedJobsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');
  const jobs = await listJobs(db);
  return c.json({ jobs, presets: PRESETS }, 200, { 'Cache-Control': 'no-store' });
}

export async function createFeedJobHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const parsed = await safeJsonBody<{
    name: string;
    source_url: string;
    parser: FeedJob['parser'];
    interval_minutes?: number;
    tags?: string[];
  }>(c, { maxBytes: 4 * 1024 });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;

  if (!body.name?.trim() || !body.source_url?.trim() || !body.parser) {
    return badRequest(c, 'name, source_url, and parser are required');
  }

  if (!VALID_PARSERS.includes(body.parser)) {
    return badRequest(c, `Invalid parser. Must be one of: ${VALID_PARSERS.join(', ')}`);
  }

  try {
    new URL(body.source_url);
  } catch (_catchErr) {
    logError('createFeedJobHandler failed', _catchErr);
    return badRequest(c, 'Invalid source_url');
  }

  const now_ = now();
  const job: FeedJob = {
    id: crypto.randomUUID(),
    name: body.name.trim(),
    source_url: body.source_url.trim(),
    parser: body.parser,
    interval_minutes: body.interval_minutes ?? 60,
    enabled: true,
    created_at: now_,
    last_run_at: null,
    last_status: null,
    last_item_count: 0,
    last_error: null,
    tags: body.tags ?? [],
  };

  const jobs = await listJobs(db);
  jobs.push(job);
  await saveJobs(db, jobs);
  return c.json({ job }, 201);
}

export async function updateFeedJobHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const id = c.req.param('id');
  if (!id) return badRequest(c, 'id required');

  const parsed = await safeJsonBody<Partial<FeedJob>>(c, { maxBytes: 4 * 1024 });
  if ('error' in parsed) return parsed.error;
  const body = parsed.value;

  const jobs = await listJobs(db);
  const idx = jobs.findIndex((j) => j.id === id);
  if (idx < 0) return notFound(c, 'job not found');

  const job = { ...jobs[idx]! } as FeedJob;
  if (body.parser !== undefined && !VALID_PARSERS.includes(body.parser)) {
    return badRequest(c, `Invalid parser. Must be one of: ${VALID_PARSERS.join(', ')}`);
  }
  if (body.name !== undefined) job.name = body.name;
  if (body.source_url !== undefined) {
    try {
      new URL(body.source_url);
    } catch (_catchErr) {
      logError('updateFeedJobHandler failed', _catchErr);
      return badRequest(c, 'Invalid source_url');
    }
    job.source_url = body.source_url;
  }
  if (body.interval_minutes !== undefined) job.interval_minutes = body.interval_minutes;
  if (body.enabled !== undefined) job.enabled = body.enabled;
  if (body.tags !== undefined) job.tags = body.tags;

  jobs[idx] = job;
  await saveJobs(db, jobs);
  return c.json({ job });
}

export async function deleteFeedJobHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const id = c.req.param('id');
  if (!id) return badRequest(c, 'id required');

  const jobs = await listJobs(db);
  const idx = jobs.findIndex((j) => j.id === id);
  if (idx < 0) return notFound(c, 'job not found');

  jobs.splice(idx, 1);
  await saveJobs(db, jobs);
  await deleteJobHistory(db, id);

  return c.json({ ok: true });
}

export async function runFeedJobHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const id = c.req.param('id');
  if (!id) return badRequest(c, 'id required');

  const jobs = await listJobs(db);
  const idx = jobs.findIndex((j) => j.id === id);
  if (idx < 0) return notFound(c, 'job not found');

  const job = jobs[idx]!;
  const startedAt = now();
  job.last_status = 'running';
  job.last_run_at = startedAt;
  jobs[idx] = job;
  await saveJobs(db, jobs);

  try {
    // SSRF-guarded: validates + pins the host and re-validates each redirect
    // hop, blocking private/loopback/link-local/cloud-metadata targets even
    // though this is admin-gated (defence-in-depth on the cron egress path).
    const res = await pinnedFetchFollow(job.source_url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`.trim());

    const text = await res.text();
    const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
    const count = lines.length;

    job.last_status = 'ok';
    job.last_item_count = count;
    job.last_error = null;
    jobs[idx] = job;
    await saveJobs(db, jobs);

    const finishedAt = now();
    const history: FeedRunHistory = {
      job_id: id,
      started_at: startedAt,
      finished_at: finishedAt,
      status: 'ok',
      item_count: count,
      error: null,
    };

    await appendJobHistory(db, history);

    // Fan out to any attached alert channels. Wrapped so a dead webhook cannot
    // turn a successful fetch into a failed job — the fetch already succeeded
    // and its history row is already written.
    let delivery: DeliveryOutcome[] = [];
    try {
      delivery = await deliverToJobChannels(c.env, job.id, job.name, lines, job.tags ?? []);
    } catch (err) {
      logError('feed delivery fan-out failed', err);
    }

    return c.json({ job, run: history, delivery });
  } catch (err) {
    logError('handler failed', err);
    const errMsg = err instanceof Error ? err.message : String(err);
    job.last_status = 'error';
    job.last_error = errMsg;
    jobs[idx] = job;
    await saveJobs(db, jobs);

    const finishedAt = now();
    const history: FeedRunHistory = {
      job_id: id,
      started_at: startedAt,
      finished_at: finishedAt,
      status: 'error',
      item_count: 0,
      error: errMsg,
    };

    await appendJobHistory(db, history);

    return c.json({ job, run: history }, 200);
  }
}

export async function getFeedJobHistoryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const id = c.req.param('id');
  if (!id) return badRequest(c, 'id required');

  const history = await readJobHistory(db, id);
  return c.json({ history }, 200, { 'Cache-Control': 'no-store' });
}

export async function getFeedJobsHistoryAllHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not available');

  const allHistory = await readAllHistories(db);
  return c.json({ history: allHistory }, 200, { 'Cache-Control': 'no-store' });
}

/**
 * Called by the hourly cron to auto-execute due feed jobs.
 * Runs at most 1 job per tick to stay within the 50-subrequest limit.
 * Saves fetched IOCs to graph_nodes D1 table.
 */
export async function autoRunFeedJobs(db: D1Database): Promise<{ ran: number; saved: number; skipped: number }> {
  const jobs = await listJobs(db);
  const nowMs = Date.now();
  const due = jobs.filter((j) => {
    if (!j.enabled) return false;
    if (!j.last_run_at) return true;
    return nowMs - new Date(j.last_run_at).getTime() >= j.interval_minutes * 60_000;
  });

  if (due.length === 0) return { ran: 0, saved: 0, skipped: 0 };

  const job = due.sort((a, b) => {
    const aT = a.last_run_at ? new Date(a.last_run_at).getTime() : 0;
    const bT = b.last_run_at ? new Date(b.last_run_at).getTime() : 0;
    return aT - bT;
  })[0]!;

  await ensureGraphTables(db);

  const startedAt = now();
  job.last_status = 'running';
  job.last_run_at = startedAt;
  const jobsClone = [...jobs];
  const idx = jobsClone.findIndex((j) => j.id === job.id);
  if (idx >= 0) jobsClone[idx] = job;
  await saveJobs(db, jobsClone);

  let savedCount = 0;

  let failCount = 0;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    // SSRF-guarded egress (re-validates + re-pins every redirect hop).
    const res = await pinnedFetchFollow(job.source_url, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const text = await res.text();
    const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));

    for (const line of lines) {
      const trimmed = line.trim().toLowerCase();
      let nodeType: NodeType | null = null;

      if (job.parser === 'plaintext-ips') {
        const parts = trimmed.split('.');
        if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && +p <= 255)) {
          nodeType = 'ip';
        }
      } else if (job.parser === 'plaintext-domains') {
        if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/.test(trimmed)) {
          nodeType = 'domain';
        }
      } else if (job.parser === 'plaintext-urls') {
        try {
          new URL(trimmed);
          nodeType = 'url';
        } catch (_catchErr) {
          logError('handler failed', _catchErr);
          /* skip */
        }
      } else if (job.parser === 'plaintext-hashes') {
        if (/^[a-f0-9]{32}$/.test(trimmed) || /^[a-f0-9]{40}$/.test(trimmed) || /^[a-f0-9]{64}$/.test(trimmed)) {
          nodeType = 'hash';
        }
      }

      if (nodeType) {
        try {
          await upsertNode(db, {
            type: nodeType,
            value: trimmed,
            confidence: 50,
            sources: [`feed:${job.name}`],
            properties: { label: trimmed, feed: job.name, feed_id: job.id },
          });
          savedCount++;
          // Track in IOC lifecycle table
          const lt = nodeType === 'ip' ? 'ipv4' : nodeType;
          void safeNull(recordIocObservation(db, trimmed, lt, 50, [`feed:${job.name}`]));
        } catch (err) {
          failCount++;
          logError('feed-scheduler upsert failed', err);
        }
      }
    }

    // A run that saved nothing but failed on items is an error, not ok —
    // previously the per-item swallow left job.last_status='ok' on total
    // data loss, hiding D1 outages from the scheduler dashboard.
    if (failCount > 0 && savedCount === 0) {
      job.last_status = 'error';
      job.last_error = `${failCount} item(s) failed to persist`;
      job.last_item_count = 0;
    } else {
      job.last_status = 'ok';
      job.last_item_count = lines.length;
      job.last_error = failCount > 0 ? `${failCount} item(s) failed to persist` : null;
    }
  } catch (err) {
    logError('handler failed', err);
    job.last_status = 'error';
    job.last_error = err instanceof Error ? err.message : String(err);
    job.last_item_count = 0;
  }

  const finalJobs = await listJobs(db);
  const finalIdx = finalJobs.findIndex((j) => j.id === job.id);
  if (finalIdx >= 0) {
    finalJobs[finalIdx] = job;
    await saveJobs(db, finalJobs);
  }

  const history: FeedRunHistory = {
    job_id: job.id,
    started_at: startedAt,
    finished_at: now(),
    status: job.last_status === 'ok' ? 'ok' : 'error',
    item_count: job.last_item_count ?? 0,
    error: job.last_error,
  };
  await appendJobHistory(db, history);

  return { ran: 1, saved: savedCount, skipped: due.length - 1 };
}
