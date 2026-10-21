import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';
import { executeCronJob } from '../scheduled';
import type { ExecutionContext } from '@cloudflare/workers-types';
import { errMessage } from '../lib/err';

/**
 * Cron execution Durable Object.
 *
 * The parent Worker's `handleScheduled` runs under the free-plan CPU cap
 * (10 ms per cron trigger) — far too small for the briefing build, the
 * discovery/planner pipeline, or the hourly fan-out. Durable Objects have
 * their own per-invocation CPU budget (30 s default) that is independent of
 * the calling Worker, so we hand the heavy job off here.
 *
 * Flow:
 *   1. `handleScheduled` does a single cheap fetch → POST /run with
 *      `{ cron, scheduledTime }` and returns immediately.
 *   2. This DO validates, parks the job in storage, and schedules a durable
 *      alarm (~500 ms later) so the fetch itself stays a fast-accept.
 *   3. The alarm handler runs the REAL job body ([[executeCronJob]]) with its
 *      own 15-min wall / 30s CPU budget, then releases the cron lease.
 *
 * One DO instance per cron string (`idFromName(cron)`) keeps distinct crons
 * isolated and a single (stale) instance from blocking re-scheduling.
 */
interface PendingJob {
  cron: string;
  scheduledTime: number;
}

const JOB_KEY = 'pending';

export class CronJobDO extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== '/run') {
      return Response.json({ error: 'not found' }, { status: 404 });
    }
    let body: PendingJob;
    try {
      body = (await request.json()) as PendingJob;
    } catch {
      return Response.json({ error: 'bad request body' }, { status: 400 });
    }
    if (typeof body.cron !== 'string' || typeof body.scheduledTime !== 'number') {
      return Response.json({ error: 'cron and scheduledTime required' }, { status: 400 });
    }
    // Don't clobber an already-pending job: a duplicate/overlapping dispatch
    // before the alarm fires must not reset the stored scheduledTime or the
    // alarm, otherwise the earlier job's payload is silently dropped.
    const existing = await this.ctx.storage.get<PendingJob>(JOB_KEY);
    if (!existing) {
      await this.ctx.storage.put<PendingJob>(JOB_KEY, body);
      // Defer the actual work to a durable alarm so this fetch returns fast and
      // the heavy CPU lands in its own invocation.
      await this.ctx.storage.setAlarm(Date.now() + 500);
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 202,
      headers: { 'content-type': 'application/json' },
    });
  }

  /** Durable alarm handler — the heavy job runs here with a DO CPU budget. */
  override async alarm(): Promise<void> {
    const job = await this.ctx.storage.get<PendingJob>(JOB_KEY);
    if (!job) return;

    // The job bodies expect an ExecutionContext (waitUntil for cache writes,
    // passThroughOnException for the in-process apiApp.fetch). The DO state
    // object honours waitUntil; shim the rest. Same pattern as
    // api/src/routes/rag-corpus-index.ts:stubCtx.
    const shimCtx: ExecutionContext = {
      waitUntil: (p: Promise<unknown>): void => {
        void this.ctx.waitUntil(p);
      },
      passThroughOnException: () => {},
    } as unknown as ExecutionContext;
    try {
      await executeCronJob(job.cron, job.scheduledTime, this.env, shimCtx);
    } catch (e) {
      // executeCronJob swallows per-component failures; an unexpected throw
      // means the run failed — keep JOB_KEY so the alarm retry actually has a
      // job to re-run. Deleting before execution (the old behavior) made the
      // documented "DO retries the alarm" backstop dead code: on retry,
      // `job` was already gone and the failed run was silently lost.
      console.error(
        JSON.stringify({
          job: 'cron-job',
          cron: job.cron,
          status: 'failed',
          error: errMessage(e),
        })
      );
      throw e;
    }
    // Success — clear the pending job so a spurious extra alarm is a no-op.
    await this.ctx.storage.delete(JOB_KEY);
  }
}
