import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';
import { safeEqual } from '../../api/src/lib/safe-equal';

/**
 * Single-flight lease, backed by a Durable Object.
 *
 * The cron handler previously gated overlap with a KV get-then-put under a
 * 120s TTL — which is non-atomic (two PoPs could each read "free" and then
 * each write) and per-PoP (KV is eventually consistent). A Cloudflare retry or
 * a cross-PoP duplicate fire could therefore both pass the gate and double-run
 * the hourly fan-out / briefing build (double Telegram burst, double ~33-source
 * IOC fan-out).
 *
 * A Durable Object is single-threaded and globally unique per id, so `acquire`
 * is atomic and globally consistent — the race cannot occur. Leases live in
 * durable storage so they survive a DO eviction mid-job.
 *
 * The handler currently uses `acquire` with a generous TTL (it dispatches its
 * work through `ctx.waitUntil`, which outlives the invocation, so a precise
 * finally-release/heartbeat needs the scheduled.ts job-tracking refactor). The
 * `heartbeat` / `release` ops are implemented and ready for that follow-up.
 */
interface Lease {
  token: string;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 10 * 60_000;

// Extends the platform DurableObject base class so `this.ctx` (DurableObjectState)
// and `this.env` (Env) are inherited — no hand-written constructor needed.
// The legacy `class FooDO { constructor(ctx, env) { this.ctx = ctx; ... } }`
// pattern loses type safety on `this.env` and risks drifting from the platform
// base class lifecycle hooks.
export class CronLockDO extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    let body: { op?: string; cron?: string; ttlMs?: number; token?: string };
    try {
      body = (await request.json()) as typeof body;
    } catch (_catchErr) {
      console.error('handler failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
      return Response.json({ error: 'bad request body' }, { status: 400 });
    }
    const { op, cron, ttlMs, token } = body;
    if (!op || !cron) return Response.json({ error: 'op and cron required' }, { status: 400 });

    const key = `lease:${cron}`;

    if (op === 'acquire') {
      const now = Date.now();
      const cur = await this.ctx.storage.get<Lease>(key);
      // Single-threaded DO: this get-then-put cannot interleave with another
      // request, so it is atomic where the old KV get-then-put was not.
      if (cur && cur.expiresAt > now) {
        return Response.json({ acquired: false, heldUntil: cur.expiresAt });
      }
      const newToken = crypto.randomUUID();
      await this.ctx.storage.put<Lease>(key, { token: newToken, expiresAt: now + (ttlMs ?? DEFAULT_TTL_MS) });
      return Response.json({ acquired: true, token: newToken });
    }

    if (op === 'heartbeat') {
      const cur = await this.ctx.storage.get<Lease>(key);
      // The lease token is a bearer capability — knowing it lets you extend or
      // release someone else's lease, so compare it constant-time rather than
      // letting `===` leak a prefix length through response timing.
      if (cur && token !== undefined && safeEqual(cur.token, token)) {
        await this.ctx.storage.put<Lease>(key, { token: cur.token, expiresAt: Date.now() + (ttlMs ?? DEFAULT_TTL_MS) });
        return Response.json({ ok: true });
      }
      return Response.json({ ok: false }); // lease lost / token mismatch
    }

    if (op === 'release') {
      const cur = await this.ctx.storage.get<Lease>(key);
      // Token-matched so a stale fire can never release a live lease.
      // Constant-time: the token is a bearer capability (see `heartbeat`).
      if (cur && token !== undefined && safeEqual(cur.token, token)) await this.ctx.storage.delete(key);
      return Response.json({ ok: true });
    }

    if (op === 'incr') {
      // Atomic windowed counter (rate-limit buckets). `cron` is the counter
      // key, `ttlMs` the window. A DO is single-threaded, so this
      // read-modify-write is atomic and globally consistent — a parallel burst
      // cannot undercount (which the per-colo Cache/KV path allowed). Returns
      // the post-increment count so the caller checks `count > LIMIT` with no
      // separate check-then-write window.
      const counterKey = `count:${cron}`;
      const nowMs = Date.now();
      const windowMs = ttlMs ?? DEFAULT_TTL_MS;
      // The rate-limit caller keys a DISTINCT DO instance per (ip, window-bucket)
      // — each instance is written once and never revisited (the next bucket is a
      // new instance), so without cleanup its single counter key would leak in DO
      // storage forever. Schedule a self-cleanup alarm to deleteAll() after the
      // window lapses. Resetting it each incr means cleanup fires `windowMs` after
      // the last write.
      const cur = await this.ctx.storage.get<{ count: number; expiresAt: number }>(counterKey);
      await this.ctx.storage.setAlarm(nowMs + windowMs + 5_000);
      if (!cur || cur.expiresAt <= nowMs) {
        await this.ctx.storage.put<{ count: number; expiresAt: number }>(counterKey, {
          count: 1,
          expiresAt: nowMs + windowMs,
        });
        return Response.json({ count: 1 });
      }
      const count = cur.count + 1;
      await this.ctx.storage.put<{ count: number; expiresAt: number }>(counterKey, { count, expiresAt: cur.expiresAt });
      return Response.json({ count });
    }

    return Response.json({ error: `unknown op: ${op}` }, { status: 400 });
  }

  /**
   * Self-cleanup for the per-(ip, bucket) rate-limit counter instances. Only the
   * `incr` path schedules an alarm; the global lease DO never does, so its
   * `lease:` keys are untouched. Once a counter window has lapsed, the instance
   * is inert — drop all its storage so these single-use instances don't
   * accumulate. `lease:` keys (only present on the global instance, which has no
   * alarm) are never reached here.
   */
  override async alarm(): Promise<void> {
    const now = Date.now();
    const counters = await this.ctx.storage.list<{ expiresAt: number }>({ prefix: 'count:' });
    let liveCounters = 0;
    const expired: string[] = [];
    for (const [k, v] of counters) {
      if (!v || v.expiresAt <= now) expired.push(k);
      else liveCounters += 1;
    }
    if (expired.length) await this.ctx.storage.delete(expired);
    // If a counter is somehow still live (alarm fired early), re-arm; otherwise
    // this instance is empty and can be left to evict.
    if (liveCounters > 0) await this.ctx.storage.setAlarm(now + 60_000);
  }
}

// ── Typed client ──────────────────────────────────────────────────────────
const LOCK_ORIGIN = 'https://cron-lock.internal';

function lockStub(env: Env) {
  const id = env.CRON_LOCK_DO.idFromName('global');
  return env.CRON_LOCK_DO.get(id);
}

/**
 * Try to acquire the single-flight lease for `cron`. Fail-OPEN on a DO error:
 * a DO blip must not halt every cron. The normal path is race-free (one global
 * DO), so the only exposure is a possible double-run during an actual DO outage.
 */
export async function acquireCronLease(
  env: Env,
  cron: string,
  ttlMs: number
): Promise<{ acquired: boolean; token?: string; failOpen?: boolean }> {
  try {
    const res = await lockStub(env).fetch(`${LOCK_ORIGIN}/acquire`, {
      method: 'POST',
      body: JSON.stringify({ op: 'acquire', cron, ttlMs }),
    });
    return (await res.json()) as { acquired: boolean; token?: string };
  } catch (_catchErr) {
    console.error('acquireCronLease failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
    return { acquired: true, failOpen: true };
  }
}

export async function heartbeatCronLease(env: Env, cron: string, token: string, ttlMs: number): Promise<void> {
  try {
    const res = await lockStub(env).fetch(`${LOCK_ORIGIN}/heartbeat`, {
      method: 'POST',
      body: JSON.stringify({ op: 'heartbeat', cron, token, ttlMs }),
    });
    // A lost lease (ok:false — expired and re-acquired elsewhere) means the
    // same cron is NOW running in another isolate: double-running the hourly
    // fan-out burns the free-plan budget twice. Surface it loudly instead of
    // silently continuing to believe we still hold the lease.
    if (!res.ok) {
      console.error(JSON.stringify({ job: 'cron-lease-heartbeat', status: 'lease-lost', cron }));
    }
  } catch (_catchErr) {
    console.error('heartbeatCronLease failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
    /* best-effort */
  }
}

export async function releaseCronLease(env: Env, cron: string, token: string): Promise<void> {
  try {
    await lockStub(env).fetch(`${LOCK_ORIGIN}/release`, {
      method: 'POST',
      body: JSON.stringify({ op: 'release', cron, token }),
    });
  } catch (_catchErr) {
    console.error('releaseCronLease failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
    /* best-effort — the TTL reclaims the lease */
  }
}
