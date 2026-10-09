/**
 * Tests for the cron single-flight lease Durable Object.
 *
 * Focus is the token-matched `heartbeat` / `release` capability check. These
 * moved from `cur.token === token` to `safeEqual()` (#307), so the behaviours
 * worth pinning are:
 *   - a correct token still extends / releases the lease,
 *   - a wrong or absent token can NEVER release a live lease — that check is
 *     the only thing stopping a stale fire from freeing a lease another
 *     isolate holds, which would let the next fire double-run the fan-out,
 *   - a truncated token is rejected (no partial match).
 *
 * Each test uses its own cron name so tests stay independent without needing a
 * storage reset — the DO instance is global, keyed by name, and storage
 * persists across tests in a file.
 */
import { describe, it, expect } from 'vitest';
import { env } from 'cloudflare:test';
import type { DurableObjectNamespace } from '@cloudflare/workers-types';

const ORIGIN = 'https://cron-lock.internal';

// `cloudflare:test`'s env is typed from the generated binding set, which does
// not carry the app's Env interface — name the binding we need explicitly
// rather than reaching for `any` (the repo lints at zero warnings).
const bindings = env as unknown as { CRON_LOCK_DO: DurableObjectNamespace };

type LeaseDO = { fetch(input: string, init?: RequestInit): Promise<Response> };

function stub(): LeaseDO {
  const id = bindings.CRON_LOCK_DO.idFromName('global');
  return bindings.CRON_LOCK_DO.get(id) as unknown as LeaseDO;
}

function call(body: Record<string, unknown>): Promise<Response> {
  return stub().fetch(`${ORIGIN}/`, { method: 'POST', body: JSON.stringify(body) });
}

interface AcquireResult {
  acquired: boolean;
  token?: string;
  heldUntil?: number;
}

async function acquire(cron: string, ttlMs = 60_000): Promise<AcquireResult> {
  return (await (await call({ op: 'acquire', cron, ttlMs })).json()) as AcquireResult;
}

async function op(cron: string, body: Record<string, unknown>): Promise<{ ok: boolean }> {
  return (await (await call({ op: body.op, cron, ...body })).json()) as { ok: boolean };
}

describe('CronLockDO acquire', () => {
  it('mints a token when the lease is free', async () => {
    const res = await acquire('acq-free');
    expect(res.acquired).toBe(true);
    expect(typeof res.token).toBe('string');
    expect(res.token?.length).toBeGreaterThan(16);
  });

  it('refuses a second acquire while the lease is live', async () => {
    const first = await acquire('acq-busy');
    const second = await acquire('acq-busy');
    expect(first.acquired).toBe(true);
    expect(second.acquired).toBe(false);
    expect(second.token).toBeUndefined();
  });

  it('scopes leases per cron name', async () => {
    expect((await acquire('scope-a')).acquired).toBe(true);
    // A different cron must not be blocked by an unrelated live lease.
    expect((await acquire('scope-b')).acquired).toBe(true);
  });
});

describe('CronLockDO heartbeat', () => {
  it('extends the lease with the correct token', async () => {
    const { token } = await acquire('hb-ok');
    expect(token).toBeTruthy();
    expect((await op('hb-ok', { op: 'heartbeat', token, ttlMs: 120_000 })).ok).toBe(true);
    // Still held after the extension — a lost lease would let this re-acquire.
    expect((await acquire('hb-ok')).acquired).toBe(false);
  });

  it('rejects a wrong token and leaves the lease held', async () => {
    await acquire('hb-wrong');
    expect((await op('hb-wrong', { op: 'heartbeat', token: 'not-the-token', ttlMs: 120_000 })).ok).toBe(false);
    expect((await acquire('hb-wrong')).acquired).toBe(false);
  });

  it('rejects a missing token', async () => {
    await acquire('hb-none');
    expect((await op('hb-none', { op: 'heartbeat', ttlMs: 120_000 })).ok).toBe(false);
    expect((await acquire('hb-none')).acquired).toBe(false);
  });
});

describe('CronLockDO release', () => {
  it('frees the lease for the correct token', async () => {
    const { token } = await acquire('rel-ok');
    expect((await op('rel-ok', { op: 'release', token })).ok).toBe(true);
    expect((await acquire('rel-ok')).acquired).toBe(true);
  });

  it('a wrong token cannot steal the lease', async () => {
    await acquire('rel-wrong');
    // release is idempotent-ok by design, so the response is not the signal —
    // whether the lease is still held afterwards is.
    expect((await op('rel-wrong', { op: 'release', token: 'not-the-token' })).ok).toBe(true);
    expect((await acquire('rel-wrong')).acquired).toBe(false);
  });

  it('a missing token cannot steal the lease', async () => {
    await acquire('rel-none');
    expect((await op('rel-none', { op: 'release' })).ok).toBe(true);
    expect((await acquire('rel-none')).acquired).toBe(false);
  });

  it('a truncated token is rejected — no partial match', async () => {
    const { token } = await acquire('rel-prefix');
    await op('rel-prefix', { op: 'release', token: token?.slice(0, 8) });
    expect((await acquire('rel-prefix')).acquired).toBe(false);
  });
});

describe('CronLockDO input validation', () => {
  it('rejects a missing cron or op', async () => {
    expect((await call({ op: 'acquire' })).status).toBe(400);
    expect((await call({ cron: 'x' })).status).toBe(400);
  });

  it('rejects an unknown op', async () => {
    const res = await call({ op: 'nope', cron: 'unknown-op' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain('nope');
  });

  it('rejects a malformed JSON body without throwing', async () => {
    const res = await stub().fetch(`${ORIGIN}/`, {
      method: 'POST',
      body: '{not json',
      headers: { 'content-type': 'application/json' },
    });
    expect(res.status).toBe(400);
  });
});
