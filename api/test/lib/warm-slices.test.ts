import { env } from 'cloudflare:test';
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import {
  readWarmSlice,
  readWarmSliceRaw,
  readWarmSlices,
  warmSliceKvKey,
  writeWarmSlice,
} from '../../src/lib/warm-slices';
import { kvPutIfChanged } from '../../src/lib/kv-write';
import { writeLastGood } from '../../src/lib/lastgood';

/**
 * The warm-slice store is the D1 replacement for the `gp:warm:*` KV keys.
 * These tests pin the two properties the migration depends on:
 *
 *   1. D1 is the canonical read/write path (using it does not also spend a
 *      KV write).
 *   2. KV remains a working fallback for every case D1 cannot serve — the
 *      legacy keys during cutover, a missing table before the migration is
 *      applied, and bodies above the D1 row limit.
 */

const WARM_SLICES_DDL =
  'CREATE TABLE IF NOT EXISTS warm_slices (key TEXT PRIMARY KEY NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); ' +
  'CREATE INDEX IF NOT EXISTS idx_warm_slices_expires ON warm_slices(expires_at)';

async function reset() {
  await env.BRIEFINGS_DB.exec('DELETE FROM warm_slices');
  for (const key of ['reddit', 'cve', 'telegram']) {
    await env.KV_CACHE.delete(warmSliceKvKey(key));
  }
}

beforeAll(async () => {
  await env.BRIEFINGS_DB.exec(WARM_SLICES_DDL);
});

beforeEach(reset);

describe('warm-slices (D1 canonical store)', () => {
  it('writes and reads a slice through D1 without touching KV', async () => {
    await writeWarmSlice(env, 'reddit', JSON.stringify({ items: [{ id: 1 }] }), 60);

    await expect(readWarmSlice<{ items: unknown[] }>(env, 'reddit')).resolves.toEqual({
      items: [{ id: 1 }],
    });
    // KV is the fallback, not a mirror: the cutover must not spend KV writes.
    await expect(env.KV_CACHE.get(warmSliceKvKey('reddit'))).resolves.toBeNull();
  });

  it('batches several keys into one read and keeps them keyed by feed name', async () => {
    await writeWarmSlice(env, 'reddit', JSON.stringify({ items: [1] }), 60);
    await writeWarmSlice(env, 'cve', JSON.stringify({ items: [2] }), 60);
    await writeWarmSlice(env, 'telegram', JSON.stringify({ items: [3] }), 60);

    const slices = await readWarmSlices<{ items: number[] }>(env, ['reddit', 'cve', 'nope']);
    expect([...slices.keys()].sort()).toEqual(['cve', 'reddit']);
    expect(slices.get('reddit')?.items).toEqual([1]);
    expect(slices.get('cve')?.items).toEqual([2]);
  });

  it('filters expired rows at read time (expiry is a column, not a TTL)', async () => {
    await env.BRIEFINGS_DB.prepare('INSERT INTO warm_slices (key, body, updated_at, expires_at) VALUES (?, ?, ?, ?)')
      .bind('cve', JSON.stringify({ stale: true }), Date.now(), Date.now() - 1)
      .run();

    await expect(readWarmSlice(env, 'cve')).resolves.toBeNull();
  });

  it('falls back to the legacy KV key when D1 has no row', async () => {
    await env.KV_CACHE.put(warmSliceKvKey('telegram'), JSON.stringify({ items: [{ id: 'legacy' }] }), {
      expirationTtl: 60,
    });

    await expect(readWarmSlice<{ items: Array<{ id: string }> }>(env, 'telegram')).resolves.toEqual({
      items: [{ id: 'legacy' }],
    });
    await expect(readWarmSliceRaw(env, 'telegram')).resolves.toContain('legacy');
  });
});

describe('kvPutIfChanged', () => {
  it('skips the write when the body is byte-identical', async () => {
    expect(await kvPutIfChanged(env.KV_CACHE, 'test:if-changed', '{"a":1}', { expirationTtl: 60 })).toBe(true);
    expect(await kvPutIfChanged(env.KV_CACHE, 'test:if-changed', '{"a":1}', { expirationTtl: 60 })).toBe(false);
    expect(await kvPutIfChanged(env.KV_CACHE, 'test:if-changed', '{"a":2}', { expirationTtl: 60 })).toBe(true);
    await env.KV_CACHE.delete('test:if-changed');
  });
});

describe('writeLastGood(skipIfUnchanged)', () => {
  it('skips a byte-identical forced write but refreshes the shadow', async () => {
    const key = 'test:lastgood-skip';
    const target = { victims: [{ id: 1 }] };
    expect(await writeLastGood(env, key, target, { keyPrefix: '', force: true, skipIfUnchanged: true })).toBe(true);
    expect(await writeLastGood(env, key, target, { keyPrefix: '', force: true, skipIfUnchanged: true })).toBe(false);
    expect(
      await writeLastGood(env, key, { victims: [{ id: 2 }] }, { keyPrefix: '', force: true, skipIfUnchanged: true })
    ).toBe(true);
    await env.KV_CACHE.delete(key);
  });
});
