/**
 * Write-on-change guard for KV values.
 *
 * On the free plan KV READS are 100,000/day and KV WRITES are 1,000/day — the
 * write quota is the one that actually runs out (the account hit 1,450 writes
 * on 2026-11-01). A warm/cron path that rebuilds the same payload every hour
 * and unconditionally `put`s it burns that quota for no new information.
 *
 * This helper compares the new body against the stored **raw text** and skips
 * the write when they are byte-identical. Raw text (not a parsed object) is
 * deliberate: re-serializing can reorder keys and turn every rebuild into a
 * spurious write.
 *
 * `refreshAfterSeconds` handles KV's other sharp edge: `expirationTtl` is
 * measured from the `put`, so a value that never changes would eventually
 * expire even though the producer keeps running. When set, the TTL is
 * refreshed at most once per window, marked through the free per-colo Cache
 * API (the same mechanism as `lastgood-debounce.ts`). Without it, an unchanged
 * value is left alone entirely.
 *
 * Never throws: a read error degrades to "changed" (write), which is the
 * pre-guard behaviour, and a write error is the caller's to handle.
 */
import { shouldWriteLastGood } from './lastgood-debounce';
import { resolveStore, upstashConfigured, upstashGet, upstashSet, type StoreArg } from './upstash-cache';

export interface KvPutIfChangedOptions {
  expirationTtl?: number;
  /** Refresh the TTL even when the body is unchanged, at most once per window. */
  refreshAfterSeconds?: number;
}

/**
 * Returns true when a write was issued, false when skipped (unchanged) or KV
 * is unavailable.
 */
export async function kvPutIfChanged(
  store: StoreArg,
  key: string,
  body: string,
  opts: KvPutIfChangedOptions = {}
): Promise<boolean> {
  const { kv, env } = resolveStore(store);
  if (!kv && !upstashConfigured(env)) return false;

  let previous: string | null = null;
  try {
    previous = upstashConfigured(env) ? await upstashGet(env, key) : ((await kv?.get(key)) ?? null);
  } catch {
    /* unreadable — treat as absent and write */
  }

  if (previous === body) {
    if (!opts.refreshAfterSeconds || !(await shouldWriteLastGood(`kv-ifchanged:${key}`, opts.refreshAfterSeconds))) {
      return false;
    }
  }

  if (upstashConfigured(env) && opts.expirationTtl && (await upstashSet(env, key, body, opts.expirationTtl)))
    return true;
  await kv?.put(key, body, opts.expirationTtl ? { expirationTtl: opts.expirationTtl } : undefined);
  return true;
}
