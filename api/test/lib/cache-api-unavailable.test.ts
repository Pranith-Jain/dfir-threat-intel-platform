import { describe, it, expect, afterEach, vi } from 'vitest';

/**
 * Regression cover for two helpers that documented a fail-open contract they
 * did not implement.
 *
 * Both dereference `caches.default` BEFORE their try/catch. In a runtime where
 * the Cache API global is absent, that raises a `TypeError` outside the guard,
 * so the documented behaviour ("No-ops cleanly when the cache isn't available",
 * "fail OPEN") never happens — the call throws instead:
 *
 *  - `claimSseSlot`      → 500s on all three SSE routes (ioc, actor-enrich, sample-scan)
 *  - `shouldWriteLastGood` → throws in ~20 call sites across the lastgood
 *    writers, turning a KV-quota optimisation into an availability outage
 *
 * Both are pure optimisations, so "cache unavailable" must cost a little
 * efficiency and nothing else.
 *
 * NOTE: in the deployed Workers runtime `caches` is present, so this is not a
 * live production incident — it is a contract/robustness defect, and these
 * tests pin the contract so a future refactor can't silently restore the throw.
 */

const originalCaches = Object.getOwnPropertyDescriptor(globalThis, 'caches');

/** Simulate a runtime with no Cache API global. */
function removeCaches(): void {
  Object.defineProperty(globalThis, 'caches', { value: undefined, configurable: true, writable: true });
}

afterEach(() => {
  if (originalCaches) Object.defineProperty(globalThis, 'caches', originalCaches);
  vi.restoreAllMocks();
});

describe('claimSseSlot — contract when the Cache API is unavailable', () => {
  it('returns a usable slot instead of throwing', async () => {
    const { claimSseSlot } = await import('../../src/lib/sse-concurrency');
    removeCaches();
    const slot = await claimSseSlot({} as never, '203.0.113.9');
    // A slot, not null (null means "over the cap" → caller answers 429) and
    // not a thrown TypeError.
    expect(slot).not.toBeNull();
    expect(typeof slot!.release).toBe('function');
    // Release must be safe to call.
    await expect(slot!.release()).resolves.toBeUndefined();
  });

  it('still enforces the cap when the Cache API IS available', async () => {
    // Guards against "fix" the other way: always returning a slot would turn
    // the concurrency cap off entirely.
    const { claimSseSlot, SSE_MAX_CONCURRENT } = await import('../../src/lib/sse-concurrency');
    const stored = new Map<string, string>();
    const fakeCache = {
      match: async (req: Request) => {
        const v = stored.get(req.url);
        return v === undefined ? undefined : new Response(v);
      },
      put: async (req: Request, res: Response) => {
        stored.set(req.url, await res.text());
      },
    };
    Object.defineProperty(globalThis, 'caches', { value: { default: fakeCache }, configurable: true, writable: true });

    for (let i = 0; i < SSE_MAX_CONCURRENT; i++) {
      expect(await claimSseSlot({} as never, '198.51.100.7')).not.toBeNull();
    }
    // One past the cap must be refused so the caller can answer 429.
    expect(await claimSseSlot({} as never, '198.51.100.7')).toBeNull();
  });
});

describe('shouldWriteLastGood — contract when the Cache API is unavailable', () => {
  it('fails OPEN (returns true) rather than throwing', async () => {
    const { shouldWriteLastGood } = await import('../../src/lib/lastgood-debounce');
    removeCaches();
    // True = "go ahead and write", i.e. the pre-cache behaviour. The failure
    // mode we care about is a throw, because every one of these `await` sites
    // sits on a request or cron path.
    await expect(shouldWriteLastGood('some:lastgood')).resolves.toBe(true);
  });

  it('actually debounces when the Cache API IS available', async () => {
    // Also guards against a "fix" that just always returns true, which would
    // silently remove the KV-quota saving the helper exists to provide.
    const { shouldWriteLastGood } = await import('../../src/lib/lastgood-debounce');
    const stored = new Map<string, string>();
    const fakeCache = {
      match: async (req: Request) => {
        const v = stored.get(req.url);
        return v === undefined ? undefined : new Response(v);
      },
      put: async (req: Request, res: Response) => {
        stored.set(req.url, await res.text());
      },
    };
    Object.defineProperty(globalThis, 'caches', { value: { default: fakeCache }, configurable: true, writable: true });

    // Cold marker → allowed, and it plants the marker.
    expect(await shouldWriteLastGood('debounce:probe')).toBe(true);
    // Warm marker → suppressed.
    expect(await shouldWriteLastGood('debounce:probe')).toBe(false);
    // A different name has its own marker.
    expect(await shouldWriteLastGood('debounce:other')).toBe(true);
  });
});
