/**
 * /api/v1/onion-watch — cold-cache behaviour.
 *
 * Two production faults measured 2026-10-16, both surfacing as a bare
 * Cloudflare `error code: 1102` on roughly one request in three:
 *
 *  1. Every concurrent cache miss ran its own full Ransomlook fan-out
 *     (1 + TOP_N_GROUPS upstream calls, each with up to 3 retry attempts).
 *     On the old ceiling-hugging TOP_N_GROUPS=15 that exceeded the 50
 *     subrequest budget and lost the race with an edge error.
 *  2. An exception escaping `fetchOnionWatch` propagated out of the handler
 *     instead of degrading to the route's own KV last-good path.
 *
 * Both are pinned below: the first test asserts exactly ONE upstream fan-out
 * for concurrent requests, the second that a dead upstream yields the route's
 * own 502 (or last-good), never an unhandled throw.
 */
import { SELF, env } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ONION_WATCH_CACHE_KEY, salvageLocationObjects } from '../../src/routes/onion-watch';

const LASTGOOD_KEY = 'onion-watch:lastgood:v1';
const SHADOW_KEY = `https://lastgood-cache.internal/v1/${encodeURIComponent(LASTGOOD_KEY)}`;

const cache = (caches as unknown as { default: Cache }).default;
const kv = env.KV_CACHE as unknown as { delete(key: string): Promise<void>; put(k: string, v: string): Promise<void> };

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return (input as Request).url;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

beforeEach(async () => {
  vi.restoreAllMocks();
  // The Cache API is NOT reset between tests (isolatedStorage covers KV/D1/R2),
  // so every slot this route touches is deleted explicitly. The last-good
  // shadow matters most: a payload written by an earlier test would otherwise
  // be served instead of the failure path under test.
  await Promise.all([
    cache.delete(new Request(ONION_WATCH_CACHE_KEY)),
    cache.delete(new Request(SHADOW_KEY)),
    kv.delete(LASTGOOD_KEY),
  ]);
});

describe('salvageLocationObjects', () => {
  it('extracts locations from the profile shape and strips the base64 fields', () => {
    const payload = JSON.stringify([
      {
        captcha: false,
        meta: '',
        locations: [
          {
            slug: 'http://a.onion/',
            fqdn: 'a.onion',
            title: 'A',
            version: 3,
            available: true,
            screen: 'iVBORw0KGgoAAAANSUhEUg'.repeat(40),
          },
          {
            slug: 'http://b.onion/',
            fqdn: 'b.onion',
            title: 'B',
            version: 2,
            available: false,
            source: 'Zm9vYmFy'.repeat(100),
          },
        ],
      },
    ]);
    const locs = salvageLocationObjects(payload);
    expect(locs).toHaveLength(2);
    expect(locs.map((l) => l.fqdn)).toEqual(['a.onion', 'b.onion']);
    expect(locs[0]?.available).toBe(true);
    expect(locs[1]?.version).toBe(2);
  });

  it('handles the older flat-array shape', () => {
    const flat = JSON.stringify([{ fqdn: 'x.onion', available: true }]);
    expect(salvageLocationObjects(flat).map((l) => l.fqdn)).toEqual(['x.onion']);
  });

  it('keeps complete objects and ignores a truncated trailing object', () => {
    const complete = '{"slug":"http://a.onion/","fqdn":"a.onion","title":"A","screen":"iVBORw0KGgo="}';
    const truncatedTail = ',{"slug":"http://b.onion/","fqdn":"b.onion","title":"B","screen":"' + 'A'.repeat(500_000); // mid-base64 cut — closes neither the string nor the object
    const locs = salvageLocationObjects(`[{"captcha":false,"meta":"","locations":[${complete}${truncatedTail}`);
    expect(locs.map((l) => l.fqdn)).toEqual(['a.onion']);
  });

  it('parses escaped quotes in titles', () => {
    const payload = '[{"locations":[{"fqdn":"q.onion","title":"The \\"Big\\" Leak","available":false}]}]';
    const locs = salvageLocationObjects(payload);
    expect(locs).toHaveLength(1);
    expect(locs[0]?.title).toBe('The "Big" Leak');
  });

  it('returns [] for a payload with no object yet', () => {
    expect(salvageLocationObjects('')).toEqual([]);
    expect(salvageLocationObjects('[{"locations":[{"slug":"http://a.onion"')).toEqual([]);
  });
});

describe('GET /api/v1/onion-watch (cold cache)', () => {
  it('bounds the per-group read: huge profiles stop early, not at EOF', async () => {
    // 30 locations × ~56 KB of inline base64 each ≈ 1.7 MB total. The reader
    // must stop once GROUP_READ_MAX_OBJECTS locations are salvageable (12),
    // not pull the whole stream.
    const locs = Array.from({ length: 30 }, (_, i) => {
      const screen = 'iVBORw0KGgo'.repeat(5100); // ~56 KB
      return `{"slug":"http://huge-${i}.onion/","fqdn":"huge-${i}.onion","title":"M${i}","available":${i % 2 === 0},"screen":"${screen}"}`;
    });
    const body = `[{"captcha":false,"meta":"","locations":[${locs.join(',')}]}]`;
    const CHUNK = 16_384;
    const totalChunks = Math.ceil(body.length / CHUNK);
    let chunksPulled = 0;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = urlOf(input);
      if (url.includes('ransomlook.io/api/recent')) {
        return json([{ group_name: 'huge', discovered: '2026-10-01T00:00:00Z' }]);
      }
      if (url.includes('ransomlook.io/api/group/')) {
        const encoder = new TextEncoder();
        let offset = 0;
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            if (offset >= body.length) {
              controller.close();
              return;
            }
            chunksPulled++;
            controller.enqueue(encoder.encode(body.slice(offset, offset + CHUNK)));
            offset += CHUNK;
          },
        });
        return new Response(stream, { headers: { 'content-type': 'application/json' } });
      }
      return fetch(input, init);
    });

    const r = await SELF.fetch('https://x/api/v1/onion-watch');
    expect(r.status).toBe(200);
    const parsed = (await r.json()) as { groups: Array<{ mirrors: unknown[] }>; total_count: number };
    expect(parsed.groups).toHaveLength(1);
    expect(parsed.groups[0]!.mirrors.length).toBeGreaterThanOrEqual(12);
    // Early cancellation: the reader never pulled the entire 1.7 MB body.
    expect(chunksPulled).toBeLessThan(totalChunks);
  });

  it('runs ONE upstream fan-out for concurrent requests (single-flight)', async () => {
    let recentCalls = 0;
    let releaseRecent: () => void = () => {};
    const gate = new Promise<void>((r) => {
      releaseRecent = r;
    });

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = urlOf(input);
      if (url.includes('ransomlook.io/api/recent')) {
        recentCalls++;
        await gate;
        return json([{ group_name: 'acme', discovered: '2026-10-01T00:00:00Z' }]);
      }
      if (url.includes('ransomlook.io/api/group/')) {
        return json([{ fqdn: 'acme-leak.onion', available: true, title: 'Acme Leak Site' }]);
      }
      return fetch(input, init);
    });

    const p1 = SELF.fetch('https://x/api/v1/onion-watch');
    const p2 = SELF.fetch('https://x/api/v1/onion-watch');

    // Both requests are now past `cache.match` and blocked inside the first
    // build. If single-flight regressed, each would have started its own
    // fan-out and recentCalls would already be 2.
    await new Promise((r) => setTimeout(r, 50));
    expect(recentCalls).toBe(1);

    releaseRecent();
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);

    // The shared build's payload reaches both readers intact.
    const b1 = (await r1.json()) as { groups: Array<{ group: string }>; reachable_count: number };
    const b2 = (await r2.json()) as { groups: Array<{ group: string }> };
    expect(b1.groups.map((g) => g.group)).toEqual(['acme']);
    expect(b2.groups.map((g) => g.group)).toEqual(['acme']);
    expect(b1.reachable_count).toBe(1);
    expect(recentCalls).toBe(1);
  });

  it('returns the route 502 on upstream failure instead of throwing', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = urlOf(input);
      if (url.includes('ransomlook.io')) return new Response('upstream down', { status: 503 });
      return fetch(input, init);
    });

    const r = await SELF.fetch('https://x/api/v1/onion-watch');
    expect(r.status).toBe(502);
    expect(await r.text()).toContain('ransomlook unreachable');
  });

  it('serves last-good with X-SI-Stale when the upstream dies', async () => {
    await kv.put(
      LASTGOOD_KEY,
      JSON.stringify({
        generated_at: '2026-10-15T00:00:00Z',
        source: 'Ransomlook.io',
        source_url: 'https://www.ransomlook.io',
        groups: [{ group: 'acme', last_active: '2026-10-01T00:00:00Z', any_reachable: true, mirrors: [] }],
        reachable_count: 1,
        total_count: 1,
        warnings: [],
      })
    );

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = urlOf(input);
      if (url.includes('ransomlook.io')) return new Response('upstream down', { status: 503 });
      return fetch(input, init);
    });

    const r = await SELF.fetch('https://x/api/v1/onion-watch');
    expect(r.status).toBe(200);
    expect(r.headers.get('x-si-stale')).toBe('ransomlook-unreachable');
    const body = (await r.json()) as { groups: unknown[]; warnings: string[] };
    expect(body.groups).toHaveLength(1);
    expect(body.warnings.join(' ')).toContain('showing cached data');
  });
});
