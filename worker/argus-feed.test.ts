/**
 * Tests for the ARGUS RSS proxy handler (worker/argus-feed.ts).
 * Run via: npx vitest run worker/argus-feed.test.ts
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { handleArgusRss } from './argus-feed';
import type { Env } from './env';

const ALLOWED = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';

function makeFakeCache(): Cache & { _store: Map<string, Response> } {
  const store = new Map<string, Response>();
  return {
    _store: store,
    match: async (req: Request | string) => {
      const key = typeof req === 'string' ? req : req.url;
      return store.get(key);
    },
    put: async (req: Request | string, res: Response) => {
      const key = typeof req === 'string' ? req : req.url;
      store.set(key, res);
    },
    delete: async () => {},
    add: async () => {},
    addAll: async () => {},
  } as unknown as Cache & { _store: Map<string, Response> };
}

const env = {} as Env;

function reqFor(urlParam: string | null, method = 'GET'): { request: Request; url: URL } {
  const qs = urlParam === null ? '' : `?url=${encodeURIComponent(urlParam)}`;
  const request = new Request(`https://pranithjain.qzz.io/api/v1/argus/rss${qs}`, { method });
  return { request, url: new URL(request.url) };
}

describe('handleArgusRss', () => {
  beforeEach(() => {
    vi.stubGlobal('caches', { default: makeFakeCache() });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('returns null for non-matching paths', async () => {
    const request = new Request('https://pranithjain.qzz.io/api/v1/other');
    const res = await handleArgusRss(request, env, new URL(request.url));
    expect(res).toBeNull();
  });

  it('answers OPTIONS preflight with 204 + CORS', async () => {
    const { request, url } = reqFor(ALLOWED, 'OPTIONS');
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(204);
    expect(res?.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('rejects a non-allowlisted url with 400', async () => {
    const { request, url } = reqFor('https://evil.example/feed');
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(400);
    expect(res?.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('rejects a missing url param with 400', async () => {
    const { request, url } = reqFor(null);
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(400);
  });

  it('serves a cached response without hitting upstream', async () => {
    const fake = caches.default as unknown as { _store: Map<string, Response> };
    // Pre-seed the cache for this url's cache key.
    const { request, url } = reqFor(ALLOWED);
    const cacheKey = new Request(`https://argus-rss.internal/${encodeURIComponent(ALLOWED)}`);
    fake._store.set(cacheKey.url, new Response('<rss>cached</rss>', { headers: { 'content-type': 'text/xml' } }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(200);
    expect(res?.headers.get('x-argus-feed')).toBe('cache');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('fetches and caches an allowlisted url on a miss', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('<rss>live</rss>', { status: 200 }));
    const { request, url } = reqFor(ALLOWED);
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(200);
    expect(res?.headers.get('x-argus-feed')).toBe('live');
    expect(res?.headers.get('access-control-allow-origin')).toBe('*');
    expect(await res?.text()).toBe('<rss>live</rss>');
  });

  it('returns 502 when upstream responds non-ok', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('nope', { status: 503 }));
    const { request, url } = reqFor(ALLOWED);
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(502);
  });

  it('returns 502 when the upstream fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('network down'));
    const { request, url } = reqFor(ALLOWED);
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(502);
  });

  // Regression: these three feeds used to return 502 (a 301 to an
  // un-allowlisted ESET path, and 403s from CrowdStrike / Dark Reading).
  it.each([
    'https://www.welivesecurity.com/en/rss/feed/',
    'https://www.sophos.com/en-us/blog/feed',
    'https://www.bing.com/news/search?q=site%3Adarkreading.com&format=RSS&mkt=en-US',
  ])('serves the replacement feed %s', async (target) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('<rss>ok</rss>', { status: 200 }));
    const { request, url } = reqFor(target);
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(200);
    expect(await res?.text()).toBe('<rss>ok</rss>');
  });

  it('follows the legacy ESET redirect now that the canonical path is allowlisted', async () => {
    const legacy = 'https://www.welivesecurity.com/feed/';
    const canonical = 'https://www.welivesecurity.com/en/rss/feed/';
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 301, headers: { location: canonical } }));
    fetchSpy.mockResolvedValueOnce(new Response('<rss>eset</rss>', { status: 200 }));
    const { request, url } = reqFor(legacy);
    const res = await handleArgusRss(request, env, url);
    expect(res?.status).toBe(200);
    expect(await res?.text()).toBe('<rss>eset</rss>');
  });
});
