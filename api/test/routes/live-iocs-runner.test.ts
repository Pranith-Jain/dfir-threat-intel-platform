import { describe, it, expect, vi, afterEach } from 'vitest';
import { runFeedSourceById, FEED_SOURCE_IDS, FEED_SOURCE_DEBUG_URLS, type FeedDeps } from '../../src/routes/live-iocs';

const deps: FeedDeps = {};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('runFeedSourceById', () => {
  it('returns null for an unknown source id', async () => {
    expect(await runFeedSourceById('does-not-exist', deps)).toBeNull();
  });

  it('runs a single text-feed source and returns its raw contribution', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('1.1.1.1\n8.8.8.8\n9.9.9.9\n', { status: 200 }));

    const result = await runFeedSourceById('emerging-threats', deps);
    expect(result).not.toBeNull();
    // `capped: false` — 3 entries is well under the 300 per-feed cap, so the
    // count is the feed's real size, not a truncation.
    expect(result!.sources).toEqual([{ id: 'emerging-threats', ok: true, count: 3, capped: false }]);
    expect(result!.items).toHaveLength(3);
    for (const it of result!.items) {
      expect(it.kind).toBe('ip');
      expect(it.source).toBe('emerging-threats');
      expect(it.reporter).toBe('Proofpoint ETOpen');
      expect(it.context).toBe('recent compromise / blocklist');
    }
    expect(result!.items.map((i) => i.value)).toEqual(['1.1.1.1', '8.8.8.8', '9.9.9.9']);
  });

  it('reports a fetch failure as ok:false with no items', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 502 }));
    const result = await runFeedSourceById('emerging-threats', deps);
    expect(result!.sources).toEqual([{ id: 'emerging-threats', ok: false, count: 0 }]);
    expect(result!.items).toHaveLength(0);
  });
});

describe('FEED_SOURCE_IDS', () => {
  it('lists the 45 runner units in registry order', () => {
    // Count pinned to the registry. History: 30 → 29 (threatbase removed
    // 2026-09-30 after its upstream repo began 404ing) → 45 on 2026-10-05, when
    // the ai-honeypots + llm-threatintel sources and the 15 curated
    // open-source feeds landed and webamon-campaigns was retired (403 with no
    // API key configured, so it reported ok:false on every build).
    // When adding or removing a feed, bump this number AND update the
    // assertions below.
    expect(FEED_SOURCE_IDS).toHaveLength(45);
    expect(FEED_SOURCE_IDS[0]).toBe('tweetfeed');
    expect(FEED_SOURCE_IDS[44]).toBe('swiftioc');
    expect(FEED_SOURCE_IDS).toContain('emerging-threats');
    expect(FEED_SOURCE_IDS).toContain('crypto-scam');
    // Dedicated AI / LLM threat intel.
    expect(FEED_SOURCE_IDS).toContain('ai-honeypots');
    expect(FEED_SOURCE_IDS).toContain('llm-threatintel');
    // Removed dead sources
    expect(FEED_SOURCE_IDS).not.toContain('sslbl-c2');
    expect(FEED_SOURCE_IDS).not.toContain('andreafortuna-defacements');
    expect(FEED_SOURCE_IDS).not.toContain('mythreatintel');
    // Removed 2026-09-30: upstream repo deleted, 404 on every fetch.
    expect(FEED_SOURCE_IDS).not.toContain('threatbase');
    // Removed 2026-10-05: pro.webamon.com/campaigns is 403 without a
    // WEBAMON_API_KEY (none configured), so the source could only ever report
    // ok:false and forced `degraded: true` on every build. See
    // api/src/lib/feed-curation.ts RETIRED_FEEDS.
    expect(FEED_SOURCE_IDS).not.toContain('webamon-campaigns');
  });

  it('has no duplicate source ids (a dup would make two slices collide)', () => {
    const seen = new Set<string>();
    const dups = FEED_SOURCE_IDS.filter((id) => (seen.has(id) ? true : (seen.add(id), false)));
    expect(dups).toEqual([]);
  });

  it('never registers a URL from the retired-feed list', async () => {
    // Guards against a future sync re-introducing a known-dead upstream on the
    // strength of a stale third-party feed catalogue.
    const { RETIRED_FEEDS } = await import('../../src/lib/feed-curation');
    const dead = new Set(RETIRED_FEEDS.map((r) => r.url));
    const urls = Object.values(FEED_SOURCE_DEBUG_URLS).flatMap((d) => [d.url, ...(d.fallbackUrls ?? [])]);
    for (const url of urls) {
      expect(dead.has(url), `registered a retired feed URL: ${url}`).toBe(false);
    }
  });

  it('debug mirror covers every registry source (or is a documented exception)', () => {
    // A missing entry means `?debug=1` reports "unreachable" for a source that is
    // actually fine — the mirror failing silently is worse than it being absent.
    const knownNonFeed = new Set(['malwarebazaar', 'phishing', 'openphish', 'feed-scheduler']);
    for (const id of FEED_SOURCE_IDS) {
      if (knownNonFeed.has(id)) continue;
      expect(FEED_SOURCE_DEBUG_URLS[id], `no debug mirror for registry source: ${id}`).toBeDefined();
    }
  });

  it('flags capped=true when a feed fills the per-feed cap, so 300 is not read as small', async () => {
    // The roster previously showed a bare "300" for every large feed, which is
    // indistinguishable from a feed with exactly 300 indicators and reads as
    // "not active". `capped` is the fix; this pins the boundary.
    const many = Array.from({ length: 400 }, (_, i) => `1.1.1.${i % 250}`).join('\n');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(many, { status: 200 }));

    const result = await runFeedSourceById('emerging-threats', deps);
    const src = result!.sources[0];
    expect(src).toBeDefined();
    expect(src).toMatchObject({ id: 'emerging-threats', ok: true, capped: true });
    expect(src!.count).toBeGreaterThanOrEqual(300);
  });

  it("uses the 'phishing' runner label, not its response ids", () => {
    expect(FEED_SOURCE_IDS).toContain('phishing');
    expect(FEED_SOURCE_IDS).not.toContain('phishtank');
    expect(FEED_SOURCE_IDS).not.toContain('openphish');
  });

  it('excludes feed-scheduler (a compose-time D1 read, not a queue source)', () => {
    expect(FEED_SOURCE_IDS).not.toContain('feed-scheduler');
  });
});
