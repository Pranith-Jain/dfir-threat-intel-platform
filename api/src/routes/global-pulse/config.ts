import type { FeedQueueMessage } from '../../lib/live-iocs-slices';
import { CVE_DIGEST_CACHE_KEY } from '../cve-digest';
import { AI_LLM_SLICE_KEY } from '../ai-llm-intel';
import { LIVE_IOCS_CACHE_KEY } from '../live-iocs';

/* ─── Global-pulse feed registry + queue warmer ─────────────────────────── */
// Each feed is warmed into `gp:warm:<key>` by the queue consumer — ONE feed per
// consumer invocation, so each gets its own 50-subrequest budget. The previous
// design fanned out to all ~15 feeds in a single cron invocation, which blew the
// Free-plan 50-subrequest cap ("Too many subrequests") and silently starved the
// rest of the hourly cron (telegram-archive, the briefing LLM, etc.). The read
// path stitches the per-feed keys back together (see the `warm` build below).
export const GP_FEEDS: ReadonlyArray<{ key: string; path: string }> = [
  { key: 'reddit', path: '/api/v1/reddit-feed' },
  { key: 'x', path: '/api/v1/x-feed' },
  { key: 'telegram', path: '/api/v1/telegram-feed' },
  { key: 'actor', path: '/api/v1/actor-timeline' },
  { key: 'iocc', path: '/api/v1/ioc-correlation' },
  { key: 'cve', path: '/api/v1/cve-recent?days=7' },
  { key: 'ransom', path: '/api/v1/ransomware-recent?days=7' },
  { key: 'cybercrime', path: '/api/v1/cyber-crime' },
  { key: 'writeups', path: '/api/v1/writeups' },
  { key: 'malware', path: '/api/v1/malware-samples' },
  { key: 'phishing', path: '/api/v1/phishing-urls' },
  { key: 'scam', path: '/api/v1/crypto-scam-feed' },
  { key: 'breach', path: '/api/v1/breach-disclosures' },
  { key: 'tm', path: '/api/v1/threat-map' },
  { key: 'ioc', path: '/api/v1/live-iocs' },
  { key: 'xclaims', path: '/api/v1/x-claims' },
  { key: 'stealer', path: '/api/v1/stealer-forum-intel' },
  { key: 'secretleaks', path: '/api/v1/secret-leaks' },
  { key: 'malpkg', path: '/api/v1/malicious-packages' },
  { key: 'exploit', path: '/api/v1/exploit-db?latest=1' },
  { key: 'ghsa', path: '/api/v1/github-security?ecosystem=npm' },
  { key: 'kev', path: '/api/v1/cisa-kev?days=30' },
  // 24h CVE digest — the 0-day surface (complete window + exploit flags).
  // Served from its own cron-warmed cache, so this slice is one cheap read.
  { key: 'cvedigest', path: '/api/v1/cve-digest' },
  { key: 'rss', path: '/api/v1/cyber-news' },
  { key: 'webamon', path: '/api/v1/webamon/campaign-intel' },
  { key: 'honeypot', path: '/api/v1/ai-honeypot-feed' },
  // Dedicated AI/LLM intel: campaigns, actors, write-ups, blog, and the trends
  // rollup. Separate from `honeypot` (raw observed telemetry) because this layer
  // is narrative — what is being attacked and how — not another IP list.
  { key: 'aillm', path: '/api/v1/ai-llm-intel' },
  { key: 'firms', path: '/api/v1/firms-fires' },
  { key: 'ukmto', path: '/api/v1/ukmto-incidents' },
];

// Per-feed warm-slice KV key for a global-pulse feed.
//
// Why KV, not the Cache API (which live-iocs slices use, see live-iocs-slices.ts):
// global-pulse is served from any colo to a global audience, and the read path
// must see whatever the (single-colo) cron+consumer warmed. KV is global; the
// Cache API is per-colo, so a Cache-API slice warmed in one colo would be cold
// for readers in every other colo. The cost is the KV write quota — 28 feeds/hour
// ≈ 672 writes/day, under the 1000/day free tier — the deliberate tradeoff for
// cross-colo consistency.
export const gpWarmKey = (key: string): string => `gp:warm:${key}`;

// Per-feed per-route Cache-API key (the LIVE feed response the route serves,
// SWR-revalidated, with the route's own freshness TTL). The sync build reads
// these FIRST — one cheap `cache.match` per feed, no fan-out, no handler
// re-entry — so the map is populated from the same live responses the public
// endpoints serve, NOT just the hourly KV warm slices. Per-colo by nature, so
// the warm KV slice remains the cross-colo fallback when a given colo's route
// cache is cold.
//
// MUST stay in sync with each route's `cache.put` key. Bump on route cache-key
// version changes (the route's own `vN` suffix) or the live read silently
// misses and falls back to the warm slice (correct, just older data).
export const GP_FEED_CACHE_KEYS: Readonly<Record<string, string>> = {
  reddit: 'https://reddit-feed-cache.internal/v11-raw',
  x: 'https://x-feed-cache.internal/v7-25pc',
  telegram: 'https://telegram-feed-cache.internal/v13-telegram-me',
  actor: 'https://actor-timeline-cache.internal/v3-mti',
  iocc: 'https://ioc-correlation-cache.internal/v6-mti-hashes',
  cve: 'https://cve-recent-cache.internal/v10-750-paged',
  ransom: 'https://ransomware-recent-cache.internal/v11-tz-abbrev-fix',
  cybercrime: 'https://cybercrime-cache.internal/v2-500',
  writeups: 'https://writeups-cache.internal/v22-simplified',
  malware: 'https://malware-samples-cache.internal/v3-500',
  phishing: 'https://phishing-urls-cache.internal/v11-500',
  scam: 'https://crypto-scam-feed-cache.internal/v1',
  breach: 'https://breach-cache.internal/v6-hibp-only',
  tm: 'https://threat-map-cache.internal/v5-1k',
  // Imported, not hardcoded: this key is versioned by the live-iocs route and
  // was already stale once at v13 (the route had moved to v14) — see the
  // cvedigest comment for the same rationale.
  ioc: LIVE_IOCS_CACHE_KEY,
  xclaims: 'https://x-claims-cache.internal/v2',
  // Imported, not hardcoded like the rest: this key was created alongside the
  // digest route and an import can't drift out of sync with it.
  cvedigest: CVE_DIGEST_CACHE_KEY,
  stealer: 'https://stealer-forum-intel-cache.internal/v13-no-debug',
  secretleaks: 'https://secret-leaks-cache.internal/v5-noedgecache',
  malpkg: 'https://malicious-packages-cache.internal/v2?e=npm',
  honeypot: 'https://ai-honeypot-feed.internal/v2',
  // Imported, not hardcoded: this key belongs to the ai-llm-intel route and an
  // import cannot drift out of sync with it (same rationale as cvedigest).
  aillm: AI_LLM_SLICE_KEY,
  firms: 'https://global-pulse-cache.internal/firms-ukmto-v1',
  ukmto: 'https://global-pulse-cache.internal/firms-ukmto-v1',
};

// GP-warm enqueue-cycle marker — SEPARATE from the live-iocs enqueue marker
// (live-iocs.ts ENQUEUE_CYCLE_KEY). The live-iocs hit path refreshes ITS marker
// on visitor traffic (maybeEnqueueAllFeeds → markEnqueueCycle); sharing one
// marker meant a busy /api/v1/live-iocs could keep it fresh for 105 min and
// suppress the hourly `enqueueGpFeeds`, so `gp:warm:*` slices expired (150-min
// TTL) and every layer except reddit/x (enqueued unconditionally by the */30
// cron) went dark. gp feeds get their own gate so live-iocs traffic can never
// starve the map.
export const GP_ENQUEUE_CYCLE_KEY = 'gp:enqueue-cycle';
export const GP_ENQUEUE_CYCLE_TTL_SECONDS = 60 * 60;

/** True when the last gp-warm enqueue cycle is still fresh → the hourly gp enqueue can be skipped. */
export async function shouldSkipGpEnqueue(kv: KVNamespace | undefined): Promise<boolean> {
  if (!kv) return false;
  try {
    return (await kv.get(GP_ENQUEUE_CYCLE_KEY)) !== null;
  } catch {
    return false;
  }
}

/** Record that a gp-warm enqueue completed so the next hourly cron skips its redundant re-enqueue. */
export async function markGpEnqueue(kv: KVNamespace | undefined): Promise<void> {
  if (!kv) return;
  await kv.put(GP_ENQUEUE_CYCLE_KEY, new Date().toISOString(), { expirationTtl: GP_ENQUEUE_CYCLE_TTL_SECONDS });
}

// ALL feeds are warmed every hourly tick — not a rotating subset — so the page
// never has a feed dark waiting for its window to come around (a 7-per-hour
// rotation left ~2/3 of feeds stale for up to 3h). This is only affordable
// because each feed is its OWN consumer invocation (max_batch_size:1), so
// warming 28 feeds costs 28 cheap invocations, not one over-budget one. KV cost:
// ≤28 writes/hour ≈ 672/day, under the 1000/day free tier. GP_STAGGER_SECONDS
// just spaces the sends so a burst doesn't hammer a throttling upstream (t.me);
// the budget guarantee comes from max_batch_size:1, not the stagger.
const GP_STAGGER_SECONDS = 4;

/**
 * Enqueue every global-pulse feed for the queue consumer to warm — one message
 * per feed, each consumed in its own invocation. Cheap (queue sends only, no
 * fetches), so it is safe to call from the cron. `hour` is accepted for
 * call-site symmetry but no longer selects a window (all feeds warm each tick).
 */
export async function enqueueGpFeeds(queue: Queue<FeedQueueMessage>, _hour?: number): Promise<void> {
  await queue.sendBatch(
    GP_FEEDS.map((f, i) => ({
      body: { gp: { key: f.key, path: f.path } },
      delaySeconds: i * GP_STAGGER_SECONDS,
    }))
  );
}

/* ─── Cache keys (all warmed by hourly cron) ────────────────────────────── */

export const GLOBAL_PULSE_CACHE = 'https://global-pulse-cache.internal/v25-live';
export const CACHE_TTL = 120;
// Global KV key holding the last fully-built response (raw JSON string).
// The Cache-API entry above is per-colo, so a reader in a cold colo would
// otherwise re-run the whole multi-source build (risking the Free-plan
// subrequest cap → HTTP 503). KV is global, so any colo can serve the last
// successful build with one cheap read. Rewritten on every successful build.
export const GP_RESPONSE_KEY = 'gp:response:v3';
// TTL for the global KV fallback above. Must outlive the build cadence (hourly
// cron) so cold colos and the GlobalPulse Durable Object can still read the last
// successful build between builds. CACHE_TTL (300s) is only right for the
// per-colo Cache-API entry; reusing it here made the KV entry expire ~5 min after
// each build, leaving the WS live feed empty for ~55 min of every hour.
export const GP_RESPONSE_TTL = 3600;
// Long-lived copy of the last SUCCESSFUL full build (written only by the
// background build, which is the only path that populates the external-fetcher
// layers: c2_tracker, supply_chain_attacks, blocklist, briefing, cisa_advisory).
// On a cache miss the sync build can only see warm-KV slices + 3 direct feeds, so
// those background-only layers render as 0 during cold-cache windows. The handler
// serves this last-good response instead whenever it populates more layers than
// the partial sync build (stale-if-error), so a cold cache or a CPU-killed
// background build never blanks half the map for the whole TTL.
export const GP_LAST_GOOD_KEY = 'gp:last-good:v1';
export const GP_LAST_GOOD_TTL = 43200;
