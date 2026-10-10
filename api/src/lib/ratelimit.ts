import type { Context, Next } from 'hono';
import type { Env } from '../env';

const LIMIT = 30; // keyless (website / anonymous) requests per minute per IP/colo
// Authenticated API-key callers get 4x headroom. The same-origin website is
// keyless and stays at LIMIT (its expensive fan-outs are bypassed/edge-cached,
// so 30/min of non-bypassed lookups is ample for a real visitor); a scraper
// that spoofs the Origin header to pass the auth gate also stays capped at
// LIMIT, while legitimate high-volume consumers are nudged to use a key.
const LIMIT_KEYED = 120;
const WINDOW_SEC = 60;

/**
 * Service-binding / test-harness hosts. Requests arriving with one of these
 * URL hostnames are in-process (SELF fetch) or harness traffic — never an
 * external caller — so they skip every bucket including the strict ones.
 */
const INTERNAL_HOSTS = new Set(['x', 'self', 'self.internal']);

/**
 * Circuit-breaker for cache errors. After CACHE_ERROR_THRESHOLD consecutive
 * errors, the rate limiter returns 503 instead of failing open. Resets after
 * CACHE_ERROR_RESET_SEC. Prevents unlimited requests during a Cache-API outage.
 */
let cacheErrorCount = 0;
let cacheErrorWindowStart = Date.now();
const CACHE_ERROR_THRESHOLD = 5;
const CACHE_ERROR_RESET_SEC = 60;

/**
 * Circuit-breaker check. Returns true if the cache is healthy (allow request
 * to proceed), false if too many consecutive errors (return 503).
 */
function checkCacheHealth(): boolean {
  const now = Date.now();
  // Reset counter after the window expires
  if (now - cacheErrorWindowStart > CACHE_ERROR_RESET_SEC * 1000) {
    cacheErrorCount = 0;
    cacheErrorWindowStart = now;
  }
  return cacheErrorCount < CACHE_ERROR_THRESHOLD;
}

function recordCacheError(): void {
  cacheErrorCount++;
}

/**
 * KV write budget on the free Workers KV tier is 1,000 writes/day per
 * namespace. Every non-bypassed request to /api/v1/* costs one write
 * (read-modify-write of the per-IP token bucket). Without aggressive
 * bypass, even modest portfolio traffic burns through the quota — every
 * /threatintel page load fans out to a dozen feed endpoints and turns
 * them all into KV writes.
 *
 * Strategy: only rate-limit endpoints that have an actual abuse vector
 * (user-input lookups that fan out to expensive upstream APIs). Cached
 * read-only feeds are bypassed; they're already protected by edge cache
 * (CF serves the cached response without invoking the worker most of the
 * time), and they're parameter-free so there's nothing to abuse anyway.
 */

/** Exact-match exempt paths. */
const BYPASS_EXACT = new Set<string>([
  '/api/v1/health',
  '/api/v1/health/detailed',
  '/api/v1/features',
  '/api/v1/pageviews',
  // Cached read-only aggregators — all served from edge cache; even cold-
  // cache hits do bounded upstream work and don't expose anything an
  // abuser couldn't get from RSS directly.
  '/api/v1/threat-pulse',
  '/api/v1/writeups',
  '/api/v1/cyber-crime',
  '/api/v1/telegram-feed',
  '/api/v1/reddit-feed',
  '/api/v1/x-feed',
  '/api/v1/live-iocs',
  '/api/v1/feed-status',
  '/api/v1/ransomware-recent',
  '/api/v1/breach-disclosures',
  '/api/v1/cve-recent',
  '/api/v1/phishing-urls',
  '/api/v1/malware-samples',
  '/api/v1/onion-watch',
  '/api/v1/threat-map',
  '/api/v1/rules',
  '/api/v1/ioc-correlation',
  '/api/v1/snapshot',
  '/api/v1/ioc-snapshot',
  '/api/v1/actor-timeline',
  '/api/v1/victim-releaks',
  '/api/v1/atlas/technique',
  '/api/v1/mitre/technique',
  // GET /intel-bundle is the read path for every per-item IntelCard on
  // /threatintel pages — D1-cached, never user-input-driven, must not
  // burn KV-write quota on each page load.
  '/api/v1/intel-bundle',
]);

/** Prefix-match exempt paths. Read-only endpoints only. */
const BYPASS_PREFIX = [
  // NOTE: '/api/v1/feeds/aggregate' is deliberately NOT covered by this
  // prefix. It is the one feed path whose cost is attacker-controlled: it
  // fans out to up to MAX_FEEDS (40) upstreams, each costing a cache match +
  // fetch + redirect hops + write-back put — 120-320 subrequests in a single
  // invocation, well past Cloudflare's 50-subrequest cap. Fully bypassing it
  // let an unauthenticated caller force subrequest exhaustion and use the
  // Worker as an unmetered relay against ~70 allowlisted publishers. The
  // sibling paths below (proxy, abuse-rss, ioc-summary) are single-target and
  // cache-served, so they keep the bypass.
  '/api/v1/feeds/proxy',
  '/api/v1/feeds/abuse-rss',
  '/api/v1/feeds/ioc-summary',
  '/api/v1/feeds/mti-ransomware',
  '/api/v1/feeds/ransomware-merged',
  '/api/v1/blog/', // public blog list + post detail — read-only, slug-validated, edge-cached
];

/**
 * Briefings: every GET path (list / today / rss / :slug detail) is read-only
 * and edge-cached, so none of them should pay a rate-limit KV read+write on
 * the way to a cache hit. The three admin mutations stay rate-limited — that
 * per-IP bucket is the brute-force protection on BRIEFINGS_ADMIN_TOKEN.
 */
const BRIEFINGS_ADMIN = new Set<string>([
  '/api/v1/briefings/build',
  '/api/v1/briefings/backfill',
  '/api/v1/briefings/sweep',
]);

/**
 * Admin mutations get an extra-strict bucket on TOP of the global LIMIT —
 * because each POST to /api/v1/admin/run/discover or /briefings/backfill can
 * fan out to dozens of subrequests + KV/D1 writes. Per leaked token, the
 * global 30/min would let an attacker burn a day's KV write quota in 60s.
 *
 * GETs are intentionally NOT in this bucket: the admin UI loads several
 * tabs in parallel (each firing a GET on mount) and a 5/min cap on reads
 * tripped legitimate operator traffic within a few clicks. Read endpoints
 * are cheap KV lookups and the global 30/min remains as cover.
 */
const ADMIN_STRICT_LIMIT = 5;
const ADMIN_STRICT_PREFIX = '/api/v1/admin/';
function isAdminStrict(pathname: string, method: string): boolean {
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return false;
  // CAPE submit (detonation) and recon scan (active enumeration) fan out to
  // expensive self-hosted work; cap them like other admin mutations even though
  // they live outside the /admin/ prefix.
  return (
    pathname.startsWith(ADMIN_STRICT_PREFIX) ||
    BRIEFINGS_ADMIN.has(pathname) ||
    pathname === '/api/v1/cape/submit' ||
    pathname === '/api/v1/recon/scan'
  );
}

/**
 * AI/costly-mutation bucket (10/min/IP/colo, all callers). These endpoints
 * are public by design (the SPA calls them keyless same-origin, MCP agents
 * call them keyed) but each hit burns Workers AI, paid upstream quota, or
 * shared writes — a forged-Origin scraper at the global 30/min could run up
 * real cost. 10/min is ample for interactive use; internal SELF calls
 * (hostname 'self'/'x', incl. all MCP-agent fan-out) skip limiting entirely.
 *
 * GETs are excluded from the prefix/exact lists: parallel SPA tab loads
 * must not trip a write-bucket, and those GETs are reads (the briefings
 * POSTs below stay covered). COSTLY_GET_EXACT below is the deliberate
 * exception — paid/CPU-burn reads that would otherwise sit on the global
 * 30/120-min bucket alone (120/min of $0.01 WHOIS queries or uncached
 * resvg renders is real money/CPU for a leaked key).
 */
const AI_STRICT_LIMIT = 10;
/** Prefix-match (no trailing slash; matches the path itself + /...). */
const AI_STRICT_PREFIXES = [
  '/api/v1/copilot', // chat/investigate/pivots/follow-ups/bulk-ioc/rules — AI + D1 writes
  '/api/v1/agents/chat', // vera — AI + D1 writes
  '/api/v1/ti', // ti analyze/summarize/risk-score/hunt/brief (LLM) + ti/domains POST (D1)
  '/api/v1/velociraptor', // live IR backend proxy when configured
  '/api/v1/darknet-intel/vulners', // paid VULNERS_API_KEY burn
  '/api/v1/sample-submission', // forwards samples to VT/Hybrid-Analysis
  '/api/v1/briefings', // POST feedback/annotations (D1 writes); GETs excluded by method
  '/api/v1/saved-reports', // global-shared D1 writes
  '/api/v1/workspaces', // global-shared D1 writes
  '/api/v1/ioc-watchlist', // D1 writes + stored webhooks
  '/api/v1/estate', // single-tenant whiteboard — D1 config/asset/alert writes (2026-09-30 audit)
  '/api/v1/tool-chains', // POST run — chains of timed outbound fetches (2026-09-30 audit)
  '/api/v1/tg-saved-searches', // global-shared D1 writes
  // 2026-10-10 audit: prefix families whose every mutating member was on the
  // global bucket only.
  '/api/v1/export', // 8 renderers (stix/misp/sigma/yara/snort/suricata/csv/pfsense) — CPU each
  '/api/v1/soc/playbooks', // CRUD + :id/execute — execution runs a stored step list
  '/api/v1/flowviz', // analyze / analyze-stream / assistant / validate — each runs Workers AI
  // Credential endpoints. `/api/v1/auth/login` is mounted through a sub-router,
  // so the same-origin exemption applies to it exactly as to any /api/v1 read:
  // a caller who forges an Origin header reaches it with NO API key. It also
  // had no throttle of its own — nothing in routes/auth.ts tracks failed
  // attempts — so the only bound was the global 30/min. That is 30 password
  // guesses per minute per IP against a real credential, which is a
  // credential-stuffing budget, not a UX one. 10/min is still generous for
  // interactive use and is the tightest bucket this limiter has for a
  // non-admin path. A per-account lockout belongs in the handler; this is the
  // edge-level backstop until then.
  '/api/v1/auth',
];
/** Exact-match costly POSTs. */
const AI_STRICT_EXACT = new Set<string>([
  // Single-shot AI analysis (Workers AI / Groq / Gemini / NVIDIA)
  '/api/v1/threat-analysis',
  '/api/v1/ioc-extraction',
  '/api/v1/mitre-mapping',
  '/api/v1/country-intel',
  '/api/v1/event-correlation',
  '/api/v1/campaign-tracker',
  '/api/v1/feed-quality',
  '/api/v1/story-cluster',
  '/api/v1/alert-check',
  '/api/v1/research-digest',
  '/api/v1/darkweb-intel',
  '/api/v1/knowledge-graph',
  '/api/v1/ai-summary',
  '/api/v1/ai-item-summary',
  '/api/v1/dossier', // + KV write
  '/api/v1/ttp-extract',
  '/api/v1/fivew',
  '/api/v1/image-ioc', // vision model, raw image bytes
  '/api/v1/report-analyzer',
  '/api/v1/threat-intel/ach',
  '/api/v1/campaign-generator',
  '/api/v1/unified-search/summarize',
  '/api/v1/hunting-queries/generate',
  '/api/v1/ir-playbooks/generate',
  '/api/v1/fplens/analyze',
  // Heavy/keyed provider fan-out
  '/api/v1/ioc/explain',
  '/api/v1/ioc/rule',
  '/api/v1/ioc/enrich-deep',
  '/api/v1/url-risk/analyze',
  '/api/v1/file/analyze',
  '/api/v1/cve/lookup/batch',
  '/api/v1/soc-cve-report',
  '/api/v1/soc-cve-report/json',
  '/api/v1/radar/scan', // + KV writes
  '/api/v1/tie/enrich', // + Investigator-DO spawn on deep:true
  '/api/v1/actor-enrich/otx-stream', // up to 50 keyed OTX calls
  '/api/v1/x-firehose/probe-batch', // up to 80 timelines on operator cookies
  '/api/v1/sample/scan',
  '/api/v1/email-osnit/bulk', // 10x full profile fan-out
  '/api/v1/tracer/expand', // Etherscan-keyed + set fetches
  // Shared writes / quota-sensitive singles
  '/api/v1/ti-dashboard/build', // LLM + INSERT OR REPLACE weekly_reports
  '/api/v1/auth/register', // open registration — bot-farm throttle
  '/api/v1/one-time-secret', // KV write per call
  '/api/v1/threat-intel/feedback', // aggregate-mutating writes
  '/api/v1/domain/history/snapshot', // live RDAP/WHOIS + D1 insert
  '/api/v1/phishing/fingerprint', // KV write per call
  '/api/v1/webamon/scan', // third-party scan-job initiation
  '/api/v1/si/render', // resvg-wasm PNG render (CPU)

  // ── 2026-10-10 endpoint audit: writes that were on the global bucket only ──
  //
  // Every entry below is a POST/PUT/PATCH/DELETE that reached the handler with
  // no bucket tighter than the global 30/min (120/min keyed). Each one either
  // fans out to upstream services, burns CPU, or writes shared state, so a
  // caller who has cleared the auth gate (or forged same-origin headers) could
  // drive 30x more of them per minute than the AI bucket allows. They are
  // grouped by what they cost rather than listed alphabetically, so the reason
  // for each stays visible when the list is next audited.
  //
  // Outbound-fetch relays — the caller picks the target, so each call is an
  // egress request charged to this account and an abuse surface against the
  // upstream operator:
  '/api/v1/phishing/fetch-page', // SSRF-pinned, but still an arbitrary-URL relay
  '/api/v1/infra-search', // up to 3 Overpass public instances per call
  '/api/v1/open-dir/scan', // directory-enumeration fan-out
  '/api/v1/mcp/proxy', // forwards the caller's payload to the MCP server
  '/api/v1/intodns/debug-email', // live DNS/MX probes
  '/api/v1/osv/scan', // per-package upstream OSV lookups
  '/api/v1/bloom/check', // bloom-filter build/lookup over upstream data
  '/api/v1/fortibleed/batch', // batch port/DNS/ASN checks
  '/api/v1/stealer/parse', // multi-source dump fan-out (telegram + reddit + forum)
  '/api/v1/si/enrich-ip-stix-batch', // batch IP enrichment
  // CPU / correlation work — expensive per call, no upstream quota but real time:
  '/api/v1/report-analyzer/render', // Browser Rendering render (paid binding)
  '/api/v1/cti/render/graph', // graphviz render
  '/api/v1/attack-chain/reconstruct',
  '/api/v1/threat-intel/campaign/analyze',
  '/api/v1/threat-intel/correlate',
  '/api/v1/ssvc/triage',
  '/api/v1/analytics-report',
  // Server-side work amplifiers — one call executes a stored list of steps:
  '/api/v1/automation/run',
  '/api/v1/intel-bundle', // STIX build: enrichment + Vectorize upsert + D1
  '/api/v1/intel-bundle/build',
  '/api/v1/cyberpulse/scan', // drives the full upstream ingestion + D1 writes
  // Global-shared D1 writes (no per-user ownership, so a flood is not self-limiting):
  '/api/v1/campaigns',
  '/api/v1/watchlist/digest',
  '/api/v1/cti/exposure',
  '/api/v1/yara/generate',
  '/api/v1/yara/validate',
  // Second pass, driven by the route-classification guard
  // (src/test/route-classification-coverage.test.ts) that flagged what the
  // first pass missed. Only genuinely costly paths belong here — the guard's
  // CHEAP_CRUD_EXEMPT is the other half of that decision, and two candidates
  // (`cti/parse`, `threat-intel/actor-dna/match`) were pure in-process compute
  // and went there instead.
  '/api/v1/misp', // caller-supplied baseUrl+apiKey → outbound request (relay)
  '/api/v1/cti/export/stix', // STIX serialisation over a D1 scan
  '/api/v1/telegram-custom-channels', // shared KV list rewrite; DELETE shares the path
  '/api/v1/flowviz/analyze', // graph build that runs a Workers AI model
]);
function isAiStrict(pathname: string, method: string): boolean {
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return false;
  if (AI_STRICT_EXACT.has(pathname)) return true;
  // An exact entry also covers its sub-paths. This was exact-only, so
  // `DELETE /api/v1/campaigns/:id` and `DELETE /api/v1/threat-intel/feedback/:id`
  // fell out of the bucket their own collection was in — the DELETE on a
  // resource was unprotected while the POST that created it was capped.
  for (const p of AI_STRICT_EXACT) {
    if (pathname.startsWith(`${p}/`)) return true;
  }
  return AI_STRICT_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/**
 * Costly endpoints that are hit via GET (and must NOT be left on the global
 * bucket alone). Method-agnostic on purpose: `/api/v1/si/render` is costly
 * as both GET (deep-link render) and POST (manifest render).
 */
const COSTLY_GET_EXACT = new Set<string>([
  '/api/v1/si/render', // resvg-wasm PNG render (CPU)
  '/api/v1/whoxy/reverse', // paid $0.01/query upstream
  '/api/v1/traceix/lookup', // multi-engine AV hash lookup upstream
]);

function isBypassed(pathname: string): boolean {
  if (BYPASS_EXACT.has(pathname)) return true;
  if (pathname.startsWith('/api/v1/briefings/') && !BRIEFINGS_ADMIN.has(pathname)) return true;
  for (const prefix of BYPASS_PREFIX) {
    if (pathname.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Atomically increment a strict rate-limit bucket via the CRON_LOCK_DO `incr`
 * op and return the post-increment count, or null when the DO is unbound or
 * errors (so the caller can fall back to the legacy KV/Cache path). A Durable
 * Object is single-threaded, so the read-modify-write is atomic and globally
 * consistent — this closes the parallel-burst bypass (RL-RACE-1) on the
 * brute-force-protection bucket without putting a DO hop on every public request.
 */
async function atomicStrictIncr(
  c: Context<{ Bindings: Env }>,
  scope: 'admin' | 'ai',
  ip: string,
  bucket: number
): Promise<number | null> {
  const ns = (c.env as { CRON_LOCK_DO?: DurableObjectNamespace }).CRON_LOCK_DO;
  if (!ns) return null;
  try {
    const id = ns.idFromName(`rl:${scope}:${ip}:${bucket}`);
    const res = await ns.get(id).fetch('https://cron-lock.internal/incr', {
      method: 'POST',
      body: JSON.stringify({ op: 'incr', cron: `${scope}:${ip}:${bucket}`, ttlMs: WINDOW_SEC * 2 * 1000 }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { count?: number };
    return typeof data.count === 'number' ? data.count : null;
  } catch {
    return null;
  }
}

export async function rateLimit(c: Context<{ Bindings: Env }>, next: Next): Promise<Response | void> {
  const url = new URL(c.req.url);
  if (!url.pathname.startsWith('/api/v1/') && !url.pathname.startsWith('/api/taxii2/')) return next();
  // Strict buckets (admin + AI-costly) are evaluated BEFORE the read-bypass:
  // a POST under a bypassed prefix (e.g. /api/v1/briefings/:slug/feedback)
  // must still hit its strict bucket. isAdminStrict/isAiStrict return false
  // for GET/HEAD/OPTIONS, so read bypasses are unaffected — except for
  // COSTLY_GET_EXACT, which is method-agnostic by design.
  const adminStrict = isAdminStrict(url.pathname, c.req.method);
  const aiStrict = isAiStrict(url.pathname, c.req.method) || COSTLY_GET_EXACT.has(url.pathname);
  if (isBypassed(url.pathname) && !adminStrict && !aiStrict) return next();

  // Skip rate limiting in the vitest-pool-workers test environment and for
  // internal SELF service-binding calls. The test harness makes many requests
  // from the same IP within a minute, which would trip the 30/min keyless
  // limit and cause 429s in later tests. Internal SELF.fetch calls are
  // in-process and should never be rate-limited. 'x' is the test-harness
  // host (https://x/...), 'self' comes from lib/self-fetch.ts and
  // case-study rendering, and 'self.internal' from the INTERNAL constant in
  // ioc-enrich-deep / actor-profile / stix-ip-enrich — all three are
  // service-binding hosts no external request can present.
  if (INTERNAL_HOSTS.has(url.hostname)) return next();

  // Everything below uses caches.default — per-colo state, no KV quota.
  // The trade-off (an attacker can re-do their burst per CF colo) is
  // acceptable for a personal site; the limit is abuse-protection, not
  // a payment gate. Migrated from KV 2026-05-24 to drop the 1 read +
  // 1 write per request that was the biggest single KV consumer.

  const ip = c.req.header('cf-connecting-ip') ?? 'anon';
  // `authenticate` runs before this middleware and sets `c.user` only for a
  // VALID API key — so keyed external callers get LIMIT_KEYED, while the keyless
  // website and any spoofed-Origin scraper get the firm LIMIT.
  const keyed = Boolean((c as Context<{ Bindings: Env }> & { user?: unknown }).user);
  const limit = keyed ? LIMIT_KEYED : LIMIT;
  const bucket = Math.floor(Date.now() / 1000 / WINDOW_SEC);
  const cache = (caches as unknown as { default: Cache }).default;
  const ipEnc = encodeURIComponent(ip);
  const key = new Request(`https://rl.internal/u/${bucket}/${ipEnc}`);
  const adminKey = adminStrict ? new Request(`https://rl.internal/a/${bucket}/${ipEnc}`) : null;
  const aiKey = aiStrict ? new Request(`https://rl.internal/c/${bucket}/${ipEnc}`) : null;

  let count = 0;
  let adminCount = 0;
  let adminViaDO = false;
  let aiCount = 0;
  let aiViaDO = false;
  try {
    const hit = await cache.match(key);
    if (hit) count = parseInt(await hit.text(), 10) || 0;
    if (adminKey) {
      // Prefer the atomic, globally-consistent DO counter (RL-RACE-1). It
      // increments as part of the read, so the returned value is the
      // post-increment count — map it back to the pre-increment value the
      // check below expects, and skip the separate write further down.
      const doCount = await atomicStrictIncr(c, 'admin', ip, bucket);
      if (doCount !== null) {
        adminCount = doCount - 1;
        adminViaDO = true;
      } else {
        // DO unavailable — fall back to per-colo Cache API (free, no KV quota).
        const adminHit = await cache.match(adminKey);
        if (adminHit) adminCount = parseInt(await adminHit.text(), 10) || 0;
      }
    }
    if (aiKey) {
      // Same atomic-first pattern in a separate 'ai' namespace, so AI burn
      // and admin brute-force budgets don't share headroom.
      const doCount = await atomicStrictIncr(c, 'ai', ip, bucket);
      if (doCount !== null) {
        aiCount = doCount - 1;
        aiViaDO = true;
      } else {
        const aiHit = await cache.match(aiKey);
        if (aiHit) aiCount = parseInt(await aiHit.text(), 10) || 0;
      }
    }
  } catch {
    recordCacheError();
    if (!checkCacheHealth()) {
      return c.json({ error: 'service_degraded', message: 'rate limiter temporarily unavailable' }, 503, {
        'retry-after': String(CACHE_ERROR_RESET_SEC),
      });
    }
    return next(); // cache error — fail open (below threshold)
  }

  if (count >= limit) {
    return c.json({ error: 'rate_limited', limit, window_seconds: WINDOW_SEC }, 429, {
      'retry-after': String(WINDOW_SEC),
      'x-ratelimit-limit': String(limit),
      'x-ratelimit-remaining': '0',
      'x-ratelimit-reset': String((bucket + 1) * WINDOW_SEC),
      'cache-control': 'no-store',
    });
  }

  if (adminKey && adminCount >= ADMIN_STRICT_LIMIT) {
    return c.json(
      {
        error: 'rate_limited',
        limit: ADMIN_STRICT_LIMIT,
        window_seconds: WINDOW_SEC,
        scope: 'admin',
      },
      429,
      {
        'retry-after': String(WINDOW_SEC),
        'x-ratelimit-limit': String(ADMIN_STRICT_LIMIT),
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String((bucket + 1) * WINDOW_SEC),
        'cache-control': 'no-store',
      }
    );
  }

  if (aiKey && aiCount >= AI_STRICT_LIMIT) {
    return c.json(
      {
        error: 'rate_limited',
        limit: AI_STRICT_LIMIT,
        window_seconds: WINDOW_SEC,
        scope: 'ai-costly',
      },
      429,
      {
        'retry-after': String(WINDOW_SEC),
        'x-ratelimit-limit': String(AI_STRICT_LIMIT),
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String((bucket + 1) * WINDOW_SEC),
        'cache-control': 'no-store',
      }
    );
  }

  // Best-effort increment (don't block). max-age expires the entry at
  // the end of the window so the bucket resets without a TTL sweep.
  c.executionCtx.waitUntil(
    cache
      .put(
        key,
        new Response(String(count + 1), {
          headers: { 'cache-control': `max-age=${WINDOW_SEC}` },
        })
      )
      .catch(() => undefined)
  );
  if (adminKey && !adminViaDO) {
    // Legacy admin write — only when the atomic DO path was NOT used (the DO
    // already incremented its own counter). Per-colo Cache API (free, no KV
    // quota). Admin endpoints see orders of magnitude less traffic than public
    // ones, so per-colo counting is acceptable.
    c.executionCtx.waitUntil(
      cache
        .put(
          adminKey,
          new Response(String(adminCount + 1), {
            headers: { 'cache-control': `max-age=${WINDOW_SEC}` },
          })
        )
        .catch(() => undefined)
    );
  }
  if (aiKey && !aiViaDO) {
    // Same best-effort write for the AI bucket (skipped when the DO path
    // already counted). AI endpoints see more traffic than admin ones but
    // far less than feed reads; per-colo counting is acceptable.
    c.executionCtx.waitUntil(
      cache
        .put(
          aiKey,
          new Response(String(aiCount + 1), {
            headers: { 'cache-control': `max-age=${WINDOW_SEC}` },
          })
        )
        .catch(() => undefined)
    );
  }

  return next();
}
