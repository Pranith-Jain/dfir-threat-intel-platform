import type { Context } from 'hono';
import type { Env } from '../../env';
import { logError } from '../../lib/logger';
import type {
  PulseEvent,
  PulseKind,
  GlobalPulseResponse,
  XClaimsResponse,
  ActorTimelineResponse,
  IocCorrelationResponse,
} from './types';
import {
  GP_FEEDS,
  GP_FEED_CACHE_KEYS,
  gpWarmKey,
  GLOBAL_PULSE_CACHE,
  CACHE_TTL,
  GP_RESPONSE_KEY,
  GP_RESPONSE_TTL,
  GP_LAST_GOOD_KEY,
  GP_LAST_GOOD_TTL,
} from './config';
import { routeCacheGet, routeCachePut } from '../../lib/route-cache';
import { listBriefings } from '../../lib/briefing-builder';
import { readKvJson } from './shared';
import { signInternalToken } from '../../lib/internal-token';
import {
  iocFromThreatMap,
  fromReddit,
  fromTelegram,
  fromXFeed,
  fromScam,
  fromBreaches,
  fromBriefings,
  fromLiveIocs,
  fromSecretLeaks,
  fromMaliciousPackages,
  fromExploitDb,
  fromGithubAdvisories,
  fromCisaKev,
  fromStealerForum,
  fromPhishing,
  fromMalware,
  fromRansomware,
  fromCybercrime,
  fromWriteups,
  fromCveRecent,
  fromXClaims,
  fromActorTimeline,
  fromIocCorrelation,
  fromCyberPulse,
  fromRss,
  fromWebamonCampaigns,
  fromHoneypot,
  fromAiLlmIntel,
  fromFirms,
  fromUkmto,
  fromCveDigest,
  dedupeCveEvents,
  markTrendingEvents,
  comparePulseEvents,
} from './converters';
import {
  fetchBotnetC2,
  fetchSupplyChain,
  fetchDShieldAttackers,
  fetchCompromisedIPs,
  fetchBlocklistAttackers,
  fetchCisaKev,
  fetchUrlhaus,
} from './fetchers';

/* ─── Signed self-fetch helper ──────────────────────────────────────────── */
// Retry fallbacks need to call SELF.fetch() with an internal token so the
// auth middleware lets them through. Signs once per handler invocation.
async function signedSelfFetch(
  self: { fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response> } | undefined,
  path: string,
  env: { INTERNAL_TOKEN_SECRET?: string },
  timeoutMs = 10_000
): Promise<Response | null> {
  if (!self) return null;
  const tokenSecret = env.INTERNAL_TOKEN_SECRET;
  if (!tokenSecret) return null;
  try {
    const token = await signInternalToken('cron', tokenSecret);
    return await self.fetch(
      new Request(`https://self${path}`, {
        headers: { 'x-internal-token': token },
        signal: AbortSignal.timeout(timeoutMs),
      })
    );
  } catch {
    return null;
  }
}

/* ─── Shared sync build — callable from the request handler AND the DO cron ── */
/* The free-plan 10ms CPU cap kills a stateless rebuild: the sync build reads 21
 * KV warm slices + 3 self-fetches + ~10 converters. The DO cron
 * (`gp-30-rebuild`) has a 30s CPU budget, so it runs this directly (via an
 * in-DO warm) instead of SELF.fetch-ing `?force=1` (which re-enters the 10ms
 * stateless worker). Keep the request path as the cheap primary:
 * Cache-API → GP KV last-good → this build.

/**
 * Build the sync GlobalPulse payload from warm-KV slices + direct self-fetches.
 * Pure work, no hono context, no cache writes — the caller (handler or DO cron)
 * owns the Cache-API / KV writes. Returns the payload + the incoming warm KV
 * map so the DO cron can additionally persist a last-good copy.
 */
export async function buildGlobalPulseSync(
  env: Pick<Env, 'SELF' | 'KV_CACHE' | 'INTERNAL_TOKEN_SECRET' | 'BRIEFINGS_DB'>,
  _waitUntil?: (p: Promise<unknown>) => void,
  full = false
): Promise<{ payload: GlobalPulseResponse; warm: Record<string, unknown>; sync: number }> {
  const kv = env.KV_CACHE;
  const cache = caches.default;

  // Safe wrapper — used by both the sync fetch and the background build.
  const safe = <T>(fn: () => T): T => {
    try {
      return fn();
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      return [] as unknown as T;
    }
  };

  // ── Shared subrequest budget ─────────────────────────────────────────
  // Every subrequest below (route cache.match, KV get, external upstream
  // fetch, SELF.fetch) consumes the free-plan 50-subrequest invocation cap,
  // and the request path spends a few more AFTER this build (stale-if-error
  // routeCacheGet + cache.put + routeCachePut + kv.get/put ≈ 7). So the build
  // itself gets 44 and must finish under it.
  //
  // The ORDER and SHAPE of spend is load-bearing, not cosmetic. Two changes:
  //
  //  a) The live route-cache reads were fired for all 26 feeds with a cache
  //     key. Most of those are cold in any given colo (nothing has hit that
  //     route there), so 26 subrequests were routinely spent on guaranteed
  //     misses. They are now limited to the 5 feeds whose freshness is
  //     actually visible in the UI — social + CVE recency drives the "4m ago"
  //     labels.                              26 → ≤5
  //
  //  b) The warm-KV reads were a `Promise.all`, so all 28 callbacks ran their
  //     `consume()` check before any read resolved: the budget was allocated
  //     by ARRAY POSITION and the tail of the list was deterministically
  //     dropped. That is why tm (13), secretleaks (17), malpkg (18), exploit
  //     (19), ghsa (20) and honeypot (25) rendered 0 for hours at a time while
  //     their slices sat fully populated in KV — they were last in line, not
  //     missing. They are now read sequentially (see below).
  //
  // Worst case after the fix:
  //   5 live + 9 external fetchers + 1 D1 briefings + 1 cyberpulse self-fetch
  //   + 27 warm slices = 43, under the 44 cap with the ~7 post-build writes
  //   still fitting inside 50.
  const BUDGET_MAX = 44;
  const budget = { used: 0 };
  const consume = (n = 1): boolean => {
    if (budget.used + n > BUDGET_MAX) return false;
    budget.used += n;
    return true;
  };

  /** Feeds read from the per-colo live route cache. See the budget plan above. */
  const LIVE_CACHE_PRIORITY = new Set(['reddit', 'x', 'telegram', 'cve', 'ransom']);

  // ── LIVE per-route Cache-API reads, freshness-critical feeds only ────
  // These are the same responses the public /api/v1/* endpoints serve —
  // SWR-revalidated on visitor traffic with each route's own freshness TTL
  // (minutes, not hours). Reading them directly (rather than re-entering the
  // route handler, which would re-run its own fetch fan-out) is 1 subrequest
  // per feed. Per-colo by nature: on a cold colo this misses and the feed
  // falls through to the global warm slice below.
  const live: Record<string, unknown> = {};
  await Promise.all(
    GP_FEEDS.map(async (f) => {
      if (!LIVE_CACHE_PRIORITY.has(f.key)) return;
      const key = GP_FEED_CACHE_KEYS[f.key];
      if (!key || !consume()) return;
      try {
        const hit = await cache.match(new Request(key));
        if (hit) live[f.key] = (await hit.json()) as unknown;
      } catch {
        /* cold / parse error → fall back to warm KV below */
      }
    })
  );

  // ── LIVE external fetchers (c2_tracker / supply_chain / blocklist / kev / etc.)
  // Previously FULL-only (only when ?force=1 DO rebuild) so visitor sync builds
  // rendered those layers 0 until the DO's next 10-min tick. Now budget-gated
  // but attempted on EVERY sync build: consume() guards the 50-subrequest cap,
  // so a cold colo degrades a warm layer rather than aborting. The DO full
  // build still guarantees completeness via stale-if-error + KV last-good.
  let botnetC2: PulseEvent[] = [];
  let supplyChain: PulseEvent[] = [];
  let dshieldAttackers: PulseEvent[] = [];
  let compromisedIPs: PulseEvent[] = [];
  let blocklistAttackers: PulseEvent[] = [];
  let cisaKev: PulseEvent[] = [];
  let urlhausMalware: PulseEvent[] = [];
  let briefingEvents: PulseEvent[] = [];
  // External threat-intel fetchers — always try, budget-gated. `full` no longer
  // required; the DO rebuild and the per-colo route caches already amortize cost.
  [botnetC2, supplyChain, dshieldAttackers, compromisedIPs, blocklistAttackers, cisaKev, urlhausMalware] =
    await Promise.all([
      consume(3) ? fetchBotnetC2() : Promise.resolve([] as PulseEvent[]),
      consume() ? fetchSupplyChain() : Promise.resolve([] as PulseEvent[]),
      consume() ? fetchDShieldAttackers() : Promise.resolve([] as PulseEvent[]),
      consume() ? fetchCompromisedIPs() : Promise.resolve([] as PulseEvent[]),
      consume() ? fetchBlocklistAttackers() : Promise.resolve([] as PulseEvent[]),
      consume() ? fetchCisaKev() : Promise.resolve([] as PulseEvent[]),
      consume() ? fetchUrlhaus() : Promise.resolve([] as PulseEvent[]),
    ]);

  // ── Briefings (D1) ────────────────────────────────────────────────
  try {
    if (env.BRIEFINGS_DB) {
      const { items } = await listBriefings(env.BRIEFINGS_DB, { limit: 5 });
      briefingEvents = fromBriefings(items);
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* degraded */
  }
  // `full` is retained for call-site compatibility only. It used to gate the
  // external-fetcher layers (which meant a visitor build rendered c2_tracker /
  // cyber_attack / supply_chain as 0); those are now budget-gated and run on
  // EVERY build, so both callers get the same complete map. The separate
  // `?force=1` duplicate build that used to be the "full" path is gone.
  void full;

  // ── CyberPulse incidents (D1) ────────────────────────────────────────
  let cyberpulseEvents: PulseEvent[] = [];
  if (consume()) {
    try {
      const cpRes = await signedSelfFetch(env.SELF, '/api/v1/cyberpulse/incidents?days=7&limit=30', env, 10000);
      if (cpRes && cpRes.ok) {
        const cpData = (await cpRes.json()) as Parameters<typeof fromCyberPulse>[0];
        cyberpulseEvents = safe(() => fromCyberPulse(cpData));
      }
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
    }
  }

  // ── Warm KV slices (cross-colo) — the completeness guarantee ──────────
  // `gp:warm:<key>`, written hourly by the queue consumer one feed per
  // invocation, is the source that makes a layer appear AT ALL. Route caches
  // are per-colo and usually cold for anything but the top-traffic feeds, so
  // this is the read that actually populates the map — it is not a "fallback",
  // it is the floor.
  //
  // Read SEQUENTIALLY, not in a `Promise.all`: the sequential loop is what
  // makes `consume()` meaningful. Fired in parallel, all 28 callbacks run
  // their `consume()` check before any read resolves, so the budget is
  // allocated by array position and the tail of the list is deterministically
  // dropped. Sequentially, a slow early read cannot cause a later feed to be
  // skipped for budget reasons — the only thing that can skip one is a feed
  // that genuinely has no slice.
  const warm: Record<string, unknown> = {};
  if (kv) {
    for (const f of GP_FEEDS) {
      if (live[f.key] != null) continue; // live route cache already won
      if (!consume()) break; // budget gone: keep what we have, don't abort
      const val = await readKvJson(kv, gpWarmKey(f.key));
      if (val != null) warm[f.key] = val;
    }
  }

  // ── Convert collected data → events ──────────────────────────────────
  const merged: Record<string, unknown> = { ...warm, ...live };
  const warmEvents: PulseEvent[] = [
    ...safe(() => (merged.tm ? iocFromThreatMap(merged.tm as Parameters<typeof iocFromThreatMap>[0]) : [])),
    ...safe(() => (merged.ioc ? fromLiveIocs(merged.ioc as Parameters<typeof fromLiveIocs>[0]) : [])),
    ...safe(() => (merged.telegram ? fromTelegram(merged.telegram as Parameters<typeof fromTelegram>[0]) : [])),
    ...safe(() => (merged.reddit ? fromReddit(merged.reddit as Parameters<typeof fromReddit>[0]) : [])),
    ...safe(() => (merged.x ? fromXFeed(merged.x as Parameters<typeof fromXFeed>[0]) : [])),
    ...safe(() => (merged.scam ? fromScam(merged.scam as Parameters<typeof fromScam>[0]) : [])),
    ...safe(() => (merged.breach ? fromBreaches(merged.breach as Parameters<typeof fromBreaches>[0]) : [])),
    ...safe(() => (merged.stealer ? fromStealerForum(merged.stealer as Parameters<typeof fromStealerForum>[0]) : [])),
    ...safe(() => (merged.phishing ? fromPhishing(merged.phishing as Parameters<typeof fromPhishing>[0]) : [])),
    ...safe(() => (merged.malware ? fromMalware(merged.malware as Parameters<typeof fromMalware>[0]) : [])),
    ...safe(() => (merged.cybercrime ? fromCybercrime(merged.cybercrime as Parameters<typeof fromCybercrime>[0]) : [])),
    ...safe(() => (merged.writeups ? fromWriteups(merged.writeups as Parameters<typeof fromWriteups>[0]) : [])),
    ...safe(() => (merged.xclaims ? fromXClaims(merged.xclaims as XClaimsResponse) : [])),
    ...safe(() => (merged.actor ? fromActorTimeline(merged.actor as ActorTimelineResponse) : [])),
    ...safe(() => (merged.iocc ? fromIocCorrelation(merged.iocc as IocCorrelationResponse) : [])),
    ...safe(() =>
      merged.secretleaks ? fromSecretLeaks(merged.secretleaks as Parameters<typeof fromSecretLeaks>[0]) : []
    ),
    ...safe(() =>
      merged.malpkg ? fromMaliciousPackages(merged.malpkg as Parameters<typeof fromMaliciousPackages>[0]) : []
    ),
    ...safe(() => (merged.exploit ? fromExploitDb(merged.exploit as Parameters<typeof fromExploitDb>[0]) : [])),
    ...safe(() => (merged.ghsa ? fromGithubAdvisories(merged.ghsa as Parameters<typeof fromGithubAdvisories>[0]) : [])),
    ...safe(() => (merged.kev ? fromCisaKev(merged.kev as Parameters<typeof fromCisaKev>[0]) : [])),
    ...safe(() => (merged.rss ? fromRss(merged.rss as Parameters<typeof fromRss>[0]) : [])),
    ...safe(() =>
      merged.webamon ? fromWebamonCampaigns(merged.webamon as Parameters<typeof fromWebamonCampaigns>[0]) : []
    ),
    ...safe(() => (merged.honeypot ? fromHoneypot(merged.honeypot as Parameters<typeof fromHoneypot>[0]) : [])),
    // Narrative AI/LLM intel — campaigns, actors, write-ups, blog. The observed
    // IPs already render via `honeypot`, so this deliberately omits them.
    ...safe(() => (merged.aillm ? fromAiLlmIntel(merged.aillm as Parameters<typeof fromAiLlmIntel>[0]) : [])),
    ...safe(() => (merged.cve ? fromCveRecent(merged.cve as Parameters<typeof fromCveRecent>[0]) : [])),
    // 24h digest — the 0-day surface (KEV + exploited + criticals, capped).
    // Warmed hourly via the cvedigest queue slice; shares the digest route's
    // own cache key as the live leg.
    ...safe(() => (merged.cvedigest ? fromCveDigest(merged.cvedigest as Parameters<typeof fromCveDigest>[0]) : [])),
    ...safe(() => (merged.ransom ? fromRansomware(merged.ransom as Parameters<typeof fromRansomware>[0]) : [])),
    ...safe(() =>
      (merged.firms ?? merged.ukmto) ? fromFirms((merged.firms ?? merged.ukmto) as Parameters<typeof fromFirms>[0]) : []
    ),
    ...safe(() =>
      (merged.ukmto ?? merged.firms) ? fromUkmto((merged.ukmto ?? merged.firms) as Parameters<typeof fromUkmto>[0]) : []
    ),
  ];

  // ── Merge + sort ─────────────────────────────────────────────────────
  const tagCti = <T extends PulseKind>(kind: T): PulseEvent['cti'] => {
    switch (kind) {
      case 'ransomware':
        return 'ransomware';
      case 'cve':
      case 'cisa_advisory':
        return 'cve';
      case 'ioc_activity':
      case 'cyber_attack':
      case 'c2_tracker':
      case 'blocklist':
      case 'honeypot':
        return 'ioc';
      case 'malware':
      case 'phishing':
      case 'infostealer':
      case 'breach':
      case 'cybercrime':
      case 'scam':
      case 'actor_sighting':
      case 'secret_leak':
      case 'malicious_package':
      case 'exploit':
      case 'github_advisory':
      case 'kev':
        return 'threat';
      case 'cyberpulse':
        return 'threat';
      case 'ioc_correlation':
        return 'ioc';
      case 'rss':
        return 'other';
      default:
        return 'other';
    }
  };
  // Trending is stamped BEFORE dedupe: dedupe collapses the same CVE to one
  // row, which would erase the multi-source corroboration trending counts.
  // The surviving (richest) row keeps the flag.
  // Dedupe prefers digest rows (exploit_status + EPSS + freshest timestamps),
  // so one CVE never triplicates across the digest/catalog/sample layers.
  const mergedEvents = dedupeCveEvents(
    markTrendingEvents([
      ...warmEvents,
      ...safe(() => briefingEvents),
      ...safe(() => cyberpulseEvents),
      ...safe(() => botnetC2),
      ...safe(() => supplyChain),
      ...safe(() => dshieldAttackers),
      ...safe(() => compromisedIPs),
      ...safe(() => blocklistAttackers),
      ...safe(() => cisaKev),
      ...safe(() => urlhausMalware),
    ])
  );
  // Within a severity tier, confirmed harm (ransom victims, KEV 0-days)
  // outranks vulnerability records, which outrank raw infrastructure
  // observations — this is what stops 50 "now"-stamped critical C2 IPs from
  // permanently topping the feed above real victims and 0-days.
  const allEvents = mergedEvents.map((e) => ({ ...e, cti: tagCti(e.kind) })).sort(comparePulseEvents);

  // Full layer map (all PulseKind keys present, like the background build)
  // so the SPA's layer list shows every layer — zero for empty, not missing.
  const zeroLayers = (): Record<PulseKind, number> => ({
    earthquake: 0,
    ioc_activity: 0,
    geopolitical: 0,
    tech_news: 0,
    reddit: 0,
    telegram: 0,
    x_feed: 0,
    scam: 0,
    breach: 0,
    briefing: 0,
    cyber_attack: 0,
    aircraft: 0,
    war_room: 0,
    c2_tracker: 0,
    cisa_advisory: 0,
    blocklist: 0,
    infostealer: 0,
    phishing: 0,
    malware: 0,
    ransomware: 0,
    cybercrime: 0,
    research: 0,
    cve: 0,
    actor_sighting: 0,
    ioc_correlation: 0,
    secret_leak: 0,
    malicious_package: 0,
    exploit: 0,
    github_advisory: 0,
    supply_chain_attacks: 0,
    kev: 0,
    firm: 0,
    maritime: 0,
    cyberpulse: 0,
    rss: 0,
    honeypot: 0,
    ai_llm_campaign: 0,
    ai_llm_research: 0,
  });

  const layers: Record<PulseKind, number> = zeroLayers();
  for (const e of allEvents) {
    layers[e.kind] = (layers[e.kind] ?? 0) + 1;
  }

  const payload: GlobalPulseResponse = {
    generated_at: new Date().toISOString(),
    total_events: allEvents.length,
    events: allEvents,
    layers,
  };

  return { payload, warm: merged, sync: allEvents.length };
}

/* ─── Handler ───────────────────────────────────────────────────────────── */

// In-isolate single-flight for the cold-miss sync build (DOS-1 pattern from
// live-iocs): concurrent cold-miss visitors join one in-flight build.
let inflightGpSyncBuild: Promise<GlobalPulseResponse> | null = null;

export async function globalPulseHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const force = new URL(c.req.url).searchParams.get('force') === '1';
  const cache = caches.default;
  const cacheReq = new Request(GLOBAL_PULSE_CACHE);

  // ── Self-heal nudge (no cron) ──────────────────────────────────────────
  // When the payload we're about to serve is stale, ask the GlobalPulse DO to
  // run an on-demand full rebuild (in-process, 30s CPU budget — a browser
  // `?force=1` can't survive the stateless 10ms cap, the DO can). That
  // rebuild populates every layer — including the external-fetcher ones the
  // sync build skips — so visitor traffic drives freshness instead of the
  // hourly/30-min crons. The DO throttles to ~1 rebuild/8 min and skips when
  // its data is already fresh, so this is a cheap no-op on warm traffic.
  const maybeNudgeDo = (p: { generated_at?: string } | null | undefined): void => {
    if (!c.env.GLOBAL_PULSE_DO || !p?.generated_at) return;
    const ageMs = Date.now() - new Date(p.generated_at).getTime();
    if (ageMs < 10 * 60_000) return;
    const doId = c.env.GLOBAL_PULSE_DO.idFromName('global');
    c.executionCtx.waitUntil(
      c.env.GLOBAL_PULSE_DO.get(doId)
        .fetch(new Request('https://global-pulse-do.internal/rebuild-if-stale', { method: 'POST' }))
        .catch(() => {})
    );
  };

  if (!force) {
    try {
      const cached = await cache.match(cacheReq);
      if (cached) return new Response(cached.body, cached);
    } catch (_catchErr) {
      logError('globalPulseHandler cache match failed', _catchErr);
      /* fall through to KV/compute */
    }
  }

  const kv = c.env.KV_CACHE;

  if (!force) {
    const cachedBody = await routeCacheGet<unknown>(GP_RESPONSE_KEY);
    if (cachedBody) {
      const kvBody = JSON.stringify(cachedBody);
      maybeNudgeDo(cachedBody as { generated_at?: string } | null);
      c.executionCtx.waitUntil(
        cache
          .put(
            cacheReq,
            new Response(kvBody, {
              headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_TTL}` },
            })
          )
          .catch(() => {})
      );
      return new Response(kvBody, {
        headers: {
          'content-type': 'application/json',
          'cache-control': `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}`,
          'access-control-allow-origin': '*',
        },
      });
    }
  }

  // Cache miss. buildGlobalPulseSync assembles the response synchronously
  // from LIVE data within the free-plan 50-subrequest budget:
  //   1. Per-route Cache-API entries (the live responses the public /api/v1/*
  //      endpoints serve, SWR-revalidated on visitor traffic) — 1 cache.match
  //      each, no handler re-entry, no fan-out
  //   2. External fetchers (botnet C2, supply chain, DShield, blocklists,
  //      CISA KEV, URLhaus) + D1 briefings — the layers that used to be
  //      background-build-only and rendered 0 when the CPU-killed background
  //      build didn't finish
  //   3. Per-feed warm KV slices (gp:warm:<key>) as the cross-colo fallback
  //      for route caches that are cold in this colo
  //
  // This is the ONLY build (the duplicate `?force=1` one is gone — see the
  // note at the end of this function for why it was starving this one).

  // ── Shared sync build (also used by the DO gp-30-rebuild cron) ──────
  // `full` = the DO gp-30-rebuild cron path (30s CPU budget, force=1): includes
  // the external-fetcher layers + D1 briefings. The visitor cache-miss path
  // stays cheap (route caches + warm slices + cyberpulse) so the free-plan
  // 10ms CPU cap can't kill the request — the DO's full build populates
  // KV/cache and the stale-if-error guard serves the fuller map.
  // ── Shared sync build (also used by the DO gp-30-rebuild cron) ──────
  // Single-flight: N concurrent cold-miss visitors share ONE build instead of
  // each running the full ~44-subrequest assembly (same DOS-1 collapse as
  // live-iocs' inflightLiveIoccsBuild). Payload is request-agnostic.
  if (!inflightGpSyncBuild) {
    inflightGpSyncBuild = buildGlobalPulseSync(c.env, c.executionCtx.waitUntil.bind(c.executionCtx), force).then(
      (r) => r.payload
    );
    void inflightGpSyncBuild.finally(() => {
      inflightGpSyncBuild = null;
    });
  }
  const syncResult = await inflightGpSyncBuild;

  // Stale-if-error guard: the sync build now covers every layer itself, but a
  // cold colo or a budget-gated build can still come up with fewer non-zero
  // layers than a recent full build (e.g. all route caches cold AND KV warm
  // slices expired). If a recent FULL build is available and populates more
  // layers than this sync build, serve it instead — staleness is bounded by one
  // build cycle, and a cold cache never blanks half the map for the whole
  // GP_RESPONSE_TTL.
  const nonZeroLayers = (l: unknown): number =>
    l && typeof l === 'object'
      ? Object.values(l as Record<string, unknown>).filter((n) => typeof n === 'number' && n > 0).length
      : 0;
  let payload: GlobalPulseResponse = syncResult;
  const lastGood = await routeCacheGet<GlobalPulseResponse>(GP_LAST_GOOD_KEY);
  if (
    lastGood &&
    Array.isArray(lastGood.events) &&
    lastGood.layers &&
    nonZeroLayers(lastGood.layers) > nonZeroLayers(syncResult.layers)
  ) {
    payload = lastGood;
  }

  // Self-heal: a stale served payload (cold colo, or the crons lagging)
  // kicks the DO to rebuild on-demand so the next poll/WS push is live.
  maybeNudgeDo(payload);

  const json = JSON.stringify(payload);
  const response = new Response(json, {
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}`,
      'access-control-allow-origin': '*',
    },
  });
  c.executionCtx.waitUntil(
    (async () => {
      await Promise.all([
        cache.put(cacheReq, response.clone()),
        routeCachePut(GP_RESPONSE_KEY, payload, GP_RESPONSE_TTL),
      ]);
      // ALSO write to KV (cross-colo) so the GlobalPulse DO's KV fallback
      // (pollFeeds reads kv.get(GP_RESPONSE_KEY)) actually has data. Without
      // this, the DO's KV fallback 404s and the WS live feed goes stale once
      // the per-colo Cache-API entry (300s TTL) expires — the page shows
      // "2 hours ago" because the DO has nothing newer to broadcast.
      // Write-on-change: an unchanged build must not burn the scarce free-plan
      // KV write quota (1k/day) — a cheap read skips the put when nothing moved.
      // Poisoning guard: a partial sync build (cold colo, warm slices missing)
      // must NOT clobber a fuller map already in KV (written by the background
      // build or a prior cycle). Compare non-zero layer counts before writing;
      // only overwrite when the new payload is at least as complete.
      if (kv) {
        const newNonZero = payload.layers ? nonZeroLayers(payload.layers) : 0;
        const existing = await readKvJson<GlobalPulseResponse>(kv, GP_RESPONSE_KEY);
        const existingNonZero = existing?.layers ? nonZeroLayers(existing.layers) : 0;
        if (existingNonZero > newNonZero) {
          // keep the fuller map — skip the put
        } else if ((await kv.get(GP_RESPONSE_KEY)) !== json) {
          await kv.put(GP_RESPONSE_KEY, json, { expirationTtl: GP_RESPONSE_TTL });
        }
        // Last-good: the sync build is now a complete map (route caches +
        // external fetchers + D1), so also refresh the long-lived last-good
        // copy here — the background build (the old sole writer) is killed by
        // the subrequest cap after the sync build consumes most of the 50,
        // and a fresh last-good keeps the stale-if-error guard + DO fallback
        // from serving an hours-old map. Same poisoning guard: never clobber
        // a fuller map already persisted.
        const lgExisting = await readKvJson<GlobalPulseResponse>(kv, GP_LAST_GOOD_KEY);
        const lgExistingNonZero = lgExisting?.layers ? nonZeroLayers(lgExisting.layers) : 0;
        if (newNonZero >= lgExistingNonZero) {
          await routeCachePut(GP_LAST_GOOD_KEY, payload, GP_LAST_GOOD_TTL);
          await kv.put(GP_LAST_GOOD_KEY, json, { expirationTtl: GP_LAST_GOOD_TTL });
        }
      }
    })()
  );

  // ── No second "background build" ──────────────────────────────────────
  // There used to be a ~620-line duplicate of `buildGlobalPulseSync` here,
  // gated behind `?force=1`, that re-derived every layer from the warm slices
  // plus ~19 `signedSelfFetch` fallbacks. It was the reason the map kept
  // losing layers (IOC, exploit, GHSA, secret-leak, malicious-package,
  // infostealer, honeypot, rss all rendering 0 for hours at a time):
  //
  //   * `?force=1` ran BOTH builds in ONE invocation — this duplicate's 28
  //     UNgated `Promise.all` KV reads plus its fallbacks, and
  //     `buildGlobalPulseSync`'s own ~37 — against the same free-plan
  //     50-subrequest cap. `buildGlobalPulseSync` lost the race: its reads
  //     threw "Too many subrequests by single Worker invocation" and every
  //     layer it hadn't reached yet silently rendered 0. Tail proof:
  //     `at fetchBotnetC2 → at async buildGlobalPulseSync`.
  //   * Its writes carried NO poisoning guard, so a degraded map it built
  //     overwrote GP_RESPONSE_KEY and GP_LAST_GOOD_KEY — which the
  //     stale-if-error guard above then happily kept serving.
  //
  // `buildGlobalPulseSync` is now the single build. It already includes the
  // external-fetcher layers (budget-gated, not `full`-only) and the writes
  // above already persist cache + KV + last-good behind a poisoning guard, so
  // `?force=1` (the DO's 30-min rebuild and the cron nudge) is just a normal
  // cache miss that skips the edge cache.
  return response;
}
