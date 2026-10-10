import apiApp from '../api/src/index';
import {
  BRIEFING_MAX_AGE_DAYS,
  buildBriefing,
  writeBriefing,
  sweepOldBriefings,
  briefingNeedsHeal,
  expectedWeeklySlug,
  isoDate,
} from '../api/src/lib/briefing-builder';

import {
  runDiscoveryNow,
  runPlannerNow,
  runPublisherNow,
  runSocialAutopostNow,
  refreshSocialMetricsNow,
  type CaseStudyEnv,
} from '../api/src/case-study/run';
import { runTelegramArchive } from '../api/src/routes/telegram-archive';
import {
  runTelegramLeakScanner,
  scrapeWatchedChannels,
  cleanupLeakEntries,
} from '../api/src/routes/telegram-leak-monitor';
import {
  fetchTelegramFeed,
  getTelegramFeedCacheKey,
  pollBotUpdates,
  type TelegramFeedResponse,
} from '../api/src/routes/telegram-feed';
import { fetchXFeed } from '../api/src/routes/x-feed';
import { refreshVictimReleaksCache } from '../api/src/routes/victim-releaks';
import { warmCveRecentCache } from '../api/src/routes/cve-recent';
import { warmRansomwareRecentCache } from '../api/src/routes/ransomware-recent';
import { warmPromptintelCache } from '../api/src/routes/promptintel';
import { warmIntelBundles } from '../api/src/lib/intel-bundle-warm';
import { checkWatches } from '../api/src/lib/watch-engine';
import { checkAddressWatches } from '../api/src/lib/address-watch';
import { sweepWatchlist } from '../api/src/lib/ioc-watchlist';
import {
  buildStatusSnapshot,
  upsertStatusSnapshot,
  readLatestSnapshot,
  computeStatusDeltas,
} from '../api/src/lib/breach-forum-status';
import { getCuratedForums } from '../api/src/routes/breach-forums';
import { buildDeepDarkCti } from '../api/src/routes/deepdarkcti';
import { buildBlocklists } from '../api/src/lib/blocklist-builder';
import { indexTelegramLeaks } from '../api/src/routes/rag-index';
import { indexAllCorpora } from '../api/src/routes/rag-corpus-index';
import { detectPirAlerts } from '../api/src/routes/pir';
import { syncOwaspAiLandscape, syncCuratedToolbox, syncCuratedCerts } from '../api/src/lib/landscape-sync';
import { syncGitHubAdvisories, GHSA_META_KV_KEY, GHSA_FRESH_TTL_S } from '../api/src/lib/github-security-sync';
import { runFullCollection } from '../api/src/lib/cti-collector';
import { runRetentionSweep } from '../api/src/lib/retention';
import { runGraphIngest } from '../api/src/routes/graph-ingest';
import { autoRunFeedJobs } from '../api/src/routes/feed-scheduler';
import { enqueueAllFeeds, shouldSkipEnqueueCycle, markEnqueueCycle } from '../api/src/routes/live-iocs';
import { enqueueGpFeeds, shouldSkipGpEnqueue, markGpEnqueue } from '../api/src/routes/global-pulse';
import { signInternalToken } from '../api/src/lib/internal-token';
import { scanForPhishingDomains, type PassiveDnsEnv } from '../api/src/lib/passive-dns';
import { runCyberPulseIngestion } from '../api/src/routes/cyberpulse-ingest';
import type { CyberPulsePrefetch } from '../api/src/routes/cyberpulse-ingest';
import { fetchXClaims } from '../api/src/routes/x-claims';
import { checkXHealth } from '../api/src/lib/twitter-auth-graphql';
import { fetchRedditFeed } from '../api/src/routes/reddit-feed';
import type { D1Database, ScheduledEvent, ExecutionContext } from '@cloudflare/workers-types';
import { acquireCronLease, releaseCronLease, heartbeatCronLease } from './durable-objects/cron-lock';

// Lease TTL for the cron single-flight gate. Generous so it covers the
// worst-case job window (the briefing build runs well past the old 120s) —
// the lease auto-expires if a run crashes, and the next fire can acquire.
const CRON_LEASE_TTL_MS = 15 * 60_000;
import type { Env as ApiEnv } from '../api/src/env';
import type { Env } from './env';

/**
 * Cron-triggered work. The cron stub dispatches to the CronJobDO; the heavy
 * bodies run inside that DO's durable alarm (see durable-objects/cron-job.ts)
 * with a DO CPU budget — the free-plan 10ms cron cap cannot run them inline.
 * The bodies, keyed on cron string:
 * - "0 * * * *"  → hourly: telegram scan, graph-ingest,
 *                  feed-scheduler, infra-scan, retention, PIR alerts,
 *                  breach-forum snapshot + BRIEFING HEAL
 *                  (conditional — only fires if the 00:30/00:45 primary
 *                  build left the row empty or degraded).
 *                  Optional heavy tenants (intel-bundle-warm, cti-collector,
 *                  phishing-scan, rag-reindex, victim-releaks, ghsa sync)
 *                  are admitted by an estimated subrequest-budget planner
 *                  (50/invocation free-plan cap): each tick logs
 *                  `subrequest-budget` with admitted vs deferred stages;
 *                  every stage is periodic and catches up next hour.
 * - "5 0 * * *"  → daily case-study discovery + planner (chained; one
 *                  lease, planner runs after discovery finishes so it
 *                  sees the just-updated candidate queue)
 * - "30 0 * * *" → daily briefing for the prior calendar day
 * - "45 0 * * 1" → weekly briefing for the prior ISO week (Mon → Sun)
 * - "0 * * * *"  → warm /api/v1/snapshot + /api/v1/ioc-snapshot once
 *                  per hour. Was every 5 min — that cadence was burning
 *                  Workers KV writes for negligible UX gain. Snapshot
 *                  cache TTL bumped to 1h to match.
 */
/**
 * Cron stub — runs under the free-plan 10ms CPU cap.
 *
 * It does NOT do any heavy work itself. It forwards `{ cron, scheduledTime }`
 * to the per-cron CronJobDO instance, which runs the real job body
 * ([[executeCronJob]]) inside a durable alarm with a DO CPU budget (30s).
 * A one-line fetch is ~1-2ms CPU + ~1 subrequest — well inside free limits.
 *
 * Fallback: when CRON_JOB_DO is unbound (miniflare / `wrangler dev` without
 * the binding) the job runs inline, preserving the old local-dev behavior.
 */
export async function handleScheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
  const cron = event.cron;
  const scheduledTime = event.scheduledTime;
  if (!env.CRON_JOB_DO) {
    console.warn(
      JSON.stringify({ job: 'cron-dispatch', cron, status: 'inline_fallback', reason: 'CRON_JOB_DO unbound' })
    );
    await executeCronJob(cron, scheduledTime, env, ctx);
    return;
  }
  const id = env.CRON_JOB_DO.idFromName(cron);
  const stub = env.CRON_JOB_DO.get(id);
  ctx.waitUntil(
    stub
      .fetch('https://cron-job.internal/run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cron, scheduledTime }),
      })
      .then((res) => {
        console.log(JSON.stringify({ job: 'cron-dispatch', cron, status: res.status }));
      })
      .catch((e) => console.error(JSON.stringify({ job: 'cron-dispatch', cron, status: 'failed', error: String(e) })))
  );
}

/** The actual job bodies — executed inside the CronJobDO (not the cron itself). */
export async function executeCronJob(
  cron: string,
  scheduledTime: number,
  env: Env,
  ctx: ExecutionContext
): Promise<void> {
  const startMs = Date.now();

  // === Per-cron-string single-flight lease (Durable Object) ===========
  // A DO is single-threaded + globally unique, so acquire is atomic and
  // globally consistent — unlike the old KV get-then-put, which was
  // non-atomic (two PoPs could each read "free" then each write) and per-PoP
  // (eventually consistent), so a Cloudflare retry or cross-PoP duplicate
  // could both pass the gate and double-run the fan-out / briefing build.
  // The TTL covers the job window; we fail-open on a DO error so a blip
  // never halts every cron.
  const lease = await acquireCronLease(env, cron, CRON_LEASE_TTL_MS);
  if (!lease.acquired) {
    console.log(JSON.stringify({ job: 'cron-lock', cron, status: 'skipped_overlap' }));
    return;
  }
  if (lease.failOpen) {
    console.log(JSON.stringify({ job: 'cron-lock', cron, status: 'do_error_fail_open' }));
  }

  // Release the single-flight lease as soon as the dispatched work settles, so a
  // retry / next fire isn't blocked for the whole TTL. Chained via `.finally`
  // onto each branch's waitUntil promise (per spec, the chain waits for the
  // returned promise). A no-op when we failed open (no real token to match).
  const releaseLease = (): Promise<void> => releaseCronLease(env, cron, lease.token ?? '');

  // === Case-study generator — piggybacks on the existing 3 crons ===
  const csNow = new Date(scheduledTime);
  const csCron = cron;

  const logCronFail = (job: string) => (e: unknown) =>
    console.error(JSON.stringify({ cron: csCron, job, error: e instanceof Error ? e.message : String(e) }));

  const logCronDone = (extra: Record<string, unknown> = {}) => {
    console.log(JSON.stringify({ job: 'cron-done', cron, duration_ms: Date.now() - startMs, ...extra }));
  };

  // Case-study discovery + planner — single daily invocation. Discovery
  // populates today's candidate queue; the planner runs immediately after
  // against the just-updated backlog so the day's first publish slot has
  // fresh approved material to schedule. Chained sequentially (NOT in
  // parallel) so the planner sees candidates the discovery run may have
  // also flagged for auto-approval, and so a single shared lease covers
  // both — one DO acquire/release for the whole pipeline.
  if (csCron === '5 0 * * *') {
    ctx.waitUntil(
      (async () => {
        try {
          await runDiscoveryNow(env as unknown as CaseStudyEnv, csNow);
        } catch (e) {
          logCronFail('discovery')(e);
          // Don't rethrow: a discovery failure must not block the planner,
          // which operates on the existing approved backlog and is the
          // half the platform actually depends on daily.
        }
        try {
          await runPlannerNow(env as unknown as CaseStudyEnv, csNow);
        } catch (e) {
          logCronFail('planner')(e);
        }
        logCronDone({ path: 'discovery+planner' });
      })()
        .catch(logCronFail('discovery+planner'))
        .finally(releaseLease)
    );
    return;
  }

  if (cron === '0 * * * *') {
    ctx.waitUntil(
      (async () => {
        const db = env.BRIEFINGS_DB as D1Database | undefined;
        // Heartbeat the cron lease every 5 min so long-running jobs
        // (briefing builds, intel bundles) don't lose the lease.
        const heartbeatInt = setInterval(() => {
          if (lease.token) heartbeatCronLease(env, cron, lease.token, CRON_LEASE_TTL_MS).catch(() => {});
        }, 5 * 60_000);
        try {
          // === Global Pulse feed-warm enqueue — FIRST ==========================
          // Cheap queue sends (one message per feed); the queue consumer warms
          // each feed in its OWN invocation with its own 50-subrequest budget.
          // Must land before the hourly pipeline (Telegram + X + CyberPulse +
          // CTI + phishing scan) exhausts the free-plan subrequest/CPU cap — the
          // old position inside the fireAndForget block (~line 493) was never
          // reached, so gp:warm:* expired and the map lost every warmed layer.
          if (env.FEEDS_QUEUE) {
            // Skip-when-fresh: a fan-out that completed <~105 min ago (cron
            // OR hit-path refresh) is still covered by the gp:warm 150-min TTL
            // and the 6h slice TTL, so the 48-message re-enqueue is pure waste.
            // Marker is only written on success, so a failed cycle always
            // re-enqueues next hour.
            //
            // NOTE: gp feeds use their OWN marker (GP_ENQUEUE_CYCLE_KEY), NOT
            // the live-iocs marker — the live-iocs hit path refreshes ITS marker
            // on visitor traffic, and sharing one gate meant a busy
            // /api/v1/live-iocs suppressed the gp-warm enqueue, expiring
            // gp:warm:* and darkening every layer except reddit/x (enqueued
            // unconditionally by the */30 cron). The two pipelines are
            // independent — gate them independently.
            const [gpFresh, iocFresh] = await Promise.all([
              shouldSkipGpEnqueue(env.KV_CACHE),
              shouldSkipEnqueueCycle(env.KV_CACHE),
            ]);
            if (gpFresh && iocFresh) {
              console.log(JSON.stringify({ job: 'queue-enqueue', status: 'skipped-fresh' }));
            } else {
              if (!gpFresh) {
                await enqueueGpFeeds(env.FEEDS_QUEUE, csNow.getUTCHours()).catch(logCronFail('gp-warm-enqueue'));
                await markGpEnqueue(env.KV_CACHE).catch(logCronFail('gp-enqueue-cycle-mark'));
              }
              // Live-IOC feed slices — same reasoning. The queue consumer warms each
              // source in its own invocation (own budget). Without this the compose-
              // on-read path falls back to the budget-limited synchronous fan-out,
              // which starves every source past the first ~11 — the "16 unreachable"
              // blocklists (blocklist-de, cinsscore, threatview, certpl, bitwire…).
              if (!iocFresh) {
                await enqueueAllFeeds(env.FEEDS_QUEUE).catch(logCronFail('live-iocs-enqueue'));
                await markEnqueueCycle(env.KV_CACHE).catch(logCronFail('enqueue-cycle-mark'));
              }
            }
          }

          // === CVE-recent + ransomware-recent warm — FIRST (before the pipeline) =
          // These MUST land at the top of the hourly branch: the rest of the
          // pipeline (telegram/x/reddit scans, fireAndForget fan-out, CTI
          // collector) can exhaust the DO alarm's 30s CPU budget, and these
          // warms are the only thing preventing free-plan `exceededCpu` 503s
          // on self-fetches of /api/v1/cve-recent and /api/v1/ransomware-recent
          // (GlobalPulse, fusion-exposure, ioc-enrich-deep). Same reasoning as
          // enqueueGpFeeds above — "moved to TOP because the old position was
          // never reached".
          try {
            const warm = await warmCveRecentCache(env as unknown as ApiEnv);
            console.log(JSON.stringify({ job: 'cve-recent-warm', count: warm.count, ok: warm.ok }));
          } catch (e) {
            logCronFail('cve-recent-warm')(e);
          }
          // Daily CVE digest (last 24h) — via the queue, NOT inline. The build
          // fans out over ctiwatch paging + VulnTracker + EPSS (~20
          // subrequests), and running it here after cve-recent's own ~25-fetch
          // fan-out starved it two hours running (skipped-empty both times).
          // A queue message gets its own consumer invocation → its own
          // 50-subrequest budget (same pattern as the gp:warm slices above).
          // The request handler never builds (10ms cap), so this enqueue is
          // what keeps /api/v1/cve-digest from 503ing.
          try {
            if (env.FEEDS_QUEUE) {
              await env.FEEDS_QUEUE.send({ digestWarm: true });
              console.log(JSON.stringify({ job: 'cve-digest-enqueue', status: 'sent' }));
            } else {
              console.error(JSON.stringify({ job: 'cve-digest-enqueue', status: 'no_queue' }));
            }
          } catch (e) {
            logCronFail('cve-digest-enqueue')(e);
          }
          try {
            const warm = await warmRansomwareRecentCache(env as unknown as ApiEnv);
            console.log(JSON.stringify({ job: 'ransomware-recent-warm', count: warm.count, ok: warm.ok }));
          } catch (e) {
            logCronFail('ransomware-recent-warm')(e);
          }
          // PromptIntel IoPC taxonomy + health — 2 small upstream fetches,
          // same top-of-hour reasoning as the warms above (cheap, keeps the
          // /api/v1/promptintel/* handlers on cache hits).
          try {
            const warm = await warmPromptintelCache(env as unknown as ApiEnv);
            console.log(JSON.stringify({ job: 'promptintel-warm', ok: warm.ok, taxonomy: warm.taxonomy }));
          } catch (e) {
            logCronFail('promptintel-warm')(e);
          }

          // === Daily Briefs sync (every 6 hours) ==============================
          // Runs FIRST — the hourly pipeline exhausts the free-plan 50-subrequest
          // cap (Telegram + X + CyberPulse + CTI + phishing scan) before the old
          // position at the end, so the sync never fired. 3 fetches + KV writes
          // fit easily in a fresh budget.
          if (csNow.getUTCHours() % 6 === 0) {
            try {
              const { syncDailyBriefs } = await import('./lib/daily-briefs-sync');
              const result = await syncDailyBriefs(env as unknown as Parameters<typeof syncDailyBriefs>[0]);
              if (result.types.length > 0 || result.errors.length > 0) {
                console.log(
                  JSON.stringify({
                    job: 'daily-briefs-sync',
                    types: result.types,
                    errors: result.errors,
                  })
                );
              }
            } catch (e) {
              logCronFail('daily-briefs-sync')(e);
            }
          }

          // === Telegram leak scanning — FIRST, before anything else hits t.me ===
          // Telegram throttles repeated scrape bursts from the same egress IP. The
          // cache-warm below (it fetches /api/v1/telegram-feed) and the watched-
          // channel scrape also hit t.me, so running the feed scan here guarantees
          // it gets the first, un-throttled pass. Previously it ran LAST and found
          // ~0 new leaks every hour (only manual triggers — a single clean burst —
          // worked). Also placed ahead of the briefing-rebuild early-return below,
          // so a rebuild hour can't skip leak scanning entirely.
          // Hoisted so CyberPulse (below) can reuse this single Telegram fetch
          // instead of issuing a second t.me burst that gets throttled to 0.
          let telegramFeed: Awaited<ReturnType<typeof fetchTelegramFeed>> | undefined;
          try {
            if (env.BRIEFINGS_DB) {
              // Try Cache-API first (primed by previous route hits or gp:warm)
              const tgCacheKey = await getTelegramFeedCacheKey(env as unknown as ApiEnv);
              const tgCached = await caches.default.match(tgCacheKey);
              if (tgCached) {
                const cached = (await tgCached.json()) as TelegramFeedResponse;
                // Only use cache if it has items — stale empty cache means
                // t.me was blocked; force a direct fetch instead.
                if (cached?.items?.length) {
                  telegramFeed = cached;
                }
              }
              if (!telegramFeed) {
                // Fallback to gp:warm KV slice (written by queue consumer)
                const kvWarm = (
                  env.KV_CACHE ? await env.KV_CACHE.get('gp:warm:telegram', 'json') : null
                ) as TelegramFeedResponse | null;
                if (kvWarm?.items?.length) {
                  telegramFeed = kvWarm;
                }
              }
              if (!telegramFeed) {
                // Both cache and KV empty — fetch directly (uses telegram.me/s/)
                try {
                  telegramFeed = await fetchTelegramFeed(env.KV_CACHE, env as unknown as ApiEnv);
                } catch (e) {
                  console.warn(
                    JSON.stringify({
                      job: 'telegram-direct-fetch',
                      status: 'failed',
                      error: e instanceof Error ? e.message : String(e),
                    })
                  );
                }
              }
              if (telegramFeed?.items?.length) {
                const result = await runTelegramLeakScanner(env.BRIEFINGS_DB, telegramFeed.items);
                if (result.leaks_found > 0 || result.channels_discovered > 0) {
                  console.log(
                    JSON.stringify({
                      job: 'telegram-leak-scanner',
                      leaks_found: result.leaks_found,
                      channels_discovered: result.channels_discovered,
                    })
                  );
                }
              } else {
                // Logged unconditionally: "the scanner ran and matched nothing"
                // and "the scanner never ran" look identical from the outside,
                // which is how a dead leak pipeline stayed invisible for a week.
                console.warn(
                  JSON.stringify({
                    job: 'telegram-leak-scanner',
                    status: 'no_feed_items',
                    reason: 'cache, KV warm slice and direct fetch all returned zero items',
                  })
                );
              }
            }
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'telegram-leak-scanner',
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
          }

          // Watched-channel scrape runs right after, sharing one burst window
          // before the cache-warm fans out more t.me requests.
          // Every 3h (not hourly): each run issues up to 25 D1 UPDATEs even
          // when every channel returns 0 messages. Rotation via last_scraped
          // still covers the full list — just over 3h instead of 1h.
          try {
            if (env.BRIEFINGS_DB && csNow.getUTCHours() % 3 === 0) {
              const w = await scrapeWatchedChannels(env.BRIEFINGS_DB);
              if (w.channels_scraped > 0) {
                console.log(
                  JSON.stringify({
                    job: 'telegram-watched-scrape',
                    channels_scraped: w.channels_scraped,
                    channels_unreachable: w.channels_unreachable,
                    leaks_found: w.leaks_found,
                    channels_discovered: w.channels_discovered,
                  })
                );
              }
            }
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'telegram-watched-scrape',
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
          }

          // ── X auth + query-ID diagnostic ───────────────────────────────────
          // Live canary fetch each tick so expired cookies (auth=expired) and
          // rotated GraphQL query IDs (qids=stale) surface in the logs instead
          // of waiting for an analyst to notice dead feeds.
          try {
            const health = await checkXHealth(env);
            const healthy = health.auth === 'ok' && health.qids !== 'stale';
            const line = JSON.stringify({ job: 'x-health-diagnostic', ...health });
            if (healthy) console.log(line);
            else console.warn(line);
          } catch (e) {
            console.warn(
              JSON.stringify({
                job: 'x-health-diagnostic',
                status: 'error',
                reason: e instanceof Error ? e.message : String(e),
              })
            );
          }

          // ── Pre-warm x-claims so CyberPulse gets breach/ransomware claims
          // instead of doing its own GraphQL fetches for the 14 CTI handles.
          // Calls fetchXClaims DIRECTLY instead of going through the route
          // handler, avoiding the race between waitUntil cache write and
          // CyberPulse's synchronous cache read. The result is threaded into
          // runCyberPulseIngestion via prefetched.xClaimsBreach.
          let xClaimsBreach:
            Array<{ text: string; source_url: string; handle: string; discovered: string }> | undefined;
          try {
            const allClaims = await fetchXClaims(env);
            xClaimsBreach = allClaims.breach;
            console.log(
              JSON.stringify({
                job: 'cyberpulse-x-claims-warm',
                handles: allClaims.handles.length,
                ransomware: allClaims.ransomware.length,
                breach: allClaims.breach.length,
              })
            );
          } catch (e) {
            console.warn(JSON.stringify({ job: 'cyberpulse-x-claims-warm', error: String(e) }));
          }

          // ── CyberPulse: breach/leak incident ingestion from social media firehose
          // Runs after Telegram scan (shared burst window) but before cache-warm.
          // Monitors X accounts + keyword search for breaches/leaks/cybercrime.
          // X accounts and X search data are warmed by the */30 * * * * cron via
          // the queue consumer into `cp:warm:*` KV keys — reads from there instead
          // of doing GraphQL direct fetches, preserving the 50-subrequest budget
          // for the rest of the hourly pipeline.
          try {
            if (env.BRIEFINGS_DB) {
              // Read X accounts from KV (warmed by queue consumer).
              // Fail open: if the KV key is stale or missing, runCyberPulseIngestion
              // falls back to its own GraphQL fetches.
              let xAccountPosts: unknown[] | undefined;
              let socialItems: unknown[] | undefined;
              let redditItems: unknown[] | undefined;
              if (env.KV_CACHE) {
                // One bulk read for all three warm slices (was 3 separate gets).
                // Fail open: a missing/stale slice leaves its value undefined and
                // runCyberPulseIngestion falls back to its own GraphQL fetches.
                let warm = new Map<string, unknown>();
                try {
                  warm = await env.KV_CACHE.get(['cp:warm:x_accounts', 'gp:warm:x', 'gp:warm:reddit'], 'json');
                } catch {
                  /* fail open — CyberPulse falls back to direct GraphQL */
                }
                const xa = warm.get('cp:warm:x_accounts');
                if (Array.isArray(xa) && xa.length > 0) xAccountPosts = xa as unknown[];
                const gx = warm.get('gp:warm:x');
                if (gx && typeof gx === 'object' && 'items' in (gx as Record<string, unknown>)) {
                  socialItems = (gx as { items: unknown[] }).items;
                }
                if (!socialItems) {
                  try {
                    const sf = await fetchXFeed().catch(() => undefined);
                    socialItems = sf?.items as unknown[] | undefined;
                  } catch {
                    /* fail open */
                  }
                }
                const gr = warm.get('gp:warm:reddit');
                if (gr && typeof gr === 'object' && 'items' in (gr as Record<string, unknown>)) {
                  redditItems = (gr as { items: unknown[] }).items;
                }
                if (!redditItems) {
                  try {
                    const rf = await fetchRedditFeed(
                      env as unknown as { ASSETS: import('@cloudflare/workers-types').Fetcher }
                    ).catch(() => undefined);
                    redditItems = rf?.items as unknown[] | undefined;
                  } catch {
                    /* fail open */
                  }
                }
              }
              // The values above (socialItems / redditItems from the gp:warm slices)
              // are read and passed through HERE — the old `as undefined` casts
              // discarded the freshly-read X-feed + Reddit items, silently
              // disabling "keyword search" monitoring on the hourly tick (only
              // the */30 cron ingested them). runCyberPulseIngestion dedupes by
              // incident, so passing them is safe alongside the */30 run.
              const cpResults = await runCyberPulseIngestion(env, env.BRIEFINGS_DB, {
                telegramItems: telegramFeed?.items,
                socialItems: socialItems as unknown as CyberPulsePrefetch['socialItems'],
                redditItems: redditItems as unknown as CyberPulsePrefetch['redditItems'],
                xClaimsBreach,
                xAccountPosts: xAccountPosts as unknown as CyberPulsePrefetch['xAccountPosts'],
              });
              const totalCreated = cpResults.reduce((s, r) => s + r.incidents_created, 0);
              const totalDeduped = cpResults.reduce((s, r) => s + r.incidents_deduped, 0);
              console.log(
                JSON.stringify({
                  job: 'cyberpulse-ingest',
                  incidents_created: totalCreated,
                  incidents_deduped: totalDeduped,
                  sources: cpResults.map((r) => ({
                    source: r.source,
                    items_scanned: r.items_scanned,
                    created: r.incidents_created,
                    deduped: r.incidents_deduped,
                    errors: r.errors.length,
                    duration_ms: r.duration_ms,
                  })),
                })
              );
            }
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'cyberpulse-ingest',
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
          }

          // === Briefing self-heal (hourly) ================================
          // Check if expected briefings exist. Runs BEFORE the heavy I/O
          // below (fire-and-forget publisher, telegram-archive, intel-bundle
          // warm, CTI collector, cache-warm fan-out).
          //
          // SUBREQUEST-BUDGET GUARD: the daily heal runs the FULL live fan-out
          // (NVD pagination + up to 15 individual CVE lookups + KEV + 4 IOC
          // feeds + ransomware + MTI + cvefeed + webamon + OSSF commits +
          // LLM ≈ 35-45 subrequests). The hourly invocation ALSO runs
          // warmIntelBundles (up to 35) + runFullCollection (7-10) + publisher
          // + telegram + watches in the SAME Worker invocation, all sharing
          // the free-plan 50-subrequest cap. Running both blew the cap →
          // "Too many subrequests by single Worker invocation" aborted the
          // whole invocation and no row was persisted.
          //
          // Fix: when the daily heal actually rebuilds (live fan-out), set
          // `dailyHealRan` and SKIP warmIntelBundles + runFullCollection in
          // this invocation. Both have their own cadence (intel-bundle-warm
          // is also on a dedicated `7 * * * *` cron; CTI collector catches
          // up next hour) so skipping one hourly tick loses no data, but it
          // keeps the daily heal's fan-out inside the 50-subrequest budget.
          // The weekly heal short-circuits via the D1 rollup (≈0 subrequests)
          // so it never trips this guard.
          //
          // Key difference from the old heal: we check the EXPECTED slug
          // by name, not just the latest row by type. The old code queried
          // "most recent weekly" which always returned W26 (rich+complete)
          // even when W27 was missing entirely, so the heal never fired.
          let dailyHealRan = false;
          if (db) {
            try {
              const now = new Date();
              const anchor = now;
              const weeklySlug = expectedWeeklySlug(anchor);
              const weeklyRow = await db
                .prepare('SELECT stats_json, body FROM briefings WHERE slug = ?')
                .bind(weeklySlug)
                .first<{ stats_json?: string | null; body?: string | null }>();
              if (briefingNeedsHeal(weeklyRow, { now: now.getTime(), cooldownMs: 30 * 60_000 })) {
                console.log(
                  JSON.stringify({ job: 'briefing-heal', type: 'weekly', slug: weeklySlug, status: 'rebuilding' })
                );
                const briefing = await buildBriefing('weekly', undefined, {
                  nvdApiKey: env.NVD_API_KEY,
                  env: env as unknown as ApiEnv,
                });
                const w = await writeBriefing(db, briefing);
                console.log(
                  JSON.stringify({
                    job: 'briefing-heal',
                    type: 'weekly',
                    slug: briefing.slug,
                    written: w.written,
                    reason: w.reason,
                    findings: briefing.stats.findings,
                    iocs: briefing.stats.iocs,
                  })
                );
              }
              // ── Yesterday's daily ─────────────────────────────────────────
              // The heal above only ever builds `daily-<today>` (the live
              // 24h-to-now window). `GET /api/v1/briefings/today` — the card on
              // the threat-intel front page — serves `daily-<yesterday>`, which
              // is written ONLY by the dedicated 30 00 * * * cron. So a single
              // missed night left that slug absent forever: the page 404'd with
              // "not yet generated" and nothing in the hourly job ever looked
              // for it. Repaired here only when the row is actually missing, so
              // the steady-state cost is one extra indexed SELECT and the
              // fan-out is paid only when a night was genuinely dropped.
              const yesterdaySlug = `daily-${isoDate(new Date(now.getTime() - 86400_000))}`;
              const yesterdayRow = await db
                .prepare('SELECT slug FROM briefings WHERE slug = ?')
                .bind(yesterdaySlug)
                .first<{ slug: string }>();
              if (!yesterdayRow) {
                console.warn(
                  JSON.stringify({
                    job: 'briefing-heal',
                    type: 'daily',
                    slug: yesterdaySlug,
                    status: 'rebuilding-missing',
                    reason: 'the 00:30 dedicated build did not produce this row',
                  })
                );
                // buildBriefing fans out to ~10 upstreams and makes up to 15
                // individual NVD lookups. On the free plan that can exceed the
                // 50-subrequest cap, which throws. This block used to be
                // unguarded, so the throw propagated out of the waitUntil and
                // the failure was never logged anywhere - the briefing simply
                // stopped appearing and nothing said why. Catch it, name the
                // cause, and let the rest of the hourly job continue.
                let briefing;
                try {
                  briefing = await buildBriefing('daily', undefined, {
                    nvdApiKey: env.NVD_API_KEY,
                    env: env as unknown as ApiEnv,
                  });
                } catch (e) {
                  console.error(
                    JSON.stringify({
                      job: 'briefing-heal',
                      type: 'daily',
                      slug: yesterdaySlug,
                      status: 'build-failed',
                      error: e instanceof Error ? e.message : String(e),
                    })
                  );
                  throw e;
                }
                const w = await writeBriefing(db, briefing);
                console.log(
                  JSON.stringify({
                    job: 'briefing-heal',
                    type: 'daily',
                    slug: briefing.slug,
                    written: w.written,
                    reason: w.reason,
                    findings: briefing.stats.findings,
                    iocs: briefing.stats.iocs,
                  })
                );
              }
              const dailySlug = `daily-${isoDate(now)}`;
              const dailyRow = await db
                .prepare('SELECT stats_json, body FROM briefings WHERE slug = ?')
                .bind(dailySlug)
                .first<{ stats_json?: string | null; body?: string | null }>();
              if (briefingNeedsHeal(dailyRow, { now: now.getTime(), cooldownMs: 30 * 60_000 })) {
                console.log(
                  JSON.stringify({ job: 'briefing-heal', type: 'daily', slug: dailySlug, status: 'rebuilding' })
                );
                const briefing = await buildBriefing('daily', undefined, {
                  nvdApiKey: env.NVD_API_KEY,
                  env: env as unknown as ApiEnv,
                  live: true,
                });
                await writeBriefing(db, briefing);
                dailyHealRan = true;
                console.log(
                  JSON.stringify({
                    job: 'briefing-heal',
                    type: 'daily',
                    slug: briefing.slug,
                    findings: briefing.stats.findings,
                    iocs: briefing.stats.iocs,
                  })
                );
              }
            } catch (e) {
              console.error(
                JSON.stringify({
                  job: 'briefing-heal',
                  status: 'failed',
                  error: e instanceof Error ? e.message : String(e),
                })
              );
            }
          }
          if (dailyHealRan) {
            console.log(
              JSON.stringify({
                job: 'briefing-heal',
                status: 'skipped-cotenants',
                reason:
                  'daily heal ran live fan-out; skipping intel-bundle-warm + cti-collector this tick to stay under the 50-subrequest cap',
              })
            );
          }

          // ── Hourly subrequest-budget planner ─────────────────────────────
          // The free plan caps EVERY invocation at 50 subrequests. Heavy
          // optional tenants used to gate only on `dailyHealRan`, so on a
          // normal hour the tail stages (phishing-scan, rag-reindex, …)
          // threw "Too many subrequests" and were silently lost. This
          // planner admits stages greedily against ESTIMATED costs (tuned
          // to typical runs, not worst case) so deferrals are deterministic,
          // ordered, and logged. Every deferred stage is periodic and
          // catches up next hour.
          const BUDGET_SOFT_CAP = 48; // 50 cap minus safety margin
          const PREFIX_EST = 8; // daily-briefs top block + tg/x/reddit enqueues (+ heal fan-out below)
          let estUsed = PREFIX_EST + (dailyHealRan ? 20 : 0);
          const canSpend = (cost: number): boolean => estUsed + cost <= BUDGET_SOFT_CAP;
          const spend = (cost: number): void => {
            estUsed += cost;
          };
          const deferred: string[] = [];
          const admitted: string[] = [];

          const hour = csNow.getUTCHours();
          // Priority order matters: phishing-scan only fits when nothing
          // heavy has committed yet, so admit it before intel-bundle-warm.
          let runPhishing = hour % 6 === 0;
          if (runPhishing) {
            if (canSpend(35)) {
              spend(35);
              admitted.push('phishing-scan');
            } else {
              runPhishing = false;
              deferred.push('phishing-scan');
            }
          }

          const runReleaks = hour % 6 === 3;
          if (runReleaks) {
            if (canSpend(4)) {
              spend(4);
              admitted.push('victim-releaks');
            } else {
              deferred.push('victim-releaks');
            }
          }

          const runGhsa = hour % 6 === 4;
          if (runGhsa) {
            if (canSpend(6)) {
              spend(6);
              admitted.push('github-security-sync');
            } else {
              deferred.push('github-security-sync');
            }
          }

          let runRag = hour % 6 === 2;
          if (runRag) {
            if (canSpend(6)) {
              spend(6);
              admitted.push('rag-reindex');
            } else {
              runRag = false;
              deferred.push('rag-reindex');
            }
          }

          const runBundles = !dailyHealRan && !runPhishing && canSpend(25);
          if (runBundles) {
            spend(25);
            admitted.push('intel-bundle-warm');
          } else deferred.push('intel-bundle-warm');

          // CTI ingestion runs 4x/day (01, 07, 13, 19 UTC) instead of hourly:
          // IOC value doesn't need hourly re-ingestion (upstreams are feeds,
          // half-lives are 5-30d; SwiftIOC itself collects 4-hourly), and each
          // run costs ~1k D1 writes. Hour%6==1 is free of the other 6h tenants
          // (phishing %6==0, rag %6==2, releaks %6==3, ghsa %6==4).
          const runCti =
            !!env.BRIEFINGS_DB && !dailyHealRan && !runPhishing && csNow.getUTCHours() % 6 === 1 && canSpend(8);
          if (runCti) {
            spend(8);
            admitted.push('cti-collector');
          } else deferred.push('cti-collector');

          console.log(
            JSON.stringify({
              job: 'subrequest-budget',
              estimated_used: estUsed,
              soft_cap: BUDGET_SOFT_CAP,
              admitted,
              deferred: deferred.length > 0 ? deferred : undefined,
            })
          );

          // ── Case-study publisher + Telegram archive + intel-bundle warm ─────
          // These were previously in a separate `0 * * * *` block with a shared
          // lease but no coordination — merged here so one lease + one heartbeat
          // covers all hourly work.
          const fireAndForget: Promise<unknown>[] = [];
          // enqueueGpFeeds moved to the TOP of this hourly handler — it must land
          // before the pipeline exhausts the subrequest cap (see above).
          fireAndForget.push(runPublisherNow(env as unknown as CaseStudyEnv, csNow).catch(logCronFail('publisher')));
          // Drip auto-post tick: releases approved + due X/LinkedIn posts at the
          // configured rate. No-op unless SOCIAL_AUTOPOST_ENABLED === 'true'.
          fireAndForget.push(
            runSocialAutopostNow(env as unknown as CaseStudyEnv, csNow).catch(logCronFail('social-autopost'))
          );
          // Refresh tweet engagement metrics for recent posts (analytics loop).
          fireAndForget.push(
            refreshSocialMetricsNow(env as unknown as CaseStudyEnv, csNow).catch(logCronFail('social-metrics'))
          );
          fireAndForget.push(runTelegramArchive(env as unknown as ApiEnv).catch(logCronFail('telegram-archive')));
          // enqueueAllFeeds moved to the TOP of this hourly handler (see above).
          // intel-bundle-warm is subrequest-heavy (up to 35). The budget
          // planner above admits it only when the tick can afford it (the
          // daily briefing heal fan-out and phishing-scan hours defer it).
          // It also has its own dedicated `7 * * * *` cron, so skipping one
          // hourly tick loses no data — it catches up next hour.
          if (runBundles) {
            fireAndForget.push(
              warmIntelBundles(env as unknown as ApiEnv)
                .then((r) =>
                  console.log(
                    JSON.stringify({
                      job: 'intel-bundle-warm',
                      built: r.built.length,
                      failed: r.failed.length,
                      has_more: r.hasMore,
                      slugs: r.built,
                      llm_ran: r.llmRan,
                      llm_partial: r.llmPartial,
                    })
                  )
                )
                .catch(logCronFail('intel-bundle-warm'))
            );
          }
          if (runReleaks) {
            fireAndForget.push(
              refreshVictimReleaksCache(env as unknown as ApiEnv)
                .then((b) =>
                  console.log(
                    JSON.stringify({
                      job: 'victim-releaks-refresh',
                      releaks: b.releaks.length,
                      groups: b.groups_scanned,
                      warnings: b.warnings.length,
                    })
                  )
                )
                .catch(logCronFail('victim-releaks-refresh'))
            );
          }
          // GitHub Security Advisories — pre-warm KV once every 6h so
          // the listing page reads from cache, never from the request
          // path. The previous design called GitHub live on every
          // request and was blocked by the 60 req/hr unauthenticated
          // limit on Cloudflare's shared egress IP. Hour 4 of the
          // 6h cycle (UTC: 04, 10, 16, 22) is intentionally offset
          // from the victim-releaks hour so the two upstream calls
          // don't share a burst window. Skip if the meta says we
          // already have a fresh write — protects the per-IP budget
          // even if the cron fires on a non-divisible-by-6 hour
          // (e.g. retry, manual trigger, hourly override).
          if (runGhsa) {
            fireAndForget.push(
              (async (): Promise<void> => {
                if (!env.KV_CACHE) return;
                const raw = await env.KV_CACHE.get(GHSA_META_KV_KEY, 'text');
                if (raw) {
                  try {
                    const meta = JSON.parse(raw) as {
                      ok?: boolean;
                      fetchedAt?: string;
                    };
                    const ageMs = meta.fetchedAt ? Date.now() - Date.parse(meta.fetchedAt) : Infinity;
                    if (meta.ok && Number.isFinite(ageMs) && ageMs < GHSA_FRESH_TTL_S * 1000) {
                      return;
                    }
                  } catch {
                    /* fall through to sync */
                  }
                }
                const r = await syncGitHubAdvisories(env as unknown as ApiEnv);
                console.log(
                  JSON.stringify({
                    job: 'github-security-sync',
                    ok: r.ok,
                    total: r.total,
                    status: r.status,
                    rate_limited: r.rateLimited,
                    error: r.error,
                  })
                );
              })().catch(logCronFail('github-security-sync'))
            );
          }
          await Promise.allSettled(fireAndForget);

          // ── CTI Collector: automated IOC + news ingestion (4x daily) ──────
          // Skipped this tick when the daily briefing heal just ran its live
          // fan-out in this same invocation — runFullCollection makes 7-10
          // upstream fetches (threatfox, urlhaus, malwarebazaar, feodo, sslbl,
          // openphish, cisa_kev, news feeds) and would push the combined
          // subrequest count past the free-plan 50 cap. It catches up next
          // run; no data is lost.
          // D1: decay/sweep/job-log maintenance runs once daily (01 UTC, on
          // the first ingestion tick) — hourly maintenance was ~4k wasted
          // writes + full-table scans/day for slow-moving (5-30d half-life)
          // data.
          try {
            if (env.BRIEFINGS_DB && runCti) {
              const ctiResult = await runFullCollection(env.BRIEFINGS_DB, env.ABUSECH_AUTH_KEY, {
                maintenance: csNow.getUTCHours() === 1,
              });
              console.log(
                JSON.stringify({
                  job: 'cti-collector',
                  iocs_stored: ctiResult.iocs_stored,
                  news_stored: ctiResult.news_stored,
                  sources: `${ctiResult.sources_succeeded}/${ctiResult.sources_attempted}`,
                  duration_ms: ctiResult.duration_ms,
                  errors: ctiResult.errors.length,
                })
              );
            }
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'cti-collector',
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
          }

          // (Cache-warm fan-out removed: routes cache on first real visit, which
          // is more reliable than warming 26 endpoints within the 10ms CPU budget.)

          // === Watch engine ===
          if (db) {
            try {
              const watchAlerts = await checkWatches(db, new Date().toISOString());
              if (watchAlerts.length > 0) {
                console.log(
                  JSON.stringify({
                    job: 'watch-engine',
                    triggered: watchAlerts.length,
                    alerts: watchAlerts.map((a) => ({ label: a.label, type: a.type, match: a.match })),
                  })
                );
              }
            } catch (e) {
              console.error(JSON.stringify({ job: 'watch-engine', error: e instanceof Error ? e.message : String(e) }));
            }
          }

          // === Crypto address monitor (Phase E) ===
          if (db) ctx.waitUntil(checkAddressWatches(new Date().toISOString(), db).catch(logCronFail('crypto-monitor')));

          // === IOC Watchlist sweep ===
          if (db)
            ctx.waitUntil(
              sweepWatchlist(db, new Date().toISOString())
                .then((r) => {
                  if (r.alerts > 0 || r.errors.length > 0) {
                    console.log(
                      JSON.stringify({
                        job: 'ioc-watchlist-sweep',
                        checked: r.checked,
                        alerts: r.alerts,
                        errors: r.errors.length,
                      })
                    );
                  }
                })
                .catch(logCronFail('ioc-watchlist-sweep'))
            );

          // === Breach-forum status snapshot (write-on-change + 6h heartbeat) ===
          // Was: unconditional hourly INSERT of every forum row (~30-80 rows ×
          // 24 = up to ~2k writes/day + 3 DDLs). Now: diff against the latest
          // snapshot and skip the D1 batch when nothing changed. A 6h
          // heartbeat write keeps history continuity for the deltas route.
          // Saves ~75-85% of this table's writes with zero signal loss —
          // the change ITSELF is the signal (see breach-forum-status.ts).
          try {
            if (env.BRIEFINGS_DB) {
              const ddc = await buildDeepDarkCti(env.KV_CACHE, ctx);
              const curated = getCuratedForums();
              const observedAt = new Date().toISOString();
              const snapshot = buildStatusSnapshot(ddc, curated, observedAt);
              const prev = await readLatestSnapshot(env.BRIEFINGS_DB as D1Database).catch(() => null);
              const deltas = prev ? computeStatusDeltas(prev, snapshot) : [];
              const prevMs = prev ? Date.parse(prev.observed_at) : NaN;
              const ageHrs = Number.isFinite(prevMs) ? (Date.parse(observedAt) - prevMs) / 3_600_000 : Infinity;
              const shouldWrite = !prev || deltas.length > 0 || ageHrs >= 6;
              if (shouldWrite) {
                await upsertStatusSnapshot(env.BRIEFINGS_DB as D1Database, snapshot);
              }
              console.log(
                JSON.stringify({
                  job: 'breach-forum-status-snapshot',
                  rows: snapshot.rows.length,
                  deltas: deltas.length,
                  written: shouldWrite,
                  ddc_entries: ddc.entries.filter((e) => /^(Criminal Forums|Dark Markets)$/i.test(e.category)).length,
                  curated_entries: curated.length,
                })
              );
            }
          } catch (e) {
            logCronFail('breach-forum-status-snapshot')(e);
          }

          // === Daily leak entry cleanup (6am UTC) ===
          if (csNow.getUTCHours() === 6) {
            try {
              if (env.BRIEFINGS_DB) {
                const deleted = await cleanupLeakEntries(env.BRIEFINGS_DB, 7);
                if (deleted > 0) {
                  console.log(JSON.stringify({ job: 'leak-cleanup', deleted }));
                }
              }
            } catch (e) {
              console.error(JSON.stringify({ job: 'leak-cleanup', error: e instanceof Error ? e.message : String(e) }));
            }
          }

          // === Daily blocklist build (6am UTC) ===
          if (csNow.getUTCHours() === 6) {
            try {
              const bl = await buildBlocklists(env.KV_CACHE);
              console.log(
                JSON.stringify({
                  job: 'blocklist-build',
                  ip_count: bl.ip_count,
                  generated_at: bl.generated_at,
                  pfsense_bytes: bl.pfsense.length,
                  iptables_bytes: bl.iptables.length,
                  suricata_bytes: bl.suricata.length,
                })
              );
            } catch (e) {
              console.error(
                JSON.stringify({
                  job: 'blocklist-build',
                  status: 'failed',
                  error: e instanceof Error ? e.message : String(e),
                })
              );
            }
          }

          // === PIR-level collection health alerts (every hour) ===
          try {
            const pirResult = await detectPirAlerts(env as unknown as ApiEnv);
            if (pirResult.alerts.length > 0) {
              console.log(
                JSON.stringify({
                  job: 'pir-alert-check',
                  pirs_checked: pirResult.total,
                  alerts: pirResult.alerts.length,
                  critical: pirResult.alerts.filter((a) => a.severity === 'critical').length,
                })
              );
            }
          } catch (e) {
            console.error(
              JSON.stringify({ job: 'pir-alert-check', error: e instanceof Error ? e.message : String(e) })
            );
          }

          // === Graph ingestion (daily at 2am UTC) ===
          if (csNow.getUTCHours() === 2) {
            // Guard hoisted OUT of the try: a missing db must skip ONLY graph-ingest,
            // not `return` from the whole hourly IIFE (which previously skipped
            // feed-scheduler, rag-reindex, infra-scan, AND the retention sweep).
            if (!db) {
              console.warn(JSON.stringify({ job: 'graph-ingest', status: 'skipped', reason: 'no db bound' }));
            } else {
              try {
                const gResult = await runGraphIngest(db, 'all', env as never);
                console.log(
                  JSON.stringify({
                    job: 'graph-ingest',
                    nodes_upserted: gResult['threat-intel']?.nodes_upserted ?? 0,
                    edges_created: gResult['threat-intel']?.edges_created ?? 0,
                    per_source: Object.fromEntries(
                      Object.entries(gResult).map(([k, v]) => [
                        k,
                        { n: v.nodes_upserted, e: v.edges_created, err: v.errors.length },
                      ])
                    ),
                  })
                );
              } catch (e) {
                logCronFail('graph-ingest')(e);
              }
            }
          }

          // === Auto-run due feed jobs (every hour, 1 job max) ===
          try {
            if (env.KV_CACHE && db) {
              const fr = await autoRunFeedJobs(db);
              if (fr.ran > 0) {
                console.log(
                  JSON.stringify({ job: 'feed-scheduler-auto', ran: fr.ran, saved: fr.saved, skipped: fr.skipped })
                );
              }
            }
          } catch (e) {
            logCronFail('feed-scheduler-auto')(e);
          }

          // === RAG corpus re-index (every 6h, budget-permitted) ===
          if (runRag) {
            try {
              // Independent indexers — run concurrently instead of chaining the
              // two awaits (the catch below still fails the whole job on either).
              const [telegram, corpora] = await Promise.all([
                indexTelegramLeaks(env as unknown as ApiEnv),
                indexAllCorpora(env as unknown as ApiEnv),
              ]);
              const totalIndexed =
                telegram.indexed +
                corpora.cve.indexed +
                corpora.actor_kb.indexed +
                corpora.ransomware.indexed +
                corpora.breach.indexed;
              console.log(
                JSON.stringify({
                  job: 'rag-reindex',
                  telegram_leaks: telegram.indexed,
                  cve: corpora.cve.indexed,
                  actor_kb: corpora.actor_kb.indexed,
                  ransomware: corpora.ransomware.indexed,
                  breach: corpora.breach.indexed,
                  total_indexed: totalIndexed,
                  errors:
                    telegram.errors +
                    corpora.cve.errors +
                    corpora.actor_kb.errors +
                    corpora.ransomware.errors +
                    corpora.breach.errors,
                })
              );
            } catch (e) {
              logCronFail('rag-reindex')(e);
            }
          }

          // === Infrastructure Scan (merged into hourly cron) ===
          // Scans known open directories and C2 infrastructure every hour.
          // Results are cached in KV for the Open Directory Scanner tool.
          // Runs at :15 past the hour to avoid colliding with other jobs.
          try {
            const baseUrl = (env as unknown as { SITE_URL?: string }).SITE_URL ?? 'https://pranithjain.qzz.io';
            const infraTargets = [
              'http://malware-traffic-analysis.net/',
              'http://cybercrime-tracker.net/',
              'http://tracker.h3x.eu/',
            ];
            type InfraResult = { url: string; status: number; files: number; risk: string };
            // Scan the 3 targets concurrently — each is an independent subrequest
            // and per-target failures were already swallowed, so allSettled fits.
            const settled = await Promise.allSettled(
              infraTargets.map(async (target): Promise<InfraResult | null> => {
                const req = new Request(baseUrl + '/api/v1/open-dir/scan', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ url: target }),
                });
                const res = await apiApp.fetch(req, env as never, ctx);
                if (!res.ok) return null;
                const data = (await res.json()) as { totalFiles?: number; indicators?: string[] };
                return {
                  url: target,
                  status: res.status,
                  files: data.totalFiles ?? 0,
                  risk: (data.indicators?.length ?? 0) > 0 ? 'flagged' : 'clean',
                };
              })
            );
            const infraResults: InfraResult[] = settled.flatMap((r) =>
              r.status === 'fulfilled' && r.value ? [r.value] : []
            );
            if (infraResults.length > 0) {
              console.log(
                JSON.stringify({
                  job: 'infra-scan',
                  targets_scanned: infraResults.length,
                  results: infraResults,
                })
              );
            }
          } catch (e) {
            logCronFail('infra-scan')(e);
          }

          // === 30-day data retention sweep (daily at 6am UTC) ===
          // Runs once daily instead of hourly — the sweep is a no-op most
          // runs (no rows past 30d yet) but guarantees the data-minimization
          // policy is enforced.
          if (csNow.getUTCHours() === 6) {
            try {
              const db = env.BRIEFINGS_DB as D1Database;
              const result = await runRetentionSweep(db);
              if (result.total_deleted > 0) {
                console.log(
                  JSON.stringify({
                    job: 'retention-sweep',
                    deleted: result.total_deleted,
                    tables_swept: result.tables_swept,
                    duration_ms: result.duration_ms,
                    days: result.days,
                  })
                );
              }
            } catch (e) {
              logCronFail('retention-sweep')(e);
            }
          }

          // === Phishing scan (every 6 hours, at 0, 6, 12, 18 UTC) ===
          // Admitted first by the budget planner — at up to ~50 DNS/VT
          // lookups it needs a mostly-empty invocation to fit the cap.
          if (runPhishing) {
            try {
              if (db) {
                const dnsEnv: PassiveDnsEnv = {
                  VT_API_KEY: env.VT_API_KEY,
                  URLSCAN_API_KEY: env.URLSCAN_API_KEY,
                };
                const result = await scanForPhishingDomains(db, dnsEnv, { maxDomains: 50, lookbackHours: 6 });
                if (result.new_phishing.length > 0 || result.errors.length > 0) {
                  console.log(
                    JSON.stringify({
                      job: 'phishing-scan',
                      scanned: result.scanned,
                      new_phishing: result.new_phishing.length,
                      domains: result.new_phishing.map((p) => ({
                        domain: p.domain,
                        ip: p.resolved_ip,
                        sources: p.sources,
                      })),
                      errors: result.errors.length,
                      duration_ms: result.scan_time_ms,
                    })
                  );
                }
              }
            } catch (e) {
              logCronFail('phishing-scan')(e);
            }
          }

          // (Daily Briefs sync moved to the TOP of this hourly handler —
          // the pipeline exhausts the 50-subrequest free-plan cap before
          // reaching this point, so it never fired here.)
        } finally {
          clearInterval(heartbeatInt);
        }
      })()
        .catch(logCronFail('hourly-cron'))
        .finally(releaseLease)
        .then(() => logCronDone({ path: 'hourly' }))
    );
    return;
  }

  // === Curated-landscape sync (OWASP AI + start.me toolbox) ===
  // PIGGYBACKS on the daily briefing cron ("30 0 * * *") — the free plan
  // caps cron triggers at 5, and we already have 5 distinct expressions.
  // Runs in parallel with the briefing build via Promise.allSettled so a
  // sync failure or upstream 5xx can never block the briefing pipeline.
  // Each sub-sync is bounded by FETCH_TIMEOUT_MS (20s) and writes to
  // KV_CACHE; the GET endpoints serve the latest snapshot. Sub-sync
  // failures are non-fatal: the GET handler falls back to the bundled
  // seed, and meta carries the error string for the UI badge.
  const runLandscapeSync = (): Promise<void> =>
    Promise.allSettled([
      syncOwaspAiLandscape(env as unknown as ApiEnv).then((o) => {
        console.log(
          JSON.stringify({
            job: 'landscape-owasp',
            ok: o.ok,
            error: o.error,
            counts: o.counts,
          })
        );
      }),
      syncCuratedToolbox(env as unknown as ApiEnv).then((c) => {
        console.log(
          JSON.stringify({
            job: 'landscape-curated',
            ok: c.ok,
            error: c.error,
            totalTools: c.totalTools,
            totalSections: c.totalSections,
          })
        );
      }),
      syncCuratedCerts(env as unknown as ApiEnv).then((c) => {
        console.log(
          JSON.stringify({
            job: 'landscape-certs',
            ok: c.ok,
            error: c.error,
            totalTools: c.totalTools,
            totalSections: c.totalSections,
          })
        );
      }),
    ]).then((results) => {
      const labels = ['landscape-owasp', 'landscape-curated', 'landscape-certs'];
      results.forEach((r, i) => {
        if (r.status === 'rejected') {
          logCronFail(labels[i] ?? `landscape-${i}`)(r.reason);
        }
      });
    });

  // ── CyberPulse source warm + live ingestion (every 30 min) ──────────────
  // Enqueues queue messages for X accounts and X search (each gets its own
  // 50-subrequest budget in the queue consumer). Also enqueues gp:warm messages
  // for Bluesky/X-feed and Reddit. After enqueue, reads warmed data from KV
  // (or falls back to direct fetch) and runs the full ingestion pipeline so
  // incidents appear every 30 min, not just hourly.
  if (cron === '*/30 * * * *') {
    ctx.waitUntil(
      (async () => {
        const queue = env.FEEDS_QUEUE;
        // ── Enqueue X warm messages ──
        if (queue) {
          try {
            await queue.sendBatch([
              { body: { cp: { type: 'x_accounts' } }, delaySeconds: 0 },
              { body: { gp: { key: 'x', path: '/api/v1/x-feed' } }, delaySeconds: 2 },
              { body: { gp: { key: 'reddit', path: '/api/v1/reddit-feed' } }, delaySeconds: 4 },
            ]);
            console.log(
              JSON.stringify({
                job: 'cp-30-enqueue',
                sources: ['x_accounts', 'gp:x', 'gp:reddit'],
                ok: true,
              })
            );
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'cp-30-enqueue',
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
          }
        } else {
          console.warn(JSON.stringify({ job: 'cp-30-enqueue', status: 'no_queue' }));
        }

        // ── Telegram Bot API poll ──
        const tgToken = (env as unknown as Record<string, unknown>).TELEGRAM_BOT_TOKEN as string | undefined;
        if (!tgToken) {
          console.warn(JSON.stringify({ job: 'tg-bot-poll', status: 'skipped', reason: 'TELEGRAM_BOT_TOKEN not set' }));
        } else {
          try {
            await pollBotUpdates(env as unknown as ApiEnv);
          } catch (e) {
            console.error(
              JSON.stringify({
                job: 'tg-bot-poll',
                status: 'failed',
                error: e instanceof Error ? e.message : String(e),
              })
            );
          }
        }

        // ── Inline ingestion: read from KV and produce incidents ────────────
        if (!env.KV_CACHE || !env.BRIEFINGS_DB) {
          console.warn(JSON.stringify({ job: 'cp-30-ingest', status: 'skipped', reason: 'missing bindings' }));
          return;
        }
        try {
          let xAccountPosts: unknown[] | undefined;
          let socialItems: unknown[] | undefined;
          let redditItems: unknown[] | undefined;
          let telegramItems: unknown[] | undefined;

          // KV-only reads — no direct fetches (preserves subrequest budget).
          // Queue consumer (gp:warm / cp:warm) writes these keys before the
          // cron reads them; if a key is cold it's skipped with a warning.
          // One bulk read for all four warm slices (was 4 separate gets).
          let warm = new Map<string, unknown>();
          try {
            warm = await env.KV_CACHE.get(
              ['cp:warm:x_accounts', 'gp:warm:x', 'gp:warm:reddit', 'gp:warm:telegram'],
              'json'
            );
          } catch {
            /* fail open */
          }
          try {
            const raw = warm.get('cp:warm:x_accounts');
            if (Array.isArray(raw) && raw.length > 0) xAccountPosts = raw as unknown[];
          } catch {
            /* fail open */
          }
          try {
            const raw = warm.get('gp:warm:x');
            if (raw && typeof raw === 'object' && 'items' in (raw as Record<string, unknown>)) {
              const items = (raw as { items: unknown[] }).items;
              if (items.length > 0) {
                socialItems = items;
                console.log(JSON.stringify({ job: 'cp-30-social', status: 'kv_hit', count: items.length }));
              }
            }
            if (!socialItems) {
              console.warn(JSON.stringify({ job: 'cp-30-social', status: 'kv_miss', reason: 'gp:warm:x cold' }));
            }
          } catch {
            /* fail open */
          }
          try {
            const raw = warm.get('gp:warm:reddit');
            if (raw && typeof raw === 'object' && 'items' in (raw as Record<string, unknown>)) {
              const items = (raw as { items: unknown[] }).items;
              if (items.length > 0) {
                redditItems = items;
                console.log(JSON.stringify({ job: 'cp-30-reddit', status: 'kv_hit', count: items.length }));
              }
            }
            if (!redditItems) {
              console.warn(JSON.stringify({ job: 'cp-30-reddit', status: 'kv_miss', reason: 'gp:warm:reddit cold' }));
            }
          } catch {
            /* fail open */
          }
          try {
            const kvTg = warm.get('gp:warm:telegram') as TelegramFeedResponse | null;
            if (kvTg?.items?.length) {
              telegramItems = kvTg.items;
              console.log(JSON.stringify({ job: 'cp-30-telegram', status: 'kv_hit', count: telegramItems.length }));
            } else {
              console.warn(
                JSON.stringify({ job: 'cp-30-telegram', status: 'kv_miss', reason: 'gp:warm:telegram cold or empty' })
              );
            }
          } catch {
            /* fail open */
          }

          const cpResults = await runCyberPulseIngestion(env, env.BRIEFINGS_DB, {
            telegramItems: telegramItems as unknown as CyberPulsePrefetch['telegramItems'],
            socialItems: socialItems as unknown as CyberPulsePrefetch['socialItems'],
            redditItems: redditItems as unknown as CyberPulsePrefetch['redditItems'],
            xAccountPosts: xAccountPosts as unknown as CyberPulsePrefetch['xAccountPosts'],
          });
          const totalCreated = cpResults.reduce((s, r) => s + r.incidents_created, 0);
          console.log(
            JSON.stringify({
              job: 'cp-30-ingest',
              incidents_created: totalCreated,
              sources: cpResults.map((r) => ({
                source: r.source,
                items_scanned: r.items_scanned,
                created: r.incidents_created,
                deduped: r.incidents_deduped,
                errors: r.errors.length,
              })),
            })
          );
        } catch (e) {
          console.error(
            JSON.stringify({
              job: 'cp-30-ingest',
              status: 'failed',
              error: e instanceof Error ? e.message : String(e),
            })
          );
        }

        // ── Global-pulse cache rebuild ──────────────────────────────────
        // The GlobalPulse DO only READS the cache (Cache API + KV fallback);
        // it never triggers a rebuild. Without a visitor hitting
        // /api/v1/global-pulse, the cache goes cold (Cache API 300s, KV 2h)
        // and the live WS feed goes stale ("2 hours ago"). This rebuilds the
        // cache every 30 min from the cron-warmed gp:warm:* slices so the
        // DO always has fresh data to broadcast, independent of traffic.
        //
        // IN-PROCESS dispatch, not env.SELF.fetch: a self fetch spawns a
        // stateless Worker invocation under the free-plan 10ms CPU cap, and
        // the handler's 41 KV-slice reads + JSON.parse blow that cap
        // (`exceededCpu`). Dispatching through apiApp.fetch runs the handler
        // inside this DO alarm with its 30s CPU budget — same pattern as the
        // the infra-scan block and the queue consumer's gp-warm slices.
        try {
          const tokenSecret = (env as unknown as { INTERNAL_TOKEN_SECRET?: string }).INTERNAL_TOKEN_SECRET;
          if (tokenSecret && env.SELF) {
            const token = await signInternalToken('cron', tokenSecret);
            const res = await apiApp.fetch(
              new Request('https://self/api/v1/global-pulse?force=1', {
                headers: { 'x-internal-token': token },
              }),
              env as never,
              ctx
            );
            console.log(
              JSON.stringify({
                job: 'gp-30-rebuild',
                status: res.ok ? 'ok' : 'failed',
                http: res.status,
              })
            );
          } else {
            console.warn(
              JSON.stringify({
                job: 'gp-30-rebuild',
                status: 'skipped',
                reason: 'missing INTERNAL_TOKEN_SECRET or SELF',
              })
            );
          }
        } catch (e) {
          console.error(
            JSON.stringify({
              job: 'gp-30-rebuild',
              status: 'failed',
              error: e instanceof Error ? e.message : String(e),
              reason: 'in-process apiApp.fetch',
            })
          );
        }
      })()
        .catch(logCronFail('cp-30'))
        .finally(releaseLease)
    );
    return;
  }

  if (cron !== '30 0 * * *' && cron !== '45 0 * * 1') {
    // Unknown cron string — release the lease immediately so a stale entry
    // doesn't block a future (legitimate) fire of the same string for the
    // full TTL window.
    await releaseLease();
    return;
  }
  if (!env.BRIEFINGS_DB) {
    console.warn(JSON.stringify({ job: 'briefing-build', status: 'skipped', reason: 'BRIEFINGS_DB not bound' }));
    await releaseLease();
    return;
  }

  const isWeekly = cron === '45 0 * * 1';
  const type = isWeekly ? 'weekly' : 'daily';

  const briefingHrt = setInterval(() => {
    if (lease.token) heartbeatCronLease(env, cron, lease.token, CRON_LEASE_TTL_MS).catch(() => {});
  }, 5 * 60_000);
  ctx.waitUntil(
    (async () => {
      try {
        const db = env.BRIEFINGS_DB as D1Database;
        try {
          const briefing = await buildBriefing(type, undefined, {
            nvdApiKey: env.NVD_API_KEY,
            env: env as unknown as ApiEnv,
          });
          console.log(
            JSON.stringify({
              job: 'briefing-build-debug',
              step: 'buildBriefing returned',
              slug: briefing.slug,
              findings: briefing.stats.findings,
              iocs: briefing.stats.iocs,
            })
          );
          // writeBriefing can legitimately REFUSE — it returns
          // `{written:false, reason}` for a 0-finding build and for a build that
          // would overwrite a richer existing row. The old code discarded that
          // return value and logged `briefing-build` with the slug either way,
          // so a refused write was indistinguishable from a successful one in the
          // logs. That is how a missing daily looked like a healthy run.
          const writeResult = await writeBriefing(db, briefing);
          console.log(
            JSON.stringify({
              job: 'briefing-build',
              type,
              slug: briefing.slug,
              written: writeResult.written,
              reason: writeResult.reason,
              findings: briefing.stats.findings,
              iocs: briefing.stats.iocs,
            })
          );
          if (!writeResult.written) {
            console.error(
              JSON.stringify({
                job: 'briefing-build',
                type,
                slug: briefing.slug,
                status: 'not_persisted',
                reason: writeResult.reason,
              })
            );
          }
        } catch (err) {
          console.error(
            JSON.stringify({
              job: 'briefing-build',
              type,
              status: 'failed',
              error: err instanceof Error ? err.message : String(err),
              stack: err instanceof Error ? err.stack?.split('\n').slice(0, 5).join(' | ') : undefined,
            })
          );
        }
        try {
          const result = await sweepOldBriefings(db, BRIEFING_MAX_AGE_DAYS);
          if (result.deleted.length > 0) {
            console.log(
              JSON.stringify({
                job: 'briefing-sweep',
                deleted: result.deleted.length,
                slugs: result.deleted,
                kept: result.kept,
              })
            );
          }
        } catch (err) {
          console.error(
            JSON.stringify({
              job: 'briefing-sweep',
              status: 'failed',
              error: err instanceof Error ? err.message : String(err),
            })
          );
        }
        // Weekly TI Dashboard build — collects RSS news articles + supply
        // chain incidents and generates an LLM-enriched weekly report.
        if (isWeekly && db) {
          try {
            const { buildWeeklyDashboard, persistDashboard } = await import('../api/src/lib/ti-dashboard/build');
            const report = await buildWeeklyDashboard(env as unknown as ApiEnv);
            await persistDashboard(db, report);
            console.log(
              JSON.stringify({
                job: 'ti-dashboard-build',
                slug: report.slug,
                sources: report.metadata.documents_analyzed,
              })
            );
          } catch (err) {
            console.error(
              JSON.stringify({
                job: 'ti-dashboard-build',
                status: 'failed',
                error: err instanceof Error ? err.message : String(err),
              })
            );
          }
        }

        // Weekly Telegram leak cleanup — prune entries older than 7 days
        // so the DB doesn't grow unbounded. The hourly cron runs the leak
        // scanner (which appends), but only the weekly sweeps old rows.
        if (isWeekly) {
          try {
            const tgDeleted = await cleanupLeakEntries(db, 7);
            if (tgDeleted > 0) {
              console.log(JSON.stringify({ job: 'telegram-cleanup', deleted: tgDeleted, max_age_days: 7 }));
            }
          } catch (err) {
            console.error(
              JSON.stringify({
                job: 'telegram-cleanup',
                status: 'failed',
                error: err instanceof Error ? err.message : String(err),
              })
            );
          }
          // Weekly watchlist digest — sector-filtered, uses watched actors
          if (isWeekly && db && env.KV_CACHE) {
            try {
              const { runWeeklyWatchlistDigest } = await import('../api/src/routes/watchlist');
              await runWeeklyWatchlistDigest(db, env.KV_CACHE);
            } catch (err) {
              console.error(
                JSON.stringify({
                  job: 'watchlist-digest',
                  status: 'failed',
                  error: err instanceof Error ? err.message : String(err),
                })
              );
            }
          }
        }
        // Curated-landscape sync runs AFTER the briefing is persisted, not in
        // parallel with the build.
        //
        // The free plan allows 50 subrequests per invocation and `buildBriefing`'s
        // live fan-out already spends most of it. The landscape sync issues
        // three more upstream fetches that were previously started in the same
        // tick — so the two together could cross the cap, Cloudflare would abort
        // the invocation, and NOTHING would be written. Sequencing it after the
        // write means the sync can still fail on its own without ever costing
        // the briefing its budget.
        //
        // Note on confidence: the cap is on SUBREQUESTS, and a D1 `db.batch()`
        // is one subrequest however many statements it carries — the
        // 1,494-statement breach-forum snapshot writes every hour without
        // incident. This fan-out is real `fetch()` calls, so the cap genuinely
        // applies here.
        await runLandscapeSync();
      } finally {
        clearInterval(briefingHrt);
      }
      logCronDone({ path: 'briefing-dedicated', type });
    })()
      .catch(logCronFail('briefing-dedicated'))
      .finally(releaseLease)
  );
}
