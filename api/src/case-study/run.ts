/**
 * Shared case-study pipeline runners. One wiring of the discovery /
 * planner / publisher orchestrators, used by BOTH the cron handler
 * (worker/index.ts `scheduled`) and the manual admin trigger endpoints
 * (`POST /api/v1/admin/run/:stage`). Keep the two callers DRY — the cron
 * blocks must not re-implement dep wiring.
 */
import { runDiscovery } from './discovery';
import { mulberry32, dateSeed, weightedSampleByScore } from './discovery/sampling';
import { discoverCves } from './discovery/cve';
import { selfFetchJson } from '../lib/self-fetch';
import { discoverActors } from './discovery/actor';
import { discoverMalware } from './discovery/malware';
import { discoverBreaches } from './discovery/breach';
import { discoverScams } from './discovery/scam';
import { discoverAiSec } from './discovery/aisec';
import { discoverAiSecOps } from './discovery/aisecops';
import { discoverLlmSec } from './discovery/llm';
import { discoverDarkweb } from './discovery/darkweb';
import { discoverSupplyChain } from './discovery/supplychain';
import { discoverExploits } from './discovery/exploits';
import { discoverInfostealers } from './discovery/infostealers';
import { discoverIntel } from './discovery/intel';
import { discoverOsint } from './discovery/osint';
import { discoverMethodology } from './discovery/methodology';
import { discoverCybersecNews } from './discovery/cybersec-news';
import { discoverTools } from './discovery/tools';
import { discoverBriefing } from './discovery/briefing';
import {
  discoverFromTelegramLeaks,
  discoverFromTrendingIocs,
  discoverFromThreatPulse,
} from './discovery/platform-data';
import { discoverAdvisories } from './discovery/advisories';
import { discoverVulnCheckKev } from './discovery/vulncheck';
import { discoverEuvd } from './discovery/euvd';
import { discoverTrendResearch } from './discovery/trend-research';
import { discoverPhishuntHunts } from './discovery/phishunt';
import { activeRunnerNames } from './discovery/rotation';
import { runPlanner } from './publishing/planner';
import { runPublisher } from './publishing/publisher';
import { putCandidate } from './storage/candidates';
import { listApproved, getApproved, unapprove } from './storage/approved';
import { setSchedule, markSlotStatus, pickDueSlot } from './storage/schedule';
import { loadDedupMap, touchDedup, touchDedupMany, isKeySuppressed } from './storage/dedup';
import { putPost, listPostIndex } from './storage/posts';
import { putDraft } from './storage/drafts';
import { recordFailure } from './storage/failed';
import { renderRss } from './rendering/rss';
import { generatePost } from './generation';
import { getVoiceProfileString } from './generation/voice-profile';
import { liveVerifyUrls } from './generation/verify-references';
import { createBatchedCachedVerify } from '../lib/verify-url-cache';
import { generateSocialContent } from './generation/social';
import { runSocialAutopost } from './posting/autopost';
import type { WebhookEnv } from './notifications';
import { getAi } from '../lib/ai-binding';
import {
  getSocialSchedule,
  readAutopostQueue,
  writeAutopostQueue,
  recordAutopostResult,
} from './storage/social-schedule';
import { postToTwitter, postToLinkedin } from './posting/social-poster';
import { putPostImage } from './storage/post-images';
import { fetchTweetMetrics, extractTweetId } from './analytics/tweet-metrics';
import { upsertMetrics } from './storage/social-metrics';
import type { MetricsRecord } from './analytics/analytics';
import type { SocialContent } from './types';
import { kv as csKvKeys } from './kv-keys';
import { ACTOR_RSS_FEEDS, ADVISORY_RSS_FEEDS } from './config';
import { getSiteUrl } from '../lib/site-config';
import type { D1Database } from '@cloudflare/workers-types';
import type { Candidate } from './types';
import { logError } from '../lib/logger';

/** The subset of bindings the case-study pipeline needs. */
export interface CaseStudyEnv {
  CASE_STUDIES: KVNamespace;
  /** Shared cache namespace; when present, reference-URL liveness verdicts
   *  are cached across publishes (one blob read + write per generation). */
  KV_CACHE?: KVNamespace;
  AI: unknown;
  ABUSECH_AUTH_KEY?: string;
  BRIEFINGS_DB?: D1Database;
  GROQ_API_KEY?: string;
  GOOGLE_AI_STUDIO_API_KEY?: string;
  NVIDIA_API_KEY?: string;
  INFRON_API_KEY?: string;
  /** Free VulnCheck Community token. Absent = VulnCheck KEV runner is a no-op. */
  VULNCHECK_API_TOKEN?: string;
  SITE_URL?: string;
  /**
   * When set to the literal "true" (string from `wrangler secret` or
   * `wrangler.jsonc#vars`), the publisher writes every new post to the
   * `drafts:` namespace instead of publishing. An admin promotes drafts
   * via /api/v1/admin/case-study/drafts/:slug/approve. Anything else
   * (unset, "false", "0") leaves the existing auto-publish behaviour.
   */
  BLOG_APPROVAL_REQUIRED?: string;
  /**
   * Threat-intel provider keys for layer-2 IOC validation at QA time.
   * Each is optional and degrades independently. When ALL are unset
   * the validation step is a no-op (the post-process layer-1 placeholder
   * filter stays the only IOC truth defence).
   */
  VT_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
  /** Self-referencing service binding — same Worker, in-process.
   *  Used by the platform-data discovery runner to call /api/v1/*
   *  without going through the public URL + API-key gate. */
  SELF?: { fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response> };
  /** HMAC signing secret for internal tokens (self-fetch auth). */
  INTERNAL_TOKEN_SECRET?: string;
  /** Master switch for social auto-posting. The drip cron is a no-op unless
   *  this is the literal "true". Off by default — nothing auto-posts to live
   *  accounts until this is explicitly set. */
  SOCIAL_AUTOPOST_ENABLED?: string;
  /** Max posts PER PLATFORM per cron tick (the drip rate). Default 1. */
  SOCIAL_DRIP_PER_TICK?: string;
  /** X (Twitter) OAuth 1.0a user-context credentials for auto-posting. */
  X_API_KEY?: string;
  X_API_KEY_SECRET?: string;
  X_ACCESS_TOKEN?: string;
  X_ACCESS_TOKEN_SECRET?: string;
  /** LinkedIn OAuth 2.0 bearer token for auto-posting. */
  LINKEDIN_ACCESS_TOKEN?: string;
  /** X (Twitter) app-only Bearer token — reads public_metrics for the
   *  analytics refresh. Absent → tweet-metrics refresh is a no-op. */
  X_API_BEARER_TOKEN?: string;
  /** Set to "true" to DISABLE AI blog illustrations (cost control). When
   *  unset, each published post gets an AI hero + in-body image (best-effort,
   *  falls back to the SVG hero on any failure). */
  BLOG_AI_IMAGES_DISABLED?: string;
  /** Set "true" to opt into the deep soft-404 reference probe (one extra
   *  ranged GET per HEAD-200 URL). Off by default for subrequest budget. */
  DEEP_LINK_VERIFY?: string;
  /** Discord webhook URL for pipeline notifications. */
  DISCORD_WEBHOOK_URL?: string;
  /** Slack webhook URL for pipeline notifications. */
  SLACK_WEBHOOK_URL?: string;
}

export async function runDiscoveryNow(env: CaseStudyEnv, now: Date) {
  // Graceful skip when CASE_STUDIES is unbound (local dev, half-provisioned
  // preview env). Previously a missing binding would surface as a KVNamespace
  // method-on-undefined crash inside loadDedupMap; the cron `.catch` logger
  // would catch it but the failure looks like a code bug rather than a
  // configuration gap. Explicit skip + structured log makes the cause clear.
  if (!env.CASE_STUDIES) {
    return {
      total: 0,
      kept: 0,
      suppressed: 0,
      deduped: 0,
      ids: [] as string[],
      byTopic: {} as Record<string, number>,
      byTopicSelected: {} as Record<string, number>,
    };
  }
  // Load the dedup map ONCE. Every runner scores novelty against this
  // in-memory snapshot — 0 KV reads in the runners (was ~1 read per
  // candidate, ~80-150 reads per daily run).
  const dedupMap = await loadDedupMap(env.CASE_STUDIES);
  const memGet = (k: string) => Promise.resolve(dedupMap[k] ?? null);
  // Anti-repetition gate. Two suppression windows:
  //   - PUBLISHED key  → hard-suppress for 30d (never republish the same story)
  //   - Surfaced (kept, not published) → hard-suppress for 7d to prevent the
  //     same candidates from appearing in every daily run. Without this,
  //     high-severity items keep dominating
  //     because noveltyScore only soft-deweights them.
  //   - the discovery runner itself consults the dedup map via `getDedup`.
  const REPUBLISH_BLOCK_MS = 30 * 24 * 3600 * 1000;
  const SURFACED_BLOCK_MS = 14 * 24 * 3600 * 1000;
  const isSuppressed = (key: string): boolean =>
    isKeySuppressed(dedupMap[key] ?? null, now, REPUBLISH_BLOCK_MS, SURFACED_BLOCK_MS);
  // One rand stream per run, seeded by the UTC date: stable within a day,
  // different the next. Weighted by score so high-value items stay likely
  // (and the single top item is guaranteed) without freezing the queue.
  const rand = mulberry32(dateSeed(now));
  const selectPerTopic = (cands: Parameters<typeof weightedSampleByScore>[0], k: number) =>
    weightedSampleByScore(cands, k, rand);

  // Shared platform API fetch — uses SELF service binding for in-process
  // calls so /api/v1/* endpoints don't hit the public API-key gate.
  const apiFetch: (path: string) => Promise<unknown> = async (path) => {
    return selfFetchJson<unknown>(env.SELF, path, env);
  };

  /** Coerce a self-fetch payload field into an array of row objects. */
  const asRows = (v: unknown): Array<Record<string, unknown>> =>
    Array.isArray(v) ? v.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object') : [];

  const allRunners: Record<string, () => Promise<Candidate[]>> = {
    vulncheck: () =>
      discoverVulnCheckKev({ fetch: globalThis.fetch, now, getDedup: memGet, token: env.VULNCHECK_API_TOKEN ?? '' }),
    cve: () => discoverCves({ fetch: globalThis.fetch, now, getDedup: memGet }),
    actor: () => discoverActors({ fetch: globalThis.fetch, now, getDedup: memGet, feeds: ACTOR_RSS_FEEDS }),
    malware: () =>
      discoverMalware({ fetch: globalThis.fetch, now, getDedup: memGet, abuseChKey: env.ABUSECH_AUTH_KEY ?? '' }),
    // The ransomware-victim runner is gone (see types.ts). `darkweb` covers
    // the same underground ground with far more signal per post: what access
    // is being offered, to whom, and at what price.
    darkweb: () =>
      discoverDarkweb({
        fetch: globalThis.fetch,
        now,
        getDedup: memGet,
        fetchHits: async (limit) => {
          const data = await selfFetchJson<Record<string, unknown>>(
            env.SELF,
            `/api/v1/darkweb-monitor?limit=${limit}`,
            env
          );
          return asRows(data?.items).length ? asRows(data?.items) : asRows(data?.hits);
        },
      }),
    exploit: () =>
      discoverExploits({
        fetch: globalThis.fetch,
        now,
        getDedup: memGet,
        fetchExploitDb: async (limit) => {
          const data = await selfFetchJson<Record<string, unknown>>(env.SELF, `/api/v1/exploit-db?limit=${limit}`, env);
          return asRows(data?.items).length ? asRows(data?.items) : asRows(data?.exploits);
        },
        fetchRecent: async (limit) => {
          const data = await selfFetchJson<Record<string, unknown>>(env.SELF, `/api/v1/cve-recent?limit=${limit}`, env);
          return asRows(data?.cves);
        },
      }),
    supplychain: () => discoverSupplyChain({ fetch: globalThis.fetch, now, getDedup: memGet }),
    infostealers: () => discoverInfostealers({ fetch: globalThis.fetch, now, getDedup: memGet }),
    breach: () => discoverBreaches({ fetch: globalThis.fetch, now, getDedup: memGet }),
    scam: () => discoverScams({ fetch: globalThis.fetch, now, getDedup: memGet }),
    aisec: () => discoverAiSec({ fetch: globalThis.fetch, now, getDedup: memGet }),
    llm: () => discoverLlmSec({ fetch: globalThis.fetch, now, getDedup: memGet }),
    aisecops: () => discoverAiSecOps({ fetch: globalThis.fetch, now, getDedup: memGet }),
    intel: () => discoverIntel({ fetch: globalThis.fetch, now, getDedup: memGet }),
    advisories: () => discoverAdvisories({ fetch: globalThis.fetch, now, getDedup: memGet, feeds: ADVISORY_RSS_FEEDS }),
    osint: () => discoverOsint({ fetch: globalThis.fetch, now, getDedup: memGet }),
    methodology: () => discoverMethodology({ fetch: globalThis.fetch, now, getDedup: memGet }),
    news: () => discoverCybersecNews({ fetch: globalThis.fetch, now, getDedup: memGet }),
    tool: () => discoverTools({ fetch: globalThis.fetch, now, getDedup: memGet }),
    euvd: () => discoverEuvd({ fetch: globalThis.fetch, now, getDedup: memGet }),
    briefing: () =>
      env.BRIEFINGS_DB
        ? discoverBriefing({ briefingsDb: env.BRIEFINGS_DB, now, getDedup: memGet })
        : Promise.resolve([]),
    // Platform data runners (split by source so each gets its own
    // perTopic budget instead of sharing 3 slots total).
    platformTelegram: () => discoverFromTelegramLeaks({ apiFetch, now, getDedup: memGet }),
    platformIocs: () => discoverFromTrendingIocs({ apiFetch, now, getDedup: memGet }),
    platformPulse: () => discoverFromThreatPulse({ apiFetch, now, getDedup: memGet }),
    // Phishunt: free, no-auth phishing feed with enriched data (IP, ASN, TLS,
    // detection sources). Surfaces brand impersonation campaigns and critical
    // phishing sites flagged by multiple detection engines.
    phish: () =>
      discoverPhishuntHunts({
        fetchPhishunt: async () => {
          try {
            const r = await fetch('https://phishunt.io/api/v1/domains?limit=100');
            if (!r.ok) return [];
            const data = (await r.json()) as { results?: Array<Record<string, unknown>> };
            return (data.results ?? []).map((item) => ({
              url: String(item.url ?? ''),
              domain: String(item.domain ?? ''),
              company: String(item.company ?? 'unknown'),
              date: String(item.date ?? item.first_seen ?? new Date().toISOString()),
              first_seen: String(item.first_seen ?? item.date ?? new Date().toISOString()),
              ip: String(item.ip ?? ''),
              country: String(item.country ?? ''),
              asn: String(item.asn ?? ''),
              org: String(item.org ?? ''),
              cert: String(item.cert ?? ''),
              malicious_google: Boolean(item.malicious_google),
              malicious_openphish: Boolean(item.malicious_openphish),
              malicious_phishtank: Boolean(item.malicious_phishtank),
              malicious_tweetfeed: Boolean(item.malicious_tweetfeed),
              malicious_urlscan: Boolean(item.malicious_urlscan),
            }));
          } catch {
            return [];
          }
        },
        now,
        getDedup: memGet,
      }),
    // Trend research (replaces the LLM-invented `trends` runner). Reads the
    // platform's OWN corpus for what actually moved — fresh KEV additions,
    // social-hype CVEs, EPSS outliers, fresh writeups, darkweb hits — and
    // only publishes candidates whose source URL verifiably resolves. When
    // the corpus is quiet it returns nothing, which is the correct outcome;
    // the old runner guaranteed three stories a day by inventing them.
    trends: () =>
      discoverTrendResearch({
        now,
        getDedup: memGet,
        self: env.SELF,
        internalTokenSecret: env.INTERNAL_TOKEN_SECRET,
        // One extra ranged GET per HEAD-200 source URL to catch soft-404s.
        // These URLs come from the platform's own corpus, so they are far
        // more trustworthy than the LLM's were — off by default.
        deepVerify: env.DEEP_LINK_VERIFY === 'true',
      }),
  };
  // Discovery diversity model:
  //   - 10 high-value "always-on" topics: `cve`, `actor`, `exploit`,
  //     `darkweb`, `infostealers`, `phish`, `trends`, and 3 platform
  //     sub-runners (telegram, iocs, pulse). Platform split gives each
  //     source its own perTopic budget.
  //   - The remaining optional topics partition into 6 day-buckets
  //     (rotation.ts), so each day surfaces a few of them.
  //   - Total per day: 9 always + ~3 rotating.
  //   - perTopic=2: each topic contributes up to 2 candidates, ensuring
  //     at least 10 different categories per run.
  //   - trends=3: fewer LLM candidates, higher quality bar enforced by
  //     dedup-avoidance list fed into the prompt.
  const ALWAYS_ON = new Set([
    'cve',
    'actor',
    'exploit',
    'darkweb',
    'infostealers',
    'platformTelegram',
    'platformIocs',
    'platformPulse',
    'phish',
    'trends',
  ]);
  // 6 rotation groups: with ~10 optional runners, each runs once every 6 days
  // This ensures variety while keeping daily subrequest count manageable
  const active = new Set(activeRunnerNames(Object.keys(allRunners), ALWAYS_ON, now, 6));
  const runners = Object.fromEntries(Object.entries(allRunners).filter(([name]) => active.has(name)));

  return runDiscovery({
    selectPerTopic,
    isSuppressed,
    runners,
    putCandidate: (c) => putCandidate(env.CASE_STUDIES, c),
    commitDedup: (keys, n) => touchDedupMany(env.CASE_STUDIES, keys, n),
    now,
    // Diversity controls (2026-06-11):
    //   - perTopic=2: each topic contributes up to 2. With 10 topics running
    //     per day (8 always-on + ~2 rotating), this ensures at least 10
    //     different categories surface in every discovery run.
    //   - limit=24: comfortable for ~10 active topics × 2, with headroom for
    //     trending context items.
    //   - trends=3: fewer LLM candidates; quality enforced via dedup-
    //     avoidance, category rotation, and real trending data injection.
    perTopic: 2,
    limit: 24,
    perTopicOverride: { trends: 3 },
  });
}

export function runPlannerNow(env: CaseStudyEnv, now: Date) {
  if (!env.CASE_STUDIES) {
    return Promise.resolve({ scheduled: [] as { candidateId: string; slotAt: string }[] });
  }
  return runPlanner({
    listApproved: () => listApproved(env.CASE_STUDIES),
    setSchedule: (slots) => setSchedule(env.CASE_STUDIES, slots),
    now,
    random: Math.random,
  });
}

/**
 * Fire-and-forget social copy generation for a published post.
 * Reads the post from KV, generates Twitter + LinkedIn content,
 * and stores it in KV. Safe to call on any publish path.
 */
export async function generateSocialForPost(slug: string, env: CaseStudyEnv, now: Date): Promise<void> {
  try {
    const post = await env.CASE_STUDIES.get<import('./types').Post>(csKvKeys.post(slug), 'json');
    if (!post) {
      return;
    }
    const social = await generateSocialContent(
      post,
      getAi(env),
      now,
      env.GROQ_API_KEY,
      env.GOOGLE_AI_STUDIO_API_KEY,
      env.NVIDIA_API_KEY as string | undefined,
      env.INFRON_API_KEY
    );
    await env.CASE_STUDIES.put(csKvKeys.social(slug), JSON.stringify(social));
  } catch (err) {
    console.error(
      JSON.stringify({ job: 'auto-social', slug, error: err instanceof Error ? err.message : String(err) })
    );
  }
}

export async function runPublisherNow(env: CaseStudyEnv, now: Date) {
  if (!env.CASE_STUDIES) {
    return Promise.resolve({ published: null as unknown });
  }
  const requireApproval = env.BLOG_APPROVAL_REQUIRED === 'true';
  // Build the optional validation-env once; pass undefined when no
  // provider keys are set so the validator's fast-path short-circuits.
  const validationEnv =
    env.VT_API_KEY || env.ABUSEIPDB_API_KEY || env.ABUSECH_AUTH_KEY
      ? { VT_API_KEY: env.VT_API_KEY, ABUSEIPDB_API_KEY: env.ABUSEIPDB_API_KEY, ABUSECH_AUTH_KEY: env.ABUSECH_AUTH_KEY }
      : undefined;
  const result = await runPublisher({
    pickDueSlot: (n) => pickDueSlot(env.CASE_STUDIES, n),
    markSlotStatus: (cid, status, extras) => markSlotStatus(env.CASE_STUDIES, cid, status, extras),
    getApproved: (k) => getApproved(env.CASE_STUDIES, k),
    unapprove: (k) => unapprove(env.CASE_STUDIES, k),
    generatePost: async (cand, n) =>
      generatePost({
        candidate: cand,
        ai: getAi(env),
        now: n,
        groqKey: env.GROQ_API_KEY,
        googleKey: env.GOOGLE_AI_STUDIO_API_KEY,
        infronKey: env.INFRON_API_KEY,
        validationEnv,
        // Cache reference-URL liveness across publishes when a cache binding
        // exists — one KV blob read + write per generation, vs. re-probing
        // canonical hosts (nvd, cisa, …) on every post. Falls back to a live
        // probe when KV_CACHE is unbound. DEEP_LINK_VERIFY=true opts into the
        // extra ranged-GET soft-404 probe (budget permitting); verdicts cache.
        verifyRefs: env.KV_CACHE
          ? createBatchedCachedVerify({
              kv: env.KV_CACHE,
              nowMs: n.getTime(),
              verify:
                env.DEEP_LINK_VERIFY === 'true'
                  ? (urls) => liveVerifyUrls(urls, { deepSoft404: true })
                  : liveVerifyUrls,
            })
          : undefined,
        // Research stage: SELF + token let the dossier query the platform's
        // own API (writeups, trending CVEs, darkweb hits) in addition to
        // fetching the candidate's own source pages.
        self: env.SELF,
        internalTokenSecret: env.INTERNAL_TOKEN_SECRET,
        // AI illustrations: on by default, disable via BLOG_AI_IMAGES_DISABLED.
        aiImages:
          env.BLOG_AI_IMAGES_DISABLED === 'true'
            ? undefined
            : { enabled: true, put: (slug, name, bytes) => putPostImage(env.CASE_STUDIES, slug, name, bytes) },
        // Voice profile: descriptive stats from the author's published posts,
        // injected into the system prompt so the model matches the real
        // writing rhythm (sentence length, contraction rate, hook forms,
        // vocabulary). Cached 24h in KV. Best-effort — falls back to the
        // prescriptive VOICE_IDENTITY when unavailable.
        voiceProfile: await getVoiceProfileString(env.CASE_STUDIES).catch(() => ''),
      }),
    putPost: (p) => putPost(env.CASE_STUDIES, p),
    putDraft: (p) => putDraft(env.CASE_STUDIES, p),
    refreshRss: async (index) => {
      const list = index ?? (await listPostIndex(env.CASE_STUDIES));
      const rss = renderRss(list, { siteUrl: getSiteUrl(env) });
      await env.CASE_STUDIES.put(csKvKeys.metaRss, rss);
    },
    touchDedup: (k, when, slug) => touchDedup(env.CASE_STUDIES, k, when, slug),
    recordFailure: (rec) => recordFailure(env.CASE_STUDIES, rec),
    now,
    requireApproval,
    // Pre-warm the post's social share image at publish time. The SELF-fetch
    // routes to the worker's /api/v1/og-image handler, which renders the card
    // and caches it in global KV + per-colo Cache-API — so the first X/LinkedIn
    // crawl gets a cached PNG instead of a cold resvg-wasm rasterisation that
    // can exceed the Worker CPU budget and 503 ("no card" on the share).
    warmOg: env.SELF
      ? (slug) =>
          env
            .SELF!.fetch(new Request(`https://self/api/v1/og-image/blog/${encodeURIComponent(slug)}.png`))
            .then(() => {})
      : undefined,
  });

  // Fire-and-forget auto-generation of social copy when a post was published
  if (result.published === 1 && result.slug) {
    generateSocialForPost(result.slug, env as unknown as CaseStudyEnv, now).catch((err) =>
      logError('auto-social generation failed', err)
    );
  }

  // Mirror published post to D1 for search/scale (fire-and-forget; failures non-critical)
  if (result.slug && env.BRIEFINGS_DB) {
    void import('./storage/cs-posts-d1')
      .then(async ({ upsertCsPostD1 }) => {
        const { getPost } = await import('./storage/posts');
        try {
          const post = await getPost(env.CASE_STUDIES, result.slug!);
          if (post) await upsertCsPostD1(env.BRIEFINGS_DB!, post);
        } catch {
          // D1 sync is non-critical
        }
      })
      .catch(() => {});
  }

  // Notifications
  if (result.published === 1 && result.slug) {
    void import('./notifications')
      .then(({ notifyPublished }) =>
        notifyPublished(env as unknown as WebhookEnv, result.slug!, result.slug!, 'published').catch((err) =>
          logError('notifyPublished failed', err)
        )
      )
      .catch(() => {});
  }
  if (result.published === 0 && result.slug && env.BLOG_APPROVAL_REQUIRED === 'true') {
    void import('./notifications')
      .then(({ notifyDraftReady }) =>
        notifyDraftReady(env as unknown as WebhookEnv, result.slug!, result.slug!, 'draft').catch((err) =>
          logError('notifyDraftReady failed', err)
        )
      )
      .catch(() => {});
  }

  return result;
}

/**
 * Refresh engagement metrics for recently-posted tweets. Rides the hourly
 * cron. Bounded to the most recent K posts per tick for the subrequest
 * budget, one batched metrics write. No-op without an X Bearer token.
 * LinkedIn/Instagram metrics are entered manually (no read API for personal
 * accounts).
 */
export async function refreshSocialMetricsNow(env: CaseStudyEnv, now: Date) {
  if (!env.CASE_STUDIES || !env.X_API_BEARER_TOKEN) {
    return { refreshed: 0, reason: !env.X_API_BEARER_TOKEN ? 'no-bearer' : 'no-kv' };
  }
  const index = await listPostIndex(env.CASE_STUDIES);
  const recent = [...index].sort((a, b) => (b.publishedAt ?? '').localeCompare(a.publishedAt ?? '')).slice(0, 8);
  const records: MetricsRecord[] = [];
  for (const entry of recent) {
    const sched = await getSocialSchedule(env.CASE_STUDIES, entry.slug);
    const tw = sched?.twitter;
    if (tw?.status !== 'posted' || !tw.postUrl) continue;
    const id = extractTweetId(tw.postUrl);
    if (!id) continue;
    const metrics = await fetchTweetMetrics(id, env.X_API_BEARER_TOKEN);
    if (metrics) {
      records.push({
        slug: entry.slug,
        platform: 'twitter',
        type: entry.type,
        postUrl: tw.postUrl,
        metrics,
        fetchedAt: now.toISOString(),
      });
    }
  }
  await upsertMetrics(env.CASE_STUDIES, records);

  // Refresh D1 content_performance aggregates for the analytics feedback loop
  if (env.BRIEFINGS_DB) {
    try {
      const { refreshContentPerformance } = await import('./analytics/content-performance');
      await refreshContentPerformance(env.BRIEFINGS_DB, env.CASE_STUDIES);
    } catch {
      // D1 unavailable — content performance refresh is non-critical
    }
  }
  return { refreshed: records.length };
}

/**
 * Drip auto-post tick. Called from the hourly cron. Releases approved + due
 * X/LinkedIn posts at the configured drip rate. A pure no-op (no posting)
 * unless SOCIAL_AUTOPOST_ENABLED === 'true' — the master safety switch.
 * Instagram is never auto-posted. All gate logic lives in `runSocialAutopost`;
 * this just wires it to KV + the real platform posters.
 */
export async function runSocialAutopostNow(env: CaseStudyEnv, now: Date) {
  if (!env.CASE_STUDIES) {
    return { enabled: false, posted: [], failed: [], skipped: 0, reason: 'no-kv' };
  }
  const ns = env.CASE_STUDIES;
  const enabled = env.SOCIAL_AUTOPOST_ENABLED === 'true';
  const drip = Math.max(1, Number(env.SOCIAL_DRIP_PER_TICK) || 1);

  const result = await runSocialAutopost({
    enabled,
    now,
    dripPerPlatform: drip,
    readQueue: () => readAutopostQueue(ns),
    writeQueue: (items) => writeAutopostQueue(ns, items),
    getSchedule: (slug) => getSocialSchedule(ns, slug),
    getContent: (slug) => ns.get(csKvKeys.social(slug), 'json') as Promise<SocialContent | null>,
    recordResult: (slug, platform, r) => recordAutopostResult(ns, slug, platform, r, now).then(() => undefined),
    post: async (platform, content) => {
      if (platform === 'twitter') {
        const r = await postToTwitter(content.twitter, {
          apiKey: env.X_API_KEY ?? '',
          apiKeySecret: env.X_API_KEY_SECRET ?? '',
          accessToken: env.X_ACCESS_TOKEN ?? '',
          accessTokenSecret: env.X_ACCESS_TOKEN_SECRET ?? '',
        });
        return { ok: r.ok, postUrl: r.postUrl, error: r.error };
      }
      if (!env.LINKEDIN_ACCESS_TOKEN) return { ok: false, error: 'linkedin_token_missing' };
      const r = await postToLinkedin(content.linkedin, env.LINKEDIN_ACCESS_TOKEN);
      return { ok: r.ok, postUrl: r.postUrl, error: r.error };
    },
  });
  return result;
}
