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
import { discoverReleaks, type ReleakRow } from './discovery/releak';
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
import { loadDedupMap, touchDedup, touchDedupMany, isKeySuppressed, suppressDedupMany } from './storage/dedup';
import {
  buildKevCandidate,
  fetchKevAdditions,
  selectKevBatch,
  KEV_AUTOPUBLISH_MAX_PER_TICK,
  KEV_AUTOPUBLISH_WINDOW_HOURS,
} from './kev-autopublish';
import { enrichFromNvd } from './discovery/cve';
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
  approveSocialPlatform,
  AUTOPOST_PLATFORMS,
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
import type { Candidate, Post } from './types';
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
  SAMBANOVA_API_KEY?: string;
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
      blocked: 0,
      filledFromSuppressed: 0,
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
  //   - Surfaced (kept, not published) → hard-suppress for 5d to prevent the
  //     same candidates from appearing in every daily run. Without this,
  //     high-severity items keep dominating because noveltyScore only
  //     soft-deweights them.
  //   - the discovery runner itself consults the dedup map via `getDedup`.
  //
  // The surfaced window was 14d and that is what emptied the queue: with ~14
  // active runners x perTopic, a fortnight of marks covered essentially every
  // item the RSS-backed runners can return, so a normal day surfaced 2-3
  // candidates. 5d still means "not every day" (the point of the gate) while
  // leaving the runners a pool to draw from; `MIN_DAILY_CANDIDATES` below is
  // the backstop if a day is still thin.
  const REPUBLISH_BLOCK_MS = 30 * 24 * 3600 * 1000;
  const SURFACED_BLOCK_MS = 5 * 24 * 3600 * 1000;
  /**
   * Is this candidate owned by the KEV auto-publish job?
   *
   * A fresh CISA-KEV addition is published by `runKevAutopublishNow` on the
   * hourly tick, within the hour. Offering it as a queue candidate
   * at the same time risks two posts about one CVE — the auto-published one and
   * a later human-approved one with a different slug — which is exactly the
   * duplicate the republish block exists to prevent.
   *
   * The reservation is a WINDOW, not a veto, so the fallback is automatic: if
   * the KEV job is broken or unconfigured, the entry stops being reserved after
   * 48h and discovery offers it normally (by then it also has no `publishedSlug`,
   * because the job never ran).
   */
  const isKevReserved = (c: Candidate): boolean => {
    const ev = c.evidence as { kev?: unknown; kevAddedAt?: unknown } | undefined;
    if (ev?.kev !== true || typeof ev.kevAddedAt !== 'string') return false;
    const added = Date.parse(ev.kevAddedAt);
    if (!Number.isFinite(added)) return false;
    return now.getTime() - added < KEV_AUTOPUBLISH_WINDOW_HOURS * 3600 * 1000;
  };
  const isSuppressed = (key: string, candidate?: Candidate): boolean =>
    (candidate ? isKevReserved(candidate) : false) ||
    isKeySuppressed(dedupMap[key] ?? null, now, REPUBLISH_BLOCK_MS, SURFACED_BLOCK_MS);

  /**
   * Daily floor — the operator's standing requirement is 5-8 fresh options a
   * day. When the strict pass comes back under this, `runDiscovery` refills
   * from the same fetched pool under the relaxation rules below.
   */
  const MIN_DAILY_CANDIDATES = 6;
  /**
   * How stale a previously-surfaced key must be before the top-up may re-offer
   * it. 2d is deliberately tighter than the 5d strict window: the top-up is a
   * floor, not a way to repeat yesterday's queue.
   */
  const TOPUP_MIN_AGE_MS = 2 * 24 * 3600 * 1000;
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
    // Note: the platform darkweb-monitor SELF endpoint was removed from the
    // API (the run never had a handler), so this runner is RSS-only —
    // reporting ON the underground rather than leaking-marketplace rows.
    darkweb: () => discoverDarkweb({ fetch: globalThis.fetch, now, getDedup: memGet }),
    exploit: () =>
      discoverExploits({
        fetch: globalThis.fetch,
        now,
        getDedup: memGet,
        fetchRecent: async (limit) => {
          const data = await selfFetchJson<Record<string, unknown>>(env.SELF, `/api/v1/cve-recent?limit=${limit}`, env);
          return asRows(data?.cves);
        },
      }),
    supplychain: () => discoverSupplyChain({ fetch: globalThis.fetch, now, getDedup: memGet }),
    infostealers: () => discoverInfostealers({ fetch: globalThis.fetch, now, getDedup: memGet }),
    // Re-leaks: a victim claimed by ≥2 ransomware groups — a high-signal
    // story (failed double-extortion / affiliate movement). Reads the
    // platform's own /api/v1/victim-releaks surface via the SELF binding.
    releak: () =>
      discoverReleaks({
        now,
        getDedup: memGet,
        fetchReleaks: async () => {
          const data = (await apiFetch('/api/v1/victim-releaks')) as { releaks?: ReleakRow[] } | null;
          return data?.releaks ?? [];
        },
      }),
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
    // EPSS outliers against the platform's recent baseline, fresh writeups —
    // and only publishes candidates whose source URL verifiably resolves.
    // When the corpus is quiet it returns nothing, which is the correct
    // outcome; the old runner guaranteed three stories a day by inventing
    // them.
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
  //   - The remaining optional topics partition into 4 day-buckets
  //     (rotation.ts), so each optional runner surfaces once every four
  //     days.
  //   - Total per day: 10 always-on + ~4 rotating.
  //   - perTopic=5: each topic contributes up to 5 candidates, so a quiet
  //     CVE day cannot crowd the other topics out of the queue while a busy
  //     one still fills the day's floor on its own.
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
  // 4 rotation groups: with ~16 optional runners, each runs once every 4 days,
  // so the daily mix always carries non-CVE topics alongside the always-on
  // core. Fewer groups than before = more variety per day, still bounded.
  const active = new Set(activeRunnerNames(Object.keys(allRunners), ALWAYS_ON, now, 4));
  const runners = Object.fromEntries(Object.entries(allRunners).filter(([name]) => active.has(name)));

  return runDiscovery({
    selectPerTopic,
    isSuppressed,
    runners,
    putCandidate: (c) => putCandidate(env.CASE_STUDIES, c),
    commitDedup: (keys, n) => touchDedupMany(env.CASE_STUDIES, keys, n),
    now,
    // Diversity controls:
    //   - perTopic=5: each topic contributes up to 5. With ~14 topics running
    //     per day (10 always-on + ~4 rotating), this keeps every category
    //     represented without letting one topic flood the queue.
    //   - limit=60: comfortable for ~14 active topics × 5, with headroom for
    //     context items.
    //   - trends=3: fewer LLM-generated candidates, so it keeps the old
    //     budget; kept explicit so the override is visible if either value is
    //     ever tuned.
    //   - minKept=6: the daily floor (see MIN_DAILY_CANDIDATES above).
    perTopic: 5,
    limit: 60,
    perTopicOverride: { trends: 3 },
    minKept: MIN_DAILY_CANDIDATES,
    // Top-up admission policy. Two hard rules, both non-negotiable:
    //   - an admin skip (`suppressedUntil` in the future) always wins, and
    //   - an already-PUBLISHED key is never re-offered — no duplicate post.
    // Only "surfaced, never used" keys older than TOPUP_MIN_AGE_MS qualify.
    admitSuppressed: (c) => {
      // The KEV job owns fresh additions (see isKevReserved) — the top-up must
      // not smuggle one back in through the floor.
      if (isKevReserved(c)) return false;
      const rec = dedupMap[c.key];
      if (!rec) return true;
      if (rec.suppressedUntil && Date.parse(rec.suppressedUntil) > now.getTime()) return false;
      if (rec.publishedSlug) return false;
      const seen = Date.parse(rec.lastSeenAt);
      return !Number.isFinite(seen) || now.getTime() - seen >= TOPUP_MIN_AGE_MS;
    },
    // Fill the floor oldest-first so the top-up surfaces the back of the pool
    // rather than re-offering the highest-scoring items the strict pass just
    // declined.
    rankTopUp: (pool) =>
      pool.sort((a, b) => {
        const ta = Date.parse(dedupMap[a.key]?.lastSeenAt ?? '');
        const tb = Date.parse(dedupMap[b.key]?.lastSeenAt ?? '');
        if (Number.isFinite(ta) && Number.isFinite(tb) && ta !== tb) return ta - tb;
        return b.score - a.score;
      }),
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

/**
 * Shared generation wiring — the candidate → post step every publish path
 * uses (the scheduled publisher and the KEV auto-publish job). Factored out so
 * a tuning change (model order, voice profile, reference verification) cannot
 * apply to one path and silently miss the other.
 */
async function generatePostFor(env: CaseStudyEnv, candidate: Candidate, now: Date): Promise<Post> {
  // Optional validation-env when provider keys exist; undefined lets the
  // validator's fast-path short-circuit.
  const validationEnv =
    env.VT_API_KEY || env.ABUSEIPDB_API_KEY || env.ABUSECH_AUTH_KEY
      ? { VT_API_KEY: env.VT_API_KEY, ABUSEIPDB_API_KEY: env.ABUSEIPDB_API_KEY, ABUSECH_AUTH_KEY: env.ABUSECH_AUTH_KEY }
      : undefined;
  return generatePost({
    candidate,
    ai: getAi(env),
    now,
    groqKey: env.GROQ_API_KEY,
    sambanovaKey: env.SAMBANOVA_API_KEY,
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
          nowMs: now.getTime(),
          verify:
            env.DEEP_LINK_VERIFY === 'true' ? (urls) => liveVerifyUrls(urls, { deepSoft404: true }) : liveVerifyUrls,
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
  });
}

/** RSS refresh — index-level fields only, so one render covers the whole feed. */
async function refreshRssFor(env: CaseStudyEnv, index?: Awaited<ReturnType<typeof listPostIndex>>): Promise<void> {
  const list = index ?? (await listPostIndex(env.CASE_STUDIES));
  const rss = renderRss(list, { siteUrl: getSiteUrl(env) });
  await env.CASE_STUDIES.put(csKvKeys.metaRss, rss);
}

/**
 * Post-publish side effects shared by both publish paths: social copy, the D1
 * mirror and the publish notification. The D1 mirror also runs for drafts (the
 * admin lists them from there), which is why it is not gated on `published`.
 * Every step is best-effort — none of them may fail a publish.
 */
async function recordPostSideEffects(
  env: CaseStudyEnv,
  slug: string,
  now: Date,
  opts: { published: boolean; post?: Post }
): Promise<void> {
  if (opts.published) {
    // Fire-and-forget: social copy generation must never delay the publish.
    generateSocialForPost(slug, env, now).catch((err) => logError('auto-social generation failed', err));
  }

  if (env.BRIEFINGS_DB) {
    try {
      let resolved = opts.post;
      if (!resolved) {
        const { getPost } = await import('./storage/posts');
        resolved = (await getPost(env.CASE_STUDIES, slug)) ?? undefined;
      }
      if (resolved) {
        const { upsertCsPostD1 } = await import('./storage/cs-posts-d1');
        await upsertCsPostD1(env.BRIEFINGS_DB, resolved);
      }
    } catch {
      // D1 sync is non-critical
    }
  }

  if (opts.published) {
    try {
      const { notifyPublished } = await import('./notifications');
      await notifyPublished(env as unknown as WebhookEnv, slug, slug, 'published');
    } catch (err) {
      logError('notifyPublished failed', err);
    }
  }
}

export interface KevAutopublishResult {
  /** New KEV additions seen inside the window. */
  seen: number;
  /** Keys that passed the already-published / suppression guard. */
  eligible: number;
  /** Posts written to the public index (and RSS) this tick. */
  published: number;
  slugs: string[];
  failures: Array<{ key: string; error: string }>;
  reason?: string;
}

/**
 * KEV auto-publish tick — a CVE added to CISA's Known Exploited
 * Vulnerabilities catalog gets a post, published immediately.
 *
 * Why this exists as its own job rather than a faster discovery loop: every
 * other topic is a suggestion a human vets, but a KEV addition is a confirmed
 * in-the-wild exploitation event with an authority behind it and a date on it.
 * Routing it through discovery → approval → planner → slot meant the write-up
 * landed days after the window it was meant to cover, and the day it landed
 * was random.
 *
 * Trade-offs, all deliberate and all visible in the return value:
 *   - `BLOG_APPROVAL_REQUIRED` is NOT honored. The draft gate exists so a human
 *     can reject a topic the platform chose; this topic was chosen for us.
 *   - Social copy IS generated, but it is enqueued for the drip only when
 *     `SOCIAL_AUTOPOST_ENABLED === 'true'` — the operator's existing master
 *     switch for automated posting. With it off the copy sits pending for a
 *     manual post, exactly as it does for every other published article
 *     (docs/loops/social-crosspost.md keeps that gate intact).
 *   - A generation failure does NOT retry every hour: the key is suppressed for
 *     24h so a persistently failing CVE costs one attempt a day, not 24.
 *   - The per-tick cap (`KEV_AUTOPUBLISH_MAX_PER_TICK`) keeps a 30-entry KEV
 *     batch from firing 30 generations at once; the 26h window means the rest
 *     publish over the following ticks.
 */
export async function runKevAutopublishNow(env: CaseStudyEnv, now: Date): Promise<KevAutopublishResult> {
  const empty: KevAutopublishResult = { seen: 0, eligible: 0, published: 0, slugs: [], failures: [] };
  if (!env.CASE_STUDIES) return { ...empty, reason: 'no-kv' };

  const dedupMap = await loadDedupMap(env.CASE_STUDIES);
  const memGet = (k: string) => Promise.resolve(dedupMap[k] ?? null);

  // 1) What is new in KEV? One subrequest.
  let entries;
  try {
    entries = await fetchKevAdditions({ fetch: globalThis.fetch, now, windowHours: KEV_AUTOPUBLISH_WINDOW_HOURS });
  } catch (err) {
    logError('kev-autopublish feed fetch failed', err);
    return { ...empty, reason: 'feed-fetch-failed' };
  }
  if (entries.length === 0) return empty;

  // 2) Build candidates (NVD enrichment per entry) and pick this tick's batch
  //    under the never-double-publish guard.
  const candidates = await Promise.all(
    entries.map((e) =>
      buildKevCandidate(e, {
        now,
        getDedup: memGet,
        enrich: (cveId) => enrichFromNvd(globalThis.fetch, cveId),
      })
    )
  );
  const batch = selectKevBatch(candidates, dedupMap, now, KEV_AUTOPUBLISH_MAX_PER_TICK);
  const result: KevAutopublishResult = { ...empty, seen: entries.length, eligible: batch.length };
  if (batch.length === 0) return result;

  for (const candidate of batch) {
    try {
      const post = await generatePostFor(env, candidate, now);
      const index = await putPost(env.CASE_STUDIES, post);
      await refreshRssFor(env, index);
      await touchDedup(env.CASE_STUDIES, candidate.key, now, post.slug);

      // Pre-warm the share card so the first social crawl hits a cached PNG
      // instead of a cold rasterisation (same reasoning as the publisher).
      if (env.SELF) {
        env.SELF.fetch(new Request(`https://self/api/v1/og-image/blog/${encodeURIComponent(post.slug)}.png`)).catch(
          () => {}
        );
      }

      if (env.SOCIAL_AUTOPOST_ENABLED === 'true') {
        try {
          for (const platform of AUTOPOST_PLATFORMS) {
            await approveSocialPlatform(env.CASE_STUDIES, post.slug, platform, now);
          }
        } catch (err) {
          // Approval failure must not undo the publish — the post is live and
          // the copy can be approved by hand.
          logError('kev-autopublish social enqueue failed', err);
        }
      }

      // Social copy generation is fire-and-forget inside this helper, so a slow
      // LLM cannot stall the next CVE in the batch.
      await recordPostSideEffects(env, post.slug, now, { published: true, post });

      result.published += 1;
      result.slugs.push(post.slug);
      console.log(
        JSON.stringify({
          job: 'kev-autopublish',
          status: 'published',
          slug: post.slug,
          candidateId: candidate.key,
          cve: (candidate.evidence as { cveId?: string }).cveId,
        })
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      result.failures.push({ key: candidate.key, error: msg });
      // One attempt per day for a CVE that keeps failing to generate. Without
      // this the same entry would be re-picked on every hourly tick.
      await suppressDedupMany(env.CASE_STUDIES, [candidate.key], new Date(now.getTime() + 24 * 3600 * 1000), now).catch(
        () => {}
      );
      logError(`kev-autopublish generation failed (${candidate.key})`, err);
    }
  }

  return result;
}

export async function runPublisherNow(env: CaseStudyEnv, now: Date) {
  if (!env.CASE_STUDIES) {
    return Promise.resolve({ published: null as unknown });
  }
  const requireApproval = env.BLOG_APPROVAL_REQUIRED === 'true';
  const result = await runPublisher({
    pickDueSlot: (n) => pickDueSlot(env.CASE_STUDIES, n),
    markSlotStatus: (cid, status, extras) => markSlotStatus(env.CASE_STUDIES, cid, status, extras),
    getApproved: (k) => getApproved(env.CASE_STUDIES, k),
    unapprove: (k) => unapprove(env.CASE_STUDIES, k),
    generatePost: (cand, n) => generatePostFor(env, cand, n),
    putPost: (p) => putPost(env.CASE_STUDIES, p),
    putDraft: (p) => putDraft(env.CASE_STUDIES, p),
    refreshRss: (index) => refreshRssFor(env, index),
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

  // Social copy + D1 mirror + publish notification, same wiring the KEV
  // auto-publish path uses (see recordPostSideEffects).
  if (result.slug) {
    await recordPostSideEffects(env, result.slug, now, { published: result.published === 1 });
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
