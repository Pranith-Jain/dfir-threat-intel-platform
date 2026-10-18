import type { D1Database, Fetcher, Queue } from '@cloudflare/workers-types';
import type { FeedQueueMessage } from './lib/live-iocs-slices';

export interface Env {
  /** Service binding to self (in-process loopback-safe fetch). */
  SELF: Fetcher;
  KV_CACHE?: KVNamespace;
  /** Producer binding for the live-IOC per-source feed fan-out (PR2/PR3). */
  FEEDS_QUEUE?: Queue<FeedQueueMessage>;
  /** Durable Object used as a globally-consistent single-flight lease AND, via
   *  its `incr` op, an atomic windowed counter for the admin rate-limit bucket
   *  (so a parallel burst can't bypass the brute-force cap). Optional — the
   *  rate limiter degrades to the per-colos Cache/KV path when it is unbound. */
  CRON_LOCK_DO: DurableObjectNamespace;
  /** Cron execution DO — per-cron instances run the heavy cron bodies in a
   *  durable alarm (30s CPU budget), keeping the parent `scheduled` handler
   *  inside the free-plan 10ms cron cap. */
  CRON_JOB_DO?: DurableObjectNamespace;
  /** Report-generation pipeline DO (Copilot full-report builder). */
  REPORT_BUILDER: DurableObjectNamespace;
  /** Autonomous investigator agent DO. */
  INVESTIGATOR_AGENT: DurableObjectNamespace;
  /** Live-feed WebSocket fan-out DO. */
  LIVE_FEED_DO: DurableObjectNamespace;
  /** DFIR MCP server DO. */
  DFIR_MCP: DurableObjectNamespace;
  /** Radar deep-crawl DO. */
  RADAR_CRAWLER?: DurableObjectNamespace; /** Global Pulse real-time DO. */
  GLOBAL_PULSE_DO?: DurableObjectNamespace;
  /** Threat-data DO — SQLite storage for briefings, telegram leaks,
   *  cyberpulse incidents, and breach-forum status. Replaces D1 for these
   *  four verticals to avoid the free-plan 5M-row/day hard block. */
  THREAT_DATA_DO?: DurableObjectNamespace;
  BRIEFINGS_DB?: D1Database;
  /** Emergency valve for the external-read API-key gate. When set to the string
   *  `'true'` (a Worker secret, so it can be toggled without a redeploy),
   *  external GET/HEAD `/api/v1/*` reads are allowed WITHOUT an API key again —
   *  restoring the fully-public behavior. Unset/anything-else keeps reads gated. */
  OPEN_PUBLIC_READS?: string;
  /** Velociraptor endpoint-connector (gRPC-gateway HTTP JSON API). Optional —
   *  velo_* tools degrade to {configured:false} when unset. */
  VELO_API_URL?: string;
  VELO_API_TOKEN?: string;
  VELO_USERNAME?: string;
  VELO_PASSWORD?: string;
  CASE_STUDIES: KVNamespace;
  AI: Ai;
  VECTORIZE?: VectorizeIndex;
  /** Browser Run (Puppeteer) for JS-rendered page extraction. */
  BROWSER: Fetcher;
  /** Optional NVD API key (Worker secret) — raises NVD rate limit ~10x. */
  NVD_API_KEY?: string;
  /** Optional NVIDIA API key (Worker secret) — for NVIDIA completion fallback. */
  NVIDIA_API_KEY?: string;
  // Optional Worker secrets — unset in dev/preview and consumed with a
  // `?? ''` fallback. Declaring them required was a type lie that would
  // hide a genuine `undefined` if any caller forgot the fallback.
  VT_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
  SHODAN_API_KEY?: string;
  CENSYS_PAT?: string;
  CENSYS_ORG_ID?: string;
  NETLAS_API_KEY?: string;
  /** NumVerify API key (free at apilayer.net) for phone number validation and
   *  carrier lookup. Optional — the phone-osint route degrades gracefully when unset. */
  NUMVERIFY_API_KEY?: string;
  /** OpenSourceMalware API token (free at opensourcemalware.com → Settings → API Tokens).
   *  Optional — the provider degrades to 'unsupported' when unset. */
  OSM_API_KEY?: string;
  OTX_API_KEY?: string;
  URLSCAN_API_KEY?: string;
  HYBRID_ANALYSIS_API_KEY?: string;
  ABUSECH_AUTH_KEY?: string;
  /** ChainAbuse API key (free key at chainabuse.com) for BTC abuse lookups.
   *  Optional — /api/v1/darknet/btc-abuse-check degrades gracefully when unset. */
  CHAINABUSE_API_KEY?: string;
  /** Spur.us API token for VPN/proxy/tor detection. Optional — the
   *  IOC check degrades to 'unsupported' when unset. */
  SPUR_API_KEY?: string;
  /** MalShare API key (free registration at malshare.com). Optional —
   *  hash lookups degrade gracefully when unset. */
  MALSHARE_API_KEY?: string;
  /** EmailRep.io API key. Optional — the free anonymous tier (~100 req/hr per IP)
   *  works without; setting a key lifts the rate ceiling. */
  EMAILREP_API_KEY?: string;
  /** SerpAPI key for the Google-Dorks tool (`/dfir/google-dorks`). Required —
   *  the tool route returns 503 when unset. */
  SERPAPI_API_KEY?: string;
  DFIR_DEV_ERRORS?: string;
  AJ_analytics?: AnalyticsEngineDataset;
  ADMIN_TOKEN: string;
  /** Increment to invalidate all existing admin session cookies without
   *  rotating the ADMIN_TOKEN secret itself. The session cookie endpoint
   *  stamps this value into the cookie; the auth gate rejects stale versions.
   *  Set via `wrangler secret put ADMIN_TOKEN_VERSION`. Optional — when
   *  unset, version checking is disabled (all cookies are valid). */
  ADMIN_TOKEN_VERSION?: string;
  /** Bearer token for briefings admin endpoints (build, backfill, sweep).
   *  Set via `wrangler secret put BRIEFINGS_ADMIN_TOKEN`. Optional — when
   *  unset, the briefings admin handlers return 404. */
  BRIEFINGS_ADMIN_TOKEN?: string;
  /** Turnstile widget secret. Set via `wrangler secret put TURNSTILE_SECRET`.
   *  Optional and deliberately fail-open-when-absent: until it is set the
   *  bot-challenge gate in lib/turnstile.ts is a no-op and the site behaves
   *  exactly as before. Once set, keyless MUTATIONS on the shared-state routes
   *  must carry a verified `cf-turnstile-response` token — see lib/turnstile.ts
   *  for why the header-based same-origin grant is not an authorization proof. */
  TURNSTILE_SECRET?: string;
  /** Turnstile site key (public — served to the browser via /api/v1/features
   *  and rendered into every widget). Optional; when absent the frontend never
   *  loads the Turnstile script and sends no token. */
  TURNSTILE_SITE_KEY?: string;
  /** Comma-separated hostnames siteverify results must match, e.g.
   *  `pranithjain.qzz.io,www.pranithjain.qzz.io`. Empty = don't check the
   *  hostname (still requires `success === true`). */
  TURNSTILE_HOSTNAMES?: string;
  /** ransomware.live PRO API key (set via `wrangler secret put`). Optional —
   *  the /api/v1/rl/* proxy degrades to 503 when unset. */
  RANSOMWARELIVE_API_KEY?: string;
  /** Etherscan V2 API key (set via `wrangler secret put ETHERSCAN_API_KEY`).
   *  Optional — upgrades the tracer's EVM native-ETH source to Etherscan; when
   *  unset, native ETH transfers come from Blockscout's keyless endpoint. */
  ETHERSCAN_API_KEY?: string;
  /** Google AI Studio (Gemini) API key (set via `wrangler secret put GOOGLE_AI_STUDIO_API_KEY`).
   *  Free tier: gemini-3.6-flash (1,500 req/day), gemini-2.5-flash fallback. When
   *  set, Gemini is tried first before Groq/Workers AI. */
  GOOGLE_AI_STUDIO_API_KEY?: string;
  /** SambaNova free-tier API key (set via `wrangler secret put SAMBANOVA_API_KEY`).
   *  Free tier: ~10 RPM / 1K RPD. OpenAI-compatible endpoint with strong
   *  free models (MiniMax-M3 1M ctx, DeepSeek-V3.2, Llama 3.3 70B, gpt-oss-120b). */
  SAMBANOVA_API_KEY?: string;
  /** Groq free-tier API key (set via `wrangler secret put GROQ_API_KEY`).
   *  Free tier: gpt-oss-120b (1,000 req/day). Used as the primary LLM for
   *  feed summaries (preferGroq) and fallback for analyst paths. */
  GROQ_API_KEY?: string;
  /**
   * @deprecated Infron (llm.onerouter.pro) was removed from the LLM provider
   * chain (2026-09). Kept so the `wrangler secret` doesn't break the type;
   * the value is never read at runtime. Safe to delete the secret.
   */
  INFRON_API_KEY?: string;
  /** Free VulnCheck Community token (`wrangler secret put VULNCHECK_API_TOKEN`).
   *  Powers the `vulncheck` IP-intel provider, CVE-lookup exploitation enrichment,
   *  and the report engine's VulnCheck source. Optional — those degrade cleanly
   *  when unset. */
  VULNCHECK_API_TOKEN?: string;
  /** Google Safe Browsing v4 API key (`wrangler secret put GOOGLE_SAFE_BROWSING_API_KEY`).
   *  Free tier: 10K req/day. Enriches url-rep and phishing tools with
   *  Google's threat database (malware, social engineering, unwanted software). */
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
  /** ZoomEye API key (`wrangler secret put ZOOMEYE_API_KEY`).
   *  Free tier: 10K req/month. Host/port search + web fingerprinting. */
  ZOOMEYE_API_KEY?: string;
  /** IntoDNS.ai API key (`wrangler secret put INTODNS_API_KEY`).
   *  Optional — public diagnostic endpoints work without a key; setting
   *  one raises the upstream abuse-protection ceiling for `/scan/quick`,
   *  `/report/everything`, and snapshot creation. */
  INTODNS_API_KEY?: string;
  /** PolySwarm API key (`wrangler secret put POLYSWARM_API_KEY`).
   *  Optional — the provider degrades to 'unsupported' when unset.
   *  Free tier available at polyswarm.network/signup. */
  POLYSWARM_API_KEY?: string;
  /** FullHunt API key (`wrangler secret put FULLHUNT_API_KEY`).
   *  Optional — the provider degrades to 'unsupported' when unset.
   *  Free tier available at fullhunt.io. Used for attack surface discovery. */
  FULLHUNT_API_KEY?: string;
  /** OpenSanctions API key (`wrangler secret put OPENSANCTIONS_API_KEY`).
   *  The hosted API requires `Authorization: ApiKey …` since 2025. Free for
   *  public-interest work (journalism, civil-society, academic) at
   *  opensanctions.org. Optional — the provider degrades to 'unsupported'
   *  (no_api_key) when unset instead of surfacing a hard 401. */
  OPENSANCTIONS_API_KEY?: string;

  /** X (Twitter) auth cookies for the cookie-authenticated firehose at
   *  /api/v1/x-firehose. Set via `wrangler secret put X_AUTH_TOKEN` and
   *  `wrangler secret put X_CT0` (values are the `auth_token` and `ct0`
   *  cookies from a logged-in x.com session). Optional — when unset, the
   *  firehose endpoint returns 503 with setup instructions and the x-live
   *  / x-watch surfaces continue to work via the anonymous paths. */
  X_AUTH_TOKEN?: string;
  X_CT0?: string;
  /** Override for the public web bearer that ships in every x.com bundle.
   *  Rarely needed — only if Twitter rotates the default. */
  X_BEARER?: string;
  /** X (Twitter) API OAuth 2.0 Bearer token for posting tweets via API v2.
   *  Set via `wrangler secret put X_API_BEARER_TOKEN`. Optional — the
   *  automated posting routes return 503 when unset. */
  X_API_BEARER_TOKEN?: string;
  /** X (Twitter) API OAuth 1.0a credentials for user-authenticated posting.
   *  Required alongside X_API_BEARER_TOKEN to post as a user. Set via
   *  `wrangler secret put X_API_KEY`, `X_API_KEY_SECRET`,
   *  `X_ACCESS_TOKEN`, `X_ACCESS_TOKEN_SECRET`. All optional — posting
   *  routes return 503 when incomplete. */
  X_API_KEY?: string;
  X_API_KEY_SECRET?: string;
  X_ACCESS_TOKEN?: string;
  X_ACCESS_TOKEN_SECRET?: string;
  /** LinkedIn API access token for posting (OAuth 2.0, `w_member_social`
   *  scope). Set via `wrangler secret put LINKEDIN_ACCESS_TOKEN`. Optional
   *  — the automated posting routes return 503 when unset. */
  LINKEDIN_ACCESS_TOKEN?: string;
  /** LinkedIn API client credentials for refreshing the access token.
   *  Set via `wrangler secret put LINKEDIN_CLIENT_ID` and
   *  `LINKEDIN_CLIENT_SECRET`. Optional — without them, the token
   *  cannot be auto-refreshed when it expires. */
  LINKEDIN_CLIENT_ID?: string;
  LINKEDIN_CLIENT_SECRET?: string;
  /** Master switch for social auto-posting. The drip cron only posts when
   *  this is the literal "true". Off by default — set via
   *  `wrangler secret put SOCIAL_AUTOPOST_ENABLED` (or vars). */
  SOCIAL_AUTOPOST_ENABLED?: string;
  /** Max auto-posts PER PLATFORM per cron tick (drip rate). Default 1. */
  SOCIAL_DRIP_PER_TICK?: string;
  /** MyThreatIntel REST API bearer token (set via
   *  `wrangler secret put MYTHREATINTEL_API_TOKEN`). Optional — the
   *  /api/v1/mti proxy degrades to 503 when unset, and the in-process
   *  consumers (live-iocs, ransomware-recent) fall back to the existing
   *  t.me/s/mythreatintel scraper so nothing that works today breaks. */
  MYTHREATINTEL_API_TOKEN?: string;
  /** PromptIntel IoPC registry bearer token (set via
   *  `wrangler secret put PROMPTINTEL_API_KEY` — request one from the
   *  PromptIntel team). Optional — /api/v1/promptintel/health works
   *  without it; /taxonomy and /prompts degrade to 501 with setup
   *  instructions when unset. Docs: https://promptintel.novahunting.ai/api */
  PROMPTINTEL_API_KEY?: string;
  /** ProjectDiscovery Cloud Platform API key (free tier; set via
   *  `wrangler secret put PDCP_API_KEY`). Used as the Chaos `Authorization`
   *  header for free public-domain subdomain recon. Optional — the
   *  /api/v1/pd/subdomains endpoint returns 503 when unset; the credentials
   *  (leaks stats) and CVE-catalog endpoints need no key and work regardless. */
  PDCP_API_KEY?: string;
  /** Telegram bot token for CTI-archive posting + leak-monitor bot.
   *  TELEGRAM_CHANNEL_ID can be a comma-separated list of target chats
   *  for the archive. Optional — both features skip gracefully when unset. */
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHANNEL_ID?: string;
  /** Secret token validated on every Telegram webhook request. Set via
   *  `wrangler secret put TELEGRAM_WEBHOOK_SECRET`. Must match the
   *  `secret_token` passed to Telegram's `setWebhook` API. */
  TELEGRAM_WEBHOOK_SECRET?: string;
  /** When the literal string "true", the case-study publisher writes new
   *  posts to the `drafts:` namespace instead of `posts:` — promoting a
   *  draft requires an admin click via /api/v1/admin/case-study/drafts/
   *  <slug>/approve. Unset (or any other value) keeps the existing
   *  auto-publish flow. Set via `wrangler.jsonc#vars.BLOG_APPROVAL_REQUIRED`
   *  or `wrangler secret put`. */
  BLOG_APPROVAL_REQUIRED?: string;
  /** Cloudflare zone ID for cache purge operations. */
  CF_ZONE_ID?: string;
  /** Cloudflare API token with Cache Purge permission. */
  CF_API_TOKEN?: string;
  /** Triage (tria.ge) API key. Set via `wrangler secret put TRIAGE_API_KEY`. */
  TRIAGE_API_KEY?: string;
  /** Optional self-hosted file2txt bridge for CPU-heavy PDF/DOCX extraction.
   *  Unset → /api/v1/report/ingest returns 503 for PDF/DOCX (the free-plan
   *  10ms CPU cap blocks in-Worker parsing); text/HTML/image still work. */
  FILE2TXT_BRIDGE_URL?: string;
  FILE2TXT_BRIDGE_TOKEN?: string;
  /** CrowdSec CTI API key (free registration at crowdsec.net). Optional —
   *  the /api/v1/ioc/check CrowdSec provider degrades to 'unsupported'
   *  when unset. Free tier: 1000 lookups/month. */
  CROWDSEC_API_KEY?: string;
  /** IPinfo.io access token (free registration at ipinfo.io). Optional —
   *  improves rate limits from ~50/day to 50k/month. */
  IPINFO_TOKEN?: string;
  /** IP Quality Score API key (free at ipqualityscore.com). Optional — the
   *  IP enrichment provider degrades to 'unsupported' when unset. Provides
   *  proxy/VPN/TOR detection, fraud scoring, and abuse velocity. */
  IPQS_API_KEY?: string;
  /** CriminalIP API key (free registration at criminalip.io). Optional —
   *  the /api/v1/ioc/check CriminalIP provider degrades to 'unsupported'
   *  when unset. Free tier: 100 lookups/month. */
  CRIMINALIP_API_KEY?: string;
  /** Kaspersky OpenTip API key. Set via `wrangler secret put KASPERSKY_API_KEY`.
   *  Free tier: 1000 lookups/day. Used for hash, URL, IP, and domain reputation. */
  KASPERSKY_API_KEY?: string;
  /** GitHub personal access token for the malicious-packages API.
   *  Set via `wrangler secret put GITHUB_TOKEN`. Optional — the free
   *  anonymous GitHub API tier (60 req/hr) is the default. */
  GITHUB_TOKEN?: string;
  /** CTIWatch API key (free at ctiwatch.com/settings/api-keys; format
   *  `ctw_` + 64 hex). Set via `wrangler secret put CTIWATCH_API_KEY`.
   *
   *  OPTIONAL — and genuinely optional, which is unusual and worth stating
   *  plainly: /api/v1/cve-digest works without it. CTIWatch 401s every
   *  endpoint for a keyless caller, but it also mints an anonymous session
   *  cookie on any HTML page load, which the client replays. That anonymous
   *  scope is capped at `offset=1000` (HTTP 403 beyond) and 150 requests.
   *  A free key lifts the pagination ceiling entirely, which matters on a
   *  heavy patch day where a 24h window exceeds 1000 CVEs. */
  CTIWATCH_API_KEY?: string;
  /** OffSeq Threat Radar API key (optional). Anonymous access works for the
   *  public /api/threats endpoints; a key lifts the ~100 req/window ceiling
   *  and unlocks the documented /api/v1 tier. Set via
   *  `wrangler secret put OFFSEQ_API_KEY`. */
  OFFSEQ_API_KEY?: string;
  /** VulnTracker API key for the full /all-cves feed. Optional — see
   *  api/src/lib/vulntracker.ts. The digest-only endpoints need no key, so
   *  this only unlocks the complete per-CVE list. */
  VULNTRACKER_API_KEY?: string;
  /** PhishTank API key (free registration at phishtank.org/developer_info.php).
   *  Set via `wrangler secret put PHISHTANK_API_KEY`. Optional — the phish
   *  feed works without it using OpenPhish + brand detection; setting a key
   *  adds PhishTank's verified + target metadata. */
  PHISHTANK_API_KEY?: string;
  /** Hudson Rock Cavalier API v3 key (free at hudsonrock.com/free-api-key).
   *  Set via `wrangler secret put HUDSONROCK_API_KEY`. Optional — when unset,
   *  the infostealer intelligence routes and MCP tools degrade to the legacy
   *  v2 free endpoints (no key required, limited fields). */
  HUDSONROCK_API_KEY?: string;
  /** Canonical site URL. Set via
   *  `wrangler.jsonc#vars.SITE_URL` — used for CORS, RSS links, and
   *  canonical URLs. Falls back to the hardcoded default. */
  SITE_URL?: string;
  /** Path-prefix→hostname map for the tools surfaces, as a comma-separated
   *  `pathPrefix=hostname` list. Set via `wrangler.jsonc#vars.TOOLS_HOSTS`
   *  (see `api/src/lib/surface-hosts.ts` for the format). Requests whose Host
   *  header matches any configured hostname get the tools nav + ToolsHome
   *  instead of the portfolio ones, and each configured prefix is canonical on
   *  its own host. Must stay identical to `TOOL_HOSTS_BY_PATH` in
   *  `src/lib/surface.ts`, or the Worker and the browser will disagree about
   *  which surface they are on. Unset/empty collapses everything onto the
   *  apex — the pre-split behaviour. */
  TOOLS_HOSTS?: string;
  /** Secret for signing internal tokens (HMAC-SHA256). When set, replaces the
   *  deterministic fallback. Set via `wrangler secret put INTERNAL_TOKEN_SECRET`. */
  INTERNAL_TOKEN_SECRET?: string;
  /** Secret for signing public-by-link FEED tokens (HMAC-SHA256, see
   *  `api/src/lib/feed-token.ts`). Set via `wrangler secret put
   *  FEED_TOKEN_SECRET`. Rotating it revokes every outstanding feed URL at
   *  once. Optional — falls back to INTERNAL_TOKEN_SECRET, which is
   *  domain-separated in the HMAC message so the two credential types can
   *  never be confused. With neither set, feed-token-gated paths stay
   *  key-gated (the module fails closed). */
  FEED_TOKEN_SECRET?: string;
  /** When set to "true", allows localhost dev origins in CORS and auth checks.
   *  Unset in production to prevent local dev servers from authenticating. */
  ALLOW_DEV_ORIGINS?: string;
  /** PhantomCandle threat intel API credentials. Set via wrangler secrets.
   *  Required for si_enrich_ip / si_enrich_ip_batch to query
   *  phantomcandle.net for port-level threat attribution. */
  PHANTOMCANDLE_USER?: string;
  PHANTOMCANDLE_TOKEN?: string;
  /** Set "true" to disable AI blog illustrations (cost control). Default: on. */
  BLOG_AI_IMAGES_DISABLED?: string;
  /** Set "true" to enable the deep soft-404 probe on reference URLs: a HEAD-200
   *  URL gets one extra ranged GET whose <title> is sniffed for not-found
   *  markers, catching fabricated article slugs on hosts that answer HEAD 200
   *  for any path. OFF by default — it spends one extra subrequest per HEAD-200
   *  URL (free-plan budget is 50/invocation); verdicts are KV-cached. */
  DEEP_LINK_VERIFY?: string;
  /** BuiltWith Domain API key (paid). Optional — when unset, the
   *  /api/v1/builtwith tech-stack lookup falls back to a free, self-contained
   *  heuristic that fingerprints the target's live HTTP headers + HTML body.
   *  There is no free BuiltWith JSON API, so the heuristic is the default. */
  BUILTWITH_API_KEY?: string;
  /**
   * ASSETS binding — the SVG-PNG renderer (si-svg-png.ts) loads its fonts
   * from the static asset bucket at runtime. The binding is plumbed in by
   * the worker (worker/index.ts) which mounts apiApp with the full Env
   * (including ASSETS). Marked optional so the type stays usable from
   * contexts (api-only unit tests, vitest) that don't have the binding.
   */
  /** Traceix.com (PCEF) API key for SHA-256 hash AV/reputation lookups.
   *  Set via `wrangler secret put TRACEIX_API_KEY`. Free at perkinsfund.org. */
  TRACEIX_API_KEY?: string;
  /** Whoxy.com Reverse WHOIS API key.
   *  Set via `wrangler secret put WHOXY_API_KEY`. Paid ($0.01/query at whoxy.com). */
  WHOXY_API_KEY?: string;
  /** StalkPhish.io phishing-intel API token.
   *  Set via `wrangler secret put STALKPHISH_API_KEY`. Free tier at stalkphish.io (50 req/day). */
  STALKPHISH_API_KEY?: string;
  /** APIVoid IP + domain reputation API key (NoVirusThanks).
   *  Set via `wrangler secret put APIVOID_API_KEY`. Paid plans, 1 credit/call.
   *  Successor to the URLVoid/IPVoid web checkers. */
  APIVOID_API_KEY?: string;
  /** MetaDefender Cloud multi-engine hash reputation API key (OPSWAT).
   *  Set via `wrangler secret put METADEFENDER_API_KEY`. Free community key via OPSWAT account. */
  METADEFENDER_API_KEY?: string;
  /** OpenCVE Cloud organization API token (Bearer).
   *  Set via `wrangler secret put OPENCVE_API_TOKEN`. Free org token at app.opencve.io. */
  OPENCVE_API_TOKEN?: string;
  /** Truecaller reverse phone lookup API key.
   *  Set via `wrangler secret put TRUECALLER_API_KEY`. Free tier at truecaller.com. */
  TRUECALLER_API_KEY?: string;
  /** Webamon pro campaign-intelligence API key (x-api-key mode).
   *  Set via `wrangler secret put WEBAMON_API_KEY`. Powers the campaign/changes/
   *  clusters endpoints (intel.webamon.com estate brief) at pro.webamon.com. */
  WEBAMON_API_KEY?: string;
  /** Webamon OAuth client credentials (console session mode, optional).
   *  Set via `wrangler secret put WEBAMON_CLIENT_ID` / `WEBAMON_CLIENT_SECRET`. */
  WEBAMON_CLIENT_ID?: string;
  WEBAMON_CLIENT_SECRET?: string;
  /** Static asset bucket binding. Type matches `Fetcher` from
   *  @cloudflare/workers-types so the SVG-PNG renderer's `env.ASSETS.fetch(...)`
   *  call is fully typed end-to-end. Optional so api-only unit tests still
   *  compile when the binding is unbound. */
  ASSETS: Fetcher;
  /** GreyNoise Community API key (optional, free community tier works without).
   *  Set via `wrangler secret put GREYNOISE_API_KEY`. Raises rate limits. */
  GREYNOISE_API_KEY?: string;
  /** Pulsedive API key (optional). Set via `wrangler secret put PULSEDIVE_API_KEY`.
   *  Free tier works without; key raises rate limits. */
  PULSEDIVE_API_KEY?: string;
  /** Vulners API key (optional). Set via `wrangler secret put VULNERS_API_KEY`.
   *  Free tier works for ID lookups; key enables search/exploit queries. */
  VULNERS_API_KEY?: string;
  /** IntelligenceX API key (paid). Set via `wrangler secret put INTELX_API_KEY`.
   *  Required for intelx_search, intelx_phonebook, and result endpoints. */
  INTELX_API_KEY?: string;
  /** Have I Been Pwned API key (paid). Set via `wrangler secret put HIBP_API_KEY`.
   *  Required for account/paste search; breach list endpoints work without. */
  HIBP_API_KEY?: string;
  /** Discord webhook URL for case-study pipeline notifications (publish, fail,
   *  draft-ready events). Set via `wrangler secret put DISCORD_WEBHOOK_URL`. */
  DISCORD_WEBHOOK_URL?: string;
  /** Slack webhook URL for case-study pipeline notifications (publish, fail,
   *  draft-ready events). Set via `wrangler secret put SLACK_WEBHOOK_URL`. */
  SLACK_WEBHOOK_URL?: string;
}
