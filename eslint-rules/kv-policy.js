/**
 * The KV-policy allowlist shared by the ROOT eslint.config.js and
 * api/eslint.config.js (flat-config cascading means api/** files resolve to
 * api/eslint.config.js, so both configs must enforce the same rule with the
 * same list — otherwise one tree silently loses the guardrail).
 *
 * See CLAUDE.md "KV policy — Cache API first". Adding a file here is a
 * conscious decision: cross-colo correctness state, last-good durability,
 * cron/admin sync pipelines, and the shared helper libs themselves.
 */
export const KV_ALLOW_FILES = [
  // ── shared Cache-API/KV helpers (they ARE the implementation) ──
  'api/src/lib/route-cache.ts',
  'api/src/lib/lastgood.ts',
  'api/src/lib/safe-catch.ts',
  'api/src/lib/cache.ts',
  'api/src/lib/blog-kv.ts',
  'worker/lib/blog-kv.ts',
  // ── cross-colo correctness state (must stay on KV) ──
  'api/src/routes/telegram-feed.ts',
  'api/src/routes/telegram-archive.ts',
  'api/src/routes/telegram-leak-monitor.ts',
  'api/src/routes/phishing-fingerprint.ts', // evict-on-write shadow; raw get inside its own L1 helper
  'api/src/routes/wayback.ts', // global circuit-breaker cooldown
  'api/src/routes/novelty.ts', // dedup marker (write-once)
  'api/src/lib/rag-embedder.ts', // embed seen-markers
  'api/src/routes/live-iocs.ts', // enqueue cooldown/cycle markers (+ shadowed reads)
  'api/src/routes/global-pulse/config.ts', // enqueue-cycle gate
  'api/src/routes/global-pulse/handler.ts', // GP response/last-good write-on-change
  'worker/queue-consumer.ts', // slice writer, write-on-change guards
  'api/src/lib/twitter-auth-graphql.ts', // admin-managed X qids/cookies
  'api/src/routes/admin-x-qids.ts',
  'api/src/routes/admin-x-cookies.ts',
  // ── upstream-outage last-good durability / fallback reads ──
  'api/src/routes/ransomware-recent.ts',
  'api/src/routes/cve-recent.ts',
  // Daily CVE digest — same three-layer discipline as cve-recent (edge cache →
  // KV last-good → 503). The KV write is the cron-warm last-good, the read the
  // request-path fallback; both are the documented durability pattern.
  'api/src/routes/cve-digest.ts',
  // Digest CSV/RSS exports — read the SAME last-good key as cve-digest.ts
  // (fallback leg only; the edge-cache hit path never touches KV).
  'api/src/routes/cve-digest-export.ts',
  'api/src/routes/onion-watch.ts',
  'api/src/routes/secret-leaks.ts',
  'api/src/routes/depx.ts',
  'api/src/routes/malicious-packages.ts',
  'api/src/routes/k8s-cve.ts',
  'api/src/routes/supply-chain-attacks.ts',
  'api/src/routes/ransomwhere.ts',
  'api/src/routes/pcmedicalist.ts',
  'api/src/routes/attack-flow-library.ts',
  'api/src/routes/phishing-urls.ts',
  'api/src/lib/scrapedintel.ts',
  'api/src/routes/hackertarget.ts', // rate-limit state + L2 leg
  'api/src/lib/darknet.ts', // tor-exit L2 leg behind shadow
  'api/src/lib/blocklist-builder.ts',
  'api/src/lib/ai-item-summary.ts',
  'api/src/lib/twitter-graphql.ts', // guest-token L2 leg + clear
  'api/src/lib/github-security-sync.ts', // cron sync write-on-change
  'api/src/lib/landscape-sync.ts',
  'api/src/routes/pir.ts', // alert store behind shadow helpers
  'api/src/lib/verify-url-cache.ts',
  'api/src/routes/threatsignal-rss.ts', // per-source RSS shadow + KV L2 legs
  'api/src/routes/ssvc-triage.ts',
  'api/src/routes/dossier.ts',
  // ── matrix/navigator/graph routes: cache-first, raw get = cold-miss L2 leg ──
  'api/src/routes/a3m-matrix.ts',
  'api/src/routes/d3fend-matrix.ts',
  'api/src/routes/attack-navigator.ts',
  'api/src/routes/relationship-graph.ts',
  'api/src/routes/snapshot.ts',
  // ── workspace-CRUD family: routeCache fronts, raw get = L2 blob/index legs ──
  'api/src/routes/soc-automation.ts',
  // ── cron/admin/user-tool mutations (low frequency by design) ──
  'worker/scheduled.ts',
  'worker/index.ts', // daily-briefs KV branch (shadowed read + ASSETS fallback)
  'worker/blog-image-route.ts', // immutable image shadow; raw get = cold-miss L2 leg
  'worker/og-route.ts', // pre-rendered page cards: cache-first, KV on miss
  'worker/durable-objects/global-pulse.ts', // pollFeeds KV leg behind Cache-API
  'worker/lib/daily-briefs-sync.ts',
  'api/src/routes/dashboard.ts', // watchlist cache behind shadow
  'api/src/routes/watchlist.ts',
  'api/src/routes/feedback.ts', // aggregate RMW + shadow evictions
  'api/src/routes/assessments.ts',
  'api/src/routes/campaigns.ts',
  'api/src/routes/external-resources.ts',
  'api/src/routes/observable-db.ts',
  'api/src/routes/maltrail-sync.ts',
  'api/src/routes/radar.ts',
  'api/src/routes/malware-vault.ts', // artifact L2 legs + meta store
  'api/src/routes/cyberpulse-ingest.ts',
  'api/src/routes/entity-graph.ts',
  'api/src/routes/bloom-filter.ts',
  'api/src/routes/health-detailed.ts',
  'api/src/routes/health.ts',
  'api/src/routes/feed-status.ts',
  'api/src/routes/tifce.ts',
  'api/src/index.ts', // webhook/status reads + route registrations
  'api/src/case-study/**',
  'api/src/routes/admin/**',
  'worker/durable-objects/**',
  'worker/bindings.ts',
  // ── legacy KV L2 read-only legs (phase out with their TTLs) ──
  'api/src/providers/**',
];
