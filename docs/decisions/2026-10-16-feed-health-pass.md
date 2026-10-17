# Decision: Feed-health pass — single allowlist, Bing News migration, catalog audit

**Date:** 2026-10-16
**Status:** Implemented
**Owner:** Pranith
**Driver:** A full audit of every feed surface found four independent breakages that were
invisible in the build and, in three cases, had been broken in production for months.

---

## FINDINGS (evidence)

Audited by probing upstream **and** by replaying the SPA's real request path against the
deployed Worker (`/api/v1/feeds/aggregate` with a same-origin `Origin` header), which is
what users actually get — not what a status check on the origin suggests.

| Surface                           | Method                          | Result                                                                     |
| --------------------------------- | ------------------------------- | -------------------------------------------------------------------------- |
| IOC registry (46 sources)         | `npm run audit:feeds`           | 44/46 healthy, 2 key-gated skips — **green**                               |
| RSS catalog (142 entries)         | live aggregator replay          | **105/142 healthy, 37 failures**                                           |
| Reddit                            | branch data + runtime logic     | fresh (today), but only **8–9 of 16** subs per run                         |
| Telegram RSS + MTProto            | orphan branches + workflow runs | 31/31 channels ok, both branches fresh — **green**                         |
| X live (TweetFeed→FxTwitter)      | upstream probe                  | fresh today — **green**                                                    |
| X firehose                        | code + admin surface            | unverifiable remotely (admin-only deep probe; needs operator cookies/qids) |
| CVEs (`cve-recent`, `cve-health`) | live API                        | `nvd-published-14d` **ok:false**, `github_api` **403**                     |
| Ransomware (merged + MTI)         | live RSS                        | fresh (Oct 14 items) — **green**                                           |

The 37 RSS failures broke into five classes:

1. **Allowlist drift (1 feed, whole-class bug).** `blog.trailofbits.com` — the exact symptom
   reported — was in `feeds.ts`'s allowlist but **missing from the copy inlined into
   `feeds-aggregate.ts`**, the route the SPA actually calls. The aggregator answered
   `host_not_in_allowlist` for a healthy feed. Two hand-maintained copies of one list, one
   of them commented "could be DRYed", is the defect.
2. **Google News is unusable from Workers (28 feeds).** Every `news.google.com/rss/search`
   URL returned 503 to Worker egress. This also broke the **BleepingComputer mirror**
   (`bleepingcomputer` + `bleepingcomputer-breaches`, 503) and five other server-side
   consumers that fetched the same Google mirror. The catalog had already been partly
   amputated in response (`TechAiNews.tsx` had dropped its gnews feeds with a comment), but
   28 remained wired.
3. **HTTP 200 with an empty channel (3 feeds).** `hackread` data-breach category,
   `redhuntlabs.com/blog/feed/`, `vpnmentor` research category — all returned valid RSS
   shells with **0 items**. A status-code check passes them forever.
4. **Origins that refuse datacenter egress (4 feeds).** `securityweek` cybercrime category
   and `hackers-arise` → 403; `venturebeat.com` → 429 (even from a residential IP);
   `helpnetsecurity` → 200 with an unparseable empty body from the Worker.
5. **Silent catalog rot.** 3 duplicate ids (`huggingface-blog`, `the-decoder`,
   `deepmind-blog`), a FeedBurner URL that stopped syncing 6 months ago
   (`mandiant` — newest Apr 2026 while the blog published that week), and no check that
   catalog hosts are allowlisted at all.

Two more, outside the catalog:

- **Reddit starves its own tail.** With `DELAY_BETWEEN_MS=20s` against `MAX_RUN_MS=20min`,
  a throttled run truncates the list — but the order is fixed, so every published feed
  contained the **same first 8–9 subs**. `r/threatintel`, `r/Scams`, `r/phishing`,
  `r/scambait` and the forensics set were never fetched at all.
- **NVD drops out of the CVE aggregate.** Three parallel pages at a 12s timeout: NVD's
  published-CVE endpoint regularly takes longer, so all three rejected and
  `nvd-published-14d` reported `ok:false` — while `cve-health`'s single-request probe still
  said "NVD API reachable". It also never sent the already-configured `NVD_API_KEY`.

And the operator's specific question: **`radar.offseq.com` could not be added** for two
independent reasons — `https://radar.offseq.com/feeds` is an HTML directory page (Next.js app
shell, 45KB of markup, zero RSS items), and neither the host nor the feed path
(`/rss.xml`) was allowlisted. Fixing only the URL still fails on the host.

---

## DECISIONS

### 1. One allowlist, one file: `api/src/lib/feed-hosts.ts`

Both routes import it (`FEED_ALLOWED_HOSTS as ALLOWED_HOSTS`), so drift is impossible by
construction. 248 hosts: the union of both old copies, plus the three additions this pass
needed (`blog.trailofbits.com`, `www.bing.com`/`bing.com`, `radar.offseq.com`).
Every redirect hop is still re-validated against it — the SSRF guard is unchanged.

**Rejected:** adding only the missing hosts to the second copy. It fixes today's symptom and
guarantees the same one next quarter.

### 2. Google News → Bing News, everywhere

28 catalog feeds, the BleepingComputer mirror in both routes, and five server-side
consumers (`cti-collector`, `cybercrime-sources`, `breach-coverage`, `cyber-news-feeds`,
`case-study/discovery/{scam,intel}`, `ti-dashboard`, `snapshot`, `ironsight`, `argus-feed`).

Every query was tuned against live responses. Two Bing behaviours shaped the queries:

- **`OR` returns nothing.** `?q=a OR b OR c` yields 0 items; Bing ANDs the terms. Queries
  were simplified to their 1–3 strongest terms (`AI regulation governance policy`, not
  `AI regulation OR AI governance OR AI policy`).
- **Results are relevance-ranked, not date-ranked**, so `banking cyber` returned 2020
  articles. `qft=interval%3d%227%22` (7-day) or `%2230%22` (30-day) is now set per feed;
  all 28 were re-verified to return fresh items.

Bing wraps every link in an `apiclick.aspx` redirect. Items are unwrapped server-side in
`parseFeedBody` and client-side in `sanitizeUrl`, so cards link straight to the publisher.

**Rejected:** retiring the 28 feeds. The query surface (scam types, AI funding/acquisition,
banking/payment incidents) is load-bearing on Scam Watch, Tech & AI, Finance and the
dashboard; Bing keeps the pages populated. Also rejected: another aggregator proxy — one
more third party to rot.

### 3. Catalog repairs

| Feed                                               | Action                                                                             | Reason                                                            |
| -------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `hackread-breaches`                                | repoint → `hackread.com/feed/`                                                     | category feed is an empty channel                                 |
| `vpnmentor-research`                               | repoint → `vpnmentor.com/feed/`                                                    | research category is an empty channel                             |
| `securityweek-breaches`                            | repoint → `securityweek.com/feed/`                                                 | category feed 403s egress                                         |
| `helpnetsecurity`                                  | repoint → Bing `site:` mirror                                                      | origin serves an empty body to the Worker                         |
| `venturebeat-security`                             | repoint → Bing `site:` mirror                                                      | origin 429s all clients                                           |
| `mandiant`                                         | repoint → `security.googleblog.com/feeds/posts/default?alt=rss`                    | FeedBurner stopped syncing (6 months stale)                       |
| `redhunt-research`, `hackers-arise`                | **retired** + `RETIRED_FEEDS` entries                                              | feed dead since 2023 / 403s every client                          |
| `huggingface-blog`, `the-decoder`, `deepmind-blog` | duplicate entries removed                                                          | same id defined twice (deepmind kept the 100-item canonical feed) |
| `offseq-radar`                                     | **added** (`radar.offseq.com/rss.xml`, threat-intel, `landingThreatInvestigation`) | operator request                                                  |

`radar.offseq.com` is the one host added purely for a new feed; `radar.offseq.com/feeds`
stays uncalled, with a comment saying why.

### 4. `scripts/audit-rss-catalog.mjs` + a second CI job

The IOC registry had `audit-feed-health.mjs`; the RSS catalog had nothing, which is how all of
the above shipped. The new script checks statically (url parses, **host allowlisted**, no
duplicate ids, no dangling ids in the `landing*Feeds` lists) and live (status, HTML-shell
detection, item count, newest-item age). Wired into `.github/workflows/feed-health-audit.yml`
as a second job with the same non-zero-exit contract, and as `npm run audit:feeds:rss`
(`:rss:static` for the no-network variant).

Two deliberate design points:

- **A 45-day staleness verdict** catches the "200 but stopped publishing" class. Ten
  low-frequency publishers (`rekt-news`, `dfir-report`, `mandiant`, …) are documented in a
  `LOW_FREQUENCY` map with measured dates: they are _reported_ with `!`, never failed. A
  permanent red CI is how an audit gets ignored — the same argument the sibling script makes
  for key-gated endpoints.
- **Retries + 4-way concurrency** in the probe, because bursty probing of Bing/hnrss from one
  IP produces false failures.

### 5. Reddit: rotate the fetch order per time slot

`rotatedSubs()` offsets the queue by `floor(now / 30min) % SUBS.length`. Truncated runs then
truncate at a _different_ point each slot, so every sub is fetched early within a couple of
runs. Verified: 16/16 subs appear in the first 8 positions across 16 consecutive slots.
Pacing, cooldowns and the mass-throttle abort are unchanged.

### 6. NVD: send the key, wait longer, retry sequentially

`NVD_API_KEY` (already declared on `Env`, already used by `/api/v1/cisa-kev`) is now sent;
NVD-specific timeout 12s → 20s (cron-only path — `fetchRecentCves` has no request-path
caller); and when all three parallel pages fail, one sequential retry pass with a 1.5s gap
runs before giving up, because bursts are what trip the anonymous limiter.

---

## PHASE 2 — following up on the residual list

Same evidence method: live replay of the SPA's request path against the deployed
Worker, plus reading the code paths the probes surfaced.

### 1. A silent unwrap bug, caught by its own test

Every Bing item link is a click redirector. Unwrapping it is required in **nine**
parsers, and the first version of the helper failed on real bodies: Bing URLs
arrive XML-escaped (`…&amp;tid=abc&amp;url=…`), `URL` doesn't treat `&amp;` as a
separator, so `searchParams.get('url')` was `null` and the unwrap returned the
input unchanged. Items still rendered — they just linked through Bing's tracker.
The unit test in `api/test/lib/rss-parser.test.mjs` (added in the same change)
failed on the first run and caught it. The helper now decodes entities itself
before parsing, so no call site can get it wrong, and all nine parsers
(`feeds-aggregate`, `ironsight`, `cybercrime`, `rss-parser`, `cti-collector`,
`cyber-news-feeds`, `ti-dashboard`, `case-study/discovery/rss-util`, plus the
client `rssService` + ARGUS `FeedView`) route through one implementation.

### 2. Query windows are measured, not guessed

`ironsight` (strike + regional monitors) was **dead in production** — Google News
503s, so both handlers returned zero items and nothing errored. Migrating it to
Bing needed the right freshness window: for its multi-term conflict queries Bing
returns **0 items** at `qft=interval="1"` and relevance-ranked 4-month-old
articles at 30 days. Only 7 days both filters and fills (11 items, verified
against the live endpoint's own queries). Same exercise behind every one of the
28 catalog queries.

### 3. `/api/v1/onion-watch` returned `error code: 1102` on ~1 in 3 requests

Reproduced by replaying the request three times. Two causes, both fixed:

- **The fan-out sat on the subrequest ceiling.** 1 + 15 groups × up to 3 retry
  attempts + Cache-API ops ≈ 48 against a hard 50 per invocation; one slow or
  429-ing group tipped a third of cold builds into "Too many subrequests", which
  escaped as an opaque edge error. `TOP_N_GROUPS` 15 → 10 (worst case ~35;
  groups are ordered by most-recent activity, so the dropped tail is the least
  active).
- **No single-flight, and an unguarded build.** Concurrent cache misses each ran
  the whole fan-out, and an exception escaping `fetchOnionWatch` propagated out
  of the handler → the same bare 1102 instead of the route's own KV last-good
  path. Now: one shared in-isolate build (same idiom as `live-iocs.ts`), plus a
  `.catch` that degrades to last-good/502.

### 4. `/api/v1/stealer-forum-intel` cached a permanent zero

Chatter counts are read from the per-colo Cache-API entries the telegram-feed and
reddit-feed producers write. On a cold colo both reads miss → `matches: 0` →
and because the deepdarkCTI forum rows were non-empty, that zero-chatter payload
was still cached for the full 30 minutes. Readers saw "0 matches", which reads as
"no stealer chatter exists". Proof: warming both feeds and re-reading still
returned 0/0 (served from that cached payload) while an offline run of the same
regex over the same payloads found **2 telegram and 4 reddit** matches.

Now the build reports `warnings: ['chatter-source-missing:<platform>']`, the
handler serves those with a 5-minute TTL instead of 30 (`x-si-stale:
chatter-source-missing`) so they self-heal on the next request — the
`ttlFor()` pattern already used in `deepdarkcti`.

### 5. ARGUS kept its own copy of the source list — and diverged

The Worker proxy's allowlist (`worker/argus-feed.ts`) moved to the Bing mirror in
phase 1, but the view's own `RSS_SOURCES` (`src/pages/argus/views/FeedView.tsx`)
still requested the Google News URL, which the proxy no longer allows: that
source was silently dead, and no test or status page showed it. Caught by the new
static guard, which now asserts the two lists agree.

### 6. Regression guards (`scripts/feed-source-guard.test.mjs`, 7 tests)

Both phase-1 root causes came back from plausible one-line edits, so they are now
pinned: neither RSS route may declare its own allowlist; the shared list must
keep the three hosts added this pass; no runtime code may point at
`news.google.com/rss`; no catalog Bing query may contain `OR` (returns 0 items);
both routes must use the Bing BleepingComputer mirror; every Bing-consuming
parser must unwrap click links; and the ARGUS view list must match its proxy.
Comment-aware, so migration notes stay legal. Wired into `npm run test:feeds`
and chained into `npm run test:scripts`.

### Phase-2 verification

- `npm run audit:feeds:rss` → 137/137 healthy, 10 low-frequency, 2 synthesised, **exit 0**
- `npm run audit:feeds` → 44/46 healthy, 2 key-gated skips, **exit 0**
- root suite **1910/1910**, api suite **3335/3335**, feed-source guards **7/7**
- `typecheck` (src) clean; `typecheck:api` clean apart from one error inside a
  _concurrent_ uncommitted rename by another session (`api/src/lib/err.ts`
  importing `'../../src/lib/log'`), not from this work

---

## PHASE 3 — the two code-addressable residuals (GitHub quota, X surfaces)

### 1. Every `api.github.com` call on a health-critical surface now authenticates

Residual #1 (below) was diagnosed in phase 1 as _"the secret is unset"_, but that was
only half of it: of 23 files calling `api.github.com`, only 10 asked for the token at
all. The other 13 ran anonymously against one shared egress pool with a 60 req/hour
budget — which anything can exhaust, after which GitHub 403s _everyone_, feeding the
`sources_failed` counts in `cve-health`, the supply-chain card and the IOC surfaces.

- New `api/src/lib/github-api.ts` — one header builder (`githubHeaders`), one JSON
  fetch with rate-limit-aware diagnostics (`githubFetchJson`), and URL builders for the
  two shapes that were being hand-built (`advisoriesUrl`, `repoContentsUrl`). A 403 now
  says _"anonymous egress quota exhausted; set the GITHUB_TOKEN Worker secret"_ instead
  of a bare status code, and the helper deliberately does not retry a rate limit
  (retrying multiplies the load that caused it).
- Converted the CVE/supply-chain/IOC call sites: `cve-lookup` (GHSA advisories on the
  hot path), `global-pulse/fetchers` (the dashboard's only malware-advisory source while
  supplychainattack.org is 402-gated), `malware-iocs`, `maltrail`, `maltrail-sync`,
  `volexity-threat-intel`, `attack-flow-library`, `detection-rules`, `actor-enrich`, and
  the `lookupCve` callers (`unified-search`, `cve-batch`) that thread `env` in.
  `global-pulse`'s `BuildEnv` Pick was widened with `GITHUB_TOKEN` so the value actually
  flows rather than being cast in.
- **Still operator-gated:** with no secret set everything keeps working anonymously —
  the code fix means that when `wrangler secret put GITHUB_TOKEN` happens, every surface
  benefits instead of 10 of them.
- Guard: `scripts/github-auth-guard.test.mjs` (5 tests, `npm run test:github-auth`,
  chained into `test:scripts`) pins the converted files to `githubHeaders()`, pins the
  `lookupCve` env-threading, and pins the helper's token + diagnostic contract. The
  exemption set (profile-stats, email-enrichment, poc-scraper) is named in the test with
  reasons.

### 2. X: the live feed is healthy; the anonymous timeline was silently dead

Audited all three X surfaces against live upstreams:

- **`x-live` — healthy.** TweetFeed's `today.csv` was updated the same morning (32 rows)
  and `week.csv` holds 927; `fxtwitter` decoded a sampled status correctly; the deployed
  endpoint returned 5 enriched items in 1.5s.
- **`x-tweets` — silent zero, root-caused and fixed.** Three active accounts
  (briankrebs / vxunderground / malwrhunterteam) all returned `items: []` with the user
  profile resolved and no error. Reproducing the exact guest-token GraphQL flow locally
  showed why: X's anonymous timeline now serves a **frozen snapshot** — 99-100 tweets per
  account, _every one_ outside the 7-day window (newest ~1 year old). The freshness
  filter therefore always emptied, and the empty payload was then cached for 30 minutes.
  Fix: when the guest timeline is empty in-window, `x-tweets` now serves that account's
  recent items from the TweetFeed firehose (which is fresh and covers exactly the
  IOC-tweeting accounts the endpoint exists for), mapped into the unchanged response
  shape; if the handle isn't in the firehose the response says why
  (`stale_guest_timeline`, `newest_available_at`, `x-si-stale: guest-timeline-stale`) on
  a 5-minute window instead of pinning a bare zero for 30. Pinned by
  `api/test/routes/x-tweets.test.ts`.
- **`x-firehose` — public path correct** (400 without `handle` is the intended
  validation); the authenticated path returned 0 items from the live endpoint, but its
  credentials live only as Worker secrets, so the operator's admin `?status=deep` probe
  (which exists for exactly this, including the `qids: stale` classification) remains the
  verification step. Its route file is part of the concurrent uncommitted work and was
  not touched.

### 3. Route tests for the phase-2 fixes (behavioural, not static)

- `api/test/routes/onion-watch.test.ts` — asserts **one** upstream fan-out for two
  concurrent cold-cache requests (the single-flight), that a dead upstream yields the
  route's own 502 rather than an escaped exception, and that KV last-good is served with
  `X-SI-Stale`.
- `api/test/routes/stealer-forum-intel.test.ts` — asserts real match counts when both
  chatter feeds are seeded, per-source `chatter-source-missing` warnings when a feed is
  absent, and that degraded builds are never pinned for the full 30-minute window.
- Test-infrastructure gotcha discovered while writing these: **workerd's Cache API
  `put()` silently no-ops for responses without a `cache-control` header** (verified:
  put-without-cc → match miss, put-with-cc → hit). Seeding helpers must set one, or a
  "cold cache" test passes for the wrong reason.

### Phase-3 verification

- `api/test/routes/onion-watch.test.ts` + `stealer-forum-intel.test.ts` → 6/6 pass;
  `x-tweets.test.ts` → 2/2 pass; `github-auth-guard` → 5/5 pass
- X upstreams probed live 2026-10-17: TweetFeed 200 (32 + 927 rows, updated same day),
  fxtwitter 200, `x-live` 200 with 5 items, `x-tweets` fix verified by test
- `typecheck` (src) clean; `typecheck:api` clean on all files in this pass
- `npm run audit:feeds:rss` → **137/137 healthy**, 0 static problems, 9 low-frequency,
  2 skipped, exit 0 (re-run after bumping the body budget to 60s)
- `npm run audit:feeds` → **44/44 healthy**, 0 on fallback, 2 skipped, exit 0
  (re-run on the recovered link; the earlier 37KB/s link produced false timeouts)

---

## RESIDUAL RISKS / NOT DONE

1. **`GITHUB_TOKEN` secret is still unset in production** — the _code_ now sends it where
   it's available (phase 3), so the remaining step is purely
   `wrangler secret put GITHUB_TOKEN`; until then every surface still shares the
   anonymous quota. Deliberately not done here — minting a token and putting it in prod
   is the operator's call.
2. **X firehose authenticated health is unverified.** Its deep probe is admin-only
   (correctly — it spends operator credentials). Check
   `/api/v1/x-firehose?status=deep` signed in, or the `x-health-diagnostic` cron log. The
   anonymous timeline path is separately confirmed stale (phase 3), so if the
   authenticated path _also_ returns 0 items the same frozen-snapshot behaviour applies
   to the operator's session and the `qids` will need refreshing.
3. **X anonymous data now depends on TweetFeed coverage** — the rescue serves the ~7-day
   window the firehose holds and only for accounts it tracks. Handles outside it report
   the staleness explicitly but still return empty until X restores guest timelines.
4. **Bing is now a dependency**, and `qft` is honoured inconsistently (a 7-day window on one
   low-volume query returned 0 items; a 30-day window on another was ignored). The audit
   catches both; retune rather than re-migrate if Bing starts 503ing Worker egress.
5. **Catalog probes run from a workstation IP, not Worker egress.** That is how
   `helpnetsecurity`/`securityweek`/`venturebeat` slipped through: the probe sees them fine,
   the Worker does not. Post-deploy, re-run the live aggregator replay to confirm. (The CI
   `rss-catalog` job _does_ probe from datacenter egress — GH Actions runners — which is a
   much closer proxy than a workstation; treat a green CI run as that verification.)
6. Not audited in depth (out of scope of "feeds", no findings so far): `onion-watch`,
   `deepdarkcti`, `negotiations`, `stealer-forum-intel`, `breach-forums` — all read
   `feed-status` as `cold` from an unvisited colo, which is by design. (Phase 2 and 3
   subsequently covered `onion-watch` and `stealer-forum-intel`.)

## VERIFICATION

- `npm run audit:feeds:rss` → **137/137 probed feeds healthy**, 10 low-frequency reported,
  2 synthesised skipped, exit 0.
- `npm run audit:feeds` → 44/46 healthy, 2 key-gated skips, exit 0.
- `npm run typecheck`, `typecheck:api`, `typecheck:worker` → clean.
- `npm run test:run` → 145 files / **1892 tests passed**.
- prettier clean on all touched files; eslint clean (scripts are eslint-ignored by config).
- Before/after on the deployed aggregator: Trail of Bits `host_not_in_allowlist` → items; the
  28 gnews feeds `http_503` → items; hackread/vpnmentor `parser_zero_items` → items.
