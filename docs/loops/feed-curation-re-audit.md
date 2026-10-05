# Feed Curation Re-audit

**Category:** Reliability / scheduled

## Loop Description

Re-probe every registered IOC feed and confirm it still returns real indicator rows, then
update `api/src/lib/feed-curation.ts` with the result. Feed rot is invisible by default: a dead
upstream reports `ok:false`, the source quietly stops contributing, and nothing in the build
fails. That is how `webamon-campaigns` sat in the registry 403-ing on every build, and how
`threatbase` stayed wired after its upstream repo was deleted.

Distinct from **Feed Onboarding** (adding a feed) and **Add Provider** (per-IOC enrichment).
This loop only re-verifies what is already wired and records what changed.

## The two failure modes this catches

A status-code-only health check passes both of these, which is why a third-party catalogue
listing them as "Active" is not evidence they work:

1. **Dead** — non-2xx, DNS failure, connection reset.
2. **200 but not a feed** — an HTML page, a JS bundle, a ToS interstitial, or an empty stub.
   Four feeds were adopted from the community catalogue in this state (`ellio`, `netcraft`,
   `snort`, and the two `sslbl` IP lists) and contributed zero indicators forever.

## Cadence

Monthly, and before any bulk feed change. The 2026-10-05 full audit is the baseline.

## Guardrails

**Type:** Hardened with anti-gaming rules

- Do NOT treat HTTP 200 as healthy — verify the body has indicator rows and is not an HTML
  document. A "clean" audit that only checked status codes would have passed 4 broken feeds.
- Do NOT delete a `RETIRED_FEEDS` entry because a feed looks interesting again — re-probe it,
  confirm it returns real rows, then move it to `CURATED_FEEDS`. That list exists so a future
  sync does not re-introduce known-dead upstreams from a stale CSV.
- Do NOT add a key-gated or POST-only endpoint to the probe set expecting it to pass. Those are
  in `NOT_PLAIN_GET` and are skipped by design; leaving them probed means the audit reports
  failures forever and everyone learns to ignore it.
- Do NOT "fix" an unhealthy feed by loosening the probe. Either the URL is wrong, the upstream
  changed shape, or the feed is dead — all three need a registry change, not a threshold change.
- Do NOT raise the drift threshold (`rows < auditRows * 0.25`) to silence a collapse warning. A
  feed that shrank by more than 4x is a real signal about the upstream.

## Kickoff Prompt

```
Start the "Feed Curation Re-audit" loop.

Goal: Every registered feed returns real indicator rows, and feed-curation.ts reflects reality
Max iterations: 6
Between iterations run: npm run audit:feeds
Exit when: audit reports 0 unhealthy registered feeds AND every auditRows value matches the
           observed row count within the collapse threshold

Step 1: Run `npm run audit:feeds -- --json` and save the output as a baseline.
Step 2: For each unhealthy feed, classify it: dead / html-not-feed / empty-stub /
        negligible-volume. Fix by re-pointing the URL, adopting a replacement, or retiring.
Step 3: Update `auditRows` in api/src/lib/feed-curation.ts from the observed counts.
Step 4: Re-run `npm run audit:feeds` and confirm 0 unhealthy.
Step 5: Run `npm run audit:feeds:all` — any retired feed flagged RECOVERED is a candidate for
        re-adoption; re-probe it and decide.

Self-pace. Report the diff: feeds added, retired, re-pointed, and any row-count drift > 4x.
```

## Steps (Agent Actions)

1. **Probe** — `npm run audit:feeds -- --json` captures status, rows, bytes, HTML detection,
   and timing for every registered feed plus its fallback chain.
2. **Classify** — dead / html-not-feed / empty-stub / negligible-volume / key-gated-skipped.
3. **Act** — re-point, replace, or retire. Retiring means a `RETIRED_FEEDS` entry with the
   observed status in `note`; the drift test enforces that nothing retired stays registered.
4. **Re-audit** — confirm 0 unhealthy and update `auditRows`.
5. **Check the dead** — `npm run audit:feeds:all` for recovered retired feeds.

## Files

| File                                       | Role                                                                                                                                                              |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api/src/lib/feed-curation.ts`             | `CURATED_FEEDS` (verified-live), `RETIRED_FEEDS` (do-not-use), `DEMOTED_FEEDS` (still wired, low volume), `EXCLUDED_BY_DESIGN` (live but not discrete indicators) |
| `scripts/audit-feed-health.mjs`            | The probe. `npm run audit:feeds` / `:all`                                                                                                                         |
| `api/src/routes/live-iocs.ts`              | `FEED_SOURCES` registry; `FEED_SOURCE_DEBUG_URLS` mirror                                                                                                          |
| `api/test/routes/live-iocs-runner.test.ts` | Pins registry size/order, no duplicate ids, no registered retired URL, debug mirror coverage                                                                      |

## Related invariants

- **Registry size** — `live-iocs-runner.test.ts` pins `FEED_SOURCE_IDS.length`. Bump it on any
  add/remove.
- **Debug mirror** — every registry source needs an entry in `FEED_SOURCE_DEBUG_URLS`, or
  `?debug=1` reports "unreachable" for a working feed.
- **Subrequest budget** — the queue path is batched (6 sources/invocation) and is the primary
  refresh model. The synchronous cold-start fallback runs 45 sources against a 42-subrequest
  budget, so `priority: 1` feeds are ordered first in `CURATED_FEEDS`. See
  [ioc-subrequest-budget.md](./ioc-subrequest-budget.md).
