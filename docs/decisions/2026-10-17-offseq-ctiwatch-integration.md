# Decision: Integrate OffSeq Threat Radar + CTIWatch threat feeds

**Date:** 2026-10-17
**Status:** Implemented
**Owner:** Pranith
**Driver:** Reverse-engineer `radar.offseq.com` (incl. `/feeds`, `/threats`) and
`ctiwatch.com`, then integrate their threat feeds into the platform. REA was used
for the RE (browser scenarios + curl of discovered public endpoints); no REA
artifacts were committed to the repo.

---

## FINDINGS (evidence)

### OffSeq Threat Radar (`radar.offseq.com`)

- Next.js app. Public anonymous API the SPA itself calls:
  `GET /api/threats?limit=&page=&sort=-publishedDate&days=&type=`,
  `/api/threats/tags`, `/api/threats/stats/overview`, `/api/threats/countries/map`,
  `/api/threats/countries/detailed-map`. Anonymous tier advertises
  `x-ratelimit-limit-threats: 100` per window. Documented commercial tier at
  `/api/v1` with `X-API-Key` (free tier 30 req/hour per docs).
- `/rss.xml` (already in the catalog). Real-time socket feed ("[Socket] Connected
  to real-time feed").
- `/feeds` is a catalog page of ~40 aggregated upstream sources (NCSC UK, JVN,
  AWS, GCP, CERT/CC, Talos, Unit 42, OTX, ThreatFox MISP, Reddit subs, CVEs,
  …) with per-source counts — not an RSS feed (documented in
  `docs/decisions/2026-10-16-feed-health-pass.md`).
- Displayed stats: 152,613 unique / 6,759,292 events, 396 new/24h, 144,682
  AI-enriched. Each threat carries AI-generated summary/impact, KEV correlation,
  Mirage honeypot exploitation telemetry (`mirageIntel.exploited`, countries,
  services), Reddit previews, and source attribution.
- API response is paged (`pagination.total`/`pages`); `limit` is silently clamped
  to 25.

### CTIWatch (`ctiwatch.com`)

- Next.js App Router. API base `https://ctiwatch.com/api/v1`. Anonymous access
  works via a session cookie minted by loading any HTML page
  (`Set-Cookie: cti_anon=<signed>; Max-Age=86400`); replaying it against
  `/api/v1/*` returns 200. Free key `X-Api-Key: ctw_<64hex>` lifts quotas.
  Docs: `github.com/ctiwatch/docs` (`docs/en/api.md`).
- Observed (anonymous): 2.08M IOCs, 409k CVEs, 4.3k KEV, 10.9k threat actors,
  34.9k victims, 96 sources, rate `600;w=60` per IP.
- Single-value lookup: `/iocs/lookup?value=` (works; the documented `/check/{value}`
  route returns `{"error":"Not found"}` even for values present in the list —
  verified against two of their own rows, so `lookup` is the usable surface).
- `/search?q=` returns cross-domain results (IOCs + vulns + actors + articles).

### Existing repo state (gap analysis)

- `offseq-radar` RSS already in `src/data/rssFeeds.ts` (added 2026-10-16).
- `api/src/lib/ctiwatch.ts` committed client (session minting + optional key)
  used only by the CVE digest.
- IOC fan-out (`api/src/lib/ioc-providers.ts` + `api/src/providers/`) had no
  CTIWatch adapter; OffSeq's structured data (KEV, exploitation telemetry, AI
  summaries) was consumed nowhere beyond RSS.

## DECISIONS

1. **Two scopes, both shipped.** (a) Live integrations into existing surfaces
   (CTIWatch IOC provider + OffSeq client feeding the CVE digest + feed health),
   (b) full replicated verticals for both sources (threatcluster/dphish pattern:
   sync → staging → `public/data/threat-intel/<id>/` → manifest loaders → edge
   routes → MCP tools → SPA page → workflow). User selected both.
2. **CTIWatch IOC provider uses `/iocs/lookup?value=`**, not `/check/{value}` (broken
   upstream) and not `/search?q=` (heavier, cross-domain). Tier 1 (always runs),
   weight 3 for ip/domain/url/hash, 2 for email; session-cached auth + shared
   batched KV result cache; no per-provider cache ops (subrequest budget).
3. **OffSeq digest integration annotates by CVE id** (map built from
   `cveIds` extracted from `cveId`/tags/title/description), adding
   `offseq_exploited`, `offseq_url`, `offseq_count` and an `offseq-radar` source
   row. Optional params (`offseqByCve`/`offseqOk`) keep existing tests green when
   offseq isn't fetched.
4. **Verticals sampled, not full mirrors.** OffSeq: 200 recent threats (8 pages ×
   25). CTIWatch: 300 IOCs, 200 recent CVEs + 100 KEV, 200 actors, 200 victims,
   50 campaigns — sized to the static-asset budget (20k files cap) and the
   anonymous rate limits.
5. **CTIWatch staging stores raw records; build slims.** Keeps mapping logic in
   one place (build script + manifest types). IOCs/actors/campaigns served from
   index; vulnerabilities + victims get per-record bodies for the detail view.
6. **OffSeq `exploited` = `mirageIntel.exploited || knownExploitsInWild`.**
7. **No REA artifacts committed.** All RE scratch lives in the OS temp dir;
   integration code contains no REA references. Verified via `git grep`.

## CONSEQUENCES

- IOC checker gains ~2M IOCs (CTIWatch, confidence-graded, source-attributed).
- CVE digest gains in-the-wild exploitation telemetry neither ctiwatch nor NVD carry.
- Two new SPA pages (`/threatintel/feeds/offseq`, `/threatintel/feeds/ctiwatch`),
  5 MCP tools, 7 REST routes, both riding the daily sync workflow.
- Worker manifest test suite extended (124 tests, all green); `public/mcp-manifest.json`
  regenerated (423 tools).
- Anonymous rate limits respected; keys optional (`OFFSEQ_API_KEY`, `CTIWATCH_API_KEY`).
- `public/data/threat-intel/{offseq,ctiwatch}/` are committed (convention); staging
  dirs remain gitignored.
- Mirage exploitation flag is 0/200 in the first sample (rare upstream); digest
  `offseq_count` will reflect real hits as data refreshes.

## FILES

Live: `api/src/providers/ctiwatch.ts` (+ test), `api/src/lib/offseq.ts`,
`api/src/routes/cve-digest.ts`, `api/src/lib/confidence.ts`,
`api/src/routes/feed-status.ts`, `api/src/providers/{types,index}.ts`,
`api/src/lib/scoring.ts`, `api/src/env.ts`, `src/data/threatintel/external-resources.ts`.

Verticals: `scripts/sync-{offseq,ctiwatch}.mjs`, `scripts/build-{offseq,ctiwatch}.mjs`,
`worker/lib/threat-intel-manifest.ts`, `api/src/routes/threat-intel-edge-tools.ts`,
`worker/mcp-tools/ti-manifests.ts`, `src/pages/threatintel/{Offseq,Ctiwatch}.tsx`,
`src/App.tsx`, `src/data/{pages-index,threatintel-hubs}.ts`,
`.github/workflows/threat-intel-sync.yml`.

Docs: `CLAUDE.md` (new section), this decision doc.
