# CLAUDE.md

Guidance for agents working in this repo. Keep it short; deep context lives in
`docs/` and in the loop templates.

## Loop templates — read these first for recurring workflows

This repo encodes its recurring dev workflows as **loop templates** in
[`docs/loops/`](docs/loops/) (see [`docs/LOOP-ENGINEERING.md`](docs/LOOP-ENGINEERING.md)).
Each is a goal + max-iterations + a between-iteration check + an exit condition + anti-
gaming guardrails, designed to be driven by an agent (e.g. Claude Code's `/loop`). Before
deploying, editing a provider, touching a route, changing the IOC fan-out, etc., check
[`docs/loops/README.md`](docs/loops/README.md) for the matching loop — it carries this
repo's footguns so you don't rediscover them.

## Operational footguns (the short list)

- **Two wranglers.** Deploy from the **repo root** (`wrangler.jsonc` → Worker
  `pranithjain`), NOT from `api/`, for any frontend/prod change. `npm run deploy` from
  root. See [`docs/loops/deploy-from-root.md`](docs/loops/deploy-from-root.md).
- **esbuild deploys past `tsc`.** Workers bundle without a typecheck, so type errors
  accumulate invisibly and a single parse error masks the rest. Run all three projects:
  `tsc -p tsconfig.json`, `tsc -p api/tsconfig.json`, `tsc -p api/tsconfig.worker.json`.
  The per-edit hook checks api/src but skips `worker/`.
- **API route tests.** CI runs `test/routes/` as its own step (`api vitest (routes)`),
  no sandbox flag needed. External `/api/v1/*` reads are key-gated.
- **D1 binding is `BRIEFINGS_DB`** (database `pranithjain-briefings`), not `DB`.
  Migrations are immutable; add new ones via `/create-migration`; `--remote` is
  destructive.
- **Free-plan limits.** 50 subrequests per invocation (KV + Cache-API both count); the
  IOC fan-out must use one batched `primeBatch` + one `flushBatch`. Briefing self-heal
  runs its own `20 * * * *` cron, one build per invocation.
- **KV policy — Cache API first.** The free per-colo `caches.default` fronts every
  read-heavy request path; KV is the cross-colo durable layer only. Use the shared
  helpers, never hand-roll a third pattern: `kvBackedGet`/`kvBackedPut`
  (`api/src/lib/route-cache.ts`) for cached upstream data, `readLastGood`/`writeLastGood`
  (`api/src/lib/lastgood.ts`, `keyPrefix: ''` for legacy verbatim keys) for upstream-
  outage fallbacks, `routeCacheGet`/`routeCachePut` + evict-on-write for mutable blobs.
  Records that mutate need short shadow TTLs + evict-on-write (see
  `phishing-fingerprint.ts`, `feedback.ts`). Cross-colo correctness state stays on KV:
  bot offsets, one-time secrets, dedup/idempotency markers, queue cooldowns.
  Bulk reads: `kvBulkGetText` (`api/src/lib/safe-catch.ts`) — one subrequest per ≤100
  keys; batch `get(keys[])` over per-key loops.
  **Guardrail:** the `no-raw-kv-access` ESLint rule (error) enforces this — raw KV
  ops outside `eslint-rules/kv-policy.js`'s allowlist fail lint. Add a file there
  only as a conscious decision; prefer the helpers.
- **`main` moves fast.** Feature branches auto-FF-merge into `main` mid-session; commit on
  a branch and let it merge — never rebase/force-push/`branch -f main`. Re-check the
  current branch before any git mutation. Rebase onto `origin/main` right before
  deploying.
- **MCP server** (`worker/mcp-server.ts`, `/api/mcp`) is mirrored to the standalone repo
  `dfir-mcp-server` via branch + PR.
- **19 generators are manual-only** — no npm script, no workflow reference. Their output is
  still live and served from `public/data/`, so editing generated JSON by hand works but the
  next run silently reverts it. See the inventory below before hand-editing anything under
  `public/data/`.

## Data generators — which ones run on their own

`public/data/**` is committed, not built (see the footgun above about `ci.yml` using
`build:client`). That splits the generators into three groups:

**Automatic — `prebuild` runs these on every build.** Safe to treat as derived; never
hand-edit, because the next build overwrites you.

    build-breach-watch  build-mcp-manifest  build-llms-full  build-sitemap
    generate-og-png  generate-og-version  build-og-overrides  extract-wiki-meta
    build-telegram-actor-catalog  sync-tesseract-assets

**Automatic — CI-only.** A scheduled workflow fetches upstream and auto-merges the result
back to `main`. Locally you have no generator; the committed JSON _is_ the deliverable.
(`ai-security`, `ai-threats`, `anarchy`, `apt-actors`, `cairn`, `capec`, `car`, `cert-in`,
`cti-bookmarks`, `daily-briefs`, `denali`, `detection-wiki`, `engage`, `hijacklibs`,
`lots`, `malapi`, `nova`, `pcmedicalist`, `ransomware-groups`, `si`, `sigbase`, `veris`,
`webamon-dtb`, `winreg`, and all of `threat-intel/*`.)

**Manual — run the script yourself.** These have no npm alias; invoke by path. The first
group reads curated input that _is_ committed, so they are offline and deterministic.

| Script                                               | Reads                                                           | Writes                                    |
| ---------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------- |
| `build-cloak.mjs`                                    | `scripts/data-src/cloak/`                                       | `public/data/cloak/`                      |
| `build-cloud-ref.mjs`                                | `scripts/data-src/cloud-ref/`                                   | `public/data/cloud-ref/`                  |
| `build-dfir-ref.mjs`                                 | `scripts/data-src/dfir-ref/`                                    | `public/data/dfir-ref/`                   |
| `build-grc-manifest.mjs`                             | `scripts/data-src/grc/`                                         | `public/data/grc/`                        |
| `build-hunt-hypotheses.mjs`                          | `scripts/data-src/hunt-hypotheses/`                             | `public/data/hunt-hypotheses/`            |
| `build-pqc.mjs`                                      | `scripts/data-src/pqc/`                                         | `public/data/pqc/`                        |
| `build-siem-library.mjs`                             | `scripts/data-src/siem-library/`                                | `public/data/siem-library/`               |
| `build-campaigns-manifest.mjs`                       | inlined in the script                                           | `public/data/campaigns/`                  |
| `build-reports-manifest.mjs`                         | inlined in the script                                           | `public/data/reports/`                    |
| `build-osint-manifest.mjs`                           | inlined in the script                                           | `public/data/osint/`                      |
| `build-threat-monitor.mjs`                           | `src/data/threat-monitor/`                                      | `public/data/threat-monitor/`             |
| `build-actor-kb.mjs`                                 | `src/data/dfir/`                                                | `src/data/dfir/actor-kb.ts`               |
| `generate-mitre-matrix.mjs`                          | MITRE STIX (**network**)                                        | `src/data/dfir/mitre-matrix.ts`           |
| `generate-osint-countries.mjs`                       | (**network**)                                                   | `src/data/threatintel/osint-countries.ts` |
| `fetch-powershell-analyzer.mjs`                      | (**network**)                                                   | `src/lib/dfir/powershell-analyzer.ts`     |
| `build-attack-index.mjs`                             | MITRE STIX (**network**)                                        | `public/data/attack-id-index.json`        |
| `build-oss-feeds.mjs`                                | `threat-intel-staging/oss-feed-registry/` (**untracked input**) | `public/data/oss-feed-registry/`          |
| `sync-frameworks.mjs`                                | (**network**)                                                   | `public/data/frameworks/tid-cmm/`         |
| `sync-oss-feeds.mjs`                                 | (**network**)                                                   | `threat-intel-staging/oss-feed-registry/` |
| `generate-avatar.mjs`, `generate-linkedin-cover.mjs` | design sources                                                  | profile assets                            |
| `build-tools-manifest.mjs`                           | rewrites its own `index.json` in place                          | `public/data/tools/index.json`            |

Two traps worth knowing: `build-oss-feeds.mjs` reads a **gitignored** staging dir, so the
committed output is the only copy — run `sync-oss-feeds.mjs` first or you get an empty
build. And `build-tools-manifest.mjs` is simultaneously source-of-truth and output, so it
edits the file it reads.

**Parked, not dead.** `scripts/codegen.mjs` (`npm run codegen`) is functional but cannot
succeed: `api/src/lib/openapi.ts` builds a full spec that no route mounts, so the fetch
returns 401. `src/lib/api-types.ts` does not exist and nothing imports it. Mounting
`/api/v1/openapi.json` re-enables it — but that route enumerates the whole API surface, so
treat exposing it as a deliberate decision.

## Runtime loop engine

The investigator agent is built on a small generic loop engine
(`api/src/lib/agent/loop-engine.ts` + `cti-loop.ts`); its behavior is pinned by
`api/test/lib/loop-engine.test.ts`. Keep that parity test green when changing exit
conditions or guardrails. See [`docs/LOOP-ENGINEERING.md`](docs/LOOP-ENGINEERING.md).

## Security Investigator (replicated) — edge MCP tools

The Worker exposes the replicated SCStelz/security-investigator content (25 Agent
Skills + 45 KQL queries + 3 automations) as 6 MCP tools on the existing
`DFIR_MCP` Durable Object. The data lives in `public/data/si/` (slim index + per-slug
bodies) and is read back at runtime through `env.ASSETS` — no public internet hop.

| Tool                | Purpose                                           |
| ------------------- | ------------------------------------------------- |
| `si_list_skills`    | List the 25 skills, filter by category/keyword    |
| `si_get_skill`      | Return full SKILL.md body (markdown) for a slug   |
| `si_list_queries`   | List the 45 KQL queries, filter by domain/keyword |
| `si_get_query`      | Return full KQL query body (markdown) for a slug  |
| `si_get_automation` | Return a scheduled-workflow definition (3 ship)   |
| `si_stats`          | Cache + manifest stats for cold-start diagnosis   |

**Files**:

- `worker/lib/si-manifest.ts` — loader (LRU body cache, 200 entries, in-memory index)
- `worker/lib/si-manifest.test.ts` — 12 unit tests (run via `npx vitest run worker/lib/si-manifest.test.ts`)
- `worker/mcp-server.ts` — 6 new `this.server.tool(...)` registrations
- `public/data/si/` — `index.json` (37 KB) + `skills/*.json` + `queries/*.json` + `automations/*.json` (3.2 MB total)
- `scripts/build-si-manifest.mjs` — regenerates `public/data/si/` from `security-investigator-replication/` (transient sparse clone — run `scripts/sync-si-from-upstream.mjs` first if the folder is absent; it is NOT committed)

**Source**: `github.com/SCStelz/security-investigator` (MIT, 210★). Bodies are raw
markdown — clients should render markdown themselves. The replication folder is a
transient local clone (not tracked in git) recreated by the sync script; the MCP
tools read the same data via `env.ASSETS` from `public/data/si/`, never from the
folder directly. The weekly `si-upstream-sync.yml` runs sync + build, so a fresh
checkout never needs the folder until someone rebuilds locally.

**To rebuild the data** after editing upstream: `node scripts/build-si-manifest.mjs`
**To re-fetch from upstream**: `node scripts/sync-si-from-upstream.mjs && node scripts/build-si-manifest.mjs`

### Extended content types (round 2)

| Tool                          | Purpose                                                                                                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `si_render_svg_dashboard`     | Return the SVG widget manifest (YAML) for a skill that ships one (14 of 25). Pair with `si_get_skill({slug: 'svg-dashboard'})` for the component library.             |
| `si_list_docs` / `si_get_doc` | Browse + retrieve the 10 upstream knowledge-base docs (Sentinel Exposure Graph guide, signinlog KQL cookbook, identity protection, honeypot, ingestion cost, etc).    |
| `si_get_routing_prompt`       | Return the upstream `.github/copilot-instructions.md` (91 KB) verbatim — the universal skill-detection prompt. Load once at session start.                            |
| `si_list_ref` / `si_get_ref`  | Retrieve 14 reference datasets: MITRE ATT&CK catalog (32 KB), known KQL tables (17 KB), M365 platform coverage (16 KB), and 11 Sentinel ingestion-scan query schemas. |

**Data layout** (107 files, 4.2 MB total):

- `public/data/si/index.json` (~40 KB) — slim manifest for skills/queries/automations
- `public/data/si/skills/<slug>.json` — 27 files; 14 include an embedded `svgWidgetsYaml` field
- `public/data/si/queries/<slug>.json` — 45 KQL files
- `public/data/si/automations/<slug>.json` — 3 workflow definitions
- `public/data/si/docs/<slug>.md` — 10 long-form KB docs
- `public/data/si/docs-index.json` — slim doc index
- `public/data/si/routing-prompt.md` — 91 KB routing prompt
- `public/data/si/ref/<name>.json` — 14 reference datasets
- `public/data/si/scripts/<name>` — 5 PowerShell + detection-manifest assets (360 KB)

### Extended SI tools (rounds 3–4)

| Tool                 | Purpose                                                                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `si_enrich_ip`       | Enrich a single IP through existing platform providers (ipinfo, abuseipdb, shodan, shodan-internetdb, vpnapi) — output shape matches upstream `enrich_ips.py`. |
| `si_enrich_ip_batch` | Same, up to 25 IPs in parallel.                                                                                                                                |
| `si_kql_to_ah_url`   | Encode a KQL query to a Defender XDR Advanced Hunting deep link (UTF-16LE → GZip → Base64url). TS port of `kql_to_ah_url.py`.                                  |
| `si_list_scripts`    | List the 5 PowerShell / detection-manifest assets.                                                                                                             |
| `si_get_script`      | Return the raw body of a script.                                                                                                                               |
| `si_render_svg`      | Server-render an SVG dashboard from a JSON manifest (14 widget types).                                                                                         |
| `si_render_png`      | Rasterise a dashboard to PNG (base64 in the MCP text field). Uses bundled `@resvg/resvg-wasm` + Hanken Grotesk TTF.                                            |

**HTTP routes**: `GET /api/v1/si/render?slug=…&format=svg|png`, `POST /api/v1/si/render` with JSON/YAML manifest.

**Key modules**: `worker/lib/si-svg-renderer.ts`, `worker/lib/si-svg-png.ts`, `worker/lib/si-rate-limit.ts`, `api/src/lib/si-yaml-mini.ts`, `src/lib/security-investigator.ts` (typed client).

**Weekly sync**: `.github/workflows/si-upstream-sync.yml` re-runs sync + build every Monday 06:00 UTC; opens a PR if `public/data/si/` changed.

**MCP tool inventory**: 283 tools total across the `DFIR_MCP` Durable Object — DFIR/threat-intel tools (`check_ioc`, `lookup_cve`, `enrich_actor`, `lookup_domain`, etc.) + SI tools (`si_*`) + threat-intel vertical (`ti_*`) + NHI scanner (`nhi_*`) + depx (`depx_*`) + winreg (`winreg_*`) + HudsonRock (`hr_*`) + Telegram (`tg_*`) + workspace/notebook (`ws_*`, `notebook_*`) + passive DNS + IOC watchlist + report analysis + more. Regenerate `public/mcp-manifest.json` + `public/mcp/README.md` + `public/llms-full.txt` with `node scripts/build-mcp-manifest.mjs && node scripts/build-llms-full.mjs`.

## Threat Intel vertical — CVE/KEV/IOC/sector brief (v1)

A second data vertical replicating the SI pattern (`public/data/threat-intel/`, weekly cron sync, slim-index + per-slug JSON bodies read through `env.ASSETS`). Three upstream references feed the design:

| Source                                                                    | What it brings                                                                     | License    |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ---------- |
| [OpenThreat](https://github.com/hoodinformatik/OpenThreat)                | NVD + CISA KEV ingest, priority scoring (AGPL — design ref only, no code vendored) | AGPL-3.0   |
| [cyber_threat_intel](https://github.com/NarendraKarki/cyber_threat_intel) | Sector briefing pipeline (Financial/Healthcare/Government)                         | MIT        |
| [Daily-Hunt](https://github.com/TheRavenFile/Daily-Hunt)                  | 130+ IOC families (ransomware/malware/APT) as a knowledge base                     | Unlicensed |

**Decision doc**: `docs/decisions/2026-06-29-threat-intel-vertical.md`

**6 MCP tools** (new `ti_*` namespace, registered on `DFIR_MCP`):
`ti_list_cves`, `ti_get_cve`, `ti_list_kev`, `ti_list_iocs`, `ti_get_ioc`, `ti_brief_sector`, `ti_stats`

**9 REST routes** under `/api/v1/threat-intel/*` — all read-only, key-gated.

**1 SPA route** at `/threat-intel` (lazy, 4 tabs: CVEs / KEV / IOC Families / Sector Briefs).

**Files**:

- `worker/lib/threat-intel-manifest.ts` — LRU loader + filter helpers + priority scoring
- `worker/lib/threat-intel-manifest.test.ts` — 52 unit tests
- `scripts/sync-threat-intel.mjs` — NVD + CISA KEV + Daily-Hunt fetch
- `scripts/build-threat-intel.mjs` — normalize + score + slice into per-slug JSON
- `worker/mcp-server.ts` — 7 `ti_*` tool registrations
- `api/src/routes/threat-intel-edge-tools.ts` — 9 REST route handlers
- `api/src/lib/threat-intel-manifest.ts` — symlink to `worker/lib/threat-intel-manifest.ts`
- `src/pages/ThreatIntel.tsx` — SPA dashboard
- `.github/workflows/threat-intel-sync.yml` — daily sync workflow (05:30 UTC). Each sync/build
  step is isolated with `continue-on-error` so one flaky upstream (NVD times out under load)
  never aborts the other verticals; covers threat-intel, darknetlist, ThreatCluster, dPhish,
  Living Threat, MalwareAnalyzer, and Threaticon (main vertical, 1 req/s pacing).
- `docs/loops/threat-intel-sync.md` — loop template for manual sync
- `public/data/threat-intel/` — generated manifest tree (not committed empty; populate via sync + build)

**Sync pipeline** (matches `si-upstream-sync.yml` pattern):

```bash
node scripts/sync-threat-intel.mjs   # fetches NVD recent + CISA KEV + Daily-Hunt
node scripts/build-threat-intel.mjs  # slices into public/data/threat-intel/
```

**To rebuild**: `node scripts/sync-threat-intel.mjs && node scripts/build-threat-intel.mjs`

**Tests**: 52 vitest tests in `worker/lib/threat-intel-manifest.test.ts`

### Darknetlist — Tor Site Directory (darknetlist.is)

A live directory of Tor-accessible sites from [darknetlist.is](https://darknetlist.is/),
integrated as a sub-vertical of the threat-intel platform. A scanner on the
upstream server walks the list through a fresh SOCKS circuit every 30 minutes
and rewrites the page with whatever responded. 108 sites across 9 categories
(markets, search, forums, news, security, comms, crypto, tools, AI), each with
live up/down status, onion URLs, response codes, and fingerprints.

**3 MCP tools** (registered on `DFIR_MCP`):
`ti_list_darknet`, `ti_get_darknet_site`, `ti_get_darknet_category`

**5 REST routes** under `/api/v1/threat-intel/darknet/*`:
`GET /darknet`, `GET /darknet/sites`, `GET /darknet/sites/:slug`,
`GET /darknet/categories`, `GET /darknet/categories/:category`

**1 SPA route** at `/threatintel/darkweb/darknetlist`.

**Files**:

- `scripts/sync-darknetlist.mjs` — fetch + parse darknetlist.is HTML into staging JSON
- `scripts/build-darknetlist.mjs` — slice staging into `public/data/threat-intel/darknet/`
- `worker/lib/threat-intel-manifest.ts` — darknet types + loader + filter helpers (same file)
- `worker/mcp-server.ts` — 3 `ti_*darknet*` tool registrations
- `api/src/routes/threat-intel-edge-tools.ts` — 5 darknet REST route handlers
- `src/pages/threatintel/DarknetList.tsx` — SPA page at `/threatintel/darkweb/darknetlist`
- `public/data/threat-intel/darknet/` — generated manifest tree (index + categories + sites)

**To rebuild**: `node scripts/sync-darknetlist.mjs && node scripts/build-darknetlist.mjs`

**Data layout**:

- `public/data/threat-intel/darknet/index.json` — slim index (categories + sites)
- `public/data/threat-intel/darknet/categories/<id>.json` — 9 category bodies with sites
- `public/data/threat-intel/darknet/sites/<dwd-id>.json` — 108 per-site bodies

### ThreatCluster — Trending Clusters, CVEs, Exploits, Dark-Web Victims, IOC Blocklist

A feed vertical replicating 5 public feeds from [threatcluster.io](https://threatcluster.io/feeds)
(hourly refresh, no API key): top-50 trending threat clusters (7d), CVE vulnerability feed (7d),
exploits with public PoCs (30d), ransomware leak-site victims (14d), and a high-confidence
domain/IP blocklist (30d). Plus a slim MISP manifest pass-through. The SmartNews feed is
deliberately skipped (same clusters, only for news-aggregator submission).

**6 MCP tools** (registered on `DFIR_MCP`): `tc_feed`, `tc_get_cluster`, `tc_get_cve`,
`tc_list_victims`, `tc_list_iocs`, `tc_list_misp_events`

**11 REST routes** under `/api/v1/threat-intel/threatcluster/*`:
`/`, `/clusters`, `/clusters/:slug`, `/vulnerabilities`, `/vulnerabilities/:cveId`,
`/exploits`, `/exploits/:cveId`, `/victims`, `/victims/:id`, `/iocs`, `/misp`

**1 SPA route** at `/threatintel/feeds/threatcluster` (6 tabs: Trending Clusters /
Vulnerabilities / Exploits / Dark Web Victims / IOC Blocklist / MISP Events; IOC tab has
copy-all for pfSense/Pi-hole blocklists).

### ThreatCluster Entity Intelligence (sub-vertical)

Derived entity profiles from ThreatCluster data — threat actors (MISP galaxy attribution),
ransomware groups + sectors (dark-web victims), malware families (Daily-Hunt dictionary
matching), CVEs (feed + cluster-text regex). **Deterministic build-time extraction — no LLM.**
Each profile: first/last seen, mention frequency by day, recent activity, weighted
co-occurrence relationship graph, MITRE techniques (groups also carry their victim list).

**8 MCP tools** (6 above + `tc_list_entities`, `tc_get_entity`)

**3 REST routes** under `/api/v1/threat-intel/threatcluster/entities*`:
`GET /entities` (q, type, min_mentions, limit → flat list with counts),
`GET /entities/:type`, `GET /entities/:type/:slug` (activity_limit)

**1 SPA route** at `/threatintel/feeds/threatcluster/entities` (explorer + profile with
frequency chart, relationship chips, victim table).

**Files**:

- `scripts/sync-threatcluster.mjs` — fetches + regex-parses the RSS feeds + IOC JSON into `threat-intel-staging/threatcluster/`
- `scripts/build-threatcluster.mjs` — slices staged data into `public/data/threat-intel/threatcluster/`
- `scripts/build-tc-entities.mjs` — entity extraction pipeline → `entities/` tree (index + 5 type dirs)
- `worker/lib/threat-intel-manifest.ts` — `loadThreatClusterIndex`, `getTcCluster/Vuln/Exploit/Victim`, `loadTcIocs`, `loadTcMispEvents`, `filterTc*` helpers + `loadTcEntities`/`getTcEntity`/`filterTcEntities`/`getTcEntityTypeOrNull` (same file as darknet)
- `worker/mcp-server.ts` — 6 `tc_*` tool registrations (+2 entity tools)
- `api/src/routes/threat-intel-edge-tools.ts` — 11 route handlers (+3 entity routes)
- `src/pages/threatintel/ThreatCluster.tsx` — SPA page
- `src/pages/threatintel/ThreatClusterEntities.tsx` — SPA entity explorer
- `public/data/threat-intel/threatcluster/` — generated tree (index + clusters/ + vulnerabilities/ + exploits/ + victims/ + iocs.json + misp.json + entities/)

**To rebuild**: `node scripts/sync-threatcluster.mjs && node scripts/build-threatcluster.mjs && node scripts/build-tc-entities.mjs`

**To re-run entity extraction only**: `node scripts/build-tc-entities.mjs` (reads staging + feeds from `public/data/threat-intel/threatcluster/`)

**Data layout**:

- `index.json` — slim index (counts, feed metadata, lastBuildDates, per-feed slim arrays)
- `clusters/<slug>.json` — 50 trending cluster bodies (title, source count, description w/ key points)
- `vulnerabilities/<cve-id>.json` — 50 CVE bodies
- `exploits/<cve-id>.json` — ~50 exploit bodies (severity, KEV flag)
- `victims/<id>.json` — 50 victim bodies (group, sector, country)
- `iocs.json` — whole IOC blocklist (38+ indicators with sources)
- `misp.json` — slim MISP manifest pass-through (uuid, title, tags, threat level)

### Threaticon — Threat-Actor Catalog, Malware Dictionary, Detection Coverage, Threat Map

A replicated vertical from [threaticon.com](https://threaticon.com) (STIX 2.1/TAXII
platform, public server-rendered preview, no API key): ~1,500 threat-actor profiles,
~9,200 malware family entries, an ATT&CK detection-coverage dataset (493 techniques /
13 tactics with per-technique rule counts), and a country-level threat map
(actor origins × targeted countries × sectors). Also feeds the ThreatCluster entity
dictionary (malware family names merged at build time).

**3 MCP tools** (registered on `DFIR_MCP`): `ti_list_threaticon_actors`,
`ti_get_threaticon_actor`, `ti_threaticon_coverage`

**6 REST routes** under `/api/v1/threat-intel/threaticon/*`:
`/` (index + counts + cache), `/actors` (q, type, country, tlp, status, has_mitre, limit),
`/actors/:slug`, `/malware` (category, q, min_confidence, limit), `/coverage`
(tactic, min_rules, q, limit), `/map`

**1 SPA route** at `/threatintel/feeds/threaticon` (9 tabs: Threat Actors / Malware /
Detection Coverage / Threat Map / Campaigns / Attack Patterns / Vulnerabilities /
Controls Catalog / Indicators; actor + catalog cards expand to full bodies on
demand — never fetch details for closed cards, the upstream rate bucket is ~30
requests/min and a full-profile storm 429s every list fetch).

**Files**:

- `scripts/sync-threaticon.mjs` — fetches coverage + malware + actor list pages (`?page=N`) + actor details (sitemap ids) into `threat-intel-staging/threaticon/`; resumable, 429 backoff, `--skip-details`/`--malware-pages N`/`--actors-pages N`/`--actors-limit N`/`--concurrency N`
- `scripts/build-threaticon.mjs` — slices staging into `public/data/threat-intel/threaticon/` (index + actors/ + malware.json + coverage.json + map.json)
- `worker/lib/threat-intel-manifest.ts` — `TiThreaticon*` types + `loadThreaticonIndex`/`getThreaticonActor`/`loadThreaticonMalware`/`loadThreaticonCoverage`/`loadThreaticonMap` + `filterThreaticon*` helpers; `tiCacheStats().threaticon`
- `worker/lib/stix-export.ts` (+ symlink `api/src/lib/stix-export.ts`) — STIX 2.1 bundle builder with deterministic UUIDv5 ids
- `worker/mcp-server.ts` — 3 `ti_*threaticon*` tool registrations; `api/src/lib/agent/mcp-bridge.ts` mirrors
- `api/src/routes/threat-intel-edge-tools.ts` — 6 threaticon route handlers + `GET /threat-intel/export/stix` (STIX 2.1 bundle, `include`/`max`/`download` params)
- `src/pages/threatintel/Threaticon.tsx` — SPA page
- `public/data/threat-intel/threaticon/` — generated tree

**To rebuild**: `node scripts/sync-threaticon.mjs && node scripts/build-threaticon.mjs`

**Data layout**:

- `index.json` — slim actor index + counts + per-tactic coverage summary
- `actors/<slug>.json` — full actor profiles (MITRE ID, types, origin, confidence, aliases, sectors/countries, tactics/techniques, tools, IOC patterns, key capabilities, campaigns)
- `malware.json` — family dictionary (name, category, TLP, confidence, status) — consumed by `build-tc-entities.mjs`
- `coverage.json` — 493 techniques (patternId, techniqueId, name, tactic, rules) + per-tactic coverage %s
- `map.json` — origin/targeted country counts + sector counts

**Upstream quirks tolerated**: dirty origin values ("R"), dominant Type "Unknown",
future-ish "added" dates (platform test/seed data). Parser notes live in
`scripts/sync-threaticon.mjs` (section-boundary scoping for actor details).

## Ransomware Groups directory (Sinon-style reference)

`public/data/ransomware-groups/` (built, committed): `index.json` (620 slim rows,
rows with bodies carry a `shard` pointer) + `groups/shard-NNNN.json` maps for
active/profiled groups (capped 200 bodies, 16/shard — sharded because per-slug
files pushed dist/ over the 20k static-asset cap). Clearnet
aggregation only — Ransomlook group list + deep-recent victims + ransomware.live
dump; leak-site _status_ from Ransomlook reachability probes (Workers cannot
egress via Tor, same constraint as `onion-watch.ts`).

- `scripts/sync-ransomware-groups.mjs [--enrich 30]` → `threat-intel-staging/ransomware-groups/`
- `scripts/build-ransomware-groups.mjs` → `public/data/ransomware-groups/`
- `worker/lib/ransomware-groups-manifest.ts` (+ `api/` symlink) — loader + filters
- `api/src/routes/ransomware-groups.ts` — 4 REST routes under `/api/v1/ransomware-groups/`
- `src/pages/threatintel/RansomwareGroups.tsx` — SPA at `/threatintel/ransomware-groups`
- `.github/workflows/ransomware-groups-sync.yml` — weekly sync + PR

## AI Escape Watch (agent containment-failure registry)

`public/data/ai-escape/` (built, committed): `index.json` + `incidents/<id>.json`
(15) + `guardrails.json` (10) + `trackers.json`. Curatorial seed
(`threat-intel-staging/ai-escape/seed.json`) — summaries are original
condensations of cited sources, disputed figures flagged never averaged, every
entry needs ≥1 source. New disclosures land via PR (reviewed before publish);
no sync script by design. CBS v0.1 is a draft scale — scorer is curated data,
not computed.

- `scripts/build-ai-escape.mjs` — fail-closed validation (klass/sev/tier/cbs/chain/sources)
- `worker/lib/ai-escape-manifest.ts` (+ `api/` symlink) — loader + `filterEscapes` + timeline buckets
- `api/src/routes/ai-escape.ts` — 6 REST routes under `/api/v1/ai-escape/`
- `src/pages/threatintel/AiEscape.tsx` — SPA at `/threatintel/ai-escape`
- Community report queue: `migrations/0045_ai_escape_reports.sql` (D1
  `ai_escape_reports`: pending → approved/rejected, review note kept) +
  `POST /api/v1/ai-escape/reports` (strict validation, honeypot,
  best-effort 5/day/IP Cache-API throttle — review gate is the defense) +
  `GET /reports` (public queue) + admin `POST /reports/:id/review`
  (`ADMIN_TOKEN` via `requireAdmin`). Form + queue live on the SPA;
  approved entries are promoted into `seed.json` via PR (no auto-publish).

## Destroylist — Phishing & Scam Domain Blacklist

A replicated vertical from [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)
(MIT): ~193k curated primary phishing/scam domains plus a 13+ source community
aggregate (~1M). **Primary ships as 64 hash-bucketed sorted domain arrays**
(`public/data/threat-intel/destroylist/buckets/`) — membership = one ASSETS
fetch + binary search, LRU-cached per isolate. The community aggregate is NOT
shipped (23MB); it stays reachable through the keyless `api.destroy.tools`
live lookup with a 24h per-colo Cache-API shadow.

**2 MCP tools** (registered on `DFIR_MCP`): `dl_check_domain`, `dl_stats`

**5 REST routes** under `/api/v1/threat-intel/destroylist/*`:
`/` (index+counts+cache), `/check?domain=`, `POST /check` (bulk ≤100),
`/search?q=` (root-domain substring), `/roots.txt` (Pi-hole/AdGuard-ready
subscription, 6h edge cache)

**1 provider adapter** (`destroylist`, tier 1, domains/URLs) in the IOC
fan-out — local manifest first, live API only on primary miss.

**1 SPA route** at `/threatintel/feeds/destroylist`.

**Files**: `scripts/sync-destroylist.mjs` + `build-destroylist.mjs`,
manifest loaders in `worker/lib/threat-intel-manifest.ts`
(`checkDestroylistDomain`, bucket djb2 hash MUST stay in sync with the build
script), provider `api/src/providers/destroylist.ts`, routes in
`api/src/routes/threat-intel-edge-tools.ts`, SPA `src/pages/threatintel/
Destroylist.tsx`. Daily sync rides `.github/workflows/threat-intel-sync.yml`.

## Content-generation system (/admin)

The pipeline is **RESEARCH → WRITE → NORMALISE**. The research stage
(`api/src/case-study/research/`) fetches and reads the candidate's real
source pages, resolves its CVEs against NVD/CISA KEV/FIRST EPSS/public-PoC
indexes, queries the platform's own corpus, and writes down what it could NOT
establish. That dossier — not raw evidence JSON — is what the writer sees.

This replaced two things that were actively causing bad output:

- **Quality scoring.** `postProcess` used to score length, section count,
  sentences-per-section, a keyword match against a "technical terms" list,
  and a filler-phrase penalty, then fail the publish below 45/100. The
  cheapest way to pass was to write more sentences, which is exactly the
  padding the rules existed to prevent. Removed; `Post.audit` now records
  factual counters (words, sections, references, IOCs, warnings) for the
  human reviewing the draft.
- **Slop detection.** `EGREGIOUS_SLOP` (blog, sentence-deleting),
  `SLOP_PATTERNS`/`detectSlop` (26 regexes), the cross-platform
  `readiness-gate`, and the social `validateSocial` retry-on-score loop are
  all gone. They punished legitimate security writing ("leverage" and
  "ecosystem" appear in advisories the pipeline quotes verbatim), measured
  fluency rather than truth, and the retry loop taught the model to satisfy
  a checklist instead of improving.

Grounding is now prevented **upstream** (real facts in, dossier instructions
in, fabricated CVE ids out) rather than detected afterwards. What remains
post-write is correctness only: markdown repair, empty-section removal,
citation-host filtering, indicator extraction. Only one thing fails a
publish — output with no section headings, which cannot render as an
article.

**Content types** (`api/src/case-study/types.ts`): `ransom` was removed —
ransomware remains an intel _signal_ (KEV `known_ransomware_campaign_use`,
leak trackers, negotiation data, graph ingest) but is no longer a content
topic. New types: `vulnfaq` (answer-first vulnerability deep-dives),
`exploit` (weaponisation timelines), `darkweb` (underground/IAB/infostealer),
`llm` (model-layer security), `aisecops` (AI in the SOC), `supplychain`.

**Trend research** (`discovery/trend-research.ts`) replaced the LLM-invented
`agentic-trends` runner, which guaranteed three stories a day by asking an
LLM to invent them and then needed a fabricated-host blocklist to catch its
own output. The new runner reads the platform's own corpus (fresh KEV
additions, cvemon trending CVEs, EPSS outliers, fresh writeups, darkweb hits)
and returns **nothing** when the corpus is quiet — which is the correct
outcome.

**New discovery runners**: `aisecops`, `llm`, `darkweb`, `exploits`,
`supplychain`, `infostealers` (Hudson Rock infostealer telemetry + ClickFix
family). `infostealers` is always-on: ClickFix needs no CVE, so CVE feeds
never mention it.

**Generation cost dropped by two LLM calls**: the pre-generation
"fact extraction" pass (deterministic extraction is now code) and the
QA-triggered repair pass (there is no gate to repair).

**CVE trending** (`api/src/lib/cvemon.ts`, `/api/v1/cve-trends`): Intruder's
cvemon feed is the only source that measures social _attention_ rather than
severity. Surfaced as its own "Trending" tab in `/threatintel/cve-intel`
and merged into `/api/v1/cve-recent` as tier 8 (hype fields annotate any
merged id). "Trending but not yet in KEV" is the interesting case — that is
the window where a write-up has value.

### Admin content-generation UI (/admin/generate + tabs)

The admin Generate tab drives on-demand content: topic + audience + tone +
type → blog draft and/or LinkedIn/X posts via `POST /admin/generate`. The
approval gate now rejects only **empty or too-short** output (empty/too-short
is returned `rejected` with a reason, never usable); the old
`quality_score_below_threshold` check that read the removed composite score is
gone. Normalized single `final_post` field per format, optional `dry_run`.
Social publishing supports `?dry_run=true` on
`/social/:slug/:platform/post-*` — returns exactly what would be posted.
Social panels in PublishedTab show factual per-platform checks (char limit,
ungrounded CVEs, untrusted links stripped) rather than the removed
"readiness" verdict.

## WinReg DFIR — Windows Registry Forensic Artifact Reference

A data vertical replicating the SI pattern for the upstream Windows Registry
Forensic Artifacts schema from [dfir-scripts.github.io/registry/](https://dfir-scripts.github.io/registry/).
292 artifacts, 16 categories, 10 hive types, 77 MITRE techniques.

**Data**: `public/data/winreg/` (generated by build script)

**Files**:

- `scripts/build-winreg-manifest.mjs` — fetches upstream JSON, slices into manifest + per-artifact bodies
- `worker/lib/winreg-manifest.ts` — LRU loader + filter helpers
- `worker/mcp-server.ts` — 4 `winreg_*` MCP tools
- `api/src/routes/winreg-edge-tools.ts` — 5 REST routes under `/api/v1/winreg/*`
- `api/src/lib/winreg-manifest.ts` — symlink to `worker/lib/winreg-manifest.ts`
- `src/pages/WinReg.tsx` — SPA page at `/winreg`

**To rebuild**: `node scripts/build-winreg-manifest.mjs`

**MCP tools**: `winreg_list_artifacts`, `winreg_get_artifact`, `winreg_list_categories`, `winreg_stats`

## Traceix — SHA-256 Hash AV/Reputation Lookup

A live enrichment provider for SHA-256 file hash lookups against
[traceix.com](https://traceix.com) (PCEF / Perkins Fund, a 501(c)(3) nonprofit).
Returns per-engine antivirus/reputation verdicts (Safe/Malicious/Unknown/Failed).

**API docs**: https://docs.perkinsfund.org/readme/traceix-endpoints/traceix.md

**Files**:

- `worker/lib/traceix.ts` — core lookup module (`traceixLookup` function)
- `api/src/lib/traceix.ts` — symlink to `worker/lib/traceix.ts`
- `worker/mcp-server.ts` — `traceix_lookup` MCP tool
- `api/src/routes/traceix.ts` — `GET /api/v1/traceix/lookup?hash=<sha256>` REST route
- `src/pages/Traceix.tsx` — SPA page at `/traceix`

**Secret**: `TRACEIX_API_KEY` (`wrangler secret put TRACEIX_API_KEY`)

## NHI Scanner — Non-Human & Agent Identity Risk (nhi-scan port)

A TypeScript port of [nhi-scan](https://github.com/rpmsft9/nhi-scan) (MIT) —
inventories non-human & agent identities (service accounts, API keys, OAuth
apps, service principals, workload identities, CI/CD tokens, PATs, webhooks,
secrets, AI agents) and assigns each a defensible Tier 1–4 (critical→baseline)
from a transparent floor-tier rules engine, mapped to the OWASP NHI Top 10
with a least-privilege remediation per finding. **Deterministic and fully
local — no LLM in the verdict path, no secrets required, no upstream calls.**

**3 MCP tools** (registered on `DFIR_MCP`): `nhi_scan`, `nhi_inventory`, `nhi_owasp_catalog`

**2 REST routes** under `/api/v1/nhi/` (key-gated like every other route):

- `POST /api/v1/nhi/scan` — body is the inventory (list or `{identities:[...]}`) or `{inventory, format?: json|markdown}`; returns the full JSON report or `{markdown}`
- `GET /api/v1/nhi/catalog` — OWASP NHI Top 10 catalog + tiering rules + thresholds + allowed values

**1 SPA route** at `/dfir/nhi-scan` (alias `/nhi-scan`), under the Identity & OSINT hub.

**Files**:

- `worker/lib/nhi-scan.ts` — full engine port: models/parse, `TIER_RULES` + `assess`, `CHECKS` + `runChecks`, `OWASP_CATALOG`, `parseFleet`, `scan`, `reportToJson`/`reportToMarkdown`, `catalogSummary`
- `worker/lib/nhi-scan.test.ts` — 36 vitest tests (port of the upstream pytest suite)
- `api/src/lib/nhi-scan.ts` — symlink to `worker/lib/nhi-scan.ts`
- `api/src/routes/nhi-scan.ts` — the 2 REST routes
- `worker/mcp-server.ts` — 3 `nhi_*` MCP tool registrations
- `api/src/lib/agent/mcp-bridge.ts` — `nhi_*` agent bridge tools (call the lib directly, no HTTP hop)
- `src/pages/NhiScan.tsx` — SPA page at `/dfir/nhi-scan`

**Policy tuning**: thresholds live at the top of `worker/lib/nhi-scan.ts`
(`ROTATION_MAX_DAYS`, `STALE_DAYS`, `WILDCARD_SCOPES`); tiering rules and OWASP
checks are ordered pure-function lists (`TIER_RULES`, `CHECKS`) — edit those,
not scattered logic. Upstream source: `github.com/rpmsft9/nhi-scan` (MIT).

**Tests**: `npx vitest run worker/lib/nhi-scan.test.ts` (36 tests)

## BreachVIP — Breach Database Search

A breach data source integrated into the existing `/dfir/breach` checker.
[BreachVIP](https://breach.vip) is a free, keyless breach search engine with
10B+ records across 1000+ breach datasets. Searches by email, username,
domain, IP, phone, password, name, Minecraft UUID, Steam ID, or Discord ID.

**API**: `POST https://breach.vip/api/search` — `{term, fields, categories?, wildcard?, case_sensitive?}`.
Rate-limited to 15 req/min. The site sits behind a Cloudflare managed challenge
that may block server-side egress; the helpers degrade gracefully to `[]` on
non-JSON/403 responses (same pattern as every other source helper).

**Files**:

- `api/src/routes/breach.ts` — `queryBreachVipEmail` / `queryBreachVipDomain` + `groupBreachVipResults` (groups raw records by breach source into metadata-only entries: record count + data-class labels; raw credentials never surfaced)
- `worker/mcp-server.ts` — `breach_vip_search` MCP tool (direct API call, full 10-field set)
- `api/src/lib/confidence.ts` — `breachvip` source reliability entry (C / secondary)
- `src/pages/dfir/Breach.tsx` — `breachvip` source label/color + privacy notices
- `src/components/dfir/BreachDatabasesPanel.tsx` — BreachVIP external catalog entry
- `api/test/routes/breach.test.ts` — 5 tests (email grouping, empty, CF challenge; domain grouping, non-JSON)

**No secret required** — free, keyless API.

## Whoxy — Reverse WHOIS Lookup

A live enrichment provider for reverse WHOIS lookups against
[whoxy.com](https://www.whoxy.com/reverse-whois/) — 705M+ WHOIS records across
1,596 TLDs. Find all domains registered by an email, owner name, company, or
keyword. Costs $0.01/query (paid, no free tier).

**API docs**: https://www.whoxy.com/reverse-whois/

**Files**:

- `worker/lib/whoxy.ts` — core lookup module (`whoxyReverseWhois` function)
- `api/src/lib/whoxy.ts` — symlink to `worker/lib/whoxy.ts`
- `worker/mcp-server.ts` — `whoxy_reverse_whois` MCP tool
- `api/src/routes/whoxy.ts` — `GET /api/v1/whoxy/reverse?q=<term>&type=email|name|company|keyword` REST route
- `src/pages/Whoxy.tsx` — SPA page at `/dfir/whoxy`

**Secret**: `WHOXY_API_KEY` (`wrangler secret put WHOXY_API_KEY`)

## Heatwave — Cold-Email Sending-Domain Blocklist

A keyless sender-reputation source from Validity's Heatwave DBL
(lookup.validity.tools): synthetic reputation warming vs. active cold
outreach on the _sending domain_. No public API and the public DNS resolver
is retired (both partner-only), so the free web Lookup page (100/day/IP) is
parsed server-side — same scraper pattern as the MTI/Telegram helpers.

**Semantics enforced in code** (`worker/lib/heatwave.ts`): exact-match only,
score is a relative display-only band, "not listed" is unknown (never clean),
warming-only is suspicious (never malicious), and scope is sending-domain
only — it is NOT an IOC fan-out provider (a warming hit on a random domain
would be a false phishing signal).

**Files**:

- `worker/lib/heatwave.ts` — `heatwaveLookup` + `parseHeatwavePage` + `heatwaveVerdict`
- `worker/lib/heatwave.test.ts` — 9 parser/verdict tests over saved fixtures
- `api/src/lib/heatwave.ts` — symlink to `worker/lib/heatwave.ts`
- `api/src/routes/heatwave.ts` — `GET /api/v1/heatwave/lookup?domain=` (24h edge cache + KV last-good)
- `api/test/routes/heatwave.test.ts` — 4 route tests (pass mock ExecutionContext; `app.request()` has none)
- `src/pages/dfir/EmailReputation.tsx` — sender-domain panel + composite floors (active 60 / warming 40)

**Secret**: none — keyless, quota-guarded by cache.

## depx — Supply-Chain Intelligence

A supply-chain intelligence vertical replicating the depx pattern — recently
disclosed malicious packages from the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)
database. Fetches recently disclosed malicious packages via GitHub Commits API
and returns them in a depx-style feed format with ecosystem breakdown, disclosure
age, and package verdicts.

**Files**:

- `api/src/routes/depx.ts` — 3 route handlers: feed, stats, check
- `worker/mcp-server.ts` — 3 MCP tools: `depx_feed`, `depx_check`, `depx_stats`
- `src/pages/threatintel/SupplyChainFeed.tsx` — SPA page at `/threatintel/depx`

**REST routes** (under `/api/v1/depx/`):

- `GET /api/v1/depx/feed?since=7d&ecosystem=npm&limit=100` — recently disclosed malicious packages
- `GET /api/v1/depx/feed/stats` — 30-day ecosystem breakdown
- `GET /api/v1/depx/feed/check?ecosystem=npm&package=lodash` — package verdict (clean/malicious/unknown)

**MCP tools** (registered on `DFIR_MCP`):

- `depx_feed` — list recently disclosed malicious packages
- `depx_check` — check if a package is known-malicious
- `depx_stats` — ecosystem breakdown and feed statistics

**Data flow**: OSSF GitHub Commits API → Cache-API L1 + KV last-good fallback.
No sync scripts needed — live data on each request with aggressive caching.

## Bookmark-gap verticals — CTI Bookmarks, LOTS, MalAPI, CAR, CAPEC, HijackLibs, VERIS, Engage

Eight read-only data verticals closing the
`Chick3nHawk01/Open_Source-CTI-Tooling` bookmark gaps, all following the
osint pattern (build script → `public/data/<name>/index.json` → manifest
loader → edge routes → 3 MCP tools + agent-bridge mirror → SPA page).
The bookmarks vertical tags every entry live/reference/missing against the
platform map in `scripts/build-cti-bookmarks.mjs` — currently 0 missing.

| Vertical        | Source                                      | Entries             | MCP tools         | Page                         |
| --------------- | ------------------------------------------- | ------------------- | ----------------- | ---------------------------- |
| `cti-bookmarks` | upstream bookmark HTML                      | 387 links, 30 cats  | `cti_bookmarks_*` | `/threatintel/cti-bookmarks` |
| `lots`          | lots-project.com scrape                     | 175 trusted sites   | `lots_*`          | `/dfir/lots`                 |
| `malapi`        | malapi.io scrape (370 detail pages)         | 369 APIs            | `malapi_*`        | `/dfir/malapi`               |
| `car`           | mitre-attack/car shallow clone (Apache-2.0) | 102 analytics       | `car_*`           | `/dfir/car`                  |
| `capec`         | mitre/cti sparse clone (STIX 2.0)           | 559 + 56 deprecated | `capec_*`         | `/dfir/capec`                |
| `hijacklibs`    | hijacklibs.net/api JSON                     | 608 DLLs            | `hijacklibs_*`    | `/dfir/hijacklibs`           |
| `veris`         | vz-risk/VERIS enums (CC BY-SA 4.0)          | 68 fields           | `veris_*`         | `/dfir/veris`                |
| `engage`        | engage.mitre.org matrix tables              | 53 approaches       | `engage_*`        | `/dfir/engage`               |

**Files**: `scripts/build-<name>-manifest.mjs` (each supports `--source` for
offline/staging overrides; LOTS/MalAPI crawl politely at 3 concurrent +
200ms), `worker/lib/<name>-manifest.ts` (+ `.test.ts`, + `api/` symlink),
`api/src/routes/<name>-edge-tools.ts`, SPA pages in `src/pages/dfir/` (+
`threatintel/CtiBookmarks.tsx`, `threatintel/RansomwareRecovery.tsx` for the
ransomware RECOVERY tab wiring ID Ransomware → No More Ransom).

**Weekly sync**: `.github/workflows/cti-verticals-sync.yml` (Mon 07:30 UTC,
each step `continue-on-error`, PR + auto-merge + self-deploy). Loop template:
`docs/loops/cti-verticals-sync.md` (count floors per vertical).

**Companion integrations from the same audit**: `apivoid` (IP/domain, covers
IPVoid+URLVoid which expose no own API) + `metadefender` (hash) providers in
`api/src/providers/` (tier 2, `APIVOID_API_KEY` / `METADEFENDER_API_KEY`);
`opencve` CVE route + `opencve_get_cve` tool (`OPENCVE_API_TOKEN`, Bearer org
token, defensive v2 parse — live verification pending keys); FireHOL L1/L2/
WebServer appended in `scripts/build-oss-feeds.mjs`; X-Force (EOL 2026),
OnionTree (dead), Yeti (self-hosted) kept as `ExternalResources` reference
entries only — no live integration is possible.

## AI-security verticals — CAIRN, NOVA, Denali

Three AI-security reference + detection verticals, all following the osint
pattern (build script → `public/data/<name>/` → manifest loader + edge
engine → edge routes → MCP tools + agent-bridge mirror → SPA page).
All data is static via `env.ASSETS`; the scan/evaluate endpoints are pure
local computation (no LLM, no upstream calls, no secrets).

| Vertical | Source (license)                                   | Data                                                                    | Edge engine (TS port)                             | MCP tools      | Page                  |
| -------- | -------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------- | -------------- | --------------------- |
| `cairn`  | Cisco-Talos CAIRN (MIT)                            | 26 YARA rules (9 T1/8 T2/9 T3), 27 filters, A0–A11, 10 families         | `cairn/rules.py` substring + condition subset     | `cairn_*` (7)  | `/threatintel/cairn`  |
| `nova`   | Nova-Hunting nova-rules + framework taxonomy (MIT) | 69 `.nov` rules (518 kw / 97 sem / 51 llm), 4-cat taxonomy (38 threats) | `keywords.py` + `condition.py` + NFKC/confusables | `nova_*` (5)   | `/threatintel/nova`   |
| `denali` | transilienceai/denali (Apache-2.0)                 | 9 deterministic rules, 16-kind taxonomy, 38 ADRs                        | sliding-window checks (3/24h, 5m, scope/token)    | `denali_*` (6) | `/threatintel/denali` |

**Edge boundaries (enforced in code, mirrored in docs)**:

- CAIRN is fully evaluable (substring matching needs no models).
- NOVA evaluates `keywords` only; `semantics` (sentence-transformers) and
  `llm` (provider APIs) are fail-closed gates (`needs-semantics`/`needs-llm`,
  `matched: false`) — same verdict upstream `NovaMatcher` reaches with no
  evaluator. Short-circuit + `can_*_change_outcome` brute-force ported.
- Denali collectors/connectors/snapshot evaluators need Postgres + provider
  credentials and are reference-only; the evaluate surface covers the
  self-contained rules (`DENALI-RUNTIME-ENTRA-FAILURES-001`,
  `-ENTRA-CONSENT-001` scope lists, `-AWS-RISKY-SEQUENCE-001` 5m window,
  mutating-tool tokens). Sequence + identity only, never intent.

**Files**: `scripts/build-{cairn,nova,denali}-manifest.mjs` (each supports
`--source <dir>` for offline builds; live mode hits raw.githubusercontent +
GitHub tree API), `worker/lib/{cairn,nova,denali}-manifest.ts`
(+ `.test.ts`: 15 + 18 + 9, + `api/` symlink — symlink target is
`../../../worker/lib/`, not `../../`),
`api/src/routes/{cairn,nova,denali}-edge-tools.ts`
(`api/test/routes/cairn-nova-denali.test.ts`, 9 tests — runs in CI with the
full route suite),
`src/pages/threatintel/{Cairn,Nova,Denali}.tsx` (Rules/Families|Taxonomy|Docs +
Scanner/Evaluate tabs; family/ADR bodies render via `renderMarkdown`).

**REST** (all under `/api/v1/`, key-gated): `/cairn/` `/cairn/rules*`
`/cairn/families*` `/cairn/filters` `/cairn/archetypes` `POST /cairn/scan`
(text ≤200KB); `/nova/` `/nova/rules*` `/nova/taxonomy` `POST /nova/scan`
(prompt ≤50KB); `/denali/` `/denali/rules*` `/denali/taxonomy`
`/denali/docs*` `POST /denali/evaluate/activity` (≤500 activities).

**Weekly sync**: `.github/workflows/ai-security-verticals-sync.yml`
(Tue 07:30 UTC, each step `continue-on-error`, PR + auto-merge +
self-deploy). Count floors: cairn 26/27/10, nova 69, denali 9/38.
