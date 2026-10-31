# dfir-threat-intel-platform

**A 98+ tool DFIR toolkit, a live self-updating threat-intel platform, and a 429-tool MCP server — on one Cloudflare Workers deploy.** Edge-cached, free at the edge, no signup required.

**[Live platform →](https://pranithjain.qzz.io/dfir)** · [Threat Intel →](https://pranithjain.qzz.io/threatintel) · [MCP catalog →](https://pranithjain.qzz.io/mcp)

MIT licensed. Built and maintained by [Pranith Jain](https://github.com/Pranith-Jain) — Security Analyst, Threat Intel · Email Defense · Security Automation.

---

## 👋 The person behind it

This repo is the **work**, not the résumé. For the personal portfolio — background, experience, certifications, case studies, and the reasoning behind these projects — go to:

### **[pranithjain.qzz.io](https://pranithjain.qzz.io)**

|               |                                                                                                                              |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Focus**     | Threat intelligence & IOC analysis · detection engineering · email security & BEC · security automation                      |
| **Currently** | Associate Cyber Security Analyst, CERT Threat & Vulnerability Intelligence Group                                             |
| **Also**      | [LinkedIn](https://www.linkedin.com/in/pranithjain) · [GitHub](https://github.com/Pranith-Jain) · `hello@pranithjain.qzz.io` |

The portfolio is the _first surface_ of the same deploy (`/`, `/about`, `/skills`, `/experience`, `/projects`) — it is simply not what this repository is about. Everything below is the platform.

---

## Three surfaces, one deploy

### 1. Portfolio (`/`, `/about`, `/skills`, `/experience`, `/projects`)

React + Vite + TypeScript with SSR prerendering. Hero, skills grid, timeline experience, certifications, featured work, contact CTA. Dark/light, responsive, accessible, fast first paint via prerendered routes.

### 2. DFIR Toolkit — CRUCIBLE (`/dfir/*`)

98+ interactive analyst tools across 21 categories — triage, OSINT, email security, detection engineering, AI security, data security, crypto tracing, malware analysis, and more. Zero signup, zero keys to start. Includes a **universal rule converter** (Sigma / KQL / SPL / Lucene / EQL / YARA / DLP) and a **purpose-built detection engine**.

### 3. Threat Intel Platform — PANOPTICON (`/threatintel/*`)

A live CTI surface that updates itself: ransomware leak-site + negotiation tracking, CVE/KEV feeds, cross-source IOC firehose with consensus scoring, actor timelines, dark-web/forum intelligence, social/Telegram/Reddit firehoses, a 3D Global Pulse threat globe, auto-generated briefings, and a fully autonomous case-study blog (discover → QA → publish) — all hourly-refreshed, all on the free tier.

---

## Threat Intel Platform — surfaces at a glance

| Surface                                 | What it does                                                                                                       |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Live Ransomware Activity                | Leak-site claims merged across Ransomlook, ransomware.live, MyThreatIntel & Andrea Fortuna; per-victim screenshots |
| Ransomware Groups Directory             | 635-group leak-site directory — status, 7d victims, profiles, recent moves (Sinon-style reference)                 |
| AI Escape Watch                         | 15-incident agent containment-failure registry — CBS scores, 7-stage chains, absent-guardrail analysis             |
| Ransomware Negotiations                 | ransomware.live PRO negotiation chats — demand vs. settled, discount %, full transcripts                           |
| Actor Activity Timeline                 | Per-actor leak-site cadence heatmap + MITRE ATT&CK group/TTP pivot                                                 |
| Victim Re-leak Trends                   | Sector + operation-type breakdowns, group re-claim pairs, re-leak timeline                                         |
| Infostealer Live Tracker                | HudsonRock victim exposure, log-market threads, stealer-log directory, family-matched IOCs (metadata only)         |
| Breach / Leak-Forum Tracker             | deepdarkCTI criminal-forum + dark-market directory — names/status/links only                                       |
| CVE List                                | NVD + CISA KEV merge, EPSS/KEV-aware, MyThreatIntel API-primary with TG-scrape fallback                            |
| IOC Correlation                         | Cross-source consensus scoring across 21 feeds                                                                     |
| Live IOC Stream                         | Chronological multi-source firehose                                                                                |
| C2 Hunting Playbooks                    | MANTIS catalog port — 1,029 hunting queries across 9 engines, favicon MMH3 + JARM fingerprints                     |
| Malware IOCs                            | Gen Threat Labs manifest (gendigitalinc/ioc) — 61 families, 11k hashes, 3.3k network IoCs, YARA + README context   |
| Threat Pulse                            | Entities ranked by cross-source mentions over 24h                                                                  |
| Global Pulse                            | 3D interactive threat globe — 700+ geo-coded events across 33 layers                                               |
| Threat Intel Metrics                    | 16 hand-rolled SVG panels with live deltas                                                                         |
| Dark Web Watch                          | Aggregated leak-site/breach/research RSS, keyword watchlist                                                        |
| Telegram / Reddit / Social              | Curated public Telegram channels, infosec subreddits, Bluesky+Mastodon                                             |
| Live Breach Disclosures                 | Have I Been Pwned feed with verification flags                                                                     |
| Onion Watch                             | .onion mirror inventory for ransomware leak sites                                                                  |
| Cyber Crime & Fraud                     | Indictments, crypto-crime tracing, breach reporting                                                                |
| Tech & AI News / Scam Watch             | Curated multi-section RSS aggregations                                                                             |
| Intel Briefings                         | Daily/weekly auto-generated digests (cron-built, D1-backed)                                                        |
| Case-Study Blog (`/blog`)               | Autonomous pipeline: discover → score/dedupe → AI generate → QA gate → publish                                     |
| Writeups / Threat Actors / MITRE ATT&CK | Analyst-blog aggregation, APT catalogue, full matrix, dark-web index                                               |
| Feed Status                             | Health dashboard for every upstream + internal feed                                                                |
| Catalogs                                | CVE Resources (~70), SecOps Tools (187), OSINT Framework (70+), Knowledge Base                                     |

---

**Upstream catalogs.** Two surfaces are build-time snapshots of third-party sources, rebuilt and committed
by the weekly `genioc-c2-sync` workflow: the C2 playbook catalog (above) is ported from
[MANTIS](https://github.com/fareedfauzi/MANTIS) (MIT, `backend/c2_hunting_catalog.py` via
`npm run build:c2-playbooks`), and the malware IOC manifest from
[Gen Threat Labs](https://github.com/gendigitalinc/ioc) (IOCs published by Gen contributors, per that
repo's readme, via `npm run build:genioc`). API surfaces: `/api/v1/genioc/**` and `/api/v1/c2-playbooks/**`.

---

## DFIR Toolkit — tools at a glance

| Category                  | Tools                                                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Triage & IOCs**         | IOC & Hash Checker (streaming, 60+ providers), Malware Scanner, IOC Extractor, Decoder/Encoder, PowerShell Deobfuscator, Timestamp Converter, Hash Calculator                              |
| **Domain & Network**      | Domain Lookup, Full Spectrum Domain, ASN Lookup, Exposure Scanner, Web Vuln Scanner, Subdomain Takeover, Certificate Search, Domain/IP & URL Reputation                                    |
| **OSINT**                 | Username Pivot (50+ services), Wayback Pivot, IP Geo, SOCMINT Pivots, URL Preview, EXIF, Reverse Image, Homograph Detector, Crypto Tracer, Dork Builder, Brand Impersonation, OSINT Mapper |
| **Email Security**        | Phishing Email Analyzer, EML Attachment Extractor, Email Defense / BEC Score, Email Reputation                                                                                             |
| **Vulns & Identity**      | CVE Lookup (NVD + CVSS + EPSS + KEV), Breach Checker, JWT Inspector                                                                                                                        |
| **Detection Engineering** | YARA/Sigma Playground, YARA Rule Manager, LOLBins/GTFOBins, Log Parser, STIX 2.1 Viewer, Rule Converter                                                                                    |
| **Frameworks & Posture**  | Kill Chain, Diamond Model, OWASP Top 10, NHI Inventory, Tabletop Generator, GRC Maturity                                                                                                   |
| **AI Security**           | Prompt Injection & Red-Team, MCP & Claude Code Auditor, AI Agent Attack-Surface Mapper, MITRE ATLAS                                                                                        |
| **Data Security**         | Sensitive Data Detector, Data Classification, Privacy Hub (GDPR/CCPA/DPDP/HIPAA/PCI)                                                                                                       |
| **Crypto & Blockchain**   | Fund-Flow Tracer (BTC/ETH/Solana/Tron), Wallet Risk Scoring, Address Watch & Alerts                                                                                                        |
| **Malware Analysis**      | Malware Capabilities, Sample Scanner, PE Analysis, String Extraction                                                                                                                       |

**IOC providers (60+):** VirusTotal, AbuseIPDB, Shodan, Censys, Netlas, OTX, URLScan, Hybrid Analysis, GreyNoise, CrowdSec, VulnCheck, Maltiverse, PulseDive, PhishTank, YARAify, StalkPhish, and many more — all optional, the toolkit works with zero keys.

---

## MCP Server

A 429-tool MCP (Model Context Protocol) server runs on the same Worker, exposing every DFIR and threat-intel capability to AI agents. Connect Claude Desktop, Cursor, or any MCP client.

**Repo:** [dfir-mcp-server](https://github.com/Pranith-Jain/dfir-mcp-server)

---

## Tech stack

| Layer           | Choice                                                                                                               |
| --------------- | -------------------------------------------------------------------------------------------------------------------- |
| Frontend        | React 19 + Vite + TypeScript + Tailwind                                                                              |
| Routing         | React Router v7, lazy-loaded (303 route components)                                                                  |
| SSR             | Prerendered routes for instant first paint                                                                           |
| Backend         | Cloudflare Workers + Hono                                                                                            |
| Storage         | KV (briefings, dedup, rate-limit), Cache API (provider/feed results), D1 (briefings DB), Vectorize (semantic search) |
| Durable Objects | 8 — MCP server, cron lock, live feed, report builder, investigator agent, radar crawler, global pulse                |
| AI              | Groq (primary) → Workers AI (fallback) for case-study engine; Gemini for agent QA                                    |
| Tests           | Vitest — 6,700+ tests across 531 test files                                                                          |
| Quality         | ESLint + Prettier + husky/lint-staged; `tsc --noEmit` gate                                                           |
| CI              | GitHub Actions: lint + typecheck + vitest, per-ref concurrency cancel                                                |
| Deploy          | `wrangler deploy`                                                                                                    |

---

## Local dev

```bash
npm install
npm run dev          # Vite — http://localhost:5173
npm run dev:api      # Worker — http://localhost:8787
npm test             # Vitest
npm run typecheck    # tsc --noEmit
npm run lint         # ESLint (max-warnings 0)
npm run deploy       # build + wrangler deploy
```

Requires `wrangler login` and the `pranithjain.qzz.io` zone (or fork and point `wrangler.jsonc` at your own).

## Secrets

The toolkit works with **zero** keys. These unlock extra providers / the CTI engine:

```bash
# IOC providers (all optional)
npx wrangler secret put VT_API_KEY ABUSEIPDB_API_KEY SHODAN_API_KEY \
  CENSYS_PAT NETLAS_API_KEY OTX_API_KEY URLSCAN_API_KEY HYBRID_ANALYSIS_API_KEY
npx wrangler secret put ABUSECH_AUTH_KEY        # ThreatFox + URLhaus + MalwareBazaar
npx wrangler secret put STALKPHISH_API_KEY      # StalkPhish phishing intel (free: 50/day)

# Threat-intel / content engine
npx wrangler secret put RANSOMWARELIVE_API_KEY  # ransomware.live PRO
npx wrangler secret put MYTHREATINTEL_API_TOKEN # MyThreatIntel REST API
npx wrangler secret put GROQ_API_KEY            # case-study generation
npx wrangler secret put GOOGLE_AI_STUDIO_API_KEY # agent QA (Gemini)

# Admin tokens
npx wrangler secret put ADMIN_TOKEN             # shared admin secret
npx wrangler secret put BRIEFINGS_ADMIN_TOKEN   # briefings build/backfill/sweep

# Telegram CTI digest (optional)
npx wrangler secret put TELEGRAM_BOT_TOKEN      # bot for hourly digest broadcasts
npx wrangler secret put TELEGRAM_CHAT_IDS       # comma-separated chat list
```

Every secret is optional and fails safe — the relevant feature degrades or falls back rather than breaking the deploy.

## Cost / quotas

Engineered for the **Cloudflare Workers free tier**:

- Provider/feed results cached to the **Cache API** (not KV) — KV write quota stays free
- Discovery dedup folded into a single KV blob (1 read/run, not ~100)
- Short, self-expiring cache TTLs so publishes/deletes reflect in minutes
- World atlas bundled locally; lean asset bundle; fast worker startup

## Security & accessibility

- **Per-request nonce CSP**, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy on every response
- **SSRF guard** via DNS-level public-IP validation + manual-redirect `pinnedFetch`
- **Prompt-injection scrub** on every LLM input; output sanitised through DOMPurify
- **Single-flight cron lock** — Durable Object lease prevents double-fire on retried scheduler events
- **Admin rate-limit** — atomic Durable Object counter (5/min on admin mutations)
- Constant-time token comparison; no hardcoded secrets, all via `wrangler secret`
- Defensive-only handling of breach/stealer/forum data: metadata only, never stolen content
- WCAG 2.2 AA: skip-to-content, focus traps, ARIA roles, reduced-motion support, 44px touch targets

---

## Open-source releases

### Libraries (npm packages)

| Repo                                                                               | What it does                                                                                          |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [cti-text-extract](https://github.com/Pranith-Jain/cti-text-extract)               | Dependency-free CTI entity extractor — IoCs, CVEs, actors, malware families from unstructured text    |
| [stix21-builder](https://github.com/Pranith-Jain/stix21-builder)                   | STIX 2.1 bundle builder — deterministic UUIDv5 IDs, MITRE ATT&CK cross-references, OASIS TLP markings |
| [cti-ioc-enrich](https://github.com/Pranith-Jain/cti-ioc-enrich)                   | Pluggable IOC enrichment framework — bounded concurrency, per-provider timeouts, composite verdicts   |
| [telegram-preview-parser](https://github.com/Pranith-Jain/telegram-preview-parser) | Parse Telegram channel previews (`t.me/s/<handle>`) to structured JSON — no Bot API key required      |
| [deepdarkcti-parser](https://github.com/Pranith-Jain/deepdarkcti-parser)           | Parse the fastfire/deepdarkCTI markdown index into typed JSON across 18 categories                    |

### Standalone apps

| Repo                                                                               | What it does                                                                      |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [cti-platform](https://github.com/Pranith-Jain/cti-platform)                       | The threat-intel platform on its own — 30+ live CTI surfaces                      |
| [DFIR-PLATFORM](https://github.com/Pranith-Jain/DFIR-PLATFORM)                     | Design notes & prototypes for the DFIR platform — shipped code lives in this repo |
| [dfir-mcp-server](https://github.com/Pranith-Jain/dfir-mcp-server)                 | The 323-tool standalone MCP proxy of the platform API                             |
| [dfir-cli](https://github.com/Pranith-Jain/dfir-cli)                               | Command-line DFIR toolkit — IOC extraction, encoding, file analysis, PE triage    |
| [cti-cli](https://github.com/Pranith-Jain/cti-cli)                                 | Command-line threat intelligence — AI copilot, IOC checker, 13+ feeds             |
| [dfir-threat-intel-agent](https://github.com/Pranith-Jain/dfir-threat-intel-agent) | Autonomous DFIR investigator agent — multi-step LLM-powered tool-calling          |
| [cti-stix-connector](https://github.com/Pranith-Jain/cti-stix-connector)           | Python container that ingests CSV/JSON data and emits STIX 2.1 bundles            |

### AI skills

| Repo                                                             | What it does                                                                            |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [dfir-ai-skills](https://github.com/Pranith-Jain/dfir-ai-skills) | AI coding assistant skills for DFIR — investigation workflows, threat report generation |
| [cti-ai-skills](https://github.com/Pranith-Jain/cti-ai-skills)   | AI coding assistant skills for CTI — IOC extraction, OCR analysis, feed management      |

---

## Repository layout

```
src/                    React app — pages/{dfir,threatintel}, components, lib, data, hooks
  pages/                Top-level portfolio pages (About, Skills, Experience, Projects, Blog)
  pages/dfir/           CRUCIBLE tool pages
  pages/threatintel/    PANOPTICON platform pages
  data/content.ts       personalInfo + projects (includes PLATFORM_REPO_URL, this repo)
api/src/                Cloudflare Worker (Hono) — routes/, providers/ (60+ IOC), lib/, case-study/
worker/                 Worker entry, MCP server (429 tools), Durable Objects, scheduled cron
public/data/            Generated data manifests (49 verticals) — build output, not hand-edited
scripts/                Prerender, manifest builders, sync scripts
docs/                   Design specs, decisions, loop templates
```

**Renaming this repo?** The canonical self-reference is `PLATFORM_REPO_URL` in
`src/data/content.ts`. Two other places must move in lockstep or they break silently:

| Location                                 | Why it matters                                                      |
| ---------------------------------------- | ------------------------------------------------------------------- |
| `api/src/routes/reddit-feed.ts`          | `raw.githubusercontent.com` fallback — pairs with `reddit-feed.yml` |
| `.github/workflows/reddit-feed.yml`      | Pushes the `reddit-feed-data` branch via `${GITHUB_REPOSITORY}`     |
| `scripts/export-briefings-to-github.mjs` | Generates a README link pointing back at this repo                  |
| `public/.well-known/security.txt`        | Security-disclosure contact + advisory URLs                         |

---

## Contact

Built and maintained by **Pranith Jain** — Security Analyst (Threat Intel · Email Defense · Security Automation).
[pranithjain.qzz.io](https://pranithjain.qzz.io) · [LinkedIn](https://www.linkedin.com/in/pranithjain) · [GitHub](https://github.com/Pranith-Jain)

PRs that add genuinely distinctive sources or improve scoring/detection math are welcome. Security reports: see [`.well-known/security.txt`](public/.well-known/security.txt).

## License

MIT
