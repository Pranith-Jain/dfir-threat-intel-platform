# Integrating the seven external OSINT tools

How the upstream repositories were reverse-engineered and folded into this
platform, what each one became, and — for the ones that needed a judgement
call — what was decided and why.

The tools:

| Upstream                                                                                      | What it is                                                                                   | Became                                                   |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| [Fazmin/cve-intel](https://github.com/Fazmin/cve-intel)                                       | Rust desktop CVE triage: 38 sources, risk scoring, SSVC v2, patch ordering, weekly landscape | `/threatintel/cve-triage` + three APIs + three MCP tools |
| [Ivancastl/LeakScope](https://github.com/Ivancastl/LeakScope)                                 | Flask search over breach/dark-forum leak thread metadata                                     | `/threatintel/leakscope`                                 |
| [Ivancastl/darkforums-ip-intel](https://github.com/Ivancastl/darkforums-ip-intel)             | Flask map of forum IPs and actors, geolocated by country                                     | `/threatintel/darkforums-ip`                             |
| [Ivancastl/dominiosint](https://github.com/Ivancastl/dominiosint)                             | Flask keyword filter over daily newly-registered domain lists                                | `/threatintel/domain-registrations`                      |
| [Ivancastl/GeoX](https://github.com/Ivancastl/GeoX)                                           | Flask tool generating X/Twitter `geocode:` queries                                           | `/dfir/geox`                                             |
| [Ivancastl/actores-maliciosos-search](https://github.com/Ivancastl/actores-maliciosos-search) | Flask search over a 324k-account MyBB forum dump                                             | `/threatintel/forum-actors`                              |

---

## 1. CVE Intel → CVE Triage

The most valuable of the seven and the one that needed the most care: it is a
native Rust desktop application, so nothing could be vendored. What was
taken was the **analytical logic**, re-implemented in TypeScript against the
platform's own data sources.

### What was ported

| Upstream (Rust)                       | Here (TypeScript)                 |
| ------------------------------------- | --------------------------------- |
| `crates/cve-core/src/risk.rs`         | `api/src/lib/cve-risk.ts`         |
| `crates/cve-core/src/ssvc.rs`         | `api/src/lib/ssvc-v2.ts`          |
| `crates/cve-core/src/exploits.rs`     | `api/src/lib/exploit-evidence.ts` |
| `crates/cve-core/src/compare.rs`      | `api/src/lib/cve-compare.ts`      |
| `crates/cve-core/src/landscape.rs`    | `api/src/lib/cve-landscape.ts`    |
| `crates/cve-core/src/feeds.rs` (EUVD) | `api/src/lib/euvd.ts`             |

The scoring engine is the centrepiece:

```
base  = cvss×0.20 + epss×0.35 + kev×0.30 + poc×0.15
score = round2(base × multiplier)          capped at 100
label = LOW ≤25 < MEDIUM ≤50 < HIGH ≤75 < CRITICAL
```

with multiplicative boosters (`KEV+PoC` ×1.15, `CVSS≥9+EPSS>0.7` ×1.10,
`Published<7days` ×1.05) and the CISA KEV hard override — a confirmed-
exploited CVE is always CRITICAL with a floor of 76.

This is **not** the platform's existing `computeCtiScore`, which scores a
_feed slice_ as CVSS 30% + EPSS 35% + KEV 25% + recency 10%. The two are
deliberately different and now coexist:

- `cve-risk-matrix.ts` — "how do I rank this list of 100 new CVEs?"
- `cve-risk.ts` — "should I patch this one CVE today, and why?"

The second needs public-exploit evidence as an input; the first does not
have it and uses recency instead, which is a better tiebreak across a
recent feed and a worse one for a single long-published CVE.

### Two decisions worth recording

**SSVC v2 is kept separate from the existing SSVC-V.** `api/src/lib/ssvc-v.ts`
implements the older SSVC-V variant with `act` / `prioritise` / `track` /
`watch` outcomes. CVE Intel implements the CISA Deployer tree with `Act` /
`Attend` / `Track*` / `Track`. Mixing the vocabularies would misreport a
decision to an analyst who knows the model, so both live side by side: SSVC-V
rides the feed surfaces, SSVC v2 rides single-CVE triage.

**The heavy corpora moved to build time.** Exploit-DB (~10 MB), Metasploit
(~25 MB) and the EPSS daily files (~3 MB gzipped, 290k rows each) are
whole-corpus downloads. Pulling 38 MB into a Worker to answer one question
would blow the 50-subrequest budget and the free-plan CPU cap, so
`scripts/sync-exploit-index.mjs` reduces each to a compact CVE-keyed index
under `public/data/threat-intel/exploit-index/`, and the Worker reads that
from the ASSETS binding. One triage request costs three live lookups and two
asset reads.

### The surfaces

| Route                                                       | What it does                                                                         |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `GET /api/v1/cve-triage/:cveId?depth=quick\|standard\|deep` | One CVE: risk score with components, SSVC v2, exploit tier + evidence, patch urgency |
| `GET /api/v1/cve-compare?cves=A,B,…`                        | 2–10 CVEs in a patch order, every position explained                                 |
| `GET /api/v1/cve-landscape?days=7`                          | Seven panels + the CVEs two or more sources agree on                                 |

MCP tools: `cve_triage`, `cve_compare`, `cve_landscape`.

---

## 2. LeakScope → leak index

Upstream is a Flask app over two CSVs of breach and dark-forum thread
metadata, already stripped of URL columns at render time.

**The sync strips them at write time instead**, so a URL never enters the
staging area and cannot leak into a build artifact. The date formats needed
care: the upstream CSVs mix ISO-with-offset, `22-03-26, 05:56 PM`
(day-month-year) and naive datetimes. The day-month-year reading is pinned
rather than guessed — getting it wrong shifts every thread by months.

The index is 11.8k rows / 3.9 MB, so the **Worker** searches it and returns
paginated slices. Shipping it to the browser would mean a multi-megabyte
download before the first character is typed, for a page whose whole job is
to be typed into.

---

## 3. DarkForums IP intel → map

312k forum observations → 119k distinct (ip, username) pairs across 186
countries and 45k actors.

- **Country attribution** comes from DB-IP's free country database, mirrored
  as CSV (`sapics/ip-location-db`), so the build needs no MaxMind library and
  no license key.
- **The data is sharded by country** (186 files). One file with all of them
  would be a ~7 MB download the browser then has to render as markers.
- **The jitter is deterministic.** Upstream scatters points around a country
  centroid with `random.uniform(-2.5, 2.5)` — a fresh offset on every
  request, so the same thread's points moved each time the map reloaded.
  Here the offset is a hash of the observation, so a point stays where it
  was. A map that reshuffles itself on reload is a map nobody trusts twice.

---

## 4. DominiosINT → domain monitor

Fetches the daily list of newly registered domains and filters it by keyword.

The upstream matcher strips accents, lowercases and keeps only
alphanumerics, dots and dashes — which is what makes a watch for "banco" also
catch "BANCO-SEGUR0" and "bancó". That normalization is preserved, and the
keyword floor of three characters is preserved (two-letter keywords match
half the domain space).

What was added is the **watchlist**: upstream is a one-shot search — you type
a word, you read the result. A watch is checked on every daily sweep
(`worker/scheduled.ts`, gated by a KV marker so it does not spend one of the
five cron slots the free plan allows) and its matches are recorded, so the
page answers "has anyone registered a domain containing _this word_ recently"
without anyone having to remember to look.

The dedupe is a unique index on `(watch_id, domain, registered_on)`, which
makes a re-sweep idempotent — that is what allows the sweep to run without a
"did we already run today" flag.

---

## 5. GeoX → DFIR tool

The only one of the seven that needed no backend at all: pick a point on a
Leaflet map, set a radius, copy the `geocode:` query.

Two improvements over upstream: the hardcoded `countrycodes=mx` on the
Nominatim lookup is gone (it was an artefact of the original author's
location, not a feature), and the page states plainly what `geocode:`
actually matches — the **profile location an author set**, not the device
they posted from. That is the difference between "a lead" and "a location
fix", and the page should not let an analyst assume the posts are physically
where the circle is.

---

## 6. Actores Maliciosos → forum actors

A 149 MB MyBB forum dump behind Git LFS, holding 323,986 real accounts.

### The judgement call

The upstream tool returns the whole row for an account, which includes the
**password hash, the salt and the session key**. Replicating 324k password
hashes into this repository would turn it into a credential-stuffing
target, so the build copies none of it:

```
password, salt, loginkey, password_algorithm, password_encryption,
password_downgraded                    — credential material
pmfolders, notepad, buddylist, ignorelist
                                        — private per-user state
pow, ougc_*, classicpostbit, postbitbg  — presentation state
```

29 columns in all. The exclusion list is **published in the manifest and in
the API response**, so the omission can be audited rather than taken on
trust.

Email addresses are handled the same way: the upstream tool searches by
email, so the capability is kept, but the shipped table holds a salted
SHA-256 of each address rather than the address. The salt is public, so this
is not a defence against someone determined — it is a decision not to make
this repository the place where 324k addresses sit in the clear.

### The second judgement call

The dump merges rows from several forum schemas, and **131 of the 323,986
rows** were written with a different column order than the table declares.
In those rows the `email` column holds a password salt, `postnum` holds a
password hash and `regip` holds the string "hydrocodone" — which would put
nonsense into an IP field and send an analyst pivoting on garbage.

Every row is validated before it is copied, and the 131 that fail are
dropped and counted in the manifest. A misaligned row is worse than a
missing one: a missing actor is an absence, a misaligned actor is a false
lead.

### Sharding

324k actors do not fit in a Worker's memory as one document, so the
directory is sharded by the first character of the username (37 shards) and
the email table by hash prefix (256 shards). A handle lookup reads exactly
one shard; an email lookup reads exactly one hash shard, and the table
carries the username so the actor record resolves from one more shard.

---

## What was deliberately not done

- **No link to any leak.** LeakScope's URL columns are stripped before the
  staging write. The index says _what was exposed_ and never _where to get
  it_.
- **No credential material.** 29 columns of the forum dump are excluded and
  the exclusion list is published for audit.
- **No plaintext email corpus.** 324k addresses are stored as salted hashes.
- **No sixth cron.** The free plan allows five and all five are taken; the
  domain watch sweep rides the hourly tick behind a KV marker.
- **No per-request bulk downloads.** The three heavy corpora are build-time
  indexes.

---

## Files

### cve-intel core

```
api/src/lib/cve-risk.ts            risk scorer (scoring v1.1)
api/src/lib/ssvc-v2.ts             SSVC v2 CISA Deployer
api/src/lib/exploit-evidence.ts    exploit tier ladder + evidence
api/src/lib/cve-compare.ts         patch ordering + tie-breakers
api/src/lib/cve-landscape.ts       landscape panels + correlation
api/src/lib/cve-triage.ts          triage assembly
api/src/lib/euvd.ts                ENISA EUVD client
api/src/routes/cve-triage.ts       GET /api/v1/cve-triage/:cveId
api/src/routes/cve-compare.ts      GET /api/v1/cve-compare
api/src/routes/cve-landscape.ts    GET /api/v1/cve-landscape
worker/mcp-tools/cve-triage.ts     cve_triage / cve_compare / cve_landscape
scripts/sync-exploit-index.mjs     build-time exploit + EPSS indexes
```

### OSINT verticals

```
worker/lib/forum-intel-manifest.ts    the three forum manifests
api/src/routes/osint-verticals.ts     leakscope + darkforums-ip
api/src/routes/forum-actors.ts        forum actor search
api/src/routes/domain-monitor.ts      domain search + watchlist
api/src/lib/domain-monitor.ts         normalization + matching
api/src/lib/domain-watch-sweep.ts     daily sweep
src/pages/threatintel/CveTriage.tsx
src/pages/threatintel/LeakScope.tsx
src/pages/threatintel/DarkforumsMap.tsx
src/pages/threatintel/DomainRegistrationMonitor.tsx
src/pages/threatintel/ForumActors.tsx
src/pages/dfir/GeoX.tsx
migrations/0058_domain_watchlist.sql
```

### Tests

```
api/test/lib/cve-risk.test.ts          ports CVE Intel's risk ground truth
api/test/lib/ssvc-v2.test.ts           ports CVE Intel's SSVC ground truth
api/test/lib/cve-compare.test.ts       ports CVE Intel's ordering ground truth
api/test/lib/exploit-evidence.test.ts  the tier ladder + correlation
api/test/lib/domain-monitor.test.ts    normalization and matching
scripts/sync-exploit-index.test.mjs    the CSV/parse helpers
```
