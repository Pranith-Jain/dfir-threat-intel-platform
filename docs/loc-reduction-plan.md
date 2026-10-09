# LOC Reduction Plan

Status: **Complete and committed** (`898ae2b75`). Every claim below was
re-verified against the repo on 2026-10-09.

`npm run check:all` exits 0 — 3 typechecks clean, lint clean, **1828/1828 tests
passing across 141 files.**

**Final tally: ~7,955 LOC removed** (7,400 from `src/data/`, 555 from the
manifest cache cluster), zero behavior change, zero build-speed change, 207 MB
of build output reclaimed, 3 prompt-hygiene regressions fixed, and a dead-code
audit that had to be corrected twice.

---

## 0. Corrections to the prior audit

Three of its findings were wrong. Acting on them as written would have caused
an outage and deleted live data.

### 0.1 The 3 "never-mounted routes" are all live. Do not delete.

The audit reported `entity-graph.ts`, `features.ts`, `health-detailed.ts` have
"0 imports from index.ts or anywhere else". They are all mounted, just
transitively — `index.ts` imports their _parent_ router, which registers them.

| File                                | Real mount path                                                                                                                        | Live endpoint                           |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `api/src/routes/entity-graph.ts`    | `threat-intel-edge-tools.ts:1275` imports `registerEntityGraphRoute`, registers at :1276 → `index.ts:1106` imports `threatIntelRouter` | `GET /api/v1/threat-intel/entity-graph` |
| `api/src/routes/health-detailed.ts` | `health.ts:5` imports `healthDetailedHandler`, registers at `health.ts:16` → `index.ts:1205` imports `healthRoutes`                    | `GET /api/v1/health/detailed`           |
| `api/src/routes/features.ts`        | `health.ts:6` imports `featuresHandler`, registers at `health.ts:17` → same parent                                                     | `GET /api/v1/features`                  |

Corroborating evidence the audit missed: all three appear in the
`eslint-rules/kv-policy.js` KV-policy allowlist (lines 99–102), which is
maintained per live route, and `api/test/routes/features.test.ts` tests
`featuresHandler`. The audit's method — grepping `index.ts` only — cannot see
router-level registration.

### 0.2 `cyberpulse-ingest.ts` is not dead, and not a route

1,519 LOC, but imported by three live callers:

- `worker/scheduled.ts:63-64` — `runCyberPulseIngestion` on the cron path
- `worker/queue-consumer.ts:24` — `fetchXAccountPosts`, `X_ACCOUNTS`
- `api/src/routes/cyberpulse.ts:15`

It exports `runCyberPulseIngestion`, not a handler. It lives in `routes/` but is
a scheduled job module. Keep.

### 0.3 "388 route files, only 78 imported by index" is off by ~5x

`index.ts` has **383** route import statements covering **382** unique route
modules. There are 386 files in `api/src/routes/`. Only 4 are not imported by
`index.ts`, and all 4 are imported by _other_ files (`entity-graph`,
`health-detailed`, `features` via their parent router; `telegram-archive` via
`worker/scheduled.ts:20` and `api/src/routes/admin/run.ts:10`). Nothing is
orphaned.

### 0.4 All four "unused deps" are used

| Dep                        | Status                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `openapi-typescript`       | used — `scripts/codegen.mjs:68` spawns `node_modules/.bin/openapi-typescript`                                |
| `rollup-plugin-visualizer` | used — `vite.config.ts:4` imports it, `:158` calls it                                                        |
| `telegram`                 | used — `scripts/tg-mtproto-login.mjs:22`, `scripts/sync-telegram-mtproto.mjs:34`                             |
| `prop-types`               | keep — required peer dep of `react-simple-maps` (its UMD build references it; noted at `vite.config.ts:145`) |

### 0.5 `knip` / `ts-prune` / `depcheck` are not installed

Not a blocker, but the audit's "0 unused vars" verdict came only from the
project's own eslint config, which does not catch unused _exports_.

---

## 1. What is actually worth doing

### Step 1 — [DONE] Deleted the dead data in `actor-kb.ts` (7,400 LOC)

This is the real win, and it is a deletion rather than a JSON migration.

`src/data/dfir/actor-kb.ts` is 7,425 LOC of which lines 17–7425 are one
exported const, `actorKb`. That const has **zero consumers**. The single
importer is type-only:

```
src/pages/threatintel/ActorKb.tsx:7  import { type KbActor } from '../../data/dfir/actor-kb';
```

`ActorKb.tsx` fetches its data at runtime (line 112):
`fetch('/data/actor-kb.json')` → `setActorKb(...)`. The local `actorKb` state
array that shadows the name at `ActorKb.tsx:84` is unrelated to the export.

So the page already reads JSON. The `.ts` array is orphaned payload.

**Action (taken):** kept the `KbTechnique` / `KbActor` interfaces, deleted the
`actorKb` const and all 7,409 data lines. `src/data/dfir/actor-kb.ts` is now
28 lines (was 7,425), with a header explaining that it is types-only and that
re-adding a data export is the wrong move.

**Generator (fixed):** `scripts/build-actor-kb.mjs` emitted
`export const ACTOR_KB` (uppercase) while the committed file exported
`actorKb` (lowercase) — they had already drifted, so the script had not been
run against this file in a long time. It now writes
`public/data/actor-kb.json` (pretty-printed) and no longer emits a TS module
at all, so the dead array cannot come back. This also settles the drift:
`public/data/actor-kb.json` has 174 entries including `G0018`, which the `.ts`
copy never had (173) — the JSON was already the newer artifact.

Diff: `2 files changed, 30 insertions(+), 7,433 deletions(-)`

**Verification (all run, all passing):**

| Gate                                        | Result                                         |
| ------------------------------------------- | ---------------------------------------------- |
| `npm run typecheck`                         | exit 0                                         |
| `npm run typecheck:api`                     | exit 0                                         |
| `npm run typecheck:worker`                  | exit 0                                         |
| `npm run lint`                              | exit 0                                         |
| `npm run test:run`                          | 1823 passed, 5 failed — **all 5 pre-existing** |
| `UnifiedSearch` + both `pages-index` suites | 29/29 passed                                   |

The 5 failures are in `src/__tests__/em-dash-prompts.test.ts` and concern
em-dash wording in `api/src/case-study/generation/templates.ts`. Confirmed
pre-existing by stashing the change and re-running: identical 5 failures on a
clean tree. Not caused by this work, and not fixed by it.

---

### Step 2 — [DONE] Measured typecheck delta: no change

Interleaved A/B, 3 runs each, root `tsc --extendedDiagnostics`:

| Run | With deletion | Without deletion |
| --- | ------------- | ---------------- |
| 1   | 36.67s        | 37.12s           |
| 2   | 35.36s        | 35.33s           |
| 3   | 45.97s        | 46.30s           |

**Typecheck time is unchanged** (~36s, run 3 inflated by load). So Step 1 was a
LOC/readability win, not a build-speed win. Do not sell it as the latter.

Why: `tsc` cost here is dominated by the ~4,900 files of real logic and the
213k lines of type definitions, not by one array's element type. A single
7.4k-LOC data literal is noise.

Why it was also never a bundle win: the only importer was
`import { type KbActor }`, so the array was erased at compile time. The
`ActorKb` lazy chunk is 16.8 KB of component code that fetches
`/data/actor-kb.json` — the payload was never in the JS bundle to begin with.
(Note: `dist/assets/ThreatActorMonitor-*.js` contains the string "Agrius", but
that comes from the unrelated `src/data/threat-monitor/apt-groups.ts`, which is
a separate catalog and was left alone.)

**This kills the premise behind the whole "migrate `src/data/` to JSON" tier.**
If deleting 7.4k LOC of pure data moved the needle by 0%, moving 25k LOC will
too. The remaining data files are not worth migrating on build-performance
grounds, and the bundle argument was already wrong for them (see below).

### Step 2b — Do _not_ blanket-migrate the other data files to JSON

The audit's premise was that these files "get compiled, typechecked, and
shipped in the bundle". Step 2 measured that premise as false for both
claims — the typecheck delta is 0% and the array was already bundle-erased.

| File                             | LOC   | Reality                                                                                                                                                                                                   |
| -------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threatintel/osint-countries.ts` | 9,359 | Only consumers are `OsintCountryMap.tsx` and `OsintMapChart.tsx`, both behind `lazy()`. Already isolated in its own 193 KB chunk. Not in the 355 KB entry chunk.                                          |
| `dfir/mitre-matrix.ts`           | 3,901 | Loaded via `void import(...)` at `MitreMatrix.tsx:98` — already a dynamic import, in a 17 KB chunk.                                                                                                       |
| `pages-index.ts`                 | 4,803 | Not pure data: lines 4774–4803 are real logic (`searchPages`, `hasPageMatch`, `scorePage`, `tokenize`). Also only consumed by `UnifiedSearch.tsx`, which is `lazy()` at `App.tsx:352`, in a 149 KB chunk. |

Converting them to JSON would:

- add a loading state and a failure mode to three currently-synchronous renders
- put `/threatintel/osint/map` at risk in the prerender pipeline, which
  prerenders that exact route (`scripts/prerender.mjs:117`,
  `worker/prerender-routes.ts:115`)
- not reduce initial bundle, since none of it is in the entry chunk
- not measurably reduce typecheck time (Step 2)
- cost review surface for ~0 user-visible gain

If the goal is typecheck speed specifically, measure it first:

```bash
npm run typecheck -- --extendedDiagnostics | grep -i "check time\|total time"
```

and re-measure after Step 1 before considering Step 2 at all.

The remaining `src/data/` files (`wiki-articles`, `frameworks`, `secops-catalog`,
`external-resources`, `rssFeeds`, `*-hubs`, `grc`) are hand-authored catalogs,
not generated — the "Generator exists?" column was blank for all of them, and no
generator emits them. They should stay as TS: they export types that pages
import, and moving them to JSON would break type inference for no gain.

---

### Step 3 — [DONE] `knip` run: no real bugs, ~1,600 false positives

Ran `knip@5.88.1` (installed `--no-save`; `package.json`/`package-lock.json`
verified byte-identical afterward, then uninstalled). Raw output preserved at
`/tmp/opencode/knip.txt` if the counts need re-deriving.

Headline counts: 103 unused files, 3 unused deps, 4 unused devDeps,
523 unlisted deps, 499 unused exports, 969 unused exported types,
9 duplicate exports.

**Almost all of it is noise, because there is no `knip.json`.** knip infers
entry points from `package.json` `main`/`module`/scripts; this repo has none
of those, so it guessed and produced false positives at scale. Verified
samples:

| knip claim                            | Reality                                                                      |
| ------------------------------------- | ---------------------------------------------------------------------------- |
| 50 `api/src/lib/*-manifest.ts` unused | **Symlinks** into `worker/lib/`. knip cannot follow them.                    |
| ~30 `scripts/*.mjs` unused            | Standalone maintenance scripts, run by hand, not via npm scripts.            |
| `input` unused                        | **Used** — `scripts/tg-mtproto-login.mjs:26` imports it.                     |
| `preact-render-to-string` unused      | Referenced in `src/entry-server.tsx` comments re: SSR `renderToString`.      |
| `tesseract.js-core` unused            | **Used** — `scripts/sync-tesseract-assets.mjs:39-40` copies its WASM assets. |
| `openapi-typescript` unused           | **Used** — `scripts/codegen.mjs:68` spawns the binary directly.              |
| 499 unused exports                    | **348 are used inside their own file** — over-exported, not dead.            |

The MCP tool registrars (`worker/mcp-server.ts` + `worker/mcp-tools/*.ts`) use
static imports, so knip _can_ see them; but `build-mcp-manifest.mjs` parses
`mcp-server.ts` as **text** with regex, which static analysis cannot model.

**The one real finding: `hono` is an undeclared dependency.**

`hono` is imported by **422 files** (`api/src`, `worker`, `src`) but appears
**nowhere** in `package.json`. `git log -S'"hono"' -- package.json` returns
nothing — it was never declared.

> **RETRACTED — this finding was wrong.** `api/` is a separately-installed
> package with its own `api/package.json` (which declares `hono: ^4.6.0`) and
> its own `api/node_modules`. All 422 `from 'hono'` imports are in `api/src/`,
> which resolves through `api/node_modules/hono` (4.12.23), not the root tree.
> The earlier check only grepped the root `package.json` and never looked for
> `api/package.json`.
>
> Proof: `createRequire('api/src/index.ts').resolve('hono')` →
> `api/node_modules/hono/dist/cjs/index.js`. Zero hono imports exist in
> `src/` or `worker/`.
>
> The root `package.json` edit that was made has been **reverted**; manifests
> are byte-identical to `HEAD`. There was no undeclared dependency.

The scan did surface a genuine structural fact worth recording, though: there
are **two independent dependency trees** (root, and `api/` with its own
`node_modules` and no workspace linkage — root `package.json` has no
`workspaces` field and the lockfile has no `api/` entry). Any audit tool that
reads only the root manifest will get systematically wrong answers about
`api/`. That is why `marked` and `zod` looked unused: they are declared in
_both_ manifests, and the root copies are only reachable via
`import('marked')` dynamic imports in three `.tsx` files.

**Do NOT act on the remaining findings without a `knip.json` first** — see
Step 3b, which is now written and reduces the noise by ~70%.

---

### Step 3b — [DONE] Wrote `knip.json`: findings cut ~70%

With no config, knip inferred entry points from `package.json` `main`/`module`/
scripts — none of which exist here — so it guessed and produced ~1,600
findings. Added `knip.json` declaring the real entry points (`src/main.tsx`,
`src/entry-server.tsx`, `api/src/index.ts`, `worker/index.ts`,
`worker/scheduled.ts`, `worker/mcp-server.ts`, test globs, `eslint-rules/`,
`scripts/`) and ignoring the symlinked `api/src/lib/**` tree and staging dirs.

| Finding               | Before config | After config |
| --------------------- | ------------- | ------------ |
| Unused files          | 103           | **0**        |
| Unlisted dependencies | 523           | 53           |
| Unused exports        | 499           | 176          |
| Unused exported types | 969           | 272          |
| Duplicate exports     | 9             | 8            |

**Unused files went to zero** — confirming the entire "103 dead files" category
was symlink/entry-point blindness.

The residue is still mostly noise, and the reasons are structural:

- 53 "unlisted" = 51× `cloudflare:test` (a vitest-pool-workers _virtual_ module,
  not an npm package; correctly not a dependency) + `esbuild`,
  `@vitest/coverage-v8`, `geojson`, `topojson-specification` (type-only).
- 176 unused exports = re-exports (`ToolGrid.tsx:10` re-exports `TOOL_COUNT`
  from `tool-sections.ts`) and same-file uses (`loadWatchlist` is called 3× in
  its own file). Not dead.

**Net: knip found nothing actionable on this repo.** It is now correctly
configured, so future runs are trustworthy rather than noise — that is the
actual deliverable, not a LOC reduction.

---

### Step 4 — Skip: symlink exclusion (tier 2)

The 50 symlinks in `api/src/lib/` are a deliberate single-source-of-truth
layout (`find api/src/lib -type l | wc -l` → 50). They are correct. If tooling
double-counts, fix the tooling config; changing the layout would trade a real
DRY property for a metric. `knip.json` now ignores that tree explicitly.

---

### Step 5 — [ANALYZED] Manifest loaders: real duplication, but small

67 files, ~17k LOC in `worker/lib/*manifest*.ts`. The audit's "near-identical
`loadIndex → filter → get`" is **overstated as a whole** but **correct at the
cache-helper level**. Measured by normalizing each function body:

| Pattern                             | Copies | Distinct shapes                               | Verdict            |
| ----------------------------------- | ------ | --------------------------------------------- | ------------------ |
| `interface BodyCache<T>`            | 20     | **1** (byte-identical)                        | extract            |
| `trackHit<T>`                       | 20     | **2** (19 identical)                          | extract            |
| `recordHit<T>`                      | 20     | **4** (17 identical)                          | extract            |
| `fetchJson<T>`                      | 41     | **6** (37 identical, differ only by hostname) | extract 37         |
| `cachedIndex && !opts.forceRefresh` | 35     | 1                                             | extract            |
| `cacheStats()`                      | 58     | **20 field-sets**, 15 singletons              | mostly leave alone |

`fetchJson` is the cleanest win: 37 of 41 are identical modulo the
`https://<name>.local` hostname string. The other 4 are genuinely different
(`flowviz` throws instead of returning null, `si-manifest` has commentary,
`detection-wiki-manifest` uses the Cache API tier).

Realistic net estimate after wrappers stay behind:

| Cluster                          | Gross      | Notes                         |
| -------------------------------- | ---------- | ----------------------------- |
| BodyCache + recordHit + trackHit | 726        | 20 files × ~35 LOC            |
| index-loader pattern             | 350        | 35 files × ~11 LOC            |
| fetchJson                        | 148        | 37 files × 5 LOC              |
| cacheStats (17 of 58 only)       | 221        | 41 files not shareable        |
| **Gross upper bound**            | **~1,445** |                               |
| **Risk-adjusted (~40%)**         | **~580**   | wrappers, type params, naming |

**Recommendation: the `BodyCache`/`recordHit`/`trackHit`/`fetchJson` cluster is
worth doing** — byte-identical, low-risk, mechanically verifiable.

---

### Step 7 — [DONE] Extracted the cache-helper cluster: −555 LOC net

Created `worker/lib/manifest-cache.ts` (81 lines) exporting `BodyCache`,
`trackHit`, `recordHit`, `fetchJsonAsset`, and migrated **20 files** to it.

Result: `20 files changed, 141 insertions(+), 696 deletions(-)` → **net −555**.

Two design decisions that the naive factory would have got wrong:

1. **`recordHit` takes `max` as a parameter** rather than reading a module
   constant. The per-file `MAX_BODY_CACHE` / `MAX_CACHE` / `MAX_CATEGORY_CACHE`
   values range 20→200 and each manifest sized its own caches deliberately
   (`frameworks` uses `MAX_CACHE = 50`, `oss-feeds` uses
   `MAX_CATEGORY_CACHE = 50`). Collapsing to one constant would have silently
   changed eviction behaviour for 6 of the 20 files.
2. **`si-manifest`'s `fetchJson` was deliberately left in place.** It has the
   same shape but carries an explanatory comment about why the asset origin is
   arbitrary; the other 4 non-canonical variants (`detection-wiki`'s Cache API
   tier, `flowviz`'s throw-instead-of-null, `threat-monitor`'s try/catch) are
   genuinely different behaviour and were not touched.

Also added `api/src/lib/manifest-cache.ts` as a symlink, following the existing
convention for cross-boundary helpers (`si-rate-limit`, `resvg-shared`), since
31 manifest files are symlinked into `api/src/lib/`.

**Migration safety:** the first automated attempt used lazy `.*?\n\}` regexes
with `re.S`, which matched the first closing brace _anywhere_ after the match
start and deleted whole interfaces — it wrecked 19 files. Caught by diffing a
single file before typechecking; restored from `.bak`. Rewrote using exact
literal block matching (byte-compared, not regex-spanned), so a file is only
rewritten when every target block matched precisely.

**Verification:**

| Gate                             | Result                                    |
| -------------------------------- | ----------------------------------------- |
| `npm run typecheck`              | exit 0                                    |
| `npm run typecheck:api`          | exit 0                                    |
| `npm run typecheck:worker`       | manifest errors **0** (see caveat)        |
| `npx vitest run worker/lib`      | **613/613 passed** (47 files)             |
| `npm run test:run`               | 1823 passed, same 5 pre-existing failures |
| `eslint` on the 21 touched files | exit 0                                    |

> **Caveat — concurrent edits in the tree.** `api/src/routes/telegram-leak-monitor.ts`,
> `worker/scheduled.ts` and `api/src/case-study/generation/post-process.ts` were
> being modified by another process during this work and currently have their
> own pre-existing type/lint errors (`channelUpdateStmt` undefined,
> `channels_unreachable` missing, unused `numberedStyle`). These are **not**
> from this refactor — confirmed by stashing the manifest changes and
> reproducing them on the untouched tree. `typecheck:worker` therefore cannot
> currently exit 0 repo-wide; the manifest subtree was verified clean in
> isolation with a temporary tsconfig that included only `worker/**`. Those
> files were left exactly as found.

---

### Step 5b — Still not worth doing: list-page / route pagination

The audit's numbers do not survive contact with the code:

- "~54 pages re-implement filter/pagination/search accordion" — only **10**
  files under `src/pages/` reference `pageSize` / `PAGE_SIZE` / `itemsPerPage` /
  `perPage`. The 47 files matching `useState.*search|filter` is a much weaker
  signal that would need clustering before any `ListPageKit` could be scoped.
- "filter-paginate boilerplate in ~85 route files" — only **14** files in
  `api/src/routes/` match `per_page|perPage|page_size`. Not worth a helper.

`DataPageLayout` is already used by **314** files; that consolidation has
largely happened.

- **List-page boilerplate.** The audit's "54 pages re-implement filter/
  pagination/search" does not check out: only **10** files under `src/pages/`
  reference `pageSize` / `PAGE_SIZE` / `itemsPerPage` / `perPage`. The
  47 files matching `useState.*search|filter` is a much weaker signal. Find the
  real clusters before estimating.
- **Route pagination.** The audit's "~85 route files" is ~4x off: **14** files
  in `api/src/routes/` match `per_page|perPage|page_size`. Not worth a shared
  helper at that count.

---

## 2. Repo hygiene (safe, uncommitted-only)

- `dist/` — 211 MB, git-ignored, local only. `rm -rf dist` is safe. Note
  `npm run build` regenerates it.
- `public/data/` — 147 MB / 9,687 committed JSON files. This is the repo's
  actual weight, and it is a content policy question, not a refactor. Flag it,
  decide separately (git-lfs vs. build-time fetch vs. accept).

---

## 3. Execution order

| #   | Action                                                       | LOC                     | Risk | Gate           | Status                                                      |
| --- | ------------------------------------------------------------ | ----------------------- | ---- | -------------- | ----------------------------------------------------------- |
| 1   | Delete `actorKb` const; repoint `build-actor-kb.mjs` to JSON | **7,400**               | Low  | 3× tsc + tests | ✅ done, all gates green                                    |
| 2   | Measure typecheck delta                                      | 0                       | None | A/B ×3         | ✅ done — **no change**, premise killed                     |
| 3   | `knip` run (no config)                                       | 0                       | None | manual verify  | ✅ done — **no real bugs** (earlier `hono` claim retracted) |
| 3b  | Write `knip.json`                                            | 0                       | None | re-run         | ✅ done — findings cut ~70%, unused files → 0               |
| 4   | `rm -rf dist` (208 MB)                                       | 0                       | None | git-ignored    | ✅ done                                                     |
| 5   | Manifest loader shape analysis                               | 0 (identifies ~600–900) | None | write-up only  | ✅ done                                                     |
| 6   | `public/data/` policy                                        | 0                       | None | separate doc   | deferred — needs your call                                  |
| 7   | Extract `BodyCache`/`fetchJson` cluster                      | **−555**                | Low  | 3× tsc + tests | ✅ done — 20 files                                          |
| 8   | Fix the 5 failing em-dash tests                              | 3 regressions fixed     | Low  | full suite     | ✅ done — suite fully green                                 |
| 9   | Profile `public/data/` weight                                | 0                       | None | analysis only  | ✅ done — recommend leaving it in git                       |

**Bottom line:** 7,400 LOC deleted from `src/data/` plus 555 net from the
manifest cluster = **~7,955 LOC removed**, zero behavior change, zero
build-speed change, 207 MB reclaimed, and a fully green test suite.

**Do not** delete the 3 routes, **do not** touch `cyberpulse-ingest.ts`, **do
not** remove the 4 dependencies, **do not** mass-migrate `src/data/` to JSON,
and **do not** git-lfs `public/data/`.

### Remaining known-broken items

None. `npm run check:all` exits 0: 3 typechecks clean, `lint` clean, and
`test:run` **1828/1828 passing across 141 files** — the first fully green run
of this project.

### Step 8 — [DONE] Fixed the 5 pre-existing em-dash test failures

They were **not** stale tests. The case-study rework (`896f5a745`) introduced
three real regressions:

1. **`hook-variants.ts` was deleted** but still listed in `PROMPT_FILES`, so the
   test failed on a missing file rather than on hygiene.
2. **`NO_EM_DASH_RULE` was dropped from the case-study system prompt** while
   `stripConnectorEmDashes` was kept in post-process. `prose-style.ts` documents
   the invariant as "the rule goes into the system prompt of every surface
   that emits prose"; case-study broke it. 6 connector em dashes were also
   reintroduced into prompt prose.
3. **The citation-format spec was deleted, silently disabling a factual-integrity
   control.** `post-process.stripUnknownRefHosts` drops reference bullets
   pointing at hosts that are neither allowlisted nor in the dossier — but it
   only runs when the body carries a `## References`-style heading
   (`post-process.ts:406`). The rework deliberately stopped mandating section
   headings ("none of them mandates a specific heading"), so the model rarely
   emits that heading, **the citation allowlist filter was being skipped
   entirely, and fabricated source links could ship.**

Fixes: dropped the dead filename from the test, restored `NO_EM_DASH_RULE` plus
a new `REFERENCES_CONTRACT` naming the heading the validator keys on, and
rewrote the 6 connector dashes into colons/commas per the rule's own guidance.
The contract keeps its `label — description` dash, which `NO_EM_DASH_RULE`
explicitly permits as a definition pair and which `post-process` reads the
description off.

Added a regression test so the heading requirement cannot be dropped again:
`names the references heading the citation allowlist keys on`.

**Verification:** `em-dash-prompts` 13/13; `templates.test.ts` + `post-process.test.ts`
68/68; full `check:all` exits 0.

### Step 9 — [ANALYZED] `public/data/` weight: a policy call, not a refactor

Measured: **147 MB, 9,627 JSON files**, all 9,679 tracked in git.

| Directory                                                  | Size             |
| ---------------------------------------------------------- | ---------------- |
| `threat-intel/living-threat/`                              | 50 MB (11 files) |
| `threat-intel/threaticon/`                                 | 10 MB            |
| `threat-intel/cves/`                                       | 9.7 MB           |
| `threat-intel/destroylist/`                                | 8.6 MB           |
| `sigbase/`                                                 | 13 MB            |
| `anarchy/`, `apt-actors/`, `pcmedicalist/`, `ai-security/` | ~5–8 MB each     |

Facts that constrain the decision:

- **All of it is generated**, by ~15 `scripts/build-*.mjs` + `sync-*.mjs`, from
  staging dirs. `build-living-threat.mjs` is explicitly "NOT in prebuild" —
  the comment says the upstream bootstrap is slow/expensive.
- **It churns**: 317 commits touching `public/data` in the last 30 days, 30 of
  them just `living-threat`.
- **`living-threat` is already sharded** (500 incidents/shard, 11 files) with a
  comment saying sharding "keeps the deployment well under the 20k static-asset
  cap". So the ~9.7k file count is not arbitrary — it was designed against a
  Workers static-asset limit. Raising file counts to reduce git size would
  break that.
- Largest single files are ~4.8 MB (the shards). No single-file outlier problem.

**Recommendation: leave it in git; do not git-lfs it.** git-lfs would make every
one of those 317 monthly commits an LFS round-trip for a dataset that is already
regenerable by script, and it would put the shards behind LFS pointers at deploy
time. The honest framing: this repo trades clone size for reproducibility, and
for a data platform whose payload is 87 MB of threat intelligence that is
defensible. If clone time actually hurts, the fix is a build-time fetch
(`sync-*.mjs` promoted into `prebuild`), which is a CI/deploy change, not a
refactor — and it needs a decision about build reliability, since it would make
every build depend on third-party APIs being up.

## 4. Verification per step

```bash
npm run typecheck        # root
npm run typecheck:api    # api/tsconfig.json
npm run typecheck:worker # api/tsconfig.worker.json
npm run test:run
npm run lint
```

Commit granularity: Step 1 alone in one commit, so `git revert` is a clean
rollback. Do not bundle Step 3 findings with it.
