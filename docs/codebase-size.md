# Codebase Size

A measured baseline of the repository, so "how big is this?" has an answer that
does not require re-deriving it.

**Measured:** 2026-10-10, at `48b0ba0cd` on `main`, from `git ls-files`.

> **Read this before quoting a number.** A naive `wc -l` over the repo reports
> roughly **3.0 million lines**. About 80% of that is committed JSON data and
> machine-generated source, not code. The figure that means anything is
> **549,374 lines of hand-written code**.

---

## Headline

| Metric                                       | Files |       Lines |
| -------------------------------------------- | ----: | ----------: |
| **Hand-written code**                        | 2,588 | **549,374** |
| Generated source (`wrangler types`, codegen) |    10 |      25,304 |
| Generated data (`public/data/`, staging)     | 9,742 |   2,486,922 |
| Markdown prose                               |   131 |      15,047 |

Of the hand-written total: **44,614** blank lines, **55,150** comment lines,
**549,374** code lines — 649,138 physical lines in all. Comment density is
**10.0%** (55,150 comments against 549,374 code), which is high, and deliberate:
this codebase documents _why_ rather than _what_. Several comments exist
specifically so a future reader does not re-introduce a bug that was already made
and caught once — this file's own [methodology](#methodology) section is an
example.

---

## By area

| Area                                     |     Files |      Blank |    Comment |    **Code** |
| ---------------------------------------- | --------: | ---------: | ---------: | ----------: |
| `src/` — React frontend                  |       900 |     15,903 |     11,649 | **256,686** |
| `api/` — Hono Worker routes              |     1,263 |     21,737 |     32,270 | **216,468** |
| `worker/` — cron + Durable Objects       |       187 |      3,899 |      5,407 |  **43,870** |
| `scripts/` — build/codegen tooling       |       127 |      2,183 |      3,828 |  **21,875** |
| `public/` (excluding `public/data/`)     |        12 |         92 |        418 |       4,392 |
| `.github/` workflows                     |        26 |        391 |        530 |       2,335 |
| `migrations/`                            |        50 |        169 |          0 |       1,633 |
| `eslint-rules/`                          |         5 |         82 |        326 |         943 |
| `social-content/`                        |        10 |        130 |        184 |         778 |
| root (`vite.config.ts`, `index.html`, …) |         5 |         21 |        402 |         350 |
| `docs/` (code blocks only)               |         3 |          7 |        136 |          44 |
| **Total**                                | **2,588** | **44,614** | **55,150** | **549,374** |

## By language

| Language   |     Files |        Code | Share |
| ---------- | --------: | ----------: | ----: |
| TypeScript |     2,357 |     516,965 | 94.1% |
| JavaScript |       135 |      23,052 |  4.2% |
| HTML       |         3 |       2,495 |  0.5% |
| YAML       |        26 |       2,335 |  0.4% |
| XML        |         1 |       1,773 |  0.3% |
| SQL        |        50 |       1,633 |  0.3% |
| CSS        |         2 |         819 |  0.2% |
| Python     |         1 |         197 |  0.0% |
| SVG        |        11 |          69 |  0.0% |
| TOML       |         2 |          36 |  0.0% |
| **Total**  | **2,588** | **549,374** |       |

Both tables reconcile to the same totals by construction — that consistency is
asserted by the counter, not by hand. An earlier draft of this file did **not**
reconcile: the language table accidentally included the 25,304 lines of
generated source, summing to 574,481 against an area total of 549,177. The
discrepancy was exactly the generated-source total, which is how it was caught.

`api/` is a **separately-installed package** with its own `package.json` and its
own `node_modules`, and the root `package.json` has no `workspaces` field. Any
tooling that reads only the root manifest gets systematically wrong answers
about `api/` — this bit `knip` before it was configured (see
[`loc-reduction-plan.md`](./loc-reduction-plan.md) §0.4 and Step 3b).

---

## Methodology

`scripts/count-loc.py`.

```bash
python3 scripts/count-loc.py
```

### Counting rules

Operates on `git ls-files`, so `.gitignore`d paths (`node_modules/`, `dist/`,
`.ssr-build/`, `coverage/`) are excluded **by construction** rather than by a
maintainable deny-list. Note this means the counter measures the **index**,
which tracks the working tree — not the last commit. If files are staged for
deletion, they stop being counted immediately.

Blank / comment / code are classified per language family, not by raw line count:

| Family | Extensions                               | Comment syntax   |
| ------ | ---------------------------------------- | ---------------- |
| c      | `.ts .tsx .js .jsx .mjs .cjs .css .scss` | `//` and `/* */` |
| hash   | `.py .sh .yml .yaml .toml .sql`          | `#`              |
| html   | `.html .xml .svg`                        | `<!-- -->`       |
| data   | `.json .jsonc`                           | counted as data  |
| md     | `.md`                                    | counted as prose |

### Four things that had to be excluded, and why

Each of these was a real number that would otherwise have made the headline
wrong.

**1. Generated JSON data — 2,486,922 lines across 9,742 files.**
`public/data/` holds 9,690 committed JSON files of upstream threat
intelligence, plus `threat-intel-staging/`. This is the repo's actual weight and
it is a _content policy_ question, not a refactor — see
[`loc-reduction-plan.md`](./loc-reduction-plan.md) §2 and Step 9, which
recommends leaving it in git.

**2. Generated source — 25,304 lines across 10 files.**

```
api/src/lib/_telegram-actor-catalog.generated.ts   (TypeScript)
api/worker-configuration.d.ts                      (TypeScript)
public/fonts/fonts.css                            (CSS)
src/data/dfir/mitre-matrix.ts                     (TypeScript)
src/data/dfir/wiki-meta.ts                        (TypeScript)
src/data/sidebar-nav.ts                           (TypeScript)
src/data/threatintel/osint-countries.ts           (TypeScript)
src/lib/dfir/powershell-analyzer.ts               (TypeScript)
worker-configuration.d.ts                         (TypeScript)
worker/og-version.generated.ts                    (TypeScript)
```

`worker-configuration.d.ts` alone is 15,740 lines emitted by `wrangler types`.

> **The detector needed tightening twice, and the false positives are worth
> recording.** Scanning the whole file flagged three hand-written files:
> `BlogPost.tsx` (imports `AutoGeneratedBadge`), `McpCatalog.tsx` (_"Loads the
> auto-generated manifest"_ — the _manifest_ is generated, the page is not), and
> `tool-count.test.ts` (_"do not edit SECTIONS"_). Restricting to a 12-line
> header **and** requiring a generation **statement** (`auto-generated from`, `do
not edit`, `generated by wrangler`) narrows it to the correct 10.
>
> The distinction is not cosmetic: `src/data/sidebar-nav.ts` **is** generated
> ("Auto-generated from `data/threatintel-hubs.ts`"), while its input
> `src/data/threatintel-hubs.ts` is hand-written. A looser matcher would have
> excluded the wrong one.

**3. Binary assets.** `wc -l` on `public/tesseract/eng.traineddata.gz` reports
27,713 "lines" that are bytes, and `earth-night.jpg` reports 11,108. These never
entered the count — unknown extensions are skipped — but the explicit
`BINARY_EXT` set documents the trap.

**4. Markdown prose — 15,047 lines.** Documentation, not source.

---

## Largest single source files

Useful for spotting anything that has quietly become a maintenance hazard.

| Lines | File                                      | Note                           |
| ----: | ----------------------------------------- | ------------------------------ |
| 9,359 | `src/data/threatintel/osint-countries.ts` | generated (excluded above)     |
| 4,604 | `src/data/pages-index.ts`                 | not pure data — has real logic |
| 4,407 | `src/pages/argus/data/actors.ts`          | data                           |
| 4,111 | `api/src/lib/agent/mcp-bridge.ts`         |                                |
| 3,977 | `api/src/routes/wifi-investigation.ts`    |                                |
| 3,901 | `src/data/dfir/mitre-matrix.ts`           | generated (excluded above)     |
| 2,971 | `src/lib/dfir/powershell-analyzer.ts`     | generated (excluded above)     |
| 2,871 | `src/data/dfir/wiki-articles.ts`          | data                           |
| 2,571 | `api/src/index.ts`                        | route table                    |
| 2,229 | `api/src/lib/agent/tools.ts`              |                                |
| 2,043 | `src/data/frameworks.ts`                  | data                           |

`worker-configuration.d.ts` is excluded above — it is generated, and its 15,740
lines would otherwise top this list without meaning anything.

---

## What this does _not_ say

LOC is a size metric, not a quality one. A high number is not a defect, and none
of the following follow from this document:

- **Nothing here argues for deletion.** The measured reductions in
  [`loc-reduction-plan.md`](./loc-reduction-plan.md) were driven by dead data
  and byte-identical duplication found by reading code, not by counting it. That
  document's Step 2 is the cautionary case: a 7,400-line deletion moved typecheck
  time by **0%**, because the file was already erased at compile time.
- **File count fell without size falling.** Between `be5aa7a71` and `48b0ba0cd`,
  38 `src/` files were deleted (14,351 lines) — but `src/` still measures 900
  files and 256,686 code lines, because ~14,400 lines were consolidated into
  surviving files. Retiring routes by folding them into fewer, larger components
  reduces file count and route-table noise, and **does not** reduce LOC. If you
  are tracking "did the refactor shrink the codebase", file count is the metric
  that moved; LOC was flat.
- **`api/` at 216k lines across 1,263 files is not obviously over-fragmented.**
  ~10% comment density and heavy JSDoc inflate the figure relative to a codebase
  that documents nothing.
- **The 2.4M generated lines are a deliberate trade.** The repo chose
  reproducibility over clone size; Step 9 of the reduction plan argues that
  choice is correct for a threat-intelligence payload that is regenerable by
  script.

## Keeping this current

The figure goes stale the moment other work lands. Re-run the counter and update
the three tables when you touch anything structural:

```bash
python3 scripts/count-loc.py
```

If the area and language tables ever disagree, the counter has a bug — that is
the invariant that caught the drafting error noted above.
