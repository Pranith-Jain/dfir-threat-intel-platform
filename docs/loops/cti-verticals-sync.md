# CTI Verticals Sync

**Category:** Data / weekly

## Loop Description

Rebuild the bookmark-gap data verticals + the MMD toolkit from their upstreams
and confirm each manifest is fresh and correctly shaped. Same cadence as the
`cti-verticals-sync.yml` weekly workflow — run this loop after editing any
`scripts/build-{cti-bookmarks,lots,malapi,car,capec,hijacklibs,veris,engage}-manifest.mjs`
script or before cutting a data PR.

## Guardrails

**Type:** Hardened with anti-gaming rules

- Do NOT lower a build script's fail-closed entry threshold to clear the run — a
  parse yielding <50% of the expected entries means the upstream format changed;
  fix the parser.
- Do NOT commit `public/data/*` output from a run where any step printed `detail
failed` for >20% of its fetches — re-run that vertical with `--source` staged
  data or increased delays instead of shipping a hollow manifest.
- Do NOT keep retrying a 429/403 upstream in a tight loop — back off, keep the
  previous committed manifest, and report the upstream as degraded.
- If a git-clone step (CAR/CAPEC) fails for lack of network/git, STOP and report
  it — do not hand-write manifest entries.

## Kickoff Prompt

```
Start the "CTI Verticals Sync" loop.

Goal: all eight bookmark-gap manifests rebuild cleanly from upstream
Max iterations: 6
Between iterations run: the eight build scripts + manifest shape check
Exit when: every manifest meets its count floor with <20% fetch failures

Step 1: Run the eight build scripts (cti-bookmarks, lots, malapi, car,
capec, hijacklibs, veris, engage). Read the first failure or hollow
output, fix the parser/fetcher at the source, and re-run.

Count floors: bookmarks ≥350 entries, lots ≥150, malapi ≥300, car ≥80,
capec ≥500, hijacklibs ≥400, veris ≥50 fields, engage ≥40 approaches,
mmd ≥220 files across ≥12 categories.

Self-pace this loop. After each iteration, run the check command, read the
output, and only continue if any vertical is still failing. Stop when green
or max iterations is reached. Give a short status update each pass.
```

## Steps (Agent Actions)

1. **Run builds locally** — all eight `scripts/build-*-manifest.mjs` in sequence
   (CAR/CAPEC need git; LOTS/MalAPI are politeness-delayed, ~2 min each).
2. **Read first failure** — parser error, hollow output, or mass fetch failure.
3. **Fix at the source** — correct the selector/regex/label mapping in the build
   script; never hand-edit `public/data/` output.
4. **Re-run + verify counts** — confirm each manifest meets its floor, then run
   the manifest vitest files and rebuild `mcp-manifest.json` if tool counts changed.
