#!/usr/bin/env bash
#
# Merge one bot-generated data-sync PR, tolerating the one check that is
# EXPECTED to fail on bot PRs and never actually blocks a merge.
#
# Why this exists: every `*-sync.yml` workflow opens its PR with
# peter-evans/create-pull-request, and the PR's only check is
# `Workers Builds: pranithjain` — the Cloudflare watcher, which fails on bot
# PRs (it builds `main`, not the PR head) and is non-required because main is
# unprotected (branch protection 404s). A plain `gh pr merge` succeeds anyway
# (verified 2026-10-27 on PRs #387/#391: UNSTABLE state, merge succeeded), but
# individual workflows were missing the merge step entirely, so bot PRs piled
# up open and their branches accumulated one stale ref per run.
#
# Contract:
#   exit 0 — PR merged (or already merged)
#   exit 1 — PR could not be merged and the failure is NOT explainable by the
#            non-required Workers Builds watcher; the workflow should fail.
#
# Usage: automerge-sync-pr.sh <pr-number>
set -uo pipefail

pr="${1:-}"
[ -z "$pr" ] && { echo "usage: automerge-sync-pr.sh <pr-number>" >&2; exit 1; }

# Already merged (race between workflows / daily-automerge sweep) → success.
state="$(gh pr view "$pr" --json state -q .state 2>/dev/null || echo '')"
if [ "$state" = "MERGED" ] || [ "$state" = "CLOSED" ]; then
  echo "PR #$pr is already $state — nothing to do"
  exit 0
fi

if gh pr merge "$pr" --merge --delete-branch >/dev/null 2>&1; then
  echo "PR #$pr merged"
  exit 0
fi

# Inspect WHY it failed. The `Workers Builds:` Cloudflare watcher failing is
# fine (non-required, unprotected main). Anything else failing — or the merge
# being refused for a protected-branch reason — is a real problem.
failing="$(gh pr checks "$pr" --json name,bucket 2>/dev/null | jq -r '[.[] | select(.bucket == "fail") | .name] | join("\n")' || true)"
non_build_fails="$(printf '%s' "$failing" | grep -v '^Workers Builds:' || true)"

if [ -z "$non_build_fails" ]; then
  # Only the Workers Builds watcher failed (or no failing checks at all) —
  # retry once; the first attempt can fail transiently (GraphQL hiccups,
  # mergeStateStatus UNKNOWN right after the check started).
  sleep 5
  if gh pr merge "$pr" --merge --delete-branch >/dev/null 2>&1; then
    echo "PR #$pr merged (retry after tolerating the non-required Workers Builds check)"
    exit 0
  fi
  echo "PR #$pr could not be merged; the only failing check is the non-required Workers Builds watcher. Retrying later via daily-automerge." >&2
  exit 1
fi

echo "PR #$pr has real failing checks — refusing to merge:" >&2
printf '%s\n' "$non_build_fails" >&2
exit 1
