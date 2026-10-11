# Reviewer instructions for dfir-threat-intel-platform

What a reviewer of this repository must know. This file is quoted into the review
brief as text from the repository, so it can widen or narrow what gets flagged.
Deeper context lives in `CLAUDE.md` and `docs/`.

## What this is

A DFIR toolkit and live threat-intel platform on Cloudflare Workers, plus the
portfolio site at the same origin. Three TypeScript projects: the React SPA and
scripts at the repo root (`src/`, `scripts/`), the API (`api/src/`), and the
Worker (`worker/`). Data under `public/data/**` is generated and excluded from
review.

## Always check these

- **Cloudflare free-plan subrequest budget.** 50 subrequests per invocation, and
  both KV and the Cache API count. Any new read path that loops over keys is a
  finding unless it is batched (`get(keys[])`) or goes through `kvBulkGetText`
  (one subrequest per <=100 keys). Flag a per-key loop in a request handler.
- **Raw KV access.** Reads and writes go through `kvBackedGet`/`kvBackedPut`
  (`api/src/lib/route-cache.ts`), `readLastGood`/`writeLastGood`
  (`api/src/lib/lastgood.ts`) or `routeCacheGet`/`routeCachePut`. A direct
  `env.KV.get`/`env.KV.put` outside the allowlist in `eslint-rules/kv-policy.js`
  is a finding, even though a custom ESLint rule already enforces it.
- **Records that mutate** need a short shadow TTL plus evict-on-write. Flag a
  cache write with no eviction for a record that changes.
- **Two wranglers.** Production deploys run from the repo root (`wrangler.jsonc`,
  Worker `pranithjain`), never from `api/`. Flag a change that deploys from
  `api/` or edits `api/wrangler.toml` as though it were production.
- **Migrations are immutable.** A change to an existing file under `migrations/`
  is a finding. A new migration is fine; D1 is bound as `BRIEFINGS_DB`, not `DB`.
- **Type errors hide here.** Workers bundle with esbuild and skip `tsc`, so all
  three projects must typecheck: `tsconfig.json`, `api/tsconfig.json`,
  `api/tsconfig.worker.json`. Flag a change under `worker/` that is not covered.
- **`main` moves during a session.** Feature branches auto-FF-merge into `main`
  mid-session. Never rebase, force-push or `branch -f main`. A workflow that
  pushes to `main` in a loop, or force-pushes, is a finding.
- **Prompt injection from upstream feeds.** This app ingests external threat
  intel, RSS, Telegram and Reddit content and renders it. Treat every string
  from a feed as untrusted: it must never reach `dangerouslySetInnerHTML`,
  `innerHTML`, `eval`, a shell command or a KV key without sanitising or
  escaping. This is the highest-value class of finding in this repo.

## Never flag these

- Generated content under `public/data/**`, `worker-configuration.d.ts`, and
  the binaries under `public/textures/`, `public/tesseract/`, `public/fonts/`.
  They are build output, already excluded.
- `any`, non-null assertions and `!` in Workers code. This codebase uses them
  deliberately against Cloudflare bindings.
- Hand-rolled KV caching that already goes through the shared helpers. Do not
  ask for a third caching pattern; the helpers are the standard.
- Style, formatting and import order. Prettier and ESLint own those, and the
  scanner pass already ran oxlint.

## Severity for this repo

- `critical`: untrusted feed content reaching HTML/eval/shell, a leaked secret, a
  production deploy path that is wrong, an unbounded subrequest loop on a live
  route, or a destructive migration against production.
- `major`: a cache that can serve stale data forever, a missing evict-on-write on
  a mutable record, a change that cannot typecheck, a workflow that pushes to
  `main` destructively.
- `minor`: a duplicated helper where an existing one fits, a missing test on a
  changed route, a comment that no longer matches the code.
