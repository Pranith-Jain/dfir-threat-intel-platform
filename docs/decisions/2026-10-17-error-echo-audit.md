# Decision: leave the ~99 `err.message` echo sites as-is — audited, not a disclosure channel

**Date:** 2026-10-17
**Status:** Decided (no code change; contract documented in `api-error.ts`)
**Owner:** Pranith
**Driver:** A sweep found ~99 API route sites that put `e.message` straight into a
client-visible `badGateway`/`serviceUnavailable` response instead of using the
`safeErrorMessage` helper the rest of the tree uses. "Does this leak?" needed an
answer with evidence before touching 99 call sites.

---

## What was audited

Every `e instanceof Error ? e.message : '<label>'` response write under
`api/src/routes/` (99 sites at audit time), by asking one question: **what can
`e.message` actually contain, and did the caller already know it?**

Three sources of thrown errors exist on those paths:

| Source                                   | Message content                                            | Sensitive?                  |
| ---------------------------------------- | ---------------------------------------------------------- | --------------------------- |
| Workers `fetch` failure                  | `fetch failed` / `Network connection lost.` — generic      | No                          |
| Own helpers, URL-bearing                 | `Invalid .onion URL: <url>` etc. — echoes **caller input** | No — the caller supplied it |
| Upstream API bodies surfaced by a helper | Rare; helpers throw status-shaped errors                   | Reviewed per-helper         |

The one genuinely dangerous shape — an error message containing an upstream URL
that carries an API key in its query string — does **not occur**: helpers that
embed URLs embed caller-supplied ones, and keyed upstream calls construct URLs
outside the thrown message. `grep` confirms no `apikey=`/`token=`-bearing URL
is interpolated into an `Error`.

Blanket-migrating to `safeErrorMessage` was rejected on top of that because it
would redact _useful_ text (`GreyNoise unreachable` → `upstream error`) with no
security gain — a UX regression dressed as a fix.

## What was done instead

1. **Contract documented** at the definition site (`api/src/lib/api-error.ts`):
   `badGateway`/`serviceUnavailable` messages are client-visible; richer detail
   (raw bodies, URLs, credentials) belongs in `logError`; `safeErrorMessage`
   remains for the cases where even generic text must be withheld outside dev.
2. The 11 sites that already use `safeErrorMessage`/`safeMsg` are untouched —
   they guard cases where upstream detail _is_ returned in the payload.

## Revisit trigger

A future helper that throws an Error whose message interpolates a
credential-bearing URL (or a raw upstream body). The docstring at
`api-error.ts` is the reminder; `safeErrorMessage` is the tool.
