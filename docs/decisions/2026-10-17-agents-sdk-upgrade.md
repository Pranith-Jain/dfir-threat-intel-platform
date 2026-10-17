# Decision: stay on `agents@0.17.4` — 0.28 evaluated and declined for now

**Date:** 2026-10-17
**Status:** Decided (revisit when either trigger below fires)
**Owner:** Pranith
**Driver:** `agents` is 11 minors behind, and it is the one dependency whose runtime
behaviour no test executed — so "should we bump it?" could not be answered with
evidence in either direction. This pass built the missing evidence and used it.

---

## Background

`agents` powers two Durable Objects:

| Consumer                                       | Coverage before this pass                                                   |
| ---------------------------------------------- | --------------------------------------------------------------------------- |
| `worker/mcp-server.ts` (MCP)                   | none — only an import smoke test that could not cross `cloudflare:` imports |
| `worker/durable-objects/investigator-agent.ts` | none — WS-only surface, no HTTP routes                                      |

Earlier in the same session the nested vulnerable `@modelcontextprotocol/sdk`
(1.29.0, pulled by `agents`) was neutralised with a flat `overrides` pin to
`^1.32.1` rather than by upgrading the framework. `agents@0.28` had been skipped
as "breaking, unverifiable" — unverifiable being the part this pass fixed.

## What was built first (the prerequisite)

`api/test/lib/mcp-handshake.test.ts` — an end-to-end protocol test against the
real Durable Object. The api suite runs under workerd and loads the root
`wrangler.jsonc`, so `DFIR_MCP` and its class are the real ones, and the test
drives them the way production does (`DfirMcpServer.serve('/api/mcp', …)`; a
direct stub fetch fails with _"Invalid transport type"_ because the framework
owns transport wiring).

Four assertions: keyless request → 401 at the worker edge; unknown key →
rejected inside the DO with no session issued; `initialize` → real protocol
version, capabilities and server info; `tools/list` → the registered catalogue.

## Measurements (all on 2026-10-17)

| Check                                   | 0.17.4 (current)                | 0.28.1 + two split packages     |
| --------------------------------------- | ------------------------------- | ------------------------------- |
| MCP handshake tests (14 across 3 files) | pass                            | pass                            |
| worker `tsc --noEmit`                   | 0 errors                        | 0 errors                        |
| client build + budgets                  | pass (unaffected)               | pass (unaffected)               |
| **worker bundle (wrangler dry-run)**    | **13,084 KiB / 3,144 KiB gzip** | **14,063 KiB / 3,347 KiB gzip** |
| `npm audit`                             | 0 vulnerabilities               | 0 vulnerabilities               |

`agents@0.28` statically imports a new split-out `@modelcontextprotocol/client`
(and `server`) package — the DO cannot even load without both installed, and
because the import is static the client package cannot be tree-shaken out even
though a Worker never acts as an MCP _client_. Cost: **+979 KiB raw / +203 KiB
gzip** (~6.5%) for no functional gain.

## Decision

Stay on `agents@0.17.4` with the `@modelcontextprotocol/sdk` override.

- No security driver: 0 advisories on either version.
- The override hack is now **guarded**: the handshake test exercises the exact
  framework↔SDK pairing on every CI run, so a bad resolution fails loudly.
- 0.28's cost (+203 KiB gzip, two new runtime packages) buys currency only.
- The decisive unknown is `InvestigatorAgentDO`: a 1,661-line, WS-only DO with
  zero test coverage. Bumping the framework under it on "the MCP half passes"
  is not a defensible risk trade.

## Revisit triggers

1. A security advisory lands against `@modelcontextprotocol/sdk` 1.32.x that
   the override cannot dodge — take 0.28 and pay the size.
2. `InvestigatorAgentDO` gets a WebSocket smoke test (connect, `onConnect`
   limits, an `onMessage` round-trip). With both consumers covered, the bump
   becomes a tested change: `npm i agents@0.28.1 @modelcontextprotocol/client@2.3.1
@modelcontextprotocol/server@2.3.1`, then run the api suite and
   `wrangler deploy --dry-run` to re-check the size delta.

## Artifacts

- `api/test/lib/mcp-handshake.test.ts` — the protocol test (new).
- `package.json` `overrides` — `@modelcontextprotocol/sdk: ^1.32.1` (unchanged).
