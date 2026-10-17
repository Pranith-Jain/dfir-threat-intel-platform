import { McpServer, type RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import type { Connection, ConnectionContext } from 'agents';
import { z } from 'zod';
import { validateRawKey } from '../api/src/lib/auth';
import { type Env, type McpToolHost } from './mcp-tools/host';
import { registerApiProxyTools } from './mcp-tools/api-proxy';
import { registerSiSkillsTools } from './mcp-tools/si-skills';
import { registerDfirManifestsTools } from './mcp-tools/dfir-manifests';
import { registerDetectionManifestsTools } from './mcp-tools/detection-manifests';
import { registerReferenceManifestsTools } from './mcp-tools/reference-manifests';
import { registerTiManifestsTools } from './mcp-tools/ti-manifests';
import { registerRegistryRenderTools } from './mcp-tools/registry-render';
import { registerScriptsRenderAiTools } from './mcp-tools/scripts-render-ai';
import { registerSiAnalystTools } from './mcp-tools/si-analyst';
import { registerIdentityOsintTools } from './mcp-tools/identity-osint';
import { registerWorkspaceCveTools } from './mcp-tools/workspace-cve';
import { registerTelegramDarknetAgentTools } from './mcp-tools/telegram-darknet-agent';
import { registerDnSourcesTools } from './mcp-tools/dn-sources';
import { registerSampleVelociraptorTools } from './mcp-tools/sample-velociraptor';
import { registerNetworkFrameworksTools } from './mcp-tools/network-frameworks';

/**
 * The MCP framework constrains its Env generic to the generated
 * `Cloudflare.Env`, which the SDK tightened in 1.32. That generated interface
 * differs per project (the Worker build and the `api/` build bind different
 * things), while `McpToolHost` keeps the deliberately looser registrar-facing
 * `Env` where every binding is optional so tools degrade to a setup hint instead
 * of a type error. The intersection satisfies the constraint without forcing
 * either side to match the other, and the host is handed over through an
 * existing cast.
 */
type McpAgentEnv = Cloudflare.Env & Env;

export class DfirMcpServer extends McpAgent<McpAgentEnv, Record<string, never>, Record<string, never>> {
  server = new McpServer({
    name: 'DFIR-ThreatIntel-MCP',
    version: '1.0.0',
  });

  /**
   * Typed tool registration wrapper.
   *
   * The MCP SDK's `tool()` overload 2 uses `Args | ToolAnnotations` for the 3rd
   * parameter, which prevents TypeScript from inferring the callback param types
   * (they fall back to `unknown`). By routing through `server.tool()` directly with a
   * concrete `Args` constraint, callback params are inferred correctly.
   */
  private tools<A extends Record<string, z.ZodTypeAny>>(
    name: string,
    description: string,
    schema: A,
    cb: (args: { [K in keyof A]: z.infer<A[K]> }) => Promise<{ content: Array<{ type: string; text: string }> }>
  ): RegisteredTool {
    // Cast to the single overload we want (schema + inferred callback args) to
    // bypass the SDK's overload-2 ambiguity that degrades callback params to
    // `unknown`.
    const server = this.server as unknown as {
      tool(
        name: string,
        description: string,
        schema: A,
        cb: (args: { [K in keyof A]: z.infer<A[K]> }) => unknown
      ): RegisteredTool;
    };
    return server.tool(name, description, schema, async (args: { [K in keyof A]: z.infer<A[K]> }) => {
      this.rateLimit();
      return cb(args);
    });
  }

  /** Maximum tool calls per sliding window per connection. */
  private static readonly RATE_LIMIT_MAX = 100;
  /** Sliding window duration in milliseconds (1 minute). */
  private static readonly RATE_LIMIT_WINDOW_MS = 60_000;

  /** Tool calls in the current sliding window. */
  private toolCallCount = 0;
  /** Start of the current sliding window. */
  private windowStart = Date.now();

  /**
   * Check and increment the per-connection rate limit. Throws if the limit is
   * exceeded. The window resets automatically when it expires.
   */
  private checkRateLimit(): void {
    const now = Date.now();
    if (now - this.windowStart > DfirMcpServer.RATE_LIMIT_WINDOW_MS) {
      this.toolCallCount = 0;
      this.windowStart = now;
    }
    this.toolCallCount++;
    if (this.toolCallCount > DfirMcpServer.RATE_LIMIT_MAX) {
      const retryAfter = Math.ceil((this.windowStart + DfirMcpServer.RATE_LIMIT_WINDOW_MS - now) / 1000);
      throw new Error(
        `Rate limit exceeded — ${DfirMcpServer.RATE_LIMIT_MAX} calls per minute. Retry in ${retryAfter}s.`
      );
    }
  }

  /**
   * Wrap a tool handler with rate limiting. Call this at the start of every
   * tool callback to enforce the per-connection rate limit.
   */
  private rateLimit(): void {
    this.checkRateLimit();
  }

  /**
   * API key extracted from the MCP client's Authorization header, used to
   * authorize downstream `/api/v1/*` calls (which are now key-gated).
   *
   * INVARIANT: McpAgent maps one MCP session → one Durable Object instance, so
   * a given instance serves a single client and this per-instance field is
   * effectively per-client. The key is updated on EVERY onConnect call (i.e.
   * every reconnection), so a client that rotates its key and reconnects will
   * immediately use the new key for all subsequent tool calls.
   *
   * NOTE: there is no per-call connection context in the SDK's `server.tool`
   * callbacks, so an in-flight tool call reads whatever `this.apiKey` currently
   * holds. If multi-connection sessions are ever added, thread the key through
   * per-connection state instead of this field.
   */
  private apiKey: string | undefined;

  /**
   * Called when a new MCP client connects. Captures the caller's API key
   * from the initial request headers (the streamable-HTTP transport forwards
   * the original client headers on the internal connection request) so the
   * tool handlers below can authorize downstream API calls.
   *
   * The key is updated unconditionally — if a client reconnects with a new
   * key (e.g. after rotation), subsequent tool calls use the new key.
   */
  override async onConnect(conn: Connection, ctx: ConnectionContext): Promise<void> {
    const authz = ctx.request.headers.get('authorization') ?? '';
    const bearer = /^Bearer\s+(.+)$/i.exec(authz)?.[1];
    const apiKey = ctx.request.headers.get('x-api-key') ?? undefined;
    const rawKey = bearer ?? apiKey;

    // Require a valid API key. Without this gate, any party that can reach
    // the MCP endpoint has full tool access including D1 write operations
    // (shiftlog, promptvault, notebooks) that bypass backend auth.
    if (!rawKey) {
      throw new Error('API key required — provide via Authorization: Bearer or X-API-Key');
    }
    const db = this.env.BRIEFINGS_DB;
    if (!db) {
      throw new Error('Auth backend unavailable');
    }
    const user = await validateRawKey(db, rawKey);
    if (!user) {
      throw new Error('Invalid API key');
    }
    this.apiKey = rawKey;

    // CRITICAL: delegate to the base McpAgent. Its onConnect wires the
    // streamable-HTTP transport (handlePostRequest / handleGetRequest) — i.e.
    // it feeds JSON-RPC messages into the MCP server. Without this super call,
    // every message (starting with `initialize`) is dropped on the floor: the
    // server returns 200 + a session id but never writes a response, so every
    // client hangs and times out on connect.
    await super.onConnect(conn, ctx);
  }

  async init() {
    // The 418 tool registrations live in ./mcp-tools/*, one module per domain.
    // They receive this instance typed as McpToolHost so the tool bodies could
    // be moved verbatim — `this.tools(...)` still applies the per-connection rate
    // limit, and `this.env` / `this.apiKey` are read live at call time.
    //
    // ORDER IS SIGNIFICANT. MCP `tools/list` ordering follows registration
    // order, and registerTiManifestsTools is awaited because it performs
    // `await import()` before registering the ti_search_* / ti_export_stix tools.
    // Keep the sequence below in sync with the original init() body order.
    const h = this as unknown as McpToolHost;
    registerApiProxyTools(h);
    registerSiSkillsTools(h);
    registerDfirManifestsTools(h);
    registerDetectionManifestsTools(h);
    registerReferenceManifestsTools(h);
    await registerTiManifestsTools(h);
    registerRegistryRenderTools(h);
    registerScriptsRenderAiTools(h);
    registerSiAnalystTools(h);
    registerIdentityOsintTools(h);
    registerWorkspaceCveTools(h);
    registerTelegramDarknetAgentTools(h);
    registerDnSourcesTools(h);
    registerSampleVelociraptorTools(h);
    registerNetworkFrameworksTools(h);
  }
}
