import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { DfirMcpServer } from '../../../worker/mcp-server';
import { handleMcp } from '../../../worker/mcp-handler';

/**
 * End-to-end MCP handshake against the real Durable Object.
 *
 * ## Why this file exists
 *
 * `worker/mcp-server.ts` is the only Worker module that could not be imported by
 * the jsdom suite (it pulls `agents` → `cloudflare:` imports), so for a long time
 * nothing outside a deployment executed it. The practical consequence showed up
 * as a *dependency* risk rather than a code bug: `agents` pinned an exact,
 * advisory-flagged `@modelcontextprotocol/sdk`, and the SDK tightened
 * `McpAgent`'s Env constraint in 1.32. Both were resolved by hand (an override
 * plus a generic-parameter change), which is precisely the kind of edit that
 * should be verified by a test rather than by a deploy.
 *
 * The api suite runs under workerd AND loads the root `wrangler.jsonc`, so the
 * `DFIR_MCP` binding and its class are both real here. That makes it possible to
 * assert the things an import smoke test cannot:
 *
 *   1. the DO accepts an API key, rejects a bad one (fail-closed auth),
 *   2. `initialize` answers with a real protocol version and capabilities —
 *      i.e. the agent framework and the SDK actually speak to each other,
 *   3. `tools/list` returns the registered surface.
 *
 * If a future SDK/framework bump breaks the pairing, this fails in CI with a
 * protocol error instead of silently in production.
 */

const RAW_KEY = 'mcp-handshake-test-key-0123456789abcdef';

async function sha256Hex(value: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Address the DO the way production does: `worker/mcp-handler.ts` hands the
 * request to `DfirMcpServer.serve('/api/mcp', { binding: 'DFIR_MCP' })`, and
 * that indirection is load-bearing — fetching the Durable Object stub directly
 * fails with "Invalid transport type. McpAgent must be addressed with a valid
 * protocol", because the agent framework owns the transport wiring.
 */
async function post(body: Record<string, unknown>, headers: Record<string, string>): Promise<Response> {
  const request = new Request('https://mcp.test/api/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // Streamable HTTP requires the client to accept both response forms.
      accept: 'application/json, text/event-stream',
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const ctx = createExecutionContext();
  const res = await DfirMcpServer.serve('/api/mcp', { binding: 'DFIR_MCP' }).fetch(request, env as never, ctx as never);
  await waitOnExecutionContext(ctx);
  return res;
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: number | string;
  result?: {
    protocolVersion?: string;
    capabilities?: Record<string, unknown>;
    serverInfo?: { name?: string; version?: string };
    tools?: Array<{ name: string }>;
  };
  error?: { code: number; message: string };
}

async function rpc(
  body: Record<string, unknown>,
  opts: { key?: string | null; sessionId?: string } = {}
): Promise<{ status: number; json: JsonRpcResponse | null; sessionId: string | null; raw: string }> {
  const headers: Record<string, string> = {};
  if (opts.key !== null) headers.authorization = `Bearer ${opts.key ?? RAW_KEY}`;
  if (opts.sessionId) headers['mcp-session-id'] = opts.sessionId;

  const res = await post(body, headers);
  const raw = await res.text();
  // SSE framing (`event: message\ndata: {...}`) or plain JSON, depending on
  // what the transport negotiates — parse whichever arrived.
  const jsonMatch = /data:\s*(\{.*\})/.exec(raw);
  let json: JsonRpcResponse | null = null;
  try {
    json = JSON.parse(jsonMatch ? (jsonMatch[1] ?? raw) : raw) as JsonRpcResponse;
  } catch {
    json = null;
  }
  return { status: res.status, json, sessionId: res.headers.get('mcp-session-id'), raw };
}

beforeAll(async () => {
  const db = (env as unknown as { BRIEFINGS_DB: D1Database }).BRIEFINGS_DB;
  // Single-line DDL: D1's exec() treats each line as its own statement, so a
  // wrapped CREATE TABLE arrives truncated ("incomplete input").
  await db.exec(
    'CREATE TABLE IF NOT EXISTS api_keys ( id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE,' +
      " prefix TEXT NOT NULL, label TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'readonly'," +
      ' created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT)'
  );
  await db.exec('CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash)');
  await db
    .prepare(
      `INSERT OR REPLACE INTO api_keys (id, key_hash, prefix, label, role, created_at)
       VALUES ('mcp-test', ?, ?, 'mcp handshake test', 'admin', '2026-01-01T00:00:00.000Z')`
    )
    .bind(await sha256Hex(RAW_KEY), RAW_KEY.slice(0, 8))
    .run();
});

describe('DFIR_MCP Durable Object', () => {
  it('rejects a keyless request at the worker edge with 401', async () => {
    // Two layers guard this surface, and the split matters: the worker returns
    // 401 before a Durable Object is ever created (so an anonymous caller can't
    // drive DO allocation), while the DO re-validates the key itself — a bad
    // key therefore fails INSIDE the object and surfaces as 400, not 401.
    const request = new Request('https://mcp.test/api/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
    });
    const ctx = createExecutionContext();
    const res = await handleMcp(request, env as never, ctx as never, new URL('https://mcp.test/api/mcp'));
    await waitOnExecutionContext(ctx);
    expect(res?.status).toBe(401);
  });

  it('refuses an unknown API key inside the DO without issuing a session', async () => {
    const { status, json, sessionId } = await rpc(
      { jsonrpc: '2.0', id: 1, method: 'initialize' },
      { key: 'not-a-real-key-000000000000' }
    );
    // 4xx, not 2xx — and specifically no protocol handshake and no session.
    expect(status).toBeGreaterThanOrEqual(400);
    expect(status).toBeLessThan(500);
    expect(sessionId).toBeNull();
    expect(json?.result?.serverInfo).toBeUndefined();
  });

  it('completes an MCP initialize handshake with a real protocol version', async () => {
    const { status, json, sessionId } = await rpc({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'handshake-test', version: '0.0.0' },
      },
    });

    expect(status).toBe(200);
    expect(json).not.toBeNull();
    expect(json?.error).toBeUndefined();
    expect(json?.result?.protocolVersion).toBe('2025-06-18');
    // The server must advertise the tool surface, otherwise tools/list below
    // would be meaningless.
    expect(json?.result?.capabilities?.tools).toBeDefined();
    expect(json?.result?.serverInfo?.name).toBe('DFIR-ThreatIntel-MCP');
    expect(sessionId, 'no session id issued — stateless mode, or the transport changed').toBeTruthy();
  });

  it('lists the registered tools over the session', async () => {
    const init = await rpc({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'handshake-test', version: '0' } },
    });
    const list = await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, { sessionId: init.sessionId ?? undefined });

    expect(list.status).toBe(200);
    expect(list.json?.error).toBeUndefined();
    const tools = list.json?.result?.tools ?? [];
    // The catalogue is large (hundreds of registrars); a floor catches an
    // empty/half-registered surface without pinning an exact count that would
    // break every time a tool is added.
    expect(tools.length).toBeGreaterThan(100);
    // Spot-check two registrars from opposite ends of the stack: the
    // Velociraptor family (which needed the internal-token fix) and a
    // threat-intel registrar.
    const names = tools.map((t) => t.name);
    expect(names).toContain('velo_list_clients');
    expect(names.some((n) => n.startsWith('si_') || n.startsWith('ti_'))).toBe(true);
  });
});
