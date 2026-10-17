import { describe, it, expect } from 'vitest';
import { adminApiFetch } from '../../../worker/mcp-tools/core';
import { validateInternalToken, ALLOWED_INTERNAL_CALLERS } from '../../src/lib/internal-token';
import { DfirMcpServer } from '../../../worker/mcp-server';

/**
 * MCP → API auth for admin-gated routes.
 *
 * Two problems this file exists to pin:
 *
 * 1. **The MCP server has no other coverage.** `worker/mcp-server.ts` pulls in
 *    `agents` → `cloudflare:` imports, so it cannot be imported by the root
 *    jsdom suite — it only loads under the api package's workerd pool. A
 *    dependency bump that breaks the `agents`/MCP-SDK pairing (an SDK major
 *    jump, an override) otherwise ships silently, because nothing imports this
 *    file outside a deployment. The import + prototype assertions below turn
 *    "the MCP server still constructs" into a test.
 *
 * 2. **The registrars used to be unable to authenticate at all.** The admin
 *    gate (`requireAdminMiddleware`) accepts `ADMIN_TOKEN` or a signed
 *    `x-internal-token` — never an API-key role. Every registrar that
 *    self-fetched a gated route with only `h.apiKey` (`/rules/validate`,
 *    `/ct-monitor/watch`, `/notebooks`, `/report/parse`, `/velociraptor/*`)
 *    therefore got a 401 on every call. `adminApiFetch` fixes that by signing
 *    an internal token; these tests assert the header it produces actually
 *    validates, and that it is absent — not malformed — when no secret is
 *    configured.
 */

const SECRET = 'test-internal-secret';

/** Records the request it was handed so the assertions can read the headers. */
function recordingFetcher(): { fetcher: Fetcher; seen: Request[] } {
  const seen: Request[] = [];
  const fetcher = {
    fetch: async (req: Request) => {
      seen.push(req);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  } as unknown as Fetcher;
  return { fetcher, seen };
}

describe('adminApiFetch', () => {
  it('signs an internal token the admin gate will accept, alongside the caller api key', async () => {
    const { fetcher, seen } = recordingFetcher();
    const host = {
      env: { SELF: fetcher, INTERNAL_TOKEN_SECRET: SECRET },
      apiKey: 'caller-api-key',
    };

    await adminApiFetch(host, '/api/v1/velociraptor/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ limit: 5 }),
    });

    expect(seen).toHaveLength(1);
    const req = seen[0]!;
    // The caller's key still rides along (it gates the route when the token is
    // absent, and identifies the caller in the logs).
    expect(req.headers.get('authorization')).toBe('Bearer caller-api-key');
    // The caller's own headers are preserved, not clobbered.
    expect(req.headers.get('content-type')).toBe('application/json');

    const token = req.headers.get('x-internal-token');
    expect(token, 'no internal token attached — admin-gated routes would 401').toBeTruthy();
    const validated = await validateInternalToken(token!, SECRET);
    expect(validated.ok, 'token failed signature validation').toBe(true);
    if (validated.ok) {
      // The allowlist is the authorization boundary; a caller missing from it is
      // refused by requireAdminMiddleware even with a valid signature.
      expect(ALLOWED_INTERNAL_CALLERS.has(validated.caller)).toBe(true);
    }
  });

  it('attaches a valid token on every call, whatever the path or method', async () => {
    const { fetcher, seen } = recordingFetcher();
    const host = { env: { SELF: fetcher, INTERNAL_TOKEN_SECRET: SECRET }, apiKey: 'k' };
    // A token is only as good as its last call: one un-signed call would be a
    // silent 401 in the field. (Tokens are deterministic within a millisecond —
    // same caller, same expiry — so this asserts validity, not uniqueness.)
    await adminApiFetch(host, '/api/v1/notebooks');
    await adminApiFetch(host, '/api/v1/velociraptor/hunts', { method: 'POST' });

    for (const req of seen) {
      const token = req.headers.get('x-internal-token');
      expect(token).toBeTruthy();
      const validated = await validateInternalToken(token!, SECRET);
      expect(validated.ok).toBe(true);
      if (validated.ok) expect(validated.caller).toBe('mcp-server');
    }
  });

  it('omits the header (rather than sending a broken one) when no secret is configured', async () => {
    const { fetcher, seen } = recordingFetcher();
    const host = { env: { SELF: fetcher }, apiKey: 'k' };

    await adminApiFetch(host, '/api/v1/notebooks');

    const token = seen[0]!.headers.get('x-internal-token');
    expect(token).toBeNull();
    // Degrades to the pre-existing behaviour: a 401 from the gate, surfaced by
    // apiFetch as a normal error rather than an exception from signing.
    expect(seen[0]!.headers.get('authorization')).toBe('Bearer k');
  });

  it('surfaces a gate rejection as a normal API error', async () => {
    const fetcher = {
      fetch: async () => new Response('unauthorized', { status: 401 }),
    } as unknown as Fetcher;
    const host = { env: { SELF: fetcher, INTERNAL_TOKEN_SECRET: SECRET }, apiKey: 'k' };

    await expect(adminApiFetch(host, '/api/v1/velociraptor/hunts')).rejects.toThrow(/API 401/);
  });
});

describe('MCP server module', () => {
  it('loads with agents/McpAgent intact (guards the dependency pairing)', () => {
    expect(typeof DfirMcpServer).toBe('function');
    // Resolving the base class is the part a bad SDK bump would break.
    expect(Object.getPrototypeOf(DfirMcpServer)).toBeDefined();
    expect(DfirMcpServer.prototype).toBeDefined();
  });
});
