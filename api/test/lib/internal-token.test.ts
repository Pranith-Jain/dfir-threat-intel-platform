import { describe, it, expect } from 'vitest';
import { ALLOWED_INTERNAL_CALLERS, signInternalToken, validateInternalToken } from '../../src/lib/internal-token';

/**
 * Internal-token gating for DO → API in-process calls.
 *
 * `requireAdminMiddleware` (lib/admin-auth.ts) treats a valid signed
 * `x-internal-token` as an admin credential, so this module is a real
 * authorization boundary rather than bookkeeping: an allowlisted caller can
 * reach every admin-gated route (malware vault, investigations, notebooks,
 * velociraptor, …). The list grew by 'mcp-server' when the Velociraptor and
 * rule-validation MCP tools were moved onto this path, which is exactly the
 * kind of edit a future refactor could silently widen.
 *
 * Layering matters when reading these tests:
 *   - `validateInternalToken` proves AUTHENTICITY (signature, expiry, secret).
 *   - `ALLOWED_INTERNAL_CALLERS` decides AUTHORIZATION, and only
 *     `requireAdminMiddleware` consults it. A correctly signed token for an
 *     unknown caller therefore *validates* and is still refused at the gate.
 *
 * The properties pinned here are the ones a mistake would break quietly:
 * round-trip for every allowlisted caller, tamper/expiry/secret rejection,
 * fail-closed behaviour when the secret is missing, and the allowlist itself.
 */

const SECRET = 'test-internal-secret';

/** Sign an arbitrary payload so expiry can be tested without waiting 5 minutes. */
async function signRaw(caller: string, exp: number, secret: string): Promise<string> {
  const payload = JSON.stringify({ caller, exp });
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload)));
  const sigHex = Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
  const payloadB64 = btoa(payload).replace(/[=+/]/g, (c) => (c === '=' ? '' : c === '+' ? '-' : '_'));
  return `${payloadB64}.${sigHex}`;
}

describe('internal tokens', () => {
  it('round-trips for every allowlisted caller', async () => {
    for (const caller of ALLOWED_INTERNAL_CALLERS) {
      const token = await signInternalToken(caller, SECRET);
      const res = await validateInternalToken(token, SECRET);
      expect(res.ok, `caller ${caller}: ${!res.ok && res.reason}`).toBe(true);
      if (res.ok) expect(res.caller).toBe(caller);
    }
  });

  it('exposes the mcp-server caller used by the Velociraptor / rule-validation tools', () => {
    expect(ALLOWED_INTERNAL_CALLERS.has('mcp-server')).toBe(true);
  });

  it('keeps an unknown caller out of the allowlist, so the gate refuses it', async () => {
    const token = await signInternalToken('totally-not-a-caller', SECRET);
    // The signature layer accepts it — authorization is the allowlist's job,
    // and `requireAdminMiddleware` is the only thing that reads it.
    const res = await validateInternalToken(token, SECRET);
    expect(res.ok).toBe(true);
    expect(ALLOWED_INTERNAL_CALLERS.has('totally-not-a-caller')).toBe(false);
  });

  it('rejects a token whose signature does not match its payload', async () => {
    const token = await signInternalToken('investigator-do', SECRET);
    const sep = token.lastIndexOf('.');
    const tampered = `${token.slice(0, sep)}.${'0'.repeat(64)}`;
    const res = await validateInternalToken(tampered, SECRET);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('invalid signature');
  });

  it('rejects a token signed with a different secret', async () => {
    const token = await signInternalToken('investigator-do', SECRET);
    const res = await validateInternalToken(token, 'other-secret');
    expect(res.ok).toBe(false);
  });

  it('rejects an expired token even though the signature is valid', async () => {
    const token = await signRaw('cron', Date.now() - 1_000, SECRET);
    const res = await validateInternalToken(token, SECRET);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('token expired');
  });

  it('accepts a token issued inside the 5-minute TTL', async () => {
    const token = await signRaw('cron', Date.now() + 60_000, SECRET);
    const res = await validateInternalToken(token, SECRET);
    expect(res.ok).toBe(true);
  });

  it('fails closed when the verifier has no secret configured', async () => {
    const token = await signInternalToken('investigator-do', SECRET);
    const res = await validateInternalToken(token, undefined);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain('not configured');
  });

  it('refuses to sign without a secret (fail closed on the generation side too)', async () => {
    await expect(signInternalToken('cron', '' as string)).rejects.toThrow(/INTERNAL_TOKEN_SECRET/);
  });

  it('rejects a malformed token', async () => {
    const res = await validateInternalToken('not-a-token', SECRET);
    expect(res.ok).toBe(false);
  });
});
