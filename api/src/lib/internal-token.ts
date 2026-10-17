/**
 * Signed internal-token utility for DO→API in-process calls.
 *
 * Replaces the old `X-Internal-Agent: investigator-do` header bypass,
 * which any external caller could forge. Tokens are HMAC-SHA256-signed
 * and expire after a short TTL (default 5 minutes).
 *
 * The signing secret is provided via the `INTERNAL_TOKEN_SECRET` Worker
 * secret (set with `wrangler secret put INTERNAL_TOKEN_SECRET`). Both DOs
 * and API routes receive the same secret through the env binding, so
 * tokens are valid across isolates within the same Worker.
 *
 * SECURITY: The module FAILS CLOSED when `INTERNAL_TOKEN_SECRET` is not
 * set — signing throws and validation rejects. This prevents the old
 * behaviour where a hardcoded fallback made tokens forgeable by anyone
 * with the source code.
 *
 * Set the secret with `wrangler secret put INTERNAL_TOKEN_SECRET`.
 */

const TOKEN_TTL_MS = 5 * 60_000; // 5 minutes
const SEP = '.';

/** Cache the derived CryptoKey per secret value. */
let _cachedSecret: string | null = null;
let _cachedKey: CryptoKey | null = null;

function requireSecret(secret?: string): string {
  if (!secret) {
    throw new Error(
      'INTERNAL_TOKEN_SECRET is not configured. ' + 'Set it with `wrangler secret put INTERNAL_TOKEN_SECRET`.'
    );
  }
  return secret;
}

async function getSecret(secret: string): Promise<CryptoKey> {
  if (_cachedSecret === secret && _cachedKey) return _cachedKey;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  _cachedSecret = secret;
  _cachedKey = key;
  return key;
}

export interface InternalTokenPayload {
  /** Caller identity — e.g. 'investigator-do', 'report-builder-do'. */
  caller: string;
  /** Unix-ms expiry timestamp. */
  exp: number;
}

/**
 * Generate a signed internal token. Called by Durable Objects before
 * making in-process API calls via the SELF service binding.
 *
 * @param caller - Caller identity (e.g. 'investigator-do')
 * @param secret - The INTERNAL_TOKEN_SECRET from env. When provided, uses
 *   a cryptographically random secret instead of the deterministic fallback.
 */
export async function signInternalToken(caller: string, secret: string): Promise<string> {
  const raw = requireSecret(secret);
  const key = await getSecret(raw);
  const payload: InternalTokenPayload = { caller, exp: Date.now() + TOKEN_TTL_MS };
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  const sigHex = Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
  // payload is base64url so it's safe in a header value
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/[=+/]/g, (c) => (c === '=' ? '' : c === '+' ? '-' : '_'));
  return `${payloadB64}${SEP}${sigHex}`;
}

export type InternalTokenResult = { ok: true; caller: string } | { ok: false; reason: string };

/**
 * Validate a signed internal token. Returns the caller identity on
 * success, or a rejection reason on failure.
 *
 * @param token - The signed token to validate
 * @param secret - The INTERNAL_TOKEN_SECRET from env. When provided, uses
 *   the secret-based key instead of the deterministic fallback.
 */
export async function validateInternalToken(token: string, secret?: string): Promise<InternalTokenResult> {
  if (!secret) {
    return { ok: false, reason: 'internal token secret not configured' };
  }

  const sepIdx = token.lastIndexOf(SEP);
  if (sepIdx < 0) return { ok: false, reason: 'malformed token' };

  const payloadB64 = token.slice(0, sepIdx);
  const sigHex = token.slice(sepIdx + 1);

  // Reconstruct the original JSON from base64url
  let payloadJson: string;
  try {
    // Reverse base64url → base64
    const b64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
    // Pad to a multiple of 4
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    payloadJson = atob(padded);
  } catch {
    return { ok: false, reason: 'invalid payload encoding' };
  }

  let payload: InternalTokenPayload;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    return { ok: false, reason: 'invalid payload json' };
  }

  if (typeof payload.exp !== 'number' || typeof payload.caller !== 'string') {
    return { ok: false, reason: 'missing fields' };
  }

  // Check expiry
  if (Date.now() > payload.exp) {
    return { ok: false, reason: 'token expired' };
  }

  // Verify HMAC signature
  const key = await getSecret(secret);
  const data = new TextEncoder().encode(payloadJson);
  // Decode hex signature — must be even-length hex
  const hexPairs = sigHex.match(/.{2}/g);
  if (!hexPairs || hexPairs.some((h) => !/^[0-9a-fA-F]{2}$/.test(h))) {
    return { ok: false, reason: 'invalid signature encoding' };
  }
  const sigBytes = new Uint8Array(hexPairs.map((h) => parseInt(h, 16)));
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
  if (!valid) {
    return { ok: false, reason: 'invalid signature' };
  }

  return { ok: true, caller: payload.caller };
}

/**
 * Allowed caller identities. Reject any token with an unknown caller
 * to prevent an attacker from crafting tokens with arbitrary caller
 * values (even if they can't forge the signature, defence-in-depth).
 */
export const ALLOWED_INTERNAL_CALLERS = new Set([
  'investigator-do',
  'report-builder-do',
  'cron',
  'api-enrich-deep',
  'tie-enrich',
  'queue-consumer',
  // The worker's MCP server self-fetches its own /api/v1 routes through the
  // SELF binding. Its normal path carries the caller's API key, but the
  // operator-only routers (e.g. /api/v1/velociraptor/*) require the admin
  // gate, which does not accept API-key roles. The MCP server is an operator
  // surface, so those tools sign an internal token instead.
  'mcp-server',
]);
