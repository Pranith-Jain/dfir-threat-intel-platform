/**
 * Operator admin token management.
 *
 * SECURITY: The primary auth mechanism is an HttpOnly session cookie
 * (set by POST /api/v1/admin/session). JavaScript cannot read HttpOnly
 * cookies, so XSS cannot exfiltrate the token from the cookie jar.
 * The browser sends the cookie automatically on every API request.
 *
 * localStorage is used ONLY as a UI state hint (to show/hide the admin
 * panel) - it does NOT store the token itself. The `adminAuthHeaders()`
 * function returns empty headers; the browser sends the HttpOnly cookie
 * automatically.
 *
 * For non-browser API clients (curl, scripts), use the
 * `Authorization: Bearer <token>` header directly.
 */

const SESSION_STATE_KEY = 'adminSessionActive';

export function readAdminToken(): string | null {
  // No token in localStorage - rely on HttpOnly cookie.
  // Return a non-null sentinel so UI knows a session exists.
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(SESSION_STATE_KEY) === 'true' ? '__cookie__' : null;
  } catch {
    return null;
  }
}

export function writeAdminToken(_token: string): void {
  if (typeof window === 'undefined') return;
  try {
    // Store only a boolean flag - never the token itself.
    window.localStorage.setItem(SESSION_STATE_KEY, 'true');
  } catch {
    // Storage quota or private browsing - non-fatal.
  }
}

export function clearAdminToken(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(SESSION_STATE_KEY);
  } catch {
    // non-fatal
  }
}

/**
 * Build headers for admin API requests.
 *
 * The HttpOnly session cookie is sent automatically by the browser -
 * no token header is needed. Returns empty headers to avoid leaking
 * any token value via JavaScript-accessible headers.
 *
 * NOTE: Non-browser clients (curl, scripts) should pass the token
 * directly via `Authorization: Bearer <token>`.
 */
export function adminAuthHeaders(): Record<string, string> {
  return {};
}

/**
 * Create an HttpOnly session cookie by calling POST /api/v1/admin/session.
 * The browser will store the cookie and send it automatically on all
 * subsequent API requests - no JS involvement needed.
 *
 * Call this after the user enters their admin token. Only a boolean UI hint is
 * stored in localStorage; the token itself is never persisted in
 * JavaScript-readable storage.
 */
export async function createAdminSession(token: string, baseUrl = ''): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}/api/v1/admin/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
      credentials: 'same-origin', // include cookies
    });
    if (res.ok) {
      writeAdminToken(token); // also keep in localStorage for UI state
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Clear the admin session cookie (logout).
 */
export async function clearAdminSession(baseUrl = ''): Promise<void> {
  try {
    await fetch(`${baseUrl}/api/v1/admin/session`, {
      method: 'DELETE',
      credentials: 'same-origin',
    });
  } catch {
    // best-effort
  }
  clearAdminToken();
}
