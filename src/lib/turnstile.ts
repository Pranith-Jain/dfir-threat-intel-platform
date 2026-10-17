/**
 * Turnstile token acquisition for gated writes.
 *
 * ## Why this is a helper and not a `<div class="cf-turnstile">` in each form
 *
 * The gate applies to keyless mutations on shared-state routes (see
 * `api/src/lib/turnstile.ts`). Those live in tool panels, not sign-up forms, so
 * there is no form to drop a widget into — there is a `fetch()` that already
 * exists. This module gets a token for that fetch and nothing else: it loads
 * the script once, renders a widget off-screen, executes it, and returns the
 * header to merge in.
 *
 * ```ts
 * const res = await fetch('/api/v1/cyberpulse/scan', {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/json', ...(await turnstileHeaders('cyberpulse-scan')) },
 *   body: JSON.stringify({}),
 * });
 * ```
 *
 * ## When it is a no-op
 *
 * `/api/v1/features` reports `turnstile_required` + `turnstile_site_key`. If
 * the deployment has no secret configured, this helper resolves to `{}` — no
 * script load, no network call, no behaviour change. That is what lets the
 * server-side gate land before the widget exists.
 *
 * ## Failure behaviour
 *
 * If the challenge cannot produce a token (script blocked, network down,
 * ad-blocker, 20s challenge timeout) this **throws**, because a write that
 * silently omits the token comes back as an opaque 403 and the user's click
 * appears broken with no explanation. The caller's existing error path then
 * shows the real reason.
 */

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const SCRIPT_TIMEOUT_MS = 10_000;
const TOKEN_TIMEOUT_MS = 20_000;

interface TurnstileApi {
  render: (el: HTMLElement | string, opts: Record<string, unknown>) => string;
  execute: (widgetId: string, opts?: Record<string, unknown>) => void;
  remove?: (widgetId?: string) => void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

let featurePromise: Promise<{ required: boolean; siteKey: string }> | null = null;

/**
 * Read the deployment's Turnstile configuration from `/api/v1/features`.
 *
 * Cached for the page's lifetime: the flags only flip when an operator sets or
 * clears a secret, and that needs a reload to take effect anyway. A failed
 * probe resolves to "not required" so a transient network blip can never brick
 * every write in the app.
 */
export async function turnstileFeatures(): Promise<{ required: boolean; siteKey: string }> {
  if (!featurePromise) {
    featurePromise = (async () => {
      try {
        const res = await fetch('/api/v1/features', { headers: { accept: 'application/json' } });
        if (!res.ok) return { required: false, siteKey: '' };
        const data = (await res.json()) as { turnstile_required?: boolean; turnstile_site_key?: string };
        return {
          required: data.turnstile_required === true && !!data.turnstile_site_key,
          siteKey: data.turnstile_site_key ?? '',
        };
      } catch {
        return { required: false, siteKey: '' };
      }
    })();
  }
  return featurePromise;
}

/** Reset the cached probe. Exposed for tests and for an explicit retry. */
export function resetTurnstileFeatures(): void {
  featurePromise = null;
}

let scriptPromise: Promise<TurnstileApi> | null = null;

/**
 * Load `api.js?render=explicit` once and resolve when the global is usable.
 *
 * Polls for the global rather than stubbing `turnstile.ready`: api.js installs
 * the global itself when it boots, so a pre-installed stub gets replaced and a
 * ready-callback shim silently never fires in some load orders.
 */
function loadScript(): Promise<TurnstileApi> {
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise<TurnstileApi>((resolve, reject) => {
    if (window.turnstile?.render) {
      resolve(window.turnstile);
      return;
    }
    const script = document.createElement('script');
    script.src = SCRIPT_URL;
    script.async = true;
    script.defer = true;
    script.onerror = () => {
      scriptPromise = null;
      reject(new Error('turnstile script failed to load'));
    };
    document.head.appendChild(script);

    const deadline = Date.now() + SCRIPT_TIMEOUT_MS;
    const poll = window.setInterval(() => {
      if (window.turnstile?.render) {
        window.clearInterval(poll);
        resolve(window.turnstile);
      } else if (Date.now() > deadline) {
        window.clearInterval(poll);
        scriptPromise = null;
        reject(new Error('turnstile script load timed out'));
      }
    }, 50);
  });
  return scriptPromise;
}

/**
 * Fetch a single-use token for `action`.
 *
 * Explicit render into an off-screen host, then `execute()` on that widget id:
 * Turnstile hands the token back through the widget's `callback`. Real visitors
 * never see anything; a suspicious one may get the interactive challenge, which
 * is the point. Tokens are single-use, so nothing is cached between requests.
 */
export async function getTurnstileToken(action: string): Promise<string> {
  const turnstile = await loadScript();
  const { siteKey } = await turnstileFeatures();
  if (!siteKey) throw new Error('turnstile site key missing');

  const container = document.createElement('div');
  // Off-screen rather than display:none — a zero-size or hidden container can
  // stop the widget from ever firing its callback.
  container.style.cssText = 'position:absolute;left:-9999px;top:0;width:300px;height:65px;';
  document.body.appendChild(container);

  try {
    return await new Promise<string>((resolve, reject) => {
      const timer = window.setTimeout(() => reject(new Error('turnstile challenge timed out')), TOKEN_TIMEOUT_MS);
      const finish = (fn: () => void) => {
        window.clearTimeout(timer);
        fn();
      };

      const widgetId = turnstile.render(container, {
        sitekey: siteKey,
        action,
        size: 'flexible',
        execution: 'execute',
        appearance: 'interaction-only',
        callback: (value: string) => finish(() => resolve(value)),
        'error-callback': () => finish(() => reject(new Error('turnstile challenge failed'))),
      });

      try {
        turnstile.execute(widgetId);
      } catch (err) {
        finish(() => reject(err instanceof Error ? err : new Error(String(err))));
      }
    });
  } finally {
    container.remove();
  }
}

/**
 * Headers to merge into a gated mutation. Returns `{}` when the deployment has
 * no challenge configured or the request is a read, so callers can spread it
 * unconditionally.
 *
 * Pass the same `action` on both sides: the server can pin it to a surface, and
 * a shared constant keeps the two from drifting.
 */
export async function turnstileHeaders(action: string, method = 'POST'): Promise<Record<string, string>> {
  const upper = method.toUpperCase();
  if (upper === 'GET' || upper === 'HEAD' || upper === 'OPTIONS') return {};
  const features = await turnstileFeatures();
  if (!features.required) return {};
  return { 'cf-turnstile-response': await getTurnstileToken(action) };
}
