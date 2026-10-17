import type { Context } from 'hono';
import type { Env } from '../env';
import { turnstileConfig } from '../lib/turnstile';

/**
 * GET /api/v1/features
 *
 * Public, unauthenticated boolean map of which optional self-hosted
 * bridges this deployment has configured. The frontend probes this once
 * on load to hide dormant tools from nav + search until an operator
 * sets the matching `*_BRIDGE_URL` secret — a tool that can only return
 * a 503 setup hint shouldn't be advertised.
 *
 * Returns only booleans — never the URLs or tokens themselves — so it's
 * safe to expose without auth. Short edge-cache: the flags flip within a
 * minute of setting/clearing a secret (which takes effect on the next
 * request without a redeploy).
 */
export function featuresHandler(c: Context<{ Bindings: Env }>): Response {
  const turnstile = turnstileConfig(c.env);
  return c.json(
    {
      // Always-on: /api/v1/sample/scan fans out to free public lookup APIs
      // (VirusTotal, MalwareBazaar, YARAify, Hybrid Analysis, ...) plus
      // surfaces one-click deep links to free public sandboxes. No secret
      // required. See docs/free/sample-scan.md.
      samples: true,
      // Public site key — rendered into every widget by definition, so this
      // endpoint discloses nothing. `true` means the secret is configured and
      // keyless mutations on the gated prefixes require a challenge token; the
      // frontend uses this to decide whether to load the Turnstile script at
      // all, so an unconfigured deployment pays nothing.
      turnstile_required: turnstile.enabled,
      turnstile_site_key: turnstile.siteKey,
    },
    200,
    { 'Cache-Control': 'public, max-age=60' }
  );
}
