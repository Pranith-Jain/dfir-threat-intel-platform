import type { Env } from './env';
import { parseToolHosts, toolHostList, toolHostForPath } from '../api/src/lib/surface-hosts';

/**
 * Presentation surface — which front door a request is for.
 *
 *   portfolio  pranithjain.qzz.io                     portfolio nav + Home
 *   tools      crucible./panopticon./scout.…qzz.io    tools nav + ToolsHome
 *
 * Mirrors `src/lib/surface.ts` on the client. The worker resolves it from the
 * request hostname so it can serve the matching prerendered HTML tree
 * (`dist/__prerendered-tools/`) and so the browser — which then resolves the
 * same surface from `location.hostname` — renders identical chrome.
 *
 * The prefix→host map itself lives in `api/src/lib/surface-hosts.ts` and is
 * configured by `env.TOOLS_HOSTS`; keep that var identical to
 * `TOOL_HOSTS_BY_PATH` in `src/lib/surface.ts` or the two sides will disagree
 * about which surface they are on and show the wrong nav for the first frame.
 */
export type Surface = 'portfolio' | 'tools';

/**
 * Resolve the surface for a request hostname against `env.TOOLS_HOSTS`.
 *
 * Fails safe: an unset, empty, or whitespace-only `TOOLS_HOSTS` collapses
 * every request to the portfolio surface, which is exactly the pre-split
 * behaviour — the split can only engage once the var is configured with a
 * hostname that actually exists.
 *
 * Comparison is case-insensitive and ignores any port, so local dev on
 * `localhost:8787` and the real `crucible.pranithjain.qzz.io` both work.
 */
export function surfaceForHostname(hostname: string, env: Env): Surface {
  const hosts = toolHostList(env.TOOLS_HOSTS);
  if (hosts.length === 0) return 'portfolio';
  const host = (hostname ?? '').trim().toLowerCase().split(':')[0] ?? '';
  return hosts.includes(host) ? 'tools' : 'portfolio';
}

/** Path prefix a tool host's root should redirect to (null for the apex). */
export function rootRedirectForHost(
  pathname: string,
  hostname: string,
  surface: Surface,
  rawToolsHosts?: string | null
): string | null {
  if (pathname !== '/' || surface !== 'tools') return null;
  const host = (hostname ?? '').toLowerCase();
  return parseToolHosts(rawToolsHosts).find((entry) => entry.host === host)?.prefix ?? null;
}

/**
 * Hostname that owns `pathname`, or `null` when the apex owns it.
 * Used to give each path exactly one canonical origin across hosts.
 */
export function owningToolHost(pathname: string, env: Env): string | null {
  return toolHostForPath(pathname, env.TOOLS_HOSTS);
}
