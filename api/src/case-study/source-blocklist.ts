/**
 * Sources barred from every discovery / pending-candidate surface.
 *
 * ExploitGrid was removed from the live-CVE feed and from the `exploits`
 * discovery runner (2026-10-19): its rows are unreviewed community PoC
 * submissions (`status: PENDING` on every live record), and the product owner
 * does not want them surfaced at all — not as a candidate, not as a source
 * link in the pending queue.
 *
 * The runner change alone was not enough. Candidates live in KV for up to 30
 * days, so entries discovered *before* the change kept appearing in
 * `/admin` → Pending with `exploitgrid.net` source links until their TTL
 * expired. This module is the single choke point both paths consult, so the
 * rule is enforced on the way in (discovery) and on the way out (the admin
 * queue) without waiting for storage to age out.
 *
 * This is a product decision, not a bug workaround — do not "tidy it away"
 * when the last old candidate expires.
 */

/** Hostnames (no scheme, no `www.`) whose candidates must never be surfaced. */
export const BLOCKED_DISCOVERY_HOSTS: readonly string[] = ['exploitgrid.net'];

function isBlockedUrl(value: unknown): boolean {
  if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return false;
  let host: string;
  try {
    host = new URL(value).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return false;
  }
  return BLOCKED_DISCOVERY_HOSTS.some((b) => host === b || host.endsWith(`.${b}`));
}

/**
 * True when a candidate carries a blocked source anywhere in its evidence.
 *
 * Walks the URL-bearing fields the runners actually populate (`url`, `urls[]`,
 * `sources[]`, `sourceUrl`, `victims[].url`, plus the `link`/`permalink` spellings
 * used by a few RSS runners) rather than stringifying the whole evidence blob:
 * stringifying would also match a *mention* of the host in a description, and a
 * post about a third party citing an ExploitGrid URL is not the same thing as a
 * candidate sourced from ExploitGrid.
 */
export function candidateUsesBlockedSource(candidate: { evidence?: Record<string, unknown> } | null): boolean {
  const ev = candidate?.evidence;
  if (!ev || typeof ev !== 'object') return false;
  const check = (v: unknown) => {
    if (isBlockedUrl(v)) return true;
    return false;
  };
  if (check(ev.url) || check(ev.sourceUrl) || check(ev.link) || check(ev.permalink)) return true;
  for (const field of ['urls', 'sources', 'references'] as const) {
    const arr = ev[field];
    if (Array.isArray(arr) && arr.some((u) => check(u))) return true;
  }
  const victims = ev.victims;
  if (Array.isArray(victims)) {
    for (const v of victims) {
      if (v && typeof v === 'object' && check((v as Record<string, unknown>).url)) return true;
    }
  }
  return false;
}
