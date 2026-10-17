/**
 * Compact relative-time formatter used by the live-snapshot cards.
 *
 * Distinct from `formatRelativeTime()` in services/rssService - that one
 * spells out units ("5 minutes ago"); this one is space-constrained for
 * timestamp slots in narrow card rows ("5m ago"). Same input convention:
 * an ISO-8601 string. Returns `''` for malformed input so the caller's
 * truthiness check renders nothing rather than "Invalid Date".
 */
export function shortRel(iso?: string): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '';
  const ageS = Math.max(0, (Date.now() - t) / 1000);
  if (ageS < 60) return 'now';
  if (ageS < 3600) return `${Math.floor(ageS / 60)}m ago`;
  if (ageS < 86400) return `${Math.floor(ageS / 3600)}h ago`;
  return `${Math.floor(ageS / 86400)}d ago`;
}

/**
 * "X ago" formatter used across the threat-intel feed/table rows. Differs from
 * `shortRel` above: floored units and a "just now" label (the convention these
 * pages already shipped), with a configurable label for missing/invalid input
 * (most pages want '', a couple want 'no timestamp'). Accepts ISO-8601 or any
 * `Date.parse`-able string (RFC-822 feed dates included).
 */
export function relativeAgo(iso?: string, emptyLabel = ''): string {
  if (!iso) return emptyLabel;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return emptyLabel;
  const diff = Math.max(0, Date.now() - t) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/**
 * Feed-row variant of {@link relativeAgo}.
 *
 * The feed builders write a zero-date sentinel (`1970-01-01…`) for rows with no
 * real timestamp. Ageing that honestly prints "20y ago" on every seeded row, so
 * those pages label it instead. This lives here rather than in each page because
 * three feed pages had grown byte-identical copies of the same guard — and a
 * fourth copy is exactly what happens when the rule lives in three places.
 */
export function relativeAgoSeeded(iso?: string, opts: { missing?: string; invalid?: string } = {}): string {
  if (!iso || iso.startsWith('1970')) return opts.missing ?? 'seed';
  return relativeAgo(iso, opts.invalid ?? 'unknown');
}
