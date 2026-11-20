/** Small, defensive helpers shared by the CyberView replication pages.
 * Upstream data frequently omits optional fields, so every accessor here
 * coerces to a safe value instead of throwing on render. */

export function asArray<T>(value: readonly T[] | null | undefined): T[] {
  return Array.isArray(value) ? [...value] : [];
}

export function text(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value);
}

export function fmtDay(iso?: string | null): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '';
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }).format(t);
}

export function fmtDayFull(iso?: string | null): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '';
  return new Intl.DateTimeFormat('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(t);
}

export function fmtNum(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  if (value >= 1e9) return `${(value / 1e9).toFixed(1).replace(/\.0$/, '')}B`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(1).replace(/\.0$/, '')}M`;
  if (value >= 1e4) return `${Math.round(value / 1e3)}K`;
  return Math.round(value).toLocaleString('en-US');
}

/** Case-insensitive substring match that never throws on missing fields. */
export function matches(haystack: unknown, needle: string): boolean {
  return text(haystack).toLowerCase().includes(needle.toLowerCase());
}

export function topCounts(values: Array<string | null | undefined>, limit = 8): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = text(value).trim();
    if (key) counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit);
}
