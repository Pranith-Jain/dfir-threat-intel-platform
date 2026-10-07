export function slugify(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/[^\w\s-]/g, ' ')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function nonEmpty(s: string, field: string): string {
  if (!s || !s.trim()) throw new Error(`${field} must not be empty`);
  return s;
}

export function cveKey(cveId: string): string {
  return nonEmpty(cveId, 'cveId').toLowerCase();
}

export function actorKey(name: string): string {
  return `actor-${slugify(nonEmpty(name, 'name'))}`;
}

export function malwareKey(family: string): string {
  return `malware-${slugify(nonEmpty(family, 'family'))}`;
}

/**
 * Generic stable key for the RSS/JSON-derived topics (breach, scam, aisec,
 * intel). `seed` is the breach name / article title / CVE id — slugified
 * and truncated so keys stay bounded and dedupe-stable across runs.
 */
export function topicKey(prefix: string, seed: string): string {
  return `${prefix}-${slugify(nonEmpty(seed, 'seed')).slice(0, 60)}`;
}

export function slotIdFor(slotAtIso: string): string {
  return `slot-${slotAtIso.toLowerCase().replace(/[:.]/g, '-')}`;
}
