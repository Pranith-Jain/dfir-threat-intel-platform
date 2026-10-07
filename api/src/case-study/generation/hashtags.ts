/**
 * Hashtag intelligence: derive specific, on-topic hashtags from a post's
 * actual entities (CVE id, vendor, product, malware family, threat group,
 * sectors) plus a small per-type base. Replaces the generic "#cybersecurity
 * #infosec" stacks the LLM defaults to — specific tags reach the people
 * actually searching the campaign / CVE / sector. Pure + deterministic.
 */

export interface HashtagInput {
  type: string;
  title?: string;
  evidence?: Record<string, unknown>;
  /** Max tags returned (default 3 — LinkedIn 2026 algorithm penalizes >3). */
  max?: number;
}

/** Per-type base tags — used to round out the entity-derived ones. */
const BASE: Record<string, string[]> = {
  cve: ['infosec', 'vulnerability', 'CVE'],
  ransom: ['ransomware', 'infosec', 'DFIR'],
  breach: ['databreach', 'infosec'],
  actor: ['threatintel', 'APT'],
  malware: ['malware', 'threatintel'],
  aisec: ['AISecurity', 'infosec'],
  scam: ['scam', 'infosec'],
  intel: ['threatintel', 'OSINT'],
  osint: ['OSINT', 'threatintel'],
  trend: ['cybersecurity', 'threatintel'],
  analysis: ['cybersecurity', 'infosec'],
  agentic: ['AISecurity', 'AgenticAI'],
  hunting: ['threatintel', 'DFIR'],
  report: ['threatintel', 'cybersecurity'],
};
const DEFAULT_BASE = ['cybersecurity', 'infosec', 'threatintel'];

/** Strip everything but ASCII alphanumerics (hashtags can't contain hyphens,
 *  spaces, or punctuation). A CVE id loses its hyphens and becomes a single
 *  tag token. */
function normalize(s: unknown): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[^A-Za-z0-9]+/g, '');
}

function strings(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
  if (typeof v === 'string') return [v];
  return [];
}

/**
 * Build an ordered, deduped hashtag list. Entity-specific tags come first so
 * they survive the cap; the per-type base fills any remaining slots.
 */
export function buildHashtags(input: HashtagInput): string[] {
  const ev = input.evidence ?? {};
  const max = input.max ?? 3;

  // Priority order: most specific → least.
  const raw: string[] = [];
  for (const cve of strings(ev.cveId)) raw.push(normalize(cve));
  for (const g of strings(ev.group)) raw.push(normalize(g));
  for (const f of strings(ev.family)) raw.push(normalize(f));
  for (const v of strings(ev.vendor)) raw.push(normalize(v));
  for (const p of strings(ev.product)) raw.push(normalize(p));
  for (const s of strings(ev.sectors)) raw.push(normalize(s));
  raw.push(...(BASE[input.type] ?? DEFAULT_BASE));

  const out: string[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    const tag = normalize(r);
    if (tag.length < 2 || tag.length > 30) continue;
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(`#${tag}`);
    if (out.length >= max) break;
  }
  return out;
}
