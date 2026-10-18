import type { Candidate, DedupRecord } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';

const EUVD_URL = 'https://euvdservices.enisa.europa.eu/api/lastvulnerabilities';
const WINDOW_MS = 7 * 24 * 3600 * 1000;

interface EuvdEntry {
  id?: string;
  description?: string;
  datePublished?: string;
  baseScore?: number;
}

/** Parse EUVD's `datePublished` ("Oct 13, 2026, 8:38:59 AM") as UTC.
 *  The bare `new Date(...)` parses date+time strings in the host's local
 *  zone, which would shift the recency window (and the cutoff) by the
 *  runtime offset — correct only by accident in UTC workers, wrong in any
 *  TZ. Falls back to native parsing for anything that doesn't match the shape.
 */
function parseEuvdDate(s: string): number {
  const m = s.match(/^([A-Z][a-z]{2})\s+(\d{1,2}),\s+(\d{4}),\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)$/i);
  if (!m) return Date.parse(s);
  const months: Record<string, number> = {
    jan: 0,
    feb: 1,
    mar: 2,
    apr: 3,
    may: 4,
    jun: 5,
    jul: 6,
    aug: 7,
    sep: 8,
    oct: 9,
    nov: 10,
    dec: 11,
  };
  const mi = months[m[1]!.toLowerCase().slice(0, 3)];
  if (mi === undefined) return Number.NaN;
  let h = Number(m[4]);
  const ap = m[7]!.toUpperCase();
  if (ap === 'PM' && h !== 12) h += 12;
  if (ap === 'AM' && h === 12) h = 0;
  return Date.UTC(Number(m[3]), mi, Number(m[2]), h, Number(m[5]), Number(m[6]));
}

export interface DiscoverEuvdDeps {
  fetch: typeof globalThis.fetch;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

/** Recently published EU vulnerabilities (ENISA EUVD). Keyless. */
export async function discoverEuvd(deps: DiscoverEuvdDeps): Promise<Candidate[]> {
  const out: Candidate[] = [];
  try {
    const r = await deps.fetch(EUVD_URL, {
      headers: { Accept: 'application/json', 'User-Agent': 'pranithjain.qzz.io case-study-discovery' },
    });
    if (!r.ok) throw new Error(`EUVD ${r.status}`);
    const all = (await r.json()) as EuvdEntry[];
    const cutoff = deps.now.getTime() - WINDOW_MS;
    for (const v of Array.isArray(all) ? all : []) {
      if (!v.id || !v.datePublished) continue;
      const pub = parseEuvdDate(v.datePublished);
      if (!Number.isFinite(pub) || pub < cutoff) continue;
      // v.id already starts with "EUVD-"; strip it so topicKey's own "euvd-"
      // prefix isn't doubled (e.g. "euvd-euvd-2026-1001").
      const key = topicKey('euvd', v.id.toLowerCase().replace(/^euvd-/, ''));
      const dedup = await deps.getDedup(key);
      const score = finalScore({
        recency: recencyScore(new Date(pub).toISOString(), deps.now),
        severity: severityScore({ cvss: v.baseScore }),
        novelty: noveltyScore(dedup, deps.now),
        sourceWeight: 0.75,
      });
      out.push({
        key,
        type: 'cve',
        title: `${v.id}${typeof v.baseScore === 'number' ? ` (CVSS ${v.baseScore})` : ''}`,
        rationale: `ENISA EUVD · ${v.datePublished.slice(0, 10)}${v.description ? ` · ${v.description.slice(0, 100)}` : ''}`,
        score,
        evidence: {
          id: v.id,
          baseScore: v.baseScore,
          datePublished: v.datePublished,
          description: v.description,
          url: `https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(v.id)}`,
        },
        discoveredAt: deps.now.toISOString(),
        status: 'pending',
      });
    }
  } catch {}
  return out;
}
