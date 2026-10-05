/**
 * Lightweight client-side NATO Admiralty Code computation for IOCs that
 * come from the live-iocs / correlation feeds (where the API doesn't
 * attach a grade per row).
 *
 * Reliability is set by the source - known curated lists score B, OSINT
 * aggregators C, social/firehose D. Credibility is set by the artifact
 * type - file hashes are most persistent (=2), domains/URLs middle
 * (=3), IPs lowest (=4, because they rotate fast).
 *
 * Source IDs match the live-iocs handler. Unknown sources fall back to
 * D (reasonable upper bound for "unknown reliability").
 */

export type AdmiraltyReliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
export type AdmiraltyCredibility = 1 | 2 | 3 | 4 | 5 | 6;

export interface AdmiraltyGrade {
  reliability: AdmiraltyReliability;
  credibility: AdmiraltyCredibility;
  label: string;
}

/**
 * Client-side mirror of the canonical registry in
 * `api/src/lib/confidence.ts` (`SOURCE_RELIABILITY_REGISTRY`).
 *
 * ## Why this is duplicated
 *
 * The registry is the single source of truth for source reliability, but it
 * lives under `api/` and is ~32KB of data. `api/src/` and `src/` share no
 * runtime imports anywhere in this repo, and the eager bundle budget has
 * ~4KB of gzip headroom, so the client cannot import it.
 *
 * This follows the same pattern as `components/dfir/tool-count.ts`: a leaf
 * mirror, kept honest by `admiralty-drift.test.ts`, which asserts every
 * grade here equals the registry's. That test fails the build if either
 * side is edited without the other.
 *
 * Two grades were reconciled during the merge:
 *   - `yaraify` was B here and C in `api/src/lib/admiralty.ts`. Crowdsourced
 *     rules of uneven quality, so C wins — now consistent everywhere.
 *   - `abuseipdb` was B here and C in the registry. Deferred to the registry,
 *     which carries an explicit `known_bias` ("can be gamed"); whether
 *     AbuseIPDB should really be C is an analyst call, so the registry value
 *     stands rather than being silently overridden in two other tables.
 *
 * The `D` fallback for unrecognised sources is deliberate and NOT the same as
 * the registry's `C` default: this module grades rows that arrive from live
 * feeds without per-source provenance, and D is the honest ceiling for
 * "we do not know what this is".
 *
 * Exported so `api/test/lib/admiralty-drift.test.ts` can diff it against the
 * canonical registry. Not part of the UI's API surface.
 */
export const SOURCE_RELIABILITY: Record<string, AdmiraltyReliability> = {
  // abuse.ch family - curated, vetted, well-maintained
  urlhaus: 'B',
  threatfox: 'B',
  malwarebazaar: 'B',
  sslbl: 'B',
  yaraify: 'C',
  // institutional / curated lists
  'sans-isc': 'B',
  'cisa-kev': 'A',
  spamhaus: 'B',
  // OSINT aggregators / GitHub-maintained
  'c2-intel': 'C',
  otx: 'C',
  shodan: 'C',
  censys: 'C',
  netlas: 'C',
  greynoise: 'C',
  c2tracker: 'B',
  // social / community
  tweetfeed: 'D',
  reddit: 'D',
  // commercial wrappers
  virustotal: 'B',
  abuseipdb: 'C',
  // MyThreatIntel (sourced from many places - average C)
  mti: 'C',
  mythreatintel: 'C',
  // Dedicated AI / LLM threat intelligence. `ai-honeypots` is first-hand
  // telemetry (B) but its bulk is deliberately low-confidence scanners;
  // `llm-threatintel` is a single-analyst operation, so secondary reporting.
  'ai-honeypots': 'B',
  'llm-threatintel': 'C',
  // Curated open-source C2 feeds — B for the Cobalt Strike sources (scanner or
  // vendor research with real infrastructure attribution), C for the rest.
  'foxit-cobaltstrike': 'B',
  'carbonblack-c2': 'B',
  'threatview-c2': 'C',
  'c2intel-domains': 'C',
  'threatfox-hostfile': 'B',
  'threatfox-urls': 'B',
  'threatcluster-ip': 'C',
  'threatcluster-domains': 'C',
  'sslbl-ja3': 'B',
  greensnow: 'C',
  siberkapan: 'C',
  'bruteforce-login': 'C',
  'bl-de-ssh': 'C',
  'tsirolnik-spam': 'C',
  'botvrij-domain': 'C',
};

const KIND_CREDIBILITY: Record<string, AdmiraltyCredibility> = {
  hash: 2,
  ipv4: 4,
  ipv6: 4,
  ip: 4,
  domain: 3,
  url: 3,
  email: 3,
};

export function gradeForLiveIoc(source: string, kind: string): AdmiraltyGrade {
  const reliability = SOURCE_RELIABILITY[source.toLowerCase()] ?? 'D';
  const credibility = KIND_CREDIBILITY[kind.toLowerCase()] ?? 4;
  return { reliability, credibility, label: `${reliability}${credibility}` };
}
