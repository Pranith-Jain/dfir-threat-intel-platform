/**
 * Pillar taxonomy — the top-level wayfinding layer for both surfaces.
 *
 * Problem this solves: the registries in `dfir-hubs.ts` and
 * `threatintel-hubs.ts` together declare 40 hubs, and the sidebar emitted
 * each one as its own top-level group. Forty undifferentiated collapsible
 * groups reads as a tool dump rather than a product — a visitor can't tell
 * which area answers their question, and nothing in the nav conveys the
 * shape of the platform.
 *
 * A pillar is a labelled band that groups the hubs answering the same kind
 * of question. It is presentation-only:
 *
 *   - No hub is dropped, merged, hidden or re-routed.
 *   - `path`, `label`, `icon`, `badge` and page membership are untouched.
 *   - The catalog pages still list every page under its own hub category.
 *
 * So the taxonomy can be re-cut at any time without touching routing or data.
 *
 * `malware` and `ai-security` exist as hub ids on BOTH surfaces and resolve
 * to the same pillar in each case, so the map is keyed by bare hub id.
 */

export interface Pillar {
  /** Stable id; used as the map key and in tests. */
  id: string;
  /** Rendered as the sidebar band label. */
  label: string;
  /** One-line description of what the band is for. */
  blurb: string;
}

/**
 * Pillar order is significant: it is the order bands appear in the sidebar.
 * Ordered roughly by the analyst's workflow — orient, scope an indicator,
 * assess exposure, investigate, respond — rather than alphabetically.
 */
export const PILLARS: readonly Pillar[] = [
  {
    id: 'threat-landscape',
    label: 'Threat Landscape',
    blurb: 'Who is active, what they are running, and where it is trending.',
  },
  {
    id: 'iocs-enrichment',
    label: 'IOCs & Enrichment',
    blurb: 'Indicator collection, pivoting and reputation across 60+ sources.',
  },
  {
    id: 'vulns-detection',
    label: 'Vulnerabilities & Detection',
    blurb: 'CVE/KEV triage, rule engineering, STIX/TAXII and hunting.',
  },
  {
    id: 'ransomware-darkweb',
    label: 'Ransomware & Dark Web',
    blurb: 'Leak sites, group tracking, breach disclosures and dark-web intel.',
  },
  {
    id: 'malware-artifacts',
    label: 'Malware & Artifacts',
    blurb: 'Sample triage, binary decoding, PCAP and artifact parsing.',
  },
  {
    id: 'cloud-identity',
    label: 'Cloud, Identity & AppSec',
    blurb: 'Cloud posture, IAM/RBAC, email defense, API and AI security.',
  },
  {
    id: 'investigation',
    label: 'Investigation & Research',
    blurb: 'Copilot-driven investigation, pivoting, OSINT and reporting.',
  },
  {
    id: 'sources-frameworks',
    label: 'Sources & Frameworks',
    blurb: 'Feed inventory, knowledge base, MITRE/ATT&CK and GRC models.',
  },
] as const;

/**
 * Hub id → pillar id. Every hub in both registries must appear here; the
 * test suite asserts full coverage so a newly added hub cannot silently fall
 * back to an unbanded position.
 */
export const HUB_PILLAR: Readonly<Record<string, string>> = {
  // ── Threat Landscape ──────────────────────────────────────────────
  'threatintel:actors': 'threat-landscape',
  'threatintel:campaigns': 'threat-landscape',
  'threatintel:monitoring-estate': 'threat-landscape',
  'threatintel:predictive': 'threat-landscape',
  'threatintel:social': 'threat-landscape',

  // ── IOCs & Enrichment ─────────────────────────────────────────────
  'threatintel:iocs': 'iocs-enrichment',
  'threatintel:infra': 'iocs-enrichment',
  'threatintel:phishing': 'iocs-enrichment',
  'dfir:ioc-triage': 'iocs-enrichment',
  'dfir:domain-network': 'iocs-enrichment',
  'dfir:identity-osint': 'iocs-enrichment',

  // ── Vulnerabilities & Detection ───────────────────────────────────
  'threatintel:cves': 'vulns-detection',
  'threatintel:detections': 'vulns-detection',
  'dfir:vuln': 'vulns-detection',
  'dfir:detection': 'vulns-detection',
  'dfir:stix-taxii': 'vulns-detection',

  // ── Ransomware & Dark Web ─────────────────────────────────────────
  'threatintel:darkweb': 'ransomware-darkweb',

  // ── Malware & Artifacts ───────────────────────────────────────────
  'threatintel:malware': 'malware-artifacts',
  'dfir:malware': 'malware-artifacts',
  'dfir:file-analysis': 'malware-artifacts',
  'dfir:artifacts': 'malware-artifacts',

  // ── Cloud, Identity & AppSec ──────────────────────────────────────
  'threatintel:ai-security': 'cloud-identity',
  'dfir:cloud': 'cloud-identity',
  'dfir:api': 'cloud-identity',
  'dfir:ai-security': 'cloud-identity',
  'dfir:asset-attack': 'cloud-identity',
  'dfir:email': 'cloud-identity',

  // ── Investigation & Research ──────────────────────────────────────
  'threatintel:research-hub': 'investigation',
  'threatintel:osint': 'investigation',
  'threatintel:tools': 'investigation',
  'dfir:copilot': 'investigation',
  'dfir:reports': 'investigation',
  'dfir:overview': 'investigation',

  // ── Sources & Frameworks ──────────────────────────────────────────
  'threatintel:feeds': 'sources-frameworks',
  'threatintel:external': 'sources-frameworks',
  'threatintel:wiki': 'sources-frameworks',
  'dfir:frameworks': 'sources-frameworks',
  'dfir:grc': 'sources-frameworks',
} as const;

/** Which registry a hub id came from. */
export type Surface = 'dfir' | 'threatintel';

/** Namespace a hub id so `malware` on DFIR and on threat-intel stay distinct. */
export function hubKey(surface: Surface, hubId: string): string {
  return `${surface}:${hubId}`;
}

/**
 * Resolve the pillar for a hub. Falls back to the first pillar so an
 * unmapped hub still renders (in a band) rather than vanishing from the
 * sidebar; `pillars.test.ts` fails the build if any real hub is unmapped, so
 * the fallback exists for robustness, not to paper over gaps.
 */
export function pillarFor(surface: Surface, hubId: string): Pillar {
  const id = HUB_PILLAR[hubKey(surface, hubId)];
  const found = id === undefined ? undefined : PILLARS.find((p) => p.id === id);
  return found ?? PILLARS[0]!;
}

/** Sort key for a hub, so hubs of one pillar end up adjacent in `PILLARS` order. */
export function pillarOrder(surface: Surface, hubId: string): number {
  return PILLARS.findIndex((p) => p.id === pillarFor(surface, hubId).id);
}
