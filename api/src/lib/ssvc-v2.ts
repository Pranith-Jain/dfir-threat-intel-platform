/**
 * SSVC v2 — CISA Deployer decision model.
 *
 * Ported from CVE Intel's `crates/cve-core/src/ssvc.rs` (scoring version
 * 2.0). This is the *CISA Deployer* tree with the four canonical outcomes
 * (`Act` / `Attend` / `Track*` / `Track`) — deliberately distinct from the
 * platform's existing `ssvc-v.ts`, which implements the older SSVC-V variant
 * with `act` / `prioritise` / `track` / `watch` outcomes and a different
 * traversal order. Both are kept: SSVC-V rides the feed surfaces, SSVC v2
 * rides single-CVE triage, and mixing the vocabularies would misreport a
 * decision to an analyst who knows the model.
 *
 * ## How the inputs resolve
 *
 * - **Exploitation** — the *higher* of CISA's published value and the live
 *   signals (CISA KEV, exploitation reported by VulnCheck KEV / ENISA EUVD,
 *   EPSS ≥ 0.90, a public exploit). CISA's assessment is a point-in-time
 *   snapshot; live evidence can raise the value above it but never lowers it.
 * - **Automatable** — CISA's value when present, else estimated. A system
 *   exposure other than `open` forces `no`: a closed network cannot be
 *   wormed, whatever CISA said about the bug.
 * - **Technical Impact** — CISA's value when present, else a CVSS proxy
 *   (`≥ 9` → total, otherwise partial).
 * - **Mission & Well-being** — derived from CVSS (`≥ 9` high, `≥ 7` medium,
 *   else low). It is the row selector in the decision table, not a signal.
 *
 * CISA values outside the SSVC vocabulary are ignored rather than trusted.
 */

export const SSVC_SCORING_VERSION = '2.0';

export type SsvcExploitation = 'none' | 'poc' | 'active';
export type SsvcAutomatable = 'yes' | 'no';
export type SsvcExposure = 'small' | 'controlled' | 'open';
export type SsvcTechnicalImpact = 'partial' | 'total';
export type SsvcMissionWellbeing = 'low' | 'medium' | 'high';
export type SsvcAction = 'Act' | 'Attend' | 'Track*' | 'Track';

/** CISA's published SSVC options, as carried in a CVE record's ADP container. */
export interface CisaSsvc {
  exploitation: string;
  automatable: string;
  technical_impact: string;
  version?: string;
  timestamp?: string;
}

export interface SsvcDecision {
  scoring_version: string;
  exploitation: SsvcExploitation;
  exposure: SsvcExposure;
  automatable: SsvcAutomatable;
  technical_impact: SsvcTechnicalImpact;
  mission_wellbeing: SsvcMissionWellbeing;
  action: SsvcAction;
  rationale: string;
  /** `"CISA Vulnrichment"` when CISA's published options were used for any
   *  input, otherwise `"estimated"`. */
  inputs_source: 'CISA Vulnrichment' | 'estimated';
}

const EXPLOITATION_ORDER: readonly SsvcExploitation[] = ['none', 'poc', 'active'];

/** PoC tiers that count as "a proof of concept exists". */
const POC_TIERS = new Set([
  'WEAPONIZED',
  'PUBLIC_EXPLOIT_REMOTE',
  'PUBLIC_EXPLOIT',
  'PUBLIC_POC_HIGH_QUALITY',
  'PUBLIC_POC_LOW_QUALITY',
  'PUBLIC',
  'POC',
  'PROOF_OF_CONCEPT',
]);

/**
 * CISA Deployer decision table.
 * `(exploitation, automatable, technical impact) → [low, medium, high]`.
 */
const DECISION_TABLE: Record<string, readonly [SsvcAction, SsvcAction, SsvcAction]> = {
  'none|no|partial': ['Track', 'Track', 'Track'],
  'none|no|total': ['Track', 'Track', 'Track*'],
  'none|yes|partial': ['Track', 'Track', 'Attend'],
  'none|yes|total': ['Track', 'Track', 'Attend'],
  'poc|no|partial': ['Track', 'Track', 'Track*'],
  'poc|no|total': ['Track', 'Track*', 'Attend'],
  'poc|yes|partial': ['Track', 'Track', 'Attend'],
  'poc|yes|total': ['Track', 'Track*', 'Attend'],
  'active|no|partial': ['Track', 'Track', 'Attend'],
  'active|no|total': ['Track', 'Attend', 'Act'],
  'active|yes|partial': ['Attend', 'Attend', 'Act'],
  'active|yes|total': ['Attend', 'Act', 'Act'],
};

const GUIDANCE: Record<SsvcAction, string> = {
  Act: 'Requires immediate attention from supervisory and leadership staff; remediate as soon as possible (patch, isolate, or mitigate).',
  Attend: 'Requires attention from supervisory staff; remediate sooner than standard update timelines.',
  'Track*': 'Monitor closely for change; remediate within standard update timelines.',
  Track: 'No action required at this time; remediate within standard update timelines.',
};

/** Pick the vocabulary entry matching `value`, or undefined if it is not in
 *  the vocabulary. CISA strings outside the vocabulary are ignored. */
function pick(value: string | undefined, allowed: readonly string[]): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return allowed.find((a) => a.toLowerCase() === trimmed.toLowerCase());
}

function rank(exploitation: string): number {
  const i = EXPLOITATION_ORDER.indexOf(exploitation as SsvcExploitation);
  return i === -1 ? 0 : i;
}

/**
 * Classify exploitation from live signals only.
 * EPSS ≥ 0.90 means "active"; a public PoC or EPSS ≥ 0.10 means "poc".
 */
export function classifyExploitation(exploited: boolean, epss: number, pocConfidence: string): SsvcExploitation {
  if (exploited || epss >= 0.9) return 'active';
  if (POC_TIERS.has(pocConfidence.toUpperCase()) || epss >= 0.1) return 'poc';
  return 'none';
}

export interface SsvcInput {
  /** In the CISA KEV catalog. */
  in_kev: boolean;
  /** Other sources reporting exploitation, e.g. `['VulnCheck KEV', 'ENISA EUVD']`. */
  reported_exploited?: readonly string[];
  /** FIRST EPSS probability, 0–1. */
  epss_probability: number;
  /** Public-exploit tier (see `PocConfidence`). */
  poc_confidence: string;
  /** CVSS base score, 0–10. */
  cvss_score: number;
  /** System exposure. Anything unrecognised is treated as `open`. */
  exposure: string;
  /** CISA's published SSVC options, when the record carries them. */
  cisa?: CisaSsvc | null;
}

/**
 * Compute the SSVC v2 Deployer decision.
 *
 * `reportedExploited` names the non-CISA sources that report exploitation.
 * They raise the Exploitation input and appear in the rationale, but they do
 * not earn the KEV risk points — only CISA KEV does that.
 */
export function ssvcDecision(input: SsvcInput): SsvcDecision {
  const epss = clamp(input.epss_probability, 0, 1);
  const cvss = clamp(input.cvss_score, 0, 10);
  const reported = input.reported_exploited ?? [];

  const live = classifyExploitation(input.in_kev || reported.length > 0, epss, input.poc_confidence);

  const cisaExp = pick(input.cisa?.exploitation, EXPLOITATION_ORDER);
  const cisaAuto = pick(input.cisa?.automatable, ['yes', 'no']);
  const cisaTi = pick(input.cisa?.technical_impact, ['partial', 'total']);

  let exploitation: SsvcExploitation;
  let exploitationSource: string;
  if (cisaExp && rank(cisaExp) >= rank(live)) {
    exploitation = cisaExp as SsvcExploitation;
    exploitationSource = 'CISA Vulnrichment';
  } else {
    const why: string[] = [];
    if (input.in_kev) why.push('CISA KEV');
    why.push(...reported);
    if (why.length === 0) why.push('EPSS and public exploit evidence');
    exploitation = live;
    exploitationSource = why.join(', ');
  }

  const exposureRaw = (input.exposure ?? '').trim().toLowerCase();
  const exposure: SsvcExposure = (['small', 'controlled', 'open'] as const).includes(exposureRaw as SsvcExposure)
    ? (exposureRaw as SsvcExposure)
    : 'open';

  let automatable: SsvcAutomatable;
  let automatableSource: string;
  if (exposure !== 'open') {
    automatable = 'no';
    automatableSource = `system exposure is ${exposure}`;
  } else if (cisaAuto) {
    automatable = cisaAuto as SsvcAutomatable;
    automatableSource = 'CISA Vulnrichment';
  } else if (exploitation !== 'none' || epss >= 0.1) {
    automatable = 'yes';
    automatableSource = 'estimated';
  } else {
    automatable = 'no';
    automatableSource = 'estimated';
  }

  let technicalImpact: SsvcTechnicalImpact;
  let technicalImpactSource: string;
  if (cisaTi) {
    technicalImpact = cisaTi as SsvcTechnicalImpact;
    technicalImpactSource = 'CISA Vulnrichment';
  } else {
    technicalImpact = cvss >= 9 ? 'total' : 'partial';
    technicalImpactSource = `CVSS ${cvss} severity proxy`;
  }

  const missionWellbeing: SsvcMissionWellbeing = cvss >= 9 ? 'high' : cvss >= 7 ? 'medium' : 'low';
  const rowIndex = missionWellbeing === 'low' ? 0 : missionWellbeing === 'medium' ? 1 : 2;
  const row = DECISION_TABLE[`${exploitation}|${automatable}|${technicalImpact}`] ?? ['Attend', 'Act', 'Act'];
  const action = row[rowIndex];

  const inputsSource: SsvcDecision['inputs_source'] = cisaExp || cisaAuto || cisaTi ? 'CISA Vulnrichment' : 'estimated';

  const rationale =
    `SSVC Deployer decision: Exploitation=${exploitation} (${exploitationSource}); ` +
    `System Exposure=${exposure}; Automatable=${automatable} (${automatableSource}); ` +
    `Technical Impact=${technicalImpact} (${technicalImpactSource}); ` +
    `Mission & Well-being=${missionWellbeing} (CVSS ${cvss} severity proxy). ` +
    `This path resolves to '${action}': ${GUIDANCE[action]}`;

  return {
    scoring_version: SSVC_SCORING_VERSION,
    exploitation,
    exposure,
    automatable,
    technical_impact: technicalImpact,
    mission_wellbeing: missionWellbeing,
    action,
    rationale,
    inputs_source: inputsSource,
  };
}

/**
 * Extract CISA's published SSVC options from a CVE 5.x record.
 *
 * CISA publishes them in the `CISA-ADP` container as
 * `metrics[].other.content` where `other.type === 'ssvc'` and `options` is
 * an array of `{ "Exploitation": "active" }`-style single-key objects.
 */
export function extractCisaSsvc(doc: unknown): CisaSsvc | undefined {
  if (!doc || typeof doc !== 'object') return undefined;
  const containers = (doc as { containers?: Record<string, unknown> }).containers ?? {};
  const adp = Array.isArray(containers.adp) ? (containers.adp as Record<string, unknown>[]) : [];
  for (const a of adp) {
    const metrics = Array.isArray(a.metrics) ? (a.metrics as Record<string, unknown>[]) : [];
    for (const m of metrics) {
      const other = m.other as { type?: string; content?: Record<string, unknown> } | undefined;
      if (other?.type !== 'ssvc' || !other.content) continue;
      const content = other.content;
      const options = Array.isArray(content.options) ? (content.options as Record<string, unknown>[]) : [];
      const read = (key: string): string => {
        for (const o of options) {
          const v = o[key];
          if (typeof v === 'string' && v.trim()) return v.trim().toLowerCase();
        }
        return '';
      };
      const exploitation = read('Exploitation');
      const automatable = read('Automatable');
      const technicalImpact = read('Technical Impact');
      if (!exploitation && !automatable && !technicalImpact) continue;
      return {
        exploitation,
        automatable,
        technical_impact: technicalImpact,
        version: typeof content.version === 'string' ? content.version : undefined,
        timestamp: typeof content.timestamp === 'string' ? content.timestamp : undefined,
      };
    }
  }
  return undefined;
}

function clamp(x: number, lo: number, hi: number): number {
  if (!Number.isFinite(x)) return lo;
  return Math.min(hi, Math.max(lo, x));
}
