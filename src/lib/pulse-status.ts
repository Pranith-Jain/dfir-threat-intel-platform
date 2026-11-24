/**
 * Evidence status for Global Hack Map-style incident rows.
 *
 * Mirrors the honest status taxonomy of Global Hack Map (MIT): Confirmed /
 * Reported / Claimed / Precautionary / Disputed. Status comes from the
 * *strongest* available signal on the row (source kind, KEV listing, exploit
 * evidence, or explicit denial/precaution language), and is `null` for
 * non-incident layers. An absent result is never proof that you are safe.
 */

export type EvidenceStatus = 'confirmed' | 'reported' | 'claimed' | 'precautionary' | 'disputed';

export const EVIDENCE_STATUSES: readonly EvidenceStatus[] = [
  'confirmed',
  'reported',
  'claimed',
  'precautionary',
  'disputed',
] as const;

export const STATUS_META: Record<EvidenceStatus, { label: string; description: string }> = {
  confirmed: { label: 'Confirmed', description: 'Acknowledged by the organisation, a regulator or a filing' },
  reported: { label: 'Reported', description: 'Covered by the press, not yet confirmed by the organisation' },
  claimed: { label: 'Claimed', description: 'Asserted by attackers on a leak site, unverified' },
  precautionary: { label: 'Precautionary', description: 'Systems taken offline as a precaution, no compromise stated' },
  disputed: { label: 'Disputed', description: 'Reported, and denied by the organisation' },
};

export interface StatusInput {
  kind: string;
  source: string;
  title?: string;
  description?: string;
  kev?: boolean;
  exploitStatus?: string;
}

const INCIDENT_KINDS = new Set([
  'ransomware',
  'breach',
  'cyber_attack',
  'scam',
  'phishing',
  'malware',
  'infostealer',
  'cybercrime',
  'supply_chain_attacks',
  'ai_incident',
]);

const DISPUTED_RE = /\b(denies|denied|disputes|disputed|refutes|refuted|false claim|no evidence of (a|any)? ?breach)\b/i;
const PRECAUTIONARY_RE = /\bprecautionary|as a precaution|taken offline as a precaution|no compromise (was |has been )?stated\b/i;
const CONFIRMED_SOURCE_RE = /\b(SEC EDGAR|8-K|regulator|filing|CISA|NVD|KEV)\b/i;
const CLAIM_SOURCE_RE = /\b(leak ?site|ransomlook|claim(ed|s)?|darknet|dread|breachforums)\b/i;

/** Strongest-evidence status for one pulse row; null for non-incident layers. */
export function incidentStatus(event: StatusInput): EvidenceStatus | null {
  const text = `${event.title ?? ''} ${event.description ?? ''}`;
  if (DISPUTED_RE.test(text)) return 'disputed';
  if (PRECAUTIONARY_RE.test(text)) return 'precautionary';
  const confirmed = event.kev === true || event.exploitStatus === 'in_the_wild' || CONFIRMED_SOURCE_RE.test(event.source);
  if (confirmed) return 'confirmed';
  if (event.kind === 'ransomware' || CLAIM_SOURCE_RE.test(event.source)) return 'claimed';
  if (INCIDENT_KINDS.has(event.kind)) return 'reported';
  return null;
}
