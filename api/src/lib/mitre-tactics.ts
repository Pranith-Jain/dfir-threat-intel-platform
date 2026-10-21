/**
 * AUTO-GENERATED from MITRE ATT&CK enterprise-attack.json. Do not edit by
 * hand. To resync from upstream, run:
 *   node scripts/generate-mitre-matrix.mjs
 *
 * Upstream: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
 * Generated: 2026-10-21 (ATT&CK v3.3.0)
 *
 * The canonical ATT&CK Enterprise tactic list, in kill-chain order.
 *
 * This is generated rather than hand-written because ATT&CK's tactic
 * taxonomy changes: the v3.3 spec split `defense-evasion` into
 * `stealth` (TA0005) and `defense-impairment` (TA0112). A hand-kept
 * list silently mis-sorted every technique in the new tactics and kept
 * labelling the reassigned TA0005 as "Defense Evasion".
 */

/** One ATT&CK Enterprise tactic, in kill-chain order. */
export interface MitreTacticMeta {
  /** ATT&CK external id (TA00xx). */
  id: string;
  name: string;
  /** ATT&CK short name, e.g. `defense-impairment`. */
  short_name: string;
  /** 1-based kill-chain position. */
  order: number;
}

export const MITRE_TACTICS: MitreTacticMeta[] = [
  {
    id: 'TA0043',
    name: 'Reconnaissance',
    short_name: 'reconnaissance',
    order: 1,
  },
  {
    id: 'TA0042',
    name: 'Resource Development',
    short_name: 'resource-development',
    order: 2,
  },
  {
    id: 'TA0001',
    name: 'Initial Access',
    short_name: 'initial-access',
    order: 3,
  },
  {
    id: 'TA0002',
    name: 'Execution',
    short_name: 'execution',
    order: 4,
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    short_name: 'persistence',
    order: 5,
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    short_name: 'privilege-escalation',
    order: 6,
  },
  {
    id: 'TA0005',
    name: 'Stealth',
    short_name: 'stealth',
    order: 7,
  },
  {
    id: 'TA0112',
    name: 'Defense Impairment',
    short_name: 'defense-impairment',
    order: 8,
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    short_name: 'credential-access',
    order: 9,
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    short_name: 'discovery',
    order: 10,
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    short_name: 'lateral-movement',
    order: 11,
  },
  {
    id: 'TA0009',
    name: 'Collection',
    short_name: 'collection',
    order: 12,
  },
  {
    id: 'TA0011',
    name: 'Command and Control',
    short_name: 'command-and-control',
    order: 13,
  },
  {
    id: 'TA0010',
    name: 'Exfiltration',
    short_name: 'exfiltration',
    order: 14,
  },
  {
    id: 'TA0040',
    name: 'Impact',
    short_name: 'impact',
    order: 15,
  },
];
