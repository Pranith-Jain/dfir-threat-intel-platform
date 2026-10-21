import type { StixCommon } from './stix-build';
import { loadedAttackIdIndexOrNull } from './attack-id-lazy';
import { MITRE_TACTICS } from './mitre-tactics';

/** MITRE Attack-Flow STIX 2.1 extension-definition id (canonical, from the spec). */
export const ATTACK_FLOW_EXT_ID = 'extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4';

/** Enterprise tactics in kill-chain order (mitre-attack phase_name shortnames). */
/**
 * Kill-chain order of the ATT&CK Enterprise tactics.
 *
 * Derived from the generated tactic list rather than hand-kept. ATT&CK's
 * v3.3 spec split `defense-evasion` into `stealth` and `defense-impairment`
 * (and reassigned TA0005 to Stealth), so a hand-kept list left 204
 * techniques sorting to the end of every kill chain and kept labelling the
 * reassigned id as "Defense Evasion".
 */
export const TACTIC_ORDER: string[] = MITRE_TACTICS.map((t) => t.short_name);

export interface FlowTechnique {
  id: string; // ATT&CK technique id, e.g. T1566 / T1059.001
  name: string;
  stixApId: string; // the attack-pattern STIX object id this action references
  tactic?: string; // optional LLM-provided tactic (phase_name shortname)
}

function tacticIndex(t: FlowTechnique): number {
  // Graceful when the runtime index hasn't loaded (pure-function tests,
  // pre-middleware calls): unknown ids sort last, same as a missing tac.
  const tac = (t.tactic ?? loadedAttackIdIndexOrNull()?.[t.id]?.tac ?? '').toLowerCase();
  const i = TACTIC_ORDER.indexOf(tac);
  return i === -1 ? TACTIC_ORDER.length : i;
}

/** Deterministic kill-chain sort: tactic phase, then technique id. Pure. */
export function orderByTactic(techs: FlowTechnique[]): FlowTechnique[] {
  return [...techs].sort((a, b) => tacticIndex(a) - tacticIndex(b) || a.id.localeCompare(b.id));
}

const EXT_MARKER = { [ATTACK_FLOW_EXT_ID]: { extension_type: 'new-sdo' } } as const;

export interface FlowBuildOpts {
  flowName: string;
  identityId: string;
  time: Record<string, unknown>; // spread of timeFields() — { created, modified, ... }
  keyPrefix: string; // `${sourceId}|${itemRef}` — for deterministic ids
  idFor: (type: string, key: string) => Promise<string>; // pass stixId
  scope?: string; // default 'incident'
}

/** Build the Attack-Flow SDOs for an ordered technique list. Returns
 *  [extension-definition, attack-flow, ...attack-actions] (linear chain via
 *  effect_refs). Empty input → empty output. */
export async function buildAttackFlowObjects(
  ordered: FlowTechnique[],
  opts: FlowBuildOpts
): Promise<{ objects: StixCommon[]; flowId: string | null; startRef: string | null }> {
  if (ordered.length === 0) return { objects: [], flowId: null, startRef: null };

  const actionIds = await Promise.all(
    ordered.map((t) => opts.idFor('attack-action', `attack-action|${opts.keyPrefix}|${t.id}`))
  );
  const flowId = await opts.idFor('attack-flow', `attack-flow|${opts.keyPrefix}`);

  const actions: StixCommon[] = ordered.map(
    (t, i) =>
      ({
        type: 'attack-action',
        spec_version: '2.1',
        id: actionIds[i]!,
        ...opts.time,
        created_by_ref: opts.identityId,
        name: t.name || t.id,
        technique_id: t.id,
        technique_ref: t.stixApId,
        ...(i < ordered.length - 1 ? { effect_refs: [actionIds[i + 1]!] } : {}),
        extensions: { ...EXT_MARKER },
      }) as unknown as StixCommon
  );

  const extDef = {
    type: 'extension-definition',
    spec_version: '2.1',
    id: ATTACK_FLOW_EXT_ID,
    ...opts.time,
    created_by_ref: opts.identityId,
    name: 'Attack Flow',
    schema: 'https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json',
    version: '2.0.0',
    extension_types: ['new-sdo'],
  } as unknown as StixCommon;

  const flow = {
    type: 'attack-flow',
    spec_version: '2.1',
    id: flowId,
    ...opts.time,
    created_by_ref: opts.identityId,
    name: opts.flowName,
    scope: opts.scope ?? 'incident',
    start_refs: [actionIds[0]!],
    extensions: { ...EXT_MARKER },
  } as unknown as StixCommon;

  return { objects: [extDef, flow, ...actions], flowId, startRef: actionIds[0]! };
}
