/**
 * Regenerate the MITRE ATT&CK artifacts from the upstream
 * enterprise-attack.json bundle.
 *
 * Emits TWO files, both from the same fetch so they can never disagree:
 *
 *   src/data/dfir/mitre-matrix.ts     the full matrix (tactic + technique
 *                                     titles) — powers /dfir/mitre's grid
 *   api/src/lib/mitre-tactics.ts       the canonical ordered tactic list
 *                                     (id, name, short_name, order) —
 *                                     consumed by the API's attack-flow
 *                                     and attack-chain routes
 *
 * The second file exists because the API used to hand-maintain its own
 * tactic list. That list was a 14-tactic pre-split copy, so two live
 * tactics (Stealth, Defense Impairment — 204 techniques) sorted to the end
 * of every kill chain, and TA0005 was still labelled "Defense Evasion" after
 * ATT&CK reassigned that id to Stealth. A hand-maintained list of a
 * changing taxonomy is a bug waiting for the next release; generating it
 * from the same bundle the matrix comes from is the fix.
 *
 * ATT&CK reorganised its tactic taxonomy in the v3.3 spec: `defense-evasion`
 * was split into `stealth` (TA0005, reusing the old id) and
 * `defense-impairment` (TA0112, new). Anything that assumed 14 tactics, or
 * that mapped a tactic id to a name, was wrong from that release on.
 *
 * Re-run: `node scripts/generate-mitre-matrix.mjs`
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const BUNDLE_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

const OUT = resolve(import.meta.dirname, '..', 'src', 'data', 'dfir', 'mitre-matrix.ts');
const OUT_TACTICS = resolve(import.meta.dirname, '..', 'api', 'src', 'lib', 'mitre-tactics.ts');

const PRE = `/**
 * AUTO-GENERATED from MITRE ATT&CK enterprise-attack.json. Do not edit by
 * hand. To resync from upstream, run:
 *   node scripts/generate-mitre-matrix.mjs
 *
 * Upstream: ${BUNDLE_URL}
 * Generated: %DATE% (ATT&CK %VERSION%)
 *
 * This file ships the tactic + technique titles only. Per-technique
 * detail (description, procedures, mitigations) loads live from
 * /api/v1/mitre/technique against the same upstream.
 */

export interface MitreTechnique {
  id: string;
  name: string;
  description?: string;
  subtechniques?: Array<{ id: string; name: string }>;
}

export interface MitreTactic {
  id: string;
  name: string;
  short_name: string;
  description: string;
  techniques: MitreTechnique[];
}

export const mitreMatrix: MitreTactic[] = `;

const PRE_TACTICS = `/**
 * AUTO-GENERATED from MITRE ATT&CK enterprise-attack.json. Do not edit by
 * hand. To resync from upstream, run:
 *   node scripts/generate-mitre-matrix.mjs
 *
 * Upstream: ${BUNDLE_URL}
 * Generated: %DATE% (ATT&CK %VERSION%)
 *
 * The canonical ATT&CK Enterprise tactic list, in kill-chain order.
 *
 * This is generated rather than hand-written because ATT&CK's tactic
 * taxonomy changes: the v3.3 spec split \`defense-evasion\` into
 * \`stealth\` (TA0005) and \`defense-impairment\` (TA0112). A hand-kept
 * list silently mis-sorted every technique in the new tactics and kept
 * labelling the reassigned TA0005 as "Defense Evasion".
 */

/** One ATT&CK Enterprise tactic, in kill-chain order. */
export interface MitreTacticMeta {
  /** ATT&CK external id (TA00xx). */
  id: string;
  name: string;
  /** ATT&CK short name, e.g. \`defense-impairment\`. */
  short_name: string;
  /** 1-based kill-chain position. */
  order: number;
}

export const MITRE_TACTICS: MitreTacticMeta[] = `;

function externalId(obj) {
  return obj?.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id;
}

function describe(text, maxLen = 240) {
  if (!text) return '';
  const trimmed = text.replace(/\s+/g, ' ').trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen).trim() + '…' : trimmed;
}

async function main() {
  console.log(`fetching ${BUNDLE_URL}…`);
  const res = await fetch(BUNDLE_URL);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const bundle = await res.json();
  const objects = bundle.objects ?? [];

  // The Enterprise matrix object lists tactic STIX refs in the order they
  // should appear in the kill chain.
  const matrixObj = objects.find((o) => o.type === 'x-mitre-matrix' && externalId(o) === 'enterprise-attack');
  if (!matrixObj) throw new Error('enterprise matrix object not found');
  const orderedTacticRefs = matrixObj.tactic_refs ?? [];

  // Tactic STIX-id → tactic record.
  const tacticById = new Map();
  for (const o of objects) {
    if (o.type !== 'x-mitre-tactic' || o.revoked || o.x_mitre_deprecated) continue;
    tacticById.set(o.id, {
      stixId: o.id,
      id: externalId(o),
      name: o.name,
      short_name: o.x_mitre_shortname,
      description: describe(o.description, 200),
    });
  }

  // Techniques grouped by parent tactic kill-chain phase.
  const byPhase = new Map();
  // Sub-technique map: parent technique external id → [{id,name}].
  const subTechs = new Map();

  for (const o of objects) {
    if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
    if (!o.kill_chain_phases?.some((p) => p.kill_chain_name === 'mitre-attack')) continue;
    if (!(o.x_mitre_domains ?? []).includes('enterprise-attack')) continue;
    const id = externalId(o);
    if (!id) continue;
    if (o.x_mitre_is_subtechnique) {
      // A sub-technique's parent is the id prefix (T1059.001 → T1059).
      // Deriving it from the id rather than from a `subtechnique-of`
      // relationship is direction-independent: ATT&CK has flipped that
      // relationship's source/target between releases, and reading it the
      // wrong way round produces a matrix with zero sub-techniques and no
      // error to signal it.
      const parent = id.split('.')[0];
      if (!subTechs.has(parent)) subTechs.set(parent, []);
      subTechs.get(parent).push({ id, name: o.name });
    } else {
      // A parent technique can belong to more than one tactic (145 of them
      // do in the v3.3 spec), and ATT&CK's own matrix lists it under each.
      for (const phase of o.kill_chain_phases) {
        if (phase.kill_chain_name !== 'mitre-attack') continue;
        if (!byPhase.has(phase.phase_name)) byPhase.set(phase.phase_name, []);
        byPhase.get(phase.phase_name).push({ id, name: o.name });
      }
    }
  }

  // Sort sub-techniques numerically (T1059.001 < .002 < .010).
  for (const arr of subTechs.values()) {
    arr.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
  }

  const tactics = [];
  for (const ref of orderedTacticRefs) {
    const tactic = tacticById.get(ref);
    if (!tactic) continue;
    const techs = (byPhase.get(tactic.short_name) ?? []).map((t) => {
      const subs = subTechs.get(t.id);
      return subs && subs.length > 0 ? { ...t, subtechniques: subs } : t;
    });
    tactics.push({
      id: tactic.id,
      name: tactic.name,
      short_name: tactic.short_name,
      description: tactic.description,
      techniques: techs,
    });
  }

  // Version detection.
  //
  // The ATT&CK *release* version is `x_mitre_attack_spec_version` on the
  // matrix object. `x_mitre_version` is the STIX object's own revision
  // number, and on the matrix it is "2.0" — which is where the old
  // "Generated: … (ATT&CK v2.0)" header came from. That label described
  // nothing a reader could act on.
  const version =
    matrixObj?.x_mitre_attack_spec_version ??
    objects.find((o) => o.x_mitre_attack_spec_version)?.x_mitre_attack_spec_version ??
    'master';

  const totals = {
    tactics: tactics.length,
    techniques: tactics.reduce((n, t) => n + t.techniques.length, 0),
    subtechniques: tactics.reduce(
      (n, t) => n + t.techniques.reduce((m, k) => m + (k.subtechniques?.length ?? 0), 0),
      0
    ),
  };
  console.log(`extracted: ${totals.tactics} tactics / ${totals.techniques} techniques / ${totals.subtechniques} subtechniques (v${version})`);

  const body = JSON.stringify(tactics, null, 2)
    // Switch JSON keys to bare identifiers where TypeScript allows.
    .replace(/^(\s*)"(id|name|short_name|description|techniques|subtechniques)":/gm, '$1$2:')
    .replace(/^/gm, '');

  const date = new Date().toISOString().slice(0, 10);
  const header = PRE.replace('%DATE%', date).replace('%VERSION%', `v${version}`);
  const out = `${header}${body};\n`;
  writeFileSync(OUT, out);
  console.log(`wrote ${OUT} (${out.length} bytes)`);

  // The canonical ordered tactic list, generated from the same fetch.
  const tacticList = tactics.map((t, i) => ({
    id: t.id,
    name: t.name,
    short_name: t.short_name,
    order: i + 1,
  }));
  const tacticsBody = JSON.stringify(tacticList, null, 2)
    .replace(/^(\s*)"(id|name|short_name|order)":/gm, '$1$2:')
    .replace(/^/gm, '');
  const tacticsHeader = PRE_TACTICS.replace('%DATE%', date).replace('%VERSION%', `v${version}`);
  writeFileSync(OUT_TACTICS, `${tacticsHeader}${tacticsBody};\n`);
  console.log(`wrote ${OUT_TACTICS} (${tacticList.length} tactics)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
