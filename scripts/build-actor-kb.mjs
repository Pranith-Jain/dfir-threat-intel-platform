/**
 * Regenerate public/data/actor-kb.json — a TRIMMED threat-actor knowledge
 * base extracted from the MITRE ATT&CK enterprise bundle (~47 MB upstream).
 *
 * Run periodically + commit the artifact (NOT in prebuild — the upstream
 * fetch is large/slow and the data changes only on ATT&CK releases):
 *   node scripts/build-actor-kb.mjs
 *
 * Output per group: ATT&CK id, name, aliases, description, the techniques
 * it `uses` (id + name + tactic) and the software it `uses` — enough for a
 * real actor profile without shipping the whole 47 MB bundle.
 *
 * NOTE: this used to emit a TypeScript data module at
 * `src/data/dfir/actor-kb.ts`. That array had no consumers once
 * `ActorKb.tsx` moved to a runtime `fetch('/data/actor-kb.json')`, so it was
 * deleted (~7.4k LOC of data that was typechecked and bundled every build).
 * `src/data/dfir/actor-kb.ts` now holds only the `KbActor` / `KbTechnique`
 * interfaces — do not re-add a data export there.
 */
import { writeFileSync } from 'node:fs';

const BUNDLE_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const OUT = new URL('../public/data/actor-kb.json', import.meta.url);

const extId = (o) => o.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id ?? '';
const attUrl = (o) => o.external_references?.find((r) => r.source_name === 'mitre-attack')?.url ?? '';
const tactic = (o) => o.kill_chain_phases?.find((p) => p.kill_chain_name === 'mitre-attack')?.phase_name ?? 'other';

async function main() {
  process.stdout.write('Fetching ATT&CK enterprise bundle (~47 MB)…\n');
  const res = await fetch(BUNDLE_URL, { headers: { 'user-agent': 'pranithjain build-actor-kb' } });
  if (!res.ok) throw new Error(`bundle fetch ${res.status}`);
  const { objects } = await res.json();

  const byId = new Map();
  for (const o of objects) byId.set(o.id, o);

  const techniques = new Map(); // stix id -> { id, name, tactic }
  for (const o of objects) {
    if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
    techniques.set(o.id, { id: extId(o), name: o.name, tactic: tactic(o) });
  }
  const softwareName = new Map(); // stix id -> name
  for (const o of objects) {
    if ((o.type === 'malware' || o.type === 'tool') && !o.revoked && !o.x_mitre_deprecated)
      softwareName.set(o.id, o.name);
  }

  const groups = new Map(); // stix id -> group record
  for (const o of objects) {
    if (o.type !== 'intrusion-set' || o.revoked || o.x_mitre_deprecated) continue;
    groups.set(o.id, {
      attackId: extId(o),
      name: o.name,
      aliases: (o.aliases ?? []).filter((a) => a !== o.name),
      description: (o.description ?? '').replace(/\(Citation:[^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').trim().slice(0, 900),
      url: attUrl(o),
      techniques: [],
      software: [],
    });
  }

  for (const o of objects) {
    if (o.type !== 'relationship' || o.relationship_type !== 'uses') continue;
    const g = groups.get(o.source_ref);
    if (!g) continue;
    const t = techniques.get(o.target_ref);
    if (t && t.id) {
      if (!g.techniques.some((x) => x.id === t.id)) g.techniques.push(t);
      continue;
    }
    const sw = softwareName.get(o.target_ref);
    if (sw && !g.software.includes(sw)) g.software.push(sw);
  }

  const list = [...groups.values()]
    .filter((g) => g.attackId)
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((g) => ({
      ...g,
      techniques: g.techniques.sort((a, b) => a.tactic.localeCompare(b.tactic) || a.id.localeCompare(b.id)),
      software: g.software.sort(),
    }));

  const json = JSON.stringify(list, null, 2) + '\n';
  writeFileSync(OUT, json);
  process.stdout.write(
    `Wrote ${list.length} groups → public/data/actor-kb.json (${(json.length / 1024).toFixed(0)} KB)\n`
  );
}

main().catch((e) => {
  process.stderr.write(`build-actor-kb failed: ${e.message}\n`);
  process.exit(1);
});
