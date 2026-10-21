/**
 * ATT&CK tactic-list guard.
 *
 * The API used to hand-maintain its own copy of the ATT&CK Enterprise
 * tactic list in three places (attack-flow.ts, attack-chain.ts,
 * attack-navigator.ts). When ATT&CK's v3.3 spec split `defense-evasion`
 * into `stealth` (TA0005) and `defense-impairment` (TA0112), all three
 * copies went stale at once:
 *
 *   - attack-flow sorted 204 techniques to the END of every kill chain
 *     (the two new tactics were not in its list);
 *   - attack-chain labelled the reassigned TA0005 "Defense Evasion";
 *   - attack-navigator DROPPED those techniques entirely, because
 *     `stealth` and `defense-impairment` had no tactic id, so the
 *     `if (!tacticId) continue` guard threw them away.
 *
 * The lists are now generated (api/src/lib/mitre-tactics.ts) from the same
 * upstream fetch as the matrix. This test pins the two against each other
 * and against the vendored matrix, so a future upstream taxonomy change
 * cannot leave one of them behind again.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { MITRE_TACTICS } from '../../api/src/lib/mitre-tactics';

const ROOT = resolve(__dirname, '../..');
const MATRIX = readFileSync(resolve(ROOT, 'src/data/dfir/mitre-matrix.ts'), 'utf8');

describe('MITRE tactic list', () => {
  it('is non-empty and has unique ids and short names', () => {
    expect(MITRE_TACTICS.length).toBeGreaterThan(10);
    expect(new Set(MITRE_TACTICS.map((t) => t.id)).size).toBe(MITRE_TACTICS.length);
    expect(new Set(MITRE_TACTICS.map((t) => t.short_name)).size).toBe(MITRE_TACTICS.length);
  });

  it('matches the vendored matrix tactic for tactic', () => {
    // Pull the matrix's tactic blocks out of the generated source.
    const matrixTactics = [
      ...MATRIX.matchAll(/id: "(TA\d+)",\s*\n\s*name: "([^"]+)",\s*\n\s*short_name: "([a-z-]+)"/g),
    ].map((m) => ({ id: m[1], name: m[2], short_name: m[3] }));
    expect(matrixTactics.length).toBe(MITRE_TACTICS.length);
    expect(matrixTactics.map((t) => t.id)).toEqual(MITRE_TACTICS.map((t) => t.id));
    expect(matrixTactics.map((t) => t.name)).toEqual(MITRE_TACTICS.map((t) => t.name));
    expect(matrixTactics.map((t) => t.short_name)).toEqual(MITRE_TACTICS.map((t) => t.short_name));
  });

  it('orders the tactics 1..N in kill-chain order', () => {
    expect(MITRE_TACTICS.map((t) => t.order)).toEqual(MITRE_TACTICS.map((_, i) => i + 1));
  });

  it('carries the v3.3 taxonomy split, not the pre-split one', () => {
    const shortNames = MITRE_TACTICS.map((t) => t.short_name);
    // `defense-evasion` was split into these two.
    expect(shortNames).toContain('stealth');
    expect(shortNames).toContain('defense-impairment');
    expect(shortNames).not.toContain('defense-evasion');
    // TA0005 was reassigned from Defense Evasion to Stealth.
    expect(MITRE_TACTICS.find((t) => t.id === 'TA0005')?.short_name).toBe('stealth');
    expect(MITRE_TACTICS.find((t) => t.short_name === 'defense-impairment')?.id).toBe('TA0112');
  });

  it('leaves no hand-maintained tactic list in the API', () => {
    // The three places that used to carry their own copy. A reintroduced
    // literal list is the regression this test exists to catch.
    const files = [
      'api/src/lib/attack-flow.ts',
      'api/src/routes/attack-chain.ts',
      'api/src/routes/attack-navigator.ts',
    ];
    for (const file of files) {
      const src = readFileSync(resolve(ROOT, file), 'utf8');
      expect(src, `${file} must derive its tactic list from api/src/lib/mitre-tactics.ts, not a literal`).not.toMatch(
        /'defense-evasion'/
      );
      expect(src, `${file} has a hard-coded TA00xx tactic list`).not.toMatch(/TA0005'\s*,\s*\n\s*'TA0006/);
    }
  });
});
