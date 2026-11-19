import { describe, it, expect } from 'vitest';
import {
  EXTRA_DEFAULTS,
  bandFor,
  scoreAssessment,
  syncKnownQuantities,
  volumeTier,
  type Answers,
} from '../../src/lib/vess';

/** Port fidelity checks for the VESS prototype-v4 scoring rules. */
const base = (): Answers => ({ ...EXTRA_DEFAULTS, vclass: 'memory' });

describe('VESS scoring model', () => {
  it('scores an empty assessment as 0 / Trivial', () => {
    const r = scoreAssessment(base());
    expect(r.rounded).toBe(0);
    expect(r.baseTotal).toBe(0);
    expect(r.bonus).toBe(0);
    expect(bandFor(r.rounded).label).toBe('Trivial');
  });

  it('applies residual factors to technical barriers', () => {
    const a = base();
    a.tech_memory_aslr_required = '1';
    a.tech_memory_aslr_residual = '0.5'; // ASLR max 5 × 0.5 = 2.5
    expect(scoreAssessment(a).base.find((c) => c.id === 'technical')?.points).toBe(2.5);
  });

  it('caps ordinary categories at their configured maximum', () => {
    const a = base();
    Object.assign(a, { vector: '8', auth: '7', config: '4', interaction: '4', exposure: '2' });
    expect(scoreAssessment(a).base.find((c) => c.id === 'attack')?.points).toBe(20);
  });

  it('counts only the highest escalator within a correlated group', () => {
    const a = base();
    Object.assign(a, { volume: '20', minBandwidth: '20', packetExtreme: '10' });
    const resources = scoreAssessment(a).escalators.find((g) => g.id === 'resources');
    expect(resources?.points).toBe(20);
  });

  it('flags an infeasible transfer-time path without inflating the score', () => {
    const a = base();
    Object.assign(a, { requiredTrafficGb: '100', availableMbps: '10', maxConnectionMinutes: '10' });
    const r = scoreAssessment(a);
    expect(r.feasibility.status).toBe('infeasible');
    expect(r.feasibility.issues[0]).toMatch(/exceeding the 10-minute connection window/);
    expect(r.feasibility.diagnostics.requiredTransferMinutes).toBeCloseTo(1333.33, 1);
  });

  it('auto-fills ordinary tiers from exact quantities', () => {
    expect(volumeTier(0.5)).toBe('5');
    const a = syncKnownQuantities(
      { ...base(), requiredTrafficGb: '0.5', requiredAttemptsExact: '5000' },
      'requiredTrafficGb'
    );
    expect(a.volume).toBe('5');
    const b = syncKnownQuantities(a, 'requiredAttemptsExact');
    expect(b.attempts).toBe('6');
    expect(b.attemptExtreme).toBe('10');
  });
});
