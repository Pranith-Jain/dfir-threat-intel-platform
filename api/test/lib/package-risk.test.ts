import { describe, expect, it } from 'vitest';
import { assessPackageRisk, cvssBand, remediationSla } from '../../src/lib/package-risk';

describe('cvssBand', () => {
  it('maps CVSS v3.x ranges', () => {
    expect(cvssBand(9.8)).toBe('critical');
    expect(cvssBand(7.5)).toBe('high');
    expect(cvssBand(5.3)).toBe('medium');
    expect(cvssBand(3.1)).toBe('low');
    expect(cvssBand(0)).toBe('none');
  });

  it('returns unknown for missing data rather than none', () => {
    // "no score" and "scored zero" are different facts and must not collapse.
    expect(cvssBand(null)).toBe('unknown');
    expect(cvssBand(undefined)).toBe('unknown');
    expect(cvssBand(NaN)).toBe('unknown');
  });
});

describe('assessPackageRisk', () => {
  it('gives a malicious package a floor it cannot be argued below', () => {
    const r = assessPackageRisk({ malicious: true, cvss: 1, kev: false, advisoryCount: 0 });
    expect(r.verdict).toBe('malicious');
    expect(r.score).toBeGreaterThanOrEqual(85);
    expect(r.band).toBe('critical');
  });

  it('scores a package with no advisory data as unknown, not as safe', () => {
    const r = assessPackageRisk({});
    expect(r.verdict).toBe('unknown');
    expect(r.score).toBe(0);
    expect(r.components.find((c) => c.key === 'exploitability')?.detail).toContain('unknown');
  });

  it('puts an unfixed critical above a fixed critical', () => {
    const unfixed = assessPackageRisk({ cvss: 9.8, hasUnfixedAdvisory: true });
    const fixed = assessPackageRisk({ cvss: 9.8, hasUnfixedAdvisory: false });
    expect(unfixed.score).toBeGreaterThan(fixed.score);
    expect(unfixed.verdict).toBe('act-now');
  });

  it('puts KEV above equal severity without KEV', () => {
    const kev = assessPackageRisk({ cvss: 9.0, kev: true });
    const noKev = assessPackageRisk({ cvss: 9.0, kev: false });
    expect(kev.score).toBeGreaterThan(noKev.score);
  });

  it('decays urgency with advisory age', () => {
    const fresh = assessPackageRisk({ cvss: 9.8, hasUnfixedAdvisory: true, newestAdvisoryAgeDays: 1 });
    const old = assessPackageRisk({ cvss: 9.8, hasUnfixedAdvisory: true, newestAdvisoryAgeDays: 720 });
    expect(fresh.score).toBeGreaterThan(old.score);
  });

  it('never lets advisory volume flip a verdict on its own', () => {
    // A popular package has more advisories because more people look at it, so
    // volume must never escalate past "monitor".
    const noisy = assessPackageRisk({ advisoryCount: 50 });
    expect(noisy.verdict).toBe('monitor');
    expect(noisy.score).toBeLessThan(20);
  });

  it('escalates an unpatched critical even with no exploitability data', () => {
    // The case the weighted score alone gets wrong: ~44 points reads as
    // "monitor", and an unpatched critical is not a monitoring item.
    const r = assessPackageRisk({ cvss: 9.8, hasUnfixedAdvisory: true });
    expect(r.verdict).toBe('act-now');
  });

  it('does not escalate a patched critical', () => {
    const r = assessPackageRisk({ cvss: 9.8, hasUnfixedAdvisory: false });
    expect(r.verdict).not.toBe('act-now');
  });

  it('keeps the score inside 0-100 under extreme input', () => {
    const maxed = assessPackageRisk({
      malicious: true,
      cvss: 10,
      epss: 1,
      kev: true,
      hasUnfixedAdvisory: true,
      advisoryCount: 1000,
      newestAdvisoryAgeDays: 0,
    });
    expect(maxed.score).toBeLessThanOrEqual(100);
    const empty = assessPackageRisk({});
    expect(empty.score).toBeGreaterThanOrEqual(0);
  });

  it('does not inflate on negative or malformed EPSS', () => {
    const a = assessPackageRisk({ epss: -5 });
    const b = assessPackageRisk({});
    expect(a.score).toBe(b.score);
  });

  it('reports a component breakdown that sums to the score', () => {
    const r = assessPackageRisk({ cvss: 7.5, epss: 0.3, kev: true, hasUnfixedAdvisory: true, advisoryCount: 4 });
    const summed = r.components.reduce((s, c) => s + c.points * c.weight, 0);
    expect(r.score).toBeCloseTo(Math.min(100, summed), 1);
    expect(r.components).toHaveLength(5);
  });

  it('names the dominant factor in the rationale', () => {
    const r = assessPackageRisk({ malicious: true });
    expect(r.rationale).toContain('OpenSSF');
  });
});

describe('remediationSla', () => {
  it('gives immediate action for a malicious package', () => {
    const sla = remediationSla('malicious');
    expect(sla.window).toBe('immediate');
    expect(sla.action).toContain('compromised');
  });

  it('tells you to verify rather than trust a package with no data', () => {
    const sla = remediationSla('unknown');
    expect(sla.action).toContain('typosquat');
  });

  it('returns an SLA for every verdict the scorer can emit', () => {
    for (const v of ['malicious', 'act-now', 'schedule', 'monitor', 'clean', 'unknown'] as const) {
      expect(remediationSla(v).window).toBeTruthy();
      expect(remediationSla(v).action).toBeTruthy();
    }
  });
});
