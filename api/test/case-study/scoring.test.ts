import { describe, it, expect } from 'vitest';
import {
  recencyScore,
  severityScore,
  severityFromText,
  noveltyScore,
  finalScore,
  finalScoreWithTrending,
} from '../../src/case-study/scoring';

const now = new Date('2026-05-14T12:00:00Z');

describe('recencyScore', () => {
  it('is 1.0 for events within last 24h', () => {
    const t = new Date('2026-05-13T13:00:00Z').toISOString();
    expect(recencyScore(t, now)).toBeCloseTo(1.0, 2);
  });

  it('decays linearly to 0 over 14 days', () => {
    const t = new Date('2026-04-30T12:00:00Z').toISOString(); // 14d ago
    expect(recencyScore(t, now)).toBeCloseTo(0, 2);
  });

  it('is 0 for events older than 14 days', () => {
    const t = new Date('2026-04-01T12:00:00Z').toISOString();
    expect(recencyScore(t, now)).toBe(0);
  });
});

describe('severityScore', () => {
  it('returns CVSS/10 when given a number', () => {
    expect(severityScore({ cvss: 9.8 })).toBeCloseTo(0.98, 2);
    expect(severityScore({ cvss: 5 })).toBeCloseTo(0.5, 2);
  });

  it('returns 1.0 if KEV-listed regardless of CVSS', () => {
    expect(severityScore({ cvss: 4, kev: true })).toBe(1.0);
  });

  it('scales victim count for ransomware (5+ = 1.0)', () => {
    expect(severityScore({ victims: 1 })).toBeCloseTo(0.2, 2);
    expect(severityScore({ victims: 5 })).toBe(1.0);
    expect(severityScore({ victims: 100 })).toBe(1.0);
  });

  it('returns 0.3 default for no signals', () => {
    expect(severityScore({})).toBe(0.3);
  });

  it('treats NaN and non-finite inputs as no signal instead of propagating NaN', () => {
    // A field-shape drift upstream (reading `ioc.count` when the API returns
    // `observation_count`) used to produce a NaN severity that silently
    // corrupted the whole candidate score.
    expect(severityScore({ cvss: Number.NaN })).toBe(0.3);
    expect(severityScore({ victims: Number.NaN })).toBe(0.3);
    expect(severityScore({ cvss: Number.POSITIVE_INFINITY })).toBe(0.3);
  });

  it('clamps negative victim counts to zero', () => {
    expect(severityScore({ victims: -5 })).toBe(0);
  });
});

describe('noveltyScore', () => {
  it('is 1.0 if not previously seen', () => {
    expect(noveltyScore(null, now)).toBe(1.0);
  });

  it('is 0.0 if seen today', () => {
    expect(noveltyScore({ lastSeenAt: now.toISOString() }, now)).toBe(0);
  });

  it('increases with sqrt decay over 90 days (recently seen is heavily penalized)', () => {
    // Exponential (sqrt) decay: half the window (45d) scores sqrt(0.5) ≈ 0.707,
    // NOT the linear 0.5 — the deliberate scoring change in the discovery
    // pipeline audit that strongly penalizes recently seen content.
    const t = new Date(now.getTime() - 45 * 24 * 3600 * 1000).toISOString();
    expect(noveltyScore({ lastSeenAt: t }, now)).toBeCloseTo(Math.sqrt(0.5), 2);
  });
});

describe('finalScore', () => {
  it('weighted average of recency, severity, novelty with source weight', () => {
    const s = finalScore({
      recency: 1.0,
      severity: 1.0,
      novelty: 1.0,
      sourceWeight: 1.0,
    });
    expect(s).toBeCloseTo(1.0, 2);
  });

  it('drops when novelty drops', () => {
    const hi = finalScore({ recency: 1, severity: 1, novelty: 1, sourceWeight: 1 });
    const lo = finalScore({ recency: 1, severity: 1, novelty: 0, sourceWeight: 1 });
    expect(lo).toBeLessThan(hi);
  });

  it('treats non-finite components as zero rather than producing NaN', () => {
    const s = finalScore({
      recency: Number.NaN,
      severity: 1,
      novelty: Number.NaN,
      sourceWeight: 1,
    });
    expect(Number.isFinite(s)).toBe(true);
    expect(s).toBeCloseTo(0.4, 2); // 0.3*1 + 0.1*1
  });
});

describe('finalScoreWithTrending', () => {
  it('falls back to finalScore when trending is not provided', () => {
    const base = finalScore({ recency: 1, severity: 0.8, novelty: 0.5, sourceWeight: 0.6 });
    const withTrending = finalScoreWithTrending({ recency: 1, severity: 0.8, novelty: 0.5, sourceWeight: 0.6 });
    expect(withTrending).toBeCloseTo(base, 4);
  });

  it('weights trending at 20% when provided', () => {
    const s = finalScoreWithTrending({
      recency: 1.0,
      severity: 1.0,
      novelty: 1.0,
      sourceWeight: 1.0,
      trending: 1.0,
    });
    expect(s).toBeCloseTo(1.0, 2);
  });

  it('drops score when trending is low', () => {
    const hi = finalScoreWithTrending({ recency: 1, severity: 1, novelty: 1, sourceWeight: 1, trending: 1 });
    const lo = finalScoreWithTrending({ recency: 1, severity: 1, novelty: 1, sourceWeight: 1, trending: 0 });
    expect(lo).toBeLessThan(hi);
  });

  it('reduces recency and severity weight from 0.3/0.35 to 0.25/0.25 when trending is used', () => {
    const noTrending = finalScore({ recency: 0, severity: 0, novelty: 1, sourceWeight: 0 });
    const yesTrending = finalScoreWithTrending({ recency: 0, severity: 0, novelty: 1, sourceWeight: 0, trending: 1 });
    // noTrending: 0.3*0 + 0.35*0 + 0.25*1 + 0.1*0 = 0.25
    // yesTrending: 0.25*0 + 0.25*0 + 0.2*1 + 0.1*0 + 0.2*1 = 0.4
    expect(yesTrending).toBeGreaterThan(noTrending);
  });
});

describe('severityFromText', () => {
  it('tiers confirmed exploitation at 1.0', () => {
    expect(severityFromText('Actively exploited flaw in Citrix appliances')).toBe(1.0);
    expect(severityFromText('CISA adds CVE-2026-1234 to KEV catalog')).toBe(1.0);
  });

  it('tiers weaponisation and the criminal economy at 0.9', () => {
    expect(severityFromText('Zero-day exploit traded for weeks before disclosure')).toBe(0.9);
    expect(severityFromText('Ransomware group claims breach of hospital chain')).toBe(0.9);
    expect(severityFromText('Operator arrested in coordinated takedown')).toBe(0.9);
    expect(severityFromText('Supply chain backdoor found in update channel')).toBe(0.9);
  });

  it('tiers the credential economy at 0.8', () => {
    expect(severityFromText('2.5 million records dumped after breach of payroll vendor')).toBe(0.8);
    expect(severityFromText('Stolen credentials from stealer logs offered for sale')).toBe(0.8);
    expect(severityFromText('Access broker listing for VPN appliance')).toBe(0.8);
  });

  it('tiers critical/attribution signals at 0.7', () => {
    expect(severityFromText('Critical vulnerability patched in release notes')).toBe(0.7);
    expect(severityFromText('Researchers attribute the campaign to a tracked actor')).toBe(0.7);
  });

  it('keeps routine reporting above the floor but below campaigns', () => {
    const s = severityFromText('Vendor ships advisory for minor issue');
    expect(s).toBeGreaterThanOrEqual(0.55);
    expect(s).toBeLessThan(0.7);
  });

  it('falls back to the 0.3 floor for non-security prose', () => {
    expect(severityFromText('Quarterly earnings beat expectations')).toBe(0.3);
    expect(severityFromText('')).toBe(0.3);
  });

  it('takes the highest matching tier when several appear', () => {
    const s = severityFromText('Routine advisory discloses a critical bug that is actively exploited');
    expect(s).toBe(1.0);
  });
});

describe('severityScore mentions alias', () => {
  it('scores mention counts on the victims scale', () => {
    expect(severityScore({ mentions: 5 })).toBe(1.0);
    expect(severityScore({ mentions: 1 })).toBeCloseTo(0.2, 2);
  });

  it('prefers victims when both are present', () => {
    expect(severityScore({ victims: 2, mentions: 10 })).toBeCloseTo(0.4, 2);
  });
});
