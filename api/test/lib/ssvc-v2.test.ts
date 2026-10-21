/**
 * SSVC v2 (CISA Deployer) tests.
 *
 * Ports the ground-truth cases in CVE Intel's
 * `crates/cve-core/src/ssvc.rs` `#[cfg(test)]` module, plus the cases that
 * matter most for the platform: a stale CISA value must never *lower* the
 * exploitation input, and a non-open exposure must override CISA's
 * Automatable answer.
 */

import { describe, it, expect } from 'vitest';
import { ssvcDecision, classifyExploitation, extractCisaSsvc, SSVC_SCORING_VERSION } from '../../src/lib/ssvc-v2';

describe('ssvcDecision', () => {
  it('kev + critical → Act', () => {
    const d = ssvcDecision({
      in_kev: true,
      epss_probability: 0.9,
      poc_confidence: 'WEAPONIZED',
      cvss_score: 10,
      exposure: 'open',
    });
    expect(d.action).toBe('Act');
  });

  it('a quiet CVE tracks, and the inputs are estimated', () => {
    const d = ssvcDecision({
      in_kev: false,
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 3,
      exposure: 'open',
    });
    expect(d.action).toBe('Track');
    expect(d.inputs_source).toBe('estimated');
  });

  it("uses CISA's automatable and technical impact when published", () => {
    const d = ssvcDecision({
      in_kev: false,
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 7.5,
      exposure: 'open',
      cisa: { exploitation: 'none', automatable: 'yes', technical_impact: 'total' },
    });
    expect(d.technical_impact).toBe('total');
    expect(d.automatable).toBe('yes');
    expect(d.exploitation).toBe('none');
    expect(d.inputs_source).toBe('CISA Vulnrichment');
  });

  it('live exploitation beats a stale CISA value', () => {
    const cisa = { exploitation: 'none', automatable: 'no', technical_impact: 'partial' };
    const live = ssvcDecision({
      in_kev: false,
      reported_exploited: ['VulnCheck KEV'],
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 5,
      exposure: 'open',
      cisa,
    });
    expect(live.exploitation).toBe('active');
    expect(live.rationale).toContain('VulnCheck KEV');

    const stale = ssvcDecision({
      in_kev: false,
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 5,
      exposure: 'open',
      cisa,
    });
    expect(stale.exploitation).toBe('none');
  });

  it('EUVD exploitation raises exploitation and names itself', () => {
    const d = ssvcDecision({
      in_kev: false,
      reported_exploited: ['ENISA EUVD'],
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 9.8,
      exposure: 'open',
    });
    expect(d.exploitation).toBe('active');
    expect(d.rationale).toContain('Exploitation=active (ENISA EUVD)');

    const both = ssvcDecision({
      in_kev: true,
      reported_exploited: ['VulnCheck KEV', 'ENISA EUVD'],
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 9.8,
      exposure: 'open',
    });
    expect(both.rationale).toContain('(CISA KEV, VulnCheck KEV, ENISA EUVD)');
  });

  it('ignores CISA values outside the SSVC vocabulary', () => {
    const d = ssvcDecision({
      in_kev: false,
      epss_probability: 0.01,
      poc_confidence: 'NONE',
      cvss_score: 9.8,
      exposure: 'open',
      cisa: { exploitation: 'maybe', automatable: '', technical_impact: 'huge' },
    });
    // 'total' comes from the CVSS proxy, not from the out-of-vocabulary value.
    expect(d.technical_impact).toBe('total');
    expect(d.inputs_source).toBe('estimated');
  });

  it('a limited exposure overrides CISA automatable', () => {
    const d = ssvcDecision({
      in_kev: true,
      epss_probability: 0.5,
      poc_confidence: 'NONE',
      cvss_score: 9.8,
      exposure: 'small',
      cisa: { exploitation: 'active', automatable: 'yes', technical_impact: 'total' },
    });
    expect(d.automatable).toBe('no');
    expect(d.action).toBe('Act');
  });

  it('reports the scoring version', () => {
    const d = ssvcDecision({
      in_kev: false,
      epss_probability: 0,
      poc_confidence: 'NONE',
      cvss_score: 0,
      exposure: 'open',
    });
    expect(d.scoring_version).toBe(SSVC_SCORING_VERSION);
    expect(d.scoring_version).toBe('2.0');
  });

  it('treats an unrecognised exposure as open', () => {
    const d = ssvcDecision({
      in_kev: false,
      epss_probability: 0.5,
      poc_confidence: 'NONE',
      cvss_score: 5,
      exposure: 'somewhere-else',
    });
    expect(d.exposure).toBe('open');
  });
});

describe('classifyExploitation', () => {
  it('maps EPSS and PoC tiers onto the three levels', () => {
    expect(classifyExploitation(true, 0, 'NONE')).toBe('active');
    expect(classifyExploitation(false, 0.95, 'NONE')).toBe('active');
    expect(classifyExploitation(false, 0.5, 'NONE')).toBe('poc');
    expect(classifyExploitation(false, 0, 'WEAPONIZED')).toBe('poc');
    expect(classifyExploitation(false, 0, 'public_poc_low_quality')).toBe('poc');
    expect(classifyExploitation(false, 0.01, 'NONE')).toBe('none');
  });
});

describe('extractCisaSsvc', () => {
  it('reads CISA-ADP SSVC options out of a CVE 5.x record', () => {
    const doc = {
      containers: {
        adp: [
          {
            metrics: [
              {
                other: {
                  type: 'ssvc',
                  content: {
                    id: 'CVE-2024-3400',
                    role: 'CISA Coordinator',
                    options: [{ Exploitation: 'active' }, { Automatable: 'yes' }, { 'Technical Impact': 'total' }],
                    version: '2.0.3',
                    timestamp: '2024-04-17T04:00:13.543064Z',
                  },
                },
              },
            ],
          },
        ],
      },
    };
    const s = extractCisaSsvc(doc);
    expect(s).toBeDefined();
    expect(s?.exploitation).toBe('active');
    expect(s?.automatable).toBe('yes');
    expect(s?.technical_impact).toBe('total');
    expect(s?.version).toBe('2.0.3');
  });

  it('returns undefined when the record carries no SSVC', () => {
    expect(extractCisaSsvc({ containers: { adp: [] } })).toBeUndefined();
    expect(extractCisaSsvc({})).toBeUndefined();
    expect(extractCisaSsvc(null)).toBeUndefined();
  });
});
