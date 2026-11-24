import { describe, expect, it } from 'vitest';
import { EVIDENCE_STATUSES, incidentStatus, STATUS_META } from '../pulse-status';

const row = (over: Record<string, unknown> = {}) => ({
  kind: 'breach', source: 'News report',
  title: 'ExampleOrg breach exposes records',
  description: 'A reporter covered the incident.',
  ...over,
});

describe('incidentStatus', () => {
  it('uses explicit language over source strength', () => {
    expect(incidentStatus(row({ title: 'ExampleOrg denies breach reports' }))).toBe('disputed');
    expect(incidentStatus(row({ kind: 'ransomware', source: 'RansomLook', description: 'taken offline as a precaution' }))).toBe('precautionary');
  });
  it('promotes confirmed evidence above press coverage', () => {
    expect(incidentStatus(row({ kev: true }))).toBe('confirmed');
    expect(incidentStatus(row({ exploitStatus: 'in_the_wild' }))).toBe('confirmed');
    expect(incidentStatus(row({ source: 'SEC EDGAR 8-K filing' }))).toBe('confirmed');
    expect(incidentStatus(row())).toBe('reported');
  });
  it('keeps leak-site assertions as claims', () => {
    expect(incidentStatus(row({ kind: 'ransomware', source: 'RansomLook' }))).toBe('claimed');
    expect(incidentStatus(row({ source: 'Leak site claim' }))).toBe('claimed');
  });
  it('returns null for non-incident layers', () => {
    expect(incidentStatus(row({ kind: 'cve', title: 'CVE-2026-1234' }))).toBeNull();
    expect(incidentStatus(row({ kind: 'earthquake' }))).toBeNull();
    expect(incidentStatus(row({ kind: 'ai_incident' }))).toBe('reported');
  });
  it('exposes all five statuses with honest descriptions', () => {
    expect(EVIDENCE_STATUSES).toHaveLength(5);
    for (const status of EVIDENCE_STATUSES) {
      expect(STATUS_META[status].label).toBeTruthy();
      expect(STATUS_META[status].description.length).toBeGreaterThan(20);
    }
  });
});
