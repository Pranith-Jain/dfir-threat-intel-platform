/** Route tests for the situation-room dossier's "platform record" link. */
import { describe, it, expect } from 'vitest';
import { platformRecordFor, type GhmCve, type GhmIncident } from './types';
import type { PulseEvent } from '../global-pulse-types';

const cve = { id: 'CVE-2026-133469' } as GhmCve;
const breach = {
  id: 'acme-2026-11',
  victim: 'ACME Corp',
  title: 'ACME Corp: Confirmed data breach',
  type: 'Data breach',
  actor: null,
  status: 'confirmed',
  description: '',
  place: null,
  country: 'US',
  lat: 0,
  lng: 0,
  published: '',
  url: '',
  records: null,
} as GhmIncident;
const ransomware = {
  ...breach,
  type: 'Ransomware',
  actor: 'TheGentlemen',
  title: 'Real Time Data Services: Claimed by TheGentlemen',
} as GhmIncident;
const event = {
  id: 'pulse-1',
  title: 'Company #269: Claimed by N0n, not confirmed',
  description: '',
  kind: 'breach',
  cti: 'ransomware',
  lat: 0,
  lng: 0,
  timestamp: '',
  severity: 'high',
  source: '',
} as PulseEvent;

describe('platformRecordFor', () => {
  it('sends CVE dossiers to the CVE list with the validated id', () => {
    expect(platformRecordFor({ cve, incident: null, event: null })).toEqual({
      href: '/threatintel/cve-list?q=CVE-2026-133469',
      label: 'CVE record',
    });
  });

  it('sends breach dossiers to BreachWatch with the victim as the query', () => {
    expect(platformRecordFor({ cve: null, incident: breach, event: null })).toEqual({
      href: '/threatintel/breach-hub?tab=watch&q=ACME%20Corp',
      label: 'Breach record',
    });
  });

  it('sends ransomware dossiers to RansomReport with the actor as group', () => {
    expect(platformRecordFor({ cve: null, incident: ransomware, event: null })).toEqual({
      href: '/threatintel/ransomware-hub?tab=report&group=thegentlemen',
      label: 'Ransomware group',
    });
  });

  it('recognises a ransomware claim from a Global Pulse event', () => {
    expect(platformRecordFor({ cve: null, incident: null, event })).toEqual({
      href: '/threatintel/ransomware-hub?tab=report&group=n0n',
      label: 'Ransomware group',
    });
  });

  it('detects a ransomware type even when the actor is missing', () => {
    const record = platformRecordFor({
      cve: null,
      incident: { ...breach, type: 'Ransomware' },
      event: null,
    });
    expect(record.href).toContain('/threatintel/ransomware-hub?');
    expect(record.label).toBe('Ransomware group');
  });

  it('keeps a CVE dossier on the CVE route even if the text mentions a breach', () => {
    expect(platformRecordFor({ cve, incident: ransomware, event }).label).toBe('CVE record');
  });
});
