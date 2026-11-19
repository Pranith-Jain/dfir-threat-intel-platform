// api/src/routes/global-pulse/converters.test.ts
//
// Unit tests for the pure converter functions. The geo / hand
// shelling around the converters is exercised by integration; here
// we just check the heuristic logic.

import { describe, it, expect } from 'vitest';
import {
  fromFirms,
  fromUkmto,
  fromCveDigest,
  fromHackingIncidents,
  signalClass,
  dedupeCveEvents,
  markTrendingEvents,
  comparePulseEvents,
} from './converters';
import type { PulseEvent } from './types';
import type { FirmsUkmtoResponse } from '../firms-ukmto';

const makeFirm = (
  overrides: Partial<{
    id: string;
    lat: number;
    lng: number;
    frp: number;
    brightness: number;
    acq_date: string;
    acq_time: string;
    satellite: string;
    confidence: string;
    daynight: 'D' | 'N';
  }> = {}
) => ({
  id: 'firms-1',
  lat: 0,
  lng: 0,
  frp: 5,
  brightness: 320,
  acq_date: '2026-06-13',
  acq_time: '0342',
  satellite: 'NOAA-20',
  confidence: 'high',
  daynight: 'D' as const,
  ...overrides,
});

const makeIncident = (
  overrides: Partial<{ id: string; title: string; category: string; date: string; lat: number; lng: number }> = {}
) => ({
  id: 'ukmto-1',
  title: 'Suspicious approach',
  category: 'suspicious approach',
  date: '2026-06-13',
  lat: 12.0,
  lng: 45.0,
  ...overrides,
});

const empty: FirmsUkmtoResponse = { generated_at: '2026-06-13T00:00:00Z', fires: [], incidents: [] };

describe('fromFirms', () => {
  it('returns [] for empty / nullish input', () => {
    expect(fromFirms(null)).toEqual([]);
    expect(fromFirms(undefined)).toEqual([]);
    expect(fromFirms(empty)).toEqual([]);
  });

  it('drops low-FRP noise (FRP < 1 MW)', () => {
    const r = fromFirms({ ...empty, fires: [makeFirm({ frp: 0.5 })] });
    expect(r).toEqual([]);
  });

  it('marks FRP >= 50 MW as critical', () => {
    const r = fromFirms({ ...empty, fires: [makeFirm({ frp: 60 })] });
    expect(r[0]?.severity).toBe('critical');
  });

  it('marks FRP 10..50 MW as high', () => {
    const r = fromFirms({ ...empty, fires: [makeFirm({ frp: 15 })] });
    expect(r[0]?.severity).toBe('high');
  });

  it('marks FRP 1..10 MW with brightness >= 340 K as medium', () => {
    const r = fromFirms({ ...empty, fires: [makeFirm({ frp: 5, brightness: 350 })] });
    expect(r[0]?.severity).toBe('medium');
  });

  it('caps the rendered list at 250, sorted by FRP desc', () => {
    const fires = Array.from({ length: 300 }, (_, i) => makeFirm({ id: `f-${i}`, frp: i + 1 }));
    const r = fromFirms({ ...empty, fires });
    expect(r.length).toBe(250);
    // Highest FRP first.
    expect(r[0]?.title).toContain('FRP 300.0');
    expect(r[249]?.title).toContain('FRP 51.0');
  });

  it('builds a valid ISO timestamp from acq_date + acq_time', () => {
    const r = fromFirms({ ...empty, fires: [makeFirm({ acq_date: '2026-06-13', acq_time: '0342' })] });
    expect(r[0]?.timestamp).toBe('2026-06-13T03:42Z');
  });
});

describe('fromUkmto', () => {
  it('returns [] for empty / nullish input', () => {
    expect(fromUkmto(null)).toEqual([]);
    expect(fromUkmto(undefined)).toEqual([]);
    expect(fromUkmto(empty)).toEqual([]);
  });

  it('piracy / armed attack → critical', () => {
    expect(fromUkmto({ ...empty, incidents: [makeIncident({ category: 'Piracy' })] })[0]?.severity).toBe('critical');
    expect(fromUkmto({ ...empty, incidents: [makeIncident({ category: 'Armed Attack' })] })[0]?.severity).toBe(
      'critical'
    );
  });

  it('suspicious approach → high', () => {
    expect(fromUkmto({ ...empty, incidents: [makeIncident({ category: 'Suspicious Approach' })] })[0]?.severity).toBe(
      'high'
    );
  });

  it('unknown category → medium (visible but not high-priority)', () => {
    expect(fromUkmto({ ...empty, incidents: [makeIncident({ category: 'advisory' })] })[0]?.severity).toBe('medium');
  });

  it('parses incident date to ISO', () => {
    const r = fromUkmto({ ...empty, incidents: [makeIncident({ date: '2026-06-13' })] });
    expect(r[0]?.timestamp).toBe('2026-06-13T00:00:00.000Z');
  });
});

describe('fromCveDigest — the 0-day surface', () => {
  const row = (over: Record<string, unknown> = {}) => ({
    cve_id: 'CVE-2026-50001',
    published: '2026-10-02T06:00:00.000Z',
    severity: 'HIGH' as const,
    score: 7.5,
    description: 'Test vuln',
    is_in_kev: false,
    priority_score: 0,
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-50001',
    ctiwatch_url: 'https://ctiwatch.com/vulnerabilities/CVE-2026-50001',
    ...over,
  });

  it('maps KEV rows to kind kev, critical, flagged', () => {
    const [out] = fromCveDigest({ entries: [row({ is_in_kev: true, severity: 'HIGH' })] });
    expect(out?.kind).toBe('kev');
    expect(out?.severity).toBe('critical');
    expect(out?.kev).toBe(true);
    expect(out?.description).toContain('KEV-listed');
  });

  it('floors exploited rows at high and records the exploit status', () => {
    const [out] = fromCveDigest({ entries: [row({ severity: 'MEDIUM', exploit_status: 'weaponized' })] });
    expect(out?.kind).toBe('cve');
    expect(out?.exploitStatus).toBe('weaponized');
    expect(out?.description).toContain('weaponized');
  });

  it('keeps criticals and tops up with highs by score to the cap', () => {
    const entries = [
      row({ cve_id: 'CVE-2026-50001', severity: 'CRITICAL' }),
      ...Array.from({ length: 60 }, (_, i) =>
        row({ cve_id: `CVE-2026-51${String(i).padStart(3, '0')}`, severity: 'HIGH', score: 7 + (i % 3) * 0.5 })
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        row({ cve_id: `CVE-2026-52${String(i).padStart(3, '0')}`, severity: 'LOW' })
      ),
    ];
    const out = fromCveDigest({ entries });
    // 1 critical + 39 highest-score highs = cap 40; no LOWs leak in.
    expect(out).toHaveLength(40);
    expect(out[0]?.id).toBe('digest-CVE-2026-50001');
    expect(out.every((e) => e.severity === 'critical' || e.severity === 'high')).toBe(true);
  });

  it('returns [] for a missing/empty digest', () => {
    expect(fromCveDigest({})).toEqual([]);
    expect(fromCveDigest({ entries: [] })).toEqual([]);
  });

  it('links every row to its ctiwatch page', () => {
    const [out] = fromCveDigest({ entries: [row()] });
    expect(out?.url).toBe('https://ctiwatch.com/vulnerabilities/CVE-2026-50001');
  });
});

describe('signalClass — within-severity ordering', () => {
  it('ranks ransomware and KEV above CVE records above infra', () => {
    expect(signalClass({ kind: 'ransomware', trending: undefined })).toBeGreaterThan(
      signalClass({ kind: 'cve', trending: undefined })
    );
    expect(signalClass({ kind: 'cve', trending: undefined })).toBeGreaterThan(
      signalClass({ kind: 'c2_tracker', trending: undefined })
    );
    expect(signalClass({ kind: 'kev', trending: undefined })).toBe(3);
    expect(signalClass({ kind: 'exploit', trending: undefined })).toBe(2);
  });

  it('boosts trending rows one class without crossing severity', () => {
    // A trending C2 ties a plain CVE record — severity still dominates above.
    expect(signalClass({ kind: 'c2_tracker', trending: true })).toBe(signalClass({ kind: 'cve', trending: undefined }));
    expect(signalClass({ kind: 'ransomware', trending: true })).toBe(4);
  });
});

describe('dedupeCveEvents', () => {
  const cve = (id: string, kind: 'cve' | 'kev' = 'cve', source = 'NVD') => ({
    id: `${kind}-${id}`,
    kind,
    title: id,
    description: 'x',
    lat: 0,
    lng: 0,
    timestamp: '2026-10-02T00:00:00.000Z',
    severity: 'high' as const,
    source,
  });

  it('keeps the digest row over catalog/sample duplicates', () => {
    const out = dedupeCveEvents([
      cve('CVE-2026-50001', 'cve', 'NVD'),
      { ...cve('CVE-2026-50001', 'kev', 'CISA KEV'), id: 'kev-0-CVE-2026-50001' },
      { ...cve('CVE-2026-50001', 'cve', 'CTIWatch · 24h digest'), id: 'digest-CVE-2026-50001' },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe('digest-CVE-2026-50001');
  });

  it('keeps catalog KEV over a plain sample row', () => {
    const out = dedupeCveEvents([
      cve('CVE-2026-50002', 'cve'),
      { ...cve('CVE-2026-50002', 'kev'), id: 'kev-0-CVE-2026-50002' },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]?.kind).toBe('kev');
  });

  it('preserves the trending flag when trending is stamped before dedupe (handler order)', () => {
    // The handler runs markTrendingEvents BEFORE dedupeCveEvents: dedupe
    // collapses corroboration to one row, so stamping after would leave every
    // survivor single-sourced and trending would never fire. This test pins
    // that composition.
    const digestRow = { ...cve('CVE-2026-50001', 'cve', 'CTIWatch · 24h digest'), id: 'digest-CVE-2026-50001' };
    const sampleRow = cve('CVE-2026-50001', 'cve', 'NVD');
    const out = dedupeCveEvents(markTrendingEvents([digestRow, sampleRow]));
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe('digest-CVE-2026-50001');
    expect(out[0]?.trending).toBe(true);
  });

  it('leaves non-CVE kinds and distinct CVEs alone', () => {
    const ransom = {
      id: 'ransom-x',
      kind: 'ransomware' as const,
      title: 'acme — lockbit',
      description: 'x',
      lat: 0,
      lng: 0,
      timestamp: '2026-10-02T00:00:00.000Z',
      severity: 'critical' as const,
      source: 'RL',
    };
    const out = dedupeCveEvents([cve('CVE-2026-50001'), cve('CVE-2026-50002'), ransom]);
    expect(out).toHaveLength(3);
  });
});

describe('markTrendingEvents', () => {
  const ev = (over: Record<string, unknown> = {}) => ({
    id: 'x',
    kind: 'cve' as const,
    title: 'CVE-2026-50001',
    description: 'x',
    lat: 0,
    lng: 0,
    timestamp: '2026-10-02T00:00:00.000Z',
    severity: 'high' as const,
    source: 'NVD',
    ...over,
  });

  it('flags a CVE seen in 2+ distinct sources', () => {
    const out = markTrendingEvents([
      ev({ id: 'a', source: 'NVD' }),
      ev({ id: 'b', title: 'CVE-2026-50001 — other vendor', source: 'CTIWatch · 24h digest' }),
      ev({ id: 'c', title: 'CVE-2026-59999', source: 'NVD' }),
    ]);
    expect(out.find((e) => e.id === 'a')?.trending).toBe(true);
    expect(out.find((e) => e.id === 'b')?.trending).toBe(true);
    expect(out.find((e) => e.id === 'c')?.trending).toBeUndefined();
  });

  it('does not count the same source twice', () => {
    const out = markTrendingEvents([ev({ id: 'a', source: 'NVD' }), ev({ id: 'b', source: 'NVD' })]);
    expect(out.every((e) => e.trending === undefined)).toBe(true);
  });

  it('flags a ransomware victim claimed by two groups/feeds', () => {
    const out = markTrendingEvents([
      ev({ id: 'r1', kind: 'ransomware', title: 'Acme Corp — lockbit', source: 'ransomware.live' }),
      ev({ id: 'r2', kind: 'ransomware', title: 'Acme Corp — blacksuit (X claim)', source: 'X: blacksuit' }),
    ]);
    expect(out.every((e) => e.trending === true)).toBe(true);
  });

  it('ignores kinds without a stable key', () => {
    const out = markTrendingEvents([ev({ id: 'p1', kind: 'phishing', title: 'http://evil/x' })]);
    expect(out[0]?.trending).toBeUndefined();
  });
});

describe('comparePulseEvents — the "no more C2 on top" guarantee', () => {
  // Reproduces the production complaint: 50 critical C2 rows stamped "now"
  // must NOT outrank an older critical ransomware victim or a KEV 0-day.
  const evt = (over: Partial<PulseEvent>): PulseEvent => ({
    id: 'x',
    kind: 'c2_tracker',
    title: 'C2',
    description: 'x',
    lat: 0,
    lng: 0,
    timestamp: '2026-10-02T12:00:00.000Z',
    severity: 'critical',
    source: 'Feodo Tracker',
    ...over,
  });
  const c2flood = Array.from({ length: 50 }, (_, i) => evt({ id: `c2-${i}`, title: `Emotet C2 — 1.2.3.${i}` }));
  const victim = evt({
    id: 'ransom-acme',
    kind: 'ransomware',
    title: 'Acme Corp — lockbit',
    timestamp: '2026-10-01T08:00:00.000Z',
    source: 'ransomware.live',
  });
  const zeroday = evt({
    id: 'digest-CVE-2026-50001',
    kind: 'kev',
    title: 'CVE-2026-50001',
    timestamp: '2026-10-02T06:00:00.000Z',
    source: 'CISA KEV · 24h digest',
    kev: true,
  });

  it('ranks an older ransomware victim and a 0-day above 50 fresh critical C2 rows', () => {
    const sorted = [...c2flood, victim, zeroday].sort(comparePulseEvents);
    // Both class-3 signals clear the entire C2 flood; between themselves
    // recency wins (the 0-day is fresher than yesterday's victim).
    expect(sorted.slice(0, 2).map((e) => e.id)).toEqual(['digest-CVE-2026-50001', 'ransom-acme']);
    expect(sorted.slice(2).every((e) => e.kind === 'c2_tracker')).toBe(true);
  });

  it('still lets severity dominate (critical C2 above high CVE)', () => {
    const high = evt({ id: 'h', kind: 'cve', title: 'CVE-2026-59999', severity: 'high' });
    expect([...c2flood.slice(0, 1), high].sort(comparePulseEvents)[0]?.id).toBe('c2-0');
  });

  it('trending breaks ties within the same class', () => {
    const a = evt({ id: 'a', kind: 'cve', title: 'CVE-2026-1' });
    const b = evt({ id: 'b', kind: 'cve', title: 'CVE-2026-2', trending: true });
    expect([a, b].sort(comparePulseEvents)[0]?.id).toBe('b');
  });
});

describe('fromHackingIncidents', () => {
  it('maps evidence grade, autonomy and country enrichment into mappable events', () => {
    const events = fromHackingIncidents({
      incidents: [
        {
          id: 'artex-github-oauth-secrets-2026',
          title: 'ARTEX agents search GitHub for OAuth secrets',
          date: '2026-11',
          actor: 'ARTEX operator',
          targets: 'GitHub OAuth apps',
          aiRole: ['recon'],
          models: ['Claude'],
          autonomy: 'semi-autonomous',
          confidence: 'CONFIRMED',
          countries: ['US'],
          harnessUsed: true,
        },
        {
          id: 'autonomous-run',
          title: 'Agent ran an intrusion on its own',
          date: '2026-10-15',
          confidence: 'confirmed',
          autonomy: 'autonomous',
        },
        { id: 'thin', title: 'A suspected case', date: '2025-07', confidence: 'suspected' },
      ],
    });
    expect(events).toHaveLength(3);
    const [first, second, third] = events;
    expect(first!.kind).toBe('ai_incident');
    expect(first!.severity).toBe('high');
    expect(first!.lat).toBeCloseTo(37.09);
    expect(first!.lng).toBeCloseTo(-95.71);
    expect(first!.country).toBe('US');
    expect(first!.url).toBe('https://hackingincidents.ai/incident/artex-github-oauth-secrets-2026/');
    expect(first!.cti).toBe('threat');
    expect(first!.description).toContain('ARTEX operator');
    expect(first!.timestamp).toBe('2026-11-01T00:00:00Z');
    expect(second!.severity).toBe('critical');
    expect(third!.severity).toBe('low');
    expect(third!.lat).toBe(0);
  });

  it('tolerates a missing or malformed slice', () => {
    expect(fromHackingIncidents(null)).toEqual([]);
    expect(fromHackingIncidents({ incidents: [{ id: '', title: '', date: '', confidence: '' }] })).toEqual([]);
  });
});
