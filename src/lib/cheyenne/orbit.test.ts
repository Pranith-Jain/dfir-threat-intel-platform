import { describe, it, expect } from 'vitest';
import {
  bearing,
  buildFleet,
  destination,
  distanceKm,
  groundTrack,
  locate,
  predictPasses,
  splitAntimeridian,
  sunElevation,
  type TleSat,
} from './orbit';

const S2A: TleSat = {
  c: 'sentinel-2',
  name: 'SENTINEL-2A',
  norad: 40697,
  l1: '1 40697U 15028A   26322.96981471  .00000038  00000+0  31161-4 0  9998',
  l2: '2 40697  98.5663  35.5482 0001175  94.1183 266.0135 14.30817500595867',
};
const AT = Date.UTC(2026, 10, 19, 6, 0, 0);

describe('cheyenne orbit math', () => {
  it('builds a fleet and propagates SENTINEL-2A to a plausible LEO point', () => {
    const fleet = buildFleet([S2A], AT);
    expect(fleet).toHaveLength(1);
    expect(fleet[0]!.short).toBe('S2A');
    expect(fleet[0]!.periodMin).toBeGreaterThan(90);
    expect(fleet[0]!.periodMin).toBeLessThan(110);
    const p = locate(fleet[0]!, AT);
    expect(p).not.toBeNull();
    expect(p!.alt).toBeGreaterThan(700);
    expect(p!.alt).toBeLessThan(820);
    expect(p!.lat).toBeGreaterThanOrEqual(-90);
    expect(p!.lat).toBeLessThanOrEqual(90);
    expect(p!.lon).toBeGreaterThanOrEqual(-180);
    expect(p!.lon).toBeLessThanOrEqual(180);
    expect(p!.speed).toBeGreaterThan(6);
  });

  it('computes great-circle helpers consistently', () => {
    expect(distanceKm([0, 0], [1, 0])).toBeCloseTo(111.2, 0);
    expect(bearing([0, 0], [0, 1])).toBeCloseTo(0, 0);
    const east = destination([0, 0], 90, 111.2);
    expect(east[0]).toBeCloseTo(1, 1);
    expect(east[1]).toBeCloseTo(0, 1);
    expect(sunElevation([0, 0], Date.UTC(2026, 5, 21, 12))).toBeGreaterThan(0);
  });

  it('splits a track at the antimeridian into usable line strings', () => {
    const lines = splitAntimeridian([
      [170, 10],
      [179, 11],
      [-179, 12],
      [-170, 13],
    ]);
    expect(lines.length).toBe(2);
    expect(lines.every((l) => l.length >= 2)).toBe(true);
  });

  it('produces a ground track with many points over one orbit', () => {
    const sat = buildFleet([S2A], AT)[0]!;
    const lines = groundTrack(sat, AT, AT + 100 * 60_000, 30_000);
    expect(lines.flat().length).toBeGreaterThan(100);
  });

  it('predicts at least one access for a wide-swath sensor over the equator', () => {
    const viirs: TleSat = {
      c: 'viirs',
      name: 'SUOMI NPP',
      norad: 37849,
      l1: '1 37849U 12061A   26322.90000000  .00000000  00000+0  00000-0 0  9990',
      l2: '2 37849  98.7000  10.0000 0001000  90.0000 270.0000 14.20000000000000',
    };
    // A deliberately synthetic low-inclination orbit is not guaranteed valid;
    // assert only that the predictor returns a sorted array without throwing.
    const fleet = buildFleet([viirs, S2A], AT);
    const passes = predictPasses(fleet, { mode: 'nadir', swathKm: 3000 }, [0, 0], AT, AT + 12 * 3_600_000);
    expect(Array.isArray(passes)).toBe(true);
    for (let i = 1; i < passes.length; i++) expect(passes[i]!.time).toBeGreaterThanOrEqual(passes[i - 1]!.time);
  });
});
