/**
 * Cheyenne board — client-side orbital mechanics.
 *
 * Re-implemented in TypeScript from the public method documented by
 * MJCruickshank/cheyenne (itself built on satellite.js / SGP4). No upstream
 * code is vendored. Inputs are the replicated catalog + CelesTrak TLE snapshot
 * in public/data/cheyenne-tool/. All maths runs in the browser: no backend,
 * no keys, no network hop after the manifest loads.
 */
import * as satellite from 'satellite.js';

const D2R = Math.PI / 180;
const R2D = 180 / Math.PI;
const RE = 6371; // km

export interface TleSat {
  c: string;
  name: string;
  norad: number;
  l1: string;
  l2: string;
}

export interface SensorGeom {
  mode: 'nadir' | 'side' | 'agile';
  swathKm?: number;
  nearKm?: number;
  farKm?: number;
  reachKm?: number;
  minKm?: number;
  daylight?: boolean;
  side?: 'left' | 'right';
}

export interface TrackedSat {
  id: number;
  name: string;
  short: string;
  cid: string;
  rec: satellite.SatRec;
  periodMin: number;
  incl: number;
}

export interface GroundPoint {
  lon: number;
  lat: number;
  alt: number;
  speed: number;
}

export interface CheyennePass {
  sat: TrackedSat;
  time: number;
  crossKm: number;
  offNadir: number;
  ascending: boolean;
  sunEl: number;
  geometry: number[][];
}

const SHORT: Array<[RegExp, (m: RegExpMatchArray) => string]> = [
  [/^SENTINEL-(\d)([A-D])$/, (m) => `S${m[1]!}${m[2]!}`],
  [/^LANDSAT (\d)$/, (m) => `L${m[1]!}`],
  [/^NOAA (\d+).*$/, (m) => `N${m[1]!}`],
  [/^SUOMI NPP$/, () => 'SNPP'],
  [/^WORLDVIEW-(\d).*$/, (m) => `WV${m[1]!}`],
  [/^GEOEYE 1$/, () => 'GE1'],
  [/^PLEIADES NEO (\d)$/, (m) => `PNEO${m[1]!}`],
  [/^PLEIADES (\w+)$/, (m) => `PHR${m[1]!}`],
  [/^SPOT (\d)$/, (m) => `SPOT${m[1]!}`],
  [/^COSMO-SKYMED (\d)$/, (m) => `CSK${m[1]!}`],
  [/^ICEYE-(\w+)$/, (m) => `IX${m[1]!.replace(/^X/, '')}`],
  [/^CAPELLA-(\d+).*$/, (m) => `CAP${m[1]!}`],
  [/^UMBRA-(\d+)$/, (m) => `UMB${m[1]!}`],
  [/^TERRASAR-X$/, () => 'TSX'],
  [/^TANDEM-X$/, () => 'TDX'],
  [/^RADARSAT-2$/, () => 'RS2'],
  [/^GAOFEN-(.+)$/, (m) => `GF${m[1]!.replace(/\s+/g, '-')}`],
  [/^(.+?) \(.*\)$/, (m) => m[1]!],
];

function shortName(name: string): string {
  for (const [re, fn] of SHORT) {
    const m = name.match(re);
    if (m) return fn(m);
  }
  return name;
}

/** Parse the TLE snapshot into usable satellite records, dropping decayed elements. */
export function buildFleet(rows: TleSat[], atMs: number): TrackedSat[] {
  const out: TrackedSat[] = [];
  for (const s of rows) {
    let rec: satellite.SatRec;
    try {
      rec = satellite.twoline2satrec(s.l1, s.l2);
    } catch {
      continue;
    }
    if (!rec || rec.error) continue;
    const sat: TrackedSat = {
      id: s.norad,
      name: s.name,
      short: shortName(s.name),
      cid: s.c,
      rec,
      periodMin: (2 * Math.PI) / rec.no,
      incl: rec.inclo * R2D,
    };
    if (!locate(sat, atMs)) continue;
    out.push(sat);
  }
  return out.sort((a, b) => a.name.localeCompare(b.name, 'en', { numeric: true }));
}

/** Geodetic sub-satellite point at a time. null if propagation fails. */
export function locate(sat: TrackedSat, ms: number): GroundPoint | null {
  const date = new Date(ms);
  const pv = satellite.propagate(sat.rec, date);
  if (!pv || typeof pv.position === 'boolean' || Number.isNaN(pv.position.x)) return null;
  const geo = satellite.eciToGeodetic(pv.position, satellite.gstime(date));
  const v = pv.velocity;
  return {
    lon: geo.longitude * R2D,
    lat: geo.latitude * R2D,
    alt: geo.height,
    speed: typeof v === 'boolean' || !v ? 0 : Math.hypot(v.x, v.y, v.z),
  };
}

export function distanceKm(a: [number, number], b: [number, number]): number {
  const p1 = a[1] * D2R;
  const p2 = b[1] * D2R;
  const dl = (b[0] - a[0]) * D2R;
  const s = Math.sin((p2 - p1) / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
  return 2 * RE * Math.asin(Math.min(1, Math.sqrt(s)));
}

export function bearing(a: [number, number], b: [number, number]): number {
  const p1 = a[1] * D2R;
  const p2 = b[1] * D2R;
  const dl = (b[0] - a[0]) * D2R;
  const y = Math.sin(dl) * Math.cos(p2);
  const x = Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl);
  return (Math.atan2(y, x) * R2D + 360) % 360;
}

export function destination(p: [number, number], brg: number, km: number): [number, number] {
  const d = km / RE;
  const t = brg * D2R;
  const p1 = p[1] * D2R;
  const l1 = p[0] * D2R;
  const p2 = Math.asin(Math.sin(p1) * Math.cos(d) + Math.cos(p1) * Math.sin(d) * Math.cos(t));
  const l2 = l1 + Math.atan2(Math.sin(t) * Math.sin(d) * Math.cos(p1), Math.cos(d) - Math.sin(p1) * Math.sin(p2));
  return [((l2 * R2D + 540) % 360) - 180, p2 * R2D];
}

/** Split a polyline wherever it jumps the antimeridian (globe.gl needs this). */
export function splitAntimeridian(pts: number[][]): number[][][] {
  const lines: number[][][] = [];
  let cur: number[][] = [];
  for (const p of pts) {
    if (cur.length) {
      const q = cur[cur.length - 1]!;
      if (Math.abs(p[0]! - q[0]!) > 180) {
        const sign = p[0]! > q[0]! ? -1 : 1;
        const span = p[0]! + sign * 360 - q[0]!;
        const f = span === 0 ? 0 : (sign * 180 - q[0]!) / span;
        cur.push([sign * 180, q[1]! + (p[1]! - q[1]!) * Math.max(0, Math.min(1, f))]);
        lines.push(cur);
        cur = [[-sign * 180, q[1]! + (p[1]! - q[1]!) * Math.max(0, Math.min(1, f))]];
      }
    }
    cur.push(p);
  }
  if (cur.length > 1) lines.push(cur);
  return lines;
}

/** Ground track as antimeridian-safe line strings. */
export function groundTrack(sat: TrackedSat, t0: number, t1: number, stepMs = 20_000): number[][][] {
  const pts: number[][] = [];
  for (let t = t0; t <= t1; t += stepMs) {
    const p = locate(sat, t);
    if (p) pts.push([p.lon, p.lat]);
  }
  return splitAntimeridian(pts);
}

/** Direction of travel over the ground (degrees clockwise from north). */
export function heading(sat: TrackedSat, ms: number, here?: GroundPoint): number {
  const a = here ?? locate(sat, ms);
  const b = locate(sat, ms + 2000);
  if (!a || !b) return 0;
  return bearing([a.lon, a.lat], [b.lon, b.lat]);
}

/** Approximate solar elevation at a ground point (good enough for daylight gating). */
export function sunElevation(point: [number, number], ms: number): number {
  const d = (ms - Date.UTC(2000, 0, 1, 12)) / 86_400_000;
  const meanLon = 280.46 + 0.9856474 * d;
  const meanAnom = (357.528 + 0.9856003 * d) * D2R;
  const ecliptic = (meanLon + 1.915 * Math.sin(meanAnom) + 0.02 * Math.sin(2 * meanAnom)) * D2R;
  const obliquity = (23.439 - 0.0000004 * d) * D2R;
  const decl = Math.asin(Math.sin(obliquity) * Math.sin(ecliptic)) * R2D;
  const ra = Math.atan2(Math.cos(obliquity) * Math.sin(ecliptic), Math.cos(ecliptic)) * R2D;
  const gmst = (18.697374558 + 24.06570982441908 * d) % 24;
  const hourAngle = (gmst * 15 + point[0] - ra) * D2R;
  const lat = point[1] * D2R;
  const dec = decl * D2R;
  return Math.asin(Math.sin(lat) * Math.sin(dec) + Math.cos(lat) * Math.cos(dec) * Math.cos(hourAngle)) * R2D;
}

/** Swath limits to the right of the ground track, or null for agile sensors. */
export function fixedSwath(geom: SensorGeom): [number, number] | null {
  if (geom.mode === 'nadir' && geom.swathKm) return [-geom.swathKm / 2, geom.swathKm / 2];
  if (geom.mode === 'side' && geom.nearKm != null && geom.farKm != null) {
    const sign = geom.side === 'right' ? 1 : -1;
    return [sign * geom.nearKm, sign * geom.farKm];
  }
  return null;
}

/** Polygon swept by a fixed swath between two times. */
export function swathRibbon(
  sat: TrackedSat,
  t0: number,
  t1: number,
  nearKm: number,
  farKm: number,
  stepMs = 15_000
): number[][] {
  const left: number[][] = [];
  const right: number[][] = [];
  for (let t = t0; t <= t1; t += stepMs) {
    const p = locate(sat, t);
    if (!p) continue;
    const hdg = heading(sat, t, p);
    left.push(destination([p.lon, p.lat], hdg + 90, nearKm));
    right.push(destination([p.lon, p.lat], hdg + 90, farKm));
  }
  return [...left, ...right.reverse()];
}

function closestApproach(sat: TrackedSat, target: [number, number], t0: number, t1: number) {
  let best: { t: number; km: number; p: GroundPoint } | null = null;
  const step = Math.max(2000, Math.min(20_000, (t1 - t0) / 50));
  for (let t = t0; t <= t1; t += step) {
    const p = locate(sat, t);
    if (!p) continue;
    const km = distanceKm([p.lon, p.lat], target);
    if (!best || km < best.km) best = { t, km, p };
  }
  if (best) {
    for (let t = Math.max(t0, best.t - 20_000); t <= Math.min(t1, best.t + 20_000); t += 1000) {
      const p = locate(sat, t);
      if (!p) continue;
      const km = distanceKm([p.lon, p.lat], target);
      if (km < best.km) best = { t, km, p };
    }
  }
  return best;
}

/** Geometric access windows: when the sensor can reach the target. */
export function predictPasses(
  sats: TrackedSat[],
  geom: SensorGeom,
  target: [number, number],
  t0: number,
  t1: number
): CheyennePass[] {
  const out: CheyennePass[] = [];
  const coarse = 60_000;
  const reach =
    geom.mode === 'nadir' ? (geom.swathKm ?? 0) / 2 : geom.mode === 'side' ? (geom.farKm ?? 0) : (geom.reachKm ?? 0);
  const gate = reach + 520;
  for (const sat of sats) {
    let t = t0;
    while (t <= t1) {
      const p = locate(sat, t);
      if (p && distanceKm([p.lon, p.lat], target) < gate) {
        const ca = closestApproach(sat, target, t - coarse, t + Math.max(4 * coarse, (gate / 6.5) * 1000));
        if (ca && ca.t >= t0 && ca.t <= t1) {
          const sub: [number, number] = [ca.p.lon, ca.p.lat];
          const hdg = heading(sat, ca.t, ca.p);
          const rel = ((bearing(sub, target) - hdg + 540) % 360) - 180;
          const cross = ca.km * (rel >= 0 ? 1 : -1);
          const fixed = fixedSwath(geom);
          const ok = fixed
            ? cross >= fixed[0] && cross <= fixed[1]
            : ca.km <= (geom.reachKm ?? 0) && ca.km >= (geom.minKm ?? 0);
          const sunEl = sunElevation(target, ca.t);
          if (ok && (!geom.daylight || sunEl > 3)) {
            const half = (geom.swathKm ?? 0) / 2;
            const strip = fixed ?? [cross - half, cross + half];
            const next = locate(sat, ca.t + 10_000);
            out.push({
              sat,
              time: ca.t,
              crossKm: cross,
              offNadir: Math.atan2(ca.km, ca.p.alt) * R2D,
              ascending: next ? next.lat > ca.p.lat : false,
              sunEl,
              geometry: swathRibbon(sat, ca.t - 60_000, ca.t + 60_000, strip[0], strip[1]),
            });
          }
        }
        t += 12 * coarse;
      } else {
        t += coarse;
      }
    }
  }
  return out.sort((a, b) => a.time - b.time);
}
