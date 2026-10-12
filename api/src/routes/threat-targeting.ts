/**
 * Threat-targeting country view.
 *
 * Built on `public/data/threat-intel/targeting/countries.json` (breach victims,
 * replicated at build time) merged with live ransomware victims fetched at
 * request time.
 *
 * The naming is deliberately "targeting" rather than "threats by country",
 * because that is the question the evidence answers — and the response carries
 * the caveat in three places, because the misreading this invites (reading a
 * breach count as "this country is under attack") is the exact one the
 * underlying data does not support.
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { notFound } from '../lib/api-error';
import { fetchRansomwareRecent } from './ransomware-recent';

const DATA_PATH = '/data/threat-intel/targeting/countries.json';

interface CountryRow {
  code: string;
  events: number;
  ransomwareVictims: number;
  breachVictims: number;
  groups: string[];
  lastEventAt: string | null;
  band: string;
}

interface TargetingIndex {
  schemaVersion: string;
  generatedAt: string;
  caveat: string;
  bandSemantics: string;
  bands: Record<string, string>;
  sources: Record<string, unknown>;
  totals: Record<string, number>;
  countries: CountryRow[];
}

let indexPromise: Promise<TargetingIndex | null> | null = null;

async function loadIndex(env: Env): Promise<TargetingIndex | null> {
  if (!env.ASSETS) return null;
  indexPromise ??= env.ASSETS.fetch(new Request(`https://targeting.internal${DATA_PATH}`))
    .then(async (res) => {
      if (!res.ok) return null;
      const json = (await res.json()) as TargetingIndex;
      return Array.isArray(json.countries) ? json : null;
    })
    .catch(() => null);
  return indexPromise;
}

const CACHE_TTL = 900;

/** Same normalisation the build script applies, kept in sync by construction. */
function toIso(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  return /^[A-Za-z]{2}$/.test(trimmed) ? trimmed.toUpperCase() : null;
}

export async function threatTargetingHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadIndex(c.env);
  if (!index) {
    return notFound(c, `public${DATA_PATH} not found. Run: node scripts/build-threat-targeting.mjs`);
  }

  const band = c.req.query('band')?.trim().toLowerCase();
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 100), 1), 500);

  // Live ransomware victims are merged here rather than baked into the build
  // artifact: they change hourly and a build-time snapshot would be stale by
  // the morning. A failure costs the ransomware leg only, and says so.
  const liveRansomware = new Map<string, { victims: number; groups: Set<string> }>();
  let ransomwareDegraded = false;
  try {
    const { body } = await fetchRansomwareRecent(c.env);
    for (const v of body.victims ?? []) {
      const code = toIso(v.country);
      if (!code) continue;
      const row = liveRansomware.get(code) ?? { victims: 0, groups: new Set() };
      row.victims += 1;
      if (v.group) row.groups.add(v.group);
      liveRansomware.set(code, row);
    }
  } catch (err) {
    ransomwareDegraded = true;
    logError('targeting: ransomware victim fetch failed', err);
  }

  const merged = index.countries.map((row) => {
    const live = liveRansomware.get(row.code);
    const ransomwareVictims = row.ransomwareVictims + (live?.victims ?? 0);
    const events = row.breachVictims + ransomwareVictims;
    const groups = [...new Set([...row.groups, ...(live ? [...live.groups] : [])])];
    return {
      ...row,
      ransomwareVictims,
      breachVictims: row.breachVictims,
      events,
      groups: groups.slice(0, 25),
      // Band recomputed on the merged total rather than carried from the build
      // artifact, or a country would be graded on breach data alone while the
      // page showed ransomware events too.
      band: gradeBand(events),
    };
  });

  // Countries seen only in the live ransomware feed never appeared at build
  // time, so they have to be added rather than assumed present.
  for (const [code, live] of liveRansomware) {
    if (merged.some((m) => m.code === code)) continue;
    merged.push({
      code,
      events: live.victims,
      ransomwareVictims: live.victims,
      breachVictims: 0,
      groups: [...live.groups].slice(0, 25),
      lastEventAt: null,
      band: gradeBand(live.victims),
    });
  }

  const filtered = band ? merged.filter((m) => m.band === band) : merged;
  filtered.sort((a, b) => b.events - a.events || a.code.localeCompare(b.code));

  return c.json(
    {
      schemaVersion: 'threat-targeting-api-v1',
      generatedAt: index.generatedAt,
      // Repeated here, at the top of the payload, where a reader will see it
      // before they see a country list.
      caveat: index.caveat,
      bandSemantics: index.bandSemantics,
      bands: index.bands,
      totals: {
        countries: merged.length,
        events: merged.reduce((s, c) => s + c.events, 0),
        breachEvents: merged.reduce((s, c) => s + c.breachVictims, 0),
        ransomwareEvents: merged.reduce((s, c) => s + c.ransomwareVictims, 0),
        countriesWithRansomwareEvidence: merged.filter((c) => c.ransomwareVictims > 0).length,
      },
      // Partial data, stated as partial rather than presented as complete.
      ransomwareDegraded,
      filters: { band: band ?? null },
      countries: filtered.slice(0, limit),
    },
    { headers: { 'Cache-Control': `public, max-age=${CACHE_TTL}, s-maxage=1800, stale-while-revalidate=3600` } }
  );
}

/** Must stay in lockstep with bandFor() in the build script. */
function gradeBand(events: number): string {
  if (events >= 20) return 'elevated';
  if (events >= 8) return 'moderate';
  if (events >= 2) return 'low';
  return 'minimal';
}
