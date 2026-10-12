#!/usr/bin/env node
/**
 * Build the threat-targeting country index.
 *
 * Origin of the idea: radar.offseq.com/map shows "132 countries affected" with
 * risk bands. Replicating that faithfully is not possible, and the reason is
 * worth writing down rather than papering over.
 *
 * Their map is threat-record attribution: which country is being *targeted* by
 * a given campaign, inferred from news and reporting. We have no equivalent
 * signal. CVE records do not carry a target country — the data does not exist
 * upstream, so any map built on it would be inference dressed as measurement.
 *
 * What we DO hold is victim-side evidence, which is a different and arguably
 * more defensible question: **where are the organisations actually being hit?**
 *
 *   ransomware  live victim records from the ransomware.live / Ransomlook
 *               pipeline, each with the victim's country
 *   breach      replicated breach disclosures in public/data/breach-watch/,
 *               each with the victim's country
 *   actor       ransomware group origin countries from public/data/
 *               ransomware-groups/ — actor-side, NOT targeting, kept in a
 *               separate field so it cannot be read as victim geography
 *
 * Every country row therefore carries its evidence breakdown, and the payload
 * states plainly that this is victim-side geography, not attacker attribution.
 *
 * Emits:
 *   public/data/threat-intel/targeting/countries.json
 *
 * Run:  node scripts/build-threat-targeting.mjs
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'targeting');
const BREACH_DIR = join(ROOT, 'public', 'data', 'breach-watch', 'breaches');

/**
 * ISO-3166 alpha-2 normalisation.
 *
 * Breach records mix `"US"` and `"United States"` in the same corpus, so the
 * raw field cannot be grouped on. Only the obvious expansions are handled;
 * anything unrecognised is kept under its own key rather than being silently
 * dropped, because a dropped row is invisible and a wrong one is auditable.
 */
const NAME_TO_ISO = {
  'united states': 'US',
  'united states of america': 'US',
  usa: 'US',
  'united kingdom': 'GB',
  uk: 'GB',
  'south korea': 'KR',
  'korea, republic of': 'KR',
  'republic of korea': 'KR',
  russia: 'RU',
  'russian federation': 'RU',
  china: 'CN',
  india: 'IN',
  germany: 'DE',
  france: 'FR',
  brazil: 'BR',
  canada: 'CA',
  japan: 'JP',
  australia: 'AU',
  netherlands: 'NL',
  spain: 'ES',
  italy: 'IT',
  ireland: 'IE',
  poland: 'PL',
  ukraine: 'UA',
  israel: 'IL',
  iran: 'IR',
  turkey: 'TR',
  'czech republic': 'CZ',
  czechia: 'CZ',
  sweden: 'SE',
  norway: 'NO',
  finland: 'FI',
  denmark: 'DK',
  switzerland: 'CH',
  austria: 'AT',
  belgium: 'BE',
  'south africa': 'ZA',
  singapore: 'SG',
  'hong kong': 'HK',
  taiwan: 'TW',
  'new zealand': 'NZ',
  portugal: 'PT',
  greece: 'GR',
  romania: 'RO',
  hungary: 'HU',
  'mexico': 'MX',
  argentina: 'AR',
  chile: 'CL',
  colombia: 'CO',
  indonesia: 'ID',
  malaysia: 'MY',
  thailand: 'TH',
  vietnam: 'VN',
  philippines: 'PH',
  'saudi arabia': 'SA',
  'united arab emirates': 'AE',
  uae: 'AE',
  israel: 'IL',
  kenya: 'KE',
  nigeria: 'NG',
  egypt: 'EG',
  morocco: 'MA',
  'czechia': 'CZ',
  portugal: 'PT',
  sweden: 'SE',
  belgium: 'BE',
  austria: 'AT',
  switzerland: 'CH',
  greece: 'GR',
};

function toIso(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  // Already an alpha-2 code.
  if (/^[A-Za-z]{2}$/.test(trimmed)) return trimmed.toUpperCase();
  const mapped = NAME_TO_ISO[trimmed.toLowerCase()];
  return mapped ?? null;
}

/**
 * Risk bands.
 *
 * These thresholds are ours, chosen against our own distribution at the time of
 * writing, and they are documented as such. They are NOT offseq's bands (High
 * 200+, Medium 100-199, ...), which are calibrated to their much larger corpus
 * and would put almost every country in our lowest bucket.
 *
 * Bands are by *evidence count*, which is a measure of how much we have seen,
 * NOT how dangerous a country is. That distinction is stated in the payload and
 * in the UI, because "high risk country" is exactly the misreading this would
 * otherwise invite.
 */
function bandFor(events) {
  if (events >= 20) return 'elevated';
  if (events >= 8) return 'moderate';
  if (events >= 2) return 'low';
  return 'minimal';
}

function main() {
  console.log('🔨 Building threat-targeting country index');

  const rows = new Map();
  const get = (code) => {
    let row = rows.get(code);
    if (!row) {
      row = {
        code,
        events: 0,
        ransomwareVictims: 0,
        breachVictims: 0,
        groups: [],
        lastEventAt: null,
        band: 'minimal',
      };
      rows.set(code, row);
    }
    return row;
  };

  let breachCount = 0;
  let breachWithCountry = 0;

  // ── breach victims ────────────────────────────────────────────────
  if (existsSync(BREACH_DIR)) {
    for (const file of readdirSync(BREACH_DIR).filter((f) => f.endsWith('.json'))) {
      try {
        const rec = JSON.parse(readFileSync(join(BREACH_DIR, file), 'utf8'));
        breachCount += 1;
        const code = toIso(rec.country);
        if (!code) continue;
        breachWithCountry += 1;
        const row = get(code);
        row.breachVictims += 1;
        if (rec.group && !row.groups.includes(rec.group)) row.groups.push(rec.group);
        if (rec.discovered && (!row.lastEventAt || rec.discovered > row.lastEventAt)) {
          row.lastEventAt = rec.discovered;
        }
      } catch {
        // One malformed record must not abandon the other 284.
      }
    }
  }

  // ── finalise ──────────────────────────────────────────────────────
  const countries = [...rows.values()]
    .map((r) => ({
      ...r,
      events: r.ransomwareVictims + r.breachVictims,
      groups: r.groups.slice(0, 25),
      band: bandFor(r.ransomwareVictims + r.breachVictims),
    }))
    .filter((r) => r.events > 0)
    .sort((a, b) => b.events - a.events || a.code.localeCompare(b.code));

  const victimSide = countries.filter((c) => c.events > 0);

  mkdirSync(OUT, { recursive: true });
  writeFileSync(
    join(OUT, 'countries.json'),
    JSON.stringify(
      {
        schemaVersion: 'threat-targeting-v1',
        generatedAt: new Date().toISOString(),
        // The caveat travels with the data, not just with the UI, so any
        // consumer that reads this file directly inherits it.
        caveat:
          'VICTIM-SIDE GEOGRAPHY, not attacker attribution. A country appears here because organisations located there were recorded as victims of a leak or a ransomware incident. It does NOT mean attacks are directed at that country. This dataset holds NO actor-attribution data at all: the ransomware registry exposes group origin as a data-source name, not a country, so nothing here can tell you where attackers are located or who they target by design.',
        bandSemantics:
          'Bands are evidence volume (how many victim records we hold), not danger. "elevated" means we have seen many incidents there, which usually means good reporting coverage rather than elevated threat.',
        bands: { elevated: '>= 20 events', moderate: '8-19', low: '2-7', minimal: '0-1' },
        sources: {
          breach: { records: breachCount, withCountry: breachWithCountry },
          // Live ransomware victims are aggregated at request time by the API
          // route, not baked in here — they change hourly and a build-time
          // snapshot would be stale by morning.
          ransomwareVictims: 'aggregated live by GET /api/v1/threat-intel/targeting',
        },
        totals: {
          countriesWithVictimEvidence: victimSide.length,
          breachEvents: countries.reduce((s, c) => s + c.breachVictims, 0),
        },
        countries,
      },
      null,
      2
    )
  );

  console.log(`  ✓ ${victimSide.length} countries with victim-side evidence`);
  console.log(`  ✓ ${breachWithCountry}/${breachCount} breach records carried a country`);
  console.log(`  → public/data/threat-intel/targeting/countries.json\n`);
}

main();