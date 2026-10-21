#!/usr/bin/env node
/**
 * Build the DarkForums IP intelligence manifest under
 * public/data/threat-intel/darkforums-ip/.
 *
 * Reads staging in ./threat-intel-staging/darkforums-ip/ (created by
 * `node scripts/sync-darkforums-ip.mjs`) and emits:
 *   index.json          — counts, country histogram, and the actor directory
 *   actors.json         — actor → their IPs, grouped by country
 *   geo/<iso>.json      — one file per country: the map points for that country
 *
 * ## Why the data is sharded by country
 *
 * The upstream dataset holds 119k distinct (ip, username) observations. A
 * single map file with all of them would be one ~7 MB download that the
 * browser would then try to render as markers — which no browser survives.
 * Sharding by country means the map fetches only the country it is showing,
 * and the per-country cap keeps the marker count sane.
 *
 * ## Why the jitter is deterministic
 *
 * The upstream tool scatters points around a country's centroid with
 * `random.uniform(-2.5, 2.5)` — a fresh random offset on every request, so
 * the same thread's points moved each time the map was reloaded. Here the
 * offset is derived from a hash of the observation, so a point stays exactly
 * where it was. A map that reshuffles itself on reload is a map nobody
 * trusts twice.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'darkforums-ip');
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'darkforums-ip');

/** Maximum map points emitted per country. */
const MAX_POINTS_PER_COUNTRY = 5000;
/** Maximum IPs listed per actor in actors.json. */
const MAX_IPS_PER_ACTOR = 500;
/** Degrees of scatter around a country's centroid. */
const JITTER_DEGREES = 2.5;

/**
 * ISO 3166-1 alpha-2 → country name.
 *
 * Only the codes that actually appear in the data need names; the rest fall
 * back to the code itself, which is still better than an empty label.
 */
const COUNTRY_NAMES = {
  AD: 'Andorra', AE: 'United Arab Emirates', AF: 'Afghanistan', AG: 'Antigua and Barbuda',
  AI: 'Anguilla', AL: 'Albania', AM: 'Armenia', AO: 'Angola', AR: 'Argentina', AS: 'American Samoa',
  AT: 'Austria', AU: 'Australia', AW: 'Aruba', AX: 'Aland Islands', AZ: 'Azerbaijan',
  BA: 'Bosnia and Herzegovina', BB: 'Barbados', BD: 'Bangladesh', BE: 'Belgium', BF: 'Burkina Faso',
  BG: 'Bulgaria', BH: 'Bahrain', BI: 'Burundi', BJ: 'Benin', BL: 'Saint Barthelemy',
  BM: 'Bermuda', BN: 'Brunei', BO: 'Bolivia', BQ: 'Caribbean Netherlands', BR: 'Brazil',
  BS: 'Bahamas', BT: 'Bhutan', BW: 'Botswana', BY: 'Belarus', BZ: 'Belize',
  CA: 'Canada', CD: 'DR Congo', CF: 'Central African Republic', CG: 'Congo', CH: 'Switzerland',
  CI: "Cote d'Ivoire", CK: 'Cook Islands', CL: 'Chile', CM: 'Cameroon', CN: 'China',
  CO: 'Colombia', CR: 'Costa Rica', CU: 'Cuba', CV: 'Cape Verde', CW: 'Curacao',
  CX: 'Christmas Island', CY: 'Cyprus', CZ: 'Czechia', DE: 'Germany', DJ: 'Djibouti',
  DK: 'Denmark', DM: 'Dominica', DO: 'Dominican Republic', DZ: 'Algeria',
  EC: 'Ecuador', EE: 'Estonia', EG: 'Egypt', ER: 'Eritrea', ES: 'Spain', ET: 'Ethiopia',
  FI: 'Finland', FJ: 'Fiji', FK: 'Falkland Islands', FM: 'Micronesia', FO: 'Faroe Islands',
  FR: 'France', GA: 'Gabon', GB: 'United Kingdom', GD: 'Grenada', GE: 'Georgia', GF: 'French Guiana',
  GG: 'Guernsey', GH: 'Ghana', GI: 'Gibraltar', GL: 'Greenland', GM: 'Gambia', GN: 'Guinea',
  GP: 'Guadeloupe', GQ: 'Equatorial Guinea', GR: 'Greece', GT: 'Guatemala', GU: 'Guam',
  GW: 'Guinea-Bissau', GY: 'Guyana', HK: 'Hong Kong', HN: 'Honduras', HR: 'Croatia',
  HT: 'Haiti', HU: 'Hungary', ID: 'Indonesia', IE: 'Ireland', IL: 'Israel', IM: 'Isle of Man',
  IN: 'India', IO: 'British Indian Ocean Territory', IQ: 'Iraq', IR: 'Iran', IS: 'Iceland',
  IT: 'Italy', JE: 'Jersey', JM: 'Jamaica', JO: 'Jordan', JP: 'Japan', KE: 'Kenya',
  KG: 'Kyrgyzstan', KH: 'Cambodia', KI: 'Kiribati', KM: 'Comoros', KN: 'Saint Kitts and Nevis',
  KP: 'North Korea', KR: 'South Korea', KW: 'Kuwait', KY: 'Cayman Islands', KZ: 'Kazakhstan',
  LA: 'Laos', LB: 'Lebanon', LC: 'Saint Lucia', LI: 'Liechtenstein', LK: 'Sri Lanka',
  LR: 'Liberia', LS: 'Lesotho', LT: 'Lithuania', LU: 'Luxembourg', LV: 'Latvia', LY: 'Libya',
  MA: 'Morocco', MC: 'Monaco', MD: 'Moldova', ME: 'Montenegro', MF: 'Saint Martin',
  MG: 'Madagascar', MH: 'Marshall Islands', MK: 'North Macedonia', ML: 'Mali', MM: 'Myanmar',
  MN: 'Mongolia', MO: 'Macao', MP: 'Northern Mariana Islands', MQ: 'Martinique', MR: 'Mauritania',
  MS: 'Montserrat', MT: 'Malta', MU: 'Mauritius', MV: 'Maldives', MW: 'Malawi', MX: 'Mexico',
  MY: 'Malaysia', MZ: 'Mozambique', NA: 'Namibia', NC: 'New Caledonia', NE: 'Niger',
  NF: 'Norfolk Island', NG: 'Nigeria', NI: 'Nicaragua', NL: 'Netherlands', NO: 'Norway',
  NP: 'Nepal', NR: 'Nauru', NU: 'Niue', NZ: 'New Zealand', OM: 'Oman', PA: 'Panama',
  PE: 'Peru', PF: 'French Polynesia', PG: 'Papua New Guinea', PH: 'Philippines', PK: 'Pakistan',
  PL: 'Poland', PM: 'Saint Pierre and Miquelon', PR: 'Puerto Rico', PS: 'Palestine', PT: 'Portugal',
  PW: 'Palau', PY: 'Paraguay', QA: 'Qatar', RE: 'Reunion', RO: 'Romania', RS: 'Serbia',
  RU: 'Russia', RW: 'Rwanda', SA: 'Saudi Arabia', SB: 'Solomon Islands', SC: 'Seychelles',
  SD: 'Sudan', SE: 'Sweden', SG: 'Singapore', SI: 'Slovenia', SK: 'Slovakia', SL: 'Sierra Leone',
  SM: 'San Marino', SN: 'Senegal', SO: 'Somalia', SR: 'Suriname', SS: 'South Sudan',
  ST: 'Sao Tome and Principe', SV: 'El Salvador', SX: 'Sint Maarten', SY: 'Syria',
  SZ: 'Eswatini', TC: 'Turks and Caicos Islands', TD: 'Chad', TG: 'Togo', TH: 'Thailand',
  TJ: 'Tajikistan', TK: 'Tokelau', TL: 'Timor-Leste', TM: 'Turkmenistan', TN: 'Tunisia',
  TO: 'Tonga', TR: 'Turkey', TT: 'Trinidad and Tobago', TV: 'Tuvalu', TW: 'Taiwan',
  TZ: 'Tanzania', UA: 'Ukraine', UG: 'Uganda', US: 'United States', UY: 'Uruguay',
  UZ: 'Uzbekistan', VA: 'Vatican City', VC: 'Saint Vincent', VE: 'Venezuela',
  VG: 'British Virgin Islands', VI: 'US Virgin Islands', VN: 'Vietnam', VU: 'Vanuatu',
  WF: 'Wallis and Futuna', WS: 'Samoa', YE: 'Yemen', YT: 'Mayotte', ZA: 'South Africa',
  ZM: 'Zambia', ZW: 'Zimbabwe',
};

/**
 * Country centroid (latitude, longitude).
 *
 * Country-level only — the upstream dataset is geolocated with
 * GeoLite2-Country, so it never had better than a country centroid to
 * offer. The centroid is the honest position for the data.
 */
const COUNTRY_COORDS = {
  AE: [23.42, 53.85], AF: [33.94, 67.71], AL: [41.15, 20.17], AM: [40.07, 45.04],
  AO: [-11.2, 17.87], AR: [-38.42, -63.62], AT: [47.52, 14.55], AU: [-25.27, 133.77],
  AZ: [40.14, 47.58], BA: [43.92, 17.68], BD: [23.68, 90.35], BE: [50.5, 4.47],
  BG: [42.73, 25.49], BH: [25.93, 50.64], BJ: [9.31, 2.32], BN: [4.54, 114.73],
  BO: [-16.29, -63.59], BR: [-14.23, -51.93], BS: [25.03, -77.4], BW: [-22.33, 24.68],
  BY: [53.71, 27.95], BZ: [17.19, -88.5], CA: [56.13, -106.35], CD: [-4.03, 21.76],
  CF: [6.61, 20.94], CG: [-0.23, 15.83], CH: [46.82, 8.23], CI: [7.54, -5.55],
  CL: [-35.67, -71.54], CM: [3.85, 11.5], CN: [35.86, 104.2], CO: [4.57, -74.3],
  CR: [9.75, -83.75], CU: [21.52, -77.78], CY: [35.13, 33.43], CZ: [49.82, 15.47],
  DE: [51.17, 10.45], DK: [56.26, 9.5], DO: [18.74, -70.16], DZ: [28.03, 1.66],
  EC: [-1.83, -78.18], EE: [58.6, 25.01], EG: [26.82, 30.8], ES: [40.46, -3.75],
  ET: [9.15, 40.49], FI: [61.92, 25.75], FR: [46.23, 2.21], GA: [-0.8, 11.61],
  GB: [55.38, -3.44], GE: [42.32, 43.36], GH: [7.95, -1.02], GR: [39.07, 21.82],
  GT: [15.78, -90.23], HK: [22.4, 114.11], HN: [15.2, -86.24], HR: [45.1, 15.2],
  HT: [18.97, -72.29], HU: [47.16, 19.5], ID: [-0.79, 113.92], IE: [53.41, -8.24],
  IL: [31.05, 34.85], IN: [20.59, 78.96], IQ: [33.22, 43.68], IR: [32.43, 53.69],
  IS: [64.96, -19.02], IT: [41.87, 12.57], JM: [18.11, -77.3], JO: [30.59, 36.24],
  JP: [36.2, 138.25], KE: [-0.02, 37.91], KG: [41.2, 74.77], KH: [12.57, 104.99],
  KR: [35.91, 127.77], KW: [29.31, 47.48], KZ: [48.02, 66.92], LA: [19.86, 102.5],
  LB: [33.85, 35.86], LK: [7.87, 80.77], LT: [55.17, 23.88], LU: [49.82, 6.13],
  LV: [56.88, 24.6], LY: [26.34, 17.23], MA: [31.79, -7.09], MD: [47.41, 28.37],
  ME: [42.71, 19.37], MG: [-18.77, 46.87], MK: [41.61, 21.75], ML: [17.57, -3.99],
  MM: [16.87, 96.41], MN: [46.86, 103.85], MO: [22.19, 113.54], MX: [23.63, -102.55],
  MY: [4.21, 101.98], MZ: [-18.67, 35.53], NA: [-22.96, 18.49], NG: [9.08, 8.68],
  NI: [12.87, -85.21], NL: [52.13, 5.29], NO: [60.47, 8.47], NP: [28.39, 84.12],
  NZ: [-40.9, 174.89], OM: [21.51, 55.92], PA: [8.54, -80.78], PE: [-9.19, -75.02],
  PH: [12.88, 121.77], PK: [30.38, 69.35], PL: [51.92, 19.15], PR: [18.22, -66.59],
  PT: [39.4, -8.22], PY: [-23.44, -58.44], QA: [25.35, 51.18], RO: [45.94, 24.97],
  RS: [44.02, 21.01], RU: [61.52, 105.32], SA: [23.89, 45.08], SC: [-4.68, 55.49],
  SD: [12.86, 30.22], SE: [60.13, 18.64], SG: [1.35, 103.82], SI: [46.15, 14.99],
  SK: [48.67, 19.7], SN: [14.5, -14.45], SO: [5.15, 46.2], SR: [3.92, -56.03],
  SV: [13.79, -88.9], SY: [34.8, 38.99], TH: [15.87, 100.99], TJ: [38.86, 71.28],
  TM: [38.97, 59.56], TN: [33.89, 9.54], TR: [38.96, 35.24], TT: [10.69, -61.22],
  TW: [23.7, 120.96], TZ: [-6.37, 34.89], UA: [48.38, 31.17], UG: [1.37, 32.29],
  US: [37.09, -95.71], UY: [-32.52, -55.77], UZ: [41.38, 64.59], VE: [6.42, -66.59],
  VN: [14.06, 108.28], YE: [15.55, 48.52], ZA: [-30.56, 22.94], ZM: [-13.13, 27.85],
  ZW: [-19.02, 29.15],
};

/** Convert a dotted-quad IPv4 address to its 32-bit integer. */
export function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

/**
 * A sorted, non-overlapping range table for binary search.
 *
 * The CSV has 362k ranges; a linear scan per IP would be 30 billion
 * comparisons for 80k IPs. Sorted + binary search is ~17 per lookup.
 */
export function buildRangeTable(csv) {
  const ranges = [];
  for (const line of csv.split('\n')) {
    if (!line.trim()) continue;
    const [startIp, endIp, cc] = line.split(',');
    const start = ipToInt(startIp);
    const end = ipToInt(endIp);
    if (start === null || end === null || !cc) continue;
    ranges.push({ start, end, cc: cc.trim().toUpperCase() });
  }
  ranges.sort((a, b) => a.start - b.start);
  return ranges;
}

/** Look up an IP in the range table. Returns the country code or null. */
export function lookupCountry(ranges, ip) {
  const n = ipToInt(ip);
  if (n === null) return null;
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid];
    if (n < r.start) hi = mid - 1;
    else if (n > r.end) lo = mid + 1;
    else return r.cc;
  }
  return null;
}

/**
 * Deterministic pseudo-random in [-1, 1] from a string.
 *
 * A 32-bit FNV-1a hash folded into the mantissa. The same observation
 * always yields the same offset, so a point does not move between reloads.
 */
export function stableJitter(seed) {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) / 4294967295) * 2 - 1;
}

function readStaging(file, label) {
  const p = join(STAGING, file);
  if (!existsSync(p)) {
    console.error(`  ⚠ no staging file at ${p} — run \`node scripts/sync-darkforums-ip.mjs\` first`);
    process.exit(1);
  }
  void label;
  return readFileSync(p, 'utf8');
}

function main() {
  if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
  mkdirSync(join(OUT, 'geo'), { recursive: true });

  const source = JSON.parse(readStaging('source.json', 'source'));
  const posts = JSON.parse(readStaging('posts.json', 'posts'));
  const ranges = buildRangeTable(readStaging('geo.csv', 'geo'));

  console.log(`  · ${ranges.length} country ranges loaded`);

  // Extract the observations. The upstream shape is
  // `{ postId: { ip, username, hostname } }` with an `error` key on the
  // posts that could not be parsed.
  const observations = [];
  let parseErrors = 0;
  for (const value of Object.values(posts)) {
    if (!value || typeof value !== 'object') continue;
    if (value.error) {
      parseErrors++;
      continue;
    }
    const ip = typeof value.ip === 'string' ? value.ip.trim() : '';
    const username = typeof value.username === 'string' ? value.username.trim() : '';
    if (!ip || !username) continue;
    observations.push({
      ip,
      username,
      hostname: typeof value.hostname === 'string' && value.hostname.trim() ? value.hostname.trim() : null,
    });
  }
  console.log(`  · ${observations.length} observations (${parseErrors} unparsed posts skipped)`);

  // Dedupe on (ip, username) — the same actor behind the same address is
  // one infrastructure fact, not many.
  const seen = new Set();
  const unique = [];
  for (const o of observations) {
    const key = `${o.ip}|${o.username}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(o);
  }
  console.log(`  · ${unique.length} unique (ip, username) pairs`);

  // Attribute a country to each observation.
  const byCountry = new Map();
  const actorIps = new Map();
  const countryActors = new Map();
  let unattributed = 0;

  for (const o of unique) {
    const cc = lookupCountry(ranges, o.ip);
    if (!cc) {
      unattributed++;
      continue;
    }
    let bucket = byCountry.get(cc);
    if (!bucket) {
      bucket = [];
      byCountry.set(cc, bucket);
    }
    bucket.push(o);

    let ips = actorIps.get(o.username);
    if (!ips) {
      ips = new Map();
      actorIps.set(o.username, ips);
    }
    ips.set(o.ip, cc);

    let actors = countryActors.get(cc);
    if (!actors) {
      actors = new Set();
      countryActors.set(cc, actors);
    }
    actors.add(o.username);
  }

  const uniqueIps = new Set();
  for (const o of unique) uniqueIps.add(o.ip);

  // Per-country map files.
  const countries = [];
  for (const [cc, points] of byCountry) {
    const [lat, lon] = COUNTRY_COORDS[cc] ?? [0, 0];
    const mapped = points.map((o) => {
      const jLat = stableJitter(`${o.ip}|${o.username}|lat`) * JITTER_DEGREES;
      const jLon = stableJitter(`${o.ip}|${o.username}|lon`) * JITTER_DEGREES;
      return {
        ip: o.ip,
        username: o.username,
        lat: Math.round((lat + jLat) * 10000) / 10000,
        lon: Math.round((lon + jLon) * 10000) / 10000,
      };
    });
    const shown = mapped.slice(0, MAX_POINTS_PER_COUNTRY);
    writeFileSync(
      join(OUT, 'geo', `${cc}.json`),
      JSON.stringify({
        iso: cc,
        name: COUNTRY_NAMES[cc] ?? cc,
        lat,
        lon,
        total: mapped.length,
        shown: shown.length,
        truncated: mapped.length > shown.length,
        actors: countryActors.get(cc)?.size ?? 0,
        points: shown,
      })
    );
    countries.push({
      iso: cc,
      name: COUNTRY_NAMES[cc] ?? cc,
      lat,
      lon,
      observations: mapped.length,
      actors: countryActors.get(cc)?.size ?? 0,
      unique_ips: new Set(points.map((p) => p.ip)).size,
    });
  }
  countries.sort((a, b) => b.observations - a.observations);

  // Per-actor index.
  const actors = [];
  for (const [username, ips] of actorIps) {
    const byCc = new Map();
    for (const [ip, cc] of ips) {
      let list = byCc.get(cc);
      if (!list) {
        list = [];
        byCc.set(cc, list);
      }
      list.push(ip);
    }
    const countryCounts = [...byCc.entries()]
      // ISO only — the country name is already in index.json's country list,
      // and repeating it for every actor is ~2 MB of pure duplication.
      .map(([cc, list]) => ({ iso: cc, count: list.length }))
      .sort((a, b) => b.count - a.count);
    const allIps = [...ips.keys()];
    actors.push({
      username,
      ip_count: allIps.length,
      country_count: byCc.size,
      countries: countryCounts.slice(0, 8),
      ips: allIps.slice(0, MAX_IPS_PER_ACTOR).map((ip) => ({ ip, iso: ips.get(ip) })),
      ips_truncated: allIps.length > MAX_IPS_PER_ACTOR,
    });
  }
  actors.sort((a, b) => b.ip_count - a.ip_count || a.username.localeCompare(b.username));

  const index = {
    schemaVersion: 'darkforums-ip-v1',
    source: source.source,
    sourceUrl: source.sourceUrl,
    description: source.description,
    license: source.license,
    geoSource: source.geoSource,
    syncedAt: source.synced_at,
    counts: {
      observations: unique.length,
      unique_ips: uniqueIps.size,
      actors: actorIps.size,
      countries: countries.length,
      unattributed,
      skipped_posts: parseErrors,
    },
    countries,
    top_actors: actors.slice(0, 100),
  };

  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));
  writeFileSync(join(OUT, 'actors.json'), JSON.stringify({ schemaVersion: 'darkforums-ip-v1', actors }));

  console.log(`  ✓ ${countries.length} countries, ${actorIps.size} actors`);
  console.log(`  ✓ ${uniqueIps.size} unique IPs (${unattributed} unattributed)`);
  console.log(`  → ${OUT}\n`);
}

main();
