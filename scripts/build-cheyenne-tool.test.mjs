/** Offline tests for the Cheyenne tool data builder. No network access. */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { filterTle } from './build-cheyenne-tool.mjs';

const catalog = [
  { id: 'sentinel-2', match: ['^SENTINEL-2[A-D]$'] },
  { id: 'landsat', match: ['^LANDSAT (\\d)$'] },
];

function tle(name, norad) {
  return `${name.padEnd(24)}\n1 ${String(norad).padStart(5, '0')}U 15028A   26322.96981471  .00000038  00000+0  31161-4 0  9998\n2 ${String(norad).padStart(5, '0')}  98.5663  35.5482 0001175  94.1183 266.0135 14.30817500595867`;
}

test('filterTle keeps only catalogued constellations with their NORAD ids', () => {
  const raw = [
    tle('SENTINEL-2A', 40697),
    tle('SENTINEL-2B', 42063),
    tle('LANDSAT 9', 49260),
    tle('UNRELATED SAT', 12345),
  ].join('\n');
  const sats = filterTle(raw, catalog);
  assert.deepEqual(sats.map((s) => s.c), ['sentinel-2', 'sentinel-2', 'landsat']);
  assert.deepEqual(sats.map((s) => s.norad), [40697, 42063, 49260]);
  assert.equal(sats[0].l1.startsWith('1 '), true);
  assert.equal(sats[0].l2.startsWith('2 '), true);
});

test('filterTle returns no satellites for malformed input (validation lives in main)', () => {
  assert.deepEqual(filterTle('not a tle set', catalog), []);
});
