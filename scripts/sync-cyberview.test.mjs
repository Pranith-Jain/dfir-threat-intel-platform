/** Guards the repo-driven CyberView mirror: SHAs + built bundle must exist. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const BASE = join(ROOT, 'public', 'data', 'cyberview');
const read = (rel) => JSON.parse(readFileSync(join(BASE, rel), 'utf8'));

test('manifest records upstream source-repo branch SHAs', () => {
  const m = read('manifest.json');
  assert.match(m.upstream.repo, /github\.com\/CyberViewTools\/CyberView$/);
  assert.match(m.upstream.licence, /Proprietary/i);
  assert.match(m.upstream.mainSha, /^[0-9a-f]{40}$/);
  assert.match(m.upstream.dataSha, /^[0-9a-f]{40}$/);
  assert.ok(m.files.includes('data/bundle.json'));
});

test('mirror contains the upstream-built bundle and the event array', () => {
  const bundle = read('data/bundle.json');
  assert.ok(Array.isArray(bundle.events) && bundle.events.length > 0);
  assert.ok(Array.isArray(bundle.kev));
  const events = read('data/events.json');
  assert.ok(Array.isArray(events) && events.length > 0);
  const withCoords = events.filter((e) => Number.isFinite(e.lat) && Number.isFinite(e.lng));
  assert.ok(withCoords.length > 0, 'globe needs lat/lng on upstream events');
  for (const e of withCoords) {
    assert.ok(e.lat >= -90 && e.lat <= 90 && e.lng >= -180 && e.lng <= 180);
  }
});
