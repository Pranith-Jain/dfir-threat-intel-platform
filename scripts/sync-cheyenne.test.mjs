#!/usr/bin/env node
/**
 * Tests for the Cheyenne documentation sync parsers.
 *
 * Upstream is hand-written Markdown with HTML fragments, bold feature leads
 * and pipe tables; these parsers decide what the dedicated page displays, so
 * their output is pinned here.
 *
 * Run:  node --test scripts/sync-cheyenne.test.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildDataset, bullets, extractScreenshots, featureCards, section, table } from './sync-cheyenne.mjs';

const README = `# Cheyenne

An earth-observation board.

![Overview](docs/screenshots/overview.png)

## Contents

- Features

## Features

- **Live satellite tracking.** Real-time positions for 23 fleets
  of imaging satellites.
- **Archive search.** Scene footprints on a timeline.

## Data sources

| Data | Source |
| --- | --- |
| Orbital elements | CelesTrak GP data |
| Fire detections | [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/) files |

## Limitations

- **Predicted passes** are opportunities, not commitments.
- Local use only.

## Credits and licences

| Component | Licence |
| --- | --- |
| [MapLibre GL JS](https://github.com/maplibre/maplibre-gl-js) | BSD 3-Clause |

Cheyenne is not affiliated with any provider.
`;

test('section stops at the next heading and keeps heading level', () => {
  assert.match(section(README, 'Features'), /Live satellite tracking/);
  assert.doesNotMatch(section(README, 'Features'), /Data sources/);
  assert.match(section(README, 'Requirements', 3), /^$/);
});

test('bullets folds continuation lines and featureCards splits bold leads', () => {
  const items = bullets(section(README, 'Features'), true);
  assert.equal(items.length, 2);
  assert.match(items[0], /23 fleets of imaging satellites/);
  const cards = featureCards(section(README, 'Features'));
  assert.deepEqual(cards[0], {
    title: 'Live satellite tracking',
    body: 'Real-time positions for 23 fleets of imaging satellites.',
  });
});

test('table parses pipe rows and captures cell links', () => {
  const rows = table(section(README, 'Data sources'));
  assert.equal(rows.length, 2);
  assert.equal(rows[0].data.text, 'Orbital elements');
  assert.equal(rows[1].source.text, 'NASA FIRMS files');
  assert.equal(rows[1].source.url, 'https://firms.modaps.eosdis.nasa.gov/');
});

test('extractScreenshots converts relative docs paths to raw URLs', () => {
  const shots = extractScreenshots(README, 'https://raw.githubusercontent.com/O/R/main');
  assert.deepEqual(shots, [
    {
      alt: 'Overview',
      url: 'https://raw.githubusercontent.com/O/R/main/docs/screenshots/overview.png',
    },
  ]);
});

test('buildDataset assembles repo metadata, fleets and parsed sections', () => {
  const dataset = buildDataset({
    meta: {
      name: 'cheyenne',
      full_name: 'MJCruickshank/cheyenne',
      html_url: 'https://github.com/MJCruickshank/cheyenne',
      description: 'OSINT dashboard',
      stargazers_count: 45,
      default_branch: 'main',
    },
    readme: README,
    catalog: {
      groups: [{ id: 'open', label: 'OPEN ARCHIVE', note: 'Free imagery' }],
      constellations: [{ id: 'sentinel-2', name: 'SENTINEL-2', group: 'open', sensor: 'optical' }],
    },
    now: '2026-11-19T00:00:00.000Z',
  });

  assert.equal(dataset.source.stars, 45);
  assert.equal(dataset.overview, 'An earth-observation board.');
  assert.equal(dataset.features.length, 2);
  assert.equal(dataset.fleets.length, 1);
  assert.equal(dataset.fleets[0].name, 'SENTINEL-2');
  assert.equal(dataset.groups[0].label, 'OPEN ARCHIVE');
  assert.equal(dataset.dataSources.length, 2);
  assert.equal(dataset.limitations.length, 2);
  assert.equal(dataset.credits.length, 1);
  assert.match(dataset.creditsNote, /not affiliated/);
  assert.equal(dataset.screenshots.length, 1);
});
