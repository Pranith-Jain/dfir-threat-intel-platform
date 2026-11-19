#!/usr/bin/env node
/**
 * Tests for The OSINT Toolbox sync parsers.
 *
 * The upstream READMEs are hand-maintained HTML-in-Markdown, so the link
 * extraction is the fragile part: it must keep external tool names/URLs
 * verbatim while dropping the author's own category links, images and
 * duplicate anchors.
 *
 * Run:  node --test scripts/sync-osint-toolbox.test.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildDataset, decodeEntities, extractTools, parseQuickLinks } from './sync-osint-toolbox.mjs';

const ROOT_README = `
  <a href="https://github.com/The-Osint-Toolbox/Telegram-OSINT">Telegram OSINT</a>
  <a href="https://github.com/cqcore/Data-OSINT">Data Acquisition OSINT</a>
  <a href="https://github.com/The-Osint-Toolbox/GitHub-OSINT-Resources">GitHub OSINT Accounts</a>
  <a href="https://github.com/The-Osint-Toolbox/The-OSINT-Toolbox">The OSINT Toolbox</a>
`;

const TOOL_README = `
  <img src="https://www.cqcore.uk/wp-content/uploads/logo.png">
  <a href="https://github.com/The-Osint-Toolbox/Telegram-OSINT">Telegram</a>
  <a href="https://www.cqcore.uk/about">About CQCore</a>
  <a href="https://example.com/logo.png">Logo</a>
  <a href="https://tools.example.com/search?q=abc&amp;utm_source=readme">Search &amp; Destroy</a>
  <a href="https://tools.example.com/search?q=abc">Search &amp; Destroy (duplicate)</a>
  <a href="https://another.example.org/tool">Another Tool</a>
`;

test('decodeEntities handles HTML entities in link text', () => {
  assert.equal(decodeEntities('Research &amp; analyse &#39;OSINT&#39;'), "Research & analyse 'OSINT'");
  assert.equal(decodeEntities(''), '');
});

test('parseQuickLinks maps upstream labels and renamed repos', () => {
  const labels = parseQuickLinks(ROOT_README);
  assert.equal(labels.get('Telegram-OSINT'), 'Telegram OSINT');
  assert.equal(labels.get('Data-Acquisition-OSINT'), 'Data Acquisition OSINT');
  assert.equal(labels.get('GitHub-OSINT-Accounts'), 'GitHub OSINT Accounts');
  assert.equal(labels.get('The-OSINT-Toolbox'), 'The OSINT Toolbox');
  assert.equal(labels.get('Data-OSINT'), undefined);
});

test('extractTools keeps external tools verbatim and drops internal/duplicate links', () => {
  const tools = extractTools(TOOL_README, 'Search-Engines', 'Search Engines');
  assert.equal(tools.length, 2);
  assert.deepEqual(tools[0], {
    name: 'Search & Destroy',
    url: 'https://tools.example.com/search?q=abc&utm_source=readme',
    repo: 'Search-Engines',
    category: 'Search Engines',
  });
  assert.equal(tools[1].name, 'Another Tool');
  assert.ok(!tools.some((t) => t.url.includes('cqcore.uk')));
  assert.ok(!tools.some((t) => t.url.includes('The-Osint-Toolbox')));
  assert.ok(!tools.some((t) => /\.png$/.test(t.url)));
});

test('buildDataset aggregates repos, tools, stars and category labels', () => {
  const dataset = buildDataset({
    profile: { login: 'The-Osint-Toolbox', name: 'CQCore', followers: 10, public_repos: 2 },
    repos: [
      {
        name: 'A-Tools',
        full_name: 'The-Osint-Toolbox/A-Tools',
        html_url: 'https://github.com/The-Osint-Toolbox/A-Tools',
        description: 'A tools',
        stargazers_count: 5,
        forks_count: 1,
        topics: ['osint'],
        pushed_at: '2026-11-18T00:00:00Z',
        default_branch: 'main',
      },
      {
        name: 'B-Tools',
        full_name: 'The-Osint-Toolbox/B-Tools',
        html_url: 'https://github.com/The-Osint-Toolbox/B-Tools',
        description: null,
        stargazers_count: 3,
        default_branch: 'main',
      },
    ],
    readmes: {
      'The-OSINT-Toolbox': ROOT_README,
      'A-Tools': '<a href="https://a.example.com/one">Tool One</a>',
      'B-Tools': '<a href="https://b.example.com/two">Tool Two</a>',
    },
    now: '2026-11-19T00:00:00.000Z',
  });

  assert.equal(dataset.stats.repos, 2);
  assert.equal(dataset.stats.tools, 2);
  assert.equal(dataset.stats.stars, 8);
  assert.equal(dataset.source.name, 'CQCore');
  assert.equal(dataset.generatedAt, '2026-11-19T00:00:00.000Z');
  assert.equal(dataset.repos.find((r) => r.name === 'Telegram-OSINT'), undefined);
  assert.equal(dataset.repos.find((r) => r.name === 'A-Tools').category, 'A Tools');
  assert.equal(dataset.tools.find((t) => t.name === 'Tool Two').repo, 'B-Tools');
  assert.ok(dataset.categories.includes('A Tools'));
});
