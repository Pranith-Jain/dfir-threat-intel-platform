/** Offline parser tests for the BlueTeam-Tools metadata mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseBlueTeamTools, slugify } from './build-blue-team-tools.mjs';

const MD = `
# BlueTeam-Tools
<details open>
    <summary><b>Threat Hunting</b> 2 tools</summary>
    <ul><ul>
        <li><b><a href="#huntio">hunt.io</a></b><i> Discover active C2 servers</i></li>
        <li><b><a href="#validin">Validin</a></b><i> Pivot through DNS</i></li>
    </ul></ul>
</details>
<details open>
    <summary><b>Network Discovery</b> 1 tools</summary>
    <ul><ul>
        <li><b><a href="#nmap">Nmap</a></b><i> Network scanner</i></li>
    </ul></ul>
</details>
### [🔙](#tool-list)[hunt.io](https://hunt.io)
### [🔙](#tool-list)[Validin](https://www.validin.com/)
### [🔙](#tool-list)[Nmap](https://nmap.org)
`;

test('slugify produces stable lookup keys', () => {
  assert.equal(slugify('  threathunt.app '), 'threathunt-app');
  assert.equal(slugify('C# / .NET Tools'), 'c-net-tools');
});

test('parses categories, one-line summaries and public links', () => {
  const { categories, tools } = parseBlueTeamTools(MD);
  assert.equal(categories.length, 2);
  assert.equal(tools.length, 3);
  assert.equal(categories[0].name, 'Threat Hunting');
  assert.equal(categories[0].toolCount, 2);
  assert.equal(tools[0].slug, 'hunt-io');
  assert.equal(tools[0].summary, 'Discover active C2 servers');
  assert.equal(tools[0].url, 'https://hunt.io');
  assert.match(tools[0].upstreamUrl, /blob\/main\/README\.md#huntio$/);
  assert.equal(tools[2].category, 'Network Discovery');
});

test('keeps tools without a destination link but never invents one', () => {
  const { tools } = parseBlueTeamTools('<details><summary><b>X</b> 1 tools</summary><li><b><a href="#a">A</a></b><i>desc</i></li></details>');
  assert.equal(tools.length, 1);
  assert.equal(tools[0].url, null);
});

test('degrades cleanly on an empty or changed README', () => {
  assert.deepEqual(parseBlueTeamTools(''), { categories: [], tools: [] });
  assert.deepEqual(parseBlueTeamTools(null).tools, []);
});
