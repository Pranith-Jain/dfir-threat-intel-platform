/** Offline parser tests for the CC BY 4.0 PRTF mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePrtf } from './build-prtf.mjs';

const HTML = `
<script>
const T = {
  OSINT: [{n:"Google Dorking",u:"https://example/dorks"}],
  DRONES: [{n:"Drone",u:"https://example/drone"}],
};
const tactics = [
  { id:"PRTF-1", name:"Reconnaissance", desc:"Gathering information.", sections:[
    { label:null, techniques:[
      { id:"PRTF-1.01", name:"OSINT", desc:"Public sources.", tools:T.OSINT, chains:[{id:"PRTF-2.01",name:"Avoid cameras"}], blue:{det:"Observed",cm:"Policy",refs:[]} },
      { id:"PRTF-1.02", name:"Aerial", desc:"Drones.", tools:T.DRONES, chains:[], blue:null }
    ]}
  ]}
];
</script>`;

test('parses tactics, techniques, tools and blue-team notes from embedded JS', () => {
  const { tactics, slim, bodies } = parsePrtf(HTML);
  assert.equal(tactics.length, 1);
  assert.equal(tactics[0].count, 2);
  assert.equal(slim.length, 2);
  assert.equal(bodies[0].tacticId, 'PRTF-1');
  assert.equal(bodies[0].tools[0].name, 'Google Dorking');
  assert.equal(bodies[0].tools[0].url, 'https://example/dorks');
  assert.equal(bodies[0].chains[0].name, 'Avoid cameras');
  assert.equal(bodies[0].blue.cm, 'Policy');
  assert.equal(bodies[1].url, 'https://redteam.vip/prtf/#PRTF-1.02');
});

test('degrades cleanly when the upstream literals are missing', () => {
  assert.throws(() => parsePrtf('<html></html>'), /missing const T/);
});
