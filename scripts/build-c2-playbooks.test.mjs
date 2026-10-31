/**
 * Tests for the classification ports in scripts/build-genioc-manifest.mjs
 * and scripts/build-c2-playbooks.mjs. No network access — pure functions
 * extracted from the builders so the manifest data contract is pinned.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { classifyLine, classifyText } from './build-genioc-manifest.mjs';
import { categorizeFamily, externalUrl, urlscanFragment } from './build-c2-playbooks.mjs';

// ─── genioc classification ──────────────────────────────────────────

test('classifyLine sorts Gen Threat Labs sample hashes', () => {
  assert.deepEqual(classifyLine('c5ed005bed369b4cb1aa07280fc13f7f'), { type: 'md5', value: 'c5ed005bed369b4cb1aa07280fc13f7f' });
  assert.deepEqual(classifyLine('07beca60c0a50520b8dbc0b8cc2d56614dd48fef0466f846a0a03afbfc42349d'), {
    type: 'sha256',
    value: '07beca60c0a50520b8dbc0b8cc2d56614dd48fef0466f846a0a03afbfc42349d',
  });
  assert.equal(classifyLine('ff8678cdc62494f84b5b8755ef8201502c345fa4').type, 'sha1');
});

test('classifyLine sorts network IOCs', () => {
  assert.equal(classifyLine('1.2.3.4').type, 'ip');
  assert.equal(classifyLine('10.0.0.0/8').type, 'cidr');
  assert.equal(classifyLine('https://evil.example/dl.php').type, 'url');
  assert.equal(classifyLine('evil.example').type, 'domain');
  // Trailing inline comment is stripped from the value.
  assert.deepEqual(classifyLine('1.2.3.4 # cobalt beacon'), { type: 'ip', value: '1.2.3.4' });
});

test('classifyLine blanks comments and junk', () => {
  assert.equal(classifyLine('# generated 2026-01-01'), null);
  assert.equal(classifyLine(''), null);
  assert.equal(classifyLine('   '), null);
  assert.equal(classifyLine('not canada m8').type, 'other');
});

test('classifyText keeps line iteration deterministic', () => {
  const out = classifyText('# hdr\n1.2.3.4\n\nevIL.example\n');
  assert.deepEqual(out, [
    { type: 'ip', value: '1.2.3.4' },
    { type: 'domain', value: 'evIL.example' },
  ]);
});

// ─── c2 playbook ports (MANTIS parity) ──────────────────────────────

test('categorizeFamily matches the MANTIS heuristic lanes', () => {
  assert.equal(categorizeFamily('Lumma Stealer', 'WHOIS Registrant Clustering'), 'Info Stealer');
  assert.equal(categorizeFamily('Quasar RAT', 'Hardcoded Server Certificate'), 'RAT');
  assert.equal(categorizeFamily('Gophish', 'Phishing page'), 'Phishing Framework');
  assert.equal(categorizeFamily('LockBit', 'C2 Panel'), 'Ransomware');
  assert.equal(categorizeFamily('Winnti Group', 'APT staging'), 'APT Infrastructure');
  assert.equal(categorizeFamily('Mythic', 'C2 Beacon'), 'C2 Framework');
  assert.equal(categorizeFamily('Open Directory', 'Index of /'), 'Exposed OpenDir / Secrets');
});

test('externalUrl builds platform deep-links ported from MANTIS', () => {
  // Pure IP short-circuits to the host page on shodan/censys/urlscan.
  assert.equal(externalUrl('shodan', '1.2.3.4'), 'https://www.shodan.io/host/1.2.3.4');
  assert.equal(externalUrl('censys', 'ip: 1.2.3.4'), 'https://search.censys.io/hosts/1.2.3.4');
  assert.equal(externalUrl('urlscan', '1.2.3.4'), 'https://urlscan.io/ip/1.2.3.4');
  assert.equal(externalUrl('urlscan', 'domain:example.com'), 'https://urlscan.io/domain/example.com');
  // Favicon MMH3 keeps the engine-native query syntax.
  assert.equal(externalUrl('shodan', 'http.favicon.hash:-123'), 'https://www.shodan.io/search?query=http.favicon.hash%3A-123');
  // FOFA base64-encodes the query.
  assert.equal(externalUrl('fofa', 'body="cobalt"'), `https://fofa.info/result?qbase64=${Buffer.from('body="cobalt"').toString('base64')}`);
  // Unknown engines → no fabricated URL (parities with MANTIS behaviour).
  assert.equal(externalUrl('silentpush', 'anything'), '');
  assert.equal(externalUrl('shodan', ''), '');
});

test('urlscanFragment keeps the safe charset raw and escapes the rest', () => {
  const out = urlscanFragment('task.tags:"threat" AND /page/');
  // Parity with Python urllib.parse.quote(safe=':="/+*'): spaces escape.
  assert.equal(out, 'https://urlscan.io/search/#task.tags:"threat"%20AND%20/page/');
  assert.ok(urlscanFragment('hash:A&B').includes('A%26B'));
});
