/**
 * Offline tests for the three public-site replication builders.
 * No network access — pure parser/transform checks plus manifest invariants.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { slimRow as hiSlim, fullBody as hiFull } from './build-hi-manifest.mjs';
import { slugify as ohSlug, slimRow as ohSlim } from './build-oh-manifest.mjs';
import { parseTools, parseExploits, parseRss } from './build-kp-manifest.mjs';

const ROOT = process.cwd();

test('HI normalises grade, autonomy and enrichment into the slim index', () => {
  const row = hiSlim({
    id: 'x',
    title: 'An attack',
    date: '2026-03',
    actor: 'actor',
    actor_type: 'criminal',
    targets: 'a bank',
    ai_role: ['recon'],
    models: ['Claude'],
    model_basis: 'stated',
    autonomy: 'semi-autonomous',
    confidence: 'CONFIRMED',
    sources: [{ url: 'u', primary: true }],
    enrichment: { model_named: true, harness: { used: true, names: ['ARTEX'] }, countries: ['US'], sectors: ['finance'] },
  });
  assert.equal(row.confidence, 'confirmed');
  assert.equal(row.month, '2026-03');
  assert.equal(row.primarySourceCount, 1);
  assert.equal(row.harnessUsed, true);
  assert.deepEqual(row.sectors, ['finance']);
  const full = hiFull({ id: 'x', title: 'An attack', date: '2026-03', sources: [{ url: 'u', primary: true }] });
  assert.equal(full.upstreamUrl, 'https://hackingincidents.ai/incident/x/');
  assert.equal(full.sources[0].url, 'u');
});

test('OH slugifies harness names and keeps evidence tiers and source ids', () => {
  assert.equal(ohSlug('oh-my-claudecode'), 'oh-my-claudecode');
  assert.equal(ohSlug('AntiFox / ARTEX'), 'antifox-artex');
  const row = ohSlim({
    name: 'ARTEX',
    table: 'evidence',
    tier: 'confirmed',
    repo: 'https://github.com/x/artex',
    description: 'platform',
    stars: 100,
    actors: [{ name: 'VAPOR PANDA', note: 'China-nexus' }],
    uses: [{ tag: 'recon', basis: 'attack report', source: 'u', quote: 'q' }],
    sources: ['a', 'b'],
    incidents: [{ id: 'i' }],
  });
  assert.equal(row.slug, 'artex');
  assert.equal(row.tier, 'confirmed');
  assert.deepEqual(row.useTags, ['recon']);
  assert.equal(row.sourceCount, 2);
  assert.equal(row.incidentCount, 1);
});

test('KP parses newest-tool cards from the server-rendered HTML', () => {
  const html = `<article class="surface-card group flex flex-col overflow-hidden transition-colors hover:border-primary/40">
    <a href="/en/tools/github/inradii/iottack"><img alt="iottack preview" src="https://assets.kitploit.com/x.webp"/></a>
    <h3 class="text-body font-semibold">iottack</h3>
    <span aria-label="GitHub">GitHub</span><span aria-label="Repository path">inradii/iottack</span>
    <p class="text-body-sm text-on-surface-variant line-clamp-2 flex-1">Framework for testing IoT protocols</p>
    <span class="label inline-flex">iot-security</span><span class="label">+4</span>
    <span title="Stars"><span>2</span></span></article>`;
  const tools = parseTools(html);
  assert.equal(tools.length, 1);
  assert.equal(tools[0].title, 'iottack');
  assert.equal(tools[0].provider, 'GitHub');
  assert.deepEqual(tools[0].categories, ['iot-security']);
  assert.equal(tools[0].stars, '2');
  assert.equal(tools[0].url, 'https://kitploit.com/en/tools/github/inradii/iottack');
});

test('KP parses CVE evidence cards and RSS items without calling /api/', () => {
  const html = `<article class="grid gap-3 p-4">
    <a href="/en/exploits/cve-2026-1306">CVE-2026-1306</a>
    <h3><a href="/en/exploits/cve-2026-1306">midi-Synth &lt;= 1.1.0 - File Upload</a></h3>
    <span aria-label="CVSS: 9.8; High"></span><span aria-label="EPSS: 4.8%; Low"></span>
    <dt>Exploits</dt><dd>2</dd></article>`;
  const exploits = parseExploits(html);
  assert.equal(exploits.length, 1);
  assert.equal(exploits[0].cve, 'CVE-2026-1306');
  assert.equal(exploits[0].cvssScore, 9.8);
  assert.equal(exploits[0].exploitCount, 2);

  const feed = parseRss('<rss><channel><item><title>Aliens_eye</title><link>https://kitploit.com/en/posts/x</link><description>&lt;p&gt;OSINT engine&lt;/p&gt;</description><pubDate>Thu, 19 Nov 2026 04:27:02 +0000</pubDate></item></channel></rss>');
  assert.equal(feed[0].title, 'Aliens_eye');
  assert.equal(feed[0].description.trim(), 'OSINT engine');

  const builder = readFileSync(join(ROOT, 'scripts', 'build-kp-manifest.mjs'), 'utf8');
  assert.equal(builder.includes("fetchText('/api/"), false, 'builder must never fetch the upstream JSON API');
});

test('built manifests keep counts consistent and deep-link upstream hosts', () => {
  const hi = JSON.parse(readFileSync(join(ROOT, 'public/data/hi/index.json'), 'utf8'));
  const oh = JSON.parse(readFileSync(join(ROOT, 'public/data/oh/index.json'), 'utf8'));
  const kp = JSON.parse(readFileSync(join(ROOT, 'public/data/kp/index.json'), 'utf8'));
  assert.equal(hi.incidents.length, hi.counts.records);
  assert.equal(hi.months.length, hi.counts.months);
  assert.equal(oh.harnesses.length, oh.counts.tracked);
  assert.equal(kp.tools.length, kp.counts.tools);
  assert.equal(kp.exploits.length, kp.counts.exploits);
  assert.match(kp.robots, /disallowed/i);
  for (const item of [...kp.tools, ...kp.exploits]) assert.match(item.url, /^https:\/\/kitploit\.com\//);
  assert.match(oh.upstreamData, /^https:\/\/github\.com\//);
});
